/*
 * Sylpheed -- a GTK+ based, lightweight, and fast e-mail client
 * Copyright (C) 1999-2001 Hiroyuki Yamamoto
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA 02111-1307, USA.
 */

#ifdef HAVE_CONFIG_H
#  include "config.h"
#endif

#include "defs.h"

#include <glib.h>
#include <gtk/gtkmain.h>
#include <gtk/gtksignal.h>
#include <gtk/gtkwindow.h>
#include <gtk/gtkclist.h>
#include <stdio.h>
#include <string.h>
#include <sys/time.h>
#include <unistd.h>

#include "intl.h"
#include "send.h"
#include "socket.h"
#include "ssl.h"
#include "smtp.h"
#include "esmtp.h"
#include "prefs_common.h"
#include "prefs_account.h"
#include "account.h"
#include "compose.h"
#include "progressdialog.h"
#include "manage_window.h"
#include "procmsg.h"
#include "procheader.h"
#include "utils.h"
#include "gtkutils.h"

#define SMTP_PORT	25
#if USE_SSL
#define SSMTP_PORT	465
#endif

typedef struct _SendProgressDialog	SendProgressDialog;

struct _SendProgressDialog
{
	ProgressDialog *dialog;
	GList *queue_list;
	gboolean cancelled;
};

static gint send_message_local	(const gchar *command, FILE *fp);

#if USE_SSL
static gint send_message_smtp	(GSList *to_list, const gchar *from,
				 const gchar *server, gushort port,
				 const gchar *domain, const gchar *userid,
				 const gchar *passwd, gboolean use_smtp_auth,
				 SSLSMTPType ssl_type, FILE *fp);
static SockInfo *send_smtp_open	(const gchar *server, gushort port,
				 const gchar *domain, gboolean use_smtp_auth,
				 SSLSMTPType ssl_type);
#else
static gint send_message_smtp	(GSList *to_list, const gchar *from,
				 const gchar *server, gushort port,
				 const gchar *domain, const gchar *userid,
				 const gchar *passwd, gboolean use_smtp_auth,
				 FILE *fp);
static SockInfo *send_smtp_open	(const gchar *server, gushort port,
				 const gchar *domain, gboolean use_smtp_auth);
#endif

static SendProgressDialog *send_progress_dialog_create(void);
static void send_progress_dialog_destroy(SendProgressDialog *dialog);
static void send_cancel(GtkWidget *widget, gpointer data);

gint send_message(const gchar *file, PrefsAccount *ac_prefs, GSList *to_list)
{
	FILE *fp;
	gint val;
	gushort port;
	gchar *domain;

	g_return_val_if_fail(file != NULL, -1);
	g_return_val_if_fail(ac_prefs != NULL, -1);
	g_return_val_if_fail(to_list != NULL, -1);

	if ((fp = fopen(file, "r")) == NULL) {
		FILE_OP_ERROR(file, "fopen");
		return -1;
	}

	if (prefs_common.use_extsend && prefs_common.extsend_cmd) {
		val = send_message_local(prefs_common.extsend_cmd, fp);
		fclose(fp);
		return val;
	}

#if USE_SSL
	port = ac_prefs->set_smtpport ? ac_prefs->smtpport :
		ac_prefs->ssl_smtp == SSL_SMTP_TUNNEL ? SSMTP_PORT : SMTP_PORT;
#else
	port = ac_prefs->set_smtpport ? ac_prefs->smtpport : SMTP_PORT;
#endif
	domain = ac_prefs->set_domain ? ac_prefs->domain : NULL;

#if USE_SSL
	val = send_message_smtp(to_list, ac_prefs->address,
				ac_prefs->smtp_server, port, domain,
				ac_prefs->userid, ac_prefs->passwd,
				ac_prefs->use_smtp_auth, ac_prefs->ssl_smtp,
				fp);
#else
	val = send_message_smtp(to_list, ac_prefs->address,
				ac_prefs->smtp_server, port, domain,
				ac_prefs->userid, ac_prefs->passwd,
				ac_prefs->use_smtp_auth, fp);
#endif

	fclose(fp);
	return val;
}

enum
{
	Q_SENDER     = 0,
	Q_SMTPSERVER = 1,
	Q_RECIPIENTS = 2,
	Q_ACCOUNT_ID = 3
};

gint send_message_queue(const gchar *file)
{
	static HeaderEntry qentry[] = {{"S:",   NULL, FALSE},
				       {"SSV:", NULL, FALSE},
				       {"R:",   NULL, FALSE},
				       {"AID:", NULL, FALSE},
				       {NULL,   NULL, FALSE}};
	FILE *fp;
	gint val;
	gchar *from = NULL;
	gchar *server = NULL;
	GSList *to_list = NULL;
	gchar buf[BUFFSIZE];
	gint hnum;
	PrefsAccount *ac = NULL;

	g_return_val_if_fail(file != NULL, -1);

	if ((fp = fopen(file, "r")) == NULL) {
		FILE_OP_ERROR(file, "fopen");
		return -1;
	}

	while ((hnum = procheader_get_one_field(buf, sizeof(buf), fp, qentry))
	       != -1) {
		gchar *p = buf + strlen(qentry[hnum].name);

		switch (hnum) {
		case Q_SENDER:
			if (!from) from = g_strdup(p);
			break;
		case Q_SMTPSERVER:
			if (!server) server = g_strdup(p);
			break;
		case Q_RECIPIENTS:
			to_list = address_list_append(to_list, p);
			break;
		case Q_ACCOUNT_ID:
			ac = account_find_from_id(atoi(p));
			break;
		default:
		}
	}

	if (!to_list || !from) {
		g_warning(_("Queued message header is broken.\n"));
		val = -1;
	} else if (prefs_common.use_extsend && prefs_common.extsend_cmd) {
		val = send_message_local(prefs_common.extsend_cmd, fp);
	} else {
		gushort port;
		gchar *domain;

		if (!ac) {
			ac = account_find_from_smtp_server(from, server);
			if (!ac) {
				g_warning(_("Account not found. "
					    "Using current account...\n"));
				ac = cur_account;
			}
		}

		if (ac) {
#if USE_SSL
			port = ac->set_smtpport ? ac->smtpport :
				ac->ssl_smtp == SSL_SMTP_TUNNEL ?
				SSMTP_PORT : SMTP_PORT;
#else
			port = ac->set_smtpport ? ac->smtpport : SMTP_PORT;
#endif
			domain = ac->set_domain ? ac->domain : NULL;
#if USE_SSL
			val = send_message_smtp
				(to_list, from, ac->smtp_server, port, domain,
				 ac->userid, ac->passwd, ac->use_smtp_auth,
				 ac->ssl_smtp, fp);
#else
			val = send_message_smtp
				(to_list, from, ac->smtp_server, port, domain,
				 ac->userid, ac->passwd, ac->use_smtp_auth, fp);
#endif
		} else {
			g_warning(_("Account not found.\n"));
#if USE_SSL
			val = send_message_smtp
				(to_list, from, server, SMTP_PORT, NULL,
				 NULL, NULL, FALSE, FALSE, fp);
#else
			val = send_message_smtp
				(to_list, from, server, SMTP_PORT, NULL,
				 NULL, NULL, FALSE, fp);
#endif
		}
	}

	slist_free_strings(to_list);
	g_slist_free(to_list);
	g_free(from);
	g_free(server);
	fclose(fp);

	return val;
}

static gint send_message_local(const gchar *command, FILE *fp)
{
	FILE *pipefp;
	gchar buf[BUFFSIZE];

	g_return_val_if_fail(command != NULL, -1);
	g_return_val_if_fail(fp != NULL, -1);

	pipefp = popen(command, "w");
	if (!pipefp) {
		g_warning(_("Can't execute external command: %s\n"), command);
		return -1;
	}

	while (fgets(buf, sizeof(buf), fp) != NULL) {
		strretchomp(buf);
		/* escape when a dot appears on the top */
		if (buf[0] == '.')
			fputc('.', pipefp);
		fputs(buf, pipefp);
		fputc('\n', pipefp);
	}

	pclose(pipefp);

	return 0;
}

#define EXIT_IF_CANCELLED() \
{ \
	if (dialog->cancelled) { \
		sock_close(smtp_sock); \
		send_progress_dialog_destroy(dialog); \
		return -1; \
	} \
}

#define SEND_EXIT_IF_ERROR(f, s) \
{ \
	EXIT_IF_CANCELLED(); \
	if (!(f)) { \
		log_warning("Error occurred while %s\n", s); \
		sock_close(smtp_sock); \
		send_progress_dialog_destroy(dialog); \
		return -1; \
	} \
}

#define SEND_EXIT_IF_NOTOK(f, s) \
{ \
	EXIT_IF_CANCELLED(); \
	if ((f) != SM_OK) { \
		log_warning("Error occurred while %s\n", s); \
		if (smtp_quit(smtp_sock) != SM_OK) \
			log_warning("Error occurred while sending QUIT\n"); \
		sock_close(smtp_sock); \
		send_progress_dialog_destroy(dialog); \
		return -1; \
	} \
}

#if USE_SSL
static gint send_message_smtp(GSList *to_list, const gchar *from,
			      const gchar *server, gushort port,
			      const gchar *domain, const gchar *userid,
			      const gchar *passwd, gboolean use_smtp_auth,
			      SSLSMTPType ssl_type, FILE *fp)
#else
static gint send_message_smtp(GSList *to_list, const gchar *from,
			      const gchar *server, gushort port,
			      const gchar *domain, const gchar *userid,
			      const gchar *passwd, gboolean use_smtp_auth,
			      FILE *fp)
#endif
{
	SockInfo *smtp_sock = NULL;
	SendProgressDialog *dialog;
	GtkCList *clist;
	const gchar *text[3];
	gchar buf[BUFFSIZE];
	gchar str[BUFFSIZE];
	GSList *cur;
	gint size;
	gint bytes = 0;
	struct timeval tv_prev, tv_cur;

	g_return_val_if_fail(to_list != NULL, -1);
	g_return_val_if_fail(from != NULL, -1);
	g_return_val_if_fail(server != NULL, -1);
	g_return_val_if_fail(fp != NULL, -1);

	size = get_left_file_size(fp);
	if (size < 0) return -1;

	dialog = send_progress_dialog_create();

	text[0] = NULL;
	text[1] = server;
	text[2] = _("Standby");
	clist = GTK_CLIST(dialog->dialog->clist);
	gtk_clist_append(clist, (gchar **)text);

	g_snprintf(buf, sizeof(buf), _("Connecting to SMTP server: %s ..."),
		   server);
	log_message("%s\n", buf);
	progress_dialog_set_label(dialog->dialog, buf);
	gtk_clist_set_text(clist, 0, 2, _("Connecting"));
	GTK_EVENTS_FLUSH();

#if USE_SSL
	SEND_EXIT_IF_ERROR((smtp_sock = send_smtp_open
				(server, port, domain, use_smtp_auth, ssl_type)),
			   "connecting to server");
#else
	SEND_EXIT_IF_ERROR((smtp_sock = send_smtp_open
				(server, port, domain, use_smtp_auth)),
			   "connecting to server");
#endif

	progress_dialog_set_label(dialog->dialog, _("Sending MAIL FROM..."));
	gtk_clist_set_text(clist, 0, 2, _("Sending"));
	GTK_EVENTS_FLUSH();

	SEND_EXIT_IF_NOTOK
		(smtp_from(smtp_sock, from, userid, passwd, use_smtp_auth),
		 "sending MAIL FROM");

	progress_dialog_set_label(dialog->dialog, _("Sending RCPT TO..."));
	GTK_EVENTS_FLUSH();

	for (cur = to_list; cur != NULL; cur = cur->next)
		SEND_EXIT_IF_NOTOK(smtp_rcpt(smtp_sock, (gchar *)cur->data),
				   "sending RCPT TO");

	progress_dialog_set_label(dialog->dialog, _("Sending DATA..."));
	GTK_EVENTS_FLUSH();

	SEND_EXIT_IF_NOTOK(smtp_data(smtp_sock), "sending DATA");

	gettimeofday(&tv_prev, NULL);

	/* send main part */
	while (fgets(buf, sizeof(buf), fp) != NULL) {
		bytes += strlen(buf);
		strretchomp(buf);

		gettimeofday(&tv_cur, NULL);
		if (tv_cur.tv_sec - tv_prev.tv_sec > 0 ||
		    tv_cur.tv_usec - tv_prev.tv_usec > UI_REFRESH_INTERVAL) {
			g_snprintf(str, sizeof(str),
				   _("Sending message (%d / %d bytes)"),
				   bytes, size);
			progress_dialog_set_label(dialog->dialog, str);
			progress_dialog_set_percentage
				(dialog->dialog, (gfloat)bytes / (gfloat)size);
			GTK_EVENTS_FLUSH();
			gettimeofday(&tv_prev, NULL);
		}

		/* escape when a dot appears on the top */
		if (buf[0] == '.')
			SEND_EXIT_IF_ERROR(sock_write(smtp_sock, ".", 1),
					   "sending data");

		SEND_EXIT_IF_ERROR(sock_puts(smtp_sock, buf), "sending data");
	}

	progress_dialog_set_label(dialog->dialog, _("Quitting..."));
	GTK_EVENTS_FLUSH();

	SEND_EXIT_IF_NOTOK(smtp_eom(smtp_sock), "terminating data");
	SEND_EXIT_IF_NOTOK(smtp_quit(smtp_sock), "sending QUIT");

	sock_close(smtp_sock);
	send_progress_dialog_destroy(dialog);

	return 0;
}

#if USE_SSL
static SockInfo *send_smtp_open(const gchar *server, gushort port,
				const gchar *domain, gboolean use_smtp_auth,
				SSLSMTPType ssl_type)
#else
static SockInfo *send_smtp_open(const gchar *server, gushort port,
				const gchar *domain, gboolean use_smtp_auth)
#endif
{
	SockInfo *sock;
	gint val;

	g_return_val_if_fail(server != NULL, NULL);

	if ((sock = sock_connect(server, port)) == NULL) {
		log_warning(_("Can't connect to SMTP server: %s:%d\n"),
			    server, port);
		return NULL;
	}

#if USE_SSL
	if (ssl_type == SSL_SMTP_TUNNEL && !ssl_init_socket(sock)) {
		log_warning(_("SSL connection failed"));
		sock_close(sock);
		return NULL;
	}
#endif

	if (smtp_ok(sock) != SM_OK) {
		log_warning(_("Error occurred while connecting to %s:%d\n"),
			    server, port);
		sock_close(sock);
		return NULL;
	}

#if USE_SSL
	val = smtp_helo(sock, domain ? domain : get_domain_name(),
			use_smtp_auth || ssl_type == SSL_SMTP_STARTTLS);
#else
	val = smtp_helo(sock, domain ? domain : get_domain_name(),
			use_smtp_auth);
#endif

	if (val != SM_OK) {
		log_warning(_("Error occurred while sending HELO\n"));
		sock_close(sock);
		return NULL;
	}

#if USE_SSL
	if (ssl_type == SSL_SMTP_STARTTLS) {
		val = esmtp_starttls(sock);
		if (val != SM_OK) {
			log_warning(_("Error occurred while sending STARTTLS\n"));
			sock_close(sock);
			return NULL;
		}
		if (!ssl_init_socket_with_method(sock, SSL_METHOD_TLSv1)) {
			sock_close(sock);
			return NULL;
		}
		val = esmtp_ehlo(sock, domain ? domain : get_domain_name());
		if (val != SM_OK) {
			log_warning(_("Error occurred while sending EHLO\n"));
			sock_close(sock);
			return NULL;
		}
	}
#endif

	return sock;
}


static SendProgressDialog *send_progress_dialog_create(void)
{
	SendProgressDialog *dialog;
	ProgressDialog *progress;

	dialog = g_new0(SendProgressDialog, 1);

	progress = progress_dialog_create();
	gtk_window_set_title(GTK_WINDOW(progress->window),
			     _("Sending message"));
	gtk_signal_connect(GTK_OBJECT(progress->cancel_btn), "clicked",
			   GTK_SIGNAL_FUNC(send_cancel), dialog);
	gtk_signal_connect(GTK_OBJECT(progress->window), "delete_event",
			   GTK_SIGNAL_FUNC(gtk_true), NULL);
	gtk_window_set_modal(GTK_WINDOW(progress->window), TRUE);
	manage_window_set_transient(GTK_WINDOW(progress->window));

	progress_dialog_set_value(progress, 0.0);

	gtk_widget_show_now(progress->window);

	dialog->dialog = progress;
	dialog->queue_list = NULL;
	dialog->cancelled = FALSE;

	return dialog;
}

static void send_progress_dialog_destroy(SendProgressDialog *dialog)
{
	g_return_if_fail(dialog != NULL);

	progress_dialog_destroy(dialog->dialog);
	g_free(dialog);
}

static void send_cancel(GtkWidget *widget, gpointer data)
{
	SendProgressDialog *dialog = data;

	dialog->cancelled = TRUE;
}
