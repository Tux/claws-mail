/*
 * Claws Mail -- a GTK+ based, lightweight, and fast e-mail client
 * Copyright (C) 2006-2018 Ricardo Mones and the Claws Mail Team
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
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

#ifdef HAVE_CONFIG_H
#  include "config.h"
#include "claws-features.h"
#endif

#include <glib.h>
#include <glib/gi18n.h>

#include "attachwarner.h"

#include "defs.h"
#include "attachwarner_prefs.h"
#include "prefs_common.h"
#include "prefs_gtk.h"

#define PREFS_BLOCK_NAME "AttachWarner"

AttachWarnerPrefs attwarnerprefs;

struct AttachWarnerPrefsPage
{
	PrefsPage page;
	
	GtkWidget *regexp_text;
	GtkWidget *skip_quotes_checkbox;
	GtkWidget *skip_forwards_and_redirections;
	GtkWidget *skip_signature;
	GtkWidget *case_sensitive_checkbox;
};

struct AttachWarnerPrefsPage attwarnerprefs_page;

static PrefParam param[] = {
	{"match_strings", N_("attach"), &attwarnerprefs.match_strings, P_STRING,
	 NULL, NULL, NULL},
	{"skip_quotes", "TRUE", &attwarnerprefs.skip_quotes, P_BOOL,
	 NULL, NULL, NULL},
	{"skip_forwards_and_redirections", "TRUE", &attwarnerprefs.skip_forwards_and_redirections, P_BOOL,
	 NULL, NULL, NULL},
	{"skip_signature", "TRUE", &attwarnerprefs.skip_signature, P_BOOL,
	 NULL, NULL, NULL},
	{"case_sensitive", "TRUE", &attwarnerprefs.case_sensitive, P_BOOL,
	 NULL, NULL, NULL},
	{NULL, NULL, NULL, P_OTHER, NULL, NULL, NULL}
};

static void attwarner_prefs_create_widget_func(PrefsPage * _page,
					   GtkWindow * window,
					   gpointer data)
{
	struct AttachWarnerPrefsPage *page = (struct AttachWarnerPrefsPage *) _page;
	GtkWidget *vbox, *vbox1, *vbox2;
	GtkWidget *frame;
	GtkWidget *label;
	GtkWidget *scrolledwin;
	GtkTextBuffer *buffer;
	GtkWidget *skip_quotes_checkbox;
	GtkWidget *skip_fwd_redir_checkbox;
	GtkWidget *skip_signature_checkbox;
	GtkWidget *case_sensitive_checkbox;

	vbox1 = gtk_vbox_new(FALSE, 6);
	vbox2 = gtk_vbox_new(FALSE, 6);
	
	label = gtk_label_new(_("One of the following regular expressions is matched (one per line)"));
	gtk_label_set_xalign(GTK_LABEL(label), 0.0);
	gtk_misc_set_padding(GTK_MISC(label), 2, 0);

	case_sensitive_checkbox = gtk_check_button_new_with_label(_("Expressions are case sensitive"));
	gtk_toggle_button_set_active(GTK_TOGGLE_BUTTON(case_sensitive_checkbox),
	    	 attwarnerprefs.case_sensitive);
	gtk_widget_show(case_sensitive_checkbox);

	CLAWS_SET_TIP(case_sensitive_checkbox,
			_("Case sensitive when matching for the regular expressions in the list"));
	page->case_sensitive_checkbox = case_sensitive_checkbox;

	page->regexp_text = gtk_text_view_new();
	buffer = gtk_text_view_get_buffer(GTK_TEXT_VIEW(page->regexp_text));
	gtk_text_buffer_set_text(buffer, attwarnerprefs.match_strings, -1);
	
	scrolledwin = gtk_scrolled_window_new(NULL, NULL);
	gtk_scrolled_window_set_policy
		(GTK_SCROLLED_WINDOW (scrolledwin),
		 GTK_POLICY_NEVER, GTK_POLICY_AUTOMATIC);
	gtk_scrolled_window_set_shadow_type
		(GTK_SCROLLED_WINDOW (scrolledwin), GTK_SHADOW_IN);
	gtk_container_set_border_width(GTK_CONTAINER(scrolledwin), 3);

	gtk_container_add(GTK_CONTAINER(scrolledwin), page->regexp_text);
	gtk_widget_set_size_request(page->regexp_text, -1, 100);

	gtk_box_pack_start(GTK_BOX(vbox1), label, FALSE, FALSE, 0);
	gtk_box_pack_start(GTK_BOX(vbox1), scrolledwin, FALSE, FALSE, 0);
	gtk_box_pack_start(GTK_BOX(vbox1), case_sensitive_checkbox, FALSE, FALSE, 0);
	
	skip_quotes_checkbox = gtk_check_button_new_with_label(_("Lines starting with quotation marks"));
	gtk_toggle_button_set_active(GTK_TOGGLE_BUTTON(skip_quotes_checkbox),
	    	 attwarnerprefs.skip_quotes);
	gtk_box_pack_start(GTK_BOX(vbox2), skip_quotes_checkbox, FALSE, FALSE, 0);
	gtk_widget_show(skip_quotes_checkbox);

	CLAWS_SET_TIP(skip_quotes_checkbox,
			_("Exclude quoted lines from checking for the regular expressions above. Note that handmade quotes cannot be distinguished from quotes generated by replying."));
	page->skip_quotes_checkbox = skip_quotes_checkbox;
	
	skip_fwd_redir_checkbox = gtk_check_button_new_with_label(_("Forwarded or redirected messages"));
	gtk_toggle_button_set_active(GTK_TOGGLE_BUTTON(skip_fwd_redir_checkbox),
	    	 attwarnerprefs.skip_forwards_and_redirections);
	gtk_box_pack_start(GTK_BOX(vbox2), skip_fwd_redir_checkbox, FALSE, FALSE, 0);
	gtk_widget_show(skip_fwd_redir_checkbox);

	CLAWS_SET_TIP(skip_fwd_redir_checkbox,
			_("Don't check for missing attachments when forwarding or redirecting messages"));
	page->skip_forwards_and_redirections = skip_fwd_redir_checkbox;

	skip_signature_checkbox = gtk_check_button_new_with_label(_("Signatures"));
	gtk_toggle_button_set_active(GTK_TOGGLE_BUTTON(skip_signature_checkbox),
	    	 attwarnerprefs.skip_signature);
	gtk_box_pack_start(GTK_BOX(vbox2), skip_signature_checkbox, FALSE, FALSE, 0);
	gtk_widget_show(skip_signature_checkbox);

	CLAWS_SET_TIP(skip_signature_checkbox,
			_("Exclude lines from the first signature-separator onwards from checking for the regular expressions above"));
	page->skip_signature = skip_signature_checkbox;
	
	vbox = gtk_vbox_new(FALSE, VSPACING);
	gtk_container_set_border_width (GTK_CONTAINER (vbox), VBOX_BORDER);

	PACK_FRAME (vbox, frame, _("Warn when"));
	gtk_container_set_border_width(GTK_CONTAINER(vbox1), 6);
	gtk_container_add(GTK_CONTAINER(frame), vbox1);

	PACK_FRAME (vbox, frame, _("Excluding"));
	gtk_container_set_border_width(GTK_CONTAINER(vbox2), 6);
	gtk_container_add(GTK_CONTAINER(frame), vbox2);

	gtk_widget_show_all(vbox);
	
	page->page.widget = vbox;
}

static void attwarner_prefs_destroy_widget_func(PrefsPage *_page)
{
}

static void attwarner_save_config(void)
{
	PrefFile *pfile;
	gchar *rcpath;

	debug_print("Saving AttachWarner Page\n");

	rcpath = g_strconcat(get_rc_dir(), G_DIR_SEPARATOR_S, COMMON_RC, NULL);
	pfile = prefs_write_open(rcpath);
	g_free(rcpath);
	if (!pfile || (prefs_set_block_label(pfile, PREFS_BLOCK_NAME) < 0))
		return;

	if (prefs_write_param(param, pfile->fp) < 0) {
		g_warning("failed to write AttachWarner configuration to file");
		prefs_file_close_revert(pfile);
		return;
	}
        if (fprintf(pfile->fp, "\n") < 0) {
		FILE_OP_ERROR(rcpath, "fprintf");
		prefs_file_close_revert(pfile);
	} else
	        prefs_file_close(pfile);
}


static void attwarner_prefs_save_func(PrefsPage * _page)
{
	struct AttachWarnerPrefsPage *page = (struct AttachWarnerPrefsPage *) _page;
	GtkTextBuffer *buffer;
	GtkTextIter start, end;
	gchar *tmp;
	buffer = gtk_text_view_get_buffer(GTK_TEXT_VIEW(page->regexp_text));
	
	g_free(attwarnerprefs.match_strings);
	
	gtk_text_buffer_get_start_iter(buffer, &start);
	gtk_text_buffer_get_end_iter(buffer, &end);
	
	tmp = gtk_text_buffer_get_text(buffer, &start, &end, FALSE);
	
	attwarnerprefs.match_strings = g_malloc(2*strlen(tmp)+1);
	pref_get_escaped_pref(attwarnerprefs.match_strings, tmp);

	attwarnerprefs.skip_quotes = gtk_toggle_button_get_active
			(GTK_TOGGLE_BUTTON(page->skip_quotes_checkbox));
	attwarnerprefs.skip_forwards_and_redirections = gtk_toggle_button_get_active
			(GTK_TOGGLE_BUTTON(page->skip_forwards_and_redirections));
	attwarnerprefs.skip_signature = gtk_toggle_button_get_active
			(GTK_TOGGLE_BUTTON(page->skip_signature));
	attwarnerprefs.case_sensitive = gtk_toggle_button_get_active
			(GTK_TOGGLE_BUTTON(page->case_sensitive_checkbox));

	attwarner_save_config();
	g_free(attwarnerprefs.match_strings);
	attwarnerprefs.match_strings = tmp;
}

void attachwarner_prefs_init(void)
{
	static gchar *path[3];
	gchar *rcpath;
	gchar *tmp;
	
	path[0] = _("Plugins");
	path[1] = _("Attach Warner");
	path[2] = NULL;

	prefs_set_default(param);
	rcpath = g_strconcat(get_rc_dir(), G_DIR_SEPARATOR_S, COMMON_RC, NULL);
	prefs_read_config(param, PREFS_BLOCK_NAME, rcpath, NULL);
	g_free(rcpath);

	tmp = g_malloc(strlen(attwarnerprefs.match_strings)+1);
	pref_get_unescaped_pref(tmp, attwarnerprefs.match_strings);
	
	g_free(attwarnerprefs.match_strings);
	attwarnerprefs.match_strings = tmp;
	
	attwarnerprefs_page.page.path = path;
	attwarnerprefs_page.page.create_widget = attwarner_prefs_create_widget_func;
	attwarnerprefs_page.page.destroy_widget = attwarner_prefs_destroy_widget_func;
	attwarnerprefs_page.page.save_page = attwarner_prefs_save_func;
	attwarnerprefs_page.page.weight = 40.0;

	prefs_gtk_register_page((PrefsPage *) &attwarnerprefs_page);
}

void attachwarner_prefs_done(void)
{
	prefs_gtk_unregister_page((PrefsPage *) &attwarnerprefs_page);
}
