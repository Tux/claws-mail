/*
 * Sylpheed -- a GTK+ based, lightweight, and fast e-mail client
 * Copyright (C) 1999-2005 Hiroyuki Yamamoto
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
#include <glib/gi18n.h>
#include <gtk/gtk.h>
#include <gdk/gdkkeysyms.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>

#include "main.h"
#include "prefs_gtk.h"
#include "prefs_customheader.h"
#include "prefs_common.h"
#include "prefs_account.h"
#include "mainwindow.h"
#include "foldersel.h"
#include "manage_window.h"
#include "customheader.h"
#include "folder.h"
#include "utils.h"
#include "gtkutils.h"
#include "alertpanel.h"

enum {
	CUSTHDR_STRING,		/*!< display string managed by list store */
	CUSTHDR_DATA,		/*!< string managed by us */
	N_CUSTHDR_COLUMNS
};

static struct CustomHdr {
	GtkWidget *window;

	GtkWidget *ok_btn;
	GtkWidget *cancel_btn;

	GtkWidget *hdr_combo;
	GtkWidget *hdr_entry;
	GtkWidget *val_entry;
	GtkWidget *list_view;
} customhdr;

/* widget creating functions */
static void prefs_custom_header_create	(void);

static void prefs_custom_header_set_dialog		(PrefsAccount *ac);
static void prefs_custom_header_set_list		(PrefsAccount *ac);
static void prefs_custom_header_list_view_set_row	(PrefsAccount *ac);

/* callback functions */
static void prefs_custom_header_add_cb		(void);
static void prefs_custom_header_delete_cb	(void);
static void prefs_custom_header_up		(void);
static void prefs_custom_header_down		(void);

static gboolean prefs_custom_header_key_pressed	(GtkWidget	*widget,
						 GdkEventKey	*event,
						 gpointer	 data);
static void prefs_custom_header_ok		(void);
static void prefs_custom_header_cancel		(void);
static gint prefs_custom_header_deleted		(GtkWidget	*widget,
						 GdkEventAny	*event,
						 gpointer	 data);

static GtkListStore* prefs_custom_header_create_data_store	(void);

static void prefs_custom_header_list_view_insert_header	(GtkWidget *list_view,
							 GtkTreeIter *row_iter,
							 gchar *header,
							 gpointer data);

static GtkWidget *prefs_custom_header_list_view_create (void);

static void prefs_custom_header_create_list_view_columns	(GtkWidget *list_view);

static gboolean prefs_custom_header_selected	(GtkTreeSelection *selector,
						 GtkTreeModel *model, 
						 GtkTreePath *path,
						 gboolean currently_selected,
						 gpointer data);


static PrefsAccount *cur_ac = NULL;

void prefs_custom_header_open(PrefsAccount *ac)
{
	if (!customhdr.window) {
		prefs_custom_header_create();
	}

	manage_window_set_transient(GTK_WINDOW(customhdr.window));
	gtk_widget_grab_focus(customhdr.ok_btn);

	prefs_custom_header_set_dialog(ac);

	cur_ac = ac;

	gtk_widget_show(customhdr.window);
}

static void prefs_custom_header_create(void)
{
	GtkWidget *window;
	GtkWidget *vbox;

	GtkWidget *ok_btn;
	GtkWidget *cancel_btn;

	GtkWidget *confirm_area;

	GtkWidget *vbox1;

	GtkWidget *table1;
	GtkWidget *hdr_label;
	GtkWidget *hdr_combo;
	GtkWidget *val_label;
	GtkWidget *val_entry;

	GtkWidget *reg_hbox;
	GtkWidget *btn_hbox;
	GtkWidget *arrow;
	GtkWidget *add_btn;
	GtkWidget *del_btn;

	GtkWidget *ch_hbox;
	GtkWidget *ch_scrolledwin;
	GtkWidget *list_view;

	GtkWidget *btn_vbox;
	GtkWidget *up_btn;
	GtkWidget *down_btn;

	debug_print("Creating custom header setting window...\n");

	window = gtk_window_new (GTK_WINDOW_TOPLEVEL);
	gtk_container_set_border_width (GTK_CONTAINER (window), 8);
	gtk_window_set_position (GTK_WINDOW (window), GTK_WIN_POS_CENTER);
	gtk_window_set_modal (GTK_WINDOW (window), TRUE);
	gtk_window_set_resizable(GTK_WINDOW (window), TRUE);

	vbox = gtk_vbox_new (FALSE, 6);
	gtk_widget_show (vbox);
	gtk_container_add (GTK_CONTAINER (window), vbox);

	gtkut_stock_button_set_create(&confirm_area, &ok_btn, GTK_STOCK_OK,
				      &cancel_btn, GTK_STOCK_CANCEL,
				      NULL, NULL);
	gtk_widget_show (confirm_area);
	gtk_box_pack_end (GTK_BOX(vbox), confirm_area, FALSE, FALSE, 0);
	gtk_widget_grab_default (ok_btn);

	gtk_window_set_title (GTK_WINDOW(window), _("Custom header configuration"));
	MANAGE_WINDOW_SIGNALS_CONNECT (window);
	g_signal_connect (G_OBJECT(window), "delete_event",
			  G_CALLBACK(prefs_custom_header_deleted),
			  NULL);
	g_signal_connect (G_OBJECT(window), "key_press_event",
			  G_CALLBACK(prefs_custom_header_key_pressed),
			  NULL);
	g_signal_connect (G_OBJECT(ok_btn), "clicked",
			  G_CALLBACK(prefs_custom_header_ok), NULL);
	g_signal_connect (G_OBJECT(cancel_btn), "clicked",
			  G_CALLBACK(prefs_custom_header_cancel), NULL);

	vbox1 = gtk_vbox_new (FALSE, VSPACING);
	gtk_widget_show (vbox1);
	gtk_box_pack_start (GTK_BOX (vbox), vbox1, TRUE, TRUE, 0);
	gtk_container_set_border_width (GTK_CONTAINER (vbox1), 2);

	table1 = gtk_table_new (2, 2, FALSE);
	gtk_widget_show (table1);
	gtk_box_pack_start (GTK_BOX (vbox1), table1,
			    FALSE, FALSE, 0);
	gtk_table_set_row_spacings (GTK_TABLE (table1), 8);
	gtk_table_set_col_spacings (GTK_TABLE (table1), 8);

	hdr_label = gtk_label_new (_("Header"));
	gtk_widget_show (hdr_label);
	gtk_table_attach (GTK_TABLE (table1), hdr_label, 0, 1, 0, 1,
			  GTK_EXPAND | GTK_SHRINK | GTK_FILL,
			  0, 0, 0);
	gtk_misc_set_alignment (GTK_MISC (hdr_label), 0, 0.5);
	
	hdr_combo = gtk_combo_new ();
	gtk_widget_show (hdr_combo);
	gtk_table_attach (GTK_TABLE (table1), hdr_combo, 0, 1, 1, 2,
			  GTK_EXPAND | GTK_SHRINK | GTK_FILL,
			  0, 0, 0);
	gtk_widget_set_size_request (hdr_combo, 150, -1);
	gtkut_combo_set_items (GTK_COMBO (hdr_combo),
			       "User-Agent", "X-Face", "X-Operating-System",
			       NULL);

	val_label = gtk_label_new (_("Value"));
	gtk_widget_show (val_label);
	gtk_table_attach (GTK_TABLE (table1), val_label, 1, 2, 0, 1,
			  GTK_EXPAND | GTK_SHRINK | GTK_FILL,
			  0, 0, 0);
	gtk_misc_set_alignment (GTK_MISC (val_label), 0, 0.5);
	
	val_entry = gtk_entry_new ();
	gtk_widget_show (val_entry);
	gtk_table_attach (GTK_TABLE (table1), val_entry, 1, 2, 1, 2,
			  GTK_EXPAND | GTK_SHRINK | GTK_FILL,
			  0, 0, 0);
	gtk_widget_set_size_request (val_entry, 200, -1);

	/* add / delete */

	reg_hbox = gtk_hbox_new (FALSE, 4);
	gtk_widget_show (reg_hbox);
	gtk_box_pack_start (GTK_BOX (vbox1), reg_hbox, FALSE, FALSE, 0);

	arrow = gtk_arrow_new (GTK_ARROW_DOWN, GTK_SHADOW_OUT);
	gtk_widget_show (arrow);
	gtk_box_pack_start (GTK_BOX (reg_hbox), arrow, FALSE, FALSE, 0);
	gtk_widget_set_size_request (arrow, -1, 16);

	btn_hbox = gtk_hbox_new (TRUE, 4);
	gtk_widget_show (btn_hbox);
	gtk_box_pack_start (GTK_BOX (reg_hbox), btn_hbox, FALSE, FALSE, 0);

	add_btn = gtk_button_new_from_stock (GTK_STOCK_ADD);
	gtk_widget_show (add_btn);
	gtk_box_pack_start (GTK_BOX (btn_hbox), add_btn, FALSE, TRUE, 0);
	g_signal_connect (G_OBJECT (add_btn), "clicked",
			  G_CALLBACK (prefs_custom_header_add_cb),
			  NULL);

	del_btn = gtk_button_new_from_stock (GTK_STOCK_DELETE);
	gtk_widget_show (del_btn);
	gtk_box_pack_start (GTK_BOX (btn_hbox), del_btn, FALSE, TRUE, 0);
	g_signal_connect (G_OBJECT (del_btn), "clicked",
			  G_CALLBACK (prefs_custom_header_delete_cb),
			  NULL);


	ch_hbox = gtk_hbox_new (FALSE, 8);
	gtk_widget_show (ch_hbox);
	gtk_box_pack_start (GTK_BOX (vbox1), ch_hbox, TRUE, TRUE, 0);

	ch_scrolledwin = gtk_scrolled_window_new (NULL, NULL);
	gtk_widget_set_size_request (ch_scrolledwin, -1, 200);
	gtk_widget_show (ch_scrolledwin);
	gtk_box_pack_start (GTK_BOX (ch_hbox), ch_scrolledwin, TRUE, TRUE, 0);
	gtk_scrolled_window_set_policy (GTK_SCROLLED_WINDOW (ch_scrolledwin),
					GTK_POLICY_AUTOMATIC,
					GTK_POLICY_AUTOMATIC);

	list_view = prefs_custom_header_list_view_create();
	gtk_widget_show (list_view);
	gtk_container_add (GTK_CONTAINER (ch_scrolledwin), list_view);

	btn_vbox = gtk_vbox_new (FALSE, 8);
	gtk_widget_show (btn_vbox);
	gtk_box_pack_start (GTK_BOX (ch_hbox), btn_vbox, FALSE, FALSE, 0);

	up_btn = gtk_button_new_from_stock (GTK_STOCK_GO_UP);
	gtk_widget_show (up_btn);
	gtk_box_pack_start (GTK_BOX (btn_vbox), up_btn, FALSE, FALSE, 0);
	g_signal_connect (G_OBJECT (up_btn), "clicked",
			  G_CALLBACK (prefs_custom_header_up), NULL);

	down_btn = gtk_button_new_from_stock (GTK_STOCK_GO_DOWN);
	gtk_widget_show (down_btn);
	gtk_box_pack_start (GTK_BOX (btn_vbox), down_btn, FALSE, FALSE, 0);
	g_signal_connect (G_OBJECT (down_btn), "clicked",
			  G_CALLBACK (prefs_custom_header_down), NULL);

	gtk_widget_show_all(window);

	customhdr.window     = window;
	customhdr.ok_btn     = ok_btn;
	customhdr.cancel_btn = cancel_btn;

	customhdr.hdr_combo  = hdr_combo;
	customhdr.hdr_entry  = GTK_COMBO (hdr_combo)->entry;
	customhdr.val_entry  = val_entry;

	customhdr.list_view   = list_view;
}

void prefs_custom_header_read_config(PrefsAccount *ac)
{
	gchar *rcpath;
	FILE *fp;
	gchar buf[PREFSBUFSIZE];
	CustomHeader *ch;

	debug_print("Reading custom header configuration...\n");

	rcpath = g_strconcat(get_rc_dir(), G_DIR_SEPARATOR_S,
			     CUSTOM_HEADER_RC, NULL);
	if ((fp = fopen(rcpath, "rb")) == NULL) {
		if (ENOENT != errno) FILE_OP_ERROR(rcpath, "fopen");
		g_free(rcpath);
		ac->customhdr_list = NULL;
		return;
	}
	g_free(rcpath);

	/* remove all previous headers list */
	while (ac->customhdr_list != NULL) {
		ch = (CustomHeader *)ac->customhdr_list->data;
		custom_header_free(ch);
		ac->customhdr_list = g_slist_remove(ac->customhdr_list, ch);
	}

	while (fgets(buf, sizeof(buf), fp) != NULL) {
		ch = custom_header_read_str(buf);
		if (ch) {
			if (ch->account_id == ac->account_id) {
				ac->customhdr_list =
					g_slist_append(ac->customhdr_list, ch);
			} else
				custom_header_free(ch);
		}
	}

	fclose(fp);
}

void prefs_custom_header_write_config(PrefsAccount *ac)
{
	gchar *rcpath;
	PrefFile *pfile;
	GSList *cur;
	gchar buf[PREFSBUFSIZE];
	FILE * fp;
	CustomHeader *ch;

	GSList *all_hdrs = NULL;

	debug_print("Writing custom header configuration...\n");

	rcpath = g_strconcat(get_rc_dir(), G_DIR_SEPARATOR_S,
			     CUSTOM_HEADER_RC, NULL);

	if ((fp = fopen(rcpath, "rb")) == NULL) {
		if (ENOENT != errno) FILE_OP_ERROR(rcpath, "fopen");
	} else {
		all_hdrs = NULL;

		while (fgets(buf, sizeof(buf), fp) != NULL) {
			ch = custom_header_read_str(buf);
			if (ch) {
				if (ch->account_id != ac->account_id)
					all_hdrs =
						g_slist_append(all_hdrs, ch);
				else
					custom_header_free(ch);
			}
		}

		fclose(fp);
	}

	if ((pfile = prefs_write_open(rcpath)) == NULL) {
		g_warning("failed to write configuration to file\n");
		g_free(rcpath);
		return;
	}

	for (cur = all_hdrs; cur != NULL; cur = cur->next) {
 		CustomHeader *hdr = (CustomHeader *)cur->data;
		gchar *chstr;

		chstr = custom_header_get_str(hdr);
		if (fputs(chstr, pfile->fp) == EOF ||
		    fputc('\n', pfile->fp) == EOF) {
			FILE_OP_ERROR(rcpath, "fputs || fputc");
			prefs_file_close_revert(pfile);
			g_free(rcpath);
			g_free(chstr);
			return;
		}
		g_free(chstr);
	}

	for (cur = ac->customhdr_list; cur != NULL; cur = cur->next) {
 		CustomHeader *hdr = (CustomHeader *)cur->data;
		gchar *chstr;

		chstr = custom_header_get_str(hdr);
		if (fputs(chstr, pfile->fp) == EOF ||
		    fputc('\n', pfile->fp) == EOF) {
			FILE_OP_ERROR(rcpath, "fputs || fputc");
			prefs_file_close_revert(pfile);
			g_free(rcpath);
			g_free(chstr);
			return;
		}
		g_free(chstr);
	}

	g_free(rcpath);

 	while (all_hdrs != NULL) {
 		ch = (CustomHeader *)all_hdrs->data;
 		custom_header_free(ch);
 		all_hdrs = g_slist_remove(all_hdrs, ch);
 	}

	if (prefs_file_close(pfile) < 0) {
		g_warning("failed to write configuration to file\n");
		return;
	}
}

static void prefs_custom_header_set_dialog(PrefsAccount *ac)
{
	GtkListStore *store;
	GSList *cur;
	
	store = GTK_LIST_STORE(gtk_tree_view_get_model
				(GTK_TREE_VIEW(customhdr.list_view)));
	gtk_list_store_clear(store);

	for (cur = ac->customhdr_list; cur != NULL; cur = cur->next) {
 		CustomHeader *ch = (CustomHeader *)cur->data;
		gchar *ch_str;

		ch_str = g_strdup_printf("%s: %s", ch->name,
					 ch->value ? ch->value : "");

		prefs_custom_header_list_view_insert_header
			(customhdr.list_view, NULL, ch_str, ch);						 

		g_free(ch_str);
	}
}

static void prefs_custom_header_set_list(PrefsAccount *ac)
{
	CustomHeader *ch;
	GtkTreeIter iter;
	GtkListStore *store;

	g_slist_free(ac->customhdr_list);
	ac->customhdr_list = NULL;

	store = GTK_LIST_STORE(gtk_tree_view_get_model
				(GTK_TREE_VIEW(customhdr.list_view)));

	if (gtk_tree_model_get_iter_first(GTK_TREE_MODEL(store), &iter)) {
		do {
			gtk_tree_model_get(GTK_TREE_MODEL(store), &iter,
					   CUSTHDR_DATA, &ch,
					   -1);
			ac->customhdr_list = g_slist_append(ac->customhdr_list, ch);
		} while (gtk_tree_model_iter_next(GTK_TREE_MODEL(store),
						  &iter));
	}
}

static void prefs_custom_header_list_view_set_row(PrefsAccount *ac)
{
	CustomHeader *ch;
	const gchar *entry_text;
	gchar *ch_str;
	GtkListStore *store;

	store = GTK_LIST_STORE(gtk_tree_view_get_model
				(GTK_TREE_VIEW(customhdr.list_view)));

	entry_text = gtk_entry_get_text(GTK_ENTRY(customhdr.hdr_entry));
	if (entry_text[0] == '\0') {
		alertpanel_error(_("Header name is not set."));
		return;
	}
	if (!custom_header_is_allowed(entry_text)) {
		alertpanel_error(_("This Header name is not allowed as a custom header."));
		return;
	}

	ch = g_new0(CustomHeader, 1);

	ch->account_id = ac->account_id;

	ch->name = g_strdup(entry_text);
	unfold_line(ch->name);
	g_strstrip(ch->name);
	gtk_entry_set_text(GTK_ENTRY(customhdr.hdr_entry), ch->name);

	entry_text = gtk_entry_get_text(GTK_ENTRY(customhdr.val_entry));
	if (entry_text[0] != '\0') {
		ch->value = g_strdup(entry_text);
		unfold_line(ch->value);
		g_strstrip(ch->value);
		gtk_entry_set_text(GTK_ENTRY(customhdr.val_entry), ch->value);
	}

	ch_str = g_strdup_printf("%s: %s", ch->name,
				 ch->value ? ch->value : "");
	
	prefs_custom_header_list_view_insert_header
		(customhdr.list_view, NULL, ch_str, ch);
	
	g_free(ch_str);

	prefs_custom_header_set_list(cur_ac);

}

static void prefs_custom_header_add_cb(void)
{
	prefs_custom_header_list_view_set_row(cur_ac);
}

static void prefs_custom_header_delete_cb(void)
{
	GtkTreeIter sel;
	GtkTreeModel *model;
	CustomHeader *ch;

	if (!gtk_tree_selection_get_selected(gtk_tree_view_get_selection
				(GTK_TREE_VIEW(customhdr.list_view)),
				&model, &sel))
		return;	

	if (alertpanel(_("Delete header"),
		       _("Do you really want to delete this header?"),
		       GTK_STOCK_YES, GTK_STOCK_NO, NULL) != G_ALERTDEFAULT)
		return;

	gtk_tree_model_get(model, &sel,
			   CUSTHDR_DATA, &ch,
			   -1);
	gtk_list_store_remove(GTK_LIST_STORE(model), &sel);

	cur_ac->customhdr_list = g_slist_remove(cur_ac->customhdr_list, ch);
	
	custom_header_free(ch);
}

static void prefs_custom_header_up(void)
{
	GtkTreePath *prev, *sel;
	GtkTreeIter isel;
	GtkListStore *store;
	GtkTreeIter iprev;
	
	if (!gtk_tree_selection_get_selected
		(gtk_tree_view_get_selection
			(GTK_TREE_VIEW(customhdr.list_view)),
		 (GtkTreeModel **) &store,
		 &isel))
		return;

	sel = gtk_tree_model_get_path(GTK_TREE_MODEL(store), &isel);
	if (!sel)
		return;
	
	/* no move if we're at row 0... */
	prev = gtk_tree_path_copy(sel);
	if (!gtk_tree_path_prev(prev)) {
		gtk_tree_path_free(prev);
		gtk_tree_path_free(sel);
		return;
	}

	gtk_tree_model_get_iter(GTK_TREE_MODEL(store),
				&iprev, prev);
	gtk_tree_path_free(sel);
	gtk_tree_path_free(prev);

	gtk_list_store_swap(store, &iprev, &isel);
	prefs_custom_header_set_list(cur_ac);
}

static void prefs_custom_header_down(void)
{
	GtkListStore *store;
	GtkTreeIter next, sel;
	
	if (!gtk_tree_selection_get_selected
		(gtk_tree_view_get_selection
			(GTK_TREE_VIEW(customhdr.list_view)),
		 (GtkTreeModel **) &store,
		 &sel))
		return;

	next = sel;
	if (!gtk_tree_model_iter_next(GTK_TREE_MODEL(store), &next)) 
		return;

	gtk_list_store_swap(store, &next, &sel);
	prefs_custom_header_set_list(cur_ac);
}

static gboolean prefs_custom_header_key_pressed(GtkWidget *widget,
						GdkEventKey *event,
						gpointer data)
{
	if (event && event->keyval == GDK_Escape)
		prefs_custom_header_cancel();
	return FALSE;
}

static void prefs_custom_header_ok(void)
{
	prefs_custom_header_write_config(cur_ac);
	gtk_widget_hide(customhdr.window);
}

static void prefs_custom_header_cancel(void)
{
	prefs_custom_header_read_config(cur_ac); 
	gtk_widget_hide(customhdr.window);
}

static gint prefs_custom_header_deleted(GtkWidget *widget, GdkEventAny *event,
					gpointer data)
{
	prefs_custom_header_cancel();
	return TRUE;
}

static GtkListStore* prefs_custom_header_create_data_store(void)
{
	return gtk_list_store_new(N_CUSTHDR_COLUMNS,
				  G_TYPE_STRING,	
				  G_TYPE_POINTER,
				  -1);
}

static void prefs_custom_header_list_view_insert_header(GtkWidget *list_view,
							GtkTreeIter *row_iter,
							gchar *header,
							gpointer data)
{
	GtkTreeIter iter;
	GtkListStore *list_store = GTK_LIST_STORE(gtk_tree_view_get_model
					(GTK_TREE_VIEW(list_view)));

	if (row_iter == NULL) {
		/* append new */
		gtk_list_store_append(list_store, &iter);
		gtk_list_store_set(list_store, &iter,
				   CUSTHDR_STRING, header,
				   CUSTHDR_DATA,   data,
				   -1);
	} else {
		/* change existing */
		CustomHeader *old_data;

		gtk_tree_model_get(GTK_TREE_MODEL(list_store), row_iter,
				   CUSTHDR_DATA, &old_data,
				   -1);

		custom_header_free(old_data);
		
		gtk_list_store_set(list_store, row_iter,
				   CUSTHDR_STRING, header,
				   CUSTHDR_DATA, data,
				   -1);
	}
}

static GtkWidget *prefs_custom_header_list_view_create(void)
{
	GtkTreeView *list_view;
	GtkTreeSelection *selector;
	GtkTreeModel *model;

	model = GTK_TREE_MODEL(prefs_custom_header_create_data_store());
	list_view = GTK_TREE_VIEW(gtk_tree_view_new_with_model(model));
	g_object_unref(model);	
	
	gtk_tree_view_set_rules_hint(list_view, prefs_common.enable_rules_hint);
	
	selector = gtk_tree_view_get_selection(list_view);
	gtk_tree_selection_set_mode(selector, GTK_SELECTION_BROWSE);
	gtk_tree_selection_set_select_function(selector, prefs_custom_header_selected,
					       NULL, NULL);

	/* create the columns */
	prefs_custom_header_create_list_view_columns(GTK_WIDGET(list_view));

	return GTK_WIDGET(list_view);
}

static void prefs_custom_header_create_list_view_columns(GtkWidget *list_view)
{
	GtkTreeViewColumn *column;
	GtkCellRenderer *renderer;

	renderer = gtk_cell_renderer_text_new();
	column = gtk_tree_view_column_new_with_attributes
		(_("Current custom headers"),
		 renderer,
		 "text", CUSTHDR_STRING,
		 NULL);
	gtk_tree_view_append_column(GTK_TREE_VIEW(list_view), column);		
}

#define ENTRY_SET_TEXT(entry, str) \
	gtk_entry_set_text(GTK_ENTRY(entry), str ? str : "")

static gboolean prefs_custom_header_selected(GtkTreeSelection *selector,
					     GtkTreeModel *model, 
					     GtkTreePath *path,
					     gboolean currently_selected,
					     gpointer data)
{
	GtkTreeIter iter;
	CustomHeader *ch;
	CustomHeader default_ch = { 0, "", NULL };

	if (currently_selected)
		return TRUE;

	if (!gtk_tree_model_get_iter(model, &iter, path))
		return TRUE;

	gtk_tree_model_get(model, &iter, 
			   CUSTHDR_DATA, &ch,
			   -1);
	
	if (!ch) ch = &default_ch;

	ENTRY_SET_TEXT(customhdr.hdr_entry, ch->name);
	ENTRY_SET_TEXT(customhdr.val_entry, ch->value);
			   
	return TRUE;
}

#undef ENTRY_SET_TEXT
