/*
 * Sylpheed -- a GTK+ based, lightweight, and fast e-mail client
 * Copyright (C) 2002 by the Sylpheed Claws Team and Hiroyuki Yamamoto
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

#ifndef MATCHER_H
#define MATCHER_H

#include <sys/types.h>
#include <regex.h>
#include <glib.h>
#include "procmsg.h"

/* constants generated by yacc */
#if !defined(YYBISON) && !defined(MATCHER_ALL)
#	include "matcher_parser_parse.h"
#endif

struct _MatcherProp {
	int matchtype;
	int criteria;
	gchar *header;
	gchar *expr;
	int value;
	regex_t *preg;
	int error;
	gboolean result;
};

typedef struct _MatcherProp MatcherProp;

struct _MatcherList {
	GSList *matchers;
	gboolean bool_and;
};

typedef struct _MatcherList MatcherList;


/* map MATCHCRITERIA_ to yacc's MATCHER_ */
#define MC_(name) \
	MATCHCRITERIA_ ## name = MATCHER_ ## name

/* map MATCHTYPE_ to yacc's MATCHER_ */
#define MT_(name) \
	MATCHTYPE_ ## name = MATCHER_ ## name

/* map MATCHACTION_ to yacc's MATCHER_ */
#define MA_(name) \
	MATCHACTION_ ## name = MATCHER_ ## name

/* map MATCHBOOL_ to yacc's MATCHER_ */
#define MB_(name) \
	MATCHERBOOL_ ## name = MATCHER_ ## name

enum {
	/* match */
	MC_(ALL),
	MC_(UNREAD), MC_(NOT_UNREAD),
	MC_(NEW), MC_(NOT_NEW),
	MC_(MARKED), MC_(NOT_MARKED),
	MC_(DELETED), MC_(NOT_DELETED),
	MC_(REPLIED), MC_(NOT_REPLIED),
	MC_(FORWARDED), MC_(NOT_FORWARDED),
	MC_(LOCKED), MC_(NOT_LOCKED),
	MC_(COLORLABEL), MC_(NOT_COLORLABEL),
	MC_(SUBJECT), MC_(NOT_SUBJECT),
	MC_(FROM), MC_(NOT_FROM),
	MC_(TO), MC_(NOT_TO),
	MC_(CC), MC_(NOT_CC),
	MC_(TO_OR_CC), MC_(NOT_TO_AND_NOT_CC),
	MC_(AGE_GREATER), MC_(AGE_LOWER),
	MC_(NEWSGROUPS), MC_(NOT_NEWSGROUPS),
	MC_(INREPLYTO), MC_(NOT_INREPLYTO),
	MC_(REFERENCES), MC_(NOT_REFERENCES),
	MC_(SCORE_GREATER), MC_(SCORE_LOWER),
	MC_(HEADER), MC_(NOT_HEADER),
	MC_(HEADERS_PART), MC_(NOT_HEADERS_PART),
	MC_(MESSAGE), MC_(NOT_MESSAGE),
	MC_(BODY_PART), MC_(NOT_BODY_PART),
	MC_(EXECUTE), MC_(NOT_EXECUTE),
	MC_(SCORE_EQUAL),
	MC_(SIZE_GREATER), 
	MC_(SIZE_SMALLER),
	MC_(SIZE_EQUAL),
	/* match type */
	MT_(MATCHCASE),
	MT_(MATCH),
	MT_(REGEXPCASE),
	MT_(REGEXP),
	/* actions */
	MA_(SCORE),
	MA_(EXECUTE),
	MA_(MOVE),
	MA_(COPY),
	MA_(DELETE),
	MA_(MARK),
	MA_(UNMARK),
	MA_(MARK_AS_READ),
	MA_(MARK_AS_UNREAD),
	MA_(FORWARD),
	MA_(FORWARD_AS_ATTACHMENT),
	MA_(COLOR),
	MA_(REDIRECT),
	MA_(DELETE_ON_SERVER),
	/* boolean operations */
	MB_(OR),
	MB_(AND)
};

gchar *get_matchparser_tab_str		(gint id);
gint get_matchparser_tab_id		(const gchar *str); 

MatcherProp *matcherprop_new		(gint	 criteria, 
					 gchar	*header,
					 gint	 matchtype, 
					 gchar	*expr,
					 int	 age);
MatcherProp *matcherprop_unquote_new	(gint	 criteria, 
					 gchar	*header,
					 gint	 matchtype, 
					 gchar	*expr,
					 int	 value);
void matcherprop_free			(MatcherProp *prop);

MatcherProp *matcherprop_parse		(gchar	**str);

MatcherProp *matcherprop_copy		(MatcherProp *src);

gboolean matcherprop_match		(MatcherProp	*prop, 
					 MsgInfo	*info);

MatcherList * matcherlist_new		(GSList		*matchers, 
					 gboolean	bool_and);
void matcherlist_free			(MatcherList	*cond);

MatcherList *matcherlist_parse		(gchar		**str);

gboolean matcherlist_match		(MatcherList	*cond, 
					 MsgInfo	*info);

gint matcher_parse_keyword		(gchar		**str);
gint matcher_parse_number		(gchar		**str);
gboolean matcher_parse_boolean_op	(gchar		**str);
gchar *matcher_parse_regexp		(gchar		**str);
gchar *matcher_parse_str		(gchar		**str);
gchar *matcher_escape_str		(const gchar	*str);
gchar *matcher_unescape_str		(gchar		*str);
gchar *matcherprop_to_string		(MatcherProp	*matcher);
gchar *matcherlist_to_string		(MatcherList	*matchers);
gchar *matching_build_command		(gchar		*cmd, 
					 MsgInfo	*info);

void prefs_matcher_read_config		(void);
void prefs_matcher_write_config		(void);

#endif
