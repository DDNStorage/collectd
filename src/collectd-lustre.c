/**
 * collectd - src/lustre.c
 * Copyright (C) 2014  Li Xi
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License as published by the
 * Free Software Foundation; only version 2 of the License is applicable.
 *
 * This program is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License along
 * with this program; if not, write to the Free Software Foundation, Inc.,
 * 51 Franklin St, Fifth Floor, Boston, MA  02110-1301 USA
 *
 * Authors:
 *   Li Xi <lixi at ddn.com>
 **/

#if HAVE_CONFIG_H
# include "config.h"
#endif

#include <stdlib.h>
#include <unistd.h>
#include <stdio.h>
#include <string.h>
#include <strings.h>
#include <assert.h>
#include <errno.h>
#include <curses.h>
#include <limits.h>
#include <ctype.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>
#include "lustre_config.h"
#include "lustre_common.h"
#include "liboconfig/oconfig.h"

static void usage(const char *name)
{
	fprintf(stderr,
		"Usage: %s config_file\n",
		name);
} /* void usage */

/* error return codes */
enum {
	LDIALOG_ERROR = KEY_MAX + 1,
	LDIALOG_AGAIN,
	LDIALOG_HELP,
	LDIALOG_ESCAPE,
	LDIALOG_ENTER,
};
#define KEY_ESC 27
#define KEY_TAB 9

struct ldialog_color {
	chtype	ldc_attribute;	/* Color attribute */
	int	ldc_foreground;	/* foreground */
	int	ldc_background;	/* background */
	int	ldc_highlight;	/* highlight this item */
};

struct ldialog_info {
	/* Only used by menu */
	int			 ldi_menu_offset_y;
	/* Only used by menu */
	int			 ldi_item_offset_y;
	/* Used by menu and input box */
	int			 ldi_active_button;
	/* Only used by input box */
	int			 ldi_input_active;
	/* Only used by input box */
	int			 ldi_input_scroll;
	struct ldialog_info	*ldi_child;
	struct ldialog_info	*ldi_parent;
};

struct ldialog {
	char			*ld_filename;
	int			 ld_start_y;
	int			 ld_start_x;
	int			 ld_heigth;
	int			 ld_width;
	char			 ld_backtitle[PATH_MAX * 2 + 128];
	const char		*ld_title;
	struct lustre_entry	*ld_entry;
	struct lustre_item_type	*ld_item_type;
	struct lustre_item	*ld_item;
	struct lustre_item_rule	*ld_item_rule;
	int			 ld_new_item_rule;
	struct ldialog_color	 ld_color_screen;
	struct ldialog_color	 ld_color_dialog;
	struct ldialog_color	 ld_color_border;
	struct ldialog_color	 ld_color_menubox_border;
	struct ldialog_color	 ld_color_menubox;
	struct ldialog_color	 ld_color_title;
	struct ldialog_color	 ld_color_item_selected;
	struct ldialog_color	 ld_color_item;
	struct ldialog_color	 ld_color_button_active;
	struct ldialog_color	 ld_color_button_inactive;
	struct ldialog_color	 ld_color_button_label_active;
	struct ldialog_color	 ld_color_button_label_inactive;
	struct ldialog_color	 ld_color_button_key_active;
	struct ldialog_color	 ld_color_button_key_inactive;
	struct ldialog_color	 ld_color_down_arrow;
	struct ldialog_color	 ld_color_up_arrow;
	struct ldialog_color	 ld_color_inputbox;
	struct ldialog_info	 ld_info_root;
	/* The tail of info list */
	struct ldialog_info	*ld_info_current;
};

struct ldialog_info *ldialog_info_init()
{
	struct ldialog_info *info;
	info = calloc(1, sizeof(struct ldialog_info));
	return info;
}

void ldialog_info_fini(struct ldialog_info *info)
{
	free(info);
}

int ldialog_info_push(struct ldialog *dialog)
{
	struct ldialog_info *child;

	child = ldialog_info_init();
	if (child == NULL) {
		return -1;
	}
	dialog->ld_info_current->ldi_child = child;
	child->ldi_parent = dialog->ld_info_current;
	dialog->ld_info_current = child;
	return 0;
}

void ldialog_info_pop(struct ldialog *dialog)
{
	struct ldialog_info *parent;
	assert(dialog->ld_info_current != &dialog->ld_info_root);
	parent = dialog->ld_info_current->ldi_parent;
	parent->ldi_child = NULL;
	ldialog_info_fini(dialog->ld_info_current);
	dialog->ld_info_current = parent;
}

/*
 * Set window to attribute 'attr'
 */
static void ldialog_attr_clear(WINDOW *win, int height,
			       int width, chtype attr)
{
	int i, j;

	wattrset(win, attr);
	for (i = 0; i < height; i++) {
		wmove(win, i, 0);
		for (j = 0; j < width; j++)
			waddch(win, ' ');
	}
	touchwin(win);
}

static void ldialog_clear(struct ldialog *dialog)
{
	ldialog_attr_clear(stdscr, LINES, COLS,
			   dialog->ld_color_screen.ldc_attribute);
	if (dialog->ld_backtitle != NULL) {
		int i;

		wattrset(stdscr, dialog->ld_color_screen.ldc_attribute);
		mvwaddstr(stdscr, 0, 1, dialog->ld_backtitle);
		wmove(stdscr, 1, 1);
		for (i = 1; i < COLS - 1; i++) {
			waddch(stdscr, ACS_HLINE);
		}
	}
	wnoutrefresh(stdscr);
}

/*
 * Draw a rectangular box with line drawing characters
 */
void
ldialog_draw_box(WINDOW * win, int y, int x,
		 int height, int width,
		 chtype box, chtype border)
{
	int i, j;

	wattrset(win, 0);
	for (i = 0; i < height; i++) {
		wmove(win, y + i, x);
		for (j = 0; j < width; j++)
			if (!i && !j)
				waddch(win, border | ACS_ULCORNER);
			else if (i == height - 1 && !j)
				waddch(win, border | ACS_LLCORNER);
			else if (!i && j == width - 1)
				waddch(win, box | ACS_URCORNER);
			else if (i == height - 1 && j == width - 1)
				waddch(win, box | ACS_LRCORNER);
			else if (!i)
				waddch(win, border | ACS_HLINE);
			else if (i == height - 1)
				waddch(win, box | ACS_HLINE);
			else if (!j)
				waddch(win, border | ACS_VLINE);
			else if (j == width - 1)
				waddch(win, box | ACS_VLINE);
			else
				waddch(win, box | ' ');
	}
}

#define	MIN(a, b) (((a) < (b)) ? (a) : (b))
#define	MAX(a, b) (((a) > (b)) ? (a) : (b))

/* Print the title of the dialog. Center the title and truncate
 * tile if wider than dialog (- 2 chars).
 **/
void ldialog_print_title(struct ldialog *dialog,
			 WINDOW *window, const char *title, int width)
{
	if (title) {
		int tlen = MIN(width - 2, strlen(title));
		wattrset(window, dialog->ld_color_title.ldc_attribute);
		mvwaddch(window, 0, (width - tlen) / 2 - 1, ' ');
		mvwaddnstr(window, 0, (width - tlen)/2, title, tlen);
		waddch(window, ' ');
	}
}

#define MAX_LEN 2048
/*
 * Print a string of text in a window, automatically wrap around to the
 * next line if the string is too long to fit on one line. Newline
 * characters '\n' are replaced by spaces.  We start on a new line
 * if there is no room for at least 4 nonblanks following a double-space.
 */
void ldialog_print_autowrap(WINDOW * win, const char *prompt, int width, int y, int x)
{
	int newl, cur_x, cur_y;
	int i, prompt_len, room, wlen;
	char tempstr[MAX_LEN + 1], *word, *sp, *sp2;

	strcpy(tempstr, prompt);

	prompt_len = strlen(tempstr);

	/*
	 * Remove newlines
	 */
	for (i = 0; i < prompt_len; i++) {
		if (tempstr[i] == '\n')
			tempstr[i] = ' ';
	}

	if (prompt_len <= width - x * 2) {	/* If prompt is short */
		wmove(win, y, (width - prompt_len) / 2);
		waddstr(win, tempstr);
	} else {
		cur_x = x;
		cur_y = y;
		newl = 1;
		word = tempstr;
		while (word && *word) {
			sp = strchr(word, ' ');
			if (sp)
				*sp++ = 0;

			/* Wrap to next line if either the word does not fit,
			   or it is the first word of a new sentence, and it is
			   short, and the next word does not fit. */
			room = width - cur_x;
			wlen = strlen(word);
			if (wlen > room ||
			    (newl && wlen < 4 && sp
			     && wlen + 1 + strlen(sp) > room
			     && (!(sp2 = strchr(sp, ' '))
				 || wlen + 1 + (sp2 - sp) > room))) {
				cur_y++;
				cur_x = x;
			}
			wmove(win, cur_y, cur_x);
			waddstr(win, word);
			getyx(win, cur_y, cur_x);
			cur_x++;
			if (sp && *sp == ' ') {
				cur_x++;	/* double space */
				while (*++sp == ' ') ;
				newl = 1;
			} else
				newl = 0;
			word = sp;
		}
	}
}

/*
 * Print a button
 */
void ldialog_print_button(struct ldialog *dialog,
			  WINDOW *win, const char *label,
			  int y, int x, int selected)
{
	int i, temp;

	wmove(win, y, x);
	wattrset(win, selected ?
		 dialog->ld_color_button_active.ldc_attribute
		 : dialog->ld_color_button_inactive.ldc_attribute);
	waddstr(win, "<");
	temp = strspn(label, " ");
	label += temp;
	wattrset(win, selected ?
		 dialog->ld_color_button_label_active.ldc_attribute
		 : dialog->ld_color_button_label_inactive.ldc_attribute);
	for (i = 0; i < temp; i++)
		waddch(win, ' ');
	wattrset(win, selected ?
		 dialog->ld_color_button_key_active.ldc_attribute
		 : dialog->ld_color_button_key_inactive.ldc_attribute);
	waddch(win, label[0]);
	wattrset(win, selected ?
		 dialog->ld_color_button_label_active.ldc_attribute
		 : dialog->ld_color_button_label_inactive.ldc_attribute);
	waddstr(win, (char *)label + 1);
	wattrset(win, selected ?
		 dialog->ld_color_button_active.ldc_attribute
		 : dialog->ld_color_button_inactive.ldc_attribute);
	waddstr(win, ">");
	wmove(win, y, x + temp + 1);
}

/*
 *  Print the termination buttons
 */
static void ldialog_print_buttons_ok(struct ldialog *dialog,
				     WINDOW * win,
				     int height, int width,
				     int selected)
{
	int x = width / 2 - 5;
	int y = height - 2;

	ldialog_print_button(dialog, win, "   Ok   ", y, x, selected == 1);

	if (selected) {
		wmove(win, y, x + 1);
	}
	wrefresh(win);
}

static void ldialog_message(struct ldialog *dialog,
			    const char *title,
			    const char *message)
{
	int key = 0;
	int height, width;
	int x, y;
	WINDOW *window_dialog;
	int i;

	height = 6;
	width = 75;
resize:
	if (getmaxy(stdscr) <= (height - 2) ||
	    getmaxx(stdscr) <= (width - 2))
		return;

	/* center dialog box on screen */
	x = (COLS - width) / 2;
	y = (LINES - height) / 2;

	window_dialog = newwin(height, width, y, x);
	keypad(window_dialog, TRUE);

	/* TODO: draw shadow */

	ldialog_draw_box(window_dialog, 0, 0, height, width,
			 dialog->ld_color_dialog.ldc_attribute,
			 dialog->ld_color_border.ldc_attribute);
	wattrset(window_dialog, dialog->ld_color_border.ldc_attribute);
	/* Add a line on the bottom to give space for Select/Eixt/Help */
	mvwaddch(window_dialog, height - 3, 0, ACS_LTEE);
	for (i = 0; i < width - 2; i++)
		waddch(window_dialog, ACS_HLINE);
	wattrset(window_dialog,
		 dialog->ld_color_dialog.ldc_attribute);
	wbkgdset(window_dialog,
		 dialog->ld_color_dialog.ldc_attribute & A_COLOR);
	waddch(window_dialog, ACS_RTEE);

	ldialog_print_title(dialog, window_dialog,
			    title, width);

	wattrset(window_dialog, dialog->ld_color_dialog.ldc_attribute);
	ldialog_print_autowrap(window_dialog, message,
			       width - 2, 1, 3);

	ldialog_clear(dialog);

	ldialog_print_buttons_ok(dialog,
		window_dialog,
		height, width, 1);

	while (1) {
		key = wgetch(window_dialog);

		switch(key) {
		case ' ':
		case '\n':
		case 'q':
		case 'x':
		case 'e':
		case KEY_ESC:
			goto out;
		case KEY_RESIZE:
			delwin(window_dialog);
			goto resize;
		}
	}
out:
	delwin(window_dialog);
	return;
}

static int ldialog_nchoice_entry_or_item_type(struct ldialog *dialog)
{
	struct lustre_entry *entry = dialog->ld_entry;
	struct lustre_entry *child;
	struct lustre_item_type *item;
	int count = 0;

	list_for_each_entry(item,
	                    &entry->le_item_types,
	                    lit_linkage) {
		count++;
	}

	list_for_each_entry(child,
	                    &entry->le_children,
	                    le_linkage) {
		count++;
	}
	return count;
}

static int ldialog_nchoice_item(struct ldialog *dialog)
{
	struct lustre_item_type *type = dialog->ld_item_type;
	struct lustre_item *item;
	int count = 0;

	list_for_each_entry(item,
			    &type->lit_items,
			    li_linkage) {
		count++;
	}
	/* Choice for new item */
	count++;
	return count;
}

static int ldialog_nchoice_rule(struct ldialog *dialog)
{
	struct lustre_item *item = dialog->ld_item;
	struct lustre_item_rule *rule;
	int count = 0;

	list_for_each_entry(rule,
			    &item->li_rules,
			    lir_linkage) {
		count++;
	}
	/* Choice for new rule */
	count++;
	return count;
}

static int ldialog_nchoice_field_type(struct ldialog *dialog)
{
	struct lustre_item_type *type = dialog->ld_item_type;
	struct lustre_field_type *field_type;
	int count = 0;

	list_for_each_entry(field_type,
	                    &type->lit_field_list,
	                    lft_linkage) {
		if (field_type->lft_type != TYPE_STRING) {
			continue;
		}
		count++;
	}
	/* No field for rule */
	if (count == 0) {
		count++;
	}
	return count;
}

static int ldialog_nchoice(struct ldialog *dialog)
{
	if (dialog->ld_new_item_rule) {
		assert(dialog->ld_item_rule == NULL);
		assert(dialog->ld_item != NULL);
		assert(dialog->ld_item_type != NULL);
		assert(dialog->ld_entry != NULL);
		return ldialog_nchoice_field_type(dialog);
	} else if (dialog->ld_item_rule != NULL) {
		assert(dialog->ld_item != NULL);
		assert(dialog->ld_item_type != NULL);
		assert(dialog->ld_entry != NULL);
		return ldialog_nchoice_field_type(dialog);
	} else if (dialog->ld_item != NULL) {
		assert(dialog->ld_item_type != NULL);
		assert(dialog->ld_entry != NULL);
		return ldialog_nchoice_rule(dialog);
	} else if (dialog->ld_item_type != NULL) {
		assert(dialog->ld_entry != NULL);
		return ldialog_nchoice_item(dialog);
	} else {
		assert(dialog->ld_entry != NULL);
		return ldialog_nchoice_entry_or_item_type(dialog);
	}
}

static void ldialog_choice_entry_or_item_type(struct ldialog *dialog,
					      int offset,
					      char *buffer,
					      int length)
{
	struct lustre_entry *entry = dialog->ld_entry;
	struct lustre_entry *child;
	struct lustre_item_type *item;
	int count = 0;

	list_for_each_entry(item,
	                    &entry->le_item_types,
	                    lit_linkage) {
		if (count == offset) {
			snprintf(buffer,
				 length,
				 "[%stype] %s  --->",
				 list_empty(&item->lit_items) ? "" : "*",
				 item->lit_type_name);
			return;
		}
		count++;
	}

	list_for_each_entry(child,
	                    &entry->le_children,
	                    le_linkage) {
		if (count == offset) {
			snprintf(buffer,
				 length,
				 "[%s] %s  --->",
				 child->le_mode == S_IFREG ? "file" : "directory" ,
				 child->le_subpath);
			return;
		}
		count++;
	}
	assert(0);
}

static void ldialog_choice_rule(struct ldialog *dialog,
				int offset,
				char *buffer,
				int length)
{
	struct lustre_item_type *type = dialog->ld_item_type;
	struct lustre_item *item = dialog->ld_item;
	struct lustre_item_rule *rule;
	int count = 0;

	list_for_each_entry(rule,
			    &item->li_rules,
			    lir_linkage) {
		if (count == offset) {
			snprintf(buffer,
				 length,
				 "[rule] \"%s\"=\"%s\"  --->",
				 type->lit_field_array[rule->lir_field_index]->lft_name,
				 rule->lir_string);
			return;
		}
		count++;
	}
	assert(count == offset);
	snprintf(buffer,
		 length,
		 "Add new rule  --->");
}

static int _ldialog_choice_item(struct lustre_item *item,
			        char *buffer,
			        int length)
{
	struct lustre_item_rule *rule;
	struct lustre_item_type *type = item->li_type;
	int used = 0;

	list_for_each_entry(rule,
			    &item->li_rules,
			    lir_linkage) {
		used += snprintf(buffer + used,
			length - used,
			"(\"%s\"=\"%s\")%s",
			type->lit_field_array[rule->lir_field_index]->lft_name,
			rule->lir_string,
			rule->lir_linkage.next == &item->li_rules
			? "" : "&&");
		if (used >= length) {
			break;
		}
	}
	if (used == 0) {
		used += snprintf(buffer,
			 	 length,
			 	 "Rule: Always");
	}
	return used;
}

static void ldialog_choice_item(struct ldialog *dialog,
				int offset,
				char *buffer,
				int length)
{
	struct lustre_item_type *type = dialog->ld_item_type;
	struct lustre_item *item;
	int count = 0;
	int used = 0;

	list_for_each_entry(item,
			    &type->lit_items,
			    li_linkage) {
		if (count == offset) {
			used += snprintf(buffer,
					 length,
					 "[item] ");
			if (used >= length) {
				return;
			}
			used += _ldialog_choice_item(item,
						     buffer + used,
						     length - used);
			if (used >= length) {
				return;
			}
			snprintf(buffer + used,
				 length - used,
				 "  --->");
			return;
		}
		count++;
	}
	assert(count == offset);
	snprintf(buffer,
		 length,
		 "Add new item  --->");
}

static void ldialog_choice_field_type(struct ldialog *dialog,
				      int offset,
				      char *buffer,
				      int length)
{
	struct lustre_item_type *type = dialog->ld_item_type;
	struct lustre_item_rule *rule = dialog->ld_item_rule;
	struct lustre_field_type *field_type;
	int count = 0;
	int field_index = 0;;

	list_for_each_entry(field_type,
	                    &type->lit_field_list,
	                    lft_linkage) {
		field_index++;
		if (field_type->lft_type != TYPE_STRING) {
			continue;
		}
		if (count == offset) {
			snprintf(buffer,
				 length,
				 "[%sfield] %s  --->",
				 rule && field_index == rule->lir_field_index ?
				 "*" : "",
				 field_type->lft_name);
			return;
		}
		count++;
	}
	if (count == 0 && offset == 0) {
		snprintf(buffer,
			 length,
			 "No available field");
		return;
	}
	assert(0);
}

static void ldialog_choice(struct ldialog *dialog,
			   int offset,
			   char *buffer,
			   int length)
{
	if (dialog->ld_new_item_rule != 0) {
		assert(dialog->ld_item_rule == NULL);
		assert(dialog->ld_item != NULL);
		assert(dialog->ld_entry != NULL);
		assert(dialog->ld_item_type != NULL);
		return ldialog_choice_field_type(dialog,
						 offset, buffer, length);
	} else if (dialog->ld_item_rule != NULL) {
		assert(dialog->ld_new_item_rule == 0);
		assert(dialog->ld_item != NULL);
		assert(dialog->ld_entry != NULL);
		assert(dialog->ld_item_type != NULL);
		return ldialog_choice_field_type(dialog,
						 offset, buffer, length);
	} if (dialog->ld_item != NULL) {
		assert(dialog->ld_entry != NULL);
		assert(dialog->ld_item_type != NULL);
		return ldialog_choice_rule(dialog,
					   offset, buffer, length);
	} else if (dialog->ld_item_type != NULL) {
		assert(dialog->ld_entry != NULL);
		return ldialog_choice_item(dialog,
					   offset, buffer, length);
	} else {
		assert(dialog->ld_entry != NULL);
		return ldialog_choice_entry_or_item_type(dialog,
							 offset,
							 buffer, length);
	}
}

static void ldialog_choose_entry_or_item_type(struct ldialog *dialog,
					      int offset)
{
	struct lustre_entry *entry = dialog->ld_entry;
	struct lustre_entry *child;
	struct lustre_item_type *item;
	int count = 0;
	int ret;

	assert(dialog->ld_entry != NULL);
	assert(dialog->ld_item == NULL);
	assert(dialog->ld_item_type == NULL);
	assert(dialog->ld_item_rule == NULL);
	assert(dialog->ld_new_item_rule == 0);
	list_for_each_entry(item,
	                    &entry->le_item_types,
	                    lit_linkage) {
		if (count == offset) {
			/* Go down to lower level, push*/
			ret = ldialog_info_push(dialog);
			if (ret) {
				ldialog_message(dialog, "Error",
						"Failed to push context "
						"because memory is not enough");
				return;
			}
			dialog->ld_item_type = item;
			return;
		}
		count++;
	}

	list_for_each_entry(child,
	                    &entry->le_children,
	                    le_linkage) {
		if (count == offset) {
			/* Go down to lower level, push*/
			ret = ldialog_info_push(dialog);
			if (ret) {
				ldialog_message(dialog, "Error",
						"Failed to push context "
						"because memory is not enough");
				return;
			}
			dialog->ld_entry = child;
			assert(dialog->ld_item_type == NULL);
			assert(dialog->ld_item == NULL);
			assert(dialog->ld_item_rule == NULL);
			assert(dialog->ld_new_item_rule == 0);
			return;
		}
		count++;
	}
	assert(0);
}

/*
 *  Print the termination buttons
 */
static void ldialog_print_buttons_ok_cancel(struct ldialog *dialog,
					   WINDOW * win,
					   int height, int width,
					   int selected)
{
	int x = width / 2 - 11;
	int y = height - 2;

	ldialog_print_button(dialog, win, "   Ok   ", y, x, selected == 0);
	ldialog_print_button(dialog, win, " Cancel ", y, x + 14, selected == 1);

	wmove(win, y, x + 1 + 14 * selected);
	wrefresh(win);
}

static void ldialog_choose_item(struct ldialog *dialog,
				int offset)
{
	struct lustre_item_type *type = dialog->ld_item_type;
	struct lustre_item *item;
	int count = 0;
	int ret;

	assert(dialog->ld_entry != NULL);
	assert(dialog->ld_item_type != NULL);
	assert(dialog->ld_item == NULL);
	assert(dialog->ld_item_rule == NULL);
	assert(dialog->ld_new_item_rule == 0);
	list_for_each_entry(item,
			    &type->lit_items,
			    li_linkage) {
		if (count == offset) {
			/* Go down to lower level, push*/
			ret = ldialog_info_push(dialog);
			if (ret) {
				ldialog_message(dialog, "Error",
						"Failed to push context "
						"because memory is not enough");
				return;
			}
			dialog->ld_item = item;
			return;
		}
		count++;
	}
	assert(count == offset);
	item = lustre_item_alloc();
	if (item == NULL) {
		ldialog_message(dialog, "Error",
				"Failed to create item "
				"because memory is not enough");
		return;
	}
	item->li_type = dialog->ld_item_type;
	lustre_item_add(item);
}

int ldialog_inputbox(struct ldialog *dialog,
		     const char *title,
		     const char *prompt,
		     char *input_string,
		     int max_input)
{
	int key = 0;
	int height, width, box_width;
	int x, y, box_x, box_y, input_x;
	WINDOW *window_dialog;
	int i;
	int ret = LDIALOG_AGAIN;
	struct ldialog_info *current = dialog->ld_info_current;

	height = 10;
	width = 75;
	if (getmaxy(stdscr) <= (height - 2) ||
	    getmaxx(stdscr) <= (width - 2))
		return LDIALOG_ERROR;

	/* center dialog box on screen */
	x = (COLS - width) / 2;
	y = (LINES - height) / 2;

	window_dialog = newwin(height, width, y, x);
	keypad(window_dialog, TRUE);

	/* TODO: draw shadow */

	ldialog_draw_box(window_dialog, 0, 0, height, width,
			 dialog->ld_color_dialog.ldc_attribute,
			 dialog->ld_color_border.ldc_attribute);
	wattrset(window_dialog, dialog->ld_color_border.ldc_attribute);
	/* Add a line on the bottom to give space for Select/Eixt/Help */
	mvwaddch(window_dialog, height - 3, 0, ACS_LTEE);
	for (i = 0; i < width - 2; i++)
		waddch(window_dialog, ACS_HLINE);
	wattrset(window_dialog,
		 dialog->ld_color_dialog.ldc_attribute);
	wbkgdset(window_dialog,
		 dialog->ld_color_dialog.ldc_attribute & A_COLOR);
	waddch(window_dialog, ACS_RTEE);

	ldialog_print_title(dialog, window_dialog,
			    title, width);

	wattrset(window_dialog, dialog->ld_color_dialog.ldc_attribute);
	ldialog_print_autowrap(window_dialog, prompt,
			       width - 2, 1, 3);

	/* Draw the input field box */
	box_width = width - 6;
	getyx(window_dialog, y, x);
	box_y = y + 2;
	box_x = (width - box_width) / 2;
	ldialog_draw_box(window_dialog, y + 1, box_x - 1, 3, box_width + 2,
			 dialog->ld_color_dialog.ldc_attribute,
			 dialog->ld_color_border.ldc_attribute);

	/* Set up the initial value */
	wmove(window_dialog, box_y, box_x);
	wattrset(window_dialog, dialog->ld_color_inputbox.ldc_attribute);

	input_x = strlen(input_string);

	if (input_x >= box_width) {
		current->ldi_input_scroll =
			input_x - box_width + 1;
		input_x = box_width - 1;
		for (i = 0; i < box_width - 1; i++) {
			waddch(window_dialog,
			       input_string[current->ldi_input_scroll + i]);
		}
	} else {
		waddstr(window_dialog, input_string);
	}

	ldialog_print_buttons_ok_cancel(dialog,
		window_dialog,
		height, width,
		current->ldi_active_button);

	if (current->ldi_input_active) {
		/* Move to right place for input */
		wmove(window_dialog, box_y, box_x + input_x);
	}

	while (1) {
		key = wgetch(window_dialog);

		if (current->ldi_input_active) {
			switch (key) {
			case KEY_TAB:
			case KEY_UP:
			case KEY_DOWN:
			case KEY_LEFT:
			case KEY_RIGHT:
				break;
			case KEY_BACKSPACE:
			case 127:
				if (input_x == 0 &&
				    current->ldi_input_scroll == 0) {
				    	/* Ignore */
				    	break;
				}

				if (current->ldi_input_scroll != 0) {
					current->ldi_input_scroll--;
				} else {
					assert(input_x > 0);
					input_x--;
				}
				input_string[current->ldi_input_scroll + input_x] = '\0';
				goto out;
			default:
				if (key < 0x100 && isprint(key)) {
					if (current->ldi_input_scroll + input_x < max_input) {
						input_string[current->ldi_input_scroll + input_x] = key;
						input_string[current->ldi_input_scroll + input_x + 1] = '\0';
					}
					goto out;
				}
			}
		}

		switch(key) {
		case KEY_UP:
		case KEY_LEFT:
			if (current->ldi_input_active) {
				current->ldi_input_active = 0;
				current->ldi_active_button = 1;
				ldialog_print_buttons_ok_cancel(dialog,
								window_dialog,
								height, width,
								current->ldi_active_button);
			} else if (current->ldi_active_button == 1) {
				current->ldi_active_button = 0;
				ldialog_print_buttons_ok_cancel(dialog,
								window_dialog,
								height, width,
								current->ldi_active_button);
			} else {
				current->ldi_input_active = 1;
				wmove(window_dialog, box_y, input_x + box_x);
			}
			break;
		case KEY_TAB:
		case KEY_DOWN:
		case KEY_RIGHT:
			if (current->ldi_input_active) {
				current->ldi_input_active = 0;
				current->ldi_active_button = 0;
				ldialog_print_buttons_ok_cancel(dialog,
								window_dialog,
								height, width,
								current->ldi_active_button);
			} else if (current->ldi_active_button == 0) {
				current->ldi_active_button = 1;
				ldialog_print_buttons_ok_cancel(dialog,
								window_dialog,
								height, width,
								current->ldi_active_button);
			} else {
				current->ldi_input_active = 1;
				wmove(window_dialog, box_y, input_x + box_x);
			}
			break;
		case ' ':
		case '\n':
			if (current->ldi_active_button == 0) {
				ret = LDIALOG_ENTER;
			} else {
				ret = LDIALOG_ESCAPE;
			}
			goto out;
		case 'q':
		case 'x':
		case 'e':
		case KEY_ESC:
			ret = LDIALOG_ESCAPE;
			goto out;
		case KEY_RESIZE:
			ret = LDIALOG_AGAIN;
			goto out;
		}
	}
out:
	delwin(window_dialog);
	return ret;
}

static void ldialog_input_rule_pattern(
	struct ldialog *dialog,
	struct lustre_field_type *field_type,
	int field_index)
{
	int ret;
	char prompt[MAX_NAME_LENGH + 1024];
	struct lustre_item_rule *rule;

	rule = calloc(1, sizeof (struct lustre_item_rule));
	if (rule == NULL) {
		ldialog_message(dialog, "Error",
				"Failed to create rule "
				"because memory is not enough");
		return;
	}

	if (dialog->ld_item_rule != NULL) {
		assert(dialog->ld_item_rule->lir_field_index == field_index);
		strcpy(rule->lir_string, dialog->ld_item_rule->lir_string);
	}
	rule->lir_field_index = field_index;

	snprintf(prompt, sizeof(prompt),
		 "Set pattern of field \"%s\"",
		 field_type->lft_name);

	ret = ldialog_info_push(dialog);
	if (ret) {
		ldialog_message(dialog, "Error",
				"Failed to push context "
				"because memory is not enough");
		lustre_item_rule_free(rule);
		return;
	}
	/* Activate inputbox by default */
	dialog->ld_info_current->ldi_input_active = 1;
	while (1) {
		ldialog_clear(dialog);
		ret = ldialog_inputbox(dialog, "Rule Pattern", prompt,
				       rule->lir_string,
				       sizeof(rule->lir_string) - 1);
		if (ret == LDIALOG_ESCAPE) {
			break;
		}
		if (ret == LDIALOG_ENTER) {
			int status;
			status = lustre_compile_regex(&rule->lir_regex,
						      rule->lir_string);
			if (status) {
				/* Regular expression is wrong, go on input */
				continue;
			}
			rule->lir_regex_inited = 1;
			break;
		}
	}
	ldialog_info_pop(dialog);

	if (ret != LDIALOG_ENTER ||
	    (dialog->ld_item_rule != NULL &&
	     strcmp(dialog->ld_item_rule->lir_string, rule->lir_string) == 0)) {
		lustre_item_rule_free(rule);
	} else if (dialog->ld_item_rule != NULL) {
		lustre_item_rule_replace(dialog->ld_item,
					 dialog->ld_item_rule,
					 rule);
		lustre_item_rule_free(dialog->ld_item_rule);
		dialog->ld_item_rule = rule;
	} else {
		dialog->ld_item_rule = rule;
		dialog->ld_new_item_rule = 0;
		lustre_item_rule_add(dialog->ld_item, rule);
	}
	return;
}

static void ldialog_choose_field_type(struct ldialog *dialog,
				      int offset)
{
	struct lustre_item_type *type = dialog->ld_item_type;
	struct lustre_field_type *field_type;
	int count = 0;
	int field_index = 0;;

	assert(dialog->ld_entry != NULL);
	assert(dialog->ld_item_type != NULL);
	assert(dialog->ld_item != NULL);
	assert((dialog->ld_item_rule != NULL) ||
	       (dialog->ld_new_item_rule != 0));
	assert((dialog->ld_item_rule == NULL) ||
	       (dialog->ld_new_item_rule == 0));

	list_for_each_entry(field_type,
	                    &type->lit_field_list,
	                    lft_linkage) {
		field_index++;
		if (field_type->lft_type != TYPE_STRING) {
			continue;
		}

		if (count == offset) {
			ldialog_input_rule_pattern(dialog,
						   field_type,
						   field_index);
			return;
		}
		count++;
	}
	if (count == 0 && offset == 0) {
		/* No rule type for choose */
		return;
	}
	assert(0);
}

static void ldialog_choose_rule(struct ldialog *dialog,
				int offset)
{
	struct lustre_item *item;
	struct lustre_item_rule *rule;
	int count = 0;
	int ret;

	assert(dialog->ld_entry != NULL);
	assert(dialog->ld_item_type != NULL);
	assert(dialog->ld_item != NULL);
	assert(dialog->ld_item_rule == NULL);
	assert(dialog->ld_new_item_rule == 0);
	item = dialog->ld_item;
	list_for_each_entry(rule,
			    &item->li_rules,
			    lir_linkage) {
		if (count == offset) {
			ret = ldialog_info_push(dialog);
			if (ret) {
				ldialog_message(dialog, "Error",
						"Failed to push context "
						"because memory is not enough");
				return;
			}
			dialog->ld_item_rule = rule;
			return;
		}
		count++;
	}
	assert(count == offset);

	ret = ldialog_info_push(dialog);
	if (ret) {
		ldialog_message(dialog, "Error",
				"Failed to push context "
				"because memory is not enough");
		return;
	}
	dialog->ld_new_item_rule = 1;
}

static void ldialog_choose(struct ldialog *dialog,
			   int offset)
{
	if (dialog->ld_new_item_rule != 0) {
		assert(dialog->ld_item_rule == NULL);
		assert(dialog->ld_item != NULL);
		assert(dialog->ld_item_type != NULL);
		assert(dialog->ld_entry != NULL);
		ldialog_choose_field_type(dialog,
					  offset);
	} else if (dialog->ld_item_rule != NULL) {
		assert(dialog->ld_item != NULL);
		assert(dialog->ld_item_type != NULL);
		assert(dialog->ld_entry != NULL);
		ldialog_choose_field_type(dialog,
					  offset);
	} else if (dialog->ld_item != NULL) {
		assert(dialog->ld_item_type != NULL);
		assert(dialog->ld_entry != NULL);
		ldialog_choose_rule(dialog,
				    offset);
	} else if (dialog->ld_item_type != NULL) {
		assert(dialog->ld_entry != NULL);
		ldialog_choose_item(dialog, offset);
	} else {
		ldialog_choose_entry_or_item_type(dialog, offset);
	}
}

static void ldialog_delete_rule(struct ldialog *dialog,
				int offset)
{
	struct lustre_item *item;
	struct lustre_item_rule *rule;
	struct lustre_item_rule *n;
	int count = 0;

	assert(dialog->ld_entry != NULL);
	assert(dialog->ld_item_type != NULL);
	assert(dialog->ld_item != NULL);
	assert(dialog->ld_item_rule == NULL);
	assert(dialog->ld_new_item_rule == 0);
	item = dialog->ld_item;
	list_for_each_entry_safe(rule,
				 n,
				 &item->li_rules,
				 lir_linkage) {
		if (count == offset) {
			lustre_item_rule_unlink(rule);
			lustre_item_rule_free(rule);
			return;
		}
		count++;
	}
	assert(count == offset);
	/* Do nothing */
}

static void ldialog_delete_item(struct ldialog *dialog,
				int offset)
{
	struct lustre_item_type *type = dialog->ld_item_type;
	struct lustre_item *item;
	struct lustre_item *n;
	int count = 0;

	assert(dialog->ld_entry != NULL);
	assert(dialog->ld_item_type != NULL);
	assert(dialog->ld_item == NULL);
	assert(dialog->ld_item_rule == NULL);
	assert(dialog->ld_new_item_rule == 0);
	list_for_each_entry_safe(item,
				 n,
				 &type->lit_items,
				 li_linkage) {
		if (count == offset) {
			lustre_item_unlink(item);
			lustre_item_free(item);
			return;
		}
		count++;
	}
	assert(count == offset);
	/* Do nothing */
}

static void ldialog_delete(struct ldialog *dialog,
			   int offset)
{
	if (dialog->ld_new_item_rule != 0) {
		assert(dialog->ld_item_rule == NULL);
		assert(dialog->ld_item != NULL);
		assert(dialog->ld_item_type != NULL);
		assert(dialog->ld_entry != NULL);
	} else if (dialog->ld_item_rule != NULL) {
		assert(dialog->ld_item != NULL);
		assert(dialog->ld_item_type != NULL);
		assert(dialog->ld_entry != NULL);
	} else if (dialog->ld_item != NULL) {
		assert(dialog->ld_item_type != NULL);
		assert(dialog->ld_entry != NULL);
		ldialog_delete_rule(dialog,
				    offset);
	} else if (dialog->ld_item_type != NULL) {
		assert(dialog->ld_entry != NULL);
		ldialog_delete_item(dialog, offset);
	}
}

/*
 * Print list item
 */
static void ldialog_print_item(struct ldialog *dialog,
			       WINDOW * win,
			       int item_offset_x,
			       int menu_offset_y,
			       int item_offset_y,
			       int menu_width,
			       int selected)
{
//	int j;
	char *menu_item = malloc(menu_width - item_offset_x + 1);

	ldialog_choice(dialog,
		       menu_offset_y + item_offset_y,
		       menu_item,
		       menu_width - item_offset_x + 1);
//	j = first_alpha(menu_item, "YyNnMmHh");

	/* Clear 'residue' of last item */
	wattrset(win, dialog->ld_color_menubox.ldc_attribute);
	wmove(win, item_offset_y, 0);
	wclrtoeol(win);
	wattrset(win, selected ?
		 dialog->ld_color_item_selected.ldc_attribute :
		 dialog->ld_color_item.ldc_attribute);
	mvwaddstr(win, item_offset_y, item_offset_x, menu_item);
//	if (hotkey) {
//		wattrset(win, selected ? dlg.tag_key_selected.atr
//			 : dlg.tag_key.atr);
//		mvwaddch(win, item_offset_y, item_offset_x + j, menu_item[j]);
//	}
	if (selected) {
		wmove(win, item_offset_y, item_offset_x + 1);
	}
	free(menu_item);
	wrefresh(win);
}

static int ldialog_escape(struct ldialog *dialog)
{
	int ret = LDIALOG_AGAIN;
	if (dialog->ld_new_item_rule) {
		assert(dialog->ld_item_rule == NULL);
		assert(dialog->ld_item != NULL);
		assert(dialog->ld_item_type != NULL);
		assert(dialog->ld_entry != NULL);
		dialog->ld_new_item_rule = 0;
	} else if (dialog->ld_item_rule != NULL) {
		assert(dialog->ld_new_item_rule == 0);
		assert(dialog->ld_item != NULL);
		assert(dialog->ld_item_type != NULL);
		assert(dialog->ld_entry != NULL);
		dialog->ld_item_rule = NULL;
	} else if (dialog->ld_item != NULL) {
		assert(dialog->ld_item_type != NULL);
		assert(dialog->ld_entry != NULL);
		dialog->ld_item = NULL;
	} else if (dialog->ld_item_type != NULL) {
		assert(dialog->ld_entry != NULL);
		dialog->ld_item_type = NULL;
	} else {
		if (dialog->ld_entry->le_parent == NULL) {
			ret = LDIALOG_ESCAPE;
		} else {
			dialog->ld_entry = dialog->ld_entry->le_parent;
		}
	}
	/* Go upper level, pop info */
	if (ret == LDIALOG_AGAIN) {
		ldialog_info_pop(dialog);
	}
	return ret;
}

/*
 * Print the scroll indicators.
 */
static void ldialog_print_arrows(struct ldialog *dialog,
				 WINDOW * win, int item_no,
				 int scroll, int y, int x,
				 int height)
{
	int cur_y, cur_x;

	getyx(win, cur_y, cur_x);

	wmove(win, y, x);

	if (scroll > 0) {
		wattrset(win, dialog->ld_color_up_arrow.ldc_attribute);
		waddch(win, ACS_UARROW);
		waddstr(win, "(-)");
	} else {
		wattrset(win, dialog->ld_color_menubox.ldc_attribute);
		waddch(win, ACS_HLINE);
		waddch(win, ACS_HLINE);
		waddch(win, ACS_HLINE);
		waddch(win, ACS_HLINE);
	}

	y = y + height + 1;
	wmove(win, y, x);
	wrefresh(win);

	if ((height < item_no) && (scroll + height < item_no)) {
		wattrset(win, dialog->ld_color_down_arrow.ldc_attribute);
		waddch(win, ACS_DARROW);
		waddstr(win, "(+)");
	} else {
		wattrset(win, dialog->ld_color_menubox_border.ldc_attribute);
		waddch(win, ACS_HLINE);
		waddch(win, ACS_HLINE);
		waddch(win, ACS_HLINE);
		waddch(win, ACS_HLINE);
	}

	wmove(win, cur_y, cur_x);
	wrefresh(win);
}

static void ldialog_do_scroll(WINDOW *win, int *scroll, int n)
{
	/* Scroll menu up */
	scrollok(win, TRUE);
	wscrl(win, n);
	scrollok(win, FALSE);
	*scroll = *scroll + n;
	wrefresh(win);
}

/*
 *  Print the termination buttons
 */
static void ldialog_print_buttons_save_or_exit(struct ldialog *dialog,
					       WINDOW * win,
					       int height, int width,
					       int selected)
{
	int x = width / 2 - 11;
	int y = height - 2;

	ldialog_print_button(dialog, win, "  Save  ", y, x, selected == 0);
	ldialog_print_button(dialog, win, "  Exit  ", y, x + 14, selected == 1);

	if (selected != -1) {
		wmove(win, y, x + 1 + 14 * selected);
	}
	wrefresh(win);
}

const char ldialog_help_title[] = "Arrow keys navigate the menu. "
	"<Enter> selects submenus. "
	"Highlighted letters are hotkeys. "
	"Press <Esc> for return to upper level, "
	"<Backspace> for deletion, "
	"<?> for Help, </> for Search. "
	"Legend: [*] used.";

static void ldialog_info_setup(struct ldialog *dialog)
{
	memset(&dialog->ld_info_root, 0,
	       sizeof(struct ldialog_info));
	dialog->ld_info_current = &dialog->ld_info_root;
}

static void ldialog_info_cleanup(struct ldialog *dialog)
{
	while(dialog->ld_info_current != &dialog->ld_info_root) {
		ldialog_info_pop(dialog);
	}
}

static int ldialog_menu(struct lustre_configs *lustre_config,
			struct ldialog *dialog)
{
	int i, x, y, box_x, box_y;
	int height, width, menu_height, menu_width;
	WINDOW *window_dialog;
	WINDOW *window_menu;
	int item_count, item_show;
	int key = 0;
	int item_offset_x;
	int ret = LDIALOG_AGAIN;

	height = getmaxy(stdscr);
	width = getmaxx(stdscr);
	if (height < 15 || width < 65)
		return LDIALOG_ERROR;

	height -= 4;
	width  -= 5;
	menu_height = height - 10;

	item_count = ldialog_nchoice(dialog);
	item_show = MIN(menu_height, item_count);

	/* center dialog box on screen */
	x = (COLS - width) / 2;
	y = (LINES - height) / 2;

	/* TODO: draw shadow along the right and bottom edge */

	window_dialog = newwin(height, width, y, x);
	keypad(window_dialog, TRUE);
	ldialog_draw_box(window_dialog, 0, 0, height, width,
			 dialog->ld_color_dialog.ldc_attribute,
			 dialog->ld_color_border.ldc_attribute);
	wattrset(window_dialog, dialog->ld_color_border.ldc_attribute);
	/* Add a line on the bottom to give space for Select/Eixt/Help */
	mvwaddch(window_dialog, height - 3, 0, ACS_LTEE);
	for (i = 0; i < width - 2; i++)
		waddch(window_dialog, ACS_HLINE);
	wattrset(window_dialog,
		 dialog->ld_color_dialog.ldc_attribute);
	wbkgdset(window_dialog,
		 dialog->ld_color_dialog.ldc_attribute & A_COLOR);
	waddch(window_dialog, ACS_RTEE);

	ldialog_print_title(dialog, window_dialog, dialog->ld_title, width);

	wattrset(window_dialog, dialog->ld_color_dialog.ldc_attribute);
	ldialog_print_autowrap(window_dialog, ldialog_help_title,
			       width - 2, 1, 3);

	wattrset(window_dialog, dialog->ld_color_dialog.ldc_attribute);

	menu_width = width - 6;
	box_y = height - menu_height - 5;
	box_x = (width - menu_width) / 2 - 1;

	/* create new window for the menu */
	window_menu = subwin(window_dialog, menu_height, menu_width,
			     y + box_y + 1, x + box_x + 1);
	keypad(window_menu, TRUE);

	/* draw a box around the menu items */
	ldialog_draw_box(window_dialog, box_y, box_x, menu_height + 2, menu_width + 2,
		 dialog->ld_color_menubox_border.ldc_attribute,
		 dialog->ld_color_menubox.ldc_attribute);

	if (menu_width >= 80)
		item_offset_x = (menu_width - 70) / 2;
	else
		item_offset_x = 4;

	/* Print the menu */
	for (i = 0; i < item_show; i++) {
		ldialog_print_item(dialog,
			   window_menu,
			   item_offset_x,
			   dialog->ld_info_current->ldi_menu_offset_y,
			   i,
			   menu_width,
			   i == dialog->ld_info_current->ldi_item_offset_y);
	}
	/* Move curse to the right place */
	wmove(window_menu, dialog->ld_info_current->ldi_item_offset_y,
	      item_offset_x + 1);

	ldialog_print_arrows(dialog, window_dialog, item_count,
			     dialog->ld_info_current->ldi_menu_offset_y,
			     box_y, box_x + item_offset_x + 1, menu_height);

	ldialog_print_buttons_save_or_exit(dialog, window_dialog,
		height, width,
		dialog->ld_info_current->ldi_active_button);

	wrefresh(window_dialog);
	wrefresh(window_menu);

	while (key != KEY_ESC) {
		key = wgetch(window_menu);
		if (key < 256 && isalpha(key)) {
			key = tolower(key);
		}

		if ((dialog->ld_info_current->ldi_active_button == -1) &&
		    (key == KEY_UP || key == KEY_DOWN ||
		    key == '-' || key == '+' ||
		    key == KEY_PPAGE || key == KEY_NPAGE)) {
		    	/* Remove highligt of current item */
			ldialog_print_item(dialog,
				   window_menu,
				   item_offset_x,
				   dialog->ld_info_current->ldi_menu_offset_y,
				   dialog->ld_info_current->ldi_item_offset_y,
				   menu_width,
				   FALSE);
			switch(key) {
			case KEY_UP:
			case '-':
				if (dialog->ld_info_current->ldi_item_offset_y < 2 &&
				    dialog->ld_info_current->ldi_menu_offset_y) {
				    	/* Scroll menu down */
				    	ldialog_do_scroll(window_menu,
				    			  &dialog->ld_info_current->ldi_menu_offset_y,
				    			  -1);
					/* Print the newly shown item */
					ldialog_print_item(dialog,
							   window_menu,
							   item_offset_x,
							   dialog->ld_info_current->ldi_menu_offset_y,
							   0,
							   menu_width,
							   0);
				} else {
					dialog->ld_info_current->ldi_item_offset_y--;
					dialog->ld_info_current->ldi_item_offset_y =
					  MAX(0,
					  dialog->ld_info_current->ldi_item_offset_y);
				}
				break;
			case KEY_DOWN:
			case '+':
				if (dialog->ld_info_current->ldi_item_offset_y > item_show - 3 &&
				    dialog->ld_info_current->ldi_menu_offset_y + item_show < item_count) {
				    	/* Scroll menu up */
					ldialog_do_scroll(window_menu,
				    			  &dialog->ld_info_current->ldi_menu_offset_y,
				    			  1);
					/* Print the newly shown item */
					ldialog_print_item(dialog,
							   window_menu,
							   item_offset_x,
							   dialog->ld_info_current->ldi_menu_offset_y,
							   item_show - 1,
							   menu_width,
							   0);
				} else {
					dialog->ld_info_current->ldi_item_offset_y++;
					dialog->ld_info_current->ldi_item_offset_y =
					  MIN(item_show - 1,
					  dialog->ld_info_current->ldi_item_offset_y);
				}
				break;
			case KEY_PPAGE:
				scrollok(window_menu, TRUE);
				for (i = 0; i < item_show; i++) {
					if (dialog->ld_info_current->ldi_menu_offset_y > 0) {
						ldialog_do_scroll(window_menu,
				    			  	  &dialog->ld_info_current->ldi_menu_offset_y,
				    			  	  -1);
						/* Print the newly shown item */
						ldialog_print_item(dialog,
								   window_menu,
								   item_offset_x,
								   dialog->ld_info_current->ldi_menu_offset_y,
								   0,
								   menu_width,
								   0);
					} else {
						dialog->ld_info_current->ldi_item_offset_y--;
						dialog->ld_info_current->ldi_item_offset_y =
						  MAX(0,
						  dialog->ld_info_current->ldi_item_offset_y);
					}
				}
				break;
			case KEY_NPAGE:
				for (i = 0; i < item_show; i++) {
					if (dialog->ld_info_current->ldi_menu_offset_y + item_show < item_count) {
						ldialog_do_scroll(window_menu,
								  &dialog->ld_info_current->ldi_menu_offset_y,
								  1);
						/* Print the newly shown item */
						ldialog_print_item(dialog,
								   window_menu,
								   item_offset_x,
								   dialog->ld_info_current->ldi_menu_offset_y,
								   item_show - 1,
								   menu_width,
								   0);
					} else {
						dialog->ld_info_current->ldi_item_offset_y++;
						dialog->ld_info_current->ldi_item_offset_y =
						  MIN(item_show - 1,
						  dialog->ld_info_current->ldi_item_offset_y);
					}
				}
				break;
			}
			ldialog_print_item(dialog,
				window_menu,
				item_offset_x,
				dialog->ld_info_current->ldi_menu_offset_y,
				dialog->ld_info_current->ldi_item_offset_y,
				menu_width,
				TRUE);
			ldialog_print_arrows(dialog, window_dialog, item_count,
					     dialog->ld_info_current->ldi_menu_offset_y,
					     box_y, box_x + item_offset_x + 1, menu_height);
			wnoutrefresh(window_dialog);
			wrefresh(window_menu);
			continue;	/* wait for another key press */
		}

		switch (key) {
		case KEY_LEFT:
		case KEY_TAB:
		case KEY_RIGHT:
			if (dialog->ld_info_current->ldi_active_button == -1) {
				dialog->ld_info_current->ldi_active_button = 0;
			} else if (dialog->ld_info_current->ldi_active_button == 0) {
				dialog->ld_info_current->ldi_active_button = 1;
			} else {
				dialog->ld_info_current->ldi_active_button = -1;
			}
			ldialog_print_buttons_save_or_exit(dialog,
				window_dialog,
				height, width,
				dialog->ld_info_current->ldi_active_button);
			if (dialog->ld_info_current->ldi_active_button == -1) {
				/* Move curse to the right place */
				wmove(window_menu, dialog->ld_info_current->ldi_item_offset_y,
				      item_offset_x + 1);
			}
			break;
		case KEY_BACKSPACE:
			ldialog_delete(dialog,
				dialog->ld_info_current->ldi_menu_offset_y +
				dialog->ld_info_current->ldi_item_offset_y);
			ret = LDIALOG_AGAIN;
			goto out;
		case '?':
		case 'h':
			ret = LDIALOG_HELP;
			goto out;
		case ' ':
		case '\n':
			if (dialog->ld_info_current->ldi_active_button == -1) {
				ldialog_choose(dialog,
					dialog->ld_info_current->ldi_menu_offset_y +
					dialog->ld_info_current->ldi_item_offset_y);
				/* Select menu by default */
				dialog->ld_info_current->ldi_active_button = -1;
				ret = LDIALOG_AGAIN;
				goto out;
			} else if (dialog->ld_info_current->ldi_active_button == 0) {
				ret = lustre_config_save(lustre_config, dialog->ld_filename);
				if (ret) {
					ldialog_message(dialog, "Error",
							"Failed to save configure");
					ret = LDIALOG_AGAIN;
					goto out;
				}
				break;
			} else {
				ldialog_info_cleanup(dialog);
				ret = LDIALOG_ESCAPE;
				goto out;
			}
		case 'q':
		case 'x':
		case 'e':
		case KEY_ESC:
			ret = ldialog_escape(dialog);
		case KEY_RESIZE:
			goto out;
		}
	}
out:
	delwin(window_menu);
	delwin(window_dialog);
	return ret;
}

static int ldialog_show(struct lustre_configs *lustre_config,
			struct ldialog *dialog)
{
	int height, width;
	int ret;

	height = getmaxy(stdscr);
	width = getmaxx(stdscr);
	if (height < 15 || width < 80) {
		return -1;
	}

	/* Do not active button by default */
	dialog->ld_info_current->ldi_active_button = -1;
	while(1) {
		ldialog_clear(dialog);
		ret = ldialog_menu(lustre_config, dialog);
		switch (ret) {
		case LDIALOG_ERROR:
			return -1;
		case LDIALOG_ESCAPE:
			return 0;
		case LDIALOG_HELP:
			ret = ldialog_info_push(dialog);
			if (ret) {
				ldialog_message(dialog, "Error",
						"Failed to push context "
						"because memory is not enough");
				continue;
			}
			// TODO: help window
			ldialog_info_pop(dialog);
			continue;
		}
	}
	return 0;
}

static int ldialog_fini()
{
	/* End curses mode */
	endwin();
	return 0;
}

static void ldialog_color_setup(struct ldialog *dialog)
{
	dialog->ld_color_screen.ldc_attribute = A_NORMAL;
	dialog->ld_color_dialog.ldc_attribute = A_NORMAL;
	dialog->ld_color_border.ldc_attribute = A_NORMAL;
	dialog->ld_color_menubox_border.ldc_attribute = A_NORMAL;
	dialog->ld_color_menubox.ldc_attribute = A_NORMAL;
	dialog->ld_color_title.ldc_attribute = A_BOLD;
	dialog->ld_color_item_selected.ldc_attribute = A_REVERSE;
	dialog->ld_color_item.ldc_attribute = A_NORMAL;

	dialog->ld_color_button_active.ldc_attribute = A_REVERSE;
	dialog->ld_color_button_inactive.ldc_attribute = A_DIM;
	dialog->ld_color_button_label_active.ldc_attribute = A_REVERSE;
	dialog->ld_color_button_label_inactive.ldc_attribute = A_NORMAL;
	dialog->ld_color_button_key_active.ldc_attribute = A_REVERSE;
	dialog->ld_color_button_key_inactive.ldc_attribute = A_BOLD;
	dialog->ld_color_down_arrow.ldc_attribute = A_BOLD;
	dialog->ld_color_up_arrow.ldc_attribute = A_BOLD;
	dialog->ld_color_inputbox.ldc_attribute = A_NORMAL;
}

#define LDIALOG_MIN_HEIGHT (19)
#define LDIALOG_MIN_WIDTH (80)

static int ldialog_init(struct ldialog *dialog)
{
	/* Start curses mode */
	initscr();

	/* Get current cursor position */
	getyx(stdscr, dialog->ld_start_y, dialog->ld_start_x);

	getmaxyx(stdscr, dialog->ld_heigth, dialog->ld_width);
	if (dialog->ld_heigth < LDIALOG_MIN_HEIGHT ||
	    dialog->ld_width < LDIALOG_MIN_WIDTH) {
		ldialog_fini();
		return -1;
	}
	ldialog_color_setup(dialog);
	ldialog_info_setup(dialog);

	/* We get F1, F2 etc.. */
	keypad(stdscr, TRUE);
	/* Line buffering disabled, Ctrl+c triggers termial */
	cbreak();
	/* Don't echo() while we do getch */
	noecho();
	/* Clear dialog */
	ldialog_clear(dialog);
	return 0;
}


int main(int argc, char **argv)
{
	int c;
	oconfig_item_t *conf;
	struct lustre_configs *configs = NULL;
	struct ldialog dialog;
	int size;
	int i;
	int ret;

	dialog.ld_title = "Collectd Lustre Configuration";
	while (1)
	{
		c = getopt(argc, argv, "h");
		if (c < 0) {
			break;
		}

		switch (c) {
		case 'h':
		default:
			usage(argv[0]);
			exit(1);
		} /* switch (c) */
	}

	if (optind != argc - 1) {
		usage(argv[0]);
		exit(1);
	}

	dialog.ld_filename = argv[optind];

	/* Parse input configure file */
	conf = oconfig_parse_file(dialog.ld_filename);
	if (conf == NULL) {
		LERROR("Unable to read config file %s\n",
		       dialog.ld_filename);
		return -1;
	} else if (conf->children_num == 0) {
		LERROR("Configuration file %s is empty\n",
		       dialog.ld_filename);
		oconfig_free(conf);
		return -1;
	}

	/* Searching Lustre plugin configure*/
	for (i = 0; i < conf->children_num; i++) {
		if (strcasecmp(conf->children[i].key, "Plugin") == 0 &&
		    strcasecmp(conf->children[i].values[0].value.string,
			       "lustre") == 0) {
			configs = lustre_config(&conf->children[i], NULL);
		    	if (configs == NULL) {
				LERROR("failed to get Lustre configure");
				oconfig_free(conf);
				return -1;
			}
			break;
		}
	}
	oconfig_free(conf);

	if (configs == NULL) {
		LERROR("failed to get Lustre configure");
		return -1;
	}

	/* Generate backtitle */
	size = snprintf(dialog.ld_backtitle, sizeof(dialog.ld_backtitle),
			"%s", dialog.ld_filename);
	if (size >= sizeof(dialog.ld_backtitle)) {
		dialog.ld_backtitle[sizeof(dialog.ld_backtitle) - 1] = '\0';
	}

	dialog.ld_entry = configs->lc_definition.ld_root;
	dialog.ld_item_type = NULL;
	dialog.ld_item = NULL;
	dialog.ld_item_rule = NULL;
	dialog.ld_new_item_rule = 0;

	/* Show diablog */
	if (ldialog_init(&dialog)) {
		LERROR("Display is too small, neeed at least 19 lines by 80 columns\n");
		lustre_config_free(configs);
		return -1;
	}
	ldialog_show(configs, &dialog);
	ret = lustre_config_save(configs, dialog.ld_filename);
	if (ret) {
		LERROR("Failed to save configure to %s\n",
		       dialog.ld_filename);
	}
	ldialog_fini();
	lustre_config_free(configs);
	return ret;
}

/* vim: set sw=2 ts=2 tw=78 expandtab : */
