/**
 * collectd - src/lustre.c
 * Copyright (C) 2013  Li Xi
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

#ifndef LUSTRE_H
#define LUSTRE_H

#include <regex.h>
#include "list.h"

#define MAX_JOBSTAT_FIELD_LENGTH 32
#define MAX_SUBMIT_STRING_LENGTH 32

typedef enum {
	TYPE_NULL,
	TYPE_STRING,
	TYPE_NUMBER,
} value_type_t;

struct lustre_item_type;
typedef int (*lustre_read_fn) (struct lustre_item_type *type);

#define MAX_NAME_LENGH 1024

#define LUSTRE_FIELD_FLAG_INDEX				0x00000001
#define LUSTRE_FIELD_FLAG_NAME				0x00000002
#define LUSTRE_FIELD_FLAG_TYPE				0x00000004
#define LUSTRE_FIELD_FLAG_OPTION_HOST			0x00000008
#define LUSTRE_FIELD_FLAG_OPTION_PLUGIN			0x00000010
#define LUSTRE_FIELD_FLAG_OPTION_PLUGIN_INSTANCE	0x00000020
#define LUSTRE_FIELD_FLAG_OPTION_TYPE			0x00000040
#define LUSTRE_FIELD_FLAG_OPTION_TYPE_INSTANCE		0x00000080
#define LUSTRE_FIELD_FLAG_FILLED	(LUSTRE_FIELD_FLAG_INDEX | \
					 LUSTRE_FIELD_FLAG_NAME | \
					 LUSTRE_FIELD_FLAG_TYPE |\
					 LUSTRE_FIELD_FLAG_OPTION_HOST |\
					 LUSTRE_FIELD_FLAG_OPTION_PLUGIN |\
					 LUSTRE_FIELD_FLAG_OPTION_PLUGIN_INSTANCE |\
					 LUSTRE_FIELD_FLAG_OPTION_TYPE |\
					 LUSTRE_FIELD_FLAG_OPTION_TYPE_INSTANCE)


struct lustre_submit_option {
	char			lso_string[MAX_NAME_LENGH + 1];
};

struct lustre_submit {
	struct lustre_submit_option ls_host;
	struct lustre_submit_option ls_plugin;
	struct lustre_submit_option ls_plugin_instance;
	struct lustre_submit_option ls_type;
	struct lustre_submit_option ls_type_instance;
};

struct lustre_field_type {
	struct lustre_item_type	*lft_item_type;
	int			 lft_index;
	char			 lft_name[MAX_NAME_LENGH + 1];
	value_type_t		 lft_type;
	/* Linkage to item type */
	struct list_head	 lft_linkage;
	int			 lft_flags;
	struct lustre_submit	 lft_submit;
};

struct lustre_field {
	struct lustre_field_type	*lf_type;
	char				 lf_string[MAX_JOBSTAT_FIELD_LENGTH];
	uint64_t			 lf_value;
};

#define LUSTRE_ITEM_FLAG_NAME		0x00000001
#define LUSTRE_ITEM_FLAG_PATTERN	0x00000002
#define LUSTRE_ITEM_FLAG_FIELD		0x00000004
#define LUSTRE_ITEM_FLAG_CONTEXT	0x00000008
#define LUSTRE_ITEM_FLAG_FILLED		(LUSTRE_ITEM_FLAG_NAME | \
				  	 LUSTRE_ITEM_FLAG_PATTERN | \
				  	 LUSTRE_ITEM_FLAG_FIELD)

struct lustre_item_type {
	/* Pointer to entry */
	struct lustre_entry			 *lit_entry;
	char					  lit_type_name[MAX_NAME_LENGH + 1];
	char					  lit_pattern[MAX_NAME_LENGH + 1];
	regex_t				 	  lit_regex;
	/* Linkage to entry( TODO: remove definition) */
	struct list_head			  lit_linkage;
	/* Linkage to active */
	struct list_head			  lit_active_linkage;
	/* List of items */
	struct list_head			  lit_items;
	/* List of field types */
	struct list_head			  lit_field_list;
	/* Array of field types */
	struct lustre_field_type		**lit_field_array;
	int					  lit_field_number;
	int					  lit_flags;
	char					  lit_context[MAX_NAME_LENGH + 1];
	regex_t				 	  lit_context_regex;
};

#define LUSTRE_ENTRY_FLAG_SUBPATH	0x00000001
#define LUSTRE_ENTRY_FLAG_MODE		0x00000002
#define LUSTRE_ENTRY_FLAG_FILLED	(LUSTRE_ENTRY_FLAG_SUBPATH | \
				  	 LUSTRE_ENTRY_FLAG_MODE)

typedef enum {
	SUBPATH_CONSTANT = 1,
	SUBPATH_REGULAR_EXPRESSION,
} lustre_subpath_t;


struct lustre_entry {
	/* Pointer to parent */
	struct lustre_entry	*le_parent;
	/* Relative path from parent */
	char			 le_subpath[MAX_NAME_LENGH + 1];
	lustre_subpath_t	 le_subpath_type;
	regex_t			 le_subpath_regex;
	int			 le_subpath_field_number;
	/* Directory or file */
	mode_t			 le_mode;
	/* TODO: data */
	int			 le_flags;

	/* List of children */
	struct list_head	 le_children;
	/* Linkage to parent's le_children */
	struct list_head	 le_linkage;
	/* List of item types */
	struct list_head	 le_item_types;
	/* List of path field types */
	struct list_head	 le_subpath_field_types;

	/* Whether I am active */
	_Bool			 le_active;
	/* List of active children */
	struct list_head	 le_active_children;
	/* Linkage to parent's le_active_children */
	struct list_head	 le_active_linkage;
	/* List of active item types */
	struct list_head	 le_active_item_types;
};

struct lustre_definition {
	_Bool			  ld_inited;
	struct lustre_entry	 *ld_root;
	char			 *ld_version;
};

struct lustre_item_rule {
	int			lir_field_index;
	regex_t			lir_regex;
	char			lir_string[MAX_NAME_LENGH + 1];
	_Bool			lir_regex_inited;
	struct list_head	lir_linkage;
};

struct lustre_item {
	struct lustre_item_type *li_type;
	/* Linkage to type */
	struct list_head	 li_linkage;
	struct list_head	 li_rules;
};

struct lustre_configs {
	struct lustre_definition	 lc_definition;
	regex_t				 lc_regex;
	_Bool				 lc_debug;
};

struct lustre_item_data {
	int			 lid_filed_number;
	struct lustre_field	*lid_fields;
};

struct lustre_subpath_field_type {
	/* Linkage to list */
	struct list_head	 lpft_linkage;
	int			 lpft_index;
	struct lustre_entry	*lpft_entry;
	int			 lpft_flags;
	char			 lpft_name[MAX_NAME_LENGH + 1];
};


#define LUSTRE_SUBPATH_FIELD_FLAG_INDEX 0x00000001
#define LUSTRE_SUBPATH_FIELD_FLAG_NAME  0x00000002
#define LUSTRE_SUBPATH_FIELD_FLAG_FIELD (LUSTRE_SUBPATH_FIELD_FLAG_INDEX |\
					 LUSTRE_SUBPATH_FIELD_FLAG_NAME)

struct lustre_subpath_field {
	struct lustre_subpath_field_type	*lpf_type;
	char					 lpf_value[MAX_NAME_LENGH + 1];
};

struct lustre_subpath_fields {
	int				 lpfs_field_number;
	struct lustre_subpath_field	*lpfs_fileds;
	struct list_head		 lpfs_linkage;
};

extern struct lustre_configs *lustre_config_g;
struct lustre_field_type *lustre_field_type_alloc(void);
void lustre_field_type_free(struct lustre_field_type *field_type);
int
lustre_field_type_add(struct lustre_item_type *type,
		      struct lustre_field_type *field_type);
void lustre_item_type_free(struct lustre_item_type *type);
struct lustre_item_type *lustre_item_type_alloc(void);
int lustre_compile_regex(regex_t *preg, const char *regex);

#define LINFO(format, ...)                                                     \
do {                                                                           \
    INFO("%s:%d:%s(): "format, __FILE__, __LINE__, __FUNCTION__, ## __VA_ARGS__);  \
} while (0)
#endif /* LUSTRE_H */
