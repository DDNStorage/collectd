/**
 * collectd - src/lustre_config.h
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

#ifndef LUSTRE_CONFIG_H
#define LUSTRE_CONFIG_H

#include <regex.h>
#include <stdint.h>
#include "list.h"
#include "liboconfig/oconfig.h"

#define MAX_NAME_LENGH 1024

#define MAX_JOBSTAT_FIELD_LENGTH 32
#define MAX_SUBMIT_STRING_LENGTH DATA_MAX_NAME_LEN

typedef enum {
	TYPE_NULL,
	TYPE_STRING,
	TYPE_NUMBER,
} value_type_t;

struct lustre_item_type;
typedef int (*lustre_read_fn) (struct lustre_item_type *type);

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
	int				 lf_allowed;
};

#define LUSTRE_ITEM_FLAG_NAME		0x00000001
#define LUSTRE_ITEM_FLAG_PATTERN	0x00000002
#define LUSTRE_ITEM_FLAG_FIELD		0x00000004
#define LUSTRE_ITEM_FLAG_CONTEXT	0x00000008
#define LUSTRE_ITEM_FLAG_FILLED		(LUSTRE_ITEM_FLAG_NAME | \
				  	 LUSTRE_ITEM_FLAG_PATTERN | \
				  	 LUSTRE_ITEM_FLAG_FIELD)

struct lustre_item_type {
	struct lustre_definition		 *lit_definition;
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

struct lustre_item_rule {
	int			 lir_field_index;
	regex_t			 lir_regex;
	char			 lir_string[MAX_NAME_LENGH + 1];
	_Bool			 lir_regex_inited;
	/* Linkage to item */
	struct list_head	 lir_linkage;
	/* Pointer to to item */
	struct lustre_item	*lir_item;
};

struct lustre_item_filter {
	int			 lif_field_index;
	char			 lif_string[MAX_NAME_LENGH + 1];
	/* Linkage to item */
	struct list_head	 lif_linkage;
	/* Pointer to to item */
	struct lustre_item	*lif_item;

};

struct lustre_item {
	struct lustre_definition *li_definition;
	struct lustre_item_type  *li_type;
	int                       li_query_interval;
	int query_interval;
	/* Linkage to type */
	struct list_head	  li_linkage;
	struct list_head	  li_rules;
	struct list_head	  li_filters;
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

#define LUSTRE_ENTRY_FLAG_SUBPATH	0x00000001
#define LUSTRE_ENTRY_FLAG_MODE		0x00000002
#define LUSTRE_ENTRY_FLAG_FILLED	(LUSTRE_ENTRY_FLAG_SUBPATH | \
				  	 LUSTRE_ENTRY_FLAG_MODE)

typedef enum {
	SUBPATH_CONSTANT = 1,
	SUBPATH_REGULAR_EXPRESSION,
} lustre_subpath_t;


struct lustre_entry {
	struct lustre_definition *le_definition;
	/* Pointer to parent */
	struct lustre_entry	 *le_parent;
	/* Relative path from parent */
	char			  le_subpath[MAX_NAME_LENGH + 1];
	lustre_subpath_t	  le_subpath_type;
	regex_t			  le_subpath_regex;
	int			  le_subpath_field_number;
	/* Directory or file */
	mode_t			  le_mode;
	/* TODO: data */
	int			  le_flags;

	/* List of children */
	struct list_head	  le_children;
	/* Linkage to parent's le_children */
	struct list_head	  le_linkage;
	/* List of item types */
	struct list_head	  le_item_types;
	/* List of path field types */
	struct list_head	  le_subpath_field_types;

	/* Whether I am active */
	_Bool			  le_active;
	/* List of active children */
	struct list_head	  le_active_children;
	/* Linkage to parent's le_active_children */
	struct list_head	  le_active_linkage;
	/* List of active item types */
	struct list_head	  le_active_item_types;
};

typedef int (*lustre_read_file_fn)
	(const char *path, char **buf, ssize_t *data_size);

struct lustre_definition {
	_Bool			  ld_inited;
	struct lustre_entry	 *ld_root;
	char			 *ld_filename;
	unsigned long long	  ld_query_times;
	lustre_read_file_fn	  ld_read_file;
};

struct lustre_configs {
	struct lustre_definition lc_definition;
};
struct lustre_configs *lustre_config(oconfig_item_t *ci);
int lustre_config_save(struct lustre_configs *conf,
		       const char *config_file);
void lustre_config_free(struct lustre_configs *conf);
int lustre_compile_regex(regex_t *preg, const char *regex);
void lustre_definition_fini(struct lustre_definition *definition);
int lustre_item_match(struct lustre_field *fields,
		      int field_number,
		      struct lustre_item_type *type);
struct lustre_item *lustre_item_alloc();
void lustre_item_add(struct lustre_item *item);
void lustre_item_free(struct lustre_item *item);
void lustre_item_unlink(struct lustre_item *item);

struct lustre_field_type *lustre_field_type_alloc(void);
void lustre_field_type_free(struct lustre_field_type *field_type);
int
lustre_field_type_add(struct lustre_item_type *type,
		      struct lustre_field_type *field_type);
void lustre_item_type_free(struct lustre_item_type *type);
struct lustre_item_type *lustre_item_type_alloc(void);

void lustre_item_rule_free(struct lustre_item_rule *rule);
void lustre_item_rule_unlink(struct lustre_item_rule *rule);
void lustre_item_rule_add(struct lustre_item *item,
			  struct lustre_item_rule *rule);
void lustre_item_rule_replace(struct lustre_item *item,
			      struct lustre_item_rule *old,
			      struct lustre_item_rule *new);
#endif /* LUSTRE_CONFIG_H */
