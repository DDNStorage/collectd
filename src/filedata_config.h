/**
 * collectd - src/filedata_config.h
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

#ifndef FILEDATA_CONFIG_H
#define FILEDATA_CONFIG_H

#include <regex.h>
#include <stdint.h>
#include "list.h"
#include "liboconfig/oconfig.h"

#define MAX_NAME_LENGH 1024
#define TYPE_NAME_LEN	64

#define MAX_JOBSTAT_FIELD_LENGTH 32
#define MAX_SUBMIT_STRING_LENGTH DATA_MAX_NAME_LEN
/* There might be a lot of tags, which means a long string */
#define MAX_TSDB_TAGS_LENGTH 1024

typedef enum {
	TYPE_NULL,
	TYPE_STRING,
	TYPE_NUMBER,
} value_type_t;

struct filedata_item_type;
struct filedata_configs;
typedef int (*filedata_read_fn) (struct filedata_item_type *type);

#define FILEDATA_FIELD_FLAG_INDEX			0x00000001
#define FILEDATA_FIELD_FLAG_NAME			0x00000002
#define FILEDATA_FIELD_FLAG_TYPE			0x00000004
#define FILEDATA_FIELD_FLAG_OPTION_HOST			0x00000008
#define FILEDATA_FIELD_FLAG_OPTION_PLUGIN		0x00000010
#define FILEDATA_FIELD_FLAG_OPTION_PLUGIN_INSTANCE	0x00000020
#define FILEDATA_FIELD_FLAG_OPTION_TYPE			0x00000040
#define FILEDATA_FIELD_FLAG_OPTION_TYPE_INSTANCE	0x00000080
#define FILEDATA_FIELD_FLAG_OPTION_TSDB_NAME		0x00000100
#define FILEDATA_FIELD_FLAG_OPTION_TSDB_TAGS		0x00000200
#define FILEDATA_FIELD_FLAG_FILLED	(FILEDATA_FIELD_FLAG_INDEX | \
					 FILEDATA_FIELD_FLAG_NAME | \
					 FILEDATA_FIELD_FLAG_TYPE |\
					 FILEDATA_FIELD_FLAG_OPTION_HOST |\
					 FILEDATA_FIELD_FLAG_OPTION_PLUGIN |\
					 FILEDATA_FIELD_FLAG_OPTION_PLUGIN_INSTANCE |\
					 FILEDATA_FIELD_FLAG_OPTION_TYPE |\
					 FILEDATA_FIELD_FLAG_OPTION_TYPE_INSTANCE |\
					 FILEDATA_FIELD_FLAG_OPTION_TSDB_NAME |\
					 FILEDATA_FIELD_FLAG_OPTION_TSDB_TAGS)


struct filedata_submit_option {
	char			lso_string[MAX_NAME_LENGH + 1];
};

struct filedata_submit {
	struct filedata_submit_option fs_host;
	struct filedata_submit_option fs_plugin;
	struct filedata_submit_option fs_plugin_instance;
	struct filedata_submit_option fs_type;
	struct filedata_submit_option fs_type_instance;
	/* Support for submiting to write_tsdb plugin */
	struct filedata_submit_option fs_tsdb_name;
	struct filedata_submit_option fs_tsdb_tags;
};

struct filedata_field_type {
	struct filedata_item_type	*fft_item_type;
	int				 fft_index;
	char				 fft_name[MAX_NAME_LENGH + 1];
	value_type_t			 fft_type;
	/* Linkage to item type */
	struct list_head		 fft_linkage;
	int				 fft_flags;
	struct filedata_submit		 fft_submit;
};

struct filedata_field {
	struct filedata_field_type	*ff_type;
	char				 ff_string[MAX_JOBSTAT_FIELD_LENGTH];
	uint64_t			 ff_value;
	int				 ff_allowed;
};

#define FILEDATA_ITEM_FLAG_NAME			0x00000001
#define FILEDATA_ITEM_FLAG_PATTERN		0x00000002
#define FILEDATA_ITEM_FLAG_FIELD		0x00000004
#define FILEDATA_ITEM_FLAG_CONTEXT		0x00000008
#define FILEDATA_ITEM_FLAG_CONTEXT_SUBTYPE	0x00000010
#define FILEDATA_ITEM_FLAG_FILLED		(FILEDATA_ITEM_FLAG_NAME | \
						 FILEDATA_ITEM_FLAG_PATTERN | \
						 FILEDATA_ITEM_FLAG_FIELD)

struct filedata_item_type {
	struct filedata_definition		 *fit_definition;
	/* Pointer to entry */
	struct filedata_entry			 *fit_entry;
	char					  fit_type_name[MAX_NAME_LENGH + 1];
	char					  fit_pattern[MAX_NAME_LENGH + 1];
	regex_t				 	  fit_regex;
	/* Linkage to entry( TODO: remove definition) */
	struct list_head			  fit_linkage;
	/* Linkage to active */
	struct list_head			  fit_active_linkage;
	/* List of items */
	struct list_head			  fit_items;
	/* List of extends */
	struct list_head			  fit_extends;
	char					  fit_ext_tags[MAX_TSDB_TAGS_LENGTH + 1];
	/* List of field types */
	struct list_head			  fit_field_list;
	/* Array of field types */
	struct filedata_field_type		**fit_field_array;
	int					  fit_field_number;
	int					  fit_flags;
	char					  fit_context[MAX_NAME_LENGH + 1];
	regex_t				 	  fit_context_regex;
	char					  fit_context_start[MAX_NAME_LENGH + 1];
	char					  fit_context_end[MAX_NAME_LENGH + 1];
};

struct filedata_item_rule {
	int			 fir_field_index;
	regex_t			 fir_regex;
	char			 fir_string[MAX_NAME_LENGH + 1];
	_Bool			 fir_regex_inited;
	/* Linkage to item */
	struct list_head	 fir_linkage;
	/* Pointer to item */
	struct filedata_item	*fir_item;
};

struct filedata_item_type_extend_field {
	/* Index of this field */
	int			fitef_index;
	char			fitef_name[MAX_NAME_LENGH + 1];
	char			fitef_value[MAX_NAME_LENGH + 1];
	/* Linkage of item type extend field */
	struct list_head	fitef_linkage;
	/* Pointer to item type extend */
	struct filedata_item_type_extend *fitef_ext;
};

struct filedata_item_type_extend {
	/* Filed index of this extend in item type*/
	int				fite_field_index;
	regex_t				fite_regex;
	char				fite_string[MAX_NAME_LENGH + 1];
	char				fite_tags[MAX_TSDB_TAGS_LENGTH + 1];
	_Bool				fite_regex_inited;
	/* Number of field in list fite_fields*/
	int				fite_field_number;
	/* List of item type extend field */
	struct list_head		fite_fields;
	/* Linkage to item type extend */
	struct list_head		fite_linkage;
	/* Pointer to item type */
	struct filedata_item_type	*fite_item_type;
};

struct filedata_item_filter {
	int			 fif_field_index;
	char			 fif_string[MAX_NAME_LENGH + 1];
	/* Linkage to item */
	struct list_head	 fif_linkage;
	/* Pointer to to item */
	struct filedata_item	*fif_item;

};

struct filedata_item {
	struct filedata_definition *fi_definition;
	struct filedata_item_type  *fi_type;
	int                         fi_query_interval;
	int query_interval;
	/* Linkage to type */
	struct list_head	    fi_linkage;
	struct list_head	    fi_rules;
	struct list_head	    fi_filters;
};

struct filedata_item_data {
	int			 fid_filed_number;
	struct filedata_field	*fid_fields;
	int			 fid_ext_tags_used;
	char			 fid_ext_tags[MAX_TSDB_TAGS_LENGTH + 1];
};

struct filedata_subpath_field_type {
	/* Linkage to list */
	struct list_head	 fpft_linkage;
	int			 fpft_index;
	struct filedata_entry	*fpft_entry;
	int			 fpft_flags;
	char			 fpft_name[MAX_NAME_LENGH + 1];
};


#define FILEDATA_SUBPATH_FIELD_FLAG_INDEX 0x00000001
#define FILEDATA_SUBPATH_FIELD_FLAG_NAME  0x00000002
#define FILEDATA_SUBPATH_FIELD_FLAG_FIELD (FILEDATA_SUBPATH_FIELD_FLAG_INDEX |\
					   FILEDATA_SUBPATH_FIELD_FLAG_NAME)

struct filedata_subpath_field {
	struct filedata_subpath_field_type	*fpf_type;
	char					 fpf_value[MAX_NAME_LENGH + 1];
};

struct filedata_subpath_fields {
	int				 fpfs_field_number;
	struct filedata_subpath_field	*fpfs_fileds;
	struct list_head		 fpfs_linkage;
};

#define FILEDATA_ENTRY_FLAG_SUBPATH	0x00000001
#define FILEDATA_ENTRY_FLAG_MODE	0x00000002
#define FILEDATA_ENTRY_FLAG_FILLED	(FILEDATA_ENTRY_FLAG_SUBPATH | \
					 FILEDATA_ENTRY_FLAG_MODE)

typedef enum {
	SUBPATH_CONSTANT = 1,
	SUBPATH_REGULAR_EXPRESSION,
} filedata_subpath_t;


struct filedata_entry {
	struct filedata_definition *fe_definition;
	/* Pointer to parent */
	struct filedata_entry	   *fe_parent;
	/* Relative path from parent */
	char			    fe_subpath[MAX_NAME_LENGH + 1];
	filedata_subpath_t	    fe_subpath_type;
	regex_t			    fe_subpath_regex;
	int			    fe_subpath_field_number;
	/* Directory or file */
	mode_t			    fe_mode;
	/* TODO: data */
	int			    fe_flags;

	/* List of children */
	struct list_head	    fe_children;
	/* Linkage to parent's fe_children */
	struct list_head	    fe_linkage;
	/* List of item types */
	struct list_head	    fe_item_types;
	/* List of path field types */
	struct list_head	    fe_subpath_field_types;

	/* Whether I am active */
	_Bool			    fe_active;
	/* List of active children */
	struct list_head	    fe_active_children;
	/* Linkage to parent's fe_active_children */
	struct list_head	    fe_active_linkage;
	/* List of active item types */
	struct list_head	    fe_active_item_types;
};

typedef int (*filedata_read_file_fn)
	(const char *path, char **buf, ssize_t *data_size,
	 void *private_data);
typedef int (*filedata_private_init_fn)
	(struct filedata_configs *);
typedef void (*filedata_private_fini_fn)
	(struct filedata_configs *);
typedef int (*filedata_private_config_fn)
	(oconfig_item_t *ci, struct filedata_configs *conf);

struct filedata_private_definition {
	/* Private data used by specific plugins */
	void				*fd_private_data;
	filedata_private_init_fn	 fd_private_init;
	filedata_private_fini_fn	 fd_private_fini;
	filedata_private_config_fn	 fd_private_config;
};

struct filedata_definition {
	_Bool			  fd_inited;
	struct filedata_entry	 *fd_root;
	char			 *fd_filename;
	unsigned long long	  fd_query_times;
	filedata_read_file_fn	  fd_read_file;
	struct filedata_private_definition fd_private_definition;
	/* used for tsdb tags */
	char			 *extra_tags;
};

struct filedata_configs {
	struct filedata_definition fc_definition;
};
struct filedata_configs *filedata_config(oconfig_item_t *ci,
					 struct filedata_private_definition *
					 fd_private_definition);
static inline void *filedata_get_private_data(struct filedata_configs *conf)
{
	return conf->fc_definition.fd_private_definition.fd_private_data;
}

int filedata_config_save(struct filedata_configs *conf,
			 const char *config_file);
void filedata_config_free(struct filedata_configs *conf);
int filedata_config_get_string(const oconfig_item_t *ci, char **ret_string);
int filedata_compile_regex(regex_t *preg, const char *regex);
void filedata_definition_fini(struct filedata_definition *definition);
int filedata_item_match(struct filedata_field *fields,
			int field_number,
			struct filedata_item_type *type);
struct filedata_item *filedata_item_alloc();
void filedata_item_add(struct filedata_item *item);
void filedata_item_free(struct filedata_item *item);
void filedata_item_unlink(struct filedata_item *item);

struct filedata_field_type *filedata_field_type_alloc(void);
void filedata_field_type_free(struct filedata_field_type *field_type);
int
filedata_field_type_add(struct filedata_item_type *type,
			struct filedata_field_type *field_type);
void filedata_item_type_free(struct filedata_item_type *type);
struct filedata_item_type *filedata_item_type_alloc(void);

void filedata_item_rule_free(struct filedata_item_rule *rule);
void filedata_item_rule_unlink(struct filedata_item_rule *rule);
void filedata_item_rule_add(struct filedata_item *item,
			    struct filedata_item_rule *rule);
void filedata_item_rule_replace(struct filedata_item *item,
				struct filedata_item_rule *old,
				struct filedata_item_rule *new);
struct filedata_item_type_extend_field *
filedata_item_extend_field_find(struct filedata_item_type *type, const char *name);
#endif /* FILEDATA_CONFIG_H */
