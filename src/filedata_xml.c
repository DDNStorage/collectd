/**
 * collectd - src/filedata_xml.c
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

#include <stdio.h>
#include <libxml/parser.h>
#include <libxml/tree.h>
#include <string.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>
#include "list.h"
#include "filedata_common.h"
#include "filedata_config.h"

static struct filedata_subpath_field_type *
filedata_subpath_field_type_alloc(void)
{
	struct filedata_subpath_field_type *field_type;
	field_type = calloc(1, sizeof(struct filedata_subpath_field_type));
	if (field_type == NULL)
		return NULL;

	INIT_LIST_HEAD(&field_type->fpft_linkage);
	return field_type;
}

static void
filedata_subpath_field_type_free(struct filedata_subpath_field_type *field_type)
{
	free(field_type);
}

static int
filedata_subpath_field_type_add(struct filedata_entry *entry,
				struct filedata_subpath_field_type *field_type)
{
	if (field_type->fpft_index != entry->fe_subpath_field_number + 1) {
		FERROR("index number of field is false, expecting %d, got %d",
		      entry->fe_subpath_field_number + 1,
		      field_type->fpft_index);
		return -1;
	}
	field_type->fpft_entry = entry;
	list_add_tail(&field_type->fpft_linkage, &entry->fe_subpath_field_types);
	entry->fe_subpath_field_number++;
	return 0;
}

static int
filedata_entry_add(struct filedata_entry *parent, struct filedata_entry *child)
{
	child->fe_parent = parent;
	list_add_tail(&child->fe_linkage, &parent->fe_children);

	return 0;
}

static
struct filedata_entry *filedata_entry_alloc(void)
{
	struct filedata_entry *entry;

	entry = calloc(1, sizeof(struct filedata_entry));
	if (entry == NULL) {
		FERROR("XML: not enough memory");
		return NULL;
	}

	INIT_LIST_HEAD(&entry->fe_children);
	INIT_LIST_HEAD(&entry->fe_item_types);
	INIT_LIST_HEAD(&entry->fe_linkage);
	INIT_LIST_HEAD(&entry->fe_subpath_field_types);
	INIT_LIST_HEAD(&entry->fe_active_children);
	INIT_LIST_HEAD(&entry->fe_active_linkage);
	INIT_LIST_HEAD(&entry->fe_active_item_types);

	return entry;
}

void
filedata_entry_free(struct filedata_entry *entry)
{
	struct filedata_entry *child;
	struct filedata_entry *n;
	struct filedata_item_type *item;
	struct filedata_item_type *i;
	struct filedata_subpath_field_type *path;
	struct filedata_subpath_field_type *p;

	list_for_each_entry_safe(child,
				 n,
	                         &entry->fe_children,
	                         fe_linkage) {
		list_del_init(&child->fe_linkage);
		filedata_entry_free(child);
	}

	list_for_each_entry_safe(item,
				 i,
	                         &entry->fe_item_types,
	                         fit_linkage) {
		list_del_init(&item->fit_linkage);
		filedata_item_type_free(item);
	}

	list_for_each_entry_safe(path,
				 p,
	                         &entry->fe_subpath_field_types,
	                         fpft_linkage) {
		list_del_init(&path->fpft_linkage);
		filedata_subpath_field_type_free(path);
	}
	if (entry->fe_flags & FILEDATA_ENTRY_FLAG_SUBPATH &&
	    entry->fe_subpath_type == SUBPATH_REGULAR_EXPRESSION)
		regfree(&entry->fe_subpath_regex);

	free(entry);
}

#define FILEDATA_XML_DEFINITION		"definition"
#define FILEDATA_XML_VERSION		"version"
#define FILEDATA_XML_ENTRY		"entry"
#define FILEDATA_XML_SUBPATH		"subpath"
#define FILEDATA_XML_MODE		"mode"
#define FILEDATA_XML_ITEM		"item"
#define FILEDATA_XML_DIRECTORY		"directory"
#define FILEDATA_XML_FILE		"file"
#define FILEDATA_XML_NAME		"name"
#define FILEDATA_XML_TYPE		"type"
#define FILEDATA_XML_PATTERN		"pattern"
#define FILEDATA_XML_FIELD		"field"
#define FILEDATA_XML_INDEX		"index"
#define FILEDATA_XML_STRING		"string"
#define FILEDATA_XML_NUMBER		"number"
#define FILEDATA_XML_OPTION		"option"
#define FILEDATA_XML_KEYWORD		"keyword"
#define FILEDATA_XML_HOST		"host"
#define FILEDATA_XML_PLUGIN		"plugin"
#define FILEDATA_XML_PLUGIN_INSTANCE	"plugin_instance"
#define FILEDATA_XML_TSDB_NAME		"tsdb_name"
#define FILEDATA_XML_TSDB_TAGS		"tsdb_tags"
#define FILEDATA_XML_OPTION_TYPE	"type"
#define FILEDATA_XML_TYPE_INSTANCE	"type_instance"
#define FILEDATA_XML_CONSTANT		"constant"
#define FILEDATA_XML_PATH_FIELD_NAME	"path_field_name"
#define FILEDATA_XML_PATH_FIELD		"path_field"
#define FILEDATA_XML_CONTENT_FIELD	"content_field"
#define FILEDATA_XML_CONTENT_FIELD_NAME	"content_field_name"
#define FILEDATA_XML_SUBPATH_TYPE	"subpath_type"
#define FILEDATA_XML_PATH		"path"
#define FILEDATA_XML_REGULAR_EXPRESSION	"regular_expression"
#define FILEDATA_XML_SUBPATH_FIELD 	"subpath_field"
#define FILEDATA_XML_CONTEXT 		"context"
#define FILEDATA_XML_CONTEXT_START	"start_string"
#define FILEDATA_XML_CONTEXT_END	"end_string"
#define FILEDATA_XML_WRITE_AFTER_READ	"write_after_read"

static int string2mode(const char *string, mode_t *mode)
{
	if (strcmp(string, FILEDATA_XML_DIRECTORY) == 0) {
		*mode = S_IFDIR;
	} else if (strcmp(string, FILEDATA_XML_FILE) == 0) {
		*mode = S_IFREG;
	} else {
		FERROR("XML: unkown mode");
		return -1;
	}
	return 0;
}

static char *mode2string(mode_t mode)
{
	if (mode == S_IFDIR) {
		return FILEDATA_XML_DIRECTORY;
	} else if (mode == S_IFREG) {
		return FILEDATA_XML_FILE;
	} else {
		FERROR("XML: unkown mode");
		return NULL;
	}
	return NULL;
}

static int filedata_field_string2type(char *string, value_type_t *type)
{
	if (strcmp(string, FILEDATA_XML_NUMBER) == 0) {
		*type = TYPE_NUMBER;
	} else if (strcmp(string, FILEDATA_XML_STRING) == 0) {
		*type = TYPE_STRING;
	} else {
		FERROR("XML: unkown type");
		return -1;
	}
	return 0;
}

static const char *filedata_field_type2string(value_type_t type)
{
	if (type == TYPE_STRING) {
		return FILEDATA_XML_STRING;
	} else if (type == TYPE_NUMBER) {
		return FILEDATA_XML_NUMBER;
	} else {
		FERROR("XML: unkown type");
		return NULL;
	}
	return NULL;
}

void filedata_entry_dump(struct filedata_entry *entry, int depth)
{
	struct filedata_entry *child;
	struct filedata_item_type *item;
	struct filedata_field_type *field;
	struct filedata_subpath_field_type *subpath_field;
	char prefix[1024];
	int i;

	for (i = 0; i < depth; i++) {
		prefix[i] = ' ';
	}
	prefix[i] = '\0';

	FINFO("%sentry %s, mode %s",
	      prefix, entry->fe_subpath,
	      mode2string(entry->fe_mode));

	list_for_each_entry(item,
	                    &entry->fe_item_types,
	                    fit_linkage) {
		FINFO("%s item %s, pattern %s, %llu",
		      prefix, item->fit_type_name,
		      item->fit_pattern,
		      (unsigned long long)item->fit_regex.re_nsub);
		list_for_each_entry(field,
				    &item->fit_field_list,
				    fft_linkage) {
			FINFO("%s  field[%d] %s, type %s",
			      prefix, field->fft_index,
			      field->fft_name,
			      filedata_field_type2string(field->fft_type));
		}
	}

	list_for_each_entry(subpath_field,
	                    &entry->fe_subpath_field_types,
	                    fpft_linkage) {
		FINFO("%s subpath_field[%d] %s",
		      prefix, subpath_field->fpft_index,
		      subpath_field->fpft_name);
	}

	list_for_each_entry(child,
	                    &entry->fe_children,
	                    fe_linkage) {
		filedata_entry_dump(child, depth + 1);
	}
}

void filedata_entry_dump_active(struct filedata_entry *entry, int depth)
{
	struct filedata_entry *child;
	struct filedata_item_type *item;
	char prefix[1024];
	int i;

	if (!entry->fe_active)
		return;

	for (i = 0; i < depth; i++) {
		prefix[i] = ' ';
	}
	prefix[i] = '\0';

	FINFO("%sentry %s, mode %s",
	      prefix, entry->fe_subpath,
	      mode2string(entry->fe_mode));

	list_for_each_entry(item,
			    &entry->fe_active_item_types,
			    fit_active_linkage) {
		FINFO("%s item %s, pattern %s, %llu",
		      prefix, item->fit_type_name,
		      item->fit_pattern,
		      (unsigned long long)item->fit_regex.re_nsub);
	}

	list_for_each_entry(child,
			    &entry->fe_active_children,
			    fe_active_linkage) {
		filedata_entry_dump_active(child, depth + 1);
	}
}

static void
filedata_item_type_add(struct filedata_entry *entry,
		       struct filedata_item_type *item)
{
	item->fit_entry = entry;
	list_add_tail(&item->fit_linkage, &entry->fe_item_types);
}

int
filedata_option_name_extract(char *name,
			     struct filedata_submit *submit,
			     int *flag,
			     struct filedata_submit_option **option)
{
	if (strcmp(name, FILEDATA_XML_HOST) == 0) {
		*flag = FILEDATA_FIELD_FLAG_OPTION_HOST;
		*option = &submit->fs_host;
	} else if (strcmp(name, FILEDATA_XML_PLUGIN) == 0) {
		*flag = FILEDATA_FIELD_FLAG_OPTION_PLUGIN;
		*option = &submit->fs_plugin;
	} else if (strcmp(name, FILEDATA_XML_PLUGIN_INSTANCE) == 0) {
		*flag = FILEDATA_FIELD_FLAG_OPTION_PLUGIN_INSTANCE;
		*option = &submit->fs_plugin_instance;
	} else if (strcmp(name, FILEDATA_XML_OPTION_TYPE) == 0) {
		*flag = FILEDATA_FIELD_FLAG_OPTION_TYPE;
		*option = &submit->fs_type;
	} else if (strcmp(name, FILEDATA_XML_TYPE_INSTANCE) == 0) {
		*flag = FILEDATA_FIELD_FLAG_OPTION_TYPE_INSTANCE;
		*option = &submit->fs_type_instance;
	} else if (strcmp(name, FILEDATA_XML_TSDB_NAME) == 0) {
		*flag = FILEDATA_FIELD_FLAG_OPTION_TSDB_NAME;
		*option = &submit->fs_tsdb_name;
	} else if (strcmp(name, FILEDATA_XML_TSDB_TAGS) == 0) {
		*flag = FILEDATA_FIELD_FLAG_OPTION_TSDB_TAGS;
		*option = &submit->fs_tsdb_tags;
	} else {
		FERROR("XML: unkown type");
		return -1;
	}
	return 0;
}

int
filedata_option_init(struct filedata_submit_option *option,
		     char *string)
{
	strncpy(option->lso_string, string, MAX_NAME_LENGH);
	return 0;
}

static int
filedata_context_option_parse(struct filedata_item_type *item, xmlNode *node)
{
	xmlNode *tmp;
	int status = 0;
	char *value;
	int start = 0;
	int end = 0;

	for (tmp = node; tmp; tmp = tmp->next) {
		if (tmp->type != XML_ELEMENT_NODE)
			continue;

		if (strcmp((char *)tmp->name, FILEDATA_XML_CONTEXT_START) == 0) {
			value = (char *)xmlNodeGetContent(tmp);
			strncpy(item->fit_context_start, value, MAX_NAME_LENGH);
			xmlFree(value);
			start = 1;
		} else if (strcmp((char *)tmp->name, FILEDATA_XML_CONTEXT_END)
			   == 0) {
			value = (char *)xmlNodeGetContent(tmp);
			strncpy(item->fit_context_end, value, MAX_NAME_LENGH);
			xmlFree(value);
			end = 1;
		} else {
			FERROR("XML: option has a unknown child %s", tmp->name);
			status = -1;
			break;
		}
	}

	if (status)
		return status;

	if (!start && !end)
		return 0;
	else if (start && !end)
		return 1;
	else if (start && end)
		return 2;

	return -1;
}

static int
filedata_xml_option_parse(struct filedata_field_type *field, xmlNode *node)
{
	xmlNode *tmp;
	int status = 0;
	char *value;
	int flag = 0;
	struct filedata_submit_option *option = NULL;
	char string[1024];
	int inited = 0;

	for (tmp = node; tmp; tmp = tmp->next) {
		if (tmp->type != XML_ELEMENT_NODE) {
			continue;
		}

		if (strcmp((char *)tmp->name, FILEDATA_XML_NAME) == 0) {
			value = (char*)xmlNodeGetContent(tmp);
			status = filedata_option_name_extract(value,
							&field->fft_submit,
							&flag,
							&option);
			if (status) {
				FERROR("XML: unkown option");
				break;
			}
			xmlFree(value);
		} else if (strcmp((char *)tmp->name, FILEDATA_XML_STRING) == 0) {
			if (inited != 0) {
				FERROR("XML: more than one type");
				status = -1;
				break;
			}
			value = (char*)xmlNodeGetContent(tmp);
			strncpy(string, value, 1024);
			xmlFree(value);
			inited = 1;
		} else {
			FERROR("XML: option has a unknown child %s", tmp->name);
			status = -1;
			break;
		}
	}

	if (status) {
		return status;
	}

	if (flag == 0 || option == NULL) {
		FERROR("XML: option has no name");
		return -1;
	}

	if (inited == 0) {
		FERROR("XML: option has no value");
		return -1;
	}

	filedata_option_init(option, string);
	field->fft_flags |= flag;
	return 0;
}

static int
filedata_xml_field_parse(struct filedata_item_type *item, xmlNode *node)
{
	xmlNode *tmp;
	int status = 0;
	char *value;
	struct filedata_field_type *field;

	field = filedata_field_type_alloc();
	if (field == NULL) {
		FERROR("XML: not enough memory");
		return -1;
	}

	for (tmp = node; tmp; tmp = tmp->next) {
		if (tmp->type != XML_ELEMENT_NODE) {
			continue;
		}

		if (strcmp((char *)tmp->name, FILEDATA_XML_INDEX) == 0) {
			value = (char*)xmlNodeGetContent(tmp);
			field->fft_index = strtoull(value, NULL, 10);
			if (field->fft_index != item->fit_field_number + 1) {
				status = -1;
				FERROR("XML: index of field is false, "
				      "expecting %d, got %d",
				      item->fit_field_number + 1,
				      field->fft_index);
				xmlFree(value);
				break;
			}
			field->fft_flags |= FILEDATA_FIELD_FLAG_INDEX;
			xmlFree(value);
		} else if (strcmp((char *)tmp->name, FILEDATA_XML_NAME) == 0) {
			value = (char*)xmlNodeGetContent(tmp);
			if (strlen(value) > MAX_NAME_LENGH) {
				status = -1;
				FERROR("XML: name %s is too long", value);
				xmlFree(value);
				break;
			}
			strncpy(field->fft_name, value, MAX_NAME_LENGH);
			field->fft_flags |= FILEDATA_FIELD_FLAG_NAME;
			xmlFree(value);
		} else if (strcmp((char *)tmp->name, FILEDATA_XML_TYPE) == 0) {
			value = (char*)xmlNodeGetContent(tmp);
			status = filedata_field_string2type(value, &field->fft_type);
			if (status) {
				FERROR("XML: type %s is illegal", value);
				xmlFree(value);
				break;
			}
			field->fft_flags |= FILEDATA_FIELD_FLAG_TYPE;
			xmlFree(value);
		} else if (strcmp((char *)tmp->name, FILEDATA_XML_OPTION) == 0) {
			status = filedata_xml_option_parse(field, tmp->children);
			if (status) {
				FERROR("XML: failed to compile field");
				break;
			}
		} else {
			FERROR("XML: field have a unknown child %s", tmp->name);
			status = -1;
			break;
		}
	}

	if ((field->fft_flags & FILEDATA_FIELD_FLAG_FILLED)
	    != FILEDATA_FIELD_FLAG_FILLED) {
		FERROR("XML: some fields of item is missing, flag = %d",
		      field->fft_flags);
		status = -1;
	}

	if (status) {
		filedata_field_type_free(field);
	} else {
		status = filedata_field_type_add(item, field);
		if (status) {
			filedata_field_type_free(field);
		}
	}
	return status;
}

static int filedata_item_type_build(struct filedata_item_type *item)
{
	int i = 0;
	struct filedata_field_type *field_type;

	item->fit_field_array = calloc(item->fit_field_number + 1,
				       sizeof(struct filedata_field_type *));
	if (item->fit_field_array == NULL) {
		FERROR("XML: not enough memory");
		return -1;
	}

	list_for_each_entry(field_type,
	                    &item->fit_field_list,
	                    fft_linkage) {
		i++;
		item->fit_field_array[i] = field_type;
	}
	return 0;
}

static int
filedata_xml_item_parse(struct filedata_entry *entry, xmlNode *node)
{
	xmlNode *tmp;
	int status = 0;
	char *value;
	struct filedata_item_type *item;

	item = filedata_item_type_alloc();
	if (item == NULL) {
		FERROR("XML: not enough memory");
		return -1;
	}
	item->fit_definition = entry->fe_definition;

	for (tmp = node; tmp; tmp = tmp->next) {
		if (tmp->type != XML_ELEMENT_NODE) {
			continue;
		}

		if (strcmp((char *)tmp->name, FILEDATA_XML_NAME) == 0) {
			value = (char*)xmlNodeGetContent(tmp);
			if (strlen(value) > MAX_NAME_LENGH) {
				status = -1;
				FERROR("XML: name %s is too long", value);
				xmlFree(value);
				break;
			}
			strncpy(item->fit_type_name, value, MAX_NAME_LENGH);
			item->fit_flags |= FILEDATA_ITEM_FLAG_NAME;
			xmlFree(value);
		} else if (strcmp((char *)tmp->name, FILEDATA_XML_PATTERN) == 0) {
			value = (char*)xmlNodeGetContent(tmp);
			if (strlen(value) > MAX_NAME_LENGH) {
				status = -1;
				FERROR("XML: pattern %s is too long", value);
				xmlFree(value);
				break;
			}
			strncpy(item->fit_pattern, value, MAX_NAME_LENGH);
			xmlFree(value);
			status = filedata_compile_regex(&item->fit_regex,
							item->fit_pattern);
			if (status) {
				FERROR("XML: failed to compile pattern %s",
					item->fit_pattern);
				break;
			}
			item->fit_flags |= FILEDATA_ITEM_FLAG_PATTERN;
		} else if (strcmp((char *)tmp->name, FILEDATA_XML_FIELD) == 0) {
			status = filedata_xml_field_parse(item, tmp->children);
			if (status) {
				FERROR("XML: failed to compile field");
				break;
			}
			item->fit_flags |= FILEDATA_ITEM_FLAG_FIELD;
		} else if (strcmp((char *)tmp->name, FILEDATA_XML_CONTEXT) == 0) {
			status = filedata_context_option_parse(item,
							       tmp->children);
			if (status > 0) {
				item->fit_flags |=
					FILEDATA_ITEM_FLAG_CONTEXT_SUBTYPE;
				status = 0;
				continue;
			} else if (status < 0) {
				break;
			}

			value = (char*)xmlNodeGetContent(tmp);
			if (strlen(value) > MAX_NAME_LENGH) {
				status = -1;
				FERROR("XML: context %s is too long", value);
				xmlFree(value);
				break;
			}
			strncpy(item->fit_context, value, MAX_NAME_LENGH);
			xmlFree(value);
			status = filedata_compile_regex(&item->fit_context_regex,
							item->fit_context);
			if (status) {
				FERROR("XML: failed to compile context %s",
					item->fit_context);
				break;
			}
			item->fit_flags |= FILEDATA_ITEM_FLAG_CONTEXT;
		} else {
			FERROR("XML: entry have a unknown child %s", tmp->name);
			status = -1;
			break;
		}
	}

	if ((item->fit_flags & FILEDATA_ITEM_FLAG_FILLED)
	    != FILEDATA_ITEM_FLAG_FILLED) {
		FERROR("XML: some fields of item is missing, falg = %d",
		      item->fit_flags);
		status = -1;
	}

	if (item->fit_field_number != item->fit_regex.re_nsub) {
		FERROR("XML: field number of item is false");
		status = -1;
	}

	if (status == 0) {
		status = filedata_item_type_build(item);
	}

	if (status == 0) {
		filedata_item_type_add(entry, item);
	}

	if (status) {
		filedata_item_type_free(item);
	}
	return status;
}

static int
filedata_xml_subpath_field_parse(struct filedata_entry *entry, xmlNode *node)
{
	xmlNode *tmp;
	int status = 0;
	char *value;
	struct filedata_subpath_field_type *field;

	field = filedata_subpath_field_type_alloc();
	if (field == NULL) {
		FERROR("XML: not enough memory");
		return -1;
	}

	for (tmp = node; tmp; tmp = tmp->next) {
		if (tmp->type != XML_ELEMENT_NODE) {
			continue;
		}

		if (strcmp((char *)tmp->name, FILEDATA_XML_INDEX) == 0) {
			value = (char*)xmlNodeGetContent(tmp);
			field->fpft_index = strtoull(value, NULL, 10);
			if (field->fpft_index != entry->fe_subpath_field_number + 1) {
				status = -1;
				FERROR("XML: index %s of field is false", value);
				xmlFree(value);
				break;
			}
			field->fpft_flags |= FILEDATA_SUBPATH_FIELD_FLAG_INDEX;
			xmlFree(value);
		} else if (strcmp((char *)tmp->name, FILEDATA_XML_NAME) == 0) {
			value = (char*)xmlNodeGetContent(tmp);
			if (strlen(value) > MAX_NAME_LENGH) {
				status = -1;
				FERROR("XML: name %s is too long", value);
				xmlFree(value);
				break;
			}
			strncpy(field->fpft_name, value, MAX_NAME_LENGH);
			field->fpft_flags |= FILEDATA_SUBPATH_FIELD_FLAG_NAME;
			xmlFree(value);
		} else {
			FERROR("XML: field have a unknown child %s", tmp->name);
			status = -1;
			break;
		}
	}

	if (field->fpft_flags != FILEDATA_SUBPATH_FIELD_FLAG_FIELD) {
		FERROR("XML: some fields of item is missing");
		status = -1;
	}

	if (status) {
		filedata_subpath_field_type_free(field);
	} else {
		status = filedata_subpath_field_type_add(entry, field);
		if (status) {
			filedata_subpath_field_type_free(field);
		}
	}
	return status;
}

static int
filedata_xml_subpath_parse(struct filedata_entry *entry, xmlNode *node)
{
	xmlNode *tmp;
	int status = 0;
	char *value;
	int inited = 0;

	for (tmp = node; tmp; tmp = tmp->next) {
		if (tmp->type != XML_ELEMENT_NODE) {
			continue;
		}
		if (strcmp((char *)tmp->name, FILEDATA_XML_SUBPATH_TYPE) == 0) {
			value = (char*)xmlNodeGetContent(tmp);
			if (strcmp(value, FILEDATA_XML_CONSTANT) == 0) {
				entry->fe_subpath_type = SUBPATH_CONSTANT;
			} else if (strcmp(value, FILEDATA_XML_REGULAR_EXPRESSION) == 0) {
				entry->fe_subpath_type = SUBPATH_REGULAR_EXPRESSION;
			} else {
				status = -1;
				xmlFree(value);
				FERROR("XML: subpath_type %s is unknown\n", value);
				break;
			}
			xmlFree(value);
		} else if (strcmp((char *)tmp->name, FILEDATA_XML_PATH) == 0) {
			value = (char*)xmlNodeGetContent(tmp);
			if (strlen(value) > MAX_NAME_LENGH) {
				status = -1;
				FERROR("XML: path %s is too long\n", value);
				xmlFree(value);
				break;
			}
			strncpy(entry->fe_subpath, value, MAX_NAME_LENGH);
			inited = 1;
			xmlFree(value);
		} else if (strcmp((char *)tmp->name, FILEDATA_XML_SUBPATH_FIELD) == 0) {
			status = filedata_xml_subpath_field_parse(entry, tmp->children);
			if (status) {
				break;
			}
		} else {
			FERROR("XML: subpath have a unknown child %s", tmp->name);
			status = -1;
			break;
		}
	}

	if (status) {
		return status;
	}

	if (!inited) {
		FERROR("XML: subpath does not have path");
		return -1;
	}

	if (entry->fe_subpath_type == SUBPATH_REGULAR_EXPRESSION) {
		status = filedata_compile_regex (&entry->fe_subpath_regex,
						 entry->fe_subpath);
		if (status) {
			FERROR("XML: failed to compile regular expression %s",
				entry->fe_subpath);
		} else {
			if (entry->fe_subpath_regex.re_nsub != entry->fe_subpath_field_number) {
				FERROR("XML: subpath field number is error");
				status = -1;
			}
		}
	} else if (entry->fe_subpath_type != SUBPATH_CONSTANT) {
		FERROR("XML: subpath does not have subpath_type");
		return -1;
	}
	return status;
}

static int
filedata_xml_entry_parse(struct filedata_entry *parent, xmlNode *node)
{
	xmlNode *tmp;
	int status = 0;
	char *value;
	struct filedata_entry *child;

	child = filedata_entry_alloc();
	if (child == NULL) {
		FERROR("XML: not enough memory");
		return -1;
	}
	child->fe_definition = parent->fe_definition;

	for (tmp = node; tmp; tmp = tmp->next) {
		if (tmp->type != XML_ELEMENT_NODE) {
			continue;
		}

		if (strcmp((char *)tmp->name, FILEDATA_XML_SUBPATH) == 0) {
			status = filedata_xml_subpath_parse(child, tmp->children);
			if (status) {
				break;
			}
			child->fe_flags |= FILEDATA_ENTRY_FLAG_SUBPATH;
		} else if (strcmp((char *)tmp->name, FILEDATA_XML_MODE) == 0) {
			value = (char*)xmlNodeGetContent(tmp);
			status = string2mode((const char *)value, &child->fe_mode);
			xmlFree(value);
			if (status) {
				break;
			}
			child->fe_flags |= FILEDATA_ENTRY_FLAG_MODE;
		} else if (strcmp((char *)tmp->name,
			   FILEDATA_XML_WRITE_AFTER_READ) == 0) {
			value = (char *)xmlNodeGetContent(tmp);
			if (strlen(value) > MAX_WRITE_LEN) {
				status = -1;
				FERROR("XML: write data '%s' is too long", value);
				xmlFree(value);
			}
			strncpy(child->fe_write_content, value, MAX_WRITE_LEN);
			child->fe_write_after_read = 1;
			xmlFree(value);
		} else if (strcmp((char *)tmp->name, FILEDATA_XML_ITEM) == 0) {
			value = (char*)xmlNodeGetContent(tmp);
			xmlFree(value);
			status = filedata_xml_item_parse(child, tmp->children);
			if (status) {
				break;
			}
		} else if (strcmp((char *)tmp->name, FILEDATA_XML_ENTRY) == 0) {
			status = filedata_xml_entry_parse(child, tmp->children);
			if (status) {
				break;
			}
		} else {
			FERROR("XML: entry have a unknown child %s", tmp->name);
			status = -1;
			break;
		}
	}

	if ((child->fe_flags & FILEDATA_ENTRY_FLAG_FILLED)
	    != FILEDATA_ENTRY_FLAG_FILLED) {
		FERROR("XML: some fields of entry is missing");
		status = -1;
	}

	if (child->fe_mode == S_IFREG && !list_empty(&child->fe_children)) {
		FERROR("XML: file entry should not have children");
		status = -1;
	}

	if (child->fe_mode == S_IFDIR && !list_empty(&child->fe_item_types)) {
		FERROR("XML: directory entry should not have items");
		status = -1;
	}

	if (child->fe_write_after_read && child->fe_mode != S_IFREG) {
		FERROR("XML: directory entry could not write after read");
		status = -1;
	}

	if (status) {
		filedata_entry_free(child);
	} else {
		filedata_entry_add(parent, child);
	}
	return status;
}

static int
filedata_xml_definition_fill(struct filedata_entry *root_entry, xmlNode *node)
{
	xmlNode *tmp;
	int status = 0;
	char *value;

	for (tmp = node; tmp; tmp = tmp->next) {
		if (tmp->type != XML_ELEMENT_NODE) {
			continue;
		}

		if (strcmp((char *)tmp->name, FILEDATA_XML_VERSION) == 0) {
			value = (char*)xmlNodeGetContent(tmp);
			xmlFree(value);
		} else if (strcmp((char *)tmp->name, FILEDATA_XML_ENTRY) == 0) {
			filedata_xml_entry_parse(root_entry, tmp->children);
		} else {
			FERROR("XML: definition have a unknown child %s", tmp->name);
			status = -1;
			break;
		}
	}
	return status;
}

static int
filedata_xml_definition_get(struct filedata_entry *root_entry, xmlNode *root)
{
	int status = 0;

	if (root->next != NULL) {
		FERROR("XML: more than one definition");
		return -1;
	}

	if (root->type != XML_ELEMENT_NODE) {
		FERROR("XML: root is not a element");
		return -1;
	}

	if (strcmp((char *)root->name, FILEDATA_XML_DEFINITION)) {
		FERROR("XML: root element is not a %s", FILEDATA_XML_DEFINITION);
		return -1;
	}

	//luster_entry_add(parent);
	status = filedata_xml_definition_fill(root_entry, root->children);
	if (status) {
		FERROR("XML: failed to fill definition");
	}
	return status;
}

int
filedata_xml_parse(struct filedata_definition *definition, const char *xml_file)
{
	xmlDoc *doc = NULL;
	xmlNode *root_element = NULL;
	int status;

	definition->fd_root = filedata_entry_alloc();
	if (definition->fd_root == NULL) {
		FERROR("XML: not enough memory");
		return -1;
	}
	definition->fd_root->fe_definition = definition;
	definition->fd_root->fe_subpath[0] = '/';
	definition->fd_root->fe_subpath[1] = '\0';
	definition->fd_root->fe_mode = S_IFDIR;
	definition->fd_root->fe_subpath_type = SUBPATH_CONSTANT;

	/*
	 * this initialize the library and check potential ABI mismatches
	 * between the version it was compiled for and the actual shared
	 * library used.
	 */
	LIBXML_TEST_VERSION

	/*parse the file and get the DOM */
	doc = xmlReadFile(xml_file, NULL, 0);

	if (doc == NULL) {
		FERROR("XML: failed to read %s", xml_file);
		status = -1;
		goto out;
	}

	/*Get the root element node */
	root_element = xmlDocGetRootElement(doc);

	status = filedata_xml_definition_get(definition->fd_root, root_element);
	if (status) {
		FERROR("XML: failed to get definition from %s", xml_file);
	}

	/*free the document */
	xmlFreeDoc(doc);

out:
	/*
	 *Free the global variables that may
	 *have been allocated by the parser.
	 */
	xmlCleanupParser();
	//filedata_entry_dump(definition->fd_root, 0);
	if (status) {
		filedata_entry_free(definition->fd_root);
		definition->fd_root = NULL;
	}
	return status;
}
