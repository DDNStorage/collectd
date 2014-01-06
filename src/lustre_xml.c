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

#include <stdio.h>
#include <libxml/parser.h>
#include <libxml/tree.h>
#include "collectd.h"
#include "common.h"
#include "plugin.h"
#include "list.h"
#include "lustre.h"
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>

static struct lustre_subpath_field_type *
lustre_subpath_field_type_alloc(void)
{
	struct lustre_subpath_field_type *field_type;
	field_type = calloc(1, sizeof(struct lustre_subpath_field_type));
	if (field_type == NULL)
		return NULL;

	INIT_LIST_HEAD(&field_type->lpft_linkage);
	return field_type;
}

static void
lustre_subpath_field_type_free(struct lustre_subpath_field_type *field_type)
{
	free(field_type);
}

static int
lustre_subpath_field_type_add(struct lustre_entry *entry,
			      struct lustre_subpath_field_type *field_type)
{
	if (field_type->lpft_index != entry->le_subpath_field_number + 1) {
		ERROR("index of field is false");
		return -1;
	}
	field_type->lpft_entry = entry;
	list_add_tail(&field_type->lpft_linkage, &entry->le_subpath_field_types);
	entry->le_subpath_field_number++;
	return 0;
}

static int
lustre_entry_add(struct lustre_entry *parent, struct lustre_entry *child)
{
	child->le_parent = parent;
	list_add_tail(&child->le_linkage, &parent->le_children);

	return 0;
}

static
struct lustre_entry *lustre_entry_alloc(void)
{
	struct lustre_entry *entry;

	entry = calloc(1, sizeof(struct lustre_entry));
	if (entry == NULL) {
		ERROR("XML: not enough memory");
		return NULL;
	}

	INIT_LIST_HEAD(&entry->le_children);
	INIT_LIST_HEAD(&entry->le_item_types);
	INIT_LIST_HEAD(&entry->le_linkage);
	INIT_LIST_HEAD(&entry->le_subpath_field_types);
	INIT_LIST_HEAD(&entry->le_active_children);
	INIT_LIST_HEAD(&entry->le_active_linkage);
	INIT_LIST_HEAD(&entry->le_active_item_types);

	return entry;
}

void
lustre_entry_free(struct lustre_entry *entry)
{
	struct lustre_entry *child;
	struct lustre_entry *n;
	struct lustre_item_type *item;
	struct lustre_item_type *i;
	struct lustre_subpath_field_type *path;
	struct lustre_subpath_field_type *p;

	list_for_each_entry_safe(child,
				 n,
	                         &entry->le_children,
	                         le_linkage) {
		list_del_init(&child->le_linkage);
		lustre_entry_free(child);
	}

	list_for_each_entry_safe(item,
				 i,
	                         &entry->le_item_types,
	                         lit_linkage) {
		list_del_init(&item->lit_linkage);
		lustre_item_type_free(item);
	}

	list_for_each_entry_safe(path,
				 p,
	                         &entry->le_subpath_field_types,
	                         lpft_linkage) {
		list_del_init(&path->lpft_linkage);
		lustre_subpath_field_type_free(path);
	}
	if (entry->le_flags & LUSTRE_ENTRY_FLAG_SUBPATH &&
	    entry->le_subpath_type == SUBPATH_REGULAR_EXPRESSION)
		regfree(&entry->le_subpath_regex);

	free(entry);
}

#define LUSTRE_XML_DEFINITION		"definition"
#define LUSTRE_XML_VERSION		"version"
#define LUSTRE_XML_ENTRY		"entry"
#define LUSTRE_XML_SUBPATH		"subpath"
#define LUSTRE_XML_MODE			"mode"
#define LUSTRE_XML_ITEM			"item"
#define LUSTRE_XML_DIRECTORY		"directory"
#define LUSTRE_XML_FILE			"file"
#define LUSTRE_XML_NAME			"name"
#define LUSTRE_XML_TYPE			"type"
#define LUSTRE_XML_PATTERN		"pattern"
#define LUSTRE_XML_FIELD		"field"
#define LUSTRE_XML_INDEX		"index"
#define LUSTRE_XML_STRING		"string"
#define LUSTRE_XML_NUMBER		"number"
#define LUSTRE_XML_OPTION		"option"
#define LUSTRE_XML_KEYWORD		"keyword"
#define LUSTRE_XML_HOST			"host"
#define LUSTRE_XML_PLUGIN		"plugin"
#define LUSTRE_XML_PLUGIN_INSTANCE	"plugin_instance"
#define LUSTRE_XML_OPTION_TYPE		"type"
#define LUSTRE_XML_TYPE_INSTANCE	"type_instance"
#define LUSTRE_XML_CONSTANT		"constant"
#define LUSTRE_XML_PATH_FIELD_NAME	"path_field_name"
#define LUSTRE_XML_PATH_FIELD		"path_field"
#define LUSTRE_XML_CONTENT_FIELD	"content_field"
#define LUSTRE_XML_CONTENT_FIELD_NAME	"content_field_name"
#define LUSTRE_XML_SUBPATH_TYPE		"subpath_type"
#define LUSTRE_XML_PATH			"path"
#define LUSTRE_XML_REGULAR_EXPRESSION	"regular_expression"
#define LUSTRE_XML_SUBPATH_FIELD 	"subpath_field"

static int string2mode(const char *string, mode_t *mode)
{
	if (strcmp(string, LUSTRE_XML_DIRECTORY) == 0) {
		*mode = S_IFDIR;
	} else if (strcmp(string, LUSTRE_XML_FILE) == 0) {
		*mode = S_IFREG;
	} else {
	ERROR("XML: unkown mode");
		return -1;
	}
	return 0;
}

static char *mode2string(mode_t mode)
{
	if (mode == S_IFDIR) {
		return LUSTRE_XML_DIRECTORY;
	} else if (mode == S_IFREG) {
		return LUSTRE_XML_FILE;
	} else {
		ERROR("XML: unkown mode");
		return NULL;
	}
	return NULL;
}

static int lustre_field_string2type(char *string, value_type_t *type)
{
	if (strcmp(string, LUSTRE_XML_NUMBER) == 0) {
		*type = TYPE_NUMBER;
	} else if (strcmp(string, LUSTRE_XML_STRING) == 0) {
		*type = TYPE_STRING;
	} else {
		ERROR("XML: unkown type");
		return -1;
	}
	return 0;
}

static const char *lustre_field_type2string(value_type_t type)
{
	if (type == TYPE_STRING) {
		return LUSTRE_XML_STRING;
	} else if (type == TYPE_NUMBER) {
		return LUSTRE_XML_NUMBER;
	} else {
		ERROR("XML: unkown type");
		return NULL;
	}
	return NULL;
}

void lustre_entry_dump(struct lustre_entry *entry, int depth)
{
	struct lustre_entry *child;
	struct lustre_item_type *item;
	struct lustre_field_type *field;
	struct lustre_subpath_field_type *subpath_field;
	char prefix[1024];
	int i;

	for (i = 0; i < depth; i++) {
		prefix[i] = ' ';
	}
	prefix[i] = '\0';

	LINFO("%sentry %s, mode %s",
	      prefix, entry->le_subpath,
	      mode2string(entry->le_mode));

	list_for_each_entry(item,
	                    &entry->le_item_types,
	                    lit_linkage) {
		LINFO("%s item %s, pattern %s, %llu",
		      prefix, item->lit_type_name,
		      item->lit_pattern,
		      (unsigned long long)item->lit_regex.re_nsub);
		list_for_each_entry(field,
				    &item->lit_field_list,
				    lft_linkage) {
			LINFO("%s  field[%d] %s, type %s",
			      prefix, field->lft_index,
			      field->lft_name,
			      lustre_field_type2string(field->lft_type));
		}
	}

	list_for_each_entry(subpath_field,
	                    &entry->le_subpath_field_types,
	                    lpft_linkage) {
		LINFO("%s subpath_field[%d] %s",
		      prefix, subpath_field->lpft_index,
		      subpath_field->lpft_name);
	}

	list_for_each_entry(child,
	                    &entry->le_children,
	                    le_linkage) {
		lustre_entry_dump(child, depth + 1);
	}
}

void lustre_entry_dump_active(struct lustre_entry *entry, int depth)
{
	struct lustre_entry *child;
	struct lustre_item_type *item;
	char prefix[1024];
	int i;

	if (!entry->le_active)
		return;

	for (i = 0; i < depth; i++) {
		prefix[i] = ' ';
	}
	prefix[i] = '\0';

	LINFO("%sentry %s, mode %s",
	      prefix, entry->le_subpath,
	      mode2string(entry->le_mode));

	list_for_each_entry(item,
			    &entry->le_active_item_types,
			    lit_active_linkage) {
		LINFO("%s item %s, pattern %s, %llu",
		      prefix, item->lit_type_name,
		      item->lit_pattern,
		      (unsigned long long)item->lit_regex.re_nsub);
	}

	list_for_each_entry(child,
			    &entry->le_active_children,
			    le_active_linkage) {
		lustre_entry_dump_active(child, depth + 1);
	}
}

static void
lustre_item_type_add(struct lustre_entry *entry,
		     struct lustre_item_type *item)
{
	item->lit_entry = entry;
	list_add_tail(&item->lit_linkage, &entry->le_item_types);
}

static int
lustre_option_name_extract(char *name,
			   struct lustre_submit *submit,
			   int *flag,
			   struct lustre_submit_option **option)
{
	if (strcmp(name, LUSTRE_XML_HOST) == 0) {
		*flag = LUSTRE_FIELD_FLAG_OPTION_HOST;
		*option = &submit->ls_host;
	} else if (strcmp(name, LUSTRE_XML_PLUGIN) == 0) {
		*flag = LUSTRE_FIELD_FLAG_OPTION_PLUGIN;
		*option = &submit->ls_plugin;
	} else if (strcmp(name, LUSTRE_XML_PLUGIN_INSTANCE) == 0) {
		*flag = LUSTRE_FIELD_FLAG_OPTION_PLUGIN_INSTANCE;
		*option = &submit->ls_plugin_instance;
	} else if (strcmp(name, LUSTRE_XML_OPTION_TYPE) == 0) {
		*flag = LUSTRE_FIELD_FLAG_OPTION_TYPE;
		*option = &submit->ls_type;
	} else if (strcmp(name, LUSTRE_XML_TYPE_INSTANCE) == 0) {
		*flag = LUSTRE_FIELD_FLAG_OPTION_TYPE_INSTANCE;
		*option = &submit->ls_type_instance;
	} else {
		ERROR("XML: unkown type");
		return -1;
	}
	return 0;
}

static int
lustre_option_init(struct lustre_submit_option *option,
		   char *string)
{
	strcpy(option->lso_string, string);
	return 0;
}

static int
lustre_xml_option_parse(struct lustre_field_type *field, xmlNode *node)
{
	xmlNode *tmp;
	int status = 0;
	char *value;
	int flag = 0;
	struct lustre_submit_option *option = NULL;
	char string[1024];
	int inited = 0;

	for (tmp = node; tmp; tmp = tmp->next) {
		if (tmp->type != XML_ELEMENT_NODE) {
			continue;
		}

		if (strcmp((char *)tmp->name, LUSTRE_XML_NAME) == 0) {
			value = (char*)xmlNodeGetContent(tmp);
			status = lustre_option_name_extract(value,
							    &field->lft_submit,
							    &flag,
							    &option);
			if (status) {
				ERROR("XML: unkown option");
				break;
			}
			xmlFree(value);
		} else if (strcmp((char *)tmp->name, LUSTRE_XML_STRING) == 0) {
			if (inited != 0) {
				ERROR("XML: more than one type");
				status = -1;
				break;
			}
			value = (char*)xmlNodeGetContent(tmp);
			strcpy(string, value);
			xmlFree(value);
			inited = 1;
		} else {
			ERROR("XML: option has a unknown child %s", tmp->name);
			status = -1;
			break;
		}
	}

	if (status) {
		return status;
	}

	if (flag == 0 || option == NULL) {
		ERROR("XML: option has no name");
		return -1;
	}

	if (inited == 0) {
		ERROR("XML: option has no value");
		return -1;
	}

	lustre_option_init(option, string);
	field->lft_flags |= flag;
	return 0;
}

static int
lustre_xml_field_parse(struct lustre_item_type *item, xmlNode *node)
{
	xmlNode *tmp;
	int status = 0;
	char *value;
	struct lustre_field_type *field;

	field = lustre_field_type_alloc();
	if (field == NULL) {
		ERROR("XML: not enough memory");
		return -1;
	}

	for (tmp = node; tmp; tmp = tmp->next) {
		if (tmp->type != XML_ELEMENT_NODE) {
			continue;
		}

		if (strcmp((char *)tmp->name, LUSTRE_XML_INDEX) == 0) {
			value = (char*)xmlNodeGetContent(tmp);
			field->lft_index = strtoull(value, NULL, 10);
			if (field->lft_index != item->lit_field_number + 1) {
				status = -1;
				ERROR("XML: index %s of field is false", value);
				xmlFree(value);
				break;
			}
			field->lft_flags |= LUSTRE_FIELD_FLAG_INDEX;
			xmlFree(value);
		} else if (strcmp((char *)tmp->name, LUSTRE_XML_NAME) == 0) {
			value = (char*)xmlNodeGetContent(tmp);
			if (strlen(value) > MAX_NAME_LENGH) {
				status = -1;
				ERROR("XML: name %s is too long", value);
				xmlFree(value);
				break;
			}
			strcpy(field->lft_name, value);
			field->lft_flags |= LUSTRE_FIELD_FLAG_NAME;
			xmlFree(value);
		} else if (strcmp((char *)tmp->name, LUSTRE_XML_TYPE) == 0) {
			value = (char*)xmlNodeGetContent(tmp);
			status = lustre_field_string2type(value, &field->lft_type);
			if (status) {
				ERROR("XML: type %s is illegal", value);
				xmlFree(value);
				break;
			}
			field->lft_flags |= LUSTRE_FIELD_FLAG_TYPE;
			xmlFree(value);
		} else if (strcmp((char *)tmp->name, LUSTRE_XML_OPTION) == 0) {
			status = lustre_xml_option_parse(field, tmp->children);
			if (status) {
				ERROR("XML: failed to compile field");
				break;
			}
		} else {
			ERROR("XML: field have a unknown child %s", tmp->name);
			status = -1;
			break;
		}
	}

	if (field->lft_flags != LUSTRE_FIELD_FLAG_FILLED) {
		ERROR("XML: some fields of item is missing");
		status = -1;
	}

	if (status) {
		lustre_field_type_free(field);
	} else {
		status = lustre_field_type_add(item, field);
		if (status) {
			lustre_field_type_free(field);
		}
	}
	return status;
}

static int lustre_item_type_build(struct lustre_item_type *item)
{
	int i = 0;
	struct lustre_field_type *field_type;

	item->lit_field_array = calloc(item->lit_field_number + 1,
				       sizeof(struct lustre_field_type *));
	if (item->lit_field_array == NULL) {
		ERROR("XML: not enough memory");
		return -1;
	}

	list_for_each_entry(field_type,
	                    &item->lit_field_list,
	                    lft_linkage) {
		i++;
		item->lit_field_array[i] = field_type;
	}
	return 0;
}

static int
lustre_xml_item_parse(struct lustre_entry *entry, xmlNode *node)
{
	xmlNode *tmp;
	int status = 0;
	char *value;
	struct lustre_item_type *item;

	item = lustre_item_type_alloc();
	if (item == NULL) {
		ERROR("XML: not enough memory");
		return -1;
	}

	for (tmp = node; tmp; tmp = tmp->next) {
		if (tmp->type != XML_ELEMENT_NODE) {
			continue;
		}

		if (strcmp((char *)tmp->name, LUSTRE_XML_NAME) == 0) {
			value = (char*)xmlNodeGetContent(tmp);
			if (strlen(value) > MAX_NAME_LENGH) {
				status = -1;
				ERROR("XML: name %s is too long", value);
				xmlFree(value);
				break;
			}
			strcpy(item->lit_type_name, value);
			item->lit_flags |= LUSTRE_ITEM_FLAG_NAME;
			xmlFree(value);
		} else if (strcmp((char *)tmp->name, LUSTRE_XML_PATTERN) == 0) {
			value = (char*)xmlNodeGetContent(tmp);
			if (strlen(value) > MAX_NAME_LENGH) {
				status = -1;
				ERROR("XML: pattern %s is too long", value);
				xmlFree(value);
				break;
			}
			strcpy(item->lit_pattern, value);
			xmlFree(value);
			status = lustre_compile_regex(&item->lit_regex,
						      item->lit_pattern);
			if (status) {
				ERROR("XML: failed to compile pattern %s",
					item->lit_pattern);
				break;
			}
			item->lit_flags |= LUSTRE_ITEM_FLAG_PATTERN;
		} else if (strcmp((char *)tmp->name, LUSTRE_XML_FIELD) == 0) {
			status = lustre_xml_field_parse(item, tmp->children);
			if (status) {
				ERROR("XML: failed to compile field");
				break;
			}
			item->lit_flags |= LUSTRE_ITEM_FLAG_FIELD;
		} else {
			ERROR("XML: entry have a unknown child %s", tmp->name);
			status = -1;
			break;
		}
	}

	if (item->lit_flags != LUSTRE_ITEM_FLAG_FILLED) {
		ERROR("XML: some fields of item is missing");
		status = -1;
	}

	if (item->lit_field_number != item->lit_regex.re_nsub) {
		ERROR("XML: field number of item is false");
		status = -1;
	}

	if (status == 0) {
		status = lustre_item_type_build(item);
	}

	if (status == 0) {
		lustre_item_type_add(entry, item);
	}

	if (status) {
		lustre_item_type_free(item);
	}
	return status;
}

static int
lustre_xml_subpath_field_parse(struct lustre_entry *entry, xmlNode *node)
{
	xmlNode *tmp;
	int status = 0;
	char *value;
	struct lustre_subpath_field_type *field;

	field = lustre_subpath_field_type_alloc();
	if (field == NULL) {
		ERROR("XML: not enough memory");
		return -1;
	}

	for (tmp = node; tmp; tmp = tmp->next) {
		if (tmp->type != XML_ELEMENT_NODE) {
			continue;
		}

		if (strcmp((char *)tmp->name, LUSTRE_XML_INDEX) == 0) {
			value = (char*)xmlNodeGetContent(tmp);
			field->lpft_index = strtoull(value, NULL, 10);
			if (field->lpft_index != entry->le_subpath_field_number + 1) {
				status = -1;
				ERROR("XML: index %s of field is false", value);
				xmlFree(value);
				break;
			}
			field->lpft_flags |= LUSTRE_SUBPATH_FIELD_FLAG_INDEX;
			xmlFree(value);
		} else if (strcmp((char *)tmp->name, LUSTRE_XML_NAME) == 0) {
			value = (char*)xmlNodeGetContent(tmp);
			if (strlen(value) > MAX_NAME_LENGH) {
				status = -1;
				ERROR("XML: name %s is too long", value);
				xmlFree(value);
				break;
			}
			strcpy(field->lpft_name, value);
			field->lpft_flags |= LUSTRE_SUBPATH_FIELD_FLAG_NAME;
			xmlFree(value);
		} else {
			ERROR("XML: field have a unknown child %s", tmp->name);
			status = -1;
			break;
		}
	}

	if (field->lpft_flags != LUSTRE_SUBPATH_FIELD_FLAG_FIELD) {
		ERROR("XML: some fields of item is missing");
		status = -1;
	}

	if (status) {
		lustre_subpath_field_type_free(field);
	} else {
		status = lustre_subpath_field_type_add(entry, field);
		if (status) {
			lustre_subpath_field_type_free(field);
		}
	}
	return status;
}

static int
lustre_xml_subpath_parse(struct lustre_entry *entry, xmlNode *node)
{
	xmlNode *tmp;
	int status = 0;
	char *value;
	int inited = 0;

	for (tmp = node; tmp; tmp = tmp->next) {
		if (tmp->type != XML_ELEMENT_NODE) {
			continue;
		}
		if (strcmp((char *)tmp->name, LUSTRE_XML_SUBPATH_TYPE) == 0) {
			value = (char*)xmlNodeGetContent(tmp);
			if (strcmp(value, LUSTRE_XML_CONSTANT) == 0) {
				entry->le_subpath_type = SUBPATH_CONSTANT;
			} else if (strcmp(value, LUSTRE_XML_REGULAR_EXPRESSION) == 0) {
				entry->le_subpath_type = SUBPATH_REGULAR_EXPRESSION;
			} else {
				status = -1;
				xmlFree(value);
				ERROR("XML: subpath_type %s is unknown\n", value);
				break;
			}
			xmlFree(value);
		} else if (strcmp((char *)tmp->name, LUSTRE_XML_PATH) == 0) {
			value = (char*)xmlNodeGetContent(tmp);
			if (strlen(value) > MAX_NAME_LENGH) {
				status = -1;
				ERROR("XML: path %s is too long\n", value);
				xmlFree(value);
				break;
			}
			strcpy(entry->le_subpath, value);
			inited = 1;
			xmlFree(value);
		} else if (strcmp((char *)tmp->name, LUSTRE_XML_SUBPATH_FIELD) == 0) {
			status = lustre_xml_subpath_field_parse(entry, tmp->children);
			if (status) {
				break;
			}
		} else {
			ERROR("XML: subpath have a unknown child %s", tmp->name);
			status = -1;
			break;
		}
	}

	if (status) {
		return status;
	}

	if (!inited) {
		ERROR("XML: subpath does not have path");
		return -1;
	}

	if (entry->le_subpath_type == SUBPATH_REGULAR_EXPRESSION) {
		status = lustre_compile_regex (&entry->le_subpath_regex,
					       entry->le_subpath);
		if (status) {
			ERROR("XML: failed to compile regular expression %s",
				entry->le_subpath);
		} else {
			if (entry->le_subpath_regex.re_nsub != entry->le_subpath_field_number) {
				ERROR("XML: subpath field number is error");
				status = -1;
			}
		}
	} else if (entry->le_subpath_type != SUBPATH_CONSTANT) {
		ERROR("XML: subpath does not have subpath_type");
		return -1;
	}
	return status;
}

static int
lustre_xml_entry_parse(struct lustre_entry *parent, xmlNode *node)
{
	xmlNode *tmp;
	int status = 0;
	char *value;
	struct lustre_entry *child;

	child = lustre_entry_alloc();
	if (child == NULL) {
		ERROR("XML: not enough memory");
		return -1;
	}

	for (tmp = node; tmp; tmp = tmp->next) {
		if (tmp->type != XML_ELEMENT_NODE) {
			continue;
		}

		if (strcmp((char *)tmp->name, LUSTRE_XML_SUBPATH) == 0) {
			status = lustre_xml_subpath_parse(child, tmp->children);
			if (status) {
				break;
			}
			child->le_flags |= LUSTRE_ENTRY_FLAG_SUBPATH;
		} else if (strcmp((char *)tmp->name, LUSTRE_XML_MODE) == 0) {
			value = (char*)xmlNodeGetContent(tmp);
			status = string2mode((const char *)value, &child->le_mode);
			xmlFree(value);
			if (status) {
				break;
			}
			child->le_flags |= LUSTRE_ENTRY_FLAG_MODE;
		} else if (strcmp((char *)tmp->name, LUSTRE_XML_ITEM) == 0) {
			value = (char*)xmlNodeGetContent(tmp);
			xmlFree(value);
			status = lustre_xml_item_parse(child, tmp->children);
			if (status) {
				break;
			}
		} else if (strcmp((char *)tmp->name, LUSTRE_XML_ENTRY) == 0) {
			status = lustre_xml_entry_parse(child, tmp->children);
			if (status) {
				break;
			}
		} else {
			ERROR("XML: entry have a unknown child %s", tmp->name);
			status = -1;
			break;
		}
	}

	if (child->le_flags != LUSTRE_ENTRY_FLAG_FILLED) {
		ERROR("XML: some fields of entry is missing");
		status = -1;
	}

	if (child->le_mode == S_IFREG && !list_empty(&child->le_children)) {
		ERROR("XML: file entry should not have children");
		status = -1;
	}

	if (child->le_mode == S_IFDIR && !list_empty(&child->le_item_types)) {
		ERROR("XML: directory entry should not have items");
		status = -1;
	}

	if (status) {
		lustre_entry_free(child);
	} else {
		lustre_entry_add(parent, child);
	}
	return status;
}

static int
lustre_xml_definition_fill(struct lustre_entry *root_entry, xmlNode *node)
{
	xmlNode *tmp;
	int status = 0;
	char *value;

	for (tmp = node; tmp; tmp = tmp->next) {
		if (tmp->type != XML_ELEMENT_NODE) {
			continue;
		}

		if (strcmp((char *)tmp->name, LUSTRE_XML_VERSION) == 0) {
			value = (char*)xmlNodeGetContent(tmp);
			xmlFree(value);
		} else if (strcmp((char *)tmp->name, LUSTRE_XML_ENTRY) == 0) {
			lustre_xml_entry_parse(root_entry, tmp->children);
		} else {
			ERROR("XML: definition have a unknown child %s", tmp->name);
			status = -1;
			break;
		}
	}
	return status;
}

static int
lustre_xml_definition_get(struct lustre_entry *root_entry, xmlNode *root)
{
	int status = 0;

	if (root->next != NULL) {
		ERROR("XML: more than one definition");
		return -1;
	}

	if (root->type != XML_ELEMENT_NODE) {
		ERROR("XML: root is not a element");
		return -1;
	}

	if (strcmp((char *)root->name, LUSTRE_XML_DEFINITION)) {
		ERROR("XML: root element is not a %s", LUSTRE_XML_DEFINITION);
		return -1;
	}

	//luster_entry_add(parent);
	status = lustre_xml_definition_fill(root_entry, root->children);
	if (status) {
		ERROR("XML: failed to fill definition");
	}
	return status;
}

int
lustre_xml_parse(struct lustre_definition *definition, const char *xml_file)
{
	xmlDoc *doc = NULL;
	xmlNode *root_element = NULL;
	int status;

	definition->ld_root = lustre_entry_alloc();
	if (definition->ld_root == NULL) {
		ERROR("XML: not enough memory");
		return -1;
	}
	definition->ld_root->le_subpath[0] = '/';
	definition->ld_root->le_subpath[1] = '\0';
	definition->ld_root->le_mode = S_IFDIR;
	definition->ld_root->le_subpath_type = SUBPATH_CONSTANT;

	/*
	 * this initialize the library and check potential ABI mismatches
	 * between the version it was compiled for and the actual shared
	 * library used.
	 */
	LIBXML_TEST_VERSION

	/*parse the file and get the DOM */
	doc = xmlReadFile(xml_file, NULL, 0);

	if (doc == NULL) {
		ERROR("XML: failed to read %s", xml_file);
		status = -1;
		goto out;
	}

	/*Get the root element node */
	root_element = xmlDocGetRootElement(doc);

	status = lustre_xml_definition_get(definition->ld_root, root_element);
	if (status) {
		ERROR("XML: failed to get definition from %s", xml_file);
	}

	/*free the document */
	xmlFreeDoc(doc);

out:
	/*
	 *Free the global variables that may
	 *have been allocated by the parser.
	 */
	xmlCleanupParser();
	//lustre_entry_dump(definition->ld_root, 0);
	if (status)
		lustre_entry_free(definition->ld_root);
	return status;
}
