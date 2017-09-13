/**
 * collectd - src/filedata_xml.h
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

#ifndef FILEDATA_XML_H
#define FILEDATA_XML_H
#include "filedata_config.h"

int filedata_xml_parse(struct filedata_definition *definition, const char *xml_file);
void filedata_entry_free(struct filedata_entry *entry);
void filedata_entry_dump_active(struct filedata_entry *entry, int depth);
void filedata_entry_dump(struct filedata_entry *entry, int depth);
int
filedata_option_name_extract(char *name,
			     struct filedata_submit *submit,
			     int *flag,
			     struct filedata_submit_option **option);
int
filedata_option_init(struct filedata_submit_option *option,
		     char *string);
#endif /* FILEDATA_XML_H */
