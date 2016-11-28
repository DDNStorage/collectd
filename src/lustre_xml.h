/**
 * collectd - src/lustre_xml.h
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

#ifndef LUSTRE_XML_H
#define LUSTRE_XML_H
#include "lustre_config.h"

int lustre_xml_parse(struct lustre_definition *definition, const char *xml_file);
void lustre_entry_free(struct lustre_entry *entry);
void lustre_entry_dump_active(struct lustre_entry *entry, int depth);
void lustre_entry_dump(struct lustre_entry *entry, int depth);
int
lustre_option_name_extract(char *name,
			   struct lustre_submit *submit,
			   int *flag,
			   struct lustre_submit_option **option);
int
lustre_option_init(struct lustre_submit_option *option,
		   char *string);
#endif /* LUSTRE_XML_H */
