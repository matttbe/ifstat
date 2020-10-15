/*
 * ifstat - InterFace STATistics
 * Copyright (c) 2001, Gaël Roualland <gael.roualland@iname.com>
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
 * Foundation, Inc., 675 Mass Ave, Cambridge, MA 02139, USA.
 *
 * $Id: ifstat.h,v 1.4 2001/12/18 05:07:30 gael Exp $
 */

#ifndef IFSTAT_H
#define IFSTAT_H

struct ifstat_data {
  char *name;
  unsigned long obout, obin, bout, bin;
  int flags;
  struct ifstat_data *next;
};

/* interface managing calls in ifstat.c */
void add_interface(struct ifstat_data **first, char *ifname);
void set_interface_stats(struct ifstat_data *data,
			 unsigned long bytesin,
			 unsigned long bytesout);
struct ifstat_data *get_interface(struct ifstat_data *list, char *ifname);

/* backend calls in drivers.c */
struct ifstat_data *scan_interfaces();
void get_stats(struct ifstat_data *ifs);

/* snmp backend */
void snmp_init(char *string);
struct ifstat_data *snmp_scan_interfaces();
void snmp_get_stats(struct ifstat_data *ifs);
void snmp_free();

#endif
