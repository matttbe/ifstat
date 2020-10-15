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
 * $Id: ifstat.h,v 1.7 2002/01/14 00:59:56 gael Exp $
 */

#ifndef IFSTAT_H
#define IFSTAT_H

/* interface flags */
#define IFSTAT_LOOPBACK 1
#define IFSTAT_DOWN     2
#define IFSTAT_HASSTATS 4

/* interface list */
struct ifstat_data {
  char *name;
  unsigned long obout, obin, bout, bin;
  int flags;
  struct ifstat_data *next;
};

/* driver data */
struct ifstat_driver {
  char *name;
  /* driver initialisation, returns 1 if successfull */
  int (*open_driver) (struct ifstat_driver *driver,
		      char *options);

  /* scans list of known interfaces by the driver */
  struct ifstat_data * (*scan_interfaces) (struct ifstat_driver *driver,
					   int flags);

  /* gathers stats and updates inetrface lists */
  int (*get_stats) (struct ifstat_driver *driver,
		    struct ifstat_data *ifaces);

  /* frees/closes driver data */
  void (*close_driver) (struct ifstat_driver *driver);

  /* private driver data */
  void *data;
};

/* interface managing calls in ifstat.c */
void add_interface(struct ifstat_data **first, char *ifname);
void set_interface_stats(struct ifstat_data *data,
			 unsigned long bytesin,
			 unsigned long bytesout);
struct ifstat_data *get_interface(struct ifstat_data *list, char *ifname);

extern char *progname;

/* backend calls in drivers.c */
/* searches for specified driver (NULL = default). Returns 1 if found */
int get_driver(char *name, struct ifstat_driver *driver);
/* prints driver list */
void print_drivers(FILE *dev);

/* snmp backend in snmp.c */
int snmp_open_driver(struct ifstat_driver *driver, char *options);
struct ifstat_data *snmp_scan_interfaces(struct ifstat_driver *driver,
					 int flags);
int snmp_get_stats(struct ifstat_driver *driver, struct ifstat_data *ifaces);
void snmp_close_driver(struct ifstat_driver *driver);

#endif
