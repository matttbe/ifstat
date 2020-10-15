/*
 * ifstat - InterFace STATistics
 * Copyright (c) 2001, Gaël Roualland <gael.roualland@dial.oleane.com>
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
 * $Id: ifstat.h,v 1.21 2003/04/21 19:58:42 gael Exp $
 */

#ifndef IFSTAT_H
#define IFSTAT_H

#define IFSTAT_API      1

/* interface flags */
#define IFSTAT_LOOPBACK 1
#define IFSTAT_DOWN     2
#define IFSTAT_HASSTATS 4
#define IFSTAT_HASINDEX 8
#define IFSTAT_TOTAL  128

/* interface list */
struct ifstat_data {
  char *name;
  int namelen;
  unsigned long obout, obin, bout, bin;
  int flags, index;
  struct ifstat_data *next;
};

struct ifstat_list {
  struct ifstat_data *first;
  int flags;
};

/* driver data */
struct ifstat_driver {
  char *name;
  /* driver initialisation, returns 1 if successfull */
  int (*open_driver) (struct ifstat_driver *driver,
		      char *options);

  /* scans list of known interfaces by the driver */
  int (*scan_interfaces) (struct ifstat_driver *driver,
			  struct ifstat_list *ifs);

  /* gathers stats and updates interface lists */
  int (*get_stats) (struct ifstat_driver *driver,
		    struct ifstat_list *ifs);

  /* frees/closes driver data */
  void (*close_driver) (struct ifstat_driver *driver);

  /* private driver data */
  void *data;
};

/* interface managing calls */
void ifstat_add_interface(struct ifstat_list *ifs, char *ifname, int flags);
void ifstat_free_interface(struct ifstat_data *data);

void ifstat_set_interface_stats(struct ifstat_data *data,
				unsigned long bytesin,
				unsigned long bytesout);

void ifstat_set_interface_index(struct ifstat_data *data,
				int index);

#define ifstat_get_interface_index(data) ((data)->index)
#define ifstat_get_interface_name(data) ((data)->name)

struct ifstat_data *ifstat_get_interface(struct ifstat_list *ifs,
					 char *ifname);

void ifstat_reset_interfaces(struct ifstat_list *ifs);

/* redefine those to override defaults if needed */
extern char *ifstat_progname;
extern void (*ifstat_error) (char *format, ...);
extern int ifstat_quiet;

/* version string */
extern const char *ifstat_version;

/* perror reporting --internal */
void ifstat_perror(char *);

/* searches for specified driver (NULL = default). Returns 1 if found */
int ifstat_get_driver(char *name, struct ifstat_driver *driver);
/* get driver list */
char *ifstat_list_drivers();

#endif
