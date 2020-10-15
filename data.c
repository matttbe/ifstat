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
 * $Id: data.c,v 1.7 2003/02/07 00:10:37 gael Exp $
 */

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif
#if STDC_HEADERS
#include <string.h>
#else
# ifndef HAVE_STRCHR
#  define strchr index
#  define strrchr rindex
# endif
char *strchr (), *strrchr ();
# ifndef HAVE_MEMCPY
#  define memcpy(d, s, n) bcopy ((s), (d), (n))
#  define memmove(d, s, n) bcopy ((s), (d), (n))
# endif
#endif
#ifdef HAVE_STDARG_H
#include <stdarg.h>
#endif
#ifdef HAVE_ERRNO_H
#include <errno.h>
#endif
#include <stdio.h>
#include <stdlib.h>
#include "ifstat.h"

const char *ifstat_version = VERSION;
int ifstat_quiet = 0;
char *ifstat_progname = "libifstat";

void _ifstat_error(char *format, ...) {
  va_list ap;
  
  fprintf(stderr, "%s: ", ifstat_progname);
  va_start(ap, format);
  vfprintf(stderr, format, ap);
  va_end(ap);
  putc('\n', stderr);
}

void (*ifstat_error) (char *format, ...) = &_ifstat_error;

void ifstat_perror(char *func) {
  ifstat_error("%s: %s", func, strerror(errno));
}

void ifstat_add_interface(struct ifstat_list *ifs, char *ifname, int flags) {
  struct ifstat_data *cur, *last;
  int len;

  /* check interface name */
  if (*ifname == '\0')
    return;
  len = strlen(ifname);
  
  last = NULL;
  for (cur = ifs->first; cur != NULL; cur = cur->next) {
    if (len == cur->namelen &&
	cur->name[0] == ifname[0] &&
	!strncmp(cur->name + 1, ifname + 1, len - 1) &&
	!(flags & IFSTAT_TOTAL) && !(cur->flags & IFSTAT_TOTAL))
      return;
    last = cur;
  }

  if ((cur = calloc(1, sizeof(struct ifstat_data))) == NULL) {
    ifstat_perror("malloc");
    exit(EXIT_FAILURE);
  }
  cur->name = strdup(ifname);
  cur->namelen = len;
  cur->flags = flags;
  if (last != NULL)
    last->next = cur;
  if (ifs->first == NULL)
    ifs->first = cur;
}

void ifstat_free_interface(struct ifstat_data *data) {
  free(data->name);
  free(data);
}

void ifstat_set_interface_stats(struct ifstat_data *data,
				unsigned long bytesin,
				unsigned long bytesout) {
  if (data->bout > bytesout || data->bin > bytesin) {
    if (!ifstat_quiet)
      ifstat_error("warning: rollover for interface %s, reinitialising.", data->name);
    data->obout = bytesout;
    data->obin = bytesin;
  } else {
    data->obout = data->bout;
    data->obin = data->bin;
  }
  data->bout = bytesout;
  data->bin = bytesin;
  data->flags |= IFSTAT_HASSTATS;
}

void ifstat_set_interface_index(struct ifstat_data *data,
				int index) {
  data->index = index;
  data->flags |= IFSTAT_HASINDEX;
}

struct ifstat_data *ifstat_get_interface(struct ifstat_list *ifs, char *ifname) {
  struct ifstat_data *ptr;
  int len = strlen(ifname);
  
  for (ptr = ifs->first; ptr != NULL; ptr = ptr->next)
    if (len == ptr->namelen &&
	ptr->name[0] == ifname[0] &&
	!strncmp(ptr->name + 1, ifname + 1, len - 1) &&
	!(ptr->flags & IFSTAT_TOTAL))
      return ptr;
  return NULL;
}

void ifstat_reset_interfaces(struct ifstat_list *ifs) {
  struct ifstat_data *ptr;
  int hasindex = 1;

  for (ptr = ifs->first; ptr != NULL; ptr = ptr->next) {
    if (!(ptr->flags & IFSTAT_HASINDEX))
      hasindex = 0;
    ptr->flags &= ~(IFSTAT_HASSTATS|IFSTAT_HASINDEX);
  }
  if (hasindex)
    ifs->flags |= IFSTAT_HASINDEX;
  else
    ifs->flags &= ~IFSTAT_HASINDEX;
}
