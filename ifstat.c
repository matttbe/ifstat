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
 * $Id: ifstat.c,v 1.11 2001/12/24 01:15:49 gael Exp $
 */

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif
#ifdef HAVE_SYS_TYPES_H
#include <sys/types.h>
#endif
#ifdef HAVE_UNISTD_H
#include <unistd.h>
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
#ifdef HAVE_CTYPE_H
#include <ctype.h>
#endif
#if TIME_WITH_SYS_TIME
# include <sys/time.h>
# include <time.h>
#else
# if HAVE_SYS_TIME_H
# include <sys/time.h>
# else
#  include <time.h>
# endif
#endif
#ifdef HAVE_SYS_TERMIOS_H
#include <sys/termios.h>
#endif
#ifdef HAVE_SYS_IOCTL_H
#include <sys/ioctl.h>
#endif
#include <stdio.h>
#include <stdlib.h>
#include "ifstat.h"

#define F_HASSTATS 1

void add_interface(struct ifstat_data **first, char *ifname) {
  struct ifstat_data *cur, *last;

  /* check interface name */
  if (*ifname == '\0')
    return;
  
  last = NULL;
  for (cur = *first; cur != NULL; cur = cur->next) {
    if (!strcmp(cur->name, ifname))
      return;
    last = cur;
  }

  if ((cur = calloc(1, sizeof(struct ifstat_data))) == NULL) {
    perror("malloc");
    exit(EXIT_FAILURE);
  }
  cur->name = strdup(ifname);
  if (last != NULL)
    last->next = cur;
  if (*first == NULL)
    *first = cur;
}

void set_interface_stats(struct ifstat_data *data,
			 unsigned long bytesin,
			 unsigned long bytesout) {
  if (data->bout > bytesout || data->bin > bytesin) {
    fprintf(stderr, "warning: rollover for interface %s, reinitialising.\n",
	    data->name);
    data->obout = bytesout;
    data->obin = bytesin;
  } else {
    data->obout = data->bout;
    data->obin = data->bin;
  }
  data->bout = bytesout;
  data->bin = bytesin;
  data->flags |= F_HASSTATS;
}

struct ifstat_data *get_interface(struct ifstat_data *list, char *ifname) {
  struct ifstat_data *ptr;

  for (ptr = list; ptr != NULL; ptr = ptr->next)
    if (!strcmp(ptr->name, ifname))
      return ptr;
  return NULL;
}

/* parse interface list, using \ as escape character */
static struct ifstat_data *parse_interfaces(char *list) {
  char *s, *d, *buf;
  struct ifstat_data *first = NULL;
  int len, escaped = 0;

  if (list == NULL || (len = strlen(list)) <= 0)
    return NULL;

  if ((buf = malloc(len + 1)) == NULL) {
    perror("malloc");
    return NULL;
  }

  d = buf;
  for(s = list; *s != '\0'; s++) {
    if (!escaped) {
      if (*s == '\\') {
	escaped = 1;
	continue;
      }
      if (*s == ',') {
	*d = '\0';
	add_interface(&first, buf);
	d = buf;
	continue;
      }
    } else
      escaped = 0;
    *d++ = *s;
  }
  *d = '\0';
  if (*buf != '\0')
    add_interface(&first, buf);

  free(buf);
  return first;
}

static void usage(char *arg) {
  fprintf(stderr, "usage: %s [-i if0,if1,...] [-s [comm@]host] [-h] [-n] [-v] [delay [count]]\n",
	  arg);
  exit(EXIT_FAILURE);
}

#define SPACE "  "

/*
        eth0                  lo
  KB/s in  KB/s out    KB/s in  KB/s out
 14562.23  12345.25       0.00      0.00
*/
static void print_header(struct ifstat_data *list) {
  struct ifstat_data *ptr;
  char ifname[19];
  int len, ofs, mlen = (sizeof(ifname) - 1);
  
  for (ptr = list; ptr != NULL; ptr = ptr->next) {
    memset(ifname, (int) ' ', mlen);
    ifname[mlen] = '\0';

    len = strlen(ptr->name);
    ofs = (mlen - len) / 2;
    if (ofs < 0)
      ofs = 0;
    if (len + ofs > mlen)
      len = mlen - ofs;
    strncpy(ifname + ofs, ptr->name, len);
    
    fputs(ifname, stdout);
    if (ptr->next)
      fputs(SPACE, stdout);
  }
  putc('\n', stdout);
  for (ptr = list; ptr != NULL; ptr = ptr->next) {
    fputs(" KB/s in  KB/s out", stdout);
    if (ptr->next)
      fputs(SPACE, stdout);
  }
  putc('\n', stdout);
}

static void print_stats(struct ifstat_data *list,
			struct timeval *start,
			struct timeval *end) {
  struct ifstat_data *ptr;
  double delay, kbin, kbout;
  
  delay = end->tv_sec - start->tv_sec + ((double) (end->tv_usec - start->tv_usec))
    / (double) 1000000;

  for (ptr = list; ptr != NULL; ptr = ptr->next) {
    if (ptr->flags & F_HASSTATS) {
      kbin = (double) (ptr->bin - ptr->obin) / (double) (1024 * delay);
      kbout = (double) (ptr->bout - ptr->obout) / (double) (1024 * delay);
      printf("% 8.2f  % 8.2f" SPACE, kbin, kbout);
      ptr->flags &= ~F_HASSTATS;
    } else
      fputs("     n/a       n/a" SPACE, stdout);
  }
  putc('\n', stdout);
}

int main(int argc, char **argv) {
  char *ifaces = NULL, *snmp = NULL;
  struct ifstat_data *ifs;
  int arg, iter;
  char *opt;

  int header = 25; /* simple default */
  double delay = 1;
  int count = 0;

  struct timeval start, tv_delay, tv;
  
  /* parse options */
  for (arg = 1; arg < argc; arg++) {
    if (argv[arg][0] != '-' || argv[arg][1] == '\0')
      break;
    opt = argv[arg]+1;
    while (*opt) {
      switch(*opt) {
      case 'v':
	fprintf(stderr, "ifstat version " VERSION "\n"
		"Copyright (C) 2001, Gaël Roualland <gael.roualland@iname.com>\n");
	exit(EXIT_SUCCESS);
      case 'n':
	header = 0;
	break;
      case 'i':
	if (arg + 1 >= argc) {
	  fprintf(stderr, "%s: option '-i' requires an argument!\n", argv[0]);
	  exit(EXIT_FAILURE);
	}
	ifaces = argv[++arg];
	break;
      case 's':
	if (arg + 1 >= argc) {
	  fprintf(stderr, "%s: option '-s' requires an argument!\n", argv[0]);
	  exit(EXIT_FAILURE);
	}
	snmp = argv[++arg];
	break;
      case 'h':
	usage(argv[0]);
      default:
	fprintf(stderr, "%s: invalid option '-%c'\n", argv[0], *opt);
	usage(argv[0]);
      }
      opt++;
    }
  }

  /* has delay ? */
  if (arg < argc) {
    delay = atof(argv[arg]);
    if (delay < 0.1) {
      fprintf(stderr, "%s: bad or too short delay '%s'!\n", argv[0], argv[arg]);
      usage(argv[0]);
    }
    arg++;
  }

  /* has count ? */
  if (arg < argc) {
    count = atoi(argv[arg]);
    if (count <= 0) {
      fprintf(stderr, "%s: bad count '%s'!\n", argv[0], argv[arg]);
      usage(argv[0]);
    }
    arg++;
  }

  /* extra arguments */
  if (arg < argc) {
    fprintf(stderr, "%s: too many arguments!\n", argv[0]);
    usage(argv[0]);
  }

  if (snmp != NULL)
    snmp_init(snmp);
  
  
  if (ifaces != NULL)
    ifs = parse_interfaces(ifaces);
  else if (snmp != NULL)
    ifs = snmp_scan_interfaces();
  else
    ifs = scan_interfaces();
  
  if (ifs == NULL) {
    fprintf(stderr, "%s: no interfaces to monitor!\n", argv[0]);
    exit(EXIT_FAILURE);
  }
  
  /* update header print interval if needed/possible */
#ifdef TIOCGWINSZ
  if (header > 0) {
    struct winsize ws;
    if (ioctl(STDOUT_FILENO, TIOCGWINSZ, &ws) == 0 &&
	ws.ws_row >= 4)
      header = ws.ws_row - 2;
  }
#endif
  
  print_header(ifs);
  if (snmp != NULL)
    snmp_get_stats(ifs);
  else
    get_stats(ifs);
  gettimeofday(&start, NULL);

  tv_delay.tv_sec = (int) delay;
  tv_delay.tv_usec = (int) ((delay - tv_delay.tv_sec) * 1000000);
  
  for (iter = 1; count == 0 || iter <= count; iter++) {
    tv = tv_delay;
    select(0, NULL, NULL, NULL, &tv);
    if (header != 0 && (iter % header == 0))
      print_header(ifs);
    if (snmp != NULL)
      snmp_get_stats(ifs);
    else
      get_stats(ifs);
    gettimeofday(&tv, NULL);
    print_stats(ifs, &start, &tv);
    start = tv;
    fflush(stdout);
  }

  if (snmp != NULL)
    snmp_free();
  
  exit(EXIT_SUCCESS);
}
