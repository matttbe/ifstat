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
 * $Id: ifstat.c,v 1.19 2002/01/16 00:11:48 gael Exp $
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

void add_interface(struct ifstat_data **first, char *ifname) {
  struct ifstat_data *cur, *last;

  /* check interface name */
  if (*ifname == '\0')
    return;
  
  last = NULL;
  for (cur = *first; cur != NULL; cur = cur->next) {
    if (cur->name[0] == ifname[0] && !strcmp(cur->name + 1, ifname + 1))
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
  data->flags |= IFSTAT_HASSTATS;
}

struct ifstat_data *get_interface(struct ifstat_data *list, char *ifname) {
  struct ifstat_data *ptr;

  for (ptr = list; ptr != NULL; ptr = ptr->next)
    if (ptr->name[0] == ifname[0] && !strcmp(ptr->name + 1, ifname + 1))
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

static void usage(int result) {
  fprintf(stderr,
	  "usage: %s [-a] [-l] [-n] [-v] [-h] [-t] [-i if0,if1,...] [-d drv[:opt]]\n"
	  "       -s [comm@]host] [-t] [delay[/delay] [count]]\n", progname);
  exit(result);
}

#define SPACE "  "

/*
        eth0                  lo
  KB/s in  KB/s out    KB/s in  KB/s out
 14562.23  12345.25       0.00      0.00
*/
static void print_header(struct ifstat_data *list, int tstamp) {
  struct ifstat_data *ptr;
  char ifname[19];
  int len, ofs, mlen = (sizeof(ifname) - 1);

  if (tstamp)
    fputs("  Time  " SPACE, stdout);

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

  if (tstamp)
    fputs("HH:MM:SS" SPACE, stdout);

  for (ptr = list; ptr != NULL; ptr = ptr->next) {
    fputs(" KB/s in  KB/s out", stdout);
    if (ptr->next)
      fputs(SPACE, stdout);
  }
  putc('\n', stdout);
}

static void print_stats(struct ifstat_data *list,
			struct timeval *start,
			struct timeval *end,
			int tstamp) {
  struct ifstat_data *ptr;
  double delay, kbin, kbout;
  struct tm *ltm;
  if (tstamp) {
    time_t t = end->tv_sec;
    if ((ltm = localtime(&t)) != NULL)
      fprintf(stdout, "%02d:%02d:%02d" SPACE,
	      ltm->tm_hour, ltm->tm_min, ltm->tm_sec);
    else
      fputs("--:--:--" SPACE, stdout);
  }
  
  delay = end->tv_sec - start->tv_sec + ((double) (end->tv_usec - start->tv_usec))
    / (double) 1000000;

  for (ptr = list; ptr != NULL; ptr = ptr->next) {
    if (ptr->flags & IFSTAT_HASSTATS) {
      kbin = (double) (ptr->bin - ptr->obin) / (double) (1024 * delay);
      kbout = (double) (ptr->bout - ptr->obout) / (double) (1024 * delay);
      printf("%8.2f  %8.2f" SPACE, kbin, kbout);
      ptr->flags &= ~IFSTAT_HASSTATS;
    } else
      fputs("     n/a       n/a" SPACE, stdout);
  }
  putc('\n', stdout);
}

static void needarg(char opt, int arg, int argc) {
  if (arg + 1 >= argc) {
    fprintf(stderr, "%s: option '%c' requires an argument!\n", progname, opt);
    usage(EXIT_FAILURE);
  }
}

double getdelay(char *string) {
  double delay;

  if ((delay = atof(string)) < 0.1) {
    fprintf(stderr, "%s: bad or too short delay '%s'!\n", progname, string);
    exit(EXIT_FAILURE);
  }
  return delay;
}

char *progname;

int main(int argc, char **argv) {
  char *ifaces = NULL;
  struct ifstat_data *ifs;
  struct ifstat_driver driver;
  int arg, iter;
  char *opt;
  char *dname = NULL;
  char *dopts = NULL;

  int header = 25; /* simple default */
  double delay = 1, first_delay = 1;
  int count = 0;
  int tstamp = 0;
  int flags = 0;

  struct timeval start, tv_delay, tv;

  if ((progname = strrchr(argv[0], '/')) != NULL)
    progname++;
  else
   progname = argv[0];
  
  /* parse options */
  for (arg = 1; arg < argc; arg++) {
    if (argv[arg][0] != '-' || argv[arg][1] == '\0')
      break;
    opt = argv[arg]+1;
    while (*opt) {
      switch(*opt) {
      case 'a':
	flags |= IFSTAT_LOOPBACK|IFSTAT_DOWN;
	break;
      case 'l':
	flags |= IFSTAT_LOOPBACK;
	break;
      case 'v':
	printf("ifstat version " VERSION "\n"
	       "Copyright (C) 2001, Gaël Roualland <gael.roualland@iname.com>\n");
	fputs("Compiled-in drivers: ", stdout);
	print_drivers(stdout);
	fputs(".\n", stdout);
	exit(EXIT_SUCCESS);
      case 'n':
	header = 0;
	break;
      case 't':
	tstamp = 1;
	break;
      case 'd':
	needarg(*opt, arg, argc);
	dname = argv[++arg];
	if ((dopts = strchr(dname, ':')) != NULL)
	  *dopts++ = '\0';
	break;
      case 'i':
	needarg(*opt, arg, argc);
	ifaces = argv[++arg];
	break;
      case 's':
	needarg(*opt, arg, argc);
	dname = "snmp";
	dopts = argv[++arg];
	break;
      case 'h':
	usage(EXIT_SUCCESS);
      default:
	fprintf(stderr, "%s: invalid option '-%c'.\n", progname, *opt);
	usage(EXIT_FAILURE);
      }
      opt++;
    }
  }

  /* has delay ? */
  if (arg < argc) {
    if ((opt = strchr(argv[arg], '/')) != NULL)
      *opt++ = '\0';
    first_delay = getdelay(argv[arg]);
    delay = (opt != NULL) ? getdelay(opt) : first_delay;
    arg++;
  }

  /* has count ? */
  if (arg < argc) {
    if ((count = atoi(argv[arg])) <= 0) {
      fprintf(stderr, "%s: bad count '%s'!\n", progname, argv[arg]);
      return EXIT_FAILURE;
    }
    arg++;
  }

  /* extra arguments */
  if (arg < argc) {
    fprintf(stderr, "%s: too many arguments!\n", progname);
    return EXIT_FAILURE;
  }

  /* look for driver */
  if (!get_driver(dname, &driver)) {
    fprintf(stderr, "%s: driver %s not available in this binary!\n", progname, dname);
    return EXIT_FAILURE;
  }

  /* init driver */
  if (driver.open_driver != NULL &&
      !driver.open_driver(&driver, dopts))
    return EXIT_FAILURE;
  
  if (ifaces != NULL)
    ifs = parse_interfaces(ifaces);
  else
    ifs = driver.scan_interfaces(&driver, flags);

  if (ifs == NULL) {
    fprintf(stderr, "%s: no interfaces to monitor!\n", progname);
    if (driver.close_driver != NULL)
      driver.close_driver(&driver);
    return EXIT_FAILURE;
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
  
  print_header(ifs, tstamp);
  if (driver.get_stats != NULL && !driver.get_stats(&driver, ifs))
    return EXIT_FAILURE;
  gettimeofday(&start, NULL);

  tv.tv_sec = (int) first_delay;
  tv.tv_usec = (int) ((first_delay - tv.tv_sec) * 1000000);

  if (first_delay != delay) {
    tv_delay.tv_sec = (int) delay;
    tv_delay.tv_usec = (int) ((delay - tv_delay.tv_sec) * 1000000);
  } else
    tv_delay = tv;
  
  for (iter = 1; count == 0 || iter <= count; iter++) {
    if (iter > 1)
      tv = tv_delay;
    select(0, NULL, NULL, NULL, &tv);
    if (header != 0 && (iter % header == 0))
      print_header(ifs, tstamp);
    if (driver.get_stats != NULL && !driver.get_stats(&driver, ifs))
      return EXIT_FAILURE;
    gettimeofday(&tv, NULL);
    print_stats(ifs, &start, &tv, tstamp);
    start = tv;
    fflush(stdout);
  }

  if (driver.close_driver != NULL)
    driver.close_driver(&driver);

  return EXIT_SUCCESS;
}
