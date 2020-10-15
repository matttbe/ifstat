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
 * $Id: ifstat.c,v 1.45 2003/04/19 02:08:56 gael Exp $
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
#ifdef HAVE_SIGNAL_H
#include <signal.h>
#endif
#include <stdio.h>
#include <stdlib.h>
#include "ifstat.h"

#ifdef HAVE_SIGACTION
static void _setsig(int sig, RETSIGTYPE (*handler)(int)) {
  struct sigaction sa; 

  memset(&sa, 0, sizeof(struct sigaction));
  sa.sa_handler = handler;
  sigemptyset(&sa.sa_mask);
  sa.sa_flags = SA_RESTART;
  sigaction(sig, &sa, NULL);
}
#define SIGNAL(si, handler) _setsig((si), (handler))
#define RESIGNAL(si, handler)
#else
#define SIGNAL(si, handler) signal((si), (handler))
#define RESIGNAL(si, handler) signal((si), (handler))
#endif

/* parse interface list, using \ as escape character */
static int parse_interfaces(char *string, struct ifstat_list *ifs) {
  char *s, *d, *buf;
  int len, escaped = 0;

  if (string == NULL || (len = strlen(string)) <= 0)
    return 0;

  if ((buf = malloc(len + 1)) == NULL) {
    ifstat_perror("malloc");
    return 0;
  }

  d = buf;
  for(s = string; *s != '\0'; s++) {
    if (!escaped) {
      if (*s == '\\') {
	escaped = 1;
	continue;
      }
      if (*s == ',') {
	*d = '\0';
	ifstat_add_interface(ifs, buf, 0);
	d = buf;
	continue;
      }
    } else
      escaped = 0;
    *d++ = *s;
  }
  *d = '\0';
  if (*buf != '\0')
    ifstat_add_interface(ifs, buf, 0);

  free(buf);
  return 1;
}

static void usage(int result) {
  fprintf(stderr,
	  "usage: %s [-a] [-l] [-z] [-n] [-v] [-h] [-t] [-i if0,if1,...]\n"
	  "       [-d drv[:opt]] [-s [comm@][#]host[/nn]] [-T] [-A] [-w]\n"
	  "       [-W] [-S] [-b] [-q] [delay[/delay] [count]]\n", ifstat_progname);
  exit(result);
}

static void print_center(char *s, int len, int width) {
  int ofs, i;

  ofs = (width - len) / 2;
  for (i = 0; i < ofs; i++)
    putc(' ', stdout);
  for (i = 0; i < len; i++)
    putc(s[i], stdout);
  for (i = 0; i < (width - (ofs + len)); i++)
    putc(' ', stdout);
}

struct {
  int cols, lines, datalines;
} termsize;


int _sigwinch = 0;
static RETSIGTYPE update_termsize(int sig) {
#ifdef TIOCGWINSZ
  struct winsize ws;

  if (ioctl(STDOUT_FILENO, TIOCGWINSZ, &ws) == 0 &&
      ws.ws_row > 0 && ws.ws_col > 0) {
    termsize.cols = ws.ws_col;
    termsize.lines = ws.ws_row;
  } else { /* defaults if unknown */
    termsize.lines = 25; 
    termsize.cols = 80; 
  }
#ifdef SIGWINCH
  if (sig == SIGWINCH)
    _sigwinch = 1;
  RESIGNAL(SIGWINCH, &update_termsize);
#endif
#endif
}

int _sigcont = 0;
static RETSIGTYPE sigcont(int sig) {
  _sigcont = 1;  
  RESIGNAL(SIGCONT, &sigcont);
}

#define OPT_TIMESTAMP  1
#define OPT_FIXEDWIDTH 2
#define OPT_UNITBITS   4
#define OPT_NOINDEX    8
#define OPT_NONULL    16
#define OPT_NOSCAN    32
#define OPT_WRAP      64
#define OPT_NOTITLE  128
#define OPT_NOSCROLL 256

#define SPACE "  "

#define NUM "12345.12"
#define NA  "     n/a"
#define WIDTH (sizeof(NUM) - 1) * 2 + (sizeof(SPACE) - 1)

#define LEN(options, namelen) (((options) & OPT_FIXEDWIDTH || (namelen) < WIDTH) ? WIDTH : (namelen))
#define FMT(n) (((n) < 1e+5) ? "%8.2f" : (((n) < 1e+6) ? "%.1f" : "%.2e"))

/*
        eth0                  lo
  KB/s in  KB/s out    KB/s in  KB/s out
 14562.23  12345.25       0.00      0.00
*/

static void print_wrap(int options, int line) {
  putc('\n', stdout);
  putc((char) (((line - 1) % 26) + 65), stdout);
  if (options & OPT_TIMESTAMP)
    fputs("       " SPACE, stdout);
}

static int pos_next(int pos, int len, int options) {
  int ofs = (options & OPT_TIMESTAMP) ? 8 + sizeof(SPACE) - 1 : 1;

  pos += len + sizeof(SPACE) - 1;
  if (options & OPT_WRAP &&  pos + ofs + len >= termsize.cols)
    pos = 0;
  return pos;
}

static void print_legend(struct ifstat_data *ptr, int options, int line) {
  int len, pos;

  if (line == 0) {
    putc('\n', stdout);
    if (options & OPT_TIMESTAMP)
      fputs("HH:MM:SS" SPACE, stdout);
    else if (options & OPT_WRAP)
      putc(' ', stdout);
  } else
    print_wrap(options, line);

  pos = 0;
  for (; ptr != NULL; ptr = ptr->next) {
    if (pos > 0)
      fputs(SPACE, stdout);
    len = LEN(options, ptr->namelen);
    print_center((options & OPT_UNITBITS) ? " Kbps in  Kbps out" :
		 " KB/s in  KB/s out", WIDTH, len);
    if ((pos = pos_next(pos, len, options)) == 0 && ptr->next != NULL)
      return;
  }
  putc('\n', stdout);
}
			 
static void print_header(struct ifstat_list *ifs, int options) {
  struct ifstat_data *ptr, *start;
  int len, pos, line;

  if (options & OPT_TIMESTAMP)
    fputs("  Time  " SPACE, stdout);
  else if (options & OPT_WRAP)
    putc(' ', stdout);

  pos = 0;
  line = 0;
  start = ifs->first;
  for (ptr = ifs->first; ptr != NULL; ptr = ptr->next) {
    if (pos == 0 && ptr != ifs->first) {
      print_legend(start, options, line);
      start = ptr;
      print_wrap(options, ++line);
    } else if (pos > 0)
      fputs(SPACE, stdout);
    len = LEN(options, ptr->namelen);
    print_center(ptr->name, ptr->namelen < len ? ptr->namelen : len, len);
    pos = pos_next(pos, len, options);
  }
  termsize.datalines = line + 1;
  print_legend(start, options, line);
}

static void print_stats(struct ifstat_list *ifs,
			struct timeval *start,
			struct timeval *end,
			int options) {
  struct ifstat_data *ptr;
  int hasindex = 1, pos = 0, len, line = 0;
  char stats[WIDTH + 1];
  double delay, kbin, kbout, tkbin, tkbout, scale;
  struct tm *ltm;

  if (options & OPT_NOSCROLL)
    putc('\r', stdout);
  
  if (options & OPT_TIMESTAMP) {
    time_t t = end->tv_sec;
    if ((ltm = localtime(&t)) != NULL)
      fprintf(stdout, "%02d:%02d:%02d" SPACE,
	      ltm->tm_hour, ltm->tm_min, ltm->tm_sec);
    else
      fputs("--:--:--" SPACE, stdout);
  } else if (options & OPT_WRAP)
    putc(' ', stdout);
  
  delay = end->tv_sec - start->tv_sec + ((double) (end->tv_usec - start->tv_usec))
    / (double) 1000000;
  scale = delay * (options & OPT_UNITBITS ? 128 : 1024);
  
  tkbin = tkbout = 0;
  for (ptr = ifs->first; ptr != NULL; ptr = ptr->next) {
    if (ptr->flags & IFSTAT_HASSTATS) {
      kbin = (double) (ptr->bin - ptr->obin) / (double) scale;
      tkbin += kbin;
      kbout = (double) (ptr->bout - ptr->obout) / (double) scale;
      tkbout += kbout;
      ptr->flags &= ~IFSTAT_HASSTATS;
    } else if (ptr->flags & IFSTAT_TOTAL) {
      kbin = tkbin;
      kbout = tkbout;
    } else {
      kbin = -1;
      kbout = -1;
    }

    if (ptr->flags & IFSTAT_HASINDEX)
      ptr->flags &= ~IFSTAT_HASINDEX;
    else
      hasindex = 0;

    if (kbin >= 0)
      snprintf(stats, sizeof(NUM), FMT(kbin), kbin);
    else
      strcpy(stats, NA);
    strcpy(stats + sizeof(NUM) - 1, SPACE);
    if (kbout >= 0)
      snprintf(stats + sizeof(NUM) + sizeof(SPACE) - 2,
	       sizeof(NUM), FMT(kbout), kbout);
    else
      strcpy(stats + sizeof(NUM) + sizeof(SPACE) - 2, NA);

    if (pos == 0 && ptr != ifs->first)
      print_wrap(options, ++line);
    else if (pos > 0)
      fputs(SPACE, stdout);
    
    len = LEN(options, ptr->namelen);
    print_center(stats, WIDTH, len);
    pos = pos_next(pos, len, options);
  }
  termsize.datalines = line + 1;
  if (!(options & OPT_NOSCROLL))
    putc('\n', stdout);

  if (hasindex && !(options & OPT_NOINDEX))
    ifs->flags |= IFSTAT_HASINDEX;
  else
    ifs->flags &= ~IFSTAT_HASINDEX;
}

static void filter_interfaces(struct ifstat_list *ifs, int options) {
  struct ifstat_data *cur, *next, *parent;

  cur = ifs->first;
  parent = NULL;
  while (cur != NULL) {
    if (!(cur->flags & IFSTAT_HASSTATS) ||
	((options & OPT_NONULL) && cur->bin == 0 && cur->bout == 0)) {
      next = cur->next;
      if (parent != NULL)
	parent->next = next;
      else
	ifs->first = next;
      ifstat_free_interface(cur);
      cur = next;
    } else {
      parent = cur;
      cur = cur->next;
    }
  }
}

static void needarg(char opt, int arg, int argc) {
  if (arg + 1 >= argc) {
    fprintf(stderr, "%s: option '%c' requires an argument!\n", ifstat_progname, opt);
    usage(EXIT_FAILURE);
  }
}

static double getdelay(char *string) {
  double delay;

  if ((delay = atof(string)) < 0.1) {
    fprintf(stderr, "%s: bad or too short delay '%s'!\n", ifstat_progname, string);
    exit(EXIT_FAILURE);
  }
  return delay;
}

/* computes time remaining before start + delay */
static int notdone(struct timeval *start, struct timeval *tv_delay,
		   struct timeval *remains) {
  struct timeval now;
  struct timeval end;
  
  gettimeofday(&now, NULL);

  end.tv_sec = start->tv_sec + tv_delay->tv_sec;
  end.tv_usec = start->tv_usec + tv_delay->tv_usec;
  if (end.tv_usec >= 1000000) {
    end.tv_sec += (end.tv_usec / 1000000);
    end.tv_usec %= 1000000;
  }
  
  remains->tv_sec = end.tv_sec - now.tv_sec;
  remains->tv_usec = end.tv_usec - now.tv_usec;
  if (remains->tv_usec < 0) {
    remains->tv_sec--;
    remains->tv_usec += 1000000;
  }
  return (remains->tv_sec >= 0);
}

int main(int argc, char **argv) {
  struct ifstat_list ifs;
  struct ifstat_driver driver;
  int arg, iter, lasthdr;
  char *opt;
  char *dname = NULL;
  char *dopts = NULL;
  double delay = 1, first_delay = 1;
  int count = 0;
  int options = 0;

  struct timeval start, tv_delay, tv;

  if ((ifstat_progname = strrchr(argv[0], '/')) != NULL)
    ifstat_progname++;
  else
    ifstat_progname = argv[0];

  ifs.flags = 0;
  ifs.first = NULL;
  
  /* parse options */
  for (arg = 1; arg < argc; arg++) {
    if (argv[arg][0] != '-' || argv[arg][1] == '\0')
      break;
    opt = argv[arg]+1;
    while (*opt) {
      switch(*opt) {
      case 'a':
	ifs.flags |= IFSTAT_LOOPBACK|IFSTAT_DOWN;
	break;
      case 'l':
	ifs.flags |= IFSTAT_LOOPBACK;
	break;
      case 'v':
	printf("ifstat version %s.\n"
	       "Copyright (C) 2001-2003, Gaël Roualland <gael.roualland@dial.oleane.com>\n",
	       ifstat_version);
	opt = ifstat_list_drivers();
	printf("Compiled-in drivers: %s.\n", (opt != NULL) ? opt : "");
	free(opt);
	exit(EXIT_SUCCESS);
      case 'A':
	options |= OPT_NOINDEX;
	break;
      case 'n':
	options |= OPT_NOTITLE;
	break;
      case 't':
	options |= OPT_TIMESTAMP;
	break;
      case 'w':
	options |= OPT_FIXEDWIDTH;
	break;
      case 'b':
	options |= OPT_UNITBITS;
	break;
      case 'z':
	options |= OPT_NONULL;
	break;
      case 'W':
	options |= OPT_WRAP|OPT_FIXEDWIDTH;
	break;
      case 'T':
	ifs.flags |= IFSTAT_TOTAL;
	break;
      case 'S':
	options |= OPT_NOSCROLL|OPT_NOTITLE;
	break;
      case 'd':
	needarg(*opt, arg, argc);
	dname = argv[++arg];
	if ((dopts = strchr(dname, ':')) != NULL)
	  *dopts++ = '\0';
	break;
      case 'i':
	needarg(*opt, arg, argc);
	if (!parse_interfaces(argv[++arg], &ifs)) {
	  fprintf(stderr, "%s: error parsing interface list.\n", ifstat_progname);
	  exit(EXIT_FAILURE);
	}
	options |= OPT_NOSCAN;
	break;
      case 's':
	needarg(*opt, arg, argc);
	dname = "snmp";
	dopts = argv[++arg];
	break;
      case 'q':
	ifstat_quiet = 1;
	break;
      case 'h':
	usage(EXIT_SUCCESS);
      default:
	fprintf(stderr, "%s: invalid option '-%c'.\n", ifstat_progname, *opt);
	usage(EXIT_FAILURE);
      }
      opt++;
    }
  }

  if (options & OPT_NOSCROLL)
    options &= ~OPT_WRAP;

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
      fprintf(stderr, "%s: bad count '%s'!\n", ifstat_progname, argv[arg]);
      return EXIT_FAILURE;
    }
    arg++;
  }

  /* extra arguments */
  if (arg < argc) {
    fprintf(stderr, "%s: too many arguments!\n", ifstat_progname);
    return EXIT_FAILURE;
  }

  /* look for driver */
  if (!ifstat_get_driver(dname, &driver)) {
    fprintf(stderr, "%s: driver %s not available in this binary!\n", ifstat_progname, dname);
    return EXIT_FAILURE;
  }

  /* init driver */
  if (driver.open_driver != NULL &&
      !driver.open_driver(&driver, dopts))
    return EXIT_FAILURE;

  if (ifs.first == NULL)
    driver.scan_interfaces(&driver, &ifs);

  /* poll interfaces for the first time */
  if (ifs.first != NULL) {
    if (driver.get_stats != NULL && !driver.get_stats(&driver, &ifs))
      return EXIT_FAILURE;
    gettimeofday(&start, NULL);
    
    if (!(options & OPT_NOSCAN))
      filter_interfaces(&ifs, options);
    
    ifstat_reset_interfaces(&ifs);
  }
    
  if (ifs.first == NULL) {
    fprintf(stderr, "%s: no interfaces to monitor!\n", ifstat_progname);
    if (driver.close_driver != NULL)
      driver.close_driver(&driver);
    return EXIT_FAILURE;
  }
  
  if (ifs.flags & IFSTAT_TOTAL)
    ifstat_add_interface(&ifs, "Total", IFSTAT_TOTAL);

  /* update size of terminal if needed/possible */
  if (!(options & OPT_NOTITLE) || (options & OPT_WRAP)) {
    update_termsize(0);
#ifdef SIGWINCH    
    SIGNAL(SIGWINCH, &update_termsize);
#endif
  }
  /* register SIGCONT for redisplay of header */
  if (!(options & OPT_NOTITLE) || (options & OPT_NOSCROLL))
    SIGNAL(SIGCONT, &sigcont);
  
  print_header(&ifs, options);
  lasthdr = 1;

  tv_delay.tv_sec = (int) first_delay;
  tv_delay.tv_usec = (int) ((first_delay - tv_delay.tv_sec) * 1000000);

  for (iter = 1; count == 0 || iter <= count; iter++) {
    if (iter == 2 && first_delay != delay) {
      tv_delay.tv_sec = (int) delay;
      tv_delay.tv_usec = (int) ((delay - tv_delay.tv_sec) * 1000000);
    }
    tv = tv_delay;
    while (select(0, NULL, NULL, NULL, &tv) != 0 && _sigwinch
	   && notdone(&start, &tv_delay, &tv))
      /* restart select if interrupted by sigwinch */
      _sigwinch = 0;
    if (_sigcont ||
	(!(options & OPT_NOTITLE) &&
	 termsize.lines > (3 * termsize.datalines) &&
	 (iter - lasthdr) * termsize.datalines >=
	 (termsize.lines - (3 * termsize.datalines)))) {
      print_header(&ifs, options);
      lasthdr = iter;
      _sigcont = 0;
    }
    if (driver.get_stats != NULL && !driver.get_stats(&driver, &ifs))
      return EXIT_FAILURE;
    gettimeofday(&tv, NULL);
    print_stats(&ifs, &start, &tv, options);
    start = tv;
    fflush(stdout);
  }

  if (driver.close_driver != NULL)
    driver.close_driver(&driver);

  return EXIT_SUCCESS;
}
