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
 * $Id: snmp.c,v 1.26 2003/05/06 23:30:02 gael Exp $
 */

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif
#include <stdlib.h>
#include <stdio.h>
#include "ifstat.h"

#ifdef USE_SNMP
#include <unistd.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <string.h>
#ifdef HAVE_NET_SNMP
#include <net-snmp/net-snmp-config.h>
#include <net-snmp/net-snmp-includes.h>
#else
#include <ucd-snmp/ucd-snmp-config.h>
#include <ucd-snmp/ucd-snmp-includes.h>
#endif
#include "snmp.h"

/* define this to use ifcount as a hint to discover interfaces
   does not work well with routers that do not number interfaces sequentially,
   but is faster that the ifIndex walk used otherwise */
#undef USE_SNMP_IFCOUNT

static char *snmp_sess_errstring(struct snmp_session *ss) {
  char *res;
  snmp_error(ss, NULL, NULL, &res);
  return res;
}

#ifdef USE_SNMP_IFCOUNT
/* report the value interfaces.ifNumber.0, actually the number of interfaces */
static int snmp_get_ifcount(struct snmp_session *ss) {
  int nifaces = -1;
  oid ifcount[] = { 1, 3, 6, 1, 2, 1, 2, 1, 0 };
  struct snmp_pdu *pdu;
  struct snmp_pdu *response = NULL;
  int status;

  if ((pdu = snmp_pdu_create(SNMP_MSG_GET)) == NULL) {
    ifstat_error("snmp_pdu_create: %s", snmp_api_errstring(snmp_errno));
    return -1;
  }

  snmp_add_null_var(pdu, ifcount, sizeof(ifcount) / sizeof(oid));

  if ((status = snmp_synch_response(ss, pdu, &response)) != STAT_SUCCESS ||
      response->errstat != SNMP_ERR_NOERROR ||
      response->variables == NULL ||
      response->variables->type != ASN_INTEGER) {
    if (status == STAT_SUCCESS)
      ifstat_error("snmp: Error: %s", snmp_errstring(response->errstat));
    else
      ifstat_error("snmpget(interfaces.ifNumber.0): %s", snmp_sess_errstring(ss));
    if (response)
      snmp_free_pdu(response);
    return -1;
  }
  nifaces = *(response->variables->val.integer);
  snmp_free_pdu(response);  
  
  if (nifaces < 0)
    return -1;
  return nifaces;
}
#endif

static int snmp_get_nextif(struct snmp_session *ss, int index) {
  oid ifindex[] = { 1, 3, 6, 1, 2, 1, 2, 2, 1, 1, 0 };
  unsigned int len = sizeof(ifindex) / sizeof(oid);
  struct snmp_pdu *pdu;
  struct snmp_pdu *response = NULL;
  struct variable_list *vars;
  int status;

  if (index >= 0)
    ifindex[len - 1] = index;

  if ((pdu = snmp_pdu_create(SNMP_MSG_GETNEXT)) == NULL) {
    ifstat_error("snmp_pdu_create: %s", snmp_api_errstring(snmp_errno));
    return -1;
  }

  snmp_add_null_var(pdu, ifindex, (index < 0) ? len - 1 : len);

  if ((status = snmp_synch_response(ss, pdu, &response)) != STAT_SUCCESS ||
      response->errstat != SNMP_ERR_NOERROR ||
      response->variables == NULL) {
    if (status == STAT_SUCCESS) 
      ifstat_error("snmp: Error: %s", snmp_errstring(response->errstat));
    else
      ifstat_error("snmpgetnext(interfaces.ifTable.ifEntry.ifIndex...): %s",
		   snmp_sess_errstring(ss));
    if (response != NULL)
      snmp_free_pdu(response);
    return -1;
  }

  for(vars = response->variables; vars; vars = vars->next_variable) {
    /* check that the variable is under the base oid */
    if (vars->name_length != len)
      continue;
    if (memcmp(ifindex, vars->name, sizeof(ifindex) - sizeof(oid)) != 0)
      continue;

    index = vars->name[vars->name_length - 1];
    snmp_free_pdu(response);
    return index;
  }
  snmp_free_pdu(response);
  return -1;
}

#define S_IFNAMEMAX 64

struct ifsnmp {
  char name[S_IFNAMEMAX];
  unsigned long long bout, bin;
  int flags, index;
};

#define S_UP         1
#define S_BIN        2
#define S_BOUT       4
#define S_LOOP       8
#define S_INVALID   16
#define S_NUMNAME   32
#define S_IFNAME    64
  
/* fill a struct ifsnmp buffer of selected information (flags) for
   interface index to (index + nifaces - 1). ifsnmp must be large
   enough, and nifaces shouldb'nt too large since some devices have
   limited capability for large responses...
   In case we get a unknown name answer and we're
   polling several interfaces at once, interfaces will be polled
   again individually to try to solve the problem.
*/
static int snmp_get_ifinfos(struct snmp_session *ss, int nifaces,
			    int flags, struct ifsnmp * ifsnmp, int *toobig) {
  struct snmp_pdu *pdu, *response = NULL;
  oid ifinfo[] = { 1, 3, 6, 1, 2, 1, 2, 2, 1, 0, 0 }; /* interfaces.ifTable.ifEntry.x.n */
#define ifDescr 2
#define ifType 3  
#define ifOperStatus 8  
#define ifInOctets 10
#define ifOutOctets 16
  struct variable_list *vars;
  int i, status;
 
  if (nifaces <= 0)
    return 0;
  
  if ((pdu = snmp_pdu_create(SNMP_MSG_GET)) == NULL) {
    ifstat_error("snmp_pdu_create: %s", snmp_api_errstring(snmp_errno));
    return 0;
  }

  for (i = 0; i < nifaces; i++) {
    ifsnmp[i].flags = 0;
    ifsnmp[i].name[0] = 0;

    /* set interface index */
    ifinfo[10] = ifsnmp[i].index;

    if (flags & S_NUMNAME) {
      sprintf(ifsnmp[i].name, "if%d", ifsnmp[i].index);
    } else if (flags & S_IFNAME) {
      /* require descr */
      ifinfo[9] = ifDescr;
      snmp_add_null_var(pdu, ifinfo, sizeof(ifinfo) / sizeof(oid));
    }
    
    /* then optional data */
    if (flags & S_UP) {
      ifinfo[9] = ifOperStatus;
      snmp_add_null_var(pdu, ifinfo, sizeof(ifinfo) / sizeof(oid));
    }
    if (flags & S_BOUT) {
      ifinfo[9] = ifOutOctets;
      snmp_add_null_var(pdu, ifinfo, sizeof(ifinfo) / sizeof(oid));
    }
    if (flags & S_BIN) {
      ifinfo[9] = ifInOctets;
      snmp_add_null_var(pdu, ifinfo, sizeof(ifinfo) / sizeof(oid));
    }
    if (flags & S_LOOP) {
      ifinfo[9] = ifType;
      snmp_add_null_var(pdu, ifinfo, sizeof(ifinfo) / sizeof(oid));
    }
  }
    
  if ((status = snmp_synch_response(ss, pdu, &response)) != STAT_SUCCESS ||
      response->errstat != SNMP_ERR_NOERROR ||
      response->variables == NULL) {
    if (status == STAT_SUCCESS) {
      if (response->errstat != SNMP_ERR_NOSUCHNAME &&
	  response->errstat != SNMP_ERR_TOOBIG)
	ifstat_error("snmp: Error: %s", snmp_errstring(response->errstat));
      else if (nifaces > 1) {
	/* maybe only one of the interface is broken or too many interfaces polled at once
	   -- repoll inetrface per interface */
	if (response->errstat == SNMP_ERR_TOOBIG && toobig != NULL)
	  (*toobig)++;
	if (response != NULL)
	  snmp_free_pdu(response);
	status = 0;
	for (i = 0; i < nifaces; i++) {
	  if (!snmp_get_ifinfos(ss, 1, flags, ifsnmp + i, NULL))
	    ifsnmp[i].flags |= S_INVALID;
	  else
	    status = 1;
	}
	return status;
      }
    } else
      ifstat_error("snmpget(interfaces.ifTable.ifEntry...): %s", snmp_sess_errstring(ss));
    if (response != NULL)
      snmp_free_pdu(response);
    return 0;
  }

  for(vars = response->variables; vars; vars = vars->next_variable) {
    /* check that the variable is under the base oid */
    if (memcmp(ifinfo, vars->name, sizeof(ifinfo) - 2 * sizeof(oid)) != 0)
      continue;
    for(i = 0; i < nifaces; i++) {
	if ((signed long long)ifsnmp[i].index == (signed long long)vars->name[10])
	break;
    }

    if (i == nifaces) /* not found */
      continue;

    switch (vars->name[9]) {
    case ifDescr:
      if (vars->type == ASN_OCTET_STR) {
        unsigned int count = vars->val_len;

        if (count >= sizeof(ifsnmp[i].name))
          count = sizeof(ifsnmp[i].name) - 1;
	strncpy(ifsnmp[i].name, (char *)vars->val.string, count);
        ifsnmp[i].name[count] = '\0';
      }
      break;
    case ifOperStatus:
      if (vars->type == ASN_INTEGER) {
	if (*(vars->val.integer) == 1) /* up */
	  ifsnmp[i].flags |= S_UP;
      }
      break;
    case ifType:
      if (vars->type == ASN_INTEGER) {
	if (*(vars->val.integer) == 24) /* softwareLoopback */
	  ifsnmp[i].flags |= S_LOOP;
      }
      break;
    case ifInOctets:
      if (vars->type == ASN_INTEGER || vars->type == ASN_COUNTER) {
	ifsnmp[i].flags |= S_BIN;
	ifsnmp[i].bin =	*(vars->val.integer);
      }
      break;
    case ifOutOctets:
      if (vars->type == ASN_INTEGER || vars->type == ASN_COUNTER) {
	ifsnmp[i].flags |= S_BOUT;
	ifsnmp[i].bout = *(vars->val.integer);
      }
      break;
    }
  }
  snmp_free_pdu(response);
  return 1;
}

/* driver API */

struct snmp_driver_data {
  struct snmp_session *session;
  int num_ifnames, num_ifsreqs;
  struct ifsnmp *ifsnmp;
};

/* maximum number of interfaces to poll at once, min 1 */
#define MAXIFSREQS 64
#define DEFIFSREQS 8

/* initiailise the snmp driver, strings syntax is [comm@][#]host*/
int snmp_open_driver(struct ifstat_driver *driver, char *options) {
  char *host;
  char *community;
  struct snmp_session session;
  struct snmp_driver_data *data;
  
  if ((data = malloc(sizeof(struct snmp_driver_data))) == NULL) {
    ifstat_perror("malloc");
    return 0;
  }

  if (options == NULL)
    options = "localhost";
  
  if ((host = strchr(options, '@')) != NULL) {
    *host++ = '\0';
    community = options;
  } else {
    host = options;
    community = "public";
  }

  if (*host == '#') {
    host++;
    data->num_ifnames = 1; /* numeric interface names */
  } else
    data->num_ifnames = 0;

  if ((options = strchr(host, '/')) != NULL) {
    *options++ = '\0';
    data->num_ifsreqs = atoi(options);
    if (data->num_ifsreqs < 1) {
      ifstat_error("snmp: bad number of interface requests: %s; ignored.", options);
      data->num_ifsreqs = DEFIFSREQS;
    } else if (data->num_ifsreqs > MAXIFSREQS) {
      ifstat_error("snmp: number of interface requests too large: %d; using %d instead.",
	      data->num_ifsreqs, MAXIFSREQS);
      data->num_ifsreqs = MAXIFSREQS;
    } 
  } else
    data->num_ifsreqs = DEFIFSREQS;
  
  if ((data->ifsnmp = calloc(sizeof(struct ifsnmp), data->num_ifsreqs)) == NULL) {
    ifstat_perror("malloc");
    free(data);
    return 0;
  }
  
  init_snmp(ifstat_progname);
  snmp_sess_init(&session);
  session.peername = host;
  session.version = SNMP_VERSION_1;
  session.community = (unsigned char *)community;
  session.community_len = strlen(community);

  if ((data->session = snmp_open(&session)) == NULL) {
    ifstat_error("snmp_open: %s", snmp_api_errstring(snmp_errno));
    free(data->ifsnmp);
    free(data);
    return 0;
  }
  
  driver->data = (void *) data;
  return 1;
}

/* cleanups session */
void snmp_close_driver(struct ifstat_driver *driver) {
  struct snmp_driver_data *data = driver->data;

  snmp_close(data->session);
  free(data->ifsnmp);
  free(data);
}

#ifdef USE_SNMP_IFCOUNT
static int snmp_map_ifs(struct ifstat_driver *driver,
			int (*mapf)(struct ifstat_driver *driver, int nifaces, void *pdata),
			void *pdata) {
  struct snmp_driver_data *data = driver->data;
  struct ifsnmp *ifsnmp = data->ifsnmp;
  int ifaces, nifaces, index, i;
  
  if ((ifaces = snmp_get_ifcount(data->session)) <= 0) {
    ifstat_error("snmp: no interfaces returned.");
    return 0;
  }
  
  for(index = 0; index <= (ifaces /data->num_ifsreqs); index++) {
    nifaces = ifaces - index * data->num_ifsreqs;
    if (nifaces > data->num_ifsreqs)
      nifaces = data->num_ifsreqs;
    
    for (i = 0; i < nifaces; i++) 
      ifsnmp[i].index = index * data->num_ifsreqs + i + 1;
    
    if(!mapf(driver, nifaces, pdata)) 
      return 0;
  }
  return 1;
}
#else
static int snmp_map_ifs(struct ifstat_driver *driver,
			int (*mapf)(struct ifstat_driver *driver, int nifaces, void *pdata),
			void *pdata) {
  struct snmp_driver_data *data = driver->data;
  struct ifsnmp *ifsnmp = data->ifsnmp;
  int ifaces, nifaces, index;
  
  index = -1;
  nifaces = ifaces = 0;
  while((index = snmp_get_nextif(data->session, index)) >= 0) {
    ifaces++;
    ifsnmp[nifaces++].index = index;
    if (nifaces >= data->num_ifsreqs) {
      if(!mapf(driver, nifaces, pdata)) 
	return 0;
      nifaces = 0;
    }
  }
  if (nifaces > 0)
    return mapf(driver, nifaces, pdata);
  return (ifaces != 0);
}
#endif

static int snmp_map_scan(struct ifstat_driver *driver, int nifaces, void *pdata) {
  struct snmp_driver_data *data = driver->data;
  struct ifsnmp *ifsnmp = data->ifsnmp;
  struct ifstat_list *ifs = pdata;
  struct ifstat_data *iface;
  int i;

  if (!snmp_get_ifinfos(data->session, nifaces, S_UP | S_LOOP |
			(data->num_ifnames ? S_NUMNAME : S_IFNAME),
			ifsnmp, NULL))
    return 1;

  for (i=0; i < nifaces; i++) {
    if (ifsnmp[i].flags & S_INVALID)
      continue;
    if ((ifsnmp[i].flags & S_LOOP) && !(ifs->flags & IFSTAT_LOOPBACK))
      continue;
    if ((ifsnmp[i].flags & S_UP) || (ifs->flags & IFSTAT_DOWN)) {
      if ((iface = ifstat_get_interface(ifs, ifsnmp[i].name)) != NULL) {
	if (!ifstat_quiet && !(iface->flags & IFSTAT_HASSTATS)) {
	  ifstat_error("warning: multiple interfaces detected with same name (%s); "
		       "you should enable numeric mode by prepending # to the hostname.",
		       ifsnmp[i].name);
	  iface->flags |= IFSTAT_HASSTATS;
	}
      } else 
	ifstat_add_interface(ifs, ifsnmp[i].name, 0);
    }
  }
  return 1;
}

int snmp_scan_interfaces(struct ifstat_driver *driver,
			 struct ifstat_list *ifs) {
  return snmp_map_ifs(driver, &snmp_map_scan, (void *) ifs);
}

static void snmp_toobig(struct ifstat_driver *driver) {
  struct snmp_driver_data *data = driver->data;

  if (data->num_ifsreqs > 1) {
    data->num_ifsreqs >>= 1;
    if (!ifstat_quiet)
      ifstat_error("warning: changing poll grouping to %d to avoid \"too big\" errors",
		   data->num_ifsreqs);
  }
}

static int snmp_map_stats(struct ifstat_driver *driver, int nifaces, void *pdata) {
  struct snmp_driver_data *data = driver->data;
  struct ifsnmp *ifsnmp = data->ifsnmp;
  struct ifstat_list *ifs = pdata;
  struct ifstat_data *cur;
  int i, toobig = 0;

  if (!snmp_get_ifinfos(data->session, nifaces, S_BIN | S_BOUT |
			(data->num_ifnames ? S_NUMNAME : S_IFNAME),
			ifsnmp, &toobig))
    return 1;

  if (toobig)
    snmp_toobig(driver);

  for (i=0; i < nifaces; i++) {
    if (ifsnmp[i].flags & S_INVALID)
      continue;
    if (!(ifsnmp[i].flags & S_BIN && ifsnmp[i].flags & S_BOUT))
      continue;
    /* overwrite if name if needed */
    if ((cur = ifstat_get_interface(ifs, ifsnmp[i].name)) != NULL) {
      ifstat_set_interface_stats(cur, ifsnmp[i].bin, ifsnmp[i].bout);
      ifstat_set_interface_index(cur, ifsnmp[i].index);
    }
  }
  return 1;
}

int snmp_get_stats(struct ifstat_driver *driver, struct ifstat_list *ifs) {
  struct snmp_driver_data *data = driver->data;
  int ifaces, i, toobig = 0;
  struct ifstat_data *cur, *block;
  struct ifsnmp *ifsnmp = data->ifsnmp;
  
  if (ifs->flags & IFSTAT_HASINDEX) { /* poll by index */
    cur = ifs->first;
    while (cur != NULL) {
      /* init as many interface as possible */
      block = cur;
      ifaces = 0;
      while (ifaces < data->num_ifsreqs && cur != NULL) {
	ifsnmp[ifaces++].index = cur->index;
	cur = cur->next;
      }

      /* poll them */
      if (!snmp_get_ifinfos(data->session, ifaces, S_BIN | S_BOUT |
			    (data->num_ifnames ? 0 : S_IFNAME),
			    ifsnmp, &toobig))
	continue;

      if (toobig)
	snmp_toobig(driver);
      
      for (i = 0; i < ifaces; i++) {
	if (ifsnmp[i].flags & S_INVALID)
	  continue;
	if (!(ifsnmp[i].flags & S_BIN && ifsnmp[i].flags & S_BOUT))
	  continue;
	if (!data->num_ifnames && strcmp(ifsnmp[i].name, block->name))
	  continue; /* interface changed of index... */
	ifstat_set_interface_stats(block, ifsnmp[i].bin, ifsnmp[i].bout);
	ifstat_set_interface_index(block, ifsnmp[i].index);
	block = block->next;
      }
    }
    return 1;
  }

  return snmp_map_ifs(driver, &snmp_map_stats, (void *) ifs);
}
#endif


