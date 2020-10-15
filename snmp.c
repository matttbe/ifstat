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
 * $Id: snmp.c,v 1.6 2001/12/20 23:28:38 gael Exp $
 */

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif
#include <stdlib.h>
#include <stdio.h>
#include "ifstat.h"

#ifdef HAVE_SNMP
#include <unistd.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <string.h>
#include <ucd-snmp/ucd-snmp-config.h>
#include <ucd-snmp/ucd-snmp-includes.h>

/* report the value interfaces.ifNumber.0, actually the number of interfaces */
static int snmp_get_ifcount(struct snmp_session *ss) {
  int nifs = -1;
  oid ifcount[] = { 1, 3, 6, 1, 2, 1, 2, 1, 0 };
  struct snmp_pdu *pdu;
  struct snmp_pdu *response = NULL;
  int status;
  
  if ((pdu = snmp_pdu_create(SNMP_MSG_GET)) == NULL) {
    snmp_perror("snmp_pdu_create");
    return -1;
  }

  snmp_add_null_var(pdu, ifcount, sizeof(ifcount) / sizeof(oid));

  if ((status = snmp_synch_response(ss, pdu, &response)) != STAT_SUCCESS ||
      response->errstat != SNMP_ERR_NOERROR ||
      response->variables == NULL ||
      response->variables->type != ASN_INTEGER) {
    if (status == STAT_SUCCESS)
      fprintf(stderr, "snmp: Error: %s\n",
	      snmp_errstring(response->errstat));
    else
      snmp_sess_perror("snmpget(interfaces.ifNumber.0)", ss);
    if (response)
      snmp_free_pdu(response);
    return -1;
  }
  nifs = *(response->variables->val.integer);
  snmp_free_pdu(response);

  if (nifs < 0)
    return -1;
  return nifs;
}

struct ifsnmp {
  char name[64];
  unsigned long bout, bin;
  int flags;
};

#define S_UP   1
#define S_BIN  2
#define S_BOUT 4

/* fill a struct ifsnmp buffer of selected information (flags) for
   interface index to (index + nifs - 1). ifsnmp must be large
   enough, and nifs shouldb'nt too large since some devices have
   limited capability for large responses... interface names
   are malloced and should be freed */
static int snmp_get_ifinfos(struct snmp_session *ss, int index, int nifs,
			    int flags, struct ifsnmp * ifsnmp) {
  struct snmp_pdu *pdu, *response = NULL;
  oid ifinfo[] = { 1, 3, 6, 1, 2, 1, 2, 2, 1, 0, 0 }; /* interfaces.ifTable.ifEntry.x.n */
#define ifDescr 2
#define ifOperStatus 8  
#define ifInOctets 10
#define ifOutOctets 16
  struct variable_list *vars;
  int i, status;
 
  if (nifs <= 0)
    return -1;
  
  if ((pdu = snmp_pdu_create(SNMP_MSG_GET)) == NULL) {
    snmp_perror("snmp_pdu_create");
    return -1;
  }

  for (i = 0; i < nifs; i++) {
    ifsnmp[i].flags = 0;
    ifsnmp[i].name[0] = 0;

    /* set interface index */
    ifinfo[10] = index + i;
    
    /* first require descr */
    ifinfo[9] = ifDescr;
    snmp_add_null_var(pdu, ifinfo, sizeof(ifinfo) / sizeof(oid));
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
  }
    
  if ((status = snmp_synch_response(ss, pdu, &response)) != STAT_SUCCESS ||
      response->errstat != SNMP_ERR_NOERROR ||
      response->variables == NULL) {
    if (status == STAT_SUCCESS) {
      if (response->errstat != SNMP_ERR_NOSUCHNAME)
	fprintf(stderr, "snmp: Error: %s\n",
		snmp_errstring(response->errstat));
    } else
      snmp_sess_perror("snmpget(interfaces.ifTable.ifEntry...)", ss);
    if (response != NULL)
      snmp_free_pdu(response);
    return -1;
  }

  for(vars = response->variables; vars; vars = vars->next_variable) {
    /* check that the variable is under the base oid */
    if (memcmp(ifinfo, vars->name, sizeof(ifinfo) - 2 * sizeof(oid)) != 0)
      continue;
    i = vars->name[10] - index; 
    if (i < 0 || i >= nifs)
      continue;
    switch (vars->name[9]) {
    case ifDescr:
      if (vars->type == ASN_OCTET_STR) {
        int count = vars->val_len;

        if (count >= sizeof(ifsnmp[i].name))
          count = sizeof(ifsnmp[i].name) - 1;
	strncpy(ifsnmp[i].name, vars->val.string, count);
        ifsnmp[i].name[count] = '\0';
      }
      break;
    case ifOperStatus:
      if (vars->type == ASN_INTEGER) {
	if (*(vars->val.integer) == 1) /* up */
	  ifsnmp[i].flags |= S_UP;
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
  return 0;
}

/* globals */
static struct snmp_session *sess = NULL;
static int num_ifnames = 0;

/* initiailise the snmp driver, strings syntax is [comm@][#]host*/
void snmp_init(char *string) {
  char *host;
  char *community;
  struct snmp_session session;

  if ((host = strchr(string, '@')) != NULL) {
    *host++ = '\0';
    community = string;
  } else {
    host = string;
    community = "public";
  }

  if (*host == '#') {
    host++;
    num_ifnames = 1; /* numeric interface names */
  }
  
  init_snmp("ifstat");
  snmp_sess_init(&session);
  session.peername = host;
  session.version = SNMP_VERSION_1;
  session.community = community;
  session.community_len = strlen(session.community);

  if ((sess = snmp_open(&session)) == NULL) {
    snmp_perror("snmp_open");
    exit(EXIT_FAILURE);
  }
}

/* cleanups session */
void snmp_free() {
  if (sess != NULL)
    snmp_close(sess);
  sess = NULL;
}

/* maximum number of interfaces to poll at once, min 1 */
#define MAXIFS 4

/* driver API */
struct ifstat_data *snmp_scan_interfaces() {
  struct ifstat_data *list = NULL;
  struct ifsnmp ifsnmp[MAXIFS];
  int ifs, index, i;
  
  if ((ifs = snmp_get_ifcount(sess)) <= 0)
    return NULL;

  for (index = 0; index <= (ifs / MAXIFS); index++) {
    int nifs = ifs - index * MAXIFS;
    if (nifs > MAXIFS)
      nifs = MAXIFS;

    if (snmp_get_ifinfos(sess, index * MAXIFS + 1, nifs, S_UP, ifsnmp) < 0)
      continue;
    for (i=0; i < MAXIFS; i++) {
      if (ifsnmp[i].flags & S_UP) {
	/* overwrite if name if needed */
	if (num_ifnames)
	  sprintf(ifsnmp[i].name, "if%d", index * MAXIFS + i);
	add_interface(&list, ifsnmp[i].name);
      }
    }
  }
  
  return list;
}

void snmp_get_stats(struct ifstat_data *list) {
  int ifs, index, i;
  struct ifstat_data *cur;
  struct ifsnmp ifsnmp[MAXIFS];

  if ((ifs = snmp_get_ifcount(sess)) <= 0)
    return;

  for (index = 0; index <= (ifs / MAXIFS); index++) {
    int nifs = ifs - index * MAXIFS;
    if (nifs > MAXIFS)
      nifs = MAXIFS;

    if (snmp_get_ifinfos(sess, index * MAXIFS + 1, nifs, S_BIN|S_BOUT, ifsnmp) < 0)
      continue;
    for (i=0; i < MAXIFS; i++) {
      if (ifsnmp[i].flags & S_BIN && ifsnmp[i].flags & S_BOUT) {
	/* overwrite if name if needed */
	if (num_ifnames)
	  sprintf(ifsnmp[i].name, "if%d", index * MAXIFS + i);
	if ((cur = get_interface(list, ifsnmp[i].name)) != NULL)
	  set_interface_stats(cur, ifsnmp[i].bin, ifsnmp[i].bout);
      }
    }
  }
}

#else
/* bogus API */

void snmp_init(char *string) {
  fprintf(stderr, "no SNMP support in this binary!\n");
  exit(EXIT_FAILURE);
}

struct ifstat_data *snmp_scan_interfaces() { return NULL; }
void snmp_get_stats(struct ifstat_data *ifs) {}
void snmp_free() {}
#endif
