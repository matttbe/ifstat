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
 * $Id: drivers.c,v 1.9 2001/12/18 05:07:29 gael Exp $
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
#ifdef HAVE_SYS_SOCKET_H
#include <sys/socket.h>
#endif
#ifdef HAVE_SYS_SOCKIO_H
#include <sys/sockio.h>
#endif
#ifdef HAVE_SYS_IOCTL_H
#include <sys/ioctl.h>
#endif
#ifdef HAVE_NET_IF_H
#include <net/if.h>
#endif
#ifdef HAVE_SYS_SYSCTL_H
#include <sys/sysctl.h>
#endif
#ifdef HAVE_NET_IF_MIB_H
#include <net/if_mib.h>
#endif
#ifdef HAVE_NET_IF_VAR_H
#include <net/if_var.h>
#endif
#ifdef HAVE_KSTAT_H
#include <kstat.h>
#endif
#ifdef HAVE_FCNTL_H
#include <fcntl.h>
#endif
#ifdef HAVE_KVM_H
#include <kvm.h>
#endif
#include <stdio.h>
#include <stdlib.h>
#include "ifstat.h"

#ifdef USE_KSTAT
int get_kstat_long(kstat_t *ksp, char *name, unsigned long *value) {
  kstat_named_t *data;

  if ((data = kstat_data_lookup(ksp, name)) == NULL)
    return 0;
  switch (data->data_type) {
  case KSTAT_DATA_INT32:
    *value = data->value.i32;
    break;
  case KSTAT_DATA_INT64:
    *value = data->value.i64;
    break;
  case KSTAT_DATA_UINT32:
    *value = data->value.ui32;
    break;
  case KSTAT_DATA_UINT64:
    *value = data->value.ui64;
    break;
  default:
    return 0;
  }
  return 1;
}

void get_stats(struct ifstat_data *list) {
  unsigned long bytesin, bytesout;
  struct ifstat_data *cur;
  static kstat_ctl_t *kc = NULL;
  kstat_t *ksp;

  if (kc == NULL && (kc = kstat_open()) == NULL) {
    perror("kstat_open");
    exit(EXIT_FAILURE);
  }
  
  for (cur = list; cur != NULL; cur = cur->next) {
    if ((ksp = kstat_lookup(kc, NULL, -1, cur->name)) == NULL ||
	ksp->ks_type != KSTAT_TYPE_NAMED)
      continue;
    if (kstat_read(kc, ksp, 0) >= 0 &&
	get_kstat_long(ksp, "obytes", &bytesout) &&
	get_kstat_long(ksp, "rbytes", &bytesin))
      set_interface_stats(cur, bytesin, bytesout);
  }
}
#endif

#ifdef USE_KVM
void get_stats(struct ifstat_data *list) {
  static kvm_t *kvmfd = NULL;
  static unsigned long ifnetaddr = 0, ifaddr;
  struct ifnet ifnet;
  char ifname[16], interface[32];
  struct nlist kvm_syms[] = { { "_ifnet" }, { NULL } };
  struct ifstat_data *cur;
  
  if (kvmfd == NULL &&
      (kvmfd = kvm_open(NULL, NULL, NULL, O_RDONLY, "ifstat")) == NULL)
    exit(EXIT_FAILURE);

  if (ifnetaddr == 0) {
    if (kvm_nlist(kvmfd, kvm_syms) < 0 ||
	kvm_read(kvmfd, (unsigned long) kvm_syms[0].n_value,
		 &ifnetaddr, sizeof(ifnetaddr)) < 0 ||
	ifnetaddr == 0)
      exit(EXIT_FAILURE);
  }

  for (ifaddr = ifnetaddr; ifaddr != 0;
       ifaddr = (unsigned long) ifnet.if_list.tqe_next) {
    if (kvm_read(kvmfd, ifaddr, &ifnet, sizeof(ifnet)) < 0)
      exit(EXIT_FAILURE);
#ifdef HAVE_IFNET_IF_XNAME
    memcpy(interface, ifnet.if_xname, sizeof(interface));
    interface[sizeof(interface) - 1] = '\0';
#else   
    if (kvm_read(kvmfd, (unsigned long) ifnet.if_name, &ifname, sizeof(ifname)) < 0)
      exit(EXIT_FAILURE);
    ifname[sizeof(ifname) - 1] = '\0';
    sprintf(interface, "%s%d", ifname, ifnet.if_unit);
#endif    
    
    if ((cur = get_interface(list, interface)) == NULL)
      continue;
    set_interface_stats(cur, ifnet.if_ibytes, ifnet.if_obytes);
  }
}
#endif

#ifdef USE_IFMIB
static int get_ifcount() {
  int ifcount[] = {
    CTL_NET, PF_LINK, NETLINK_GENERIC, IFMIB_SYSTEM, IFMIB_IFCOUNT
  };
  int count, size;
  
  size = sizeof(count);
  if (sysctl(ifcount, sizeof(ifcount) / sizeof(int), &count, &size, NULL, 0) < 0) {
    perror("sysctl(net.link.generic.ifmib.ifcount)");
    return -1;
  }
  return count;
}

static int get_ifdata(int index, struct ifmibdata * ifmd) {
  int ifinfo[] = {
    CTL_NET, PF_LINK, NETLINK_GENERIC, IFMIB_IFDATA, index, IFDATA_GENERAL
  };
  int size = sizeof(*ifmd);

  if (sysctl(ifinfo, sizeof(ifinfo) / sizeof(int), ifmd, &size, NULL, 0) < 0)
    return -1;

  return 0;
}

struct ifstat_data *scan_interfaces() {
  int count, i;
  struct ifmibdata ifmd;
  struct ifstat_data *list = NULL;

  if ((count = get_ifcount()) <= 0)
    return NULL;

  for (i = 1; i <= count; i++) {
    if (get_ifdata(i, &ifmd) < 0)
      continue;
    if (ifmd.ifmd_flags & IFF_UP)
      add_interface(&list, ifmd.ifmd_name);
  }
  return list;
}

void get_stats(struct ifstat_data *list) {
  int count, i;
  struct ifmibdata ifmd;
  struct ifstat_data *cur;
  
  if ((count = get_ifcount()) <= 0)
    return;

  for (i = 1; i <= count; i++) {
    if (get_ifdata(i, &ifmd) < 0)
      continue;
    if ((cur = get_interface(list, ifmd.ifmd_name)) == NULL)
      continue;
    set_interface_stats(cur,
			ifmd.ifmd_data.ifi_ibytes,
			ifmd.ifmd_data.ifi_obytes);
  }
}
#endif

#ifdef USE_IOCTL
#ifdef USE_IFNAMEINDEX
struct ifstat_data *scan_interfaces() {
  struct ifreq ifr;
  struct if_nameindex *iflist, *cur;
  struct ifstat_data *list = NULL;
  int sd;

  if ((sd = socket(AF_INET, SOCK_DGRAM, 0)) < 0) {
    perror("socket");
    goto end;
  }

  if ((iflist = if_nameindex()) == NULL) {
    perror("if_nameindex");
    goto endsd;
  }

  for(cur = iflist; cur->if_index != 0 && cur->if_name != NULL; cur++) {
    memcpy(ifr.ifr_name, cur->if_name, sizeof(ifr.ifr_name));
    ifr.ifr_name[sizeof(ifr.ifr_name) - 1] = '\0';
    if (ioctl(sd, SIOCGIFFLAGS, (char *)&ifr) == 0 &&
	ifr.ifr_flags & IFF_UP)
      add_interface(&list, ifr.ifr_name);
  }
  if_freenameindex(iflist);

 endsd:
  close(sd);
 end:
  return list;
}
#else
struct ifstat_data *scan_interfaces() {
  struct ifconf ifc;
  struct ifreq *ifr;
  struct ifstat_data *list = NULL;
  int sd, len, n;
  char *buf;

  if ((sd = socket(AF_INET, SOCK_DGRAM, 0)) < 0) {
    perror("socket");
    goto end;
  }

#ifdef SIOCGIFNUM
  if (ioctl(sd, SIOCGIFNUM, &n) < 0) {
    perror("ioctl(SIOCGIFNUM):");
    goto endsd;
  }
  n += 2;
#else
  n = 256; /* bad bad bad... */
#endif

  len = n * sizeof(struct ifreq);
  if ((buf = malloc(len)) == NULL) {
    perror("malloc");
    goto endsd;
  }

  ifc.ifc_buf = buf;
  ifc.ifc_len = len;
  if (ioctl(sd, SIOCGIFCONF, (char *)&ifc) < 0) {
    perror("ioctl(SIOCGIFCONF):");
    goto endbuf;
  }

  n = 0;
  while (n < ifc.ifc_len) {
    ifr = (struct ifreq *) (buf + n);
#ifdef HAVE_SOCKADDR_SA_LEN    
    n += sizeof(ifr->ifr_name) + ifr->ifr_addr.sa_len;
#else
    n += sizeof(struct ifreq);
#endif    
    if (ioctl(sd, SIOCGIFFLAGS, (char *)ifr) == 0 &&
	ifr->ifr_flags & IFF_UP)
      add_interface(&list, ifr->ifr_name);
  }

 endbuf:
  free(buf);
 endsd:
  close(sd);
 end:
  return list;
}
#endif
#endif

#ifdef USE_PROC
void get_stats(struct ifstat_data *list) {
  char buf[1024];
  FILE *f;
  char *iface, *stats;
  unsigned long bytesin, bytesout;
  struct ifstat_data *cur;
  static int checked;

  if ((f = fopen("/proc/net/dev", "r")) == NULL) {
    fprintf(stderr, "can't open /proc/net/dev: ");
    perror("fopen");
    exit(EXIT_FAILURE);
  }
  
  /* check first lines */
  if (fgets(buf, sizeof(buf), f) == NULL)
    goto badproc;
  if (!checked && strncmp(buf, "Inter-|", 7))
    goto badproc;
  if (fgets(buf, sizeof(buf), f) == NULL)
    goto badproc;
  if (!checked && strncmp(buf, " face |by", 9))
    goto badproc;
  else
    checked = 1;

  while (fgets(buf, sizeof(buf), f) != NULL) {
    if ((stats = strchr(buf, ':')) == NULL)
      continue;
    *stats++ = '\0';
    iface = buf;
    while (*iface == ' ')
      iface++;
    if (*iface == '\0')
      continue;
    if (sscanf(stats, "%lu %*u %*u %*u %*u %*u %*u %*u %lu %*u", &bytesin, &bytesout) != 2)
      continue;
    
    if ((cur = get_interface(list, iface)) != NULL)
      set_interface_stats(cur, bytesin, bytesout);
  }
  fclose(f);
  return;

 badproc:
  fprintf(stderr, "unsupported /proc/net/dev format.\n");
  exit(EXIT_FAILURE);
}
#endif

#ifdef USE_SNMP
/* simple local SNMP driver for unsupported OS where we have a snmpd */

static void _checkinit() {
  static int snmp_initialised = 0;

  if (!snmp_initialised) {
    snmp_init("localhost");
    snmp_initialised = 1;
  }
}    

struct ifstat_data *scan_interfaces() {
  _checkinit();
  return snmp_scan_interfaces();
}


void get_stats(struct ifstat_data *ifs) {
  _checkinit();
  snmp_get_stats(ifs);
}
#endif
