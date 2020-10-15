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
 * $Id: drivers.c,v 1.16 2002/01/14 23:36:09 gael Exp $
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
static int get_kstat_long(kstat_t *ksp, char *name, unsigned long *value) {
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

static int kstat_open_driver(struct ifstat_driver *driver,
			     char *options) {
  kstat_ctl_t *kc;
  
  if ((kc = kstat_open()) == NULL) {
    perror("kstat_open");
    return 0;
  }

  driver->data = (void *) kc;
  return 1;
}

static int kstat_get_stats(struct ifstat_driver *driver,
			    struct ifstat_data *list) {
  unsigned long bytesin, bytesout;
  struct ifstat_data *cur;
  kstat_ctl_t *kc = driver->data;
  kstat_t *ksp;

  for (cur = list; cur != NULL; cur = cur->next) {
    if ((ksp = kstat_lookup(kc, NULL, -1, cur->name)) == NULL ||
	ksp->ks_type != KSTAT_TYPE_NAMED)
      continue;
    if (kstat_read(kc, ksp, 0) >= 0 &&
	get_kstat_long(ksp, "obytes", &bytesout) &&
	get_kstat_long(ksp, "rbytes", &bytesin))
      set_interface_stats(cur, bytesin, bytesout);
  }
  return 1;
}

static void kstat_close_driver(struct ifstat_driver *driver) {
  kstat_close(((kstat_ctl_t *) driver->data));
}
#endif

#ifdef USE_KVM
struct kvm_driver_data {
  kvm_t *kvmfd;
  unsigned long ifnetaddr;
};

static int kvm_open_driver(struct ifstat_driver *driver,
			   char *options) {
  struct kvm_driver_data *data;
  struct nlist kvm_syms[] = { { "_ifnet" }, { NULL } };
  unsigned long ifnetaddr;
  char *files[3] = { NULL /* execfile */,
		     NULL /* corefile */,
		     NULL /* swapfile */ };
  int i;
  
  if ((data = malloc(sizeof(struct kvm_driver_data))) == NULL) {
    perror("malloc");
    return 0;
  }

  /* cut options : [execfile][,[corefile][,[swapfile]]] */
  i = 0;
  while (options != NULL && i < 3) {
    char *v = strchr(options, ',');

    if (v != NULL)
      *v++ = '\0';
    if (*options != '\0')
      files[i] = options;
    i++;
    options = v;
  }

  if ((data->kvmfd = kvm_open(files[0], files[1], files[2], O_RDONLY, progname)) == NULL)
    return 0;

  if (kvm_nlist(data->kvmfd, kvm_syms) < 0 ||
      kvm_read(data->kvmfd, (unsigned long) kvm_syms[0].n_value,
	       &ifnetaddr, sizeof(ifnetaddr)) < 0 ||
      ifnetaddr == 0)
    return 0;
  data->ifnetaddr = ifnetaddr;

  driver->data = (void *) data;
  return 1;
}

static int kvm_get_stats(struct ifstat_driver *driver,
			  struct ifstat_data *list) {
  struct kvm_driver_data *data = driver->data;
  unsigned long ifaddr;
  struct ifnet ifnet;
  char ifname[16], interface[32];
  struct ifstat_data *cur;
  
  for (ifaddr = data->ifnetaddr; ifaddr != 0;
       ifaddr = (unsigned long) ifnet.if_list.tqe_next) {
    if (kvm_read(data->kvmfd, ifaddr, &ifnet, sizeof(ifnet)) < 0)
      return 0;
#ifdef HAVE_IFNET_IF_XNAME
    memcpy(interface, ifnet.if_xname, sizeof(interface));
    interface[sizeof(interface) - 1] = '\0';
#else   
    if (kvm_read(data->kvmfd, (unsigned long) ifnet.if_name, &ifname, sizeof(ifname)) < 0)
      return 0;
    ifname[sizeof(ifname) - 1] = '\0';
    sprintf(interface, "%s%d", ifname, ifnet.if_unit);
#endif    
    
    if ((cur = get_interface(list, interface)) == NULL)
      continue;
    set_interface_stats(cur, ifnet.if_ibytes, ifnet.if_obytes);
  }
  return 1;
}

static void kvm_close_driver(struct ifstat_driver *driver) {
  kvm_close(((struct kvm_driver_data *) driver->data)->kvmfd);
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
    return 0;

  return 1;
}

struct ifstat_data *ifmib_scan_interfaces(struct ifstat_driver *driver,
					  int flags) {
  int count, i;
  struct ifmibdata ifmd;
  struct ifstat_data *list = NULL;
  
  if ((count = get_ifcount()) <= 0)
    return NULL;

  for (i = 1; i <= count; i++) {
    if (!get_ifdata(i, &ifmd))
      continue;
    if ((ifmd.ifmd_flags & IFF_LOOPBACK) &&
	!(flags & IFSTAT_LOOPBACK))
      continue;
    if ((ifmd.ifmd_flags & IFF_UP) ||
	(flags & IFSTAT_DOWN))
      add_interface(&list, ifmd.ifmd_name);
  }
  return list;
}

static int ifmib_get_stats(struct ifstat_driver *driver,
			   struct ifstat_data *list) {
  int count, i;
  struct ifmibdata ifmd;
  struct ifstat_data *cur;
  
  if ((count = get_ifcount()) <= 0)
    return 0;

  for (i = 1; i <= count; i++) {
    if (!get_ifdata(i, &ifmd))
      continue;
    if ((cur = get_interface(list, ifmd.ifmd_name)) == NULL)
      continue;
    set_interface_stats(cur,
			ifmd.ifmd_data.ifi_ibytes,
			ifmd.ifmd_data.ifi_obytes);
  }
  return 1;
}
#endif

#ifdef USE_IOCTL
static void ioctl_add_interface(struct ifstat_data **list, int sd,
				struct ifreq * ifr, int flags) {
  if (ioctl(sd, SIOCGIFFLAGS, (char *)ifr) != 0)
    return;
  if ((ifr->ifr_flags & IFF_LOOPBACK) &&
      !(flags & IFSTAT_LOOPBACK))
    return;
  if ((ifr->ifr_flags & IFF_UP) ||
      (flags & IFSTAT_DOWN))
    add_interface(list, ifr->ifr_name);
}

#ifdef USE_IFNAMEINDEX
static struct ifstat_data *ioctl_scan_interfaces(struct ifstat_driver *driver,
						 int flags) {
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
    ioctl_add_interface(&list, sd, &ifr, flags);
  }
  if_freenameindex(iflist);

 endsd:
  close(sd);
 end:
  return list;
}
#else
static struct ifstat_data *ioctl_scan_interfaces(struct ifstat_driver *driver,
						 int flags) {
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
    ioctl_add_interface(&list, sd, ifr, flags);
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
struct proc_driver_data {
  char *file;
  int checked;
};

static int proc_open_driver(struct ifstat_driver *driver,
			    char *options) {
  struct proc_driver_data *data;

  if ((data = malloc(sizeof(struct proc_driver_data))) == NULL)
    return 0;

  data->file = (options != NULL) ? strdup(options) : NULL;
  data->checked = 0;
  driver->data = (void *) data;

  return 1;
}

static void proc_close_driver(struct ifstat_driver *driver) {
  struct proc_driver_data *data = driver->data;

  if (data->file != NULL)
    free(data->file);
  free(data);
}

static int proc_get_stats(struct ifstat_driver *driver,
			  struct ifstat_data *list) {
  char buf[1024];
  FILE *f;
  char *iface, *stats;
  unsigned long bytesin, bytesout;
  struct ifstat_data *cur;
  struct proc_driver_data *data = driver->data;
  char *file;

  if (data->file != NULL)
    file = data->file;
  else
    file = "/proc/net/dev";

  if ((f = fopen(file, "r")) == NULL) {
    fprintf(stderr, "%s: can't open %s: ", progname, file);
    perror("fopen");
    return 0;
  }
  
  /* check first lines */
  if (fgets(buf, sizeof(buf), f) == NULL)
    goto badproc;
  if (!data->checked && strncmp(buf, "Inter-|", 7))
    goto badproc;
  if (fgets(buf, sizeof(buf), f) == NULL)
    goto badproc;
  if (!data->checked) {
    if (strncmp(buf, " face |by", 9))
      goto badproc;
    data->checked = 1;
  }

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
  return 1;

 badproc:
  fclose(f);
  fprintf(stderr, "%s: %s: unsupported format.\n", progname, file);
  return 0;
}
#endif

static struct ifstat_driver drivers[] = {
#ifdef USE_KSTAT  
  { "kstat", &kstat_open_driver, &ioctl_scan_interfaces, &kstat_get_stats,
    &kstat_close_driver },
#endif
#ifdef USE_IFMIB  
  { "ifmib", NULL, &ifmib_scan_interfaces, &ifmib_get_stats, NULL },
#endif
#ifdef USE_KVM  
  { "kvm",  &kvm_open_driver, &ioctl_scan_interfaces, &kvm_get_stats,
    &kvm_close_driver },
#endif
#ifdef USE_PROC  
  { "proc", &proc_open_driver, &ioctl_scan_interfaces, &proc_get_stats,
    &proc_close_driver },
#endif
#ifdef USE_SNMP  
  { "snmp", &snmp_open_driver, &snmp_scan_interfaces, &snmp_get_stats,
    &snmp_close_driver },
#endif  
  { NULL } };
  
int get_driver(char *name, struct ifstat_driver *driver) {
  int num = 0;
  
  if (name != NULL) 
    for (num = 0; drivers[num].name != NULL; num++)
      if (!strcasecmp(drivers[num].name, name))
	break;

  if (drivers[num].name == NULL)
    return 0;

  memcpy(driver, &(drivers[num]), sizeof(struct ifstat_driver));
  driver->data = NULL;
  return 1;
}

void print_drivers(FILE *dev) {
  int num;

  for(num = 0; drivers[num].name != NULL; num++) {
    if (num != 0)
      fprintf(dev, ", %s", drivers[num].name);
    else
      fprintf(dev, "%s", drivers[num].name);
  }
}
