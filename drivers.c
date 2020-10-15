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
 * $Id: drivers.c,v 1.38 2003/02/02 17:39:19 gael Exp $
 */

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif
#ifdef HAVE_SYS_TYPES_H
#include <sys/types.h>
#endif
#ifdef HAVE_SYS_PARAM_H
#include <sys/param.h>
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
#ifdef HAVE_NET_SOIOCTL_H
#include <net/soioctl.h>
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
#ifdef HAVE_NET_IF_TYPES_H
#include <net/if_types.h>
#endif
#ifdef HAVE_NET_IF_DL_H
#include <net/if_dl.h>
#endif
#ifdef HAVE_NET_ROUTE_H
#include <net/route.h>
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
#ifdef HAVE_ERRNO_H
#include <errno.h>
#endif
#ifdef HAVE_LIMITS_H
#include <limits.h>
#endif
#include <stdio.h>
#include <stdlib.h>
#include "ifstat.h"
#ifdef USE_SNMP  
#include "snmp.h"
#endif

#ifndef IFNAMSIZ
#define IFNAMSIZ 16
#endif

static void examine_interface(struct ifstat_list *ifs, char *name,
			      int ifflags, int iftype) {
#ifdef IFF_LOOPBACK
  if ((ifflags & IFF_LOOPBACK) && !(ifs->flags & IFSTAT_LOOPBACK))
    return;
#endif
#ifdef IFF_UP
  if (!(ifflags & IFF_UP) && !(ifs->flags & IFSTAT_DOWN))
    return;
#endif  
#ifdef IFT_PFLOG
  /* assume PFLOG interfaces are loopbacks (on OpenBSD) */
  if (iftype == IFT_PFLOG && !(ifs->flags & IFSTAT_LOOPBACK))
    return;
#endif
  ifstat_add_interface(ifs, name, 0);
}

#ifdef USE_IOCTL

#ifdef USE_IFNAMEINDEX
static int ioctl_map_ifs(int sd,
			 int (*mapf)(int sd, struct ifreq *ifr, void *data),
			 void *mdata) {
  struct if_nameindex *iflist, *cur;
  struct ifreq ifr;
  
  if ((iflist = if_nameindex()) == NULL) {
    ifstat_perror("if_nameindex");
    return 0;
  }

  for(cur = iflist; cur->if_index != 0 && cur->if_name != NULL; cur++) {
    memcpy(ifr.ifr_name, cur->if_name, sizeof(ifr.ifr_name));
    ifr.ifr_name[sizeof(ifr.ifr_name) - 1] = '\0';
    if (!mapf(sd, &ifr, mdata))
      return 0;
  }
  if_freenameindex(iflist);
  return 1;
}
#else
static int ioctl_map_ifs(int sd,
			 int (*mapf)(int sd, struct ifreq *ifr, void *data),
			 void *mdata) {
  struct ifconf ifc;
  struct ifreq *ifr;
  int len, n, res = 0;
  char *buf;

#ifdef SIOCGIFNUM
  if (ioctl(sd, SIOCGIFNUM, &n) < 0) {
    ifstat_perror("ioctl(SIOCGIFNUM):");
    goto end;
  }
  n += 2;
#else
  n = 256; /* bad bad bad... */
#endif

  len = n * sizeof(struct ifreq);
  if ((buf = malloc(len)) == NULL) {
    ifstat_perror("malloc");
    return 0;
  }

  ifc.ifc_buf = buf;
  ifc.ifc_len = len;
  if (ioctl(sd, SIOCGIFCONF, (char *)&ifc) < 0) {
    ifstat_perror("ioctl(SIOCGIFCONF):");
    goto end;
  }

  n = 0;
  while (n < ifc.ifc_len) {
    ifr = (struct ifreq *) (buf + n);
#ifdef HAVE_SOCKADDR_SA_LEN    
    n += sizeof(ifr->ifr_name) + ifr->ifr_addr.sa_len;
#else
    n += sizeof(struct ifreq);
#endif
    if (!mapf(sd, ifr, mdata))
      goto end;
  }
  res = 1;
  
 end:
  free(buf);
  return res;
}
#endif

static int ioctl_map_scan(int sd, struct ifreq *ifr, void *data) {
  
  if (ioctl(sd, SIOCGIFFLAGS, (char *)ifr) != 0)
    return 1;
  examine_interface((struct ifstat_list *) data, ifr->ifr_name,
		    ifr->ifr_flags, 0);
  return 1;
}

static int ioctl_scan_interfaces(struct ifstat_driver *driver,
				 struct ifstat_list *ifs) {
  int sd;

  if ((sd = socket(AF_INET, SOCK_DGRAM, 0)) < 0) {
    ifstat_perror("socket");
    return 0;
  }

  ioctl_map_ifs(sd, &ioctl_map_scan, (void *) ifs);
  close(sd);
  
  return 1;
} 
#endif

#ifdef USE_KSTAT
static int get_kstat_long(kstat_t *ksp, char *name, unsigned long *value) {
  kstat_named_t *data;

  if ((data = kstat_data_lookup(ksp, name)) == NULL)
    return 0;
  switch (data->data_type) {
#ifdef KSTAT_DATA_INT32
    /* solaris 2.6 and over */    
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
#else
  case KSTAT_DATA_LONGLONG:
    *value = data->value.ll;
    break;
  case KSTAT_DATA_ULONGLONG:
    *value = data->value.ull;
    break;
  case KSTAT_DATA_LONG:
    *value = data->value.l;
    break;
  case KSTAT_DATA_ULONG:
    *value = data->value.ul;
    break;
#endif    
  default:
    return 0;
  }
  return 1;
}

static int kstat_open_driver(struct ifstat_driver *driver,
			     char *options) {
  kstat_ctl_t *kc;
  
  if ((kc = kstat_open()) == NULL) {
    ifstat_perror("kstat_open");
    return 0;
  }

  driver->data = (void *) kc;
  return 1;
}

static int kstat_get_stats(struct ifstat_driver *driver,
			   struct ifstat_list *ifs) {
  unsigned long bytesin, bytesout;
  struct ifstat_data *cur;
  kstat_ctl_t *kc = driver->data;
  kstat_t *ksp;

  for (cur = ifs->first; cur != NULL; cur = cur->next) {
    if (cur->flags & IFSTAT_TOTAL)
      continue;
    if ((ksp = kstat_lookup(kc, NULL, -1, cur->name)) == NULL ||
	ksp->ks_type != KSTAT_TYPE_NAMED)
      continue;
    if (kstat_read(kc, ksp, 0) >= 0 &&
	get_kstat_long(ksp, "obytes", &bytesout) &&
	get_kstat_long(ksp, "rbytes", &bytesin))
      ifstat_set_interface_stats(cur, bytesin, bytesout);
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
  char errbuf[_POSIX2_LINE_MAX + 1];
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
    ifstat_perror("malloc");
    return 0;
  }
  data->errbuf[0] = '\0';

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

  if ((data->kvmfd = kvm_openfiles(files[0], files[1], files[2],
				   O_RDONLY, data->errbuf)) == NULL) {
    ifstat_error("kvm_openfiles: %s", data->errbuf);
    return 0;
  }

  if (kvm_nlist(data->kvmfd, kvm_syms) < 0) {
    ifstat_error("kvm_nlist(ifnetaddr): %s", data->errbuf);
    return 0;
  }

  if (kvm_read(data->kvmfd, (unsigned long) kvm_syms[0].n_value,
	       &ifnetaddr, sizeof(ifnetaddr)) < 0) {
    ifstat_error("kvm_read(ifnetaddr): %s", data->errbuf);
    return 0;
  }

  if (ifnetaddr == 0) {
    ifstat_error("kvm: ifnetaddr has null address.");
    return 0;
  }
  
  data->ifnetaddr = ifnetaddr;

  driver->data = (void *) data;
  return 1;
}

#ifndef TAILQ_NEXT
#define TAILQ_NEXT(elm, field)    ((elm)->field.tqe_next)
#endif
#ifdef HAVE_IFNET_IF_LINK
#define if_list if_link
#endif

static int kvm_map_ifs(struct ifstat_driver *driver,
		       int (*mapf)(char *name, struct ifnet *ifnet, void *data),
		       void *mdata) {
  struct kvm_driver_data *data = driver->data;
  unsigned long ifaddr;
  struct ifnet ifnet;
#ifndef HAVE_IFNET_IF_XNAME
  char ifname[IFNAMSIZ + 1];
#endif
  char interface[IFNAMSIZ + 10];

  for (ifaddr = data->ifnetaddr; ifaddr != 0;
       ifaddr = (unsigned long) TAILQ_NEXT(&ifnet, if_list)) {
    if (kvm_read(data->kvmfd, ifaddr, &ifnet, sizeof(ifnet)) < 0) {
      ifstat_error("kvm_read: %s", data->errbuf);
      return 0;
    }
#ifdef HAVE_IFNET_IF_XNAME
    memcpy(interface, ifnet.if_xname, sizeof(interface));
    interface[sizeof(interface) - 1] = '\0';
#else   
    if (kvm_read(data->kvmfd, (unsigned long) ifnet.if_name, &ifname, sizeof(ifname)) < 0) {
      ifstat_error("kvm_read: %s", data->errbuf);
      return 0;
    }
    ifname[sizeof(ifname) - 1] = '\0';
    sprintf(interface, "%s%d", ifname, ifnet.if_unit);
#endif

    if (!mapf(interface, &ifnet, mdata))
      return 0;
  }
  return 1;
}

static int kvm_map_stats(char *name, struct ifnet *ifnet, void *data) {
  struct ifstat_data *cur;
    
  if ((cur = ifstat_get_interface((struct ifstat_list *) data, name)) == NULL)
    return 1;
  ifstat_set_interface_stats(cur, ifnet->if_ibytes, ifnet->if_obytes);
  return 1;
}

static int kvm_get_stats(struct ifstat_driver *driver,
			 struct ifstat_list *ifs) {
  return kvm_map_ifs(driver, &kvm_map_stats, (void *) ifs);
}

static int kvm_map_scan(char *name, struct ifnet *ifnet, void *data) {
  examine_interface((struct ifstat_list *) data, name,
		    ifnet->if_flags, ifnet->if_type);
  return 1;
}

static int kvm_scan_interfaces(struct ifstat_driver *driver,
			       struct ifstat_list *ifs) {
  return kvm_map_ifs(driver, &kvm_map_scan, (void *) ifs);
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
    ifstat_perror("sysctl(net.link.generic.ifmib.ifcount)");
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

static int ifmib_scan_interfaces(struct ifstat_driver *driver,
				 struct ifstat_list *ifs) {
  int count, i;
  struct ifmibdata ifmd;
  
  if ((count = get_ifcount()) <= 0)
    return 0;

  for (i = 1; i <= count; i++) {
    if (!get_ifdata(i, &ifmd))
      continue;
    examine_interface(ifs, ifmd.ifmd_name, ifmd.ifmd_flags,
		      ifmd.ifmd_data.ifi_type);
  }
  return 1;
}

static int ifmib_get_stats(struct ifstat_driver *driver,
			   struct ifstat_list *ifs) {
  int count, i;
  struct ifmibdata ifmd;
  struct ifstat_data *cur;

  if (ifs->flags & IFSTAT_HASINDEX) { /* poll by index */
    for (cur = ifs->first; cur != NULL; cur = cur->next) {
      i = ifstat_get_interface_index(cur);
      if (i < 0 || !get_ifdata(i, &ifmd))
	continue;
      if (strcmp(ifstat_get_interface_name(cur), ifmd.ifmd_name))
	continue;
      ifstat_set_interface_stats(cur,
				 ifmd.ifmd_data.ifi_ibytes,
				 ifmd.ifmd_data.ifi_obytes);
      ifstat_set_interface_index(cur, i);
    }
    return 1;
  } 

  if ((count = get_ifcount()) <= 0)
    return 0;
  
  for (i = 1; i <= count; i++) {
    if (!get_ifdata(i, &ifmd))
      continue;
    if ((cur = ifstat_get_interface(ifs, ifmd.ifmd_name)) == NULL)
      continue;
    ifstat_set_interface_stats(cur,
			       ifmd.ifmd_data.ifi_ibytes,
			       ifmd.ifmd_data.ifi_obytes);
    ifstat_set_interface_index(cur, i);
  }
  return 1;
}
#endif

#ifdef USE_IFDATA
struct ifdata_driver_data {
  int sd;
#ifdef HAVE_IFREQ_IFR_DATA
  struct if_data ifd;
#else
  struct ifdatareq ifd;
#endif  
};

static int ifdata_open_driver(struct ifstat_driver *driver,
			      char *options) {
  struct ifdata_driver_data *data;

  if ((data = malloc(sizeof(struct ifdata_driver_data))) == NULL) {
    ifstat_perror("malloc");
    return 0;
  }

  if ((data->sd = socket(AF_INET, SOCK_DGRAM, 0)) < 0) {
    ifstat_perror("socket");
    free(data);
    return 0;
  }
  
  driver->data = (void *) data;
  return 1;
}

static struct if_data *ifdata_get_data(struct ifdata_driver_data *data,
				       char *name) {
#ifdef HAVE_IFREQ_IFR_DATA  
  struct ifreq ifr;
  
  strncpy(ifr.ifr_name, name, sizeof(ifr.ifr_name));
  ifr.ifr_data = (caddr_t) &(data->ifd);
  if (ioctl(data->sd, SIOCGIFDATA, (char *) &ifr) < 0)
    return NULL;
  return &(data->ifd);
#else
  strncpy(data->ifd.ifd_name, name, sizeof(data->ifd.ifd_name));
  if (ioctl(data->sd, SIOCGIFDATA, (char *) &(data->ifd)) < 0)
    return NULL;
  return &(data->ifd.ifd_ifd);
#endif
}

struct ifdata_scan_data {
  struct ifstat_list *ifs;
  struct ifdata_driver_data *data;
};

static int ifdata_map_scan(int sd, struct ifreq *ifr, void *pdata) {
  struct ifdata_scan_data *sdata = pdata;
  struct if_data *ifd;
  
  if (ioctl(sd, SIOCGIFFLAGS, (char *)ifr) != 0)
    return 1;
  if ((ifd = ifdata_get_data(sdata->data, ifr->ifr_name)) == NULL)
    return 1;
  examine_interface(sdata->ifs, ifr->ifr_name,
		    ifr->ifr_flags, ifd->ifi_type);
  return 1;
}

static int ifdata_scan_interfaces(struct ifstat_driver *driver,
				  struct ifstat_list *ifs) {
  struct ifdata_driver_data *data = driver->data;
  struct ifdata_scan_data sdata = { ifs, data };

  return ioctl_map_ifs(data->sd, &ifdata_map_scan, &sdata);
} 

static int ifdata_get_stats(struct ifstat_driver *driver,
			    struct ifstat_list *ifs) {
  struct ifdata_driver_data *data = driver->data;
  struct if_data *ifd;
  struct ifstat_data *cur;
  
  for (cur = ifs->first; cur != NULL; cur = cur->next) {
    if (cur->flags & IFSTAT_TOTAL)
      continue;
    if ((ifd = ifdata_get_data(data, cur->name)) != NULL)
      ifstat_set_interface_stats(cur, ifd->ifi_ibytes, ifd->ifi_obytes);
  }
  return 1;
}

static void ifdata_close_driver(struct ifstat_driver *driver) {
  struct ifdata_driver_data *data = driver->data;

  if (data->sd >= 0)
    close(data->sd);
  free(data);
}
#endif

#ifdef USE_PROC
struct proc_driver_data {
  char *file;
  int checked;
};

static int proc_open_driver(struct ifstat_driver *driver,
			    char *options) {
  struct proc_driver_data *data;

  if ((data = malloc(sizeof(struct proc_driver_data))) == NULL) {
    ifstat_perror("malloc");
    return 0;
  }

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
			  struct ifstat_list *ifs) {
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
    file = PROC_FILE;

  if ((f = fopen(file, "r")) == NULL) {
    ifstat_error("can't open %s: %s", file, strerror(errno));
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
    
    if ((cur = ifstat_get_interface(ifs, iface)) != NULL)
      ifstat_set_interface_stats(cur, bytesin, bytesout);
  }
  fclose(f);
  return 1;

 badproc:
  fclose(f);
  ifstat_error("%s: unsupported format.", file);
  return 0;
}
#endif

#ifdef USE_ROUTE
struct route_driver_data {
  char *buf;
  size_t size;
};

#define DEFAULT_SIZE 16384

static int route_open_driver(struct ifstat_driver *driver,
			      char *options) {
  struct route_driver_data *data;

  if ((data = malloc(sizeof(struct route_driver_data))) == NULL) {
    ifstat_perror("malloc");
    return 0;
  }

  if ((data->buf = malloc(DEFAULT_SIZE)) < 0) {
    ifstat_perror("malloc");
    free(data);
    return 0;
  }
  data->size = DEFAULT_SIZE;

  driver->data = (void *) data;
  return 1;
}

static int route_map_ifs(struct ifstat_driver *driver,
		       int (*mapf)(char *name, struct if_msghdr *ifmsg, void *data),
		       void *mdata) {
  struct route_driver_data *data = driver->data;
  int iflist[] = {
    CTL_NET, PF_ROUTE, 0, AF_LINK, NET_RT_IFLIST, 0 
  };
  struct if_msghdr *ifm;
  struct sockaddr_dl *dl;
  char *ptr;
  char ifname[IFNAMSIZ + 1];
  size_t len;

  if (data->size != 0) { /* try with current buf size */
    len = data->size;
    if (sysctl(iflist, sizeof(iflist) / sizeof(int),
	       data->buf, &len, NULL, 0) < 0) {
      if (errno != ENOMEM) {
	ifstat_perror("sysctl");
	return 0;
      }
      /* buffer too small */
      free (data->buf);
      data->size = 0;
    }
  } 
  if (data->size == 0) {
    /* ask for size */
    if (sysctl(iflist, sizeof(iflist) / sizeof(int),
	       NULL, &len, NULL, 0) < 0) {
      ifstat_perror("sysctl");
      return 0;
    }
    if ((data->buf = malloc(len)) < 0) {
      ifstat_perror("malloc");
      return 0;
    }
    if (sysctl(iflist, sizeof(iflist) / sizeof(int),
	       data->buf, &len, NULL, 0) < 0) {
      ifstat_perror("sysctl");
      return 0;
    }
  }

  /* browse interfaes */
  for (ptr = data->buf; ptr < data->buf + len; ptr += ifm->ifm_msglen) {
    ifm = (struct if_msghdr *) ptr;
    if (ifm->ifm_type != RTM_IFINFO)
      continue;
    if (ifm->ifm_msglen <= sizeof(struct if_msghdr)) /* no address */
      continue;
    dl = (struct sockaddr_dl *) (ptr + sizeof(struct if_msghdr));
    if (dl->sdl_family != AF_LINK)
      continue;
    if (dl->sdl_nlen > (sizeof(ifname) - 1))
      dl->sdl_nlen = sizeof(ifname) - 1;
    memcpy(ifname, dl->sdl_data, dl->sdl_nlen);
    ifname[dl->sdl_nlen] = '\0';

    if (!mapf(ifname, ifm, mdata))
      return 0;
  }
  return 1;
}

static int route_map_stats(char *name, struct if_msghdr *ifmsg, void *data) {
  struct ifstat_data *cur;
  
  if ((cur = ifstat_get_interface((struct ifstat_list *) data, name)) == NULL)
    return 1;
  ifstat_set_interface_stats(cur, ifmsg->ifm_data.ifi_ibytes,
			     ifmsg->ifm_data.ifi_obytes);
  return 1;
}

static int route_get_stats(struct ifstat_driver *driver,
			   struct ifstat_list *ifs) {
  return route_map_ifs(driver, &route_map_stats, ifs);
}

static int route_map_scan(char *name, struct if_msghdr *ifmsg, void *data) {
  examine_interface((struct ifstat_list *) data, name,
		    ifmsg->ifm_flags, ifmsg->ifm_data.ifi_type);
  return 1;
}

static int route_scan_interfaces(struct ifstat_driver *driver,
				 struct ifstat_list *ifs) {
  return route_map_ifs(driver, &route_map_scan, (void *) ifs);
} 

static void route_close_driver(struct ifstat_driver *driver) {
  struct route_driver_data *data = driver->data;

  if (data->buf != NULL)
    free(data->buf);
  free(data);
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
#ifdef USE_IFDATA
  { "ifdata", &ifdata_open_driver, &ifdata_scan_interfaces,
    &ifdata_get_stats, &ifdata_close_driver },
#endif
#ifdef USE_ROUTE
  { "route", &route_open_driver, &route_scan_interfaces,
    &route_get_stats, &route_close_driver },
#endif  
#ifdef USE_KVM  
  { "kvm",  &kvm_open_driver, &kvm_scan_interfaces, &kvm_get_stats,
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
  
int ifstat_get_driver(char *name, struct ifstat_driver *driver) {
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

char* ifstat_list_drivers() {
  int num;
  int len = 0, pos = 0;
  char *res;
  
  for(num = 0; drivers[num].name != NULL; num++)
    len += strlen(drivers[num].name) + 2;

  if ((res = malloc(len + 1)) == NULL) {
    ifstat_perror("malloc");
    return NULL;
  }

  for(num = 0; drivers[num].name != NULL; num++) {
    if (num != 0) {
      memcpy(res + pos, ", ", 2);
      pos += 2;
    }
    len = strlen(drivers[num].name);
    memcpy(res + pos, drivers[num].name, len);
    pos += len;
  }
  res[pos] = '\0';
  return res;
}
