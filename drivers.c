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
 * $Id: drivers.c,v 1.45 2003/11/22 01:27:51 gael Exp $
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
#ifdef HAVE_SYS_MBUF_H
#include <sys/mbuf.h>
#endif
#ifdef HAVE_NET_ROUTE_H
#include <net/route.h>
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
#ifdef HAVE_SYS_DLPI_H
#include <sys/dlpi.h>
#endif
#ifdef HAVE_SYS_DLPI_EXT_H
#include <sys/dlpi_ext.h>
#endif
#ifdef HAVE_STROPTS_H
#include <stropts.h>
#endif
#ifdef HAVE_SYS_MIB_H
#include <sys/mib.h>
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
#ifdef HAVE_NLIST_H
#include <nlist.h>
#endif
#ifdef HAVE_PATHS_H
#include <paths.h>
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

#ifdef USE_WIN32
#include <windows.h>
#include <iphlpapi.h>
#ifndef IFF_UP
#define IFF_UP       1
#endif
#ifndef IFF_LOOPBACK
#define IFF_LOOPBACK 2
#endif
#endif

static void examine_interface(struct ifstat_list *ifs, char *name,
			      int ifflags, int iftype) {
  (void)iftype;
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
  (void)driver;

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
static int get_kstat_long(kstat_t *ksp, char *name, unsigned long long *value) {
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
  case KSTAT_DATA_LONG LONGLONG:
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
  unsigned long long bytesin, bytesout;
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
#ifndef HAVE_KVM
/* use internal emulation using open/read/nlist */
#ifndef _POSIX2_LINE_MAX
#define _POSIX2_LINE_MAX 2048
#endif

#ifndef _PATH_KMEM
#define _PATH_KMEM "/dev/kmem"
#endif

#ifndef _PATH_UNIX
#define _PATH_UNIX "/vmunix"
#endif

typedef struct _kvm_t {
  int fd;
  char *errbuf;
  char *execfile;
} kvm_t;

static void _kvm_error(char *errbuf, char *message) {
  strncpy(errbuf, message ? message : strerror(errno),
	  _POSIX2_LINE_MAX - 1);
  errbuf[_POSIX2_LINE_MAX - 1] = '\0';
}

static kvm_t *kvm_openfiles(const char *execfile, const char *corefile,
			    const char *swapfile, int flags, char *errbuf) {
  kvm_t *kd;

  if (swapfile != NULL) {
    _kvm_error(errbuf, "swap file option not supported");
    return NULL;
  }
  
  if ((kd = malloc(sizeof(kvm_t))) == NULL) {
    _kvm_error(errbuf, NULL);
    return NULL;
  }

  if ((kd->fd = open(corefile ? corefile : _PATH_KMEM, flags)) < 0) {
    _kvm_error(errbuf, NULL);
    free(kd);
    return NULL;
  }
  kd->execfile = execfile ? strdup(execfile) : NULL;
  kd->errbuf = errbuf;
  return kd;
}

static int kvm_nlist (kvm_t *kd, struct nlist *nl) {
  int count;
  
#ifdef HAVE_KNLIST
  if (kd->execfile == NULL) {
#ifdef HAVE_KNLIST_ARGS3 
    for(count = 0; nl[count].n_name != NULL; count++);
    count = knlist(nl, count, sizeof(struct nlist));
#else
    count = knlist(nl);
#endif
    if (count < 0)
      _kvm_error(kd->errbuf, "error looking up symbol in live kernel");
    return count;
  }
#endif  
  if ((count = nlist(kd->execfile ? kd->execfile : _PATH_UNIX, nl)) < 0)
    _kvm_error(kd->errbuf, "error looking up symbol in kernel file");
  return count;
}

#ifdef HAVE_READX
#define KOFFSET(x) ((x) & 0x7FFFFFFF)
#define KREAD(fd, buf, size, addr) readx((fd), (buf), (size), ((off_t) (addr)) < 0 ? 1 : 0)
#else
#define KOFFSET(x) (x)
#define KREAD(fd, buf, size, addr) read((fd), (buf), (size))
#endif

static ssize_t kvm_read(kvm_t *kd, unsigned long addr, void *buf, size_t nbytes) {
  ssize_t len;

  if (lseek(kd->fd, KOFFSET(addr), SEEK_SET) == -1) {
    _kvm_error(kd->errbuf, NULL);
    return -1;
  }
  if ((len = KREAD(kd->fd, buf, nbytes, addr)) < 0) {
    _kvm_error(kd->errbuf, NULL);
    return -1;
  }
  return len;
}

static int kvm_close(kvm_t *kd) {
  close(kd->fd);
  free(kd->execfile);
  free(kd);
  return 0;
}
#endif

struct kvm_driver_data {
  kvm_t *kvmfd;
  unsigned long ifnetaddr;
  char errbuf[_POSIX2_LINE_MAX + 1];
};

static int kvm_open_driver(struct ifstat_driver *driver,
			   char *options) {
  struct kvm_driver_data *data;
  struct nlist kvm_syms[2];
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

  memset(&kvm_syms, 0, sizeof(kvm_syms));
  kvm_syms[0].n_name = "_ifnet";
  if (kvm_nlist(data->kvmfd, kvm_syms) < 0 ||
      kvm_syms[0].n_value == 0) {
    kvm_syms[0].n_name = "ifnet";
    if (kvm_nlist(data->kvmfd, kvm_syms) < 0) {
      ifstat_error("kvm_nlist: %s", data->errbuf);
      return 0;
    }
  }
  
  if (kvm_syms[0].n_value == 0) {
    ifstat_error("kvm: no _ifnet or ifnet symbol found");
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

#ifdef HAVE_IFNET_IF_NEXT
#define IFNET_NEXT(ifnet) (ifnet).if_next
#else
#ifdef HAVE_IFNET_IF_LINK
#define if_list if_link
#endif
#ifndef TAILQ_NEXT
#define TAILQ_NEXT(elm, field)    ((elm)->field.tqe_next)
#endif
#define IFNET_NEXT(ifnet) TAILQ_NEXT((&ifnet), if_list)
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
       ifaddr = (unsigned long) IFNET_NEXT(ifnet)) {
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
  unsigned long long bytesin, bytesout;
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
    if (sscanf(stats, "%llu %*u %*u %*u %*u %*u %*u %*u %llu %*u", &bytesin, &bytesout) != 2)
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

#ifdef USE_DLPI

#define DLPI_DEFBUF_LEN 1024
#define DLPI_NO_PPA -1
#define DLPI_DEVICE "/dev/dlpi"

struct dlpi_driver_data {
  int fd;
  unsigned int *buf;
  int maxlen;
  int ppa;
};

static int dlpi_open_driver(struct ifstat_driver *driver, char *options) {
  struct dlpi_driver_data *dlpi;

  if ((dlpi = malloc(sizeof(struct dlpi_driver_data))) == NULL) {
    ifstat_perror("malloc");
    return 0;
  }

  if ((dlpi->fd = open(options != NULL ? options : DLPI_DEVICE, O_RDWR)) < 0) {
    ifstat_perror("open");
    free(dlpi);
    return 0;
  }

  dlpi->maxlen = DLPI_DEFBUF_LEN;
  if ((dlpi->buf = malloc(dlpi->maxlen)) == NULL) {
    ifstat_perror("malloc");
    free(dlpi);
    return 0;

  }
  dlpi->ppa = DLPI_NO_PPA;

  driver->data = (void *) dlpi;
  return 1;
}

static int dlpi_req (struct dlpi_driver_data *dlpi, void *req, int reqlen,
		     int ackprim, void **ack, int *acklen) {
  struct strbuf ctlptr;
  int len, ret, flags;
  dl_error_ack_t *err_ack;
  
  ctlptr.maxlen = 0;
  ctlptr.len = reqlen;
  ctlptr.buf = req;
  
  if (putmsg(dlpi->fd, &ctlptr, NULL, 0) < 0) {
    ifstat_perror("putmsg");
    return 0;
  }
  
  ctlptr.maxlen = dlpi->maxlen;
  ctlptr.buf = (char *) dlpi->buf;
  ctlptr.len = 0;
  
  len = 0;
  flags = 0;
  while ((ret = getmsg(dlpi->fd, &ctlptr, NULL, &flags)) == MORECTL) {
    /* duplicate size of buf */
    dlpi->maxlen *= 2;
    if ((dlpi->buf = realloc(dlpi->buf, dlpi->maxlen)) == NULL) {
      ifstat_perror("malloc");
      return 0;
    }
    len += ctlptr.len;
    ctlptr.buf = (char *) dlpi->buf + len;
    ctlptr.maxlen = dlpi->maxlen - len;
    ctlptr.len = 0;
  }
  if (ret < 0) {
    ifstat_perror("getmsg");
    return 0;
  }
  len += ctlptr.len;
  
  err_ack = (dl_error_ack_t *) dlpi->buf;
  if (err_ack->dl_primitive != ackprim) {
    if (err_ack->dl_primitive == DL_ERROR_ACK) {
      errno = err_ack->dl_errno;
      ifstat_perror("dlpi");
    } else {
      ifstat_error("dlpi: unexpected ack type returned");
    }
    return 0;
  }

  if (ack != NULL)
    *ack = dlpi->buf;
  if (acklen != NULL)
    *acklen = len;
	
  return 1;
}

static int dlpi_attach(struct dlpi_driver_data *dlpi, int ppa) {
  dl_attach_req_t attach_req;
  dl_detach_req_t dettach_req;
  
  /* check if already attached */
  if (dlpi->ppa == ppa)
    return 1;
  
  /* else detach */
  if (dlpi->ppa != DLPI_NO_PPA) {
    dettach_req.dl_primitive = DL_DETACH_REQ;
    if (!dlpi_req(dlpi, &dettach_req, sizeof(dl_detach_req_t),
		  DL_OK_ACK, NULL, NULL))
      return 0;
    dlpi->ppa = DLPI_NO_PPA;
    if (ppa == DLPI_NO_PPA)
      return 1; /* we're done */
  }

  /* attach */
  attach_req.dl_primitive = DL_ATTACH_REQ;
  attach_req.dl_ppa = ppa;
  if (!dlpi_req(dlpi, &attach_req, sizeof(dl_attach_req_t),
		DL_OK_ACK, NULL, NULL))
    return 0;
  dlpi->ppa = ppa;
  
  return 1;
}

static int dlpi_get_ifmib(struct dlpi_driver_data *dlpi, int ppa, mib_ifEntry *mib) {
  dl_get_statistics_req_t stats_req;
  dl_get_statistics_ack_t *stats_ack;
  int len;

  /* first attach to PPA */
  if (!dlpi_attach(dlpi, ppa))
    return 0;

  /* grab stats */
  stats_req.dl_primitive = DL_GET_STATISTICS_REQ;
  if (!dlpi_req(dlpi, &stats_req, sizeof(dl_get_statistics_req_t), 
		DL_GET_STATISTICS_ACK, (void **) &stats_ack, &len))
    return 0;

  if (len < sizeof(dl_get_statistics_ack_t) ||
      stats_ack->dl_stat_offset < 0 || 
      stats_ack->dl_stat_offset + sizeof(mib_ifEntry) > len) {
    ifstat_error("dlpi: invalid data returned by stats ack");
  }

  memcpy(mib, (char *) stats_ack + stats_ack->dl_stat_offset,
	 sizeof(mib_ifEntry));

  return 1;
}

static int dlpi_map_ifs(struct dlpi_driver_data *dlpi,
			int (*mapf)(mib_ifEntry *mib, int ppa, char *name,
				    void *mdata),
			void *mdata) {
  dl_hp_ppa_req_t ppa_req;
  dl_hp_ppa_ack_t *ppa_ack;
  dl_hp_ppa_info_t *ppa_info;
  mib_ifEntry mib;
  void *buf;
  int len, i, ofs;
  char ifname[sizeof(ppa_info->dl_module_id_1) + 12];

  if (!dlpi_attach(dlpi, DLPI_NO_PPA))
    return 0;

  ppa_req.dl_primitive = DL_HP_PPA_REQ;
  if (!dlpi_req(dlpi, &ppa_req, sizeof(ppa_req),
		DL_HP_PPA_ACK, (void **) &ppa_ack, &len))
    return 0;

  if (len < sizeof(dl_hp_ppa_ack_t)) {
    ifstat_error("dlpi: short read for ppa ack");
    return 0;
  }

  /* copy buffer since used by later calls */
  if ((buf = malloc(len)) == NULL) {
    perror("malloc");
    return 0;
  }
  memcpy(buf, (void *) ppa_ack, len);
  ppa_ack = buf;
  
  /* browse interface list */
  ofs = ppa_ack->dl_offset;
  for(i = 0; i < ppa_ack->dl_count; i++) {
    if (ofs < 0 || ofs + sizeof(dl_hp_ppa_info_t) > len) {
      ifstat_error("dlpi: data returned by ppa ack exceeds data buffer");
      free(buf);
      return 0;
    }

    ppa_info = (dl_hp_ppa_info_t *) ((char *) ppa_ack + ofs);

    if (dlpi_get_ifmib(dlpi, ppa_info->dl_ppa, &mib)) {
      sprintf(ifname, "%s%d", ppa_info->dl_module_id_1, ppa_info->dl_instance_num);
      if (!mapf(&mib, ppa_info->dl_ppa, ifname, mdata)) {
	free(buf);
	return 0;
      }
    }
    
    ofs = ppa_ack->dl_offset + ppa_info->dl_next_offset;
  }

  free(buf);
  return 1;
}

static int dlpi_map_scan(mib_ifEntry *mib, int ppa, char *name,
			void *mdata) {
  examine_interface((struct ifstat_list *) mdata, name,
		    (mib->ifOper == 1 ? IFF_UP : 0) |
		    (mib->ifType == 24 ? IFF_LOOPBACK : 0), 0);
  return 1;    
}

static int dlpi_scan_interfaces(struct ifstat_driver *driver,
				struct ifstat_list *ifs) {
  return dlpi_map_ifs(driver->data, &dlpi_map_scan, (void *) ifs);
}

static int dlpi_map_stats(mib_ifEntry *mib, int ppa, char *name,
			  void *mdata) {
  struct ifstat_data *cur;

  if ((cur = ifstat_get_interface((struct ifstat_list *) mdata, name)) == NULL)
    return 1;
  ifstat_set_interface_stats(cur, mib->ifInOctets, mib->ifOutOctets);
  ifstat_set_interface_index(cur, ppa);
  return 1;
}

static int dlpi_get_stats(struct ifstat_driver *driver,
			  struct ifstat_list *ifs) {
  int i;
  struct ifstat_data *cur;
  mib_ifEntry mib;

  if (ifs->flags & IFSTAT_HASINDEX) { /* poll by index (ppa) */
    for (cur = ifs->first; cur != NULL; cur = cur->next) {
      i = ifstat_get_interface_index(cur);
      if (!dlpi_get_ifmib(driver->data, i, &mib))
	continue;
      ifstat_set_interface_stats(cur, mib.ifInOctets, mib.ifOutOctets);
      ifstat_set_interface_index(cur, i);
    }
    return 1;
  }

  return dlpi_map_ifs(driver->data, &dlpi_map_stats, (void *) ifs);
}    

void dlpi_close_driver(struct ifstat_driver *driver) {
  struct dlpi_driver_data *dlpi = driver->data;

  free(dlpi->buf);
  close(dlpi->fd);
  free(dlpi);
}
#endif

#ifdef USE_WIN32
struct win32_driver_data {
  void *buf;
  int len;
};

static int win32_open_driver(struct ifstat_driver *driver, char *options) {
  struct win32_driver_data *data;

  if ((data = malloc(sizeof(struct win32_driver_data))) == NULL) {
    ifstat_perror("malloc");
    return 0;
  }

  data->buf = NULL;
  data->len = 0;
  driver->data = (void *) data;
  return 1;
}

static int win32_getiftable(struct ifstat_driver *driver,
			    PMIB_IFTABLE *iftable) {
  struct win32_driver_data *data = driver->data;
  ULONG size;
  DWORD ret;

  size = data->len;
  while ((ret = GetIfTable((PMIB_IFTABLE) data->buf,
			   &size, 1)) == ERROR_INSUFFICIENT_BUFFER) {
    data->len = size * 2;
    if ((data->buf = realloc(data->buf, data->len)) == NULL) {
      perror("realloc");
      return 0;
    }
  }
  
  if (ret == NO_ERROR) {
    *iftable = (PMIB_IFTABLE) data->buf;
    return 1;
  }
  
  perror("GetIfTable");
  return 0;
}

static int win32_scan_interfaces(struct ifstat_driver *driver,
				 struct ifstat_list *ifs) {
  PMIB_IFTABLE iftable;
  DWORD i;
  
  if (!win32_getiftable(driver, &iftable))
    return 0;

  for (i = 0; i < iftable->dwNumEntries; i++) 
    examine_interface(ifs,
		      iftable->table[i].bDescr,
		      ((iftable->table[i].dwOperStatus ==
		       MIB_IF_OPER_STATUS_OPERATIONAL) ? IFF_UP : 0) |
		      ((iftable->table[i].dwType ==
		       MIB_IF_TYPE_LOOPBACK) ? IFF_LOOPBACK : 0), 0);

  return 1;
}

static int win32_get_stats(struct ifstat_driver *driver,
			   struct ifstat_list *ifs) {
  PMIB_IFTABLE iftable;
  DWORD i;
  struct ifstat_data *cur;

  if (!win32_getiftable(driver, &iftable))
    return 0;

  for (i = 0; i < iftable->dwNumEntries; i++) {
    if ((cur = ifstat_get_interface(ifs, iftable->table[i].bDescr)) != NULL)
      ifstat_set_interface_stats(cur,
				 (unsigned long long)
				 iftable->table[i].dwInOctets,
				 (unsigned long long)
				 iftable->table[i].dwOutOctets);
  }
  return 1;
}

void win32_close_driver(struct ifstat_driver *driver) {
  struct win32_driver_data *data = driver->data;
  
  if (data->buf != NULL)
    free(data->buf);
  free(data);
}
#endif 

static struct ifstat_driver drivers[] = {
#ifdef USE_KSTAT  
  { "kstat", &kstat_open_driver, &ioctl_scan_interfaces, &kstat_get_stats,
    &kstat_close_driver, NULL },
#endif
#ifdef USE_IFMIB  
  { "ifmib", NULL, &ifmib_scan_interfaces, &ifmib_get_stats, NULL, NULL },
#endif
#ifdef USE_IFDATA
  { "ifdata", &ifdata_open_driver, &ifdata_scan_interfaces,
    &ifdata_get_stats, &ifdata_close_driver, NULL },
#endif
#ifdef USE_ROUTE
  { "route", &route_open_driver, &route_scan_interfaces,
    &route_get_stats, &route_close_driver, NULL },
#endif  
#ifdef USE_KVM  
  { "kvm",  &kvm_open_driver, &kvm_scan_interfaces, &kvm_get_stats,
    &kvm_close_driver, NULL },
#endif
#ifdef USE_PROC  
  { "proc", &proc_open_driver, &ioctl_scan_interfaces, &proc_get_stats,
    &proc_close_driver, NULL },
#endif
#ifdef USE_DLPI
  { "dlpi", &dlpi_open_driver, &dlpi_scan_interfaces, &dlpi_get_stats,
    &dlpi_close_driver, NULL },
#endif
#ifdef USE_WIN32
  { "win32", &win32_open_driver, &win32_scan_interfaces,
    &win32_get_stats, &win32_close_driver, NULL },
#endif  
#ifdef USE_SNMP  
  { "snmp", &snmp_open_driver, &snmp_scan_interfaces, &snmp_get_stats,
    &snmp_close_driver, NULL },
#endif  
  { NULL, NULL, NULL, NULL, NULL, NULL } };
  
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
