#ifndef SNMP_H
#define SNMP_H

/* snmp backend */
int snmp_open_driver(struct ifstat_driver *driver, char *options);
int snmp_scan_interfaces(struct ifstat_driver *driver,
			 struct ifstat_list *list);
int snmp_get_stats(struct ifstat_driver *driver, struct ifstat_list *ifaces);
void snmp_close_driver(struct ifstat_driver *driver);

#endif
