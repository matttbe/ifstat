InterFace STATistics
Gaël Roualland <gael.roualland@dial.oleane.com>
===============================================

* Introduction

Ifstat is a little tool to report interface activity like vmstat/iostat do.
Since gathering these statistics is highly system dependant, only a
few operating systems are supported right now:

   Linux with /proc/net/dev interface (Linux >= 2.2.x)
   Solaris with kstat(3K) interface (Solaris >= 2.6.x)
   FreeBSD with ifmib(4) interface (FreeBSD > 2.2)
   IRIX and OpenBSD with SIOCGIFDATA ioctl(2).
   BSD like systems with route sysctl(3) interface (NetBSD, Darwin).
   BSD like systems with kvm(3) interface.
   Digital Unix (OSF/1), AIX with "legacy" kmem interface.
   HP-UX with DLPI streams interface.
   Win32 (native or with cygwin) with GetIfTable interface.

Others might be easy to add, or might simply work out-of-the-box if
some compatibility layer is there. As usual your mileage may vary.

In addition, ifstat can poll remote hosts through SNMP if you have
the ucd-snmp library. It will also be used for localhost if no other
known method works (You need to have snmpd running for this though).
 
* Compilation

To compile, just run the configure script as follows:
(Refer to the INSTALL file for generic configure instructions)

   ./configure

You might need to set several variables for the configure script 
on some systems:

   - On HP-UX, if using the HP C Compiler, add CC="cc -Ae" so that
     ANSI C syntax is accepted.
   - On Windows, you might want to add CC="gcc -mno-cygwin" under 
     Cygwin to build a native win32 binary.

You might also need to pass several options to the configure script. 
This package accepts the following extra-options:

   --enable-debug     This turns debugging on in the library.
   --enable-optim     This turns on some gcc optimization flags.
   --enable-library   Enable build and installation of libifstat.

By default, all the statistics gathering drivers are checked for 
availibility until a working one is found, but several can be
included. If you wish to force inclusion of an alternate driver 
(if available) or disable one, you can use one of the following options:

   --with-proc        Force support of /proc if available.
   --without-proc     Do not include support for /proc.
   --with-kstat       Force support of kstat if available.
   --without-kstat    Do not include support for kstat.
   --with-ifmib       Force support of ifmib if available.
   --without-ifmib    Do not include support for ifmib.
   --with-ifdata      Force support of ifdata if available.
   --without-ifata    Do not include support for ifdata.
   --with-route       Force support of route if available.
   --without-route    Do not include support for route.
   --with-kvm         Force support of kvm if available.
   --without-kvm      Do not include support for kvm.
   --with-dlpi        Force support of dlpi if available.
   --without-dlpi     Do not include support for dlpi.
   --with-win32       Force support of wiN32 if available.
   --without-win32    Do not include support for win32.
   --with-snmp=prefix Specify where the snmp library is installed
   --without-snmp     Do not include support for SNMP.
   --with-libcrypto   Force use of libcrypto with UCD-SNMP. This is needed
                      on at least OpenBSD, since the snmp library links
                      but doesn't run without it.

Then, run the make command:

   make

and finally, to install it run:

   make install

* Usage

Simply run ifstat and see stats rolling ;)

* Homepage

http://gael.roualland.free.fr/ifstat/

* Feedback

If you're happy with ifstat, I'd be glad to hear from you and know
what you use it for and on which systems. Bugs reports are welcomed
too! Thanks.
