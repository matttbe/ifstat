# Time-stamp: <01/12/25 14:04:41 ifstat.spec wbosse@berlin.snafu.de>
# $Id: ifstat.spec,v 1.9 2004/01/01 19:16:59 gael Exp $

Name: ifstat
Summary: InterFace STATistics
Version: 1.1
Release: 1
Group: Applications
Copyright: GPL
Vendor: Gaël Roualland <gael.roualland@dial.oleane.com>
URL: http://gael.roualland.free.fr/ifstat/
Packager: Werner Bosse <wbosse@berlin.snafu.de>
Source0: %{name}-%{version}.tar.gz
BuildRoot: %{_tmppath}/%{name}-%{version}-buildroot
Requires: ucd-snmp
BuildPrereq: ucd-snmp-devel

%description
ifstat(1) is a little tool to report interface activity like vmstat/iostat do.
In addition, ifstat can poll remote hosts through SNMP if you have the ucd-snmp
library. It will also be used for localhost if no other known method works (You
need to have snmpd running for this though).

See also %{_docdir}/%{name}-%{version}

%changelog
* %(echo `LC_ALL=C date '+%a %b %d %Y'`) %(whoami)@%(hostname)
- built %{version} on %(cat /etc/*-release | head -1)

* Tue Dec 25 2001 Werner Bosse <wbosse@berlin.snafu.de>
- initialization of spec file.

%prep
%setup -q
./configure --prefix=%{_prefix} --enable-optim

%build
make 

%install
rm -rf $RPM_BUILD_ROOT
make prefix=$RPM_BUILD_ROOT%{_prefix} mandir=$RPM_BUILD_ROOT%{_mandir} install

%clean
rm -rf $RPM_BUILD_ROOT

%files
%defattr(-,root,root)
%doc README INSTALL TODO COPYING HISTORY
%{_bindir}/*
%{_mandir}/man*/*
