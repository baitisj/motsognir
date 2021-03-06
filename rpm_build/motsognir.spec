#
# spec file for package motsognir
#
# Copyright (c) 2008-2019 Mateusz Viste
#

Name: motsognir
Version: 1.0.11
Release: 1%{?dist}
Summary: A robust, reliable and easy to install gopher server
Url: http://motsognir.sourceforge.net/
Group: Productivity/Networking/Other
BuildRoot: %{_tmppath}/%{name}-%{version}-%{release}-root-%(%{__id_u} -n)
License: GPL-3.0+
Source0: %{name}-%{version}.tar.gz

BuildRequires: gcc

%description
Motsognir is a robust, reliable and easy to install open-source gopher server for Unix-like systems.

The Motsognir gopher server is meant to be used for small projects (like home servers), but should scale well on bigger architectures as well. All the configuration is done via a single configuration file, which has very reasonable defaults. That makes Motsognir easily maintainable, and allows the administrator to have a full knowledge of what features are allowed/enabled on the server, and what's not. Motsognir supports server-side CGI applications and PHP scripts, is plainly compatible with UTF-8 filesystems, and is entirely written in ANSI C without external dependencies.

%prep
%setup

%build
make

%check

%install
make install DESTDIR=%{buildroot}

%files
%attr(755, root, root) %dir /usr/share/doc/motsognir
%attr(644, root, root) %doc /usr/share/doc/motsognir/changes.txt
%attr(644, root, root) %doc /usr/share/doc/motsognir/manual.pdf
%attr(644, root, root) %doc /usr/share/man/man8/motsognir.8.gz
%attr(644, root, root) %config /etc/motsognir.conf
%attr(755, root, root) /usr/sbin/motsognir
%attr(755, root, root) /etc/init.d/motsognir

%changelog
* Sat Sep 24 2013 Mateusz Viste
 - v1.0 released
