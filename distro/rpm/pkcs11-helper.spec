# doc support
%bcond_with doc

%define		name		pkcs11-helper
%define		version		1.28.0
%define		release		2
%define		prefix		/usr

Summary:	A helper library for the use with smart cards and the PKCS#11 API
Name:		%{name}
Version:	%{version}
Release:	%{release}
License:	GPLv2 or BSD
Vendor:		The OpenSC Project, https://github.com/OpenSC
Packager:	Alon Bar-Lev <alon.barlev@gmail.com>
Group:		System/Crypto
Url:		https://github.com/OpenSC/pkcs11-helper
Source:		https://github.com/OpenSC/pkcs11-helper/releases/download/%{name}-%{version}/%{name}-%{version}.tar.bz2
%if %{with doc}
BuildRequires:	doxygen
%endif
BuildRequires:	openssl-devel >= 0.9.7a
Requires:	openssl >= 0.9.7a
%description
The pkcs11-helper library allows using multiple PKCS#11 providers at
the same  time, selecting keys by id, label or certificate subject,
handling  card removal and card insert events, handling card re-insert
to a  different slot, supporting session expiration serialization and
much more, all using a simple API.

%package devel
Summary:	pkcs11-helper development files
Group:		Development/Libraries
Requires:	%{name} >= %{version}
Requires:	pkgconfig
%description devel
pkcs11-helper development files.

%prep
%setup -q

%build
%configure -q \
	%{?with_doc:--enable-doc} \
	%{nil}
%{__make} %{?_smp_mflags}

%install
%{__make} %{?_smp_mflags} install DESTDIR="%{?buildroot}"

%post -p /sbin/ldconfig
%postun -p /sbin/ldconfig

%files
%{_docdir}/%{name}/COPYING*
%{_docdir}/%{name}/README
%{_libdir}/libpkcs11-helper.so.*
%{_mandir}/*/*

%files devel
%{_datadir}/aclocal/*
%{_includedir}/*
%{_libdir}/libpkcs11-helper.a
%{_libdir}/libpkcs11-helper.la
%{_libdir}/libpkcs11-helper.so
%{_libdir}/pkgconfig/*
%if %{with doc}
%{_docdir}/%{name}/api/*
%endif

%changelog
* Sat Jan 14 2017 Alon Bar-Lev <alon.barlev@gmail.com>
- Cleanups.

* Fri Nov 11 2011 Alon Bar-Lev <alon.barlev@gmail.com>
- Cleanups.

* Thu Feb 15 2007 Alon Bar-Lev <alon.barlev@gmail.com>
- Modify docs location.

* Mon Jan 15 2007 Eddy Nigg <eddy_nigg@startcom.org>
- Make doxygen dependency only for doc builds 

* Tue Jan 9 2007 Eddy Nigg <eddy_nigg@startcom.org>
- Build new version 1.03

* Sun Jan 7 2007 Eddy Nigg <eddy_nigg@startcom.org>
- Fix for pkgconfig.

* Mon Nov 27 2006 Eddy Nigg <eddy_nigg@startcom.org>
- Fix documentation.

* Sun Nov 26 2006 Eddy Nigg <eddy_nigg@startcom.org>
- Initial build for StartCom Linux 5.0.x
