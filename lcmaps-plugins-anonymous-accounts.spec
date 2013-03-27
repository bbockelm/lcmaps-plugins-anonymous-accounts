Summary: Anonymous pool accounts plugin for the LCMAPS authorization framework
Name: lcmaps-plugins-anonymous-accounts
Version: 0.3
Release: 1%{?dist}
License: Apache v2.0
Group: System Environment/Libraries

Source0: %{name}-%{version}.tar.gz

BuildRequires: lcmaps-interface

BuildRoot: %{_tmppath}/%{name}-%{version}-%{release}-buildroot

Provides: lcmaps-plugins-pool-accounts = %{version}
Obsoletes: lcmaps-plugins-pool-accounts < 0.3

%description
This plugin, when combined with the process-tracking plugin, allows the site
to map glexec payloads to a pool of anonymous accounts.

Assuming the pilot is authorized to send jobs, it provides a level of
isolation without having to authorize the payload itself.

%prep
%setup -q

%build

%configure
make %{?_smp_mflags}

%install
rm -rf $RPM_BUILD_ROOT

make DESTDIR=$RPM_BUILD_ROOT install
rm $RPM_BUILD_ROOT/%{_libdir}/lcmaps/liblcmaps_anonymous_accounts.la
rm $RPM_BUILD_ROOT/%{_libdir}/lcmaps/liblcmaps_anonymous_accounts.a
mv $RPM_BUILD_ROOT%{_libdir}/lcmaps/liblcmaps_anonymous_accounts.so $RPM_BUILD_ROOT%{_libdir}/lcmaps/lcmaps_anonymous_accounts.mod

mkdir -p $RPM_BUILD_ROOT/var/lock/%{name}

%clean
rm -rf $RPM_BUILD_ROOT

%files
%defattr(-,root,root,-)
%{_libdir}/lcmaps/lcmaps_anonymous_accounts.mod
%dir /var/lock/%{name}

%changelog
* Mon Aug 13 2012 Brian Bockelman <bbockelm@cse.unl.edu> - 0.2-1
- Change hashing algorithm to something sticky per-job.

* Mon Aug 13 2012 Brian Bockelman <bbockelm@cse.unl.edu> - 0.1-2
Have the RPM own the lock directory.

* Sun Aug 12 2012 Brian Bockelman <bbockelm@cse.unl.edu> - 0.1-1
- First version of pool account plugin.

