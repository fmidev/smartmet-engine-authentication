%define DIRNAME authentication
%define LIBNAME smartmet-%{DIRNAME}
%define SPECNAME smartmet-engine-%{DIRNAME}
Summary: SmartMet Apikey Authorization engine
Name: %{SPECNAME}
Version: 20.12.15
Release: 1%{?dist}.fmi
License: MIT
Group: SmartMet/Engines
URL: https://github.com/fmidev/smartmet-engine-authentication
Source0: %{name}.tar.gz
BuildRoot: %{_tmppath}/%{name}-%{version}-%{release}-root-%(%{__id_u} -n)

BuildRequires: boost169-devel
BuildRequires: gcc-c++
BuildRequires: libpqxx-devel < 1:7.0
BuildRequires: make
BuildRequires: rpm-build
BuildRequires: smartmet-library-spine-devel >= 20.12.15
Requires: boost169-system
Requires: boost169-thread
Requires: libpqxx < 1:7.0
Requires: smartmet-library-spine >= 20.12.15
Requires: smartmet-server >= 20.10.28
Provides: %{SPECNAME}
Obsoletes: smartmet-brainstorm-authengine < 16.11.1
Obsoletes: smartmet-brainstorm-authengine-debuginfo < 16.11.1
#TestRequires: bzip2-devel
#TestRequires: gcc-c++
#TestRequires: make
#TestRequires: libconfig-devel >= 1.7.2
#TestRequires: smartmet-library-regression
#TestRequires: smartmet-library-spine-devel >= 20.12.15
#TestRequires: zlib-devel

%description
SmartMet Apikey Authorization engine


%package -n %{SPECNAME}-devel
Summary: SmartMet %{SPECNAME} development headers
Group: SmartMet/Development
Provides: %{SPECNAME}-devel
Obsoletes: smartmet-brainstorm-authengine-devel < 16.11.1
%description -n %{SPECNAME}-devel
SmartMet %{SPECNAME} development headers.

%prep
rm -rf $RPM_BUILD_ROOT

%setup -q -n %{SPECNAME}
 
%build -q -n %{SPECNAME}
make %{_smp_mflags}

%install
%makeinstall

%clean
rm -rf $RPM_BUILD_ROOT

%files -n %{SPECNAME}
%defattr(0755,root,root,0775)
%{_datadir}/smartmet/engines/%{DIRNAME}.so

%files -n %{SPECNAME}-devel
%defattr(0664,root,root,0775)
%{_includedir}/smartmet/engines/%{DIRNAME}

%changelog
* Tue Dec 15 2020 Mika Heiskanen <mika.heiskanen@fmi.fi> - 20.12.15-1.fmi
- Upgrade to pgdg12

* Tue Oct 20 2020 Andris Pavenis <andris.pavenis@fmi.fi> - 20.10.20-1.fmi
- Rebuild due to libconfig upgrade to version 1.7.2

* Wed Sep 23 2020 Mika Heiskanen <mika.heiskanen@fmi.fi> - 20.9.23-1.fmi
- Use Fmi::Exception instead of Spine::Exception

* Fri Aug 21 2020 Mika Heiskanen <mika.heiskanen@fmi.fi> - 20.8.21-1.fmi
- Upgrade to fmt 6.2

* Mon Jun  8 2020 Mika Heiskanen <mika.heiskanen@fmi.fi> - 20.6.8-1.fmi
- Upgraded libpqxx dependencies

* Sat Apr 18 2020 Mika Heiskanen <mika.heiskanen@fmi.fi> - 20.4.18-1.fmi
- Upgrade to Boost 1.69

* Fri Feb 14 2020 Mika Heiskanen <mika.heiskanen@fmi.fi> - 20.2.14-1.fmi
- Upgrade to pgdg12

* Thu Sep 26 2019 Mika Heiskanen <mika.heiskanen@fmi.fi> - 19.9.26-1.fmi
- Added support for ASAN & TSAN builds

* Mon Sep 10 2018 Mika Heiskanen <mika.heiskanen@fmi.fi> - 18.9.10-1.fmi
- Silenced the last CodeChecker warning

* Tue Aug 21 2018 Mika Heiskanen <mika.heiskanen@fmi.fi> - 18.8.21-1.fmi
- Silenced CodeChecker warnings

* Wed Jul 25 2018 Mika Heiskanen <mika.heiskanen@fmi.fi> - 18.7.25-1.fmi
- Prefer nullptr over NULL

* Sat Apr  7 2018 Mika Heiskanen <mika.heiskanen@fmi.fi> - 18.4.7-1.fmi
- Upgrade to boost 1.66

* Tue Mar 20 2018 Mika Heiskanen <mika.heiskanen@fmi.fi> - 18.3.20-1.fmi
- Full repackaging of the server

* Fri Feb  9 2018 Mika Heiskanen <mika.heiskanen@fmi.fi> - 18.2.9-1.fmi
- Repackaged since base class SmartMetEngine size changed

* Mon Jan 15 2018 Mika Heiskanen <mika.heiskanen@fmi.fi> - 18.1.15-1.fmi
- Updated pqxx dependency

* Wed Sep 13 2017 Mika Heiskanen <mika.heiskanen@fmi.fi> - 17.9.13-1.fmi
- Changed license to MIT

* Mon Aug 28 2017 Mika Heiskanen <mika.heiskanen@fmi.fi> - 17.8.28-1.fmi
- Upgrade to boost 1.65

* Sat Apr  8 2017 Mika Heiskanen <mika.heiskanen@fmi.fi> - 17.4.8-1.fmi
- Simplified error reporting

* Wed Mar 15 2017 Mika Heiskanen <mika.heiskanen@fmi.fi> - 17.3.15-1.fmi
- Recompiled since Spine::Exception changed

* Tue Mar 14 2017 Mika Heiskanen <mika.heiskanen@fmi.fi> - 17.3.14-1.fmi
- Switched to use macgyver StringConversion tools

* Thu Jan  5 2017 Mika Heiskanen <mika.heiskanen@fmi.fi> - 17.1.5-1.fmi
- Added new authorize() parameter to require existence of token value (SOL-4614)

* Wed Jan  4 2017 Mika Heiskanen <mika.heiskanen@fmi.fi> - 17.1.4-1.fmi
- Updated to use renamed SmartMet base libraries

* Wed Nov 30 2016 Mika Heiskanen <mika.heiskanen@fmi.fi> - 16.11.30-1.fmi
- Using test database in sample and test configuration
- No installation for configuration

* Tue Nov  1 2016 Mika Heiskanen <mika.heiskanen@fmi.fi> - 16.11.1-1.fmi
- Namespace changed

* Tue Sep  6 2016 Mika Heiskanen <mika.heiskanen@fmi.fi> - 16.9.6-1.fmi
- New exception handler

* Mon Aug 15 2016 Mika Heiskanen <mika.heiskanen@fmi.fi> - 16.8.15-1.fmi
- Full recompile

* Tue Jun 14 2016 Mika Heiskanen <mika.heiskanen@fmi.fi> - 16.6.14-1.fmi
- Full recompile

* Thu Jun  2 2016 Mika Heiskanen <mika.heiskanen@fmi.fi> - 16.6.2-1.fmi
- Full recompile

* Wed Jun  1 2016 Mika Heiskanen <mika.heiskanen@fmi.fi> - 16.6.1-1.fmi
- Added graceful shutdown
- Added wildcard token for granting global access

* Tue May  3 2016 Tuomo Lauri <tuomo.lauri@fmi.fi> - 16.5.3-1.fmi
- Fixed bug in token mapping

* Wed Apr 20 2016 Tuomo Lauri <tuomo.lauri@fmi.fi> - 16.4.20-1.fmi
- First release of Authengine


