%define DIRNAME authentication
%define LIBNAME smartmet-%{DIRNAME}
%define SPECNAME smartmet-engine-%{DIRNAME}
Summary: SmartMet Apikey Authorization engine
Name: %{SPECNAME}
Version: 18.7.25
Release: 1%{?dist}.fmi
License: MIT
Group: SmartMet/Engines
URL: https://github.com/fmidev/smartmet-engine-authentication
Source0: %{name}.tar.gz
BuildRoot: %{_tmppath}/%{name}-%{version}-%{release}-root-%(%{__id_u} -n)
BuildRequires: gcc-c++
BuildRequires: make
BuildRequires: boost-devel
BuildRequires: smartmet-library-spine-devel >= 18.7.23
BuildRequires: libpqxx-devel
Requires: smartmet-server >= 18.7.25
Requires: smartmet-library-spine >= 18.7.23
Requires: boost-system
Requires: boost-thread
Requires: libpqxx
Provides: %{SPECNAME}
Obsoletes: smartmet-brainstorm-authengine < 16.11.1
Obsoletes: smartmet-brainstorm-authengine-debuginfo < 16.11.1

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


