%define git_repo django-cas2
%define git_head HEAD

%define realname    django-cas2

Name:		python-%{realname}
Version:	%git_get_ver
Release:	%mkrel %git_get_rel2
Summary:        CAS 2.0 authentication backend for Django
Group:          Development/Python
License:        MIT
URL:            https://github.com/paulocheque/django-cas2
Source:		%git_bs_source %{name}-%{version}.tar.gz
Source1:	%{name}-gitrpm.version
Source2:	%{name}-changelog.gitrpm.txt
BuildRoot:      %{_tmppath}/%{name}-%{version}-%{release}-root
BuildArch:      noarch
BuildRequires:  python-devel python-setuptools
Requires:       python-django
Requires:       python-requests

%description
CAS 2.0 authentication backend for Django. It allows you to use
Django's built-in authentication mechanisms and User model while
adding support for CAS.

It also includes a middleware that intercepts calls to the original
login and logout pages and forwards them to the CASified versions,
and adds CAS support to the admin interface.

.. _CAS: http://www.ja-sig.org/products/cas/
.. _Django: http://www.djangoproject.com/


%prep
%git_get_source
%setup -q
find . -name \*.buildinfo* -exec rm {} +

%build
%{__python} setup.py build

%install
rm -rf $RPM_BUILD_ROOT
%{__python} setup.py install -O1 --skip-build --root $RPM_BUILD_ROOT

%clean
rm -rf $RPM_BUILD_ROOT

%files
%defattr(-,root,root,-)
%{py_puresitedir}/*

%changelog -f %{_sourcedir}/%{name}-changelog.gitrpm.txt
