#Module-Specific definitions
%define mod_name mod_xhtml
%define mod_conf A68_%{mod_name}.conf
%define mod_so %{mod_name}.so

Summary:	Adds XHTML Namespace processing to the Apache Webserver
Name:		apache-%{mod_name}
Version:	0
Release:	%mkrel 9
Group:		System/Servers
License:	GPL
URL:		http://apache.webthing.com/mod_xhtml/
# there is no official tar ball
# http://apache.webthing.com/svn/apache/filters/xmlns/
Source0:	http://apache.webthing.com/svn/apache/filters/xmlns/mod_xhtml.c
Source1:	README.mod_xhtml
Source2:	%{mod_conf}
Requires(pre): rpm-helper
Requires(postun): rpm-helper
Requires(pre):	apache-conf >= 2.2.0
Requires(pre):	apache >= 2.2.0
Requires(pre):	apache-mod_xmlns
Requires:	apache-conf >= 2.2.0
Requires:	apache >= 2.2.0
Requires:	apache-mod_xmlns
BuildRequires:	apache-devel >= 2.2.0
BuildRequires:	apache-mod_xmlns-devel
BuildRequires:	file
BuildRoot:	%{_tmppath}/%{name}-%{version}-%{release}-buildroot

%description
mod_xhtml provides a namespace processor for http://www.w3.org/1999/xhtml that
serves to ensure XHTML meets the W3C Appendix C guidelines for compatibility
with HTML browsers and the text/html MIME type. In addition, mod_xhtml
implements Server Side  Includes (SSI), both as Apache's comment-driven
processing language and as a separate XML namespace processor.

%prep

%setup -q -c -T -n %{mod_name}-%{version}

cp %{SOURCE0} mod_xhtml.c
cp %{SOURCE1} README
cp %{SOURCE2} %{mod_conf}

# strip away annoying ^M
find . -type f|xargs file|grep 'CRLF'|cut -d: -f1|xargs perl -p -i -e 's/\r//'
find . -type f|xargs file|grep 'text'|cut -d: -f1|xargs perl -p -i -e 's/\r//'

%build
%{_sbindir}/apxs -c %{mod_name}.c

%install
[ "%{buildroot}" != "/" ] && rm -rf %{buildroot}

install -d %{buildroot}%{_sysconfdir}/httpd/modules.d
install -d %{buildroot}%{_libdir}/apache-extramodules

install -m0755 .libs/*.so %{buildroot}%{_libdir}/apache-extramodules/
install -m0644 %{mod_conf} %{buildroot}%{_sysconfdir}/httpd/modules.d/%{mod_conf}

%post
if [ -f %{_var}/lock/subsys/httpd ]; then
 %{_initrddir}/httpd restart 1>&2;
fi

%postun
if [ "$1" = "0" ]; then
 if [ -f %{_var}/lock/subsys/httpd ]; then
	%{_initrddir}/httpd restart 1>&2
 fi
fi

%clean
[ "%{buildroot}" != "/" ] && rm -rf %{buildroot}

%files
%defattr(-,root,root)
%doc README
%attr(0644,root,root) %config(noreplace) %{_sysconfdir}/httpd/modules.d/%{mod_conf}
%attr(0755,root,root) %{_libdir}/apache-extramodules/%{mod_so}
