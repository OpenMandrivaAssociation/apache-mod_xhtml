#Module-Specific definitions
%define mod_name mod_xhtml
%define mod_conf A68_%{mod_name}.conf
%define mod_so %{mod_name}.so

Summary:	Adds XHTML Namespace processing to the Apache Webserver
Name:		apache-%{mod_name}
Version:	0
Release:	14
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
%{_bindir}/apxs -c %{mod_name}.c

%install

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

%files
%doc README
%attr(0644,root,root) %config(noreplace) %{_sysconfdir}/httpd/modules.d/%{mod_conf}
%attr(0755,root,root) %{_libdir}/apache-extramodules/%{mod_so}


%changelog
* Sat Feb 11 2012 Oden Eriksson <oeriksson@mandriva.com> 0-13mdv2012.0
+ Revision: 773240
- rebuild

* Tue May 24 2011 Oden Eriksson <oeriksson@mandriva.com> 0-12
+ Revision: 678444
- mass rebuild

* Sun Oct 24 2010 Oden Eriksson <oeriksson@mandriva.com> 0-11mdv2011.0
+ Revision: 588090
- rebuild

* Mon Mar 08 2010 Oden Eriksson <oeriksson@mandriva.com> 0-10mdv2010.1
+ Revision: 516269
- rebuilt for apache-2.2.15

* Sat Aug 01 2009 Oden Eriksson <oeriksson@mandriva.com> 0-9mdv2010.0
+ Revision: 406683
- rebuild

* Tue Jan 06 2009 Oden Eriksson <oeriksson@mandriva.com> 0-8mdv2009.1
+ Revision: 326277
- rebuild

* Mon Jul 14 2008 Oden Eriksson <oeriksson@mandriva.com> 0-7mdv2009.0
+ Revision: 235132
- rebuild

* Thu Jun 05 2008 Oden Eriksson <oeriksson@mandriva.com> 0-6mdv2009.0
+ Revision: 215675
- fix rebuild

* Sun Mar 09 2008 Oden Eriksson <oeriksson@mandriva.com> 0-5mdv2008.1
+ Revision: 182877
- rebuild

  + Olivier Blin <blino@mandriva.org>
    - restore BuildRoot

  + Thierry Vignaud <tv@mandriva.org>
    - kill re-definition of %%buildroot on Pixel's request

* Sat Oct 13 2007 Oden Eriksson <oeriksson@mandriva.com> 0-4mdv2008.1
+ Revision: 97989
- bunzip the sources

* Sat Sep 08 2007 Oden Eriksson <oeriksson@mandriva.com> 0-3mdv2008.0
+ Revision: 82705
- rebuild


* Sat Mar 10 2007 Oden Eriksson <oeriksson@mandriva.com> 0-2mdv2007.1
+ Revision: 140779
- rebuild

* Thu Nov 09 2006 Oden Eriksson <oeriksson@mandriva.com> 0-1mdv2007.1
+ Revision: 79560
- Import apache-mod_xhtml

* Tue Jul 18 2006 Oden Eriksson <oeriksson@mandriva.com> 0-1mdv2007.0
- initial Mandriva package

