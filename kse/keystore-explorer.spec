%global bcver 1.52
%global sname kse

%define major 1
%define gitversion 20160319
%define rel 1

%if %{gitversion}
	%define release %mkrel -c git%{gitversion} %rel
%else
	%define release %mkrel %rel
%endif


Name:		keystore-explorer
Version:	5.2.0
Release:	%{release}
Summary:	Multipurpose keystore and certificate tool
License:	GPLv3+
URL:		http://www.keystore-explorer.org/

%if %{gitversion}
Source0:	https://github.com/kaikramer/%{name}/archive/%{name}-git%{gitversion}.zip
%else
Source0:	https://github.com/kaikramer/%{name}/archive/%{name}-%{version}.zip
%endif
Patch1:		%{name}-%{version}-rename-needed-jars.patch
BuildArch:	noarch

BuildRequires:	java-devel >= 1.8.0
BuildRequires:	ant
BuildRequires:	desktop-file-utils
BuildRequires:	jpackage-utils
BuildRequires:	apache-commons-io
BuildRequires:	bouncycastle >= %{bcver}
BuildRequires:	bouncycastle-pkix >= %{bcver}
BuildRequires:	javahelp2
BuildRequires:	jgoodies-common
BuildRequires:	jgoodies-looks
BuildRequires:	jna
BuildRequires:	miglayout

Requires:		jre >= 1.8.0
Requires:		hicolor-icon-theme
Requires:		apache-commons-io
Requires:		bouncycastle >= %{bcver}
Requires:		bouncycastle-pkix >= %{bcver}
Requires:		jgoodies-common
Requires:		jgoodies-looks
Requires:		javahelp2
Requires:		jna
Requires:		miglayout
Recommends:		java-1.8.0-openjfx

%description
KeyStore Explorer is a user friendly GUI application for creating, managing and
examining keystores, keys, certificates, certificate requests, certificate
revocation lists and more.


%prep
%if %{gitversion}
#%%setup -qn %{name}
%setup -qn %{name}-master
%else
%setup -q
%endif

%patch1 -p1 -b .rename-needed-jars
pushd %{sname}

# Delete provided jars as we must compile with Mageia's to ensure their compatibility
%__rm lib/*.jar


%build
pushd %{sname}
build-jar-repository -p lib \
	bcprov bcpkix commons-io jgoodies-common jgoodies-looks \
	jna javahelp2 miglayout
%ant -DappSimpleName=%{name} resources jar


%install
pushd %{sname}

install -d -m755 %{buildroot}%{_javadir}
install -Dpm 644 dist/%{name}.jar %{buildroot}%{_javadir}/

install -d -m755 %{buildroot}%{_bindir}
install -Dpm 755 res/%{name} %{buildroot}%{_bindir}/

install -d -m755 %{buildroot}%{_datadir}/applications
install -Dpm 644 res/%{name}.desktop %{buildroot}%{_datadir}/applications/

for size in 16 32 48 128; do
	install -Dpm 644 res/icons/%{sname}_${size}.png \
		%{buildroot}%{_datadir}/icons/hicolor/${size}x${size}/apps/%{name}.png
done

install -Dpm 644 res/icons/%{sname}.svg \
	%{buildroot}%{_datadir}/icons/hicolor/scalable/apps/%{name}.svg

desktop-file-install \
	--mode=644 \
	--add-mime-type="application/x-pkcs12;application/x-pkcs7-certificates" \
	--dir=%{buildroot}%{_datadir}/applications res/%{name}.desktop


%files
%license %{sname}/res/licenses/license-kse.txt
%doc %{sname}/res/readmes/manual/readme.txt
%{_bindir}/%{name}
%{_javadir}/%{name}.jar
%{_datadir}/applications/%{name}.desktop
%{_datadir}/icons/hicolor/*/apps/%{name}.*


%changelog
* Mon Mar 21 2016 Davy Defaud <davy.defaud@free.fr> 5.2.0-0.git20160319.1
- Add new translation string
- Requires Java 8+ instead of 7+ and add Recommends java-1.8.0-openjfx
- Remove post, postun and postrans scriptlets because gtk icon cache updates are
 managed by filetriggers
- Rebuild with upstream merged code of 2016-03-19

* Thu Mar 03 2016 Davy Defaud <davy.defaud@free.fr> 5.2.0-0.git20160303.1
- Add a home made SVG icon

* Wed Mar 02 2016 Davy Defaud <davy.defaud@free.fr> 5.2.0-0.git20160302.1
- Use my own Git fork of March 2nd 2016
- Remove patch2
- Use the ant generated desktop file and Shell start script

* Sat Feb 27 2016 Davy Defaud <davy.defaud@free.fr> 5.2.0-0.git20160107.2
- Test build with my French translation

* Fri Jan 08 2016 Davy Defaud <davy.defaud@free.fr> 5.2.0-0.git20160107.1
- Git snapshop of January 7th 2016
- Drop patch 0 as tests are now disabled by default
- Rediff patch 1
- Rediff patch 2 to remove only Darcula look & feel license and reference

* Tue Jan 05 2016 Davy Defaud <davy.defaud@free.fr> 5.2.0-0.git20160105.1
- Git snapshop of January 5th 2016 that doesn't need AppleJavaExtensions.jar
- Drop uneeded tainted Java library AppleJavaExtensions.jar as Source1
- Rediff patch 1
- Create patch 2 to remove Darcula look & feel

* Wed Dec  9 2015 Davy Defaud <davy.defaud@free.fr> 5.1.1-1
- Initial import (version 5.1.1).

