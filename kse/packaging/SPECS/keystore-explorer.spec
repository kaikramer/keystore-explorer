%global bcver 1.52
%global sname kse
%global libs "bcprov bcpkix commons-io jgoodies-common jgoodies-looks jna javahelp2 miglayout-core miglayout-swing"
%define get_property() xmllint --xpath 'string(//property[@name="%1"]/@value)' %2

%define major 1
%define gitversion 20160427
%define rel 1

%if 0%{?gitversion}
	%define release %mkrel -c git%{gitversion} %rel
%else
	%define release %mkrel %rel
%endif

Name:		keystore-explorer
Version:	5.2.0
Release:	%{release}
Summary:	Multipurpose keystore and certificate tool
License:	GPLv3+
Group:		Security
URL:		http://www.keystore-explorer.org/

%if 0%{?gitversion}
Source0:	https://github.com/kaikramer/%{name}/archive/%{name}-git%{gitversion}.zip
%else
Source0:	https://github.com/kaikramer/%{name}/archive/%{name}-%{version}.zip
%endif
BuildArch:	noarch

BuildRequires:	java-devel >= 1.8.0
BuildRequires:	ant
BuildRequires:	desktop-file-utils
BuildRequires:	jpackage-utils
BuildRequires:	libxml2-utils
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
%if 0%{?gitversion}
#%%setup -qn %{name}
%setup -qn %{name}-master
%else
%setup -q
%endif

# Delete provided jars as we must compile with Mageia's to ensure their compat
pushd %{sname}
%{__rm} lib/*.jar


%build
pushd %{sname}
#build-jar-repository -p lib %{libs}

classPath=`echo %{libs} | sed -re 's|(\S+)|\1.jar|g'`

%ant -DappSimpleName=%{name} -DjavaHelp=javahelp2 -DlibDir=%{_javadir} \
 -DclassPath="$classPath" resources jar


%install
pushd %{sname}

%{__install} -d -m755 %{buildroot}%{_javadir}
%{__install} -Dpm 644 dist/%{name}.jar %{buildroot}%{_javadir}/

%{__install} -d -m755 %{buildroot}%{_bindir}
%{__install} -Dpm 755 res/%{name} %{buildroot}%{_bindir}/

%{__install} -d -m755 %{buildroot}%{_datadir}/applications
%{__install} -Dpm 644 res/%{name}.desktop %{buildroot}%{_datadir}/applications/

for size in 16 32 48 128 256 512; do
	%{__install} -Dpm 644 res/icons/%{sname}_${size}.png \
		%{buildroot}%{_datadir}/icons/hicolor/${size}x${size}/apps/%{name}.png
done

%{__install} -Dpm 644 res/icons/%{sname}.svg \
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
* Tue Apr 26 2016 Davy Defaud <davy.defaud@free.fr> 5.2.0-0.git20160427.1
- Add unless:set="classPath" in the build.xml manifestclasspath tag to be able
 to set the classpath in the manifest at build time
- Set the manifest classpath at build time to correct its bad values (remove the
 lib directory) to be able to start KSE in jar mode (java -jar)
- Rework the template start up script to start KSE in jar mode to able to see
 the splash screen that was not visible with jpackage_script
- Drop the %{jpackage_script} macro in favor of our template start up script
- Clean up the deps and the spec file: remove our get_property() macro and 
 the libxml2-utils build requirement.

* Sun Apr 24 2016 Davy Defaud <davy.defaud@free.fr> 5.2.0-0.git20160424.1
- Git snapshot of April 24th 2016
- Add 256x256 pixel an 512x512 pixel icons

* Tue Mar 29 2016 Davy Defaud <davy.defaud@free.fr> 5.2.0-0.git20160329.1
- Git snapshot of March 29th 2016
- Add start option disabling update checks

* Thu Mar 24 2016 Davy Defaud <davy.defaud@free.fr> 5.2.0-0.git20160324.1
- Define missing Group as Security
- Change build.xml to automate the start script classpath generation from its
 template
- Build with Mageia Cauldron's MiG Layout libraries now splitted into
 miglayout-core and miglayout-swing like upstream
- Add libraries names as build.xml properties to be able to change them at build
- Build with the new property javaHelp=javahelp2 and finally nuke patch 1
- Add BuildRequires libxml2 to ensure we have xmllint to parse the build.xml
 file and get the mainClass property dynamically
- Define libraries list as global %libs and use it for the build and the start
 script generation
- Generate the start script with %{jpackage_script} instead of copying the ant
 generated one.

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

