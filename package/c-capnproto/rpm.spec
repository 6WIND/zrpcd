Name: c-capnproto
Version: 1.0.2.75f7
Release: 0

Summary: ccapnproto library
Group: Applications/Internet
License: MIT
BuildRoot: /home/packager/package/rpm/bin/BUILD/ROOT

%description
Library for CCAPNPROTO.
CCAPNPROTO_BUILD_DEPS=''

%install
rm -rf %{buildroot} && mkdir -p %{buildroot}
cd /home/packager/c-capnproto/<produced>/ && find . \! -type d | cpio -o -H ustar -R 0:0 | tar -C %{buildroot} -x
find %{buildroot} -type f -o -type l|sed "s,%{buildroot},," > %{_builddir}/files
sed -ri "s/\.py$/\.py*/" %{_builddir}/files

%clean
rm -rf %{buildroot}

%pre

%postun

%post

%preun

%files -f %{_builddir}/files
%defattr(-,root,root)
