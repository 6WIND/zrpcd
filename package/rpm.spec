# Copyright 2017 6WIND S.A.
#
# Redistribution and use in source and binary forms, with or without
# modification, are permitted provided that the following conditions
# are met:
#
# - Redistributions of source code must retain the above copyright
#   notice, this list of conditions and the following disclaimer.
#
# - Redistributions in binary form must reproduce the above copyright
#   notice, this list of conditions and the following disclaimer in
#   the documentation and/or other materials provided with the
#   distribution.
#
# - Neither the name of 6WIND S.A. nor the names of its
#   contributors may be used to endorse or promote products derived
#   from this software without specific prior written permission.
#
# THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
# "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
# LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS
# FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE
# COPYRIGHT OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT,
# INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
# (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
# SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
# HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT,
# STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
# ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED
# OF THE POSSIBILITY OF SUCH DAMAGE.

Name: zrpc
Version: 0.2.
Release: 0

Summary: Zebra Remote Procedure Call
Group: Applications/Internet
License: GPL
BuildRoot: /home/packager/packager/rpm/bin/BUILD/ROOT
Requires: thrift zmq glib2 libgobject-2_0-0 ccapnproto quagga

%description
ZRPC provides a Thrift API and handles RPC to configure Quagga framework.

%install
rm -rf %{buildroot} && mkdir -p %{buildroot}
cd /home/packger/packager/<output> && find . \! -type d | cpio -o -H ustar -R 0:0 | tar -C %{buildroot} -x
find %{buildroot} -type f -o -type l|sed "s,%{buildroot},," > %{_builddir}/files
sed -ri "s/\.py$/\.py*/" %{_builddir}/files

%clean
rm -rf %{buildroot}

%pre
getent group quagga >/dev/null 2>&1 || groupadd -g 92 quagga >/dev/null 2>&1 || :
getent passwd quagga >/dev/null 2>&1 || useradd -u 92 -g 92 -M -r -s /sbin/nologin \
 -c "Quagga routing suite" -d /var/run/quagga quagga >/dev/null 2>&1 || :

%postun

%post

%preun

%files -f %{_builddir}/files
%defattr(-,root,root)
%dir %attr(750,quagga,quagga) /opt/quagga/var/run/quagga
%dir %attr(750,quagga,quagga) /opt/quagga/var/log/quagga
