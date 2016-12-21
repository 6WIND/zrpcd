# Zebra/Quagga RPC communicator

## Synopsis

This software implements a daemon to handle Quagga framework from a SDN controller.

Remote Procedure Call term is referred because of underlying mecanisms used by the daemon
to be configured, and to configure the Quagga.
Currently, 2 main RPC protocols are used:
- ZRPC uses Thrift RPC-like protocol for being configured.
- ZRPC uses CAPnProto for configuring 

By Quagga framework, it means all signaling protocol implementations from Quagga could be 
potentially launched, (un)configured, monitored.
Currently, BGP daemon is the main focus of this first implementation, since ZRPC offers 
a thrift interface defined as vpnservice.thrift. This API permits exchanging BGP updates
between VPNv4 BGP speakers. Thus permitting to the SDN controller to create dynamically 
MPLS and VXLAN tunnels between various VTEPs, where some VTEP are located to the Data Center
Gateway.

To summarize, ZRPC is kind of bridge between the SDN controller driving it and the various
Quagga daemons.

## Building ZRPC

To be able to rebuild QBGP, you will need to have several packages.
The below description has been tested by using an-Ubuntu(14.04 distribution).
Depending on the distribution, either some packages will be available and it is possible to 
download the associated package without having to compile. Or you will have to compile the
package. 
A script is available on pkgsrc ( pkgsrc/dev_compile_script.sh), and is applying the build 
and installation descriptions mentioned below.

### Dependency: Thrift

You will need thrift, especially the thrift_c_glib library.
for compilation.
The latter solution is describe:

    git clone https://git-wip-us.apache.org/repos/asf/thrift.git
    cd thrift

You will also have to patch the source code.

    https://issues.apache.org/jira/browse/THRIFT-3986
    https://issues.apache.org/jira/browse/THRIFT-3987

You will need to install the build dependencies for thrift. The command from
the [Thrift documentation](https://thrift.apache.org/docs/install/debian) is:

    sudo apt-get install automake bison flex g++ git libboost1.55-all-dev libevent-dev libssl-dev libtool make pkg-config

Then, pursue the procedure:

    touch NEWS README AUTHORS ChangeLog
    autoreconf -i
    ./configure --without-qt4 --without-qt5 --without-csharp --without-java \
    --without-erlang --without-nodejs --without-perl --without-python \
    --without-php --without-php_extension --without-dart --without-ruby \
    --without-haskell --without-go --without-haxe --without-d \
    --prefix=/opt/quagga
    make
    make install

### Dependency: ZeroMQ

You will also need to have ZMQ. Here is compilation procedure for ZMQ.

    git clone https://github.com/zeromq/zeromq4-1.git
    cd zeromq4-1
    git checkout 56b71af22db3
    autoreconf -i
    ./configure --without-libsodium --prefix=/opt/quagga
    make
    make install

### Dependency: C-capnproto

You will also need to have ccapnproto. Here is compilation and installation procedure for ccapnproto.
ccapnproto used is a copy from the original one.
Original ccapnproto stack maintained at the following url:
  https://github.com/opensourcerouting/c-capnproto
Note also some updates from
  https://github.com/sandstorm-io/capnproto

The following procedure is used:

    git clone https://github.com/opensourcerouting/c-capnproto
    cd c-capnproto
    git checkout 332076e52257
    ./configure --prefix=/opt/quagga --without-gtest
    make
    mkdir /opt/quagga/lib -p
    mkdir /opt/quagga/include/c-capnproto -p
    cp capn.h /opt/quagga/include/c-capnproto/.
    cp .libs/libcapn.so.1.0.0 .libs/libcapn_c.so.1.0.0
    ln -s .libs/libcapn_c.so.1.0.0 .libs/libcapn_c.so
    cp .libs/libcapn.so.1.0.0 /opt/quagga/lib/libcapn_c.so.1.0.0
    ln -s /opt/quagga/lib/libcapn_c.so.1.0.0 libcapn_c.so

### Dependency: Quagga

You will also need to have Quagga. 
To compile zrpc, a standard quagga based on quagga 1.1.0 is enough.
However, as ZRPC is a qagga framework for SDN controller, some adaptations have been done
for quagga too in order to handle queries from ZRPC. 
That quagga code is at following location:

     git clone https://github.com/6WIND/quagga.git
     git checkout quagga_110_mpbgp_capnp
     
Work is in progress to push to upstream the various series of patches, as indicated below. 
Other will come, the work is expected to fall in quagga upstream soon.

    https://lists.quagga.net/pipermail/quagga-dev/2016-September/016212.html
    https://lists.quagga.net/pipermail/quagga-dev/2016-October/016266.html
    https://lists.quagga.net/pipermail/quagga-dev/2016-October/016349.html
    https://lists.quagga.net/pipermail/quagga-dev/2016-October/016375.html
    https://lists.quagga.net/pipermail/quagga-dev/2016-October/016382.html

To compile quagga in order to be used by ZRPC daemon, you will have to define environment variables
in order to indicate quagga where to search for libraries and headers. Execute the following on the
shell:

    export ZEROMQ_CFLAGS="-I/tmp/zeromq4-1/include"
    export ZEROMQ_LIBS="-L/tmp/zeromq4-1/.libs/ -lzmq"
    export CAPN_C_CFLAGS='-I/tmp/c-capnproto/ -I/tmp/'
    export CAPN_C_LIBS='-L/tmp/c-capnproto/.libs/ -lcapn_c'

You will have to enable zeromq and capnproto services. Perform the following:

    cd quagga
    autoreconf -i
    LIBS='-L/tmp/zeromq4-1/.libs -L/tmp/c-capnproto/.libs/' \
    ./configure --with-zeromq --with-ccapnproto --prefix=/opt/quagga --enable-user=quagga \
    --enable-group=quagga --enable-vty-group=quagga --localstatedir=/opt/quagga/var/run/quagga \
    --disable-doc --enable-multipath=64
    make
    make install

### ZRPC build

Note that as other dependencies, GLIB2 and GOBJECT2 are other packages that need to be available on 
the platform. No description is done about the availability of those packages.

To compile zrpc, once the dependencies above resolved, retake the environment settings used to compile
quagga, and add the followingones:

    export THRIFT_CFLAGS="-I/tmp/thrift/lib/c_glib/src/thrift/c_glib/"
    export THRIFT_LIBS="-L/tmp/thrift/lib/c_glib/.libs/ -lthrift_c_glib"
    export QUAGGA_CFLAGS='-I/tmp/quagga/lib/'
    export QUAGGA_LIBS='-L/tmp/quagga/lib/.libs -lzebra'

perform the following in order to compile zrpc daemon:

    git clone https://github.com/6WIND/zrpcd.git
    cd zrpcd
    touch NEWS README
    autoreconf -i 
    LIBS='-L/tmp/zeromq4-1/.libs -L/tmp/c-capnproto -L/tmp/thrift/lib/c_glib/.libs/ \
     -L/tmp/quagga/lib/.libs' ./configure --enable-zrpcd --prefix=/opt/quagga \
     --enable-user=quagga --enable-group=quagga \
     --enable-vty-group=quagga --localstatedir=/opt/quagga/var/run/quagga 
    make
    make install
    mkdir /opt/quagga/etc/init.d -p
    cp pkgsrc/zrpcd.ubuntu /opt/quagga/etc/init.d/zrpcd
    echo "hostname bgpd" >> /opt/quagga/etc/bgpd.conf
    echo "password sdncbgpc" >> /opt/quagga/etc/bgpd.conf
    echo "service advanced-vty" >> /opt/quagga/etc/bgpd.conf
    echo "log stdout" >> /opt/quagga/etc/bgpd.conf
    echo "line vty" >> /opt/quagga/etc/bgpd.conf
    echo " exec-timeout 0 0 " >> /opt/quagga/etc/bgpd.conf
    echo "debug bgp " >> /opt/quagga/etc/bgpd.conf
    echo "debug bgp updates" >> /opt/quagga/etc/bgpd.conf
    echo "debug bgp events" >> /opt/quagga/etc/bgpd.conf
    echo "debug bgp fsm" >> /opt/quagga/etc/bgpd.conf

## Packaging ZRPC

Packaging ZRPC means that you have to rely on 4 packages, namely quagga, zrpc, but also ccapnproto, zmq and thrift. If the two last package are already available in most distribution, this is not the case for the three first ones.
This chapter focuses on packaging Quagga, Zrpc, and Ccapnproto.
To be able to produce deb or rpm packages, you will need to copy some produced files into a file system hierarchy. Once done, a script is given as well as the necessary files to produce the package.

### RPM Packaging

Create following file system hierarchy, where bin is the folder where all the package files will be present.
Let's assume the root folder where folders are created, is named package and is at following place : /home/packager/packager/.

    mkdir rpm
    touch ./rpm/.rpm-stamp
    mkdir ./rpm/bin
    mkdir ./rpm/SPECS
    mkdir ./rpm/BUILD
    mkdir ./bin
    touch ./build-stamp
    mkdir output
  
For each rpm package to produce, rpmbuild command will be used.
The rpmbuild command will be the same for each package to produce.

    rpmbuild -bb  --define '_topdir /home/packager/packager/rpm/bin' --define \
    '_rpmdir /home/packager/packager/output' --define '_rpmfilename \
    %%{NAME}-%%{VERSION}-%%{RELEASE}.%%{ARCH}.rpm' --define 'debug_package\
    %{nil}' /home/packager/packager/rpm/bin/SPECS/rpm.spec

### DEB Packaging

Create following file system hierarchy, where bin is the folder where all the package files will be present.
Let's assume the root folder where folders are created, is named package and is at following place : /home/packager/packager/.

    mkdir bin
    cd bin
    mkdir DEBIAN
    echo "#!/bin/sh" > prerm
    echo "set -e" >> prerm
    echo "#!/bin/sh" > postrm
    echo "set -e" >> postrm
    echo "if [ \"1\" = \"remove\" ]; then" >> postrm
    echo "  :" >> postrm
    echo "fi" >> postrm
    echo "#!/bin/sh" > postinst
    echo "set -e" >> postinst
    echo "if [ \"1\" = \"configure\" ]; then" >> postinst
    echo "  :" >> postinst
    echo "fi" >> postinst
    mkdir ./rpm/bin
    mkdir ./rpm/SPECS
    mkdir ./rpm/BUILD
    mkdir ./bin
    touch ./build-stamp
    mkdir output

For each deb package to produce, dpkg-deb will be used

    fakeroot dpkg-deb -b /home/packager/package/bin /home/packager/packager/output 


### Packaging ccapnproto

ccapnproto file system hierarchy looks like the following:

    ./opt/
    ./opt/quagga/
    ./opt/quagga/include/
    ./opt/quagga/include/c-capnproto/
    ./opt/quagga/include/c-capnproto/capn.h
    ./opt/quagga/lib/
    ./opt/quagga/lib/libcapn_c.so
    ./opt/quagga/lib/libcapn_c.a

For deb production, an extra file at ./bin/DEBIAN/control place contains the following

    Package: ccapnproto
    Version: 1.0.0.cfc3
    Architecture: amd64
    Maintainer: 6WIND <packaging@6wind.com>
    Description: ccapnproto library
    Library for CCAPNPROTO.
    CCAPNPROTO_BUILD_DEPS=''

For rpm production, an extra file at ./bin/SPECS/rpm.spec is copied from ccapnproto/package/rpm.spec file.


### Packaging quagga

For packaging Quagga, you will need to host following Quagga files under bin file system hierarchy as follow. Files are provided in annex: bgpd/bgpd.conf.sample4 to be copied in /etc/bgpd.conf. dummyquagga files are empty files. 

    ./bin/opt
    ./bin/opt/quagga
    ./bin/opt/quagga/var
    ./bin/opt/quagga/var/run
    ./bin/opt/quagga/var/run/quagga
    ./bin/opt/quagga/var/run/quagga/.dummyquagga
    ./bin/opt/quagga/var/log
    ./bin/opt/quagga/var/log/quagga
    ./bin/opt/quagga/var/log/quagga/.dummyquagga
    ./bin/opt/quagga/lib
    ./bin/opt/quagga/lib/libospfapiclient.so.0.0.0
    ./bin/opt/quagga/lib/libospf.so.0
    ./bin/opt/quagga/lib/libzebra.so.0
    ./bin/opt/quagga/lib/libzebra.so
    ./bin/opt/quagga/lib/libospf.so.0.0.0
    ./bin/opt/quagga/lib/libospfapiclient.so
    ./bin/opt/quagga/lib/libospf.so
    ./bin/opt/quagga/lib/libospfapiclient.so.0
    ./bin/opt/quagga/lib/libzebra.so.0.0.0
    ./bin/opt/quagga/bin
    ./bin/opt/quagga/bin/vtysh
    ./bin/opt/quagga/bin/test_igmpv3_join
    ./bin/opt/quagga/bin/bgp_btoa
    ./bin/opt/quagga/etc
    ./bin/opt/quagga/etc/bgpd.conf
    ./bin/opt/quagga/sbin
    ./bin/opt/quagga/sbin/bgpd
    ./bin/opt/quagga/sbin/zebra
    ./bin/opt/quagga/sbin/ospf6d
    ./bin/opt/quagga/sbin/ripd
    ./bin/opt/quagga/sbin/watchquagga
    ./bin/opt/quagga/sbin/ospfd
    ./bin/opt/quagga/sbin/ospfclient
    ./bin/opt/quagga/sbin/ripngd
    ./bin/opt/quagga/sbin/pimd
    ./bin/opt/quagga/sbin/isisd

For rpm production, a rpm.spec file is necessary to be copied in ./bin/SPECS/rpm.spec. Use following file:

    Name: quagga
    Version: 1.1.0.201611274
    Release: 0
    Summary: Quagga Routing Suite
    Group: Applications/Internet
    License: GPL
    BuildRoot: /home/packager/packager/rpm/bin/BUILD/ROOT
    Requires: zmq ccapnproto
 
    %description
    Quagga is an advanced routing software package that provides a suite of TCP/IP based routing protocols.

    %install
    rm -rf %{buildroot} && mkdir -p %{buildroot}
    cd /home/packager/packager/<output> && find . \! -type d | cpio -o -H ustar -R 0:0 | tar -C %{buildroot} -x
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


For deb production, an extra file at ./bin/DEBIAN/control place contains the following

    Package: quagga
    Version: 1.1.0.201611274
    Architecture: amd64
    Maintainer: 6WIND <packaging@6wind.com>
    Depends: zmq(>=4.1.0), ccapnproto(>=1.0.0)
    Description: Quagga Routing Suite
    Quagga is an advanced routing software package that provides a suite of TCP/IP based routing protocols.

A preinst configuration file is necessary to be upgraded in order to benefit from debian pre installation facilities:

    #!/bin/bash

    if [ -n "$DEBIAN_SCRIPT_DEBUG" ]; then set -v -x; DEBIAN_SCRIPT_TRACE=1; fi   
    ${DEBIAN_SCRIPT_TRACE:+ echo "#42#DEBUG# RUNNING $0 $*"}
    set -e
    set -u

    PREFIX=/opt/quagga

    # creating quagga group if it isn't already there
    if ! getent group quagga >/dev/null; then
                addgroup --system quagga >/dev/null
    fi

    # creating quagga user if he isn't already there
    if ! getent passwd quagga >/dev/null; then
          adduser \
            --system \
            --ingroup quagga \
            --home $PREFIX/var/run/quagga \
            --gecos "Quagga-BGP routing suite" \
            --shell /bin/false \
            quagga  >/dev/null
    fi

    # Do not change permissions when upgrading as it would violate policy.
    if [ "$1" = "install" ]; then
      # Logfiles are group readable in case users were put into the quagga group.
      d=$PREFIX/var/log/quagga/
      mkdir -p $d
      chown -R quagga:quagga $d
      chmod u=rwx,go=rx $d
      find $d -type f -print0 | xargs -0 --no-run-if-empty   chmod u=rw,g=r,o=

    # Strict permissions for the sockets.
            d=$PREFIX/var/run/quagga/
            mkdir -p $d
            chown -R quagga:quagga $d
            chmod u=rwx,go=rx $d
            find $d -type f -print0 | xargs -0 --no-run-if-empty   chmod u=rw,go=
    fi
    #DEBHELPER#


### Packaging ZRPC

For packaging ZRPC, you will need to host following ZRPC files under bin file system hierarchy as follow.
Files that build init.d/zrpcd are provided in annex: pkgsrc/zrpcd.ubuntu or zrpcd.suse. 
dummyzrpc files are empty files. 

    ./opt
    ./opt/quagga
    ./opt/quagga/var
    ./opt/quagga/var/run
    ./opt/quagga/var/run/quagga
    ./opt/quagga/var/run/quagga/.dummyzrpc
    ./opt/quagga/var/log
    ./opt/quagga/var/log/quagga
    ./opt/quagga/var/log/quagga/.dummyzrpc
    ./opt/quagga/sbin
    ./opt/quagga/sbin/zrpcd
    ./opt/quagga/etc
    ./opt/quagga/etc/init.d
    ./opt/quagga/etc/init.d/zrpcd


Some files are not produced by "quagga building instructions". Two files are provided in annex: etc/bgpd.conf and etc/init.d/qthriftd files. .dummy files are empty files.

For rpm production, a rpm.spec file is necessary to be copied in ./bin/SPECS/rpm.spec. Use ./package/rpm.spec file.

For deb production, an extra file at ./bin/DEBIAN/control place contains the following.

    Package: zrpc
    Version: 0.2.
    Architecture: amd64
    Maintainer: 6WIND <packaging@6wind.com>
    Depends: thrift(>=0.9), zmq(>=4.1.0), libglib2.0-0(>=2.22.5), quagga(>=1.1.0), ccapnproto(>=1.0.0)
    Description: Zebra Remote Procedure Call
    ZRPC provides a Thrift API and handles RPC to configure Quagga framework.

For deb production, please also replace preinst file with the one from package/preinst/


## Using ZRPC

To start quagga thrift service, use the following command in standard shell, from root account.

    /opt/quagga/etc/init.d/zrpcd start

To stop quagga thrift service, use the following command in standard shell, from root account.

    /opt/quagga/etc/init.d/zrpcd stop

## Troubleshooting ZRPC

Log information from zrpcd and from bgpd is collected in a rotate log file.
To see log information, use the example command :

    tail -f /opt/quagga/var/log/quagga/zrpcd.init.log

BGP daemon is started by zrpcd, when startBgp thrift call is received. 
By default,  bgp will read configuration located at /opt/quagga/etc/bgpd.conf, which contains :

    hostname bgpd
    password sdncbgpc
    log stdout
    service advanced-vty
    line vty
     exec-timeout 0 0

bgpd vty interface is present and is reachable via telnet, through port 2605.

ZRPC daemon is available and has a light vty interface to enable/disable debugging.
It is accessible through port 2611.

## License

This software is release under the GPLv2 license.
