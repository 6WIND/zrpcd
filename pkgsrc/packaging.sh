# Copyright 2017 6WIND
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
set -eux
set +u

# There must be 5 parameters given by callers:
# $1 - "zrpc" or "quagga"
# $2 - the directory where files are installed
# $3 - working directory for packaging
# $4 - hostname, including distribution and version, such as "Ubuntu14.04"
# $5 - last git commit ID

INST_BIN_DIR=$2
HOST_NAME=$4
COMMITID=$5
PACKAGING_VERSION=$7
PACKAGE_DEB="n"
#The src.rpm will be installed into following dir
SRC_INST_DIR="/usr/local/src/"

prepare_source_for_spec () {
    #The rpmbuild's spec extract SOURCES/quagga-$version.tgz then cd to quagga-$version
    name=$1
    mkdir -p $RPM_BIN_DIR/SOURCES/$name-$version
    mv $INST_BIN_DIR/../src/$name.tar $RPM_BIN_DIR/SOURCES/$name-$version/
    pushd $RPM_BIN_DIR/SOURCES/$name-$version
    tar -xf $name.tar
    rm .git -rf
    rm -rf $name.tar
    pushd $RPM_BIN_DIR/SOURCES
    tar -zcf $name-$version.tgz $name-$version
    popd
    popd
    rm -rf $RPM_BIN_DIR/SOURCES/$name-$version
}

prepare_source_for_deb () {
    name=$1
    pushd $INST_BIN_DIR
    tar -xf $name.tar
    rm .git $name.tar -rf
    popd
}

gen_rpm_src_spec() {
    echo "%prep" >> $RPM_SPEC_FILE
    echo "%setup -q" >> $RPM_SPEC_FILE
    echo  >> $RPM_SPEC_FILE
    echo "%install" >> $RPM_SPEC_FILE
    echo "%build" >> $RPM_SPEC_FILE
    echo "rm -rf $SRC_INST_DIR/%{name}-%{version}" >> $RPM_SPEC_FILE
    echo "cp -rf ../%{name}-%{version} $SRC_INST_DIR" >> $RPM_SPEC_FILE
    echo "%clean" >> $RPM_SPEC_FILE
    echo "%postun" >> $RPM_SPEC_FILE
    echo "%preun" >> $RPM_SPEC_FILE
}

zrpc_copy_bin_files () {
    if [ $DEV_PACKAGE = "n" ]; then
        mkdir -p $INST_BIN_DIR/opt/quagga/var/log/quagga
        if [ -f $INST_BIN_DIR/opt/quagga/var/log/quagga/zrpcd.init.log ]; then
              touch $INST_BIN_DIR/opt/quagga/var/log/quagga/zrpcd.init.log
        fi

        if [ -z "$PACKAGING_VERSION" ]; then
	    zrpc_version="0.2.`date +'%Y%m%d'`"
        else
	    zrpc_version="0.2.$PACKAGING_VERSION"
        fi
	echo $zrpc_version > $INST_BIN_DIR/opt/quagga/etc/zrpc.version
    else
        if [ $PACKAGE_DEB = "n" ]; then
        #For redhat: prepare source
            prepare_source_for_spec $1
        else
        #For debian: prepare souce
            prepare_source_for_deb $1
        fi
    fi

    pushd $INST_BIN_DIR
    if [ $PACKAGE_DEB = "y" ]; then
    #For debian
       find . \! -type d | cpio -o -H ustar -R 0:0 | tar -C $DEB_BIN_DIR -x
    fi
    popd
}

zrpc_rpm_bin_spec () {

    echo "Name: $1" >> $RPM_SPEC_FILE
    echo "Version: $version" >> $RPM_SPEC_FILE
    if [ $DEV_PACKAGE = "y" ]; then
        echo "Source: %{name}-%{version}.tgz" >> $RPM_SPEC_FILE
    fi
    echo "Release: 0" >> $RPM_SPEC_FILE
    echo >> $RPM_SPEC_FILE

    echo "Summary: Zebra Remote Procedure Call" >> $RPM_SPEC_FILE
    echo "Group: Applications/Internet" >> $RPM_SPEC_FILE
    echo "License: GPL" >> $RPM_SPEC_FILE

    echo "BuildRoot: $RPM_BIN_DIR/BUILD/ROOT" >> $RPM_SPEC_FILE
    case $HOST_NAME in
    RedHat7*)
        ZRPC_RPM_DEPS="thrift zmq c-capnproto quagga glib2"
        ;;
    CentOS*)
        ZRPC_RPM_DEPS="thrift zmq c-capnproto quagga"
        ;;
    SUSE*)
        ZRPC_RPM_DEPS="thrift zmq glib2 libgobject-2_0-0 c-capnproto quagga"
        ;;
    esac
    echo "Requires: $ZRPC_RPM_DEPS" >> $RPM_SPEC_FILE
    echo >> $RPM_SPEC_FILE

    echo "%description" >> $RPM_SPEC_FILE
    printf "ZRPC provides a Thrift API and handles RPC to configure Quagga framework.\n" >> $RPM_SPEC_FILE
    echo >> $RPM_SPEC_FILE

    if [ $DEV_PACKAGE = "y" ]; then
	gen_rpm_src_spec

    else
        echo "%install" >> $RPM_SPEC_FILE
        echo "rm -rf %{buildroot} && mkdir -p %{buildroot}" >> $RPM_SPEC_FILE
        echo "cd $INST_BIN_DIR && find . \! -type d | cpio -o -H ustar -R 0:0 | tar -C %{buildroot} -x" >> $RPM_SPEC_FILE
        echo "find %{buildroot} -type f -o -type l|sed "s,%{buildroot},," > %{_builddir}/files" >> $RPM_SPEC_FILE
        echo "sed -ri "s/\.py$/\.py*/" %{_builddir}/files" >> $RPM_SPEC_FILE
        echo >> $RPM_SPEC_FILE

        echo "%clean" >> $RPM_SPEC_FILE
        echo "rm -rf %{buildroot}" >> $RPM_SPEC_FILE
        echo >> $RPM_SPEC_FILE

        echo "%pre" >> $RPM_SPEC_FILE
        echo "getent group quagga >/dev/null 2>&1 || groupadd -g 92 quagga >/dev/null 2>&1 || :" >> $RPM_SPEC_FILE
        echo "getent passwd quagga >/dev/null 2>&1 || useradd -u 92 -g 92 -M -r -s /sbin/nologin \\" >> $RPM_SPEC_FILE
        echo " -d /var/run/quagga quagga >/dev/null 2>&1 || :" >> $RPM_SPEC_FILE
        echo >> $RPM_SPEC_FILE

        echo "%postun" >> $RPM_SPEC_FILE
        echo >> $RPM_SPEC_FILE

        echo "%post" >> $RPM_SPEC_FILE
        echo >> $RPM_SPEC_FILE

        echo "%preun" >> $RPM_SPEC_FILE
        echo >> $RPM_SPEC_FILE

        echo "%files -f %{_builddir}/files" >> $RPM_SPEC_FILE
        echo "%defattr(-,root,root)" >> $RPM_SPEC_FILE
    fi
}

zrpc_deb_bin_control () {
    if [ $DEV_PACKAGE = "y" ]; then
        echo "Package: zrpc-src" >> $DEB_CONTROL_FILE
        if [ -z "$COMMITID" ]; then
            echo "Source: zrpc-dev (0.2.HOST_NAME)" >> $DEB_CONTROL_FILE
            echo "Version: 0.2.$HOST_NAME" >> $DEB_CONTROL_FILE
        else
            echo "Source: zrpc-dev (0.2.$COMMITID.$HOST_NAME)" >> $DEB_CONTROL_FILE
            echo "Version: 0.2.$COMMITID.$HOST_NAME" >> $DEB_CONTROL_FILE
        fi
        echo "Bugs : https://github.com/6WIND/zrpcd/issues" >> $DEB_CONTROL_FILE
    else
        echo "Package: zrpc" >> $DEB_CONTROL_FILE
        if [ -z "$COMMITID" ]; then
            echo "Version: 0.2.$HOST_NAME" >> $DEB_CONTROL_FILE
        else
            echo "Version: 0.2.$COMMITID.$HOST_NAME" >> $DEB_CONTROL_FILE
        fi
    fi
    echo "Maintainer: 6WIND <packaging@6wind.com>" >> $DEB_CONTROL_FILE
    if [ $DEV_PACKAGE = "y" ]; then     
        echo "Vcs-Git: https://github.com/6WIND/zrpcd" >> $DEB_CONTROL_FILE
        echo "Architecture: amd64" >> $DEB_CONTROL_FILE
        echo "Depends: thrift-dev(>=0.9), zmq-dev(>=4.1.0), quagga-dev(>=1.1.0), c-capnproto-dev(>=1.0.0)" >> $DEB_CONTROL_FILE
        echo "Section: net" >> $DEB_CONTROL_FILE
        echo "Priority : optional" >> $DEB_CONTROL_FILE
        echo "Multi-Arch: same" >> $DEB_CONTROL_FILE
        echo "Description: Zebra Remote Procedure Call" >> $DEB_CONTROL_FILE
    printf " ZRPC-DEV provides source necessary to develop under ZRPC.\n" >> $DEB_CONTROL_FILE
    else
        echo "Architecture: amd64" >> $DEB_CONTROL_FILE
        echo "Depends: thrift(>=0.9), zmq(>=4.1.0), libglib2.0-0(>=2.22.5), quagga(>=1.1.0), c-capnproto(>=1.0.0)" >> $DEB_CONTROL_FILE
        echo "Description: Zebra Remote Procedure Call" >> $DEB_CONTROL_FILE
        printf " ZRPC provides a Thrift API and handles RPC to configure Quagga framework.\n" >> $DEB_CONTROL_FILE
    fi
    if [ $DEV_PACKAGE = "n" ]; then
        if [ -f $INST_BIN_DIR/preinst ]; then
            mv $INST_BIN_DIR/preinst $DEB_BIN_DIR/DEBIAN/
            rm -f $DEB_BIN_DIR/preinst
        fi

        printf '#!/bin/sh\n' > $DEB_BIN_DIR/DEBIAN/postinst
        printf 'set -e\n' >> $DEB_BIN_DIR/DEBIAN/postinst
        printf 'if [ "$1" = "configure" ]; then\n' >> $DEB_BIN_DIR/DEBIAN/postinst
        printf '  :\n' >> $DEB_BIN_DIR/DEBIAN/postinst
        printf 'fi\n' >> $DEB_BIN_DIR/DEBIAN/postinst
        chmod a+x $DEB_BIN_DIR/DEBIAN/postinst

        printf '#!/bin/sh\n' > $DEB_BIN_DIR/DEBIAN/prerm
        printf 'set -e\n' >> $DEB_BIN_DIR/DEBIAN/prerm
        chmod a+x $DEB_BIN_DIR/DEBIAN/prerm

        printf '#!/bin/sh\n' > $DEB_BIN_DIR/DEBIAN/postrm
        printf 'set -e\n' >> $DEB_BIN_DIR/DEBIAN/postrm
        printf 'if [ "$1" = "remove" ]; then\n' >> $DEB_BIN_DIR/DEBIAN/postrm
        printf '  :\n' >> $DEB_BIN_DIR/DEBIAN/postrm
        printf 'fi\n' >> $DEB_BIN_DIR/DEBIAN/postrm
        chmod a+x $DEB_BIN_DIR/DEBIAN/postrm
    fi
}

quagga_copy_bin_files () {

    if [ $DEV_PACKAGE = "n" ]; then
        if [ -f $INST_BIN_DIR/opt/quagga/etc/bgpd.conf ]; then
            sed -i -- 's/zebra/8 $5$mE$GYmnGvxYcXC7RsgqQNGUa2jvVDDl6\/rjCtduUQL3ei4/g' $INST_BIN_DIR/opt/quagga/etc/bgpd.conf
            echo "service password-encryption" >> $INST_BIN_DIR/opt/quagga/etc/bgpd.conf
        else
            echo "hostname bgpd" > $INST_BIN_DIR/opt/quagga/etc/bgpd.conf
            echo "password 8 $5$mE$GYmnGvxYcXC7RsgqQNGUa2jvVDDl6/rjCtduUQL3ei4" >> $INST_BIN_DIR/opt/quagga/etc/bgpd.conf
            echo "service advanced-vty" >> $INST_BIN_DIR/opt/quagga/etc/bgpd.conf
            echo "line vty" >> $INST_BIN_DIR/opt/quagga/etc/bgpd.conf
            echo " exec-timeout 0 0 " >> $INST_BIN_DIR/opt/quagga/etc/bgpd.conf
            echo "log record-priority" >> $INST_BIN_DIR/opt/quagga/etc/bgpd.conf
            echo "service password-encryption" >> $INST_BIN_DIR/opt/quagga/etc/bgpd.conf
            echo "debug bgp " >> $INST_BIN_DIR/opt/quagga/etc/bgpd.conf
            echo "debug bgp updates" >> $INST_BIN_DIR/opt/quagga/etc/bgpd.conf
            echo "debug bgp events" >> $INST_BIN_DIR/opt/quagga/etc/bgpd.conf
            echo "debug bgp fsm" >> $INST_BIN_DIR/opt/quagga/etc/bgpd.conf
        fi

        if [ -f $INST_BIN_DIR/opt/quagga/etc/bfdd.conf ]; then
            sed -i -- 's/zebra/8 $5$mE$GYmnGvxYcXC7RsgqQNGUa2jvVDDl6\/rjCtduUQL3ei4/g' $INST_BIN_DIR/opt/quagga/etc/bfdd.conf
            echo "service advanced-vty" >> $INST_BIN_DIR/opt/quagga/etc/bfdd.conf
            echo "log record-priority" >> $INST_BIN_DIR/opt/quagga/etc/bfdd.conf
            echo "service password-encryption" >> $INST_BIN_DIR/opt/quagga/etc/bfdd.conf
            echo "debug bfd zebra" >> $INST_BIN_DIR/opt/quagga/etc/bfdd.conf
            echo "debug bfd fsm" >> $INST_BIN_DIR/opt/quagga/etc/bfdd.conf
        else
	    touch $INST_BIN_DIR/opt/quagga/etc/bfdd.conf
        fi

        if [ -f $INST_BIN_DIR/opt/quagga/etc/zebra.conf ]; then
            sed -i -- 's/zebra/8 $5$mE$GYmnGvxYcXC7RsgqQNGUa2jvVDDl6\/rjCtduUQL3ei4/g' $INST_BIN_DIR/opt/quagga/etc/zebra.conf
            echo "log record-priority" >> $INST_BIN_DIR/opt/quagga/etc/zebra.conf
            echo "service password-encryption" >> $INST_BIN_DIR/opt/quagga/etc/zebra.conf
            echo "debug zebra events" >> $INST_BIN_DIR/opt/quagga/etc/zebra.conf
            echo "debug zebra fpm" >> $INST_BIN_DIR/opt/quagga/etc/zebra.conf
            echo "debug zebra packet" >> $INST_BIN_DIR/opt/quagga/etc/zebra.conf
        else
    	    touch $INST_BIN_DIR/opt/quagga/etc/zebra.conf
        fi

        if [ -z "$PACKAGING_VERSION" ]; then
	    quagga_version="1.1.0.`date +'%Y%m%d'`"
        else
	    quagga_version="1.1.0.$PACKAGING_VERSION"
        fi

	echo $quagga_version > $INST_BIN_DIR/opt/quagga/etc/quagga.version

        rm -rf $INST_BIN_DIR/../bin
        mkdir -p $INST_BIN_DIR/../bin

        pushd $INST_BIN_DIR
        find ./opt/quagga/lib -name *.so* | xargs tar cf - | tar xf - -C $INST_BIN_DIR/../bin
        find ./opt/quagga/lib -name *.a | xargs tar cf - | tar xf - -C $INST_BIN_DIR/../bin
        find ./opt/quagga/bin | xargs tar cf - | tar xf - -C $INST_BIN_DIR/../bin
        find ./opt/quagga/include | xargs tar cf - | tar xf - -C $INST_BIN_DIR/../bin

        tar cf - ./opt/quagga/etc/bgpd.conf | tar xf - -C $INST_BIN_DIR/../bin
        tar cf - ./opt/quagga/etc/bfdd.conf | tar xf - -C $INST_BIN_DIR/../bin
        tar cf - ./opt/quagga/etc/zebra.conf | tar xf - -C $INST_BIN_DIR/../bin
        tar cf - ./opt/quagga/etc/quagga.version | tar xf - -C $INST_BIN_DIR/../bin
        tar cf - ./opt/quagga/sbin | tar xf - -C $INST_BIN_DIR/../bin
        popd

        mkdir -p $INST_BIN_DIR/../bin/opt/quagga/var/log/quagga
        touch $INST_BIN_DIR/../bin/opt/quagga/var/log/quagga/.dummyqbgp
        mkdir -p $INST_BIN_DIR/../bin/opt/quagga/var/run/quagga
        touch $INST_BIN_DIR/../bin/opt/quagga/var/run/quagga/.dummyqbgp

        pushd $INST_BIN_DIR/../bin
    else
        if [ $PACKAGE_DEB = "n" ]; then
            #For redhat: prepare source for rpmbuild
            prepare_source_for_spec $1
	    pushd $INST_BIN_DIR/../src
        else
            #For debian source copy
            prepare_source_for_deb $1
            pushd $INST_BIN_DIR
        fi
    fi

    if [ $PACKAGE_DEB = "y" ]; then
       #For debian install binary or source
       find . \! -type d | cpio -o -H ustar -R 0:0 | tar -C $DEB_BIN_DIR -x
    fi
    popd
}

quagga_rpm_bin_spec () {

    echo "Name: $1" >> $RPM_SPEC_FILE
    echo "Version: $version" >> $RPM_SPEC_FILE
    if [ $DEV_PACKAGE = "y" ]; then
        echo "Source: %{name}-%{version}.tgz" >> $RPM_SPEC_FILE
    fi
    echo "Release: 0" >> $RPM_SPEC_FILE
    echo >> $RPM_SPEC_FILE

    echo "Summary: Quagga Routing Suite" >> $RPM_SPEC_FILE
    echo "Group: Applications/Internet" >> $RPM_SPEC_FILE
    echo "License: GPL" >> $RPM_SPEC_FILE

    echo "BuildRoot: $RPM_BIN_DIR/BUILD/ROOT" >> $RPM_SPEC_FILE
    case $HOST_NAME in
    RedHat7*)
        QBGP_RPM_DEPS="zmq c-capnproto glib2"
        ;;
    CentOS*|SUSE*)
        QBGP_RPM_DEPS="zmq c-capnproto"
        ;;
    esac
    echo "Requires: $QBGP_RPM_DEPS" >> $RPM_SPEC_FILE
    echo >> $RPM_SPEC_FILE

    echo "%description" >> $RPM_SPEC_FILE
    printf "Quagga is an advanced routing software package that provides a suite of TCP/IP based routing protocols.\n" >> $RPM_SPEC_FILE
    echo >> $RPM_SPEC_FILE

    if [ $DEV_PACKAGE = "y" ]; then
        gen_rpm_src_spec

    else
        echo "%install" >> $RPM_SPEC_FILE
        echo "rm -rf %{buildroot} && mkdir -p %{buildroot}" >> $RPM_SPEC_FILE
        echo "cd $INST_BIN_DIR/../bin && find . \! -type d | cpio -o -H ustar -R 0:0 | tar -C %{buildroot} -x" >> $RPM_SPEC_FILE
        echo "find %{buildroot} -type f -o -type l|sed "s,%{buildroot},," > %{_builddir}/files" >> $RPM_SPEC_FILE
        echo "sed -ri "s/\.py$/\.py*/" %{_builddir}/files" >> $RPM_SPEC_FILE
        echo >> $RPM_SPEC_FILE

        echo "%clean" >> $RPM_SPEC_FILE
        echo "rm -rf %{buildroot}" >> $RPM_SPEC_FILE
        echo >> $RPM_SPEC_FILE

        echo "%pre" >> $RPM_SPEC_FILE
        echo "getent group quagga >/dev/null 2>&1 || groupadd -g 92 quagga >/dev/null 2>&1 || :" >> $RPM_SPEC_FILE
        echo "getent passwd quagga >/dev/null 2>&1 || useradd -u 92 -g 92 -M -r -s /sbin/nologin \\" >> $RPM_SPEC_FILE
        echo " -d /var/run/quagga quagga >/dev/null 2>&1 || :" >> $RPM_SPEC_FILE
        echo >> $RPM_SPEC_FILE

        echo "%postun" >> $RPM_SPEC_FILE
        echo >> $RPM_SPEC_FILE

        echo "%post" >> $RPM_SPEC_FILE
        echo >> $RPM_SPEC_FILE

        echo "%preun" >> $RPM_SPEC_FILE
        echo >> $RPM_SPEC_FILE

        echo "%files -f %{_builddir}/files" >> $RPM_SPEC_FILE
        echo "%defattr(-,root,root)" >> $RPM_SPEC_FILE
        echo "%dir %attr(750,quagga,quagga) /opt/quagga/var/run/quagga" >> $RPM_SPEC_FILE
        echo "%dir %attr(1750,quagga,quagga) /opt/quagga/var/log/quagga" >> $RPM_SPEC_FILE
    fi
}

quagga_deb_bin_control () {
    if [ $DEV_PACKAGE = "y" ]; then
        echo "Package: quagga-src" >> $DEB_CONTROL_FILE
        if [ -z "$COMMITID" ]; then
            echo "Source: quagga-dev (1.1.0.HOST_NAME)" >> $DEB_CONTROL_FILE
            echo "Version: 1.1.0.$HOST_NAME" >> $DEB_CONTROL_FILE
        else
            echo "Source: quagga-dev (1.1.0.$COMMITID.$HOST_NAME)" >> $DEB_CONTROL_FILE
            echo "Version: 1.1.0.$COMMITID.$HOST_NAME" >> $DEB_CONTROL_FILE
        fi
        echo "Bugs : https://github.com/6WIND/quagga/issues" >> $DEB_CONTROL_FILE
    else
        echo "Package: quagga" >> $DEB_CONTROL_FILE
        if [ -z "$COMMITID" ]; then
            echo "Version: 1.1.0.$HOST_NAME" >> $DEB_CONTROL_FILE
        else
            echo "Version: 1.1.0.$COMMITID.$HOST_NAME" >> $DEB_CONTROL_FILE
        fi
    fi
    echo "Architecture: amd64" >> $DEB_CONTROL_FILE
    echo "Maintainer: 6WIND <packaging@6wind.com>" >> $DEB_CONTROL_FILE
    echo "Depends: zmq(>=4.1.0), c-capnproto(>=1.0.0)" >> $DEB_CONTROL_FILE
    echo "Description: Quagga Routing Suite" >> $DEB_CONTROL_FILE
    printf " Quagga is an advanced routing software package that provides a suite of TCP/IP based routing protocols.\n" >> $DEB_CONTROL_FILE

    if [ $DEV_PACKAGE = "n" ]; then
        if [ -f $INST_BIN_DIR/preinst ]; then
            cp $INST_BIN_DIR/preinst $DEB_BIN_DIR/DEBIAN/
        fi

        printf '#!/bin/sh\n' > $DEB_BIN_DIR/DEBIAN/postinst
        printf 'set -e\n' >> $DEB_BIN_DIR/DEBIAN/postinst
        printf 'if [ "$1" = "configure" ]; then\n' >> $DEB_BIN_DIR/DEBIAN/postinst
        printf '  :\n' >> $DEB_BIN_DIR/DEBIAN/postinst
        printf 'fi\n' >> $DEB_BIN_DIR/DEBIAN/postinst
        printf "setcap \'cap_setgid,cap_setuid,cap_net_bind_service,cap_net_admin,cap_net_raw+ep\' /opt/quagga/sbin/bgpd\n" >> $DEB_BIN_DIR/DEBIAN/postinst
        printf "setcap \'cap_setgid,cap_setuid,cap_net_bind_service,cap_net_admin,cap_net_raw+ep\' /opt/quagga/sbin/bfdd\n" >> $DEB_BIN_DIR/DEBIAN/postinst
        printf "setcap \'cap_setgid,cap_setuid,cap_net_bind_service,cap_net_admin,cap_sys_admin,cap_net_raw+ep\' /opt/quagga/sbin/zebra\n" >> $DEB_BIN_DIR/DEBIAN/postinst
        chmod a+x $DEB_BIN_DIR/DEBIAN/postinst

        printf '#!/bin/sh\n' > $DEB_BIN_DIR/DEBIAN/prerm
        printf 'set -e\n' >> $DEB_BIN_DIR/DEBIAN/prerm
        chmod a+x $DEB_BIN_DIR/DEBIAN/prerm

        printf '#!/bin/sh\n' > $DEB_BIN_DIR/DEBIAN/postrm
        printf 'set -e\n' >> $DEB_BIN_DIR/DEBIAN/postrm
        printf 'if [ "$1" = "remove" ]; then\n' >> $DEB_BIN_DIR/DEBIAN/postrm
        printf '  :\n' >> $DEB_BIN_DIR/DEBIAN/postrm
        printf 'fi\n' >> $DEB_BIN_DIR/DEBIAN/postrm
        chmod a+x $DEB_BIN_DIR/DEBIAN/postrm
    fi
}

ccapnproto_copy_bin_files () {

    if [ $DEV_PACKAGE = "y" ]; then
        if [ $PACKAGE_DEB = "n" ]; then
            #For redhat: prepare source for rpmbuild
            prepare_source_for_spec $1
        else
	    #For debian: prepare source
            prepare_source_for_deb $1
        fi
    fi
    #Binary has been installed before
    pushd $INST_BIN_DIR

    if [ $PACKAGE_DEB = "y" ]; then
    #For debian:
       find . \! -type d | cpio -o -H ustar -R 0:0 | tar -C $DEB_BIN_DIR -x
    fi
    popd
}

ccapnproto_rpm_bin_spec () {

    echo "Name: $1" >> $RPM_SPEC_FILE
    echo "Version: $version" >> $RPM_SPEC_FILE
    if [ $DEV_PACKAGE = "y" ]; then
        echo "Source: %{name}-%{version}.tgz" >> $RPM_SPEC_FILE
    fi
    echo "Release: 0" >> $RPM_SPEC_FILE
    echo >> $RPM_SPEC_FILE

    echo "Summary: c-ccapnproto library" >> $RPM_SPEC_FILE
    echo "Group: Applications/Internet" >> $RPM_SPEC_FILE
    echo "License: MIT" >> $RPM_SPEC_FILE

    echo "BuildRoot: $RPM_BIN_DIR/BUILD/ROOT" >> $RPM_SPEC_FILE
    echo >> $RPM_SPEC_FILE

    echo "%description" >> $RPM_SPEC_FILE
    printf "Library for CCAPNPROTO.\nCCAPNPROTO_BUILD_DEPS=''\n" >> $RPM_SPEC_FILE
    echo >> $RPM_SPEC_FILE

    if [ $DEV_PACKAGE = "y" ]; then
        gen_rpm_src_spec

    else
        echo "%install" >> $RPM_SPEC_FILE
        echo "rm -rf %{buildroot} && mkdir -p %{buildroot}" >> $RPM_SPEC_FILE
        echo "cd $INST_BIN_DIR && find . \! -type d | cpio -o -H ustar -R 0:0 | tar -C %{buildroot} -x" >> $RPM_SPEC_FILE
        echo "find %{buildroot} -type f -o -type l|sed "s,%{buildroot},," > %{_builddir}/files" >> $RPM_SPEC_FILE
        echo "sed -ri "s/\.py$/\.py*/" %{_builddir}/files" >> $RPM_SPEC_FILE
        echo >> $RPM_SPEC_FILE

        echo "%clean" >> $RPM_SPEC_FILE
        echo "rm -rf %{buildroot}" >> $RPM_SPEC_FILE
        echo >> $RPM_SPEC_FILE

        echo "%pre" >> $RPM_SPEC_FILE
        echo >> $RPM_SPEC_FILE

        echo "%postun" >> $RPM_SPEC_FILE
        echo >> $RPM_SPEC_FILE

        echo "%post" >> $RPM_SPEC_FILE
        echo >> $RPM_SPEC_FILE

        echo "%preun" >> $RPM_SPEC_FILE
        echo >> $RPM_SPEC_FILE

        echo "%files -f %{_builddir}/files" >> $RPM_SPEC_FILE
        echo "%defattr(-,root,root)" >> $RPM_SPEC_FILE
    fi
}

ccapnproto_deb_bin_control () {
    if [ $DEV_PACKAGE = "y" ]; then
        echo "Package: c-capnproto-src" >> $DEB_CONTROL_FILE
        if [ -z "$COMMITID" ]; then
            echo "Source: c-capnproto-dev (1.0.2.HOST_NAME)" >> $DEB_CONTROL_FILE
            echo "Version: 1.0.2.$HOST_NAME" >> $DEB_CONTROL_FILE
        else
            echo "Source: c-capnproto-dev (1.0.2.$COMMITID.$HOST_NAME)" >> $DEB_CONTROL_FILE
            echo "Version: 1.0.2.$COMMITID.$HOST_NAME" >> $DEB_CONTROL_FILE
        fi
        echo "Bugs : https://github.com/opensourcerouting/c-capnproto/issues" >> $DEB_CONTROL_FILE
    else
        echo "Package: c-capnproto" >> $DEB_CONTROL_FILE
        if [ -z "$COMMITID" ]; then
            echo "Version: 1.0.2.$HOST_NAME" >> $DEB_CONTROL_FILE
        else
            echo "Version: 1.0.2.$COMMITID.$HOST_NAME" >> $DEB_CONTROL_FILE
        fi
    fi
    echo "Architecture: amd64" >> $DEB_CONTROL_FILE
    echo "Maintainer: 6WIND <packaging@6wind.com>" >> $DEB_CONTROL_FILE
    echo "Description: c-ccapnproto library" >> $DEB_CONTROL_FILE
    printf " Library for CCAPNPROTO.\n  CCAPNPROTO_BUILD_DEPS=''\n" >> $DEB_CONTROL_FILE

    if [ $DEV_PACKAGE = "n" ]; then
        printf '#!/bin/sh\n' > $DEB_BIN_DIR/DEBIAN/postinst
        printf 'set -e\n' >> $DEB_BIN_DIR/DEBIAN/postinst
        printf 'if [ "$1" = "configure" ]; then\n' >> $DEB_BIN_DIR/DEBIAN/postinst
        printf '  :\n' >> $DEB_BIN_DIR/DEBIAN/postinst
        printf 'fi\n' >> $DEB_BIN_DIR/DEBIAN/postinst
        chmod a+x $DEB_BIN_DIR/DEBIAN/postinst

        printf '#!/bin/sh\n' > $DEB_BIN_DIR/DEBIAN/prerm
        printf 'set -e\n' >> $DEB_BIN_DIR/DEBIAN/prerm
        chmod a+x $DEB_BIN_DIR/DEBIAN/prerm

        printf '#!/bin/sh\n' > $DEB_BIN_DIR/DEBIAN/postrm
        printf 'set -e\n' >> $DEB_BIN_DIR/DEBIAN/postrm
        printf 'if [ "$1" = "remove" ]; then\n' >> $DEB_BIN_DIR/DEBIAN/postrm
        printf '  :\n' >> $DEB_BIN_DIR/DEBIAN/postrm
        printf 'fi\n' >> $DEB_BIN_DIR/DEBIAN/postrm
        chmod a+x $DEB_BIN_DIR/DEBIAN/postrm
    fi
}

thrift_copy_bin_files () {
    if [ $DEV_PACKAGE = "n" ]; then
	#For debian binary copy
        rm -rf $INST_BIN_DIR/../bin
        mkdir -p $INST_BIN_DIR/../bin

        pushd $INST_BIN_DIR
        find ./opt/quagga/lib -name *.so* | xargs tar cf - | tar xf - -C $INST_BIN_DIR/../bin
        tar cf - ./opt/quagga//bin | tar xf - -C $INST_BIN_DIR/../bin
        popd
        pushd $INST_BIN_DIR/../bin
    else
        if [ $PACKAGE_DEB = "n" ]; then
            #For rpm: rpmbuild's spec extract SOURCES/thrift-$version.tgz then cd to thrift-$version
            prepare_source_for_spec $1
	    pushd $INST_BIN_DIR
        else
            #For debian source copy
            prepare_source_for_deb $1
	    pushd $INST_BIN_DIR
	fi
    fi

    if [ $PACKAGE_DEB = "y" ]; then
       #For debian install binary or source
       find . \! -type d | cpio -o -H ustar -R 0:0 | tar -C $DEB_BIN_DIR -x
    fi
    popd
}

thrift_rpm_bin_spec () {

    echo "Name: $1" >> $RPM_SPEC_FILE
    echo "Version: $version" >> $RPM_SPEC_FILE
    if [ $DEV_PACKAGE = "y" ]; then
        echo "Source: %{name}-%{version}.tgz" >> $RPM_SPEC_FILE
    fi
    echo "Release: 0" >> $RPM_SPEC_FILE
    echo >> $RPM_SPEC_FILE

    echo "Summary: thrift library" >> $RPM_SPEC_FILE
    echo "Group: Applications/Internet" >> $RPM_SPEC_FILE
    echo "License: Apache" >> $RPM_SPEC_FILE

    echo "BuildRoot: $RPM_BIN_DIR/BUILD/ROOT" >> $RPM_SPEC_FILE
    case $HOST_NAME in
    SUSE*)
        THRIFT_RPM_DEPS="libgobject-2_0-0"
        ;;
    esac
    if [ -n "$THRIFT_RPM_DEPS" ]; then
        echo "Requires: $THRIFT_RPM_DEPS" >> $RPM_SPEC_FILE
    fi
    echo >> $RPM_SPEC_FILE

    echo "%description" >> $RPM_SPEC_FILE
    echo "Library for THRIFT. THRIFT_BUILD_DEPS=''" >> $RPM_SPEC_FILE
    echo >> $RPM_SPEC_FILE

    if [ $DEV_PACKAGE = "y" ]; then
        gen_rpm_src_spec

    else
        echo "%install" >> $RPM_SPEC_FILE
        echo "rm -rf %{buildroot} && mkdir -p %{buildroot}" >> $RPM_SPEC_FILE
        echo "cd $INST_BIN_DIR/../bin && find . \! -type d | cpio -o -H ustar -R 0:0 | tar -C %{buildroot} -x" >> $RPM_SPEC_FILE
        echo "find %{buildroot} -type f -o -type l|sed "s,%{buildroot},," > %{_builddir}/files" >> $RPM_SPEC_FILE
        echo "sed -ri "s/\.py$/\.py*/" %{_builddir}/files" >> $RPM_SPEC_FILE
        echo >> $RPM_SPEC_FILE

        echo "%clean" >> $RPM_SPEC_FILE
        echo "rm -rf %{buildroot}" >> $RPM_SPEC_FILE
        echo >> $RPM_SPEC_FILE

        echo "%pre" >> $RPM_SPEC_FILE
        echo >> $RPM_SPEC_FILE

        echo "%postun" >> $RPM_SPEC_FILE
        echo >> $RPM_SPEC_FILE

        echo "%post" >> $RPM_SPEC_FILE
        echo >> $RPM_SPEC_FILE

        echo "%preun" >> $RPM_SPEC_FILE
        echo >> $RPM_SPEC_FILE

        echo "%files -f %{_builddir}/files" >> $RPM_SPEC_FILE
        echo "%defattr(-,root,root)" >> $RPM_SPEC_FILE
    fi
}

thrift_deb_bin_control () {
    if [ $DEV_PACKAGE = "y" ]; then
        echo "Package: thrift-src" >> $DEB_CONTROL_FILE
        if [ -z "$COMMITID" ]; then
            echo "Source: thrift-dev (1.0.0.HOST_NAME)" >> $DEB_CONTROL_FILE
            echo "Version: 1.0.0.$HOST_NAME" >> $DEB_CONTROL_FILE
        else
            echo "Source: thrift-dev (1.0.0.$COMMITID.$HOST_NAME)" >> $DEB_CONTROL_FILE
            echo "Version: 1.0.0.$COMMITID.$HOST_NAME" >> $DEB_CONTROL_FILE
        fi
        echo "Bugs : https://jira.apache.org/jira/projects/THRIFT/issues" >> $DEB_CONTROL_FILE
    else
        echo "Package: thrift" >> $DEB_CONTROL_FILE
        if [ -z "$COMMITID" ]; then
            echo "Version: 1.0.0.$HOST_NAME" >> $DEB_CONTROL_FILE
        else
            echo "Version: 1.0.0.$COMMITID.$HOST_NAME" >> $DEB_CONTROL_FILE
        fi
    fi
    echo "Architecture: amd64" >> $DEB_CONTROL_FILE
    echo "Maintainer: 6WIND <packaging@6wind.com>" >> $DEB_CONTROL_FILE
    echo "Depends: libglib2.0-0(>=2.22.5)" >> $DEB_CONTROL_FILE
    echo "Description: thrift library" >> $DEB_CONTROL_FILE
    printf " Library for THRIFT.\n  THRIFT_BUILD_DEPS=''\n" >> $DEB_CONTROL_FILE

    if [ $DEV_PACKAGE = "n" ]; then
        printf '#!/bin/sh\n' > $DEB_BIN_DIR/DEBIAN/postinst
        printf 'set -e\n' >> $DEB_BIN_DIR/DEBIAN/postinst
        printf 'if [ "$1" = "configure" ]; then\n' >> $DEB_BIN_DIR/DEBIAN/postinst
        printf '  :\n' >> $DEB_BIN_DIR/DEBIAN/postinst
        printf 'fi\n' >> $DEB_BIN_DIR/DEBIAN/postinst
        chmod a+x $DEB_BIN_DIR/DEBIAN/postinst

        printf '#!/bin/sh\n' > $DEB_BIN_DIR/DEBIAN/prerm
        printf 'set -e\n' >> $DEB_BIN_DIR/DEBIAN/prerm
        chmod a+x $DEB_BIN_DIR/DEBIAN/prerm

        printf '#!/bin/sh\n' > $DEB_BIN_DIR/DEBIAN/postrm
        printf 'set -e\n' >> $DEB_BIN_DIR/DEBIAN/postrm
        printf 'if [ "$1" = "remove" ]; then\n' >> $DEB_BIN_DIR/DEBIAN/postrm
        printf '  :\n' >> $DEB_BIN_DIR/DEBIAN/postrm
        printf 'fi\n' >> $DEB_BIN_DIR/DEBIAN/postrm
        chmod a+x $DEB_BIN_DIR/DEBIAN/postrm
    fi
}

zmq_copy_bin_files () {

    if [ $DEV_PACKAGE = "n" ]; then
        rm -rf $INST_BIN_DIR/../bin
        mkdir -p $INST_BIN_DIR/../bin

        pushd $INST_BIN_DIR
        find ./opt/quagga/lib -name *.so* | xargs tar cf - | tar xf - -C $INST_BIN_DIR/../bin
        tar cf - ./opt/quagga/bin | tar xf - -C $INST_BIN_DIR/../bin
        popd
        pushd $INST_BIN_DIR/../bin
    else
        if [ $PACKAGE_DEB = "n" ]; then
	    #For redhat: prepare for source
            prepare_source_for_spec $1
        else
            #For debian: prepare for source
            prepare_source_for_deb $1
        fi
	pushd $INST_BIN_DIR/../src
    fi
    if [ $PACKAGE_DEB = "y" ]; then
       find . \! -type d | cpio -o -H ustar -R 0:0 | tar -C $DEB_BIN_DIR -x
    fi
    popd
}

zmq_rpm_bin_spec () {

    echo "Name: $1" >> $RPM_SPEC_FILE
    echo "Version: $version" >> $RPM_SPEC_FILE
    if [ $DEV_PACKAGE = "y" ]; then
        echo "Source:  %{name}-%{version}.tgz" >> $RPM_SPEC_FILE
    fi
    echo "Release: 0" >> $RPM_SPEC_FILE
    echo >> $RPM_SPEC_FILE

    echo "Summary: ZMQ library" >> $RPM_SPEC_FILE
    echo "Group: Applications/Internet" >> $RPM_SPEC_FILE
    echo "License: GPLv3" >> $RPM_SPEC_FILE

    echo "BuildRoot: $RPM_BIN_DIR/BUILD/ROOT" >> $RPM_SPEC_FILE
    echo >> $RPM_SPEC_FILE

    echo "%description" >> $RPM_SPEC_FILE
    printf "Zero Message Queue Library.\nZMQ_BUILD_DEPS=''\n" >> $RPM_SPEC_FILE
    echo >> $RPM_SPEC_FILE
    if [ $DEV_PACKAGE = "y" ]; then
        gen_rpm_src_spec

    else
        echo "%install" >> $RPM_SPEC_FILE
        echo "rm -rf %{buildroot} && mkdir -p %{buildroot}" >> $RPM_SPEC_FILE
        echo "cd $INST_BIN_DIR/../bin && find . \! -type d | cpio -o -H ustar -R 0:0 | tar -C %{buildroot} -x" >> $RPM_SPEC_FILE
        echo "find %{buildroot} -type f -o -type l|sed "s,%{buildroot},," > %{_builddir}/files" >> $RPM_SPEC_FILE
        echo "sed -ri "s/\.py$/\.py*/" %{_builddir}/files" >> $RPM_SPEC_FILE
        echo >> $RPM_SPEC_FILE

        echo "%clean" >> $RPM_SPEC_FILE
        echo "rm -rf %{buildroot}" >> $RPM_SPEC_FILE
        echo >> $RPM_SPEC_FILE

        echo "%pre" >> $RPM_SPEC_FILE
        echo >> $RPM_SPEC_FILE

        echo "%postun" >> $RPM_SPEC_FILE
        echo >> $RPM_SPEC_FILE

        echo "%post" >> $RPM_SPEC_FILE
        echo >> $RPM_SPEC_FILE

        echo "%preun" >> $RPM_SPEC_FILE
        echo >> $RPM_SPEC_FILE

        echo "%files -f %{_builddir}/files" >> $RPM_SPEC_FILE
        echo "%defattr(-,root,root)" >> $RPM_SPEC_FILE
    fi
}

zmq_deb_bin_control () {
    if [ $DEV_PACKAGE = "y" ]; then
        echo "Package: zmq-src" >> $DEB_CONTROL_FILE
        if [ -z "$COMMITID" ]; then
            echo "Source: zmq-dev (4.1.3.HOST_NAME)" >> $DEB_CONTROL_FILE
            echo "Version: 4.1.3.$HOST_NAME" >> $DEB_CONTROL_FILE
        else
            echo "Source: zmq-dev (4.1.3.$COMMITID.$HOST_NAME)" >> $DEB_CONTROL_FILE
            echo "Version: 4.1.3.$COMMITID.$HOST_NAME" >> $DEB_CONTROL_FILE
        fi
        echo "Bugs : https://github.com/zeromq/libzmq/issues" >> $DEB_CONTROL_FILE
    else
        echo "Package: zmq" >> $DEB_CONTROL_FILE
        if [ -z "$COMMITID" ]; then
            echo "Version: 4.1.3.$HOST_NAME" >> $DEB_CONTROL_FILE
        else
            echo "Version: 4.1.3.$COMMITID.$HOST_NAME" >> $DEB_CONTROL_FILE
        fi
    fi
    echo "Architecture: amd64" >> $DEB_CONTROL_FILE
    echo "Maintainer: 6WIND <packaging@6wind.com>" >> $DEB_CONTROL_FILE
    echo "Description: ZMQ library" >> $DEB_CONTROL_FILE
    printf " Zero Message Queue Library.\n  ZMQ_BUILD_DEPS=''\n" >> $DEB_CONTROL_FILE

    if [ $DEV_PACKAGE = "n" ]; then
        printf '#!/bin/sh\n' > $DEB_BIN_DIR/DEBIAN/postinst
        printf 'set -e\n' >> $DEB_BIN_DIR/DEBIAN/postinst
        printf 'if [ "$1" = "configure" ]; then\n' >> $DEB_BIN_DIR/DEBIAN/postinst
        printf '  :\n' >> $DEB_BIN_DIR/DEBIAN/postinst
        printf 'fi\n' >> $DEB_BIN_DIR/DEBIAN/postinst
        chmod a+x $DEB_BIN_DIR/DEBIAN/postinst

        printf '#!/bin/sh\n' > $DEB_BIN_DIR/DEBIAN/prerm
        printf 'set -e\n' >> $DEB_BIN_DIR/DEBIAN/prerm
        chmod a+x $DEB_BIN_DIR/DEBIAN/prerm

        printf '#!/bin/sh\n' > $DEB_BIN_DIR/DEBIAN/postrm
        printf 'set -e\n' >> $DEB_BIN_DIR/DEBIAN/postrm
        printf 'if [ "$1" = "remove" ]; then\n' >> $DEB_BIN_DIR/DEBIAN/postrm
        printf '  :\n' >> $DEB_BIN_DIR/DEBIAN/postrm
        printf 'fi\n' >> $DEB_BIN_DIR/DEBIAN/postrm
        chmod a+x $DEB_BIN_DIR/DEBIAN/postrm
    fi
}

substr="-src"
if [[  ${1} =~ $substr ]]; then
    DEV_PACKAGE="y"
else
    DEV_PACKAGE="n"
fi
echo "HOST_NAME=$HOST_NAME"
echo "DEV_PKG=$DEV_PACKAGE"

case $HOST_NAME in
Ubuntu*)
    PACKAGE_DEB="y"
    if [ $DEV_PACKAGE = "y" ]; then
        DEB_BIN_DIR=$3/deb/src
    else
        DEB_BIN_DIR=$3/deb/bin
    fi
    mkdir -p $DEB_BIN_DIR/DEBIAN
    DEB_CONTROL_FILE=$DEB_BIN_DIR/DEBIAN/control
    rm -f $DEB_CONTROL_FILE
    if [ $1 = "zrpc" -o $1 = "zrpc-src" ]; then
        zrpc_copy_bin_files $1
        zrpc_deb_bin_control
    elif [ $1 = "quagga" -o $1 = "quagga-src" ]; then
        quagga_copy_bin_files $1
        quagga_deb_bin_control
    elif [ $1 = "c-capnproto" -o $1 = "c-capnproto-src" ]; then
        ccapnproto_copy_bin_files $1
        ccapnproto_deb_bin_control
    elif [ $1 = "thrift" -o $1 = "thrift-src" ]; then
        thrift_copy_bin_files $1
        thrift_deb_bin_control
    elif [ $1 = "zmq" -o $1 = "zmq-src" ]; then
        zmq_copy_bin_files $1
        zmq_deb_bin_control
    fi

    PKG_DIR=`dirname $0`
    fakeroot dpkg-deb -b $DEB_BIN_DIR $PKG_DIR
    ;;
RedHat*|CentOS*|SUSE*)
    if [ $DEV_PACKAGE = "y" ]; then
        RPM_BIN_DIR=$3/rpm/src
        mkdir -p $RPM_BIN_DIR/SOURCES
    else
        RPM_BIN_DIR=$3/rpm/bin
    fi
    mkdir -p $RPM_BIN_DIR/BUILD
    mkdir -p $RPM_BIN_DIR/SPECS

    RPM_SPEC_FILE=$RPM_BIN_DIR/SPECS/rpm.spec
    rm -f $RPM_SPEC_FILE

    if [ $1 = "zrpc" -o $1 = "zrpc-src" ]; then
        if [ -z "$COMMITID" ]; then
            version="0.2.$HOST_NAME"
        else
            version="0.2.$COMMITID.$HOST_NAME"
        fi
        zrpc_copy_bin_files $1
        zrpc_rpm_bin_spec $1
    elif [ $1 = "quagga" -o $1 = "quagga-src" ]; then
        if [ -z "$COMMITID" ]; then
            version="1.1.0.$HOST_NAME"
        else
            version="1.1.0.$COMMITID.$HOST_NAME"
        fi
        quagga_copy_bin_files $1
        quagga_rpm_bin_spec $1
    elif [ $1 = "c-capnproto" -o $1 = "c-capnproto-src" ]; then
        if [ -z "$COMMITID" ]; then
            version="1.0.2.$HOST_NAME"
        else
            version="1.0.2.$COMMITID.$HOST_NAME"
        fi
        ccapnproto_copy_bin_files $1
        ccapnproto_rpm_bin_spec $1
    elif [ $1 = "thrift" -o $1 = "thrift-src" ]; then
        if [ -z "$COMMITID" ]; then
            version="1.1.0.$HOST_NAME"
        else
            version="1.1.0.$COMMITID.$HOST_NAME"
        fi
        thrift_copy_bin_files $1
        thrift_rpm_bin_spec $1
    elif [ $1 = "zmq" -o $1 = "zmq-src" ]; then
        if [ -z "$COMMITID" ]; then
            version="4.1.3.$HOST_NAME"
        else
            version="4.1.3.$COMMITID.$HOST_NAME"
        fi
        zmq_copy_bin_files $1
        zmq_rpm_bin_spec $1
    fi

    PKG_DIR=`dirname $0`
    build_type="-bb"
    if [ $DEV_PACKAGE = "y" ]; then
        build_type="-bs"
    fi
    rpmbuild ${build_type} --define "_topdir $RPM_BIN_DIR" \
             --define "_rpmdir $PKG_DIR" \
             --define '_rpmfilename %%{NAME}-%%{VERSION}-%%{RELEASE}.%%{ARCH}.rpm' \
             --define 'debug_package %{nil}' $RPM_SPEC_FILE
    if [ $DEV_PACKAGE = "y" ]; then
        cp -f $RPM_BIN_DIR/SRPMS/$1*.src.rpm $PKG_DIR/
    fi
    ;;
*)
    echo "unsupported distribution $HOST_NAME"
    exit 1
esac
