# Copyright 2016 Tata Consulting and Ericsson
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
ZRPCD_BUILD_FOLDER=${ZRPCD_BUILD_FOLDER:-/tmp}
THRIFT_FOLDER_NAME=thrift
THRIFT_BUILD_FOLDER=$ZRPCD_BUILD_FOLDER/$THRIFT_FOLDER_NAME

DIR_NAME=`dirname $0`

export_variables (){
    #these are required by quagga
    export ZEROMQ_CFLAGS="-I"$ZRPCD_BUILD_FOLDER"/zeromq4-1/include"
    export ZEROMQ_LIBS="-L"$ZRPCD_BUILD_FOLDER"/zeromq4-1/.libs/ -lzmq"
    export CAPN_C_CFLAGS='-I'$ZRPCD_BUILD_FOLDER'/c-capnproto/lib'
    export CAPN_C_LIBS='-L'$ZRPCD_BUILD_FOLDER'/c-capnproto/.libs/ -lcapnp_c'
    #In addition to the above, zrpcd requires these flags too.
    export QUAGGA_CFLAGS='-I'$ZRPCD_BUILD_FOLDER'/quagga/lib/'
    export QUAGGA_LIBS='-L'$ZRPCD_BUILD_FOLDER'/quagga/lib/.libs/. -lzebra'
    export THRIFT_CFLAGS="-I"$THRIFT_BUILD_FOLDER"/lib/c_glib/src/thrift/c_glib/ -I"$THRIFT_BUILD_FOLDER"/lib/c_glib/src"
    export THRIFT_LIBS="-L'$THRIFT_BUILD_FOLDER'/lib/c_glib/.libs/ -lthrift_c_glib"
    export THRIFT_PATH="$THRIFT_BUILD_FOLDER/compiler/cpp"
    export THRIFT_LIB_PATH="$THRIFT_BUILD_FOLDER/lib/c_glib/.libs"
}
install_deps() {
    pushd $ZRPCD_BUILD_FOLDER
    export_variables
#Install the required software for building quagga
    for i in {0..5}
    do
    	echo "Attempt $i of installing dependencies..."
        if ! [ -x "$(command -v facter)" ]; then
           echo 'Error: facter is not installed.' >&2
           echo "Facter  is installing now" 
           apt-get install -y facter || yum -y install facter || zypper install -y facter ;
        else
           echo "facter is already installed"
        fi
        distrib=`facter operatingsystem`
        version=`facter operatingsystemrelease`

        if [ $distrib = "Ubuntu" ]; then
           HOST_NAME=Ubuntu$version
           echo "its a Ubuntu-Host:$HOST_NAME " ;
        elif [ $distrib = "CentOS" ] ; then
           HOST_NAME=CentOS$version
           echo "its a CentOS-Host:$HOST_NAME" ;
        elif [ $distrib = "RedHat" ] ; then
           HOST_NAME=RedHat$version
           echo "its a RedHat-Host:$HOST_NAME" ;
        elif [ $distrib = "SUSE" ] ; then
           HOST_NAME=SUSE$version
           echo "its a SUSE-Host:$HOST_NAME" ;
        fi
    	case $HOST_NAME in
    	Ubuntu14*)
        	echo "UBUNTU 14.04 VM"
                for pkg in automake bison flex g++ git libboost1.55-all-dev libevent-dev libssl-dev libtool make pkg-config gawk libreadline-dev libglib2.0-dev wget
                do 
                      if [ $(dpkg-query -W -f='${Status}' $pkg 2>/dev/null | grep -c "ok installed") -eq 0 ]; then
                          apt-get install $pkg -y --force-yes
                      fi
                done
      	      ;;
    	Ubuntu16.04*)
         	echo "UBUNTU 16.04 VM"
         	for pkg in automake bison flex g++ git libboost1.58-all-dev libevent-dev libssl-dev libtool make pkg-config gawk libreadline-dev libglib2.0-dev wget
                do
                      if [ $(dpkg-query -W -f='${Status}' $pkg 2>/dev/null | grep -c "ok installed") -eq 0 ]; then
                           apt-cache policy $pkg
                           apt-get install $pkg -y --force-yes
                      fi
                done
       	      ;;
        Ubuntu16*|Ubuntu17* )
                echo "UBUNTU 16.*/17.* VM"
                for pkg in automake bison flex g++ git  libevent-dev libssl-dev libtool make pkg-config gawk libreadline-dev libglib2.0-dev wget
                do
                      if [ $(dpkg-query -W -f='${Status}' $pkg 2>/dev/null | grep -c "ok installed") -eq 0 ]; then
                           apt-cache policy $pkg
                           apt-get install $pkg -y --force-yes
                      fi
                done
              ;;

    	CentOS*)
         	echo "CENTOS VM"
                yum -y group install "Development Tools"
                for pkg in readline readline-devel glib2-devel autoconf* bison* libevent-devel zlib-devel openssl-devel  boost*
                do
                      if [ $(rpm -q $pkg | grep -c "not installed") -eq 1 ]; then
                            yum -y install $pkg
                      fi
                done
       	      ;;

        RedHat7*)
                echo "REDHAT VM"
                yum -y group install "Development Tools"
                for pkg in readline readline-devel glib2 glib2-devel autoconf* bison* libevent-devel zlib-devel openssl-devel boost* wget
                do
                      if [ $(rpm -q $pkg | grep -c "not installed") -eq 1 ]; then
                            yum -y install $pkg
                      fi
                done
              ;;
        SUSE*)
                echo "SUSE VM"
                for pkg in glibc-devel pcre-devel gcc automake libtool perl-Error git-core git flex bison emacs glib2-tools \
			libglib-2_0-0-debuginfo glibc-devel-static glib2-devel gcc48-c++
                do
                      if [ $(rpm -q $pkg | grep -c "not installed") -eq 1 ]; then
                            zypper install $pkg
                      fi
                done
              ;;

    	esac
    done
#Clean the directory
    rm -rf c-capnproto $THRIFT_FOLDER_NAME zeromq4-1 quagga zrpcd
#Install thrift
    git clone http://git-wip-us.apache.org/repos/asf/thrift.git
    cd $THRIFT_FOLDER_NAME
    git checkout 0.10.0
    wget https://issues.apache.org/jira/secure/attachment/12840512/0001-THRIFT-3987-externalise-declaration-of-thrift-server.patch
    patch -p1 < 0001-THRIFT-3987-externalise-declaration-of-thrift-server.patch
    wget https://issues.apache.org/jira/secure/attachment/12840511/0002-THRIFT-3986-using-autoreconf-i-fails-because-of-miss.patch
    patch -p1 < 0002-THRIFT-3986-using-autoreconf-i-fails-because-of-miss.patch

    autoreconf -i
    ./configure --without-qt4 --without-qt6 --without-csharp --without-java\
    --without-erlang --without-nodejs --without-perl --without-python\
    --without-php --without-php_extension --without-dart --without-ruby\
    --without-haskell --without-go --without-haxe --without-d\
    --prefix=/opt/quagga
    make
    if [ -z "$DO_PACKAGING" ]; then
        make install
        popd
    else
        INSTALL_DIR=$ZRPCD_BUILD_FOLDER/packager/thrift/install_tmp
        THRIFT_DIR=$ZRPCD_BUILD_FOLDER/packager/thrift
        rm -rf $INSTALL_DIR
        rm -rf $THRIFT_DIR
        make install DESTDIR=$INSTALL_DIR
        COMMITID=`git log -n1 --format="%h"`

        popd
        $DIR_NAME/packaging.sh "thrift" $INSTALL_DIR $THRIFT_DIR $HOST_NAME $COMMITID
    fi
#Install ZeroMQ
    pushd $ZRPCD_BUILD_FOLDER
    git clone https://github.com/zeromq/zeromq4-1.git
    cd zeromq4-1
    git checkout 56b71af22db3
    autoreconf -i
    ./configure --without-libsodium --prefix=/opt/quagga
    make
    if [ -z "$DO_PACKAGING" ]; then
        make install
        popd
    else
        INSTALL_DIR=$ZRPCD_BUILD_FOLDER/packager/zmq/install_tmp
        ZMQ_DIR=$ZRPCD_BUILD_FOLDER/packager/zmq
        rm -rf $INSTALL_DIR
        rm -rf $ZMQ_DIR
        make install DESTDIR=$INSTALL_DIR
        COMMITID=`git log -n1 --format="%h"`

        popd
        $DIR_NAME/packaging.sh "zmq" $INSTALL_DIR $ZMQ_DIR $HOST_NAME $COMMITID
    fi
#Install C-capnproto
     pushd $ZRPCD_BUILD_FOLDER
     git clone https://github.com/opensourcerouting/c-capnproto
     cd c-capnproto
     git checkout c-capnproto-0.2
     mkdir -p gtest/googletest
     autoreconf -fiv
     ./configure --prefix=/opt/quagga --without-gtest
     make
     if [ -z "$DO_PACKAGING" ]; then
         make install
         popd
     else
         INSTALL_DIR=$ZRPCD_BUILD_FOLDER/packager/c-capnproto/bin
         CCAPNPROTO_DIR=$ZRPCD_BUILD_FOLDER/packager/c-capnproto
         rm -rf $INSTALL_DIR
         rm -rf $CCAPNPROTO_DIR
         make install DESTDIR=$INSTALL_DIR
         COMMITID=`git log -n1 --format="%h"`

         popd
         $DIR_NAME/packaging.sh "c-capnproto" $INSTALL_DIR $CCAPNPROTO_DIR $HOST_NAME $COMMITID
     fi
#Install Quagga

    pushd $ZRPCD_BUILD_FOLDER
    if [ -z "$DO_PACKAGING" ]; then
        INSTALL_DIR=
    else
        INSTALL_DIR=$ZRPCD_BUILD_FOLDER/packager/quagga/install_tmp
        QUAGGA_DIR=$ZRPCD_BUILD_FOLDER/packager/quagga
        rm -rf $INSTALL_DIR
        rm -rf $QUAGGA_DIR
    fi
    git clone https://github.com/6WIND/quagga.git
    cd quagga
    git checkout quagga_mpbgp_capnp
    autoreconf -i
    LIBS='-L'$ZRPCD_BUILD_FOLDER'/zeromq4-1/.libs/ -L'$ZRPCD_BUILD_FOLDER'/c-capnproto/.libs/' \
    ./configure --with-zeromq --with-ccapnproto --prefix=/opt/quagga --enable-user=quagga \
    --enable-group=quagga --enable-vty-group=quagga --localstatedir=/opt/quagga/var/run/quagga \
    --disable-doc --enable-multipath=64
    make
    if [ -z "$DO_PACKAGING" ]; then
        make install
    else
        make install DESTDIR=$INSTALL_DIR
        COMMITID=`git log -n1 --format="%h"`
    fi
    cd ..
    popd

    cp $INSTALL_DIR/opt/quagga/etc/bgpd.conf.sample4 $INSTALL_DIR/opt/quagga/etc/bgpd.conf
    mkdir $INSTALL_DIR/opt/quagga/var/run/quagga -p
    mkdir $INSTALL_DIR/opt/quagga/var/log/quagga -p
    if [ -z "$DO_PACKAGING" ]; then
        touch /opt/quagga/var/log/quagga/zrpcd.init.log
        if [ $distrib = "Ubuntu" ]; then
            HOST_NAME=Ubuntu$version
            echo "its a Ubuntu-Host:$HOST_NAME " ;
        elif [ $distrib = "CentOS" ] ; then
            HOST_NAME=CentOS$version
            echo "its a CentOS-Host:$HOST_NAME" ;
        elif [ $distrib = "RedHat" ] ; then
            HOST_NAME=RedHat$version
            echo "its a RedHat-Host:$HOST_NAME" ;
        elif [ $distrib = "SUSE" ] ; then
            HOST_NAME=SUSE$version
            echo "its a SUSE-Host:$HOST_NAME" ;
        fi
        case $HOST_NAME in
        Ubuntu*)
             echo "UBUNTU VM"
             addgroup --system quagga
             addgroup --system quagga
             adduser --system --ingroup quagga --home /opt/quagga/var/run/quagga \
                     --gecos "Quagga-BGP routing suite" \
                    --shell /bin/false quagga  >/dev/null
            ;;
        CentOS*)
             echo "CENTOS VM"
             groupadd --system quagga
             adduser --system --gid quagga --home /opt/quagga/var/run/quagga \
                    --comment  "Quagga-BGP routing suite" \
                    --shell /bin/false quagga
            ;;
        RedHat*)
             echo "REDHAT VM"
             if [ $(grep -c "quagga" /etc/group) -eq 0 ]; then
                 groupadd --system quagga
                 adduser --system --gid quagga --home /opt/quagga/var/run/quagga \
                        --comment  "Quagga-BGP routing suite" \
                        --shell /bin/false quagga
             fi
            ;;
        SUSE*)
             echo "SUSE VM"
             if [ $(grep -c "quagga" /etc/group) -eq 0 ]; then
                 groupadd --system quagga
                 useradd --system --gid quagga --home /opt/quagga/var/run/quagga \
                        --comment  "Quagga-BGP routing suite" \
                        --shell /bin/false quagga
             fi
            ;;
        esac
        chown -R quagga:quagga /opt/quagga/var/run/quagga
        chown -R quagga:quagga /opt/quagga/var/log/quagga
    else
        case $HOST_NAME in
        Ubuntu*)
            if [ -f $DIR_NAME/preinst ]; then
                cp $DIR_NAME/preinst $INSTALL_DIR/
            fi
            ;;
        esac
        $DIR_NAME/packaging.sh "quagga" $INSTALL_DIR $QUAGGA_DIR $HOST_NAME $COMMITID
    fi
}
build_zrpcd (){
#Install ZRPC.
    export_variables
    distrib=`facter operatingsystem`
    version=`facter operatingsystemrelease`

    if [ -z "$DO_PACKAGING" ]; then
        INSTALL_DIR=
    else
        INSTALL_DIR=$ZRPCD_BUILD_FOLDER/packager/zrpc/bin
        ZRPC_DIR=$ZRPCD_BUILD_FOLDER/packager/zrpc
        rm -rf $INSTALL_DIR
        rm -rf $ZRPC_DIR
    fi

    if [ -z "${BUILD_FROM_DIST}" ]; then
        pushd $ZRPCD_BUILD_FOLDER
        git clone https://github.com/6WIND/zrpcd.git
        cd zrpcd
    elif [ -n "${DIST_ARCHIVE}" ]; then
        tar zxvf $DIST_ARCHIVE
        cd "${DIST_ARCHIVE%.tar.gz}"
    else
        # prepare the dist archive
        # assume we are on root folder of zrpcd
        touch NEWS README
        autoreconf -i
        LD_LIBRARY_PATH=$LD_LIBRARY_PATH:$THRIFT_LIB_PATH:$ZRPCD_BUILD_FOLDER/zeromq4-1/.libs/:$ZRPCD_BUILD_FOLDER/c-capnproto/.libs/:$ZRPCD_BUILD_FOLDER/quagga/lib/.libs/ LIBS='-L'$ZRPCD_BUILD_FOLDER'/zeromq4-1/.libs/ -lzmq -L'$ZRPCD_BUILD_FOLDER'/c-capnproto/.libs/ -lcapnp_c -L'$ZRPCD_BUILD_FOLDER'/quagga/lib/.libs/ -lzebra' PATH=$PATH:$THRIFT_PATH ./configure --prefix=/opt/quagga --enable-user=quagga --enable-group=quagga --enable-vty-group=quagga --localstatedir=/opt/quagga/var/run/quagga --with-thrift-version=$THRIFT_VERSION
        LD_LIBRARY_PATH=$LD_LIBRARY_PATH:$THRIFT_LIB_PATH PATH=$PATH:$THRIFT_PATH make dist
        DIST_ARCHIVE=$(ls *.tar.gz)
        tar zxvf $DIST_ARCHIVE
        cd "${DIST_ARCHIVE%.tar.gz}"
        cd ..
        mkdir $INSTALL_DIR/opt/quagga/etc/init.d -p
        if [ $distrib = "Ubuntu" ]; then
           HOST_NAME=Ubuntu$version
           echo "its a Ubuntu-Host:$HOST_NAME " ;
        elif [ $distrib = "CentOS" ] ; then
           HOST_NAME=CentOS$version
           echo "its a CentOS-Host:$HOST_NAME" ;
        elif [ $distrib = "RedHat" ] ; then
           HOST_NAME=RedHat$version
           echo "its a RedHat-Host:$HOST_NAME" ;
        elif [ $distrib = "SUSE" ] ; then
           HOST_NAME=SUSE$version
           echo "its a SUSE-Host:$HOST_NAME" ;
        fi         
        case $HOST_NAME in
        Ubuntu*)
             cp pkgsrc/zrpcd.ubuntu $INSTALL_DIR/opt/quagga/etc/init.d/zrpcd
           ;;
        CentOS*)
              cp pkgsrc/zrpcd.centos $INSTALL_DIR/opt/quagga/etc/init.d/zrpcd
           ;;
        RedHat*)
              cp pkgsrc/zrpcd.redhat7 $INSTALL_DIR/opt/quagga/etc/init.d/zrpcd
              if [ -d pkgsrc/systemd ]; then
                  mkdir $INSTALL_DIR/usr/lib/systemd/system -p
                  cp -p pkgsrc/systemd/qbgp.service $INSTALL_DIR/usr/lib/systemd/system
                  mkdir $INSTALL_DIR/etc/sysconfig -p
                  cp -p pkgsrc/systemd/qbgp $INSTALL_DIR/etc/sysconfig
              fi
           ;;
        SUSE*)
              cp pkgsrc/zrpcd.suse $INSTALL_DIR/opt/quagga/etc/init.d/zrpcd
           ;;
        esac
        chmod +x $INSTALL_DIR/opt/quagga/etc/init.d/zrpcd
        if [ -f pkgsrc/zrpcd_log_rotate.sh ]; then
            cp pkgsrc/zrpcd_log_rotate.sh $INSTALL_DIR/opt/quagga/etc/init.d/
        fi
        if [ -f pkgsrc/zrpcd.rotate ]; then
            cp pkgsrc/zrpcd.rotate $INSTALL_DIR/opt/quagga/etc/init.d/
        fi
    fi
    touch NEWS README
    autoreconf -i
    LD_LIBRARY_PATH=$LD_LIBRARY_PATH:$THRIFT_LIB_PATH:$ZRPCD_BUILD_FOLDER/zeromq4-1/.libs/:$ZRPCD_BUILD_FOLDER/c-capnproto/.libs/:$ZRPCD_BUILD_FOLDER/quagga/lib/.libs/ LIBS='-L'$ZRPCD_BUILD_FOLDER'/zeromq4-1/.libs/ -lzmq -L'$ZRPCD_BUILD_FOLDER'/c-capnproto/.libs/ -lcapnp_c -L'$ZRPCD_BUILD_FOLDER'/quagga/lib/.libs/ -lzebra' PATH=$PATH:$THRIFT_PATH ./configure --prefix=/opt/quagga --enable-user=quagga --enable-group=quagga --enable-vty-group=quagga --localstatedir=/opt/quagga/var/run/quagga --with-thrift-version=$THRIFT_VERSION
    LD_LIBRARY_PATH=$LD_LIBRARY_PATH:$THRIFT_LIB_PATH:$ZRPCD_BUILD_FOLDER/zeromq4-1/.libs/:$ZRPCD_BUILD_FOLDER/c-capnproto/.libs/:$ZRPCD_BUILD_FOLDER/quagga/lib/.libs/ PATH=$PATH:$THRIFT_PATH make
    if [ -z "$DO_PACKAGING" ]; then
        LD_LIBRARY_PATH=$LD_LIBRARY_PATH:$THRIFT_LIB_PATH:$ZRPCD_BUILD_FOLDER/zeromq4-1/.libs/:$ZRPCD_BUILD_FOLDER/c-capnproto/.libs/:$ZRPCD_BUILD_FOLDER/quagga/lib/.libs/ PATH=$PATH:$THRIFT_PATH make install
    else
        LD_LIBRARY_PATH=$LD_LIBRARY_PATH:$THRIFT_LIB_PATH:$ZRPCD_BUILD_FOLDER/zeromq4-1/.libs/:$ZRPCD_BUILD_FOLDER/c-capnproto/.libs/:$ZRPCD_BUILD_FOLDER/quagga/lib/.libs/ PATH=$PATH:$THRIFT_PATH make install DESTDIR=$INSTALL_DIR
        if [ -d .git ]; then
            COMMITID=`git log -n1 --format="%h"`
        else
            COMMITID=""
        fi
    fi
    # Temporarily disable this when using the dist method
    if [ -z "$BUILD_FROM_DIST" ]; then
        mkdir $INSTALL_DIR/opt/quagga/etc/init.d -p
        if [ $distrib = "Ubuntu" ]; then
           HOST_NAME=Ubuntu$version
           echo "its a Ubuntu-Host:$HOST_NAME " ;
        elif [ $distrib = "CentOS" ] ; then
           HOST_NAME=CentOS$version
           echo "its a CentOS-Host:$HOST_NAME" ;
        elif [ $distrib = "RedHat" ] ; then
           HOST_NAME=RedHat$version
           echo "its a RedHat-Host:$HOST_NAME" ;
        elif [ $distrib = "SUSE" ] ; then
           HOST_NAME=SUSE$version
           echo "its a SUSE-Host:$HOST_NAME" ;
        fi   
        case $HOST_NAME in
        Ubuntu*)
             cp pkgsrc/zrpcd.ubuntu $INSTALL_DIR/opt/quagga/etc/init.d/zrpcd
           ;;
        CentOS*)
              cp pkgsrc/zrpcd.centos $INSTALL_DIR/opt/quagga/etc/init.d/zrpcd
           ;;
        RedHat*)
              cp pkgsrc/zrpcd.redhat7 $INSTALL_DIR/opt/quagga/etc/init.d/zrpcd
              if [ -d pkgsrc/systemd ]; then
                  mkdir $INSTALL_DIR/usr/lib/systemd/system -p
                  cp -p pkgsrc/systemd/qbgp.service $INSTALL_DIR/usr/lib/systemd/system
                  mkdir $INSTALL_DIR/etc/sysconfig -p
                  cp -p pkgsrc/systemd/qbgp $INSTALL_DIR/etc/sysconfig
              fi
           ;;
        SUSE*)
              cp pkgsrc/zrpcd.suse $INSTALL_DIR/opt/quagga/etc/init.d/zrpcd
           ;;
        esac
        chmod +x $INSTALL_DIR/opt/quagga/etc/init.d/zrpcd
        if [ -f pkgsrc/zrpcd_log_rotate.sh ]; then
            cp pkgsrc/zrpcd_log_rotate.sh $INSTALL_DIR/opt/quagga/etc/init.d/
        fi
        if [ -f pkgsrc/zrpcd.rotate ]; then
            cp pkgsrc/zrpcd.rotate $INSTALL_DIR/opt/quagga/etc/init.d/
        fi
    fi
    if [ -z "${BUILD_FROM_DIST}" ]; then
        popd
    fi

    if [ -n "$DO_PACKAGING" ]; then
        case $HOST_NAME in
        Ubuntu*)
            if [ -f $DIR_NAME/preinst.zrpc ]; then
                cp $DIR_NAME/preinst.zrpc $INSTALL_DIR/preinst
            fi
	    ;;
        esac
        $DIR_NAME/packaging.sh "zrpc" $INSTALL_DIR $ZRPC_DIR $HOST_NAME $COMMITID
    else
        echo "hostname bgpd" > /opt/quagga/etc/bgpd.conf
        echo "password sdncbgpc" >> /opt/quagga/etc/bgpd.conf
        echo "service advanced-vty" >> /opt/quagga/etc/bgpd.conf
        echo "log stdout" >> /opt/quagga/etc/bgpd.conf
        echo "line vty" >> /opt/quagga/etc/bgpd.conf
        echo " exec-timeout 0 0 " >> /opt/quagga/etc/bgpd.conf
        echo "debug bgp " >> /opt/quagga/etc/bgpd.conf
        echo "debug bgp updates" >> /opt/quagga/etc/bgpd.conf
        echo "debug bgp events" >> /opt/quagga/etc/bgpd.conf
        echo "debug bgp fsm" >> /opt/quagga/etc/bgpd.conf
    fi
}
display_usage ()
{
cat << EOF
OPTIONS:
  -b/--build, build zrpcd. By default clones the master of the upstream repository and \
      builds that.
  -t/--from-dist-archive, package zrpcd using make dist and build the sources in the archive. \
      If --build is not used, the flag is ignored.
  -a/--archive [path to archive.tar.gz], give explicitly the source archive to be used instead \
      of producing one with make dist.
  -d/--install-deps, compile and install zrpcd's dependencies.
  -v/--version, define the thrift API to use with: 1 = l3vpn, 2 = evpn, 4 = ipv6
  -h help, prints this help text
EOF
}
INSTALL_DEPS=""
BUILD_ZRPCD=""
BUILD_FROM_DIST=""
DIST_ARCHIVE=""
DO_PACKAGING=""
THRIFT_VERSION="1"
parse_cmdline() {
    while [ $# -gt 0 ]
    do
        case "$1" in
            -h|--help)
                display_usage
                exit 0
                ;;
            -b|--build)
                BUILD_ZRPCD="true"
                shift
                ;;
            -d|--install-deps)
                INSTALL_DEPS="true"
                shift
                ;;
            -t|--from-dist-archive)
                BUILD_FROM_DIST="true"
                shift
                ;;
            -a|--archive)
                DIST_ARCHIVE=${2}
                shift 2
                ;;
            -p|--package)
                DO_PACKAGING="true"
                shift
                ;;
            -v|--version)
                THRIFT_VERSION=${2}
                shift 2
                ;;
            *)
                display_usage
                exit 1
                ;;
        esac
    done
}
parse_cmdline $@
if [ -n "$INSTALL_DEPS" ]; then
    install_deps
fi
if [ -n "$BUILD_ZRPCD" ]; then
    build_zrpcd
fi
