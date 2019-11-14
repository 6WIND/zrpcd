## Process this file with automake to produce Makefile.in.
## Copyright (c) 2016 6WIND

AM_CPPFLAGS = -I. -I$(top_srcdir) @QUAGGA_CFLAGS@ @CAPN_C_CFLAGS@ @THRIFT_CFLAGS@ @GLIB2_CFLAGS@ @GOBJECT2_CFLAGS@ @ZEROMQ_CFLAGS@

DEFS = @DEFS@ -DSYSCONFDIR=\"$(sysconfdir)/\"
INSTALL_SDATA=@INSTALL@ -m 600

AM_CFLAGS = $(WERROR)

noinst_LIBRARIES = libzrpc.a
sbin_PROGRAMS = zrpcd

libzrpc_a_SOURCES = \
	bgp_configurator.c zrpcd.c zrpc_vpnservice.c zrpc_network.c \
	bgp_updater.c vpnservice_types.c \
	zrpc_debug.c zrpc_bgp_configurator.c zrpc_bgp_updater.c \
	qzmqclient.c qzcclient.capnp.c qzcclient.c zrpc_util.c \
	zrpc_bgp_capnp.c zrpc_bfd_capnp.c bgp_configurator.h bgp_updater.h vpnservice_types.h \
	zrpc_thrift_wrapper.h zrpc_vpnservice.h zrpc_os_wrapper.h \
	zrpc_util.h zrpc_bgp_capnp.h zrpc_bfd_capnp.h zrpc_global.h qzcclient.h qzmqclient.h \
	qzcclient.capnp.h

BUILT_SOURCES = bgp_configurator.c bgp_updater.c vpnservice_types.c \
	bgp_configurator.h bgp_updater.h vpnservice_types.h

noinst_HEADERS = \
	zrpc_bgp_configurator.h zrpc_bgp_updater.h zrpc_debug.h zrpc_memory.h \
	zrpcd.h zrpc_network.h zrpc_thrift_wrapper.h zrpc_vpnservice.h \
	qzmqclient.h qzcclient.capnp.h qzcclient.h zrpc_util.h \
	zrpc_bgp_capnp.h zrpc_bfd_capnp.h zrpc_os_wrapper.h zrpc_global.h

zrpcd_SOURCES = \
	zrpc_main.c $(libzrpc_a_SOURCES)

zrpcd_LDADD = @QUAGGA_LIBS@ @CAPN_C_LIBS@ @THRIFT_LIBS@ @GLIB2_LIBS@ @GOBJECT2_LIBS@ @ZEROMQ_LIBS@

bgp_configurator.c : vpnservice.thrift


if HAVE_THRIFT_V1
vpnservice.thrift: vpnservice.l3vpn.thrift
	cp vpnservice.l3vpn.thrift vpnservice.thrift
	($(THRIFT_PRG) -out . --gen c_glib $(srcdir)/vpnservice.thrift)
	rm vpnservice.thrift
endif
if HAVE_THRIFT_V2
vpnservice.thrift: vpnservice.evpn.thrift
	cp vpnservice.evpn.thrift vpnservice.thrift
	($(THRIFT_PRG) -out . --gen c_glib $(srcdir)/vpnservice.thrift)
	rm vpnservice.thrift
endif
if HAVE_THRIFT_V3
vpnservice.thrift: vpnservice.ipv6.thrift
	cp vpnservice.ipv6.thrift vpnservice.thrift
	($(THRIFT_PRG) -out . --gen c_glib $(srcdir)/vpnservice.thrift)
	rm vpnservice.thrift
endif
if HAVE_THRIFT_V4
vpnservice.thrift: vpnservice.evpnipv6.thrift
	cp vpnservice.evpnipv6.thrift vpnservice.thrift
	($(THRIFT_PRG) -out . --gen c_glib $(srcdir)/vpnservice.thrift)
	rm vpnservice.thrift
endif
if HAVE_THRIFT_V5
vpnservice.thrift: vpnservice.dualstack.thrift
	cp vpnservice.dualstack.thrift vpnservice.thrift
	($(THRIFT_PRG) -out . --gen c_glib $(srcdir)/vpnservice.thrift)
	rm vpnservice.thrift
endif
if HAVE_THRIFT_V6
vpnservice.thrift: vpnservice.dualstack-ver6.thrift
	cp vpnservice.dualstack-ver6.thrift vpnservice.thrift
	($(THRIFT_PRG) -out . --gen c_glib $(srcdir)/vpnservice.thrift)
	rm vpnservice.thrift
endif

examplesdir = $(exampledir)
dist_examples_DATA = 

EXTRA_DIST = vpnservice.evpn.thrift vpnservice.l3vpn.thrift

