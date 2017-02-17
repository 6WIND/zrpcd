## Process this file with automake to produce Makefile.in.
## Copyright (c) 2016 6WIND

AM_CPPFLAGS = -I. -I$(top_srcdir) @QUAGGA_CFLAGS@ @CAPN_C_CFLAGS@ @THRIFT_CFLAGS@ @GLIB2_CFLAGS@ @GOBJECT2_CFLAGS@ @ZEROMQ_CFLAGS@

DEFS = @DEFS@ -DSYSCONFDIR=\"$(sysconfdir)/\"
INSTALL_SDATA=@INSTALL@ -m 600

AM_CFLAGS = $(WERROR)

noinst_LIBRARIES = libzrpc.a
sbin_PROGRAMS = zrpcd

libzrpc_a_SOURCES = \
	zrpcd.c zrpc_vpnservice.c zrpc_network.c \
	bgp_configurator.c bgp_updater.c vpnservice_types.c \
	zrpc_debug.c zrpc_bgp_configurator.c zrpc_bgp_updater.c \
	qzmqclient.c qzcclient.capnp.c qzcclient.c zrpc_util.c \
	zrpc_bgp_capnp.c

noinst_HEADERS = \
	bgp_configurator.h bgp_updater.h vpnservice_types.h zrpc_bgp_updater.h \
	zrpc_bgp_configurator.h zrpc_bgp_updater.h zrpc_debug.h zrpc_memory.h \
	zrpcd.h zrpc_network.h zrpc_thrift_wrapper.h zrpc_vpnservice.h \
	qzmqclient.h qzcclient.capnp.h qzcclient.h zrpc_util.h \
	zrpc_bgp_capnp.h zrpc_os_wrapper.h zrpc_global.h

zrpcd_SOURCES = \
	zrpc_main.c $(libzrpc_a_SOURCES)

zrpcd_LDADD = @QUAGGA_LIBS@ @CAPN_C_LIBS@ @THRIFT_LIBS@ @GLIB2_LIBS@ @GOBJECT2_LIBS@ @ZEROMQ_LIBS@

examplesdir = $(exampledir)
dist_examples_DATA = 

EXTRA_DIST = 

