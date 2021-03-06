/* zrpc thrift Wrapper 
 * Copyright (c) 2016 6WIND,
 *
 * This file is part of ZRPC daemon.
 *
 * See the LICENSE file.
 */

#ifndef _ZRPC_THRIFT_WRAPPER_H
#define _ZRPC_THRIFT_WRAPPER_H

#include <thrift/c_glib/thrift.h>
#include <thrift/c_glib/protocol/thrift_binary_protocol_factory.h>
#include <thrift/c_glib/server/thrift_simple_server.h>
#include <thrift/c_glib/transport/thrift_buffered_transport.h>
#include <thrift/c_glib/transport/thrift_buffered_transport_factory.h>
#include <thrift/c_glib/transport/thrift_framed_transport.h>
#include <thrift/c_glib/protocol/thrift_binary_protocol.h>
#include <thrift/c_glib/transport/thrift_server_socket.h>
#include <thrift/c_glib/transport/thrift_socket.h>

#if defined(PACKAGE)
#undef PACKAGE
#endif
#if defined(PACKAGE_TARNAME)
#undef PACKAGE_TARNAME
#endif
#if defined(PACKAGE_VERSION)
#undef PACKAGE_VERSION
#endif
#if defined(PACKAGE_STRING)
#undef PACKAGE_STRING
#endif
#if defined(PACKAGE_BUGREPORT)
#undef PACKAGE_BUGREPORT
#endif
#if defined(PACKAGE_NAME)
#undef PACKAGE_NAME
#endif
#if defined(VERSION)
#undef VERSION
#endif

#endif /* _ZRPC_THRIFT_WRAPPER_H */
