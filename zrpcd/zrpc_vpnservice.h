/* zrpc core structures and API
 * Copyright (c) 2016 6WIND,
 *
 * This file is part of ZRPC daemon.
 *
 * See the LICENSE file.
 */
#ifndef _ZRPC_VPNSERVICE_H
#define _ZRPC_VPNSERVICE_H

#define ZRPC_LISTEN_PORT	 7644
#define ZRPC_NOTIFICATION_PORT 6644
#define ZRPC_CLIENT_ADDRESS "0.0.0.0"

struct zrpc_vpnservice_client
{
  ThriftProcessor *processor;
  ThriftTransport *transport;
  ThriftBufferedTransport *transport_buffered;
  ThriftProtocol *protocol;
  ThriftServer *server;
  ThriftSimpleServer *simple_server;
};

struct zrpc_vpnservice
{
  /* configuration part */
  /* zrpc listen port number.  */
  u_int16_t  zrpc_listen_port;

  /* zrpc notification port number.  */
  u_int16_t  zrpc_notification_port;

  /* zrpc BGP Contexts */
  ThriftServerTransport *bgp_configurator_server_transport;
  BgpConfiguratorProcessor *bgp_configurator_processor;
  InstanceBgpConfiguratorHandler *bgp_configurator_handler;

  /* zrpc Update Contexts */
  BgpUpdaterIf *bgp_updater_client;
  ThriftSocket *bgp_updater_socket;
  ThriftFramedTransport *bgp_updater_transport;
  ThriftProtocol *bgp_updater_protocol;

  /* bgp context */
  struct zrpc_vpnservice_bgp_context *bgp_context;
};

void zrpc_vpnservice_terminate(struct zrpc_vpnservice *setup);
void zrpc_vpnservice_terminate_thrift_bgp_configurator_server(struct zrpc_vpnservice *setup);
void zrpc_vpnservice_terminate_thrift_bgp_updater_client(struct zrpc_vpnservice *setup);
gboolean zrpc_vpnservice_setup_thrift_bgp_updater_client (struct zrpc_vpnservice *setup);
void zrpc_vpnservice_setup_thrift_bgp_configurator_server(struct zrpc_vpnservice *setup);
void zrpc_vpnservice_setup(struct zrpc_vpnservice *setup);

void zrpc_vpnservice_get_context (struct zrpc_vpnservice **setup);
u_int16_t zrpc_vpnservice_get_thrift_bgp_configurator_server_port (struct zrpc_vpnservice *setup);
void zrpc_vpnservice_set_thrift_bgp_updater_client_port (struct zrpc_vpnservice *setup, \
                                                            u_int16_t thrift_notif_port);
u_int16_t zrpc_vpnservice_get_thrift_bgp_updater_client_port (struct zrpc_vpnservice *setup);
void zrpc_vpnservice_set_thrift_bgp_configurator_server_port (struct zrpc_vpnservice *setup, \
                                                                 u_int16_t thrift_listen_port);
void zrpc_vpnservice_setup_client(struct zrpc_vpnservice_client *peer,\
                                     struct zrpc_vpnservice *setup,  \
                                     ThriftTransport *transport);

void zrpc_vpnservice_terminate_client(struct zrpc_vpnservice_client *peer);

#endif /* _ZRPC_VPNSERVICE_H */
