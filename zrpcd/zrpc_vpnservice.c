/* zrpc core structures and API
 * Copyright (c) 2016 6WIND,
 *
 * This file is part of ZRPC daemon.
 *
 * See the LICENSE file.
 */
#include "thread.h"

#include "zrpcd/zrpc_memory.h"
#include "zrpcd/zrpc_thrift_wrapper.h"
#include "zrpcd/bgp_configurator.h"
#include "zrpcd/bgp_updater.h"
#include "zrpcd/zrpc_bgp_configurator.h"
#include "zrpcd/zrpc_bgp_updater.h"
#include "zrpcd/zrpc_vpnservice.h"
#include "zrpcd/zrpc_bgp_configurator.h"
#include "zrpcd/zrpcd.h"
#include "zrpcd/zrpc_debug.h"
#include "zrpcd/zrpc_util.h"
#include "zrpcd/qzmqclient.h"
#include "zrpcd/qzcclient.h"
#include "zrpcd/zrpc_bgp_capnp.h"
#include "zrpcd/qzcclient.capnp.h"
#include "zrpcd/zrpc_debug.h"

static void zrpc_vpnservice_callback (void *arg, void *zmqsock, struct zmq_msg_t *msg);

/* callback function for capnproto bgpupdater notifications */
static void zrpc_vpnservice_callback (void *arg, void *zmqsock, struct zmq_msg_t *message)
{
  return;
}

#define SBIN_DIR "/sbin"

void zrpc_vpnservice_setup(struct zrpc_vpnservice *setup)
{
  char bgpd_location_path[128];
  char *ptr = bgpd_location_path;

  setup->zrpc_listen_port = ZRPC_LISTEN_PORT;
  setup->zrpc_notification_port = ZRPC_NOTIFICATION_PORT;
  setup->zmq_sock = ZRPC_STRDUP(ZMQ_SOCK);
  setup->zmq_subscribe_sock = ZRPC_STRDUP(ZMQ_NOTIFY);
  ptr+=sprintf(ptr, "%s", BGPD_PATH_QUAGGA);
  ptr+=sprintf(ptr, "%s/bgpd",SBIN_DIR);
  setup->bgpd_execution_path = ZRPC_STRDUP(bgpd_location_path);
}

void zrpc_vpnservice_terminate(struct zrpc_vpnservice *setup)
{
  if(!setup)
    return;
  setup->zrpc_listen_port = 0;
  setup->zrpc_notification_port = 0;
  ZRPC_FREE(setup->zmq_sock);
  setup->zmq_sock = NULL;
  ZRPC_FREE(setup->zmq_subscribe_sock);
  setup->zmq_subscribe_sock = NULL;
  ZRPC_FREE(setup->bgpd_execution_path);
  setup->bgpd_execution_path = NULL;
}

void zrpc_vpnservice_terminate_thrift_bgp_updater_client (struct zrpc_vpnservice *setup)
{
  if(!setup)
    return;
  if(setup->bgp_updater_client)
    g_object_unref(setup->bgp_updater_client);
  setup->bgp_updater_client = NULL;
  if(setup->bgp_updater_protocol)
    g_object_unref(setup->bgp_updater_protocol);
  setup->bgp_updater_protocol = NULL;
  if(setup->bgp_updater_transport)
    g_object_unref(setup->bgp_updater_transport);
  setup->bgp_updater_transport = NULL;
  if(setup->bgp_updater_socket)
    g_object_unref(setup->bgp_updater_socket);
  setup->bgp_updater_socket = NULL;
}

void zrpc_vpnservice_terminate_qzc(struct zrpc_vpnservice *setup)
{
  if(!setup)
    return;
  if(setup->qzc_subscribe_sock)
    qzcclient_close (setup->qzc_subscribe_sock);
  setup->qzc_subscribe_sock = NULL;
  if(setup->qzc_sock)
      qzcclient_close (setup->qzc_sock);
  setup->qzc_sock = NULL;

  qzmqclient_finish();
}

void zrpc_vpnservice_setup_qzc(struct zrpc_vpnservice *setup)
{
  qzcclient_init ();
  if(setup->zmq_subscribe_sock && setup->qzc_subscribe_sock == NULL )
    setup->qzc_subscribe_sock = qzcclient_subscribe(tm->global, \
                                                    setup->zmq_subscribe_sock, \
                                                    zrpc_vpnservice_callback);
}

void zrpc_vpnservice_terminate_bgp_context(struct zrpc_vpnservice *setup)
{
  if(!setup->bgp_context)
    return;
  if(setup->bgp_context->proc)
    {
      zrpc_log ("sending SIGINT signal to Bgpd (%d)",setup->bgp_context->proc);
      kill(setup->bgp_context->proc, SIGINT);
      setup->bgp_context->proc = 0;
    }
  if(setup->bgp_context)
    {
      ZRPC_FREE(setup->bgp_context);
      setup->bgp_context = NULL;
    }
  return;
}

void zrpc_vpnservice_setup_bgp_context(struct zrpc_vpnservice *setup)
{
  setup->bgp_context=ZRPC_CALLOC( sizeof(struct zrpc_vpnservice_bgp_context));
}

struct zrpc_vpnservice_bgp_context *zrpc_vpnservice_get_bgp_context(struct zrpc_vpnservice *setup)
{
  return setup->bgp_context;
}

void zrpc_vpnservice_terminate_bgpvrf_cache (struct zrpc_vpnservice *setup)
{
  struct zrpc_vpnservice_cache_bgpvrf *entry_bgpvrf, *entry_bgpvrf_next;
  struct zrpc_vpnservice_cache_peer *entry_bgppeer, *entry_bgppeer_next;

  setup->bgp_vrf_list = NULL;
  for (entry_bgpvrf = setup->bgp_vrf_list; entry_bgpvrf; entry_bgpvrf = entry_bgpvrf_next)
    {
      entry_bgpvrf_next = entry_bgpvrf->next;
      ZRPC_FREE (entry_bgpvrf);
    }

  setup->bgp_peer_list = NULL;
  for (entry_bgppeer = setup->bgp_peer_list; entry_bgppeer; entry_bgppeer = entry_bgppeer_next)
    {
      entry_bgppeer_next = entry_bgppeer->next;
      ZRPC_FREE (entry_bgppeer->peerIp);
      ZRPC_FREE (entry_bgppeer);
    }
  setup->bgp_peer_list = NULL;
}

gboolean zrpc_vpnservice_setup_thrift_bgp_updater_client (struct zrpc_vpnservice *setup)
{
  GError *error = NULL;
  gboolean response;

  if(!setup->bgp_updater_socket)
    setup->bgp_updater_socket =
      g_object_new (THRIFT_TYPE_SOCKET,
                    "hostname",  tm->zrpc_notification_address,
                    "port",      setup->zrpc_notification_port,
                    NULL);
  if(!setup->bgp_updater_transport)
    setup->bgp_updater_transport =
      g_object_new (THRIFT_TYPE_BUFFERED_TRANSPORT,
                    "transport", setup->bgp_updater_socket,
                    NULL);
  if(!setup->bgp_updater_protocol)
    setup->bgp_updater_protocol  =
      g_object_new (THRIFT_TYPE_BINARY_PROTOCOL,
                    "transport", setup->bgp_updater_transport,
                    NULL);
  if(!setup->bgp_updater_client)
    setup->bgp_updater_client = 
      g_object_new (TYPE_BGP_UPDATER_CLIENT,
                    "input_protocol",  setup->bgp_updater_protocol,
                    "output_protocol", setup->bgp_updater_protocol,
                    NULL);
  response = thrift_transport_open (setup->bgp_updater_transport->transport, &error);
  return response;
}

void zrpc_vpnservice_setup_thrift_bgp_configurator_server (struct zrpc_vpnservice *setup)
{
  /* Create our server socket, which binds to the specified port and
     listens for client connections */
  setup->bgp_configurator_server_transport =
    g_object_new (THRIFT_TYPE_SERVER_SOCKET,
                  "port", setup->zrpc_listen_port,
                  NULL);
  /* Create an instance of our handler, which provides the service's
     methods' implementation */
  setup->bgp_configurator_handler =
      g_object_new (TYPE_INSTANCE_BGP_CONFIGURATOR_HANDLER, NULL);

  /* Create an instance of the service's processor, automatically
     generated by the Thrift compiler, which parses incoming messages
     and dispatches them to the appropriate method in the handler */
  setup->bgp_configurator_processor = g_object_new (TYPE_BGP_CONFIGURATOR_PROCESSOR,
                                  "handler", setup->bgp_configurator_handler,
                                  NULL);
}

void zrpc_vpnservice_terminate_thrift_bgp_configurator_server (struct zrpc_vpnservice *setup)
{
  if(!setup)
    return;
  g_object_unref(setup->bgp_configurator_handler);
  setup->bgp_configurator_handler = NULL;
  g_object_unref(setup->bgp_configurator_processor);
  setup->bgp_configurator_processor = NULL;
  g_object_unref(setup->bgp_configurator_server_transport);
  setup->bgp_configurator_server_transport = NULL;
}

void zrpc_vpnservice_get_context (struct zrpc_vpnservice **setup)
{
  if(!tm->zrpc)
    *setup = NULL;
  *setup = tm->zrpc->zrpc_vpnservice;
}

u_int16_t zrpc_vpnservice_get_thrift_bgp_configurator_server_port (struct zrpc_vpnservice *setup)
{
  return setup->zrpc_listen_port;
}

void zrpc_vpnservice_set_thrift_bgp_configurator_server_port (struct zrpc_vpnservice *setup, \
                                                                 u_int16_t thrift_listen_port)
{
  setup->zrpc_listen_port = thrift_listen_port;
}

u_int16_t zrpc_vpnservice_get_thrift_bgp_updater_client_port (struct zrpc_vpnservice *setup)
{
  return setup->zrpc_notification_port;
}

void zrpc_vpnservice_set_thrift_bgp_updater_client_port (struct zrpc_vpnservice *setup, uint16_t thrift_notif_port)
{
  setup->zrpc_notification_port = thrift_notif_port;
}

void zrpc_vpnservice_terminate_client(struct zrpc_vpnservice_client *peer)
{
  if(peer == NULL)
    return;
  /* peer destroy */
  thrift_transport_close(peer->transport, NULL);
  g_object_unref(peer->transport_buffered);
  g_object_unref(peer->protocol);
  peer->protocol = NULL;
  g_object_unref(peer->simple_server);
  peer->simple_server = NULL;
  peer->server = NULL;
}

void zrpc_vpnservice_setup_client(struct zrpc_vpnservice_client *peer,
                                     struct zrpc_vpnservice *server, \
                                     ThriftTransport *transport)
{
  if(!peer)
    return;
  peer->transport = transport;
  peer->transport_buffered =
    g_object_new (THRIFT_TYPE_BUFFERED_TRANSPORT,
                  "transport", transport,
                  NULL);
  peer->protocol =
    g_object_new (THRIFT_TYPE_BINARY_PROTOCOL,
                  "transport", peer->transport_buffered,
                  NULL);
  /* Create the server itself */
  peer->simple_server =
    g_object_new (THRIFT_TYPE_SIMPLE_SERVER,
                  "processor",  server->bgp_configurator_processor,
                  NULL);
  if(peer->simple_server && &(peer->simple_server->parent))
    peer->server = &(peer->simple_server->parent);
  return;
}
