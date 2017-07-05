/* zrpc core structures and API
 * Copyright (c) 2016 6WIND,
 *
 * This file is part of ZRPC daemon.
 *
 * See the LICENSE file.
 */
#include "thread.h"
#include "config.h"
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
#include "zrpcd/vpnservice_types.h"

static void zrpc_vpnservice_callback (void *arg, void *zmqsock, struct zmq_msg_t *msg);

void zrpc_transport_check_response(struct zrpc_vpnservice *setup, gboolean response);
static int zrpc_vpnservice_setup_bgp_updater_client_retry (struct thread *thread);
static int zrpc_vpnservice_setup_bgp_updater_client_monitor (struct thread *thread);
int zrpc_monitor_retry_job_in_progress;
gboolean zrpc_transport_current_status = FALSE;

void zrpc_transport_check_response(struct zrpc_vpnservice *setup, gboolean response)
{
  if(zrpc_monitor_retry_job_in_progress)
    return;
  if (zrpc_transport_current_status != response)
    {
      zrpc_log ("bgpUpdater check connection with %s:%u %s",
                tm->zrpc_notification_address,
                setup->zrpc_notification_port,
                response == TRUE?"OK":"NOK");
    }
  zrpc_transport_current_status = response;
  if(response == FALSE)
    {
      setup->bgp_update_retries++;
      setup->bgp_updater_client_thread = NULL;
      THREAD_TIMER_MSEC_ON(tm->global, setup->bgp_updater_client_thread, \
                           zrpc_vpnservice_setup_bgp_updater_client_retry, \
                           setup, 1000);
    }
  else
    {
      setup->bgp_update_monitor++;
      setup->bgp_updater_client_thread = NULL;
      THREAD_TIMER_MSEC_ON(tm->global, setup->bgp_updater_client_thread,\
                           zrpc_vpnservice_setup_bgp_updater_client_monitor,\
                           setup, 5000);

    }
  zrpc_monitor_retry_job_in_progress = 1;
}

/* returns status from recv with MSG_PEEK option
 * this permits knowing if socket is available or not.
 * values returned: -1 + EAGAIN => nothing to read, but socket is ok
 *                  0, no errno => nothing to read, but socket is ok
 *                 -1, EAGAIN => nothing to read, but socket is still ok
 *                 -1, ENOTCONN => socket got disconnected
 */
static int zrpc_vpnservice_bgp_updater_check_connection (struct zrpc_vpnservice *setup)
{
  ThriftTransport *transport = NULL;
  ThriftSocket *tsocket = NULL;
  int fd = 0;
  int ret;
  char buffer[32];

  if(!setup)
    return 0;
  if (setup->bgp_updater_transport)
    transport = setup->bgp_updater_transport->transport;
  if (transport)
    tsocket = THRIFT_SOCKET (transport);
  if (tsocket)
    fd = tsocket->sd;
  if (fd == 0)
    ret = 0;
  else
    ret = recv(fd, buffer, 32, MSG_PEEK | MSG_DONTWAIT);
  if (ret == 0)
    {
      /* error */
      errno = ENOTCONN;
      return -1;
    }
  return ret;
}

static int zrpc_vpnservice_setup_bgp_updater_client_retry (struct thread *thread)
{
  struct zrpc_vpnservice *setup;
  GError *error = NULL;
  gboolean response;

  setup = THREAD_ARG (thread);
  assert (setup);
  thrift_transport_close (setup->bgp_updater_transport->transport, &error);
  response = thrift_transport_open (setup->bgp_updater_transport->transport, &error);
  zrpc_monitor_retry_job_in_progress = 0;
  zrpc_transport_check_response(setup, response);
  return 0;
}

/* detects if remote peer is present or not
 * either relaunch monitor or retry to reconnect
 */
static int zrpc_vpnservice_setup_bgp_updater_client_monitor (struct thread *thread)
{
  struct zrpc_vpnservice *setup;
  GError *error = NULL;
  gboolean response;
  int ret;

  setup = THREAD_ARG (thread);
  assert (setup);
  ret = zrpc_vpnservice_bgp_updater_check_connection (setup);
  if (ret < 0 && errno == ENOTCONN)
    {
      thrift_transport_close (setup->bgp_updater_transport->transport, &error);
      response = thrift_transport_open (setup->bgp_updater_transport->transport, &error);
      zrpc_monitor_retry_job_in_progress = 0;
      zrpc_transport_check_response(setup, response);
      return 0;
    }
  zrpc_monitor_retry_job_in_progress = 0;
  zrpc_transport_check_response(setup, 1);
  return 0;
}
/* callback function for capnproto bgpupdater notifications */
static void zrpc_vpnservice_callback (void *arg, void *zmqsock, struct zmq_msg_t *message)
{
  struct capn rc;
  capn_ptr p;
  struct bgp_event_vrf ss;
  struct bgp_event_vrf *s;
  static gboolean client_ready;
  struct zrpc_vpnservice *ctxt = NULL;
  struct bgp_event_shut tt;
  struct bgp_event_shut *t;
  bool announce;
  gchar *nexthop;
  char nh_str[ZRPC_UTIL_IPV6_LEN_MAX];

  zrpc_vpnservice_get_context (&ctxt);
  if(!ctxt)
    {
      return;
    }
  ctxt->bgp_update_total++;
  /* if first time or previous failure, try to reconnect to client */
  if((ctxt->bgp_updater_client == NULL) || (zrpc_transport_current_status == FALSE))
    {
      if(ctxt->bgp_updater_client)
        zrpc_vpnservice_terminate_thrift_bgp_updater_client(ctxt);
      /* start the retry mecanism */
      client_ready = zrpc_vpnservice_setup_thrift_bgp_updater_client(ctxt);
      zrpc_transport_check_response(ctxt, client_ready);
      if(client_ready == FALSE)
        {
          zrpc_info ("bgp->sdnc message failed to be sent");
          ctxt->bgp_update_lost_msgs++;
          return;
        }
    }
  p = qzcclient_msg_to_notification (message, &rc);
  s = &ss;
  memset(s, 0, sizeof(struct bgp_event_vrf));
  qcapn_BGPEventVRFRoute_read(s, p);
  if (s->announce != BGP_EVENT_SHUT)
    {
      gchar *esi;
      gchar *macaddress = NULL;
      gint32 ipprefixlen = 0;
      char vrf_rd_str[ZRPC_UTIL_RDRT_LEN];
      struct zrpc_rd_prefix null_rd;
      int zrpc_invalid_rd = 0;
      struct zrpc_prefix *p = (struct zrpc_prefix *)&(s->prefix);
      afi_t afi_out;
#if !defined(HAVE_THRIFT_V1)
      protocol_type p_type;
#endif /* !HAVE_THRIFT_V1 */
      memset (&null_rd, 0, sizeof (struct zrpc_rd_prefix));
      if(s->esi)
        {
          esi = g_strdup((const gchar *)s->esi);
        }
      else
        esi = NULL;
      announce = (s->announce & BGP_EVENT_MASK_ANNOUNCE)?TRUE:FALSE;
      if (memcmp (&s->outbound_rd, &null_rd, sizeof(struct zrpc_rd_prefix)))
        zrpc_util_rd_prefix2str(&s->outbound_rd, vrf_rd_str, sizeof(vrf_rd_str));
      else
        zrpc_invalid_rd = 1;
      if (p->family == AF_INET)
        afi_out = AF_AFI_AFI_IP;
#if !defined(HAVE_THRIFT_V1)
      else if (p->family == AF_INET6)
        afi_out = AF_AFI_AFI_IPV6;
      else if (p->family == AF_L2VPN)
        {
          struct zrpc_macipaddr *m = &(p->u.prefix_macip);
          if (m->ip_len == 128)
            afi_out = AF_AFI_AFI_IPV6; /* only L2VPN -> IPv6 */
          else
            afi_out = AF_AFI_AFI_IP; /* only L2VPN -> IPv6 */
        }
        else
          afi_out = AF_AFI_AFI_IP; /* only L2VPN -> IPv6 */
      if (s->nexthop.family == AF_INET6 && afi_out == AF_AFI_AFI_IPV6 &&
          IN6_IS_ADDR_V4MAPPED (&s->nexthop.u.prefix6))
        {
          /* check that nexthop is ipv4 mapped ipv6. transform it if this is it */
          zrpc_util_convert_ipv6mappedtoipv4 (&s->nexthop);
        }
      if (s->esi)
        p_type  = PROTOCOL_TYPE_PROTOCOL_EVPN;
      else if (zrpc_invalid_rd)
        p_type = PROTOCOL_TYPE_PROTOCOL_LU;
      else
        p_type = PROTOCOL_TYPE_PROTOCOL_L3VPN;
#endif /* !HAVE_THRIFT_V1 */
      zrpc_util_prefix_2str (&s->nexthop, nh_str, ZRPC_UTIL_IPV6_LEN_MAX);
      nexthop = nh_str;
      if (announce == TRUE)
        {
          char pfx_str[ZRPC_UTIL_IPV6_LEN_MAX];
          gchar *mac_router;
          char *pfx_str_p = &pfx_str[0];

          if(s->mac_router)
            mac_router = g_strdup((const gchar *)s->mac_router);
          else
            mac_router = NULL;
          if (p->family == AF_INET)
            {
              inet_ntop (p->family, &p->u.prefix4, pfx_str, ZRPC_UTIL_IPV6_LEN_MAX);
              ipprefixlen = s->prefix.prefixlen;
            }
          else if (p->family == AF_INET6)
            {
              inet_ntop (p->family, &p->u.prefix6, pfx_str, ZRPC_UTIL_IPV6_LEN_MAX);
              ipprefixlen = s->prefix.prefixlen;
            }
          else if (p->family == AF_L2VPN)
            {
              if (ZRPC_L2VPN_PREFIX_HAS_IPV4(p))
                {
                  inet_ntop (AF_INET, &p->u.prefix_macip.ip.in4, pfx_str, ZRPC_UTIL_IPV6_LEN_MAX);
                  ipprefixlen = ZRPC_UTIL_IPV4_PREFIX_LEN_MAX;
                }
              else if (ZRPC_L2VPN_PREFIX_HAS_IPV6(p))
                {
                  inet_ntop (AF_INET6, &p->u.prefix_macip.ip.in6, pfx_str, ZRPC_UTIL_IPV6_LEN_MAX);
                  ipprefixlen = ZRPC_UTIL_IPV6_PREFIX_LEN_MAX;
                }
              else
                {
                  pfx_str_p = NULL;
                  ipprefixlen = 0;
                }
              macaddress = (gchar *) zrpc_util_mac2str((char*) &p->u.prefix_macip.mac);
            }
#if defined(HAVE_THRIFT_V1)



          zrpc_bgp_updater_on_update_push_route(
#else
          zrpc_bgp_updater_on_update_push_route(p_type,
#endif /* HAVE_THRIFT_V1 */
                                                (zrpc_invalid_rd == 1)?NULL:vrf_rd_str, pfx_str_p,
                                                (const gint32)ipprefixlen, nexthop,
                                                s->ethtag, esi, macaddress, s->label, s->l2label,
                                                mac_router, s->gatewayIp, afi_out);
        }
      else
        {
          char pfx_str[ZRPC_UTIL_IPV6_LEN_MAX];
          char *pfx_str_p = &pfx_str[0];

          if (p->family == AF_INET)
            {
              inet_ntop (p->family, &p->u.prefix4, pfx_str, ZRPC_UTIL_IPV6_LEN_MAX);
              ipprefixlen = s->prefix.prefixlen;
            }
          else if (p->family == AF_INET6)
            {
              inet_ntop (p->family, &p->u.prefix6, pfx_str, ZRPC_UTIL_IPV6_LEN_MAX);
              ipprefixlen = s->prefix.prefixlen;
            }
          else if (p->family == AF_L2VPN)
            {
              macaddress = (gchar *) zrpc_util_mac2str((char*) &p->u.prefix_macip.mac);
              if (ZRPC_L2VPN_PREFIX_HAS_IPV4(p))
                {
                  inet_ntop (AF_INET, &p->u.prefix_macip.ip.in4, pfx_str_p, ZRPC_UTIL_IPV6_LEN_MAX);
                  ipprefixlen = ZRPC_UTIL_IPV4_PREFIX_LEN_MAX;
                }
              else if (ZRPC_L2VPN_PREFIX_HAS_IPV6(p))
                {
                  inet_ntop (AF_INET6, &p->u.prefix_macip.ip.in6, pfx_str, ZRPC_UTIL_IPV6_LEN_MAX);
                  ipprefixlen = ZRPC_UTIL_IPV6_PREFIX_LEN_MAX;
                }
              else
                {
                  pfx_str_p = NULL;
                  ipprefixlen = 0;
                }
            }
#if defined(HAVE_THRIFT_V1)
          zrpc_bgp_updater_on_update_withdraw_route (
#else
          zrpc_bgp_updater_on_update_withdraw_route (p_type,
#endif /* HAVE_THRIFT_V1 */
                                                     (zrpc_invalid_rd == 1)?NULL:vrf_rd_str, pfx_str_p,
                                                     (const gint32)ipprefixlen, nexthop,
                                                     s->ethtag, esi, macaddress, s->label, s->l2label,
                                                     afi_out);
        }
      if (s->esi)
        free (s->esi);
      if (s->mac_router)
        free (s->mac_router);
    }
  else
    {
      t = &tt;
      memset(t, 0, sizeof(struct bgp_event_shut));
      zrpc_util_copy_prefix (&t->peer, &s->nexthop);
      t->type = (uint8_t)s->label;
      t->subtype = (uint8_t)s->prefix.u.prefix4.s_addr;
      zrpc_util_prefix_2str (&t->peer, nh_str, ZRPC_UTIL_IPV6_LEN_MAX);
      nexthop = nh_str;
      zrpc_bgp_updater_on_notification_send_event(nexthop, t->type, t->subtype);
    }
  capn_free(&rc);
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
  zrpc_vpnservice_setup_bgp_context (setup);
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
  if (setup->bgp_context)
    return;
  setup->bgp_context=ZRPC_CALLOC( sizeof(struct zrpc_vpnservice_bgp_context));
  setup->bgp_context->logFile = strdup (ZRPC_DEFAULT_LOG_FILE);
  setup->bgp_context->logLevel = strdup (ZRPC_DEFAULT_LOG_LEVEL);
  /* configure log settings to qthrift daemon too */
  zrpc_debug_set_log_file_with_level(setup->bgp_context->logFile, setup->bgp_context->logLevel);
  if (zrpc_disable_stdout)
    zrpc_debug_configure_stdout (0);
}

#define ERROR_BGP_MULTIPATH_SET g_error_new(1, BGP_ERR_ACTIVE, "BGP multipath already configured for afi/safi");
#define ERROR_BGP_MULTIPATH_UNSET g_error_new(1, BGP_ERR_INACTIVE, "BGP multipath already unconfigured for afi/safi");

gboolean zrpc_vpnservice_set_bgp_context_multipath (struct zrpc_vpnservice_bgp_context *bgp,
                                                    address_family_t afi, subsequent_address_family_t safi,
                                                    uint8_t on, gint32* _return, GError **error)
{
  if (on && bgp->multipath_on[afi][safi])
    {
      *_return = BGP_ERR_ACTIVE;
      *error = ERROR_BGP_MULTIPATH_SET;
      return FALSE;
    }
  if ((on == 0) && bgp->multipath_on[afi][safi] == 0)
    {
      *_return = BGP_ERR_INACTIVE;
      *error = ERROR_BGP_MULTIPATH_UNSET;
      return FALSE;
    }
  bgp->multipath_on[afi][safi] = on;
  return TRUE;
}

struct zrpc_vpnservice_bgp_context *zrpc_vpnservice_get_bgp_context(struct zrpc_vpnservice *setup)
{
  return setup->bgp_context;
}

void zrpc_vpnservice_setup_bgp_cache(struct zrpc_vpnservice *ctxt)
{
  ctxt->bgp_vrf_list = NULL;
  ctxt->bgp_peer_list = NULL;
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
      g_object_new (THRIFT_TYPE_FRAMED_TRANSPORT,
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
  zrpc_transport_check_response(setup, response);
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
  GError *error = NULL;

  if(peer == NULL)
    return;
  /* peer destroy */
  thrift_transport_flush(peer->transport, &error);
  if (error != NULL)
    {
      zlog_err("Unable to flush thrift socket: %s\n", error->message);
      g_error_free (error);
      error = NULL;
    }
  thrift_transport_close(peer->transport, &error);
  if (error != NULL)
    {
      zlog_err("Unable to close thrift socket: %s\n", error->message);
      g_error_free (error);
    }
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
