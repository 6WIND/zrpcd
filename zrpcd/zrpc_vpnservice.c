/* zrpc core structures and API
 * Copyright (c) 2016 6WIND,
 *
 * This file is part of ZRPC daemon.
 *
 * See the LICENSE file.
 */
#include "thread.h"
#ifdef HAVE_THRIFT_V6
#include "workqueue.h"
#endif
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
#include "zrpcd/zrpc_network.h"
#include "zrpcd/vpnservice_types.h"

static void zrpc_vpnservice_callback (void *arg, void *zmqsock, struct zmq_msg_queue_node *node);

void zrpc_transport_check_response(struct zrpc_vpnservice *setup, gboolean response);
void zrpc_transport_cancel_monitor(struct zrpc_vpnservice *setup);
void zrpc_transport_change_status(struct zrpc_vpnservice *setup, gboolean response);
static int zrpc_vpnservice_setup_bgp_updater_client_retry (struct thread *thread);
static int zrpc_vpnservice_setup_bgp_updater_client_monitor (struct thread *thread);
int zrpc_monitor_retry_job_in_progress = 0;
zrpc_status zrpc_transport_current_status = ZRPC_TO_SDN_UNKNOWN;

unsigned int notification_socket_errno[ZRPC_MAX_ERRNO];

static void zrpc_update_notification_socket_errno(int err) {
  if (err >= ZRPC_MAX_ERRNO)
    return;
  notification_socket_errno[err]++;
}

void zrpc_transport_change_status(struct zrpc_vpnservice *setup, gboolean response)
{
#ifdef HAVE_THRIFT_V6
  int ret;
#endif

  if ((zrpc_transport_current_status == ZRPC_TO_SDN_UNKNOWN) ||
      ((response == TRUE) && (zrpc_transport_current_status == ZRPC_TO_SDN_FALSE)) ||
      ((response == FALSE) && (zrpc_transport_current_status == ZRPC_TO_SDN_TRUE)))
    {
#ifdef HAVE_THRIFT_V6
      struct qzmqclient_cb *cb = (setup->qzc_subscribe_sock ? setup->qzc_subscribe_sock->cb : NULL);
#endif

      zrpc_info("bgpUpdater check connection with %s:%u %s",
                tm->zrpc_notification_address,
                setup->zrpc_notification_port,
                response == TRUE?"OK":"NOK");
      if (response == TRUE) {
        zrpc_transport_current_status = ZRPC_TO_SDN_TRUE;
#ifndef HAVE_THRIFT_V6
        zrpc_bgp_updater_on_start_config_resync_notification_quick (setup, FALSE);
#else
        ret = zrpc_bgp_updater_on_start_config_resync_notification_quick (setup, FALSE);
        if (ret == FALSE) {
          if (cb && cb->process_zmq_msg_queue)
            work_queue_plug (cb->process_zmq_msg_queue);
	  if (setup->bgp_updater_transport)
	    zrpc_client_transport_close(setup->bgp_updater_transport->transport);
	  zrpc_transport_current_status = ZRPC_TO_SDN_FALSE;
        } else {
          if (cb && cb->process_zmq_msg_queue)
            work_queue_unplug (cb->process_zmq_msg_queue);
        }
#endif
      } else {
#ifdef HAVE_THRIFT_V6
        if (cb && cb->process_zmq_msg_queue)
          work_queue_plug (cb->process_zmq_msg_queue);
#endif
        if (setup->bgp_updater_transport)
          zrpc_client_transport_close(setup->bgp_updater_transport->transport);
        zrpc_transport_current_status = ZRPC_TO_SDN_FALSE;
      }
    }
}
void zrpc_transport_cancel_monitor(struct zrpc_vpnservice *setup)
{
  if (setup->bgp_updater_client_thread)
    {
      THREAD_TIMER_OFF(setup->bgp_updater_client_thread);
      setup->bgp_updater_client_thread = NULL;
    }
  zrpc_monitor_retry_job_in_progress = 0;
}

void zrpc_transport_check_response(struct zrpc_vpnservice *setup, gboolean response)
{
  if(zrpc_monitor_retry_job_in_progress)
    return;
  zrpc_transport_change_status (setup, response);
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

int zrpc_vpnservice_get_bgp_updater_socket (struct zrpc_vpnservice *setup)
{
  ThriftTransport *transport = NULL;
  ThriftSocket *tsocket = NULL;

  if(!setup)
    return 0;
  if (setup->bgp_updater_transport)
    transport = setup->bgp_updater_transport->transport;
  if (transport)
    tsocket = THRIFT_SOCKET (transport);
  if (tsocket)
    return tsocket->sd;
  return 0;
}

static gboolean zrpc_vpnservice_bgp_updater_select_connection (struct zrpc_vpnservice *setup)
{
  int ret = 0;
  int fd = zrpc_vpnservice_get_bgp_updater_socket(setup);
  fd_set wrfds;
  struct timeval tout;
  int optval, optlen;

  if (fd == 0 || fd == THRIFT_INVALID_SOCKET)
    return FALSE;
  if (setup->bgp_updater_client_need_select == FALSE)
    return FALSE;

  FD_ZERO(&wrfds);
  FD_SET(fd, &wrfds);

  tout.tv_sec = 0;
  tout.tv_usec = 0;

  ret = select(FD_SETSIZE, NULL, &wrfds, NULL, &tout);
  if (ret <= 0)
    return FALSE;

  optval = -1;
  optlen = sizeof (optval);
  if (getsockopt(fd, SOL_SOCKET, SO_ERROR, &optval, (socklen_t *)&optlen) < 0)
    return FALSE;
  if (optval != 0)
    return FALSE;

  return TRUE;
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
  int ret = 0;
  int fd = zrpc_vpnservice_get_bgp_updater_socket(setup);
  char buffer[32];

  if (setup->bgp_updater_select_in_progress == TRUE)
    return 0;

  if (fd != 0 && fd != THRIFT_INVALID_SOCKET)
    ret = recv(fd, buffer, 32, MSG_PEEK | MSG_DONTWAIT);
  if (ret == 0)
    {
      /* error */
      zrpc_update_notification_socket_errno(ENOTCONN);
      return -1;
    }
  else
    {
      if (ret == -1)
        {
          zrpc_update_notification_socket_errno(errno);
          if (errno == EAGAIN || errno == EWOULDBLOCK)
            return 0;
          /* other cases : EBADF, ECONNREFUSED, EFAULT, EINTR, EINVAL,
           * EINOMEM, ENOTCONN, ENOTSOCK
           * should fall on error
           */
          return -1;
        }
    }
  return ret;
}

static int zrpc_vpnservice_setup_bgp_updater_client_retry (struct thread *thread)
{
  struct zrpc_vpnservice *setup;
  GError *error = NULL;
  gboolean response;
#ifdef HAVE_THRIFT_V6
  struct qzmqclient_cb *cb;
#endif

  setup = THREAD_ARG (thread);
  assert (setup);

#ifdef HAVE_THRIFT_V6
  /* cleanup all the nodes in the workqueue */
  cb = (setup->qzc_subscribe_sock ? setup->qzc_subscribe_sock->cb : NULL);
  if (cb && cb->process_zmq_msg_queue)
    work_queue_cleanup (cb->process_zmq_msg_queue);
#endif

  if (zrpc_vpnservice_bgp_updater_select_connection(setup))
    {
      zrpc_monitor_retry_job_in_progress = 0;
      zrpc_transport_check_response(setup, TRUE);
      return 0;
    }
  zrpc_client_transport_close(setup->bgp_updater_transport->transport);
  setup->bgp_updater_client_need_select = FALSE;
  response = zrpc_client_transport_open (setup->bgp_updater_transport->transport,
                                         &error, &setup->bgp_updater_client_need_select);
  if (error)
    {
      zrpc_log ("%s: zrpc_client_transport_open: %s\n", __func__, error->message);
      g_error_free (error);
    }
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
  if (ret < 0)
    {
      zrpc_client_transport_close(setup->bgp_updater_transport->transport);
      setup->bgp_updater_client_need_select = FALSE;
      response = zrpc_client_transport_open (setup->bgp_updater_transport->transport,
                                             &error, &setup->bgp_updater_client_need_select);
      if (error)
        {
          zrpc_log ("%s: zrpc_client_transport_open: %s\n", __func__, error->message);
          g_error_free (error);
        }
      zrpc_monitor_retry_job_in_progress = 0;
      zrpc_transport_check_response(setup, response);
      return 0;
    }
  zrpc_monitor_retry_job_in_progress = 0;
  zrpc_transport_check_response(setup, 1);
  return 0;
}
/* callback function for capnproto bgpupdater notifications */
static void zrpc_vpnservice_callback (void *arg, void *zmqsock, struct zmq_msg_queue_node *node)
{
  struct capn rc;
  capn_ptr p;
  struct bgp_event_vrf ss;
  struct bgp_event_vrf *s;
  static gboolean client_ready;
  struct zrpc_vpnservice *ctxt = NULL;
  struct bgp_event_shut tt;
  struct bgp_event_shut *t;
  bool announce, ret = FALSE;
  gchar *nexthop;
  char nh_str[ZRPC_UTIL_IPV6_LEN_MAX];

  zrpc_vpnservice_get_context (&ctxt);
  if(!ctxt)
    {
      return;
    }
  if (zrpc_silent_leave)
    {
      return;
    }
  ctxt->bgp_update_total++;
  /* if first time or previous failure, try to reconnect to client */
  if((ctxt->bgp_updater_client == NULL) ||
     (zrpc_transport_current_status == ZRPC_TO_SDN_UNKNOWN) ||
     (zrpc_transport_current_status == ZRPC_TO_SDN_FALSE))
    {
      if (ctxt->bgp_updater_transport)
        zrpc_client_transport_close(ctxt->bgp_updater_transport->transport);
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
  p = qzcclient_msg_to_notification (node->msg, &rc);
  s = &ss;
  memset(s, 0, sizeof(struct bgp_event_vrf));
  qcapn_BGPEventVRFRoute_read(s, p);
  if (s->announce <= BGP_EVENT_MASK_ANNOUNCE)
    {
      gchar *esi;
      gchar *macaddress = NULL;
      gint32 ipprefixlen = 0;
      char vrf_rd_str[ZRPC_UTIL_RDRT_LEN];
      struct zrpc_rd_prefix null_rd;
      int zrpc_invalid_rd = 0;
      struct zrpc_prefix *p = (struct zrpc_prefix *)&(s->prefix);
      af_afi afi_out;
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
          struct zrpc_macipaddr *m = &(p->u.prefix_evpn.u.prefix_macip);
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
                  inet_ntop (AF_INET, &p->u.prefix_evpn.u.prefix_macip.ip.in4, pfx_str, ZRPC_UTIL_IPV6_LEN_MAX);
                  ipprefixlen = ZRPC_UTIL_IPV4_PREFIX_LEN_MAX;
                }
              else if (ZRPC_L2VPN_PREFIX_HAS_IPV6(p))
                {
                  inet_ntop (AF_INET6, &p->u.prefix_evpn.u.prefix_macip.ip.in6, pfx_str, ZRPC_UTIL_IPV6_LEN_MAX);
                  ipprefixlen = ZRPC_UTIL_IPV6_PREFIX_LEN_MAX;
                }
              else
                {
                  pfx_str_p = NULL;
                  ipprefixlen = 0;
                }
              macaddress = (gchar *) zrpc_util_mac2str((char*) &p->u.prefix_evpn.u.prefix_macip.mac);
            }

#if defined(HAVE_THRIFT_V6)
          if (IS_ZRPC_DEBUG_NOTIFICATION)
            {
              if (node->retry_times >= 1)
                zrpc_info ("retry (%d) to send onUpdatePushRoute(rd %s, pfx %s, nh %s, l3label %d, l2label %d)",
                           node->retry_times, (zrpc_invalid_rd == 1)? NULL : vrf_rd_str,
                           pfx_str_p, nexthop, s->label, s->l2label);
            }
#endif
#if defined(HAVE_THRIFT_V1)
          ret = zrpc_bgp_updater_on_update_push_route(
#else
          ret = zrpc_bgp_updater_on_update_push_route(p_type,
#endif /* HAVE_THRIFT_V1 */
                                                (zrpc_invalid_rd == 1)?NULL:vrf_rd_str, pfx_str_p,
                                                (const gint32)ipprefixlen, nexthop,
                                                s->ethtag, esi, macaddress, s->label, s->l2label,
                                                mac_router, s->gatewayIp, afi_out);
          if (mac_router)
            g_free (mac_router);
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
              macaddress = (gchar *) zrpc_util_mac2str((char*) &p->u.prefix_evpn.u.prefix_macip.mac);
              if (ZRPC_L2VPN_PREFIX_HAS_IPV4(p))
                {
                  inet_ntop (AF_INET, &p->u.prefix_evpn.u.prefix_macip.ip.in4, pfx_str_p, ZRPC_UTIL_IPV6_LEN_MAX);
                  ipprefixlen = ZRPC_UTIL_IPV4_PREFIX_LEN_MAX;
                }
              else if (ZRPC_L2VPN_PREFIX_HAS_IPV6(p))
                {
                  inet_ntop (AF_INET6, &p->u.prefix_evpn.u.prefix_macip.ip.in6, pfx_str, ZRPC_UTIL_IPV6_LEN_MAX);
                  ipprefixlen = ZRPC_UTIL_IPV6_PREFIX_LEN_MAX;
                }
              else
                {
                  pfx_str_p = NULL;
                  ipprefixlen = 0;
                }
            }

#if defined(HAVE_THRIFT_V6)
          if (IS_ZRPC_DEBUG_NOTIFICATION)
            {
              if (node->retry_times >= 1)
                zrpc_info ("retry (%d) to send onUpdateWithdrawRoute(rd %s, pfx %s, nh %s, l3label %d, l2label %d)",
                           node->retry_times, (zrpc_invalid_rd == 1)? NULL : vrf_rd_str,
                           pfx_str_p, nexthop, s->label, s->l2label);
            }
#endif
#if defined(HAVE_THRIFT_V1)
          ret = zrpc_bgp_updater_on_update_withdraw_route (
#else
          ret = zrpc_bgp_updater_on_update_withdraw_route (p_type,
#endif /* HAVE_THRIFT_V1 */
                                                     (zrpc_invalid_rd == 1)?NULL:vrf_rd_str, pfx_str_p,
                                                     (const gint32)ipprefixlen, nexthop,
                                                     s->ethtag, esi, macaddress, s->label, s->l2label,
                                                     afi_out);
        }
      if (esi)
        g_free (esi);
      if (macaddress)
        free (macaddress);
    }
#ifdef HAVE_THRIFT_V5
  else if (s->announce == BGP_EVENT_PUSH_EVPN_RT ||
           s->announce == BGP_EVENT_WITHDRAW_EVPN_RT)
    {
      char vrf_rd_str[ZRPC_UTIL_RDRT_LEN];
      struct zrpc_rd_prefix null_rd;
      int zrpc_invalid_rd = 0;
      struct zrpc_prefix *p = (struct zrpc_prefix *)&(s->prefix);
      struct zrpc_prefix nh_pfx;

      /* assume prefix is evpn */
      if (p->family == AF_L2VPN &&
	  p->u.prefix_evpn.route_type == EVPN_INCLUSIVE_MULTICAST_ETHERNET_TAG)
	{
	  memset(&nh_pfx, 0, sizeof(struct zrpc_prefix));
	  if (p->u.prefix_evpn.u.prefix_imethtag.ip_len == ZRPC_UTIL_IPV4_PREFIX_LEN_MAX)
	    {
	      nh_pfx.family = AF_INET;
	      nh_pfx.u.prefix4.s_addr = p->u.prefix_evpn.u.prefix_imethtag.ip.in4.s_addr;
	    }
	  else
	    {
	      nh_pfx.family = AF_INET6;
	      memcpy(&nh_pfx.u.prefix6, &p->u.prefix_evpn.u.prefix_imethtag.ip.in6,
		     sizeof(struct in6_addr));
	    }
	  nh_pfx.prefixlen = p->u.prefix_evpn.u.prefix_imethtag.ip_len;
	  zrpc_util_prefix_2str (&nh_pfx, nh_str, ZRPC_UTIL_IPV6_LEN_MAX);
	  nexthop = nh_str;
	}

      memset (&null_rd, 0, sizeof (struct zrpc_rd_prefix));
      if (memcmp (&s->outbound_rd, &null_rd, sizeof(struct zrpc_rd_prefix)))
        zrpc_util_rd_prefix2str(&s->outbound_rd, vrf_rd_str, sizeof(vrf_rd_str));
      else
        zrpc_invalid_rd = 1;

      if (p->family == AF_L2VPN &&
          p->u.prefix_evpn.route_type == EVPN_INCLUSIVE_MULTICAST_ETHERNET_TAG)
        {
          if (s->announce == BGP_EVENT_PUSH_EVPN_RT)
            ret = zrpc_bgp_updater_on_update_push_evpn_rt(p->u.prefix_evpn.route_type,
                                                    (zrpc_invalid_rd == 1) ? NULL : vrf_rd_str,
                                                    NULL,            /* esi */
                                                    s->ethtag,       /* evi */
                                                    s->tunnel_type,  /* tunnelType */
                                                    nexthop,         /* tunnelId */
                                                    s->label,        /* label */
                                                    false            /* singleActiveMode */
                                                   );
          else
            ret = zrpc_bgp_updater_on_update_withdraw_evpn_rt(p->u.prefix_evpn.route_type,
                                                        (zrpc_invalid_rd == 1) ? NULL : vrf_rd_str,
                                                        NULL,            /* esi */
                                                        s->ethtag,       /* evi */
                                                        s->tunnel_type,  /* tunnelType */
                                                        nexthop,         /* tunnelId */
                                                        s->label,        /* label */
                                                        false            /* singleActiveMode */
                                                       );
        }
    }
#endif /* HAVE_THRIFT_V5 */
  else if (s->announce == BGP_EVENT_SHUT)
    {
      t = &tt;
      memset(t, 0, sizeof(struct bgp_event_shut));
      zrpc_util_copy_prefix (&t->peer, &s->nexthop);
      t->type = (uint8_t)s->label;
      t->subtype = (uint8_t)s->prefix.u.prefix4.s_addr;
      zrpc_util_prefix_2str (&t->peer, nh_str, ZRPC_UTIL_IPV6_LEN_MAX);
      nexthop = nh_str;
      ret = zrpc_bgp_updater_on_notification_send_event(nexthop, t->type, t->subtype);
    }
#ifdef HAVE_THRIFT_V5
  else if (s->announce == BGP_EVENT_BFD_STATUS)
    {
      struct bgp_event_bfd_status st;

      st.as = s->label;
      st.up_down = (uint8_t)s->prefix.u.prefix4.s_addr;
      zrpc_util_copy_prefix (&st.peer, &s->nexthop);
      zrpc_util_prefix_2str (&st.peer, nh_str, ZRPC_UTIL_IPV6_LEN_MAX);
      nexthop = nh_str;
      if (st.up_down)
        ret = zrpc_bgp_updater_peer_up (nexthop, (const gint64)st.as);
      else
        ret = zrpc_bgp_updater_peer_down (nexthop, (const gint64)st.as);
    }
#endif

  if (s->esi)
    free (s->esi);
  if (s->mac_router)
    free (s->mac_router);
  if (s->gatewayIp)
    free (s->gatewayIp);
  if (s->tunnel_id)
    free (s->tunnel_id);

  if (ret == FALSE)
    {
      zrpc_info ("bgp->sdnc message failed to be sent");
      ctxt->bgp_update_lost_msgs++;
    }

#ifdef HAVE_THRIFT_V6
  node->retry_times++;
  node->msg_not_sent = (ret == FALSE) ? 1 : 0;
  if (node->retry_times > tm->zrpc_bgp_updater_max_retries)
    {
      zrpc_info ("Maximum retry times (%d) reached, resetting connection to ODL",
                 tm->zrpc_bgp_updater_max_retries);
      zrpc_transport_cancel_monitor(ctxt);
      zrpc_transport_check_response(ctxt, FALSE);
    }
#endif

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

  setup->bfdd_enabled = 0;
  setup->bfd_multihop = 0;
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
  if (!setup->bgp_updater_transport)
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
    {
      int val = 0;
      qzcclient_setsockopt(setup->qzc_subscribe_sock, ZMQ_LINGER,
                           &val, sizeof(val));
      qzcclient_close (setup->qzc_subscribe_sock);
      setup->qzc_subscribe_sock = NULL;
    }

  if(setup->qzc_sock)
    {
      int val = 0;
      qzcclient_setsockopt(setup->qzc_sock, ZMQ_LINGER, &val, sizeof(val));
      qzcclient_close (setup->qzc_sock);
      setup->qzc_sock = NULL;
    }
}

void zrpc_vpnservice_setup_qzc(struct zrpc_vpnservice *setup)
{
  if(setup->zmq_subscribe_sock && setup->qzc_subscribe_sock == NULL )
    setup->qzc_subscribe_sock = qzcclient_subscribe(tm->global, \
                                                    setup->zmq_subscribe_sock, \
                                                    zrpc_vpnservice_callback,
                                                    QZC_CLIENT_ZMQ_LIMIT_RX);
}

void zrpc_vpnservice_terminate_qzc_bfdd(struct zrpc_vpnservice *setup)
{
  if(!setup)
    return;

  if(setup->qzc_bfdd_sock)
    {
      int val = 0;
      qzcclient_setsockopt(setup->qzc_bfdd_sock, ZMQ_LINGER, &val, sizeof(val));
      qzcclient_close (setup->qzc_bfdd_sock);
      setup->qzc_bfdd_sock = NULL;
    }
}

void zrpc_vpnservice_terminate_bfd(struct zrpc_vpnservice *setup)
{
  if(!setup)
    return;

  zrpc_vpnservice_terminate_qzc_bfdd(setup);
  zrpc_kill_child (BFDD_PID, "BFD");
  zrpc_kill_child (ZEBRA_PID, "ZEBRA");
  setup->bfdd_enabled = 0;
  if (setup->bfd_multihop)
    setup->bfd_multihop = 0;
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
  zrpc_debug_set_log_with_level(setup->bgp_context->logFile, setup->bgp_context->logLevel);
  if (zrpc_disable_stdout)
    zrpc_debug_configure_stdout (0);
  if (zrpc_disable_syslog)
    zrpc_debug_configure_syslog (0);
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

  THREAD_TIMER_OFF(setup->config_stale_thread);

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
  setup->bgp_updater_client_need_select = FALSE;
  setup->bgp_updater_select_in_progress = FALSE;
  response = zrpc_client_transport_open (setup->bgp_updater_transport->transport,
                                         &error, &setup->bgp_updater_client_need_select);
  if (error)
    {
      zrpc_log ("%s: zrpc_client_transport_open: %s\n", __func__, error->message);
      g_error_free (error);
    }
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
    {
      *setup = NULL;
      return;
    }
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
      zrpc_info("Unable to flush thrift socket: %s\n", error->message);
      g_error_free (error);
      error = NULL;
    }
  thrift_transport_close(peer->transport, &error);
  if (error != NULL)
    {
      zrpc_info("Unable to close thrift socket: %s\n", error->message);
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

void zrpc_config_stale_timer_flush(struct zrpc_vpnservice *setup, bool donotflush)
{
  struct zrpc_vpnservice_cache_bgpvrf *vrf, *vrf_next;
  struct zrpc_vpnservice_cache_peer *peer, *peer_next;

  if (donotflush) {
    zrpc_err ("ODL/Bgp connection configuration synchronization failed, "
              "stale timer expired after %d seconds, not REMOVE any "
              "stale configuration below.", zrpc_stalemarker_timer);
  }

  for (vrf = setup->bgp_vrf_list; vrf; vrf = vrf_next)
    {
      vrf_next = vrf->next;
      if (donotflush)
        {
          for (int i = 0; i < ADDRESS_FAMILY_MAX; i++)
            for (int j = 0; j < SUBSEQUENT_ADDRESS_FAMILY_MAX; j++)
              if (vrf->afc[i][j] && CHECK_FLAG (vrf->stale_flags[i][j], BGP_CONFIG_FLAG_STALE))
                {
                  if (IS_ZRPC_DEBUG)
                    {
                      af_afi afi;
                      af_safi safi;
                      char rdstr[ZRPC_UTIL_RDRT_LEN];

                      if (i == ADDRESS_FAMILY_IP)
                        afi = AF_AFI_AFI_IP;
#if defined(HAVE_THRIFT_V3) || defined(HAVE_THRIFT_V4) || defined(HAVE_THRIFT_V5)
                      else if (i == ADDRESS_FAMILY_IPV6)
                        afi = AF_AFI_AFI_IPV6;
#endif
                      if (j == SUBSEQUENT_ADDRESS_FAMILY_MPLS_VPN)
                        safi = AF_SAFI_SAFI_MPLS_VPN;
#if defined(HAVE_THRIFT_V2) || defined(HAVE_THRIFT_V3) || defined(HAVE_THRIFT_V4) || defined(HAVE_THRIFT_V5)
                      else if (j == SUBSEQUENT_ADDRESS_FAMILY_EVPN)
                        safi = AF_SAFI_SAFI_EVPN;
#endif

                      zrpc_util_rd_prefix2str (&(vrf->outbound_rd), rdstr, ZRPC_UTIL_RDRT_LEN);
                      zrpc_info ("Stale vrf(%s, afi %u, safi %u) should be deleted", rdstr, afi, safi);
                    }
                }
        }
      else
        zrpc_delete_stale_vrf(setup, vrf);
    }

  for (peer = setup->bgp_peer_list; peer; peer = peer_next)
    {
      peer_next = peer->next;
      if (CHECK_FLAG(peer->flags, BGP_CONFIG_FLAG_STALE))
        {
          if (donotflush)
            {
              if (IS_ZRPC_DEBUG)
                {
                  zrpc_info ("Stale peer %s(%llx) should be deleted",
                             peer->peerIp, (long long unsigned int)peer->peer_nid);
                }
            }
          else
            zrpc_delete_stale_peer(setup, peer);
        }
    }
}

static int zrpc_config_stale_timer_expire (struct thread *thread)
{
  struct zrpc_vpnservice *setup;

  setup = THREAD_ARG (thread);
  assert (setup);
  zrpc_config_stale_timer_flush(setup, TRUE);
  return 0;
}

/* called when ODL builds TCP connection on port 7644 */
void zrpc_config_stale_set(struct zrpc_vpnservice *setup)
{
  struct zrpc_vpnservice_cache_bgpvrf *vrf;
  struct zrpc_vpnservice_cache_peer *peer;

  if (!zrpc_stalemarker_timer)
    return;
  if (!setup)
    return;
  if (zrpc_vpnservice_get_bgp_context(setup) == NULL ||
      zrpc_vpnservice_get_bgp_context(setup)->asNumber == 0)
    return;

  /* lookup in cache context, and set QBGP_CONFIG_STALE flag */
  for (vrf = setup->bgp_vrf_list; vrf; vrf = vrf->next)
    {
      for (int i = 0; i < ADDRESS_FAMILY_MAX; i++)
        for (int j = 0; j < SUBSEQUENT_ADDRESS_FAMILY_MAX; j++)
          if (vrf->afc[i][j])
            {
              if (IS_ZRPC_DEBUG)
                {
                  af_afi afi;
                  af_safi safi;
                  char rdstr[ZRPC_UTIL_RDRT_LEN];

		  if (i == ADDRESS_FAMILY_IP)
                    afi = AF_AFI_AFI_IP;
#if defined(HAVE_THRIFT_V3) || defined(HAVE_THRIFT_V4) || defined(HAVE_THRIFT_V5)
                  else if (i == ADDRESS_FAMILY_IPV6)
                    afi = AF_AFI_AFI_IPV6;
#endif
                  if (j == SUBSEQUENT_ADDRESS_FAMILY_MPLS_VPN)
                    safi = AF_SAFI_SAFI_MPLS_VPN;
#if defined(HAVE_THRIFT_V2) || defined(HAVE_THRIFT_V3) || defined(HAVE_THRIFT_V4) || defined(HAVE_THRIFT_V5)
                  else if (j == SUBSEQUENT_ADDRESS_FAMILY_EVPN)
                    safi = AF_SAFI_SAFI_EVPN;
#endif

                  zrpc_util_rd_prefix2str (&(vrf->outbound_rd), rdstr, ZRPC_UTIL_RDRT_LEN);
                  zrpc_info ("VRF(%s, afi %u, safi %u) set to STALE state", rdstr, afi, safi);
                }
              SET_FLAG (vrf->stale_flags[i][j], BGP_CONFIG_FLAG_STALE);
            }
    }

  for (peer = setup->bgp_peer_list; peer; peer = peer->next)
    {
      if (IS_ZRPC_DEBUG)
        zrpc_info ("Peer %s set to STALE state", peer->peerIp);
      SET_FLAG (peer->flags, BGP_CONFIG_FLAG_STALE);
    }

  THREAD_TIMER_OFF(setup->config_stale_thread);
  THREAD_TIMER_MSEC_ON(tm->global, setup->config_stale_thread, \
                       zrpc_config_stale_timer_expire, \
                       setup, zrpc_stalemarker_timer * 1000);
}
