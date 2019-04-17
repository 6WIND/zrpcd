/* zrpc thrift BGP Updater Client Part
 * Copyright (c) 2016 6WIND,
 *
 * This file is part of ZRPC daemon.
 *
 * See the LICENSE file.
 */

#include <stdio.h>
#include "config.h"

#include "zrpc_global.h"
#include "zrpcd/zrpc_thrift_wrapper.h"
#include "zrpcd/bgp_updater.h"
#include "zrpcd/bgp_configurator.h"
#include "zrpcd/zrpc_bgp_updater.h"
#include "zrpcd/zrpc_bgp_configurator.h"
#include "zrpcd/zrpc_vpnservice.h"
#include "zrpcd/zrpc_debug.h"

extern zrpc_status zrpc_transport_current_status;
extern void zrpc_transport_check_response(struct zrpc_vpnservice *setup, gboolean response);
extern void zrpc_transport_cancel_monitor(struct zrpc_vpnservice *setup);

static bool zrpc_bgp_updater_handle_response(struct zrpc_vpnservice *ctxt,
                                             bool *response,
                                             GError **perror,
                                             const char *name)
{
  bool should_retry = FALSE;
  GError *error = NULL;

    if (perror != NULL)
      {
        error = *perror;
        if (error && error->domain == THRIFT_TRANSPORT_ERROR &&
            error->code == THRIFT_TRANSPORT_ERROR_SEND)
          {
            /* errors that are worth to be retried */
            if (errno == EAGAIN || errno == EWOULDBLOCK) {
              int fd = zrpc_vpnservice_get_bgp_updater_socket(ctxt);
              fd_set wrfds;
              struct timeval tout;
              int optval, optlen, selret = 0, ret;
              bool need_reset = FALSE;

              zrpc_info ("%s: sent error %s (%d), using select (%d sec) to retry",
                         name, error->message, errno, tm->zrpc_select_time);
              FD_ZERO(&wrfds);
              FD_SET(fd, &wrfds);

              tout.tv_sec = 0;
              tout.tv_usec = tm->zrpc_select_time * 1000 * 1000;
              optval = -1;
              optlen = sizeof (optval);
              ctxt->bgp_update_thrift_retries++;
              ctxt->bgp_updater_select_in_progress = TRUE;
              optval = 0;
              selret = select(fd+1, NULL, &wrfds, NULL, &tout);
              if (selret <= 0)
                {
                  if (selret == 0)
                    zrpc_info ("%s: select timeout", name);
                  else
                    zrpc_info ("%s: select error - %s (%d)", name, strerror(errno), errno);
                  need_reset = TRUE;
                }
              else
                {
                  ret = getsockopt(fd, SOL_SOCKET, SO_ERROR, &optval, (socklen_t *)&optlen);
                  if (ret < 0 || optval)
                    {
                      if (optval)
                        errno = optval;
                      zrpc_info ("%s: getsockopt error - %s (%d)", name, strerror(errno), errno);
                      need_reset = TRUE;
                    }
                }
              if (need_reset)
                {
                  /* case timeout happens. reset connection */
                  ctxt->bgp_updater_select_in_progress = FALSE;
                  zrpc_info ("%s: sent error %s (%d), resetting connection",
                             name, error->message, errno);
                  ctxt->bgp_update_thrift_lost_msgs++;
                  zrpc_transport_cancel_monitor(ctxt);
                  should_retry = FALSE;
                  *response = FALSE;
                  zrpc_transport_check_response(ctxt, FALSE);
                }
              else
                {
                  zrpc_info ("%s: retry to send", name);
                  ctxt->bgp_updater_select_in_progress = FALSE;
                  ctxt->bgp_update_thrift_retries_successfull++;
                  should_retry = TRUE;
                }
            } else {
              zrpc_info ("%s: sent error %s (%d), resetting connection",
                         name, error->message, errno);
              /* other errors fall in error */
              ctxt->bgp_update_thrift_lost_msgs++;
              zrpc_transport_cancel_monitor(ctxt);
              should_retry = FALSE;
              *response = FALSE;
              zrpc_transport_check_response(ctxt, FALSE);
            }
            g_clear_error (&error);
            error = NULL;
          }
      }
    return should_retry;
}

static bool zrpc_bgp_updater_wait_reply (struct zrpc_vpnservice *ctxt,
                                         const char *name)
{
    int fd = zrpc_vpnservice_get_bgp_updater_socket(ctxt);
    fd_set rdfds;
    struct timeval tout;
    int optval, optlen, selret = 0, ret;
    bool need_reset = FALSE, should_read = TRUE;

    zrpc_info ("%s: using select (%d sec) to wait for server reply",
               name, tm->zrpc_select_time);
    FD_ZERO(&rdfds);
    FD_SET(fd, &rdfds);
    tout.tv_sec = 0;
    tout.tv_usec = tm->zrpc_select_time * 1000 * 1000;
    optval = -1;
    optlen = sizeof (optval);
    ctxt->bgp_updater_select_in_progress = TRUE;
    optval = 0;
    selret = select(fd + 1, &rdfds, NULL, NULL, &tout);
    if (selret <= 0)
      {
        if (selret == 0)
          {
            zrpc_info ("%s: select timeout", name);
            should_read = FALSE;
          }
        else
          {
            zrpc_info ("%s: select error - %s (%d)", name, strerror(errno), errno);
            need_reset = TRUE;
          }
      }
    else
      {
        ret = getsockopt(fd, SOL_SOCKET, SO_ERROR, &optval, (socklen_t *)&optlen);
        if (ret < 0 || optval)
          {
            if (optval)
              errno = optval;
            zrpc_info ("%s: getsockopt error - %s (%d)", name, strerror(errno), errno);
            need_reset = TRUE;
          }
      }

    if (need_reset)
      {
        zrpc_info ("%s: recv error %s (%d), resetting connection",
                   name, strerror(errno), errno);
        zrpc_transport_cancel_monitor(ctxt);
        should_read = FALSE;
        zrpc_transport_check_response(ctxt, FALSE);
      }
    ctxt->bgp_updater_select_in_progress = FALSE;

    return should_read;
}

/*
 * update push route notification message
 * sent when a vpnv4 route is pushed
 */
gboolean
#if defined(HAVE_THRIFT_V1)
zrpc_bgp_updater_on_update_push_route (const gchar * rd, const gchar * prefix, const gint32 prefixlen,
#else
zrpc_bgp_updater_on_update_push_route (const protocol_type p_type, const gchar * rd, const gchar * prefix, const gint32 prefixlen, 
#endif /* HAVE_THRIFT_V1 */
                                       const gchar * nexthop, const gint64 ethtag, const gchar * esi, const gchar * macaddress,
                                       const gint32 l3label, const gint32 l2label, const gchar * routermac,
                                       const gchar * gatewayIp, const af_afi afi)
{
  GError *error = NULL;
  gboolean response;
  struct zrpc_vpnservice *ctxt = NULL;
#if !defined(HAVE_THRIFT_V6)
  int thrift_tries;
#else
  gint32 _return;
#endif

  zrpc_vpnservice_get_context (&ctxt);
  if(!ctxt || !ctxt->bgp_updater_client)
      return FALSE;

#if !defined(HAVE_THRIFT_V6)
  for (thrift_tries = 0; thrift_tries < 2; thrift_tries++) {
#if defined(HAVE_THRIFT_V1)
    response = bgp_updater_client_send_on_update_push_route(ctxt->bgp_updater_client, rd, prefix, prefixlen, nexthop,
                                                            l3label, &error);
#else
    response = bgp_updater_client_send_on_update_push_route(ctxt->bgp_updater_client, p_type,
                                                            rd, prefix, prefixlen, nexthop, ethtag, esi, macaddress,
#if defined(HAVE_THRIFT_V4)
                                                            l3label, l2label, routermac, afi, &error);
#else
#if defined(HAVE_THRIFT_V2)
                                                            l3label, l2label, routermac, &error);
#else
                                                            l3label, l2label, routermac, gatewayIp, afi, &error);
#endif /* HAVE_THRIFT_V2 */
#endif /* HAVE_THRIFT_V4 */
#endif /* HAVE_THRIFT_V1 */
    if (zrpc_bgp_updater_handle_response(ctxt, (bool *)&response, &error, "onUpdatePushRoute()") == FALSE)
      break;
    error = NULL;
  }
#else /* HAVE_THRIFT_V6 */
  response = bgp_updater_client_send_on_update_push_route(ctxt->bgp_updater_client, p_type,
                                                          rd, prefix, prefixlen, nexthop, ethtag, esi, macaddress,
                                                          l3label, l2label, routermac, afi, &error);
  if (response == FALSE)
    {
      g_error_free (error);
      error = NULL;
    }
  else
    {
      if (zrpc_bgp_updater_wait_reply(ctxt, "onUpdatePushRoute()"))
        {
          response = bgp_updater_client_recv_on_update_push_route(ctxt->bgp_updater_client, &_return, &error);
          if (error)
            {
              zrpc_info ("onUpdatePushRoute(): recv error: %s (%d)", error->message, errno);
              g_error_free (error);
              error = NULL;
            }
          else
            {
              if (_return != 0)
                {
                  zrpc_info ("onUpdatePushRoute(): return value %d", _return);
                  response = FALSE;
                }
            }
        }
      else
        response = FALSE;
    }
#endif /* HAVE_THRIFT_V6 */

  if(IS_ZRPC_DEBUG_NOTIFICATION)
  {
    char ethtag_str[20];
    sprintf(ethtag_str,"ethtag %ld", ethtag);

    zrpc_info ("onUpdatePushRoute(rd %s, pfx %s, nh %s, l3label %d, l2label %d, %s%s, %s%s, %s %s%s) sent %s",
              rd, prefix? prefix:"none", nexthop, l3label, l2label,
              esi==NULL?"":"esi ",esi==NULL?"":esi,
              macaddress==NULL?"":"macaddress ",macaddress==NULL?"":macaddress,
              ethtag==0?"":ethtag_str,
              routermac==NULL?"":"routermac ", routermac==NULL?"":routermac,
              response == TRUE?"OK":"NOK");
  }
  return response;
}

/*
 * update withdraw route notification message
 * sent when a vpnv4 route is withdrawn
 */
gboolean
#if defined(HAVE_THRIFT_V1)
zrpc_bgp_updater_on_update_withdraw_route (const gchar * rd, const gchar * prefix, const gint32 prefixlen,
#else
zrpc_bgp_updater_on_update_withdraw_route (const protocol_type p_type, const gchar * rd, const gchar * prefix, const gint32 prefixlen, 
#endif /* HAVE_THRIFT_V1 */


                                           const gchar * nexthop,  const gint64 ethtag, const gchar * esi, const gchar * macaddress, 
                                           const gint32 l3label, const gint32 l2label, const af_afi afi)
{
  GError *error = NULL;
  gboolean response;
  struct zrpc_vpnservice *ctxt = NULL;
#if !defined(HAVE_THRIFT_V6)
  int thrift_tries;
#else
  gint32 _return;
#endif

  zrpc_vpnservice_get_context (&ctxt);
  if(!ctxt || !ctxt->bgp_updater_client)
      return FALSE;

#if !defined(HAVE_THRIFT_V6)
  for (thrift_tries = 0; thrift_tries < 2; thrift_tries++) {
#if defined(HAVE_THRIFT_V1)
    response = bgp_updater_client_on_update_withdraw_route(ctxt->bgp_updater_client, rd, prefix,
                                                           prefixlen, nexthop, l3label, &error);
#else
    response = bgp_updater_client_on_update_withdraw_route(ctxt->bgp_updater_client, p_type,
                                                           rd, prefix, prefixlen, nexthop, ethtag, esi, macaddress,
#if defined(HAVE_THRIFT_V2)
                                                           l3label, l2label, &error);
#else
                                                           l3label, l2label, afi, &error);
#endif /* HAVE_THRIFT_V2 */
#endif /* HAVE_THRIFT_V1 */
    if (zrpc_bgp_updater_handle_response(ctxt, (bool *)&response, &error, "onUpdateWithdrawRoute()") == FALSE)
      break;
    error = NULL;
  }
#else /* HAVE_THRIFT_V6 */
  response = bgp_updater_client_send_on_update_withdraw_route(ctxt->bgp_updater_client, p_type,
                                                              rd, prefix, prefixlen, nexthop, ethtag, esi, macaddress,
                                                              l3label, l2label, afi, &error);
  if (response == FALSE)
    {
      g_error_free (error);
      error = NULL;
    }
  else
    {
      if (zrpc_bgp_updater_wait_reply(ctxt, "onUpdateWithdrawRoute()"))
        {
          response = bgp_updater_client_recv_on_update_withdraw_route(ctxt->bgp_updater_client, &_return, &error);
          if (error)
            {
              zrpc_info ("onUpdateWithdrawRoute(): recv error: %s (%d)", error->message, errno);
              g_error_free (error);
              error = NULL;
            }
          else
            {
	      if (_return != 0)
                {
                  zrpc_info ("onUpdateWithdrawRoute(): return value %d", _return);
                  response = FALSE;
                }
            }
        }
      else
        response = FALSE;
    }
#endif /* HAVE_THRIFT_V6 */

  if(IS_ZRPC_DEBUG_NOTIFICATION)
    {
      char ethtag_str[20];
      sprintf(ethtag_str,"ethtag %ld", ethtag);

      zrpc_info ("onUpdateWithdrawRoute(rd %s, pfx %s/%d, nh %s, label %d, l2label %d, %s%s %s%s %s) sent %s", \
                rd, prefix? prefix:"none", prefixlen, nexthop, l3label, l2label,
                esi==NULL?"":"esi ",esi==NULL?"":esi,                   \
                macaddress==NULL?"":"macaddress ",macaddress==NULL?"":macaddress,
                ethtag==0?"":ethtag_str,
                response == TRUE?"OK":"NOK");
    }
  return response;
}

gboolean
zrpc_bgp_updater_on_start_config_resync_notification_quick (struct zrpc_vpnservice *ctxt, gboolean restart)
{
  gboolean response;
  GError *error = NULL;
#if !defined(HAVE_THRIFT_V6)
  int thrift_tries;
#else
  gint32 _return;
#endif

#if !defined(HAVE_THRIFT_V6)
  for (thrift_tries = 0; thrift_tries < 2; thrift_tries++) {
    response = bgp_updater_client_on_start_config_resync_notification(ctxt->bgp_updater_client, &error);
    if (zrpc_bgp_updater_handle_response(ctxt, (bool *)&response, &error, "onStartConfigResyncNotification()") == FALSE)
      break;
    error = NULL;
  }
#else /* HAVE_THRIFT_V6 */
  response = bgp_updater_client_send_on_start_config_resync_notification(ctxt->bgp_updater_client, &error);
  if (response == FALSE)
    {
      g_error_free (error);
      error = NULL;
    }
  else
    {
      if (zrpc_bgp_updater_wait_reply(ctxt, "onStartConfigResyncNotification()"))
        {
          response = bgp_updater_client_recv_on_start_config_resync_notification(ctxt->bgp_updater_client, &_return, &error);
          if (error)
            {
              zrpc_info ("onStartConfigResyncNotification(): recv error: %s (%d)", error->message, errno);
              g_error_free (error);
              error = NULL;
            }
          else
            {
	      if (_return != 0)
                {
                  zrpc_info ("onStartConfigResyncNotification(): return value %d", _return);
                  response = FALSE;
                }
            }
        }
      else
        response = FALSE;
    }
#endif /* HAVE_THRIFT_V6 */

  if(IS_ZRPC_DEBUG_NOTIFICATION)
    zrpc_info ("onStartConfigResyncNotification() %s", response == FALSE?"NOK":"OK");
  return response;
}

/*
 * start config resync notification message sent
 * when zrpcd has started and is ready and
 * available to receive thrift configuration commands
 */
int
zrpc_bgp_updater_on_start_config_resync_notification (struct thread *thread)
{
  struct zrpc_vpnservice *ctxt = NULL;
  static gboolean client_ready;

  ctxt = THREAD_ARG (thread);
  assert (ctxt);
  if((ctxt->bgp_updater_client == NULL) ||
     (zrpc_transport_current_status == ZRPC_TO_SDN_UNKNOWN) ||
     (zrpc_transport_current_status == ZRPC_TO_SDN_FALSE))
    {
      if (ctxt->bgp_updater_client)
        {
          zrpc_vpnservice_terminate_thrift_bgp_updater_client (ctxt);
        }
      /* start the retry mechanism */
      client_ready = zrpc_vpnservice_setup_thrift_bgp_updater_client(ctxt);
      zrpc_transport_check_response(ctxt, client_ready);
      if(client_ready == FALSE)
        {
          if(IS_ZRPC_DEBUG_NOTIFICATION)
            zrpc_info ("bgp->sdnc message failed to be sent");
        }
    }
  ctxt->bgp_update_total++;
  return 0;
}

/*
 * send event notification message
 */
gboolean
zrpc_bgp_updater_on_notification_send_event (const gchar * prefix, const gint8 errCode, const gint8 errSubcode)
{
  GError *error = NULL;
  gboolean response;
  struct zrpc_vpnservice *ctxt = NULL;
#if !defined(HAVE_THRIFT_V6)
  int thrift_tries;
#else
  gint32 _return;
#endif

  zrpc_vpnservice_get_context (&ctxt);
  if(!ctxt || !ctxt->bgp_updater_client)
      return FALSE;

#if !defined(HAVE_THRIFT_V6)
  for (thrift_tries = 0; thrift_tries < 2; thrift_tries++) {
    response = bgp_updater_client_on_notification_send_event(ctxt->bgp_updater_client, \
                                                             prefix, errCode, errSubcode, &error); 
    if (zrpc_bgp_updater_handle_response(ctxt, (bool *)&response, &error, "onNotificationSendEvent()") == FALSE)
      break;
    error = NULL;
  }
#else /* HAVE_THRIFT_V6 */
  response = bgp_updater_client_send_on_notification_send_event(ctxt->bgp_updater_client, \
                                                                prefix, errCode, errSubcode, &error);
  if (response == FALSE)
    {
      g_error_free (error);
      error = NULL;
    }
  else
    {
      if (zrpc_bgp_updater_wait_reply(ctxt, "onNotificationSendEvent()"))
        {
          response = bgp_updater_client_recv_on_notification_send_event(ctxt->bgp_updater_client, &_return, &error);
          if (error)
            {
              zrpc_info ("onNotificationSendEvent(): recv error: %s (%d)", error->message, errno);
              g_error_free (error);
              error = NULL;
            }
          else
            {
	      if (_return != 0)
                {
                  zrpc_info ("onNotificationSendEvent(): return value %d", _return);
                  response = FALSE;
                }
            }
        }
      else
        response = FALSE;
    }
#endif /* HAVE_THRIFT_V6 */

 if(IS_ZRPC_DEBUG_NOTIFICATION)
    zrpc_log ("onNotificationSendEvent(%s, errCode %d, errSubCode %d) %s", \
               prefix, errCode, errSubcode, response == FALSE?"NOK":"OK");
  return response;
}

#ifdef HAVE_THRIFT_V5
/*
 * send bfd status notification
 */
gboolean
zrpc_bgp_updater_peer_up (const gchar * ipAddress, const gint64 asNumber)
{
  GError *error = NULL;
  gboolean response;
  struct zrpc_vpnservice *ctxt = NULL;
#if !defined(HAVE_THRIFT_V6)
  int thrift_tries;
#else
  gint32 _return;
#endif

  zrpc_vpnservice_get_context (&ctxt);
  if(!ctxt || !ctxt->bgp_updater_client)
      return FALSE;

#if !defined(HAVE_THRIFT_V6)
  for (thrift_tries = 0; thrift_tries < 2; thrift_tries++) {
    response = bgp_updater_client_peer_up(ctxt->bgp_updater_client,
                                          ipAddress, asNumber, &error);
    if (zrpc_bgp_updater_handle_response(ctxt, (bool *)&response, &error, "peerUp()") == FALSE)
      break;
    error = NULL;
  }
#else /* HAVE_THRIFT_V6 */
  response = bgp_updater_client_send_peer_up(ctxt->bgp_updater_client,
                                             ipAddress, asNumber, &error);
  if (response == FALSE)
    {
      g_error_free (error);
      error = NULL;
    }
  else
    {
      if (zrpc_bgp_updater_wait_reply(ctxt, "peerUp()"))
        {
          response = bgp_updater_client_recv_peer_up(ctxt->bgp_updater_client, &_return, &error);
          if (error)
            {
              zrpc_info ("peerUp(): recv error: %s (%d)", error->message, errno);
              g_error_free (error);
              error = NULL;
            }
          else
            {
	      if (_return != 0)
                {
                  zrpc_info ("peerUp(): return value %d", _return);
                  response = FALSE;
                }
            }
        }
      else
        response = FALSE;
    }
#endif /* HAVE_THRIFT_V6 */

 if(IS_ZRPC_DEBUG_NOTIFICATION)
    zrpc_log ("peerUp(%s, asNumber %u) %s",
              ipAddress, asNumber,
              response == FALSE?"NOK":"OK");
  return response;
}

/*
 * send bfd status notification
 */
gboolean
zrpc_bgp_updater_peer_down (const gchar * ipAddress, const gint64 asNumber)
{
  GError *error = NULL;
  gboolean response;
  struct zrpc_vpnservice *ctxt = NULL;
#if !defined(HAVE_THRIFT_V6)
  int thrift_tries;
#else
  gint32 _return;
#endif

  zrpc_vpnservice_get_context (&ctxt);
  if(!ctxt || !ctxt->bgp_updater_client)
      return FALSE;

#if !defined(HAVE_THRIFT_V6)
  for (thrift_tries = 0; thrift_tries < 2; thrift_tries++) {
    response = bgp_updater_client_peer_down(ctxt->bgp_updater_client,
                                            ipAddress, asNumber, &error);
    if (zrpc_bgp_updater_handle_response(ctxt, (bool *)&response, &error, "peerDown()") == FALSE)
      break;
    error = NULL;
  }
#else /* HAVE_THRIFT_V6 */
  response = bgp_updater_client_send_peer_down(ctxt->bgp_updater_client,
                                               ipAddress, asNumber, &error);
  if (response == FALSE)
    {
      g_error_free (error);
      error = NULL;
    }
  else
    {
      if (zrpc_bgp_updater_wait_reply(ctxt, "peerDown()"))
        {
          response = bgp_updater_client_recv_peer_down(ctxt->bgp_updater_client, &_return, &error);
          if (error)
            {
              zrpc_info ("peerDown(): recv error: %s (%d)", error->message, errno);
              g_error_free (error);
              error = NULL;
            }
          else
            {
	      if (_return != 0)
                {
                  zrpc_info ("peerDown(): return value %d", _return);
                  response = FALSE;
                }
            }
        }
      else
        response = FALSE;
    }
#endif /* HAVE_THRIFT_V6 */

 if(IS_ZRPC_DEBUG_NOTIFICATION)
    zrpc_log ("peerDown(%s, asNumber %u) %s",
              ipAddress, asNumber,
              response == FALSE?"NOK":"OK");
  return response;
}

/*
 * update pushEvpnRT notification message
 */
gboolean
zrpc_bgp_updater_on_update_push_evpn_rt(const gint32 routeType, const gchar * rd,
                                        const gchar * esi, const gint64 evi,
                                        const pmsi_tunnel_type tunnelType,
                                        const gchar * tunnelId, const gint32 label,
                                        const gboolean singleActiveMode)
{
  GError *error = NULL;
  gboolean response;
  struct zrpc_vpnservice *ctxt = NULL;
#if !defined(HAVE_THRIFT_V6)
  int thrift_tries;
#else
  gint32 _return;
#endif

  zrpc_vpnservice_get_context (&ctxt);
  if(!ctxt || !ctxt->bgp_updater_client)
      return FALSE;

#if !defined(HAVE_THRIFT_V6)
  for (thrift_tries = 0; thrift_tries < 2; thrift_tries++) {
    response = bgp_updater_client_send_on_update_push_evpn_r_t(ctxt->bgp_updater_client,
                                                               routeType, rd,
                                                               esi, evi, tunnelType,
                                                               tunnelId, label,
                                                               singleActiveMode, &error);
    if (zrpc_bgp_updater_handle_response(ctxt, (bool *)&response, &error, "onUpdatePushEvpnRT()") == FALSE)
      break;
    error = NULL;
  }
#else /* HAVE_THRIFT_V6 */
  response = bgp_updater_client_send_on_update_push_evpn_r_t(ctxt->bgp_updater_client,
                                                             routeType, rd,
                                                             esi, evi, tunnelType,
                                                             tunnelId, label,
                                                             singleActiveMode, &error);
  if (response == FALSE)
    {
      g_error_free (error);
      error = NULL;
    }
  else
    {
      if (zrpc_bgp_updater_wait_reply(ctxt, "onUpdatePushEvpnRT()"))
        {
          response = bgp_updater_client_recv_on_update_push_evpn_r_t(ctxt->bgp_updater_client, &_return, &error);
          if (error)
            {
              zrpc_info ("onUpdatePushEvpnRT(): recv error: %s (%d)", error->message, errno);
              g_error_free (error);
              error = NULL;
            }
          else
            {
	      if (_return != 0)
                {
                  zrpc_info ("onUpdatePushEvpnRT(): return value %d", _return);
                  response = FALSE;
                }
            }
        }
      else
        response = FALSE;
    }
#endif /* HAVE_THRIFT_V6 */

  if (IS_ZRPC_DEBUG_NOTIFICATION)
    {
      zrpc_info ("onUpdatePushEvpnRT(routeType %d, rd %s, esi %s, evi %ld, tunnelType %d, tunnelId %s, label %d, singleActiveMode %s) sent %s",
                 routeType, rd,
                 (esi == NULL) ? "none" : esi,
                 evi, tunnelType,
                 (tunnelId == NULL) ? "none" : tunnelId,
                 label,
                 (singleActiveMode == TRUE) ? "true" : "false",
                 (response == TRUE) ? "OK" : "NOK");
    }
  return response;
}

/*
 * update withdrawEvpnRT notification message
 */
gboolean
zrpc_bgp_updater_on_update_withdraw_evpn_rt(const gint32 routeType, const gchar * rd,
                                            const gchar * esi, const gint64 evi,
                                            const pmsi_tunnel_type tunnelType,
                                            const gchar * tunnelId, const gint32 label,
                                            const gboolean singleActiveMode)
{
  GError *error = NULL;
  gboolean response;
  struct zrpc_vpnservice *ctxt = NULL;
#if !defined(HAVE_THRIFT_V6)
  int thrift_tries;
#else
  gint32 _return;
#endif

  zrpc_vpnservice_get_context (&ctxt);
  if(!ctxt || !ctxt->bgp_updater_client)
      return FALSE;

#if !defined(HAVE_THRIFT_V6)
  for (thrift_tries = 0; thrift_tries < 2; thrift_tries++) {
    response = bgp_updater_client_send_on_update_withdraw_evpn_r_t(ctxt->bgp_updater_client,
                                                                   routeType, rd,
                                                                   esi, evi, tunnelType,
                                                                   tunnelId, label,
                                                                   singleActiveMode, &error);
    if (zrpc_bgp_updater_handle_response(ctxt, (bool *)&response, &error, "onUpdateWithdrawEvpnRT()") == FALSE)
      break;
    error = NULL;
  }
#else /* HAVE_THRIFT_V6 */
  response = bgp_updater_client_send_on_update_withdraw_evpn_r_t(ctxt->bgp_updater_client,
                                                                 routeType, rd,
                                                                 esi, evi, tunnelType,
                                                                 tunnelId, label,
                                                                 singleActiveMode, &error);
  if (response == FALSE)
    {
      g_error_free (error);
      error = NULL;
    }
  else
    {
      if (zrpc_bgp_updater_wait_reply(ctxt, "onUpdateWithdrawEvpnRT()"))
        {
          response = bgp_updater_client_recv_on_update_withdraw_evpn_r_t(ctxt->bgp_updater_client, &_return, &error);
          if (error)
            {
              zrpc_info ("onUpdateWithdrawEvpnRT(): recv error: %s (%d)", error->message, errno);
              g_error_free (error);
              error = NULL;
            }
          else
            {
	      if (_return != 0)
                {
                  zrpc_info ("onUpdateWithdrawEvpnRT(): return value %d", _return);
                  response = FALSE;
                }
            }
        }
      else
        response = FALSE;
    }
#endif /* HAVE_THRIFT_V6 */

  if (IS_ZRPC_DEBUG_NOTIFICATION)
    {
      zrpc_info ("onUpdateWithdrawEvpnRT(routeType %d, rd %s, esi %s, evi %ld, tunnelType %d, tunnelId %s, label %d, singleActiveMode %s) sent %s",
                 routeType, rd,
                 (esi == NULL) ? "none" : esi,
                 evi, tunnelType,
                 (tunnelId == NULL) ? "none" : tunnelId,
                 label,
                 (singleActiveMode == TRUE) ? "true" : "false",
                 (response == TRUE) ? "OK" : "NOK");
    }
  return response;
}
#endif

#ifdef HAVE_THRIFT_V6
void zrpc_bgp_updater_set_msg_queue(void)
{
  struct zrpc_vpnservice *ctxt = NULL;
  struct qzmqclient_cb *cb = NULL;

  zrpc_vpnservice_get_context (&ctxt);
  if (!ctxt)
    return;
  if (!ctxt->qzc_subscribe_sock)
    return;
  if (!(cb = ctxt->qzc_subscribe_sock->cb))
    return;
  cb->queue_size = tm->zrpc_bgp_updater_queue_maximum_size;

  if (!cb->process_zmq_msg_queue)
    return;
  cb->process_zmq_msg_queue->spec.max_retries = tm->zrpc_bgp_updater_max_retries;
  cb->process_zmq_msg_queue->spec.hold = tm->zrpc_bgp_updater_retry_time_gap;

  return;
}
#endif
