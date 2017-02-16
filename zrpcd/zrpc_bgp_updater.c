/* zrpc thrift BGP Updater Client Part
 * Copyright (c) 2016 6WIND,
 *
 * This file is part of ZRPC daemon.
 *
 * See the LICENSE file.
 */

#include <stdio.h>
#include "config.h"

#include "zrpcd/zrpc_thrift_wrapper.h"
#include "zrpcd/bgp_updater.h"
#include "zrpcd/bgp_configurator.h"
#include "zrpcd/zrpc_bgp_updater.h"
#include "zrpcd/zrpc_bgp_configurator.h"
#include "zrpcd/zrpc_vpnservice.h"
#include "zrpcd/zrpc_debug.h"

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

  zrpc_vpnservice_get_context (&ctxt);
  if(!ctxt || !ctxt->bgp_updater_client)
      return FALSE;
#if defined(HAVE_THRIFT_V1)
  response = bgp_updater_client_send_on_update_push_route(ctxt->bgp_updater_client, rd, prefix, prefixlen, nexthop,
                                                          l3label, &error);
#else
  response = bgp_updater_client_send_on_update_push_route(ctxt->bgp_updater_client, p_type,
                                                          rd, prefix, prefixlen, nexthop, ethtag, esi, macaddress, 
#if defined(HAVE_THRIFT_V2)
                                                          l3label, l2label, routermac, &error);
#else
                                                          l3label, l2label, routermac, gatewayIp, afi, &error);
#endif /* HAVE_THRIFT_V2 */
#endif /* HAVE_THRIFT_V1 */
  if(response == FALSE || IS_ZRPC_DEBUG_NOTIFICATION)
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
  if (response == FALSE)
    ctxt->bgp_update_thrift_lost_msgs++;
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

  zrpc_vpnservice_get_context (&ctxt);
  if(!ctxt || !ctxt->bgp_updater_client)
      return FALSE;
#if defined(HAVE_THRIFT_V1)
  response = bgp_updater_client_on_update_withdraw_route(ctxt->bgp_updater_client, rd, prefix, prefixlen, nexthop, l3label, &error);
#else
  response = bgp_updater_client_on_update_withdraw_route(ctxt->bgp_updater_client, p_type,
                                                         rd, prefix, prefixlen, nexthop, ethtag, esi, macaddress,
#if defined(HAVE_THRIFT_V2)
                                                         l3label, l2label, &error);
#else
                                                         l3label, l2label, afi, &error);
#endif /* HAVE_THRIFT_V2 */
#endif /* HAVE_THRIFT_V1 */
  if(response == FALSE || IS_ZRPC_DEBUG_NOTIFICATION)
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
  if (response == FALSE)
    ctxt->bgp_update_thrift_lost_msgs++;
  return response;
}

/*
 * start config resync notification message sent
 * when zrpcd has started and is ready and
 * available to receive thrift configuration commands
 */
gboolean
zrpc_bgp_updater_on_start_config_resync_notification (void)
{
  GError *error = NULL;
  gboolean response;
  struct zrpc_vpnservice *ctxt = NULL;

  zrpc_vpnservice_get_context (&ctxt);
  if(!ctxt || !ctxt->bgp_updater_client)
      return FALSE;
  response = bgp_updater_client_on_start_config_resync_notification(ctxt->bgp_updater_client, &error);
  if(IS_ZRPC_DEBUG_NOTIFICATION)
    zrpc_info ("onStartConfigResyncNotification()");
  if (response == FALSE)
    ctxt->bgp_update_thrift_lost_msgs++;
  return response;
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

  zrpc_vpnservice_get_context (&ctxt);
  if(!ctxt || !ctxt->bgp_updater_client)
      return FALSE;
  response = bgp_updater_client_on_notification_send_event(ctxt->bgp_updater_client, \
                                                           prefix, errCode, errSubcode, &error); 
  if(response == FALSE || IS_ZRPC_DEBUG_NOTIFICATION)
    zrpc_log ("onNotificationSendEvent(%s, errCode %d, errSubCode %d)", \
                prefix, errCode, errSubcode);
  if (response == FALSE)
    ctxt->bgp_update_thrift_lost_msgs++;
  return response;
}
