/* zrpc thrift BGP Updater Client Part
 * Copyright (c) 2016 6WIND,
 *
 * This file is part of ZRPC daemon.
 *
 * See the LICENSE file.
 */

#include <stdio.h>

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
zrpc_bgp_updater_on_update_push_route (const gchar * rd, const gchar * prefix, \
                                          const gint32 prefixlen, const gchar * nexthop, const gint32 label)
{
  GError *error = NULL;
  gboolean response;
  struct zrpc_vpnservice *ctxt = NULL;

  zrpc_vpnservice_get_context (&ctxt);
  if(!ctxt || !ctxt->bgp_updater_client)
      return FALSE;
  response = bgp_updater_client_send_on_update_push_route(ctxt->bgp_updater_client, \
                                                            rd, prefix, prefixlen, nexthop, label, &error);
  if(IS_ZRPC_DEBUG_NOTIFICATION)
    zrpc_log ("onUpdatePushRoute(rd %s, pfx %s, nh %s, label %d)", \
               rd, prefix, nexthop, label);
  return response;
}

/*
 * update withdraw route notification message
 * sent when a vpnv4 route is withdrawn
 */
gboolean
zrpc_bgp_updater_on_update_withdraw_route (const gchar * rd, const gchar * prefix, const gint32 prefixlen, const gchar * nexthop,  const gint32 label)
{
  GError *error = NULL;
  gboolean response;
  struct zrpc_vpnservice *ctxt = NULL;

  zrpc_vpnservice_get_context (&ctxt);
  if(!ctxt || !ctxt->bgp_updater_client)
      return FALSE;
  response = bgp_updater_client_on_update_withdraw_route(ctxt->bgp_updater_client, \
                                                         rd, prefix, prefixlen, nexthop,
                                                         label, &error);
  if(IS_ZRPC_DEBUG_NOTIFICATION)
    zrpc_log ("onUpdateWithdrawRoute(rd %s, pfx %s/%d, nh %s, label %d)", \
              rd, prefix, prefixlen, nexthop, label);
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
    zrpc_log ("onStartConfigResyncNotification()");
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
  if(IS_ZRPC_DEBUG_NOTIFICATION)
    zrpc_log ("onNotificationSendEvent(%s, errCode %d, errSubCode %d)", \
                prefix, errCode, errSubcode);
  return response;
}
