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
  return TRUE;
}

/*
 * update withdraw route notification message
 * sent when a vpnv4 route is withdrawn
 */
gboolean
zrpc_bgp_updater_on_update_withdraw_route (const gchar * rd, const gchar * prefix, const gint32 prefixlen)
{
  return TRUE;
}

/*
 * start config resync notification message sent
 * when zrpcd has started and is ready and
 * available to receive thrift configuration commands
 */
gboolean
zrpc_bgp_updater_on_start_config_resync_notification (void)
{

  return TRUE;
}

/*
 * send event notification message
 */
gboolean
zrpc_bgp_updater_on_notification_send_event (const gchar * prefix, const gint8 errCode, const gint8 errSubcode)
{
  return TRUE;
}
