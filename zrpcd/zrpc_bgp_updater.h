/* zrpc thrift BGP Updater Client Part
 * Copyright (c) 2016 6WIND,
 *
 * This file is part of ZRPC daemon.
 *
 * See the LICENSE file.
 */

#ifndef _ZRPC_BGP_UPDATER_H
#define _ZRPC_BGP_UPDATER_H


gboolean
zrpc_bgp_updater_on_notification_send_event (const gchar * prefix, const gint8 errCode, const gint8 errSubcode);

gboolean
zrpc_bgp_updater_on_start_config_resync_notification (void);

gboolean
zrpc_bgp_updater_on_update_withdraw_route (const protocol_type p_type, const gchar * rd, const gchar * prefix, const gint32 prefixlen, 
                                           const gchar * nexthop,  const gint64 ethtag, const gchar * esi, const gchar * macaddress, 
                                           const gint32 l3label, const gint32 l2label);

gboolean
zrpc_bgp_updater_on_update_push_route (const protocol_type p_type, const gchar * rd, const gchar * prefix, const gint32 prefixlen, 
                                       const gchar * nexthop, const gint64 ethtag, const gchar * esi, const gchar * macaddress,
                                       const gint32 l3label, const gint32 l2label, const gchar * routermac,
                                       const gchar *gatewayIp);

#endif /* _ZRPC_BGP_UPDATER_H */
