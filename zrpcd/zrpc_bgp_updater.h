/* zrpc thrift BGP Updater Client Part
 * Copyright (c) 2016 6WIND,
 *
 * This file is part of ZRPC daemon.
 *
 * See the LICENSE file.
 */

#ifndef _ZRPC_BGP_UPDATER_H
#define _ZRPC_BGP_UPDATER_H

struct zrpc_vpnservice;

gboolean
zrpc_bgp_updater_on_notification_send_event (const gchar * prefix, const gint8 errCode, const gint8 errSubcode);

void
zrpc_bgp_updater_on_start_config_resync_notification (void);

gboolean
zrpc_bgp_updater_on_start_config_resync_notification_quick (struct zrpc_vpnservice *ctxt, gboolean restart);

gboolean
#if defined(HAVE_THRIFT_V1)
zrpc_bgp_updater_on_update_withdraw_route (const gchar * rd, const gchar * prefix, const gint32 prefixlen,
#else
zrpc_bgp_updater_on_update_withdraw_route (const protocol_type p_type, const gchar * rd, const gchar * prefix, const gint32 prefixlen,
#endif /* HAVE_THRIFT_V1 */
                                           const gchar * nexthop,  const gint64 ethtag, const gchar * esi, const gchar * macaddress, 
                                           const gint32 l3label, const gint32 l2label, const af_afi afi);

gboolean
#if defined(HAVE_THRIFT_V1)
zrpc_bgp_updater_on_update_push_route (const gchar * rd, const gchar * prefix, const gint32 prefixlen,
#else
zrpc_bgp_updater_on_update_push_route (const protocol_type p_type, const gchar * rd, const gchar * prefix, const gint32 prefixlen,
#endif /* HAVE_THRIFT_V1 */
                                       const gchar * nexthop, const gint64 ethtag, const gchar * esi, const gchar * macaddress,
                                       const gint32 l3label, const gint32 l2label, const gchar * routermac,
                                       const gchar *gatewayIp, const af_afi afi);

#endif /* _ZRPC_BGP_UPDATER_H */
