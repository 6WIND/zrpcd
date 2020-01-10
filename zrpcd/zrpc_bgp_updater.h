/* zrpc thrift BGP Updater Client Part
 * Copyright (c) 2016 6WIND,
 *
 * This file is part of ZRPC daemon.
 *
 * See the LICENSE file.
 */

#ifndef _ZRPC_BGP_UPDATER_H
#define _ZRPC_BGP_UPDATER_H

struct thread;
struct zrpc_vpnservice;
struct zrpc_bgp_updater_client;

gboolean
zrpc_bgp_updater_on_notification_send_event (struct zrpc_bgp_updater_client *updater,
                                             const gchar * prefix,
                                             const gint8 errCode, const gint8 errSubcode);
#ifdef HAVE_THRIFT_V5
gboolean
zrpc_bgp_updater_peer_up (struct zrpc_bgp_updater_client *updater,
                          const gchar * ipAddress, const gint64 asNumber);
gboolean
zrpc_bgp_updater_peer_down (struct zrpc_bgp_updater_client *updater,
                            const gchar * ipAddress, const gint64 asNumber);

gboolean
zrpc_bgp_updater_on_update_push_evpn_rt(struct zrpc_bgp_updater_client *updater,
                                        const gint32 routeType, const gchar * rd,
                                        const gchar * esi, const gint64 evi,
                                        const pmsi_tunnel_type tunnelType,
                                        const gchar * tunnelId, const gint32 label,
                                        const gboolean singleActiveMode);
gboolean
zrpc_bgp_updater_on_update_withdraw_evpn_rt(struct zrpc_bgp_updater_client *updater,
                                            const gint32 routeType, const gchar * rd,
                                            const gchar * esi, const gint64 evi,
                                            const pmsi_tunnel_type tunnelType,
                                            const gchar * tunnelId, const gint32 label,
                                            const gboolean singleActiveMode);
#endif

int
zrpc_bgp_updater_on_start_config_resync_notification (struct thread *thread);
gboolean
zrpc_bgp_updater_on_start_config_resync_notification_quick (struct zrpc_bgp_updater_client *updater, gboolean restart);

gboolean
#if defined(HAVE_THRIFT_V1)
zrpc_bgp_updater_on_update_withdraw_route (struct zrpc_bgp_updater_client *updater, const gchar * rd,
                                           const gchar * prefix, const gint32 prefixlen,
#else
zrpc_bgp_updater_on_update_withdraw_route (struct zrpc_bgp_updater_client *updater,
                                           const protocol_type p_type, const gchar * rd,
                                           const gchar * prefix, const gint32 prefixlen,
#endif /* HAVE_THRIFT_V1 */
                                           const gchar * nexthop,  const gint64 ethtag,
                                           const gchar * esi, const gchar * macaddress, 
                                           const gint32 l3label, const gint32 l2label,
                                           const af_afi afi);

gboolean
#if defined(HAVE_THRIFT_V1)
zrpc_bgp_updater_on_update_push_route (struct zrpc_bgp_updater_client *updater, const gchar * rd,
                                       const gchar * prefix, const gint32 prefixlen,
#else
zrpc_bgp_updater_on_update_push_route (struct zrpc_bgp_updater_client *updater,
                                       const protocol_type p_type, const gchar * rd,
                                       const gchar * prefix, const gint32 prefixlen,
#endif /* HAVE_THRIFT_V1 */
                                       const gchar * nexthop, const gint64 ethtag,
                                       const gchar * esi, const gchar * macaddress,
                                       const gint32 l3label, const gint32 l2label,
                                       const gchar * routermac, const gchar *gatewayIp,
                                       const af_afi afi);

#ifdef HAVE_THRIFT_V6
extern void zrpc_bgp_updater_set_msg_queue (void);
#endif
#endif /* _ZRPC_BGP_UPDATER_H */
