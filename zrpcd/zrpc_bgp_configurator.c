/* zrpc thrift BGP Configurator Server Part
 * Copyright (c) 2016 6WIND,
 *
 * This file is part of ZRPC daemon.
 *
 * See the LICENSE file.
 */
#include <stdio.h>

#include "zrpcd/zrpc_thrift_wrapper.h"
#include "zrpcd/zrpc_global.h"
#include "zrpcd/zrpc_memory.h"
#include "zrpcd/bgp_updater.h"
#include "zrpcd/bgp_configurator.h"
#include "zrpcd/zrpc_bgp_configurator.h"
#include "zrpcd/zrpc_vpnservice.h"
#include "zrpcd/zrpc_debug.h"
#include "zrpcd/zrpc_bgp_capnp.h"
#include "zrpcd/zrpc_util.h"
#include "zrpcd/qzmqclient.h"
#include "zrpcd/qzcclient.h"
#include "zrpcd/qzcclient.capnp.h"


#ifndef MAX
#define MAX(a,b) (((a)>(b))?(a):(b))
#endif
#define ZRPC_MAXPATH_DEFAULT_VAL   8

/* ---------------------------------------------------------------- */

static gboolean
instance_bgp_configurator_handler_create_peer(BgpConfiguratorIf *iface,
                                              gint32* ret, const gchar *routerId,
                                              const gint64 asNumber, GError **error);
static gboolean
instance_bgp_configurator_handler_start_bgp(BgpConfiguratorIf *iface, gint32* _return, const gint64 asNumber,
                                            const gchar * routerId, const gint32 port, const gint32 holdTime,
                                            const gint32 keepAliveTime, const gint32 stalepathTime,
                                            const gboolean announceFbit, GError **error);
gboolean
instance_bgp_configurator_handler_set_ebgp_multihop(BgpConfiguratorIf *iface, gint32* _return,
                                                    const gchar * peerIp, const gint32 nHops, GError **error);
gboolean
instance_bgp_configurator_handler_unset_ebgp_multihop(BgpConfiguratorIf *iface, gint32* _return,
                                                      const gchar * peerIp, GError **error);
gboolean
instance_bgp_configurator_handler_push_route(BgpConfiguratorIf *iface, gint32* _return, const protocol_type p_type, const gchar * prefix,
                                             const gchar * nexthop, const gchar * rd, const gint64 ethtag, const gchar * esi,
                                             const gchar * macaddress, const gint32 l3label, const gint32 l2label,
                                             const encap_type enc_type, const gchar * routermac, const char *gatewayIp, const af_afi afi, GError **error);
gboolean
instance_bgp_configurator_handler_withdraw_route(BgpConfiguratorIf *iface, gint32* _return, const protocol_type p_type, const gchar * prefix,
                                                 const gchar * rd,  const gint64 ethtag, const gchar * esi, const gchar * macaddress, const af_afi afi, GError **error);
gboolean
instance_bgp_configurator_handler_stop_bgp(BgpConfiguratorIf *iface, gint32* _return, const gint64 asNumber, GError **error);
gboolean
instance_bgp_configurator_handler_delete_peer(BgpConfiguratorIf *iface, gint32* _return, const gchar * ipAddress, GError **error);
gboolean
instance_bgp_configurator_handler_add_vrf(BgpConfiguratorIf *iface, gint32* _return, const layer_type l_type, const gchar * rd,
                                          const GPtrArray * irts, const GPtrArray * erts, GError **error);
gboolean
instance_bgp_configurator_handler_del_vrf(BgpConfiguratorIf *iface, gint32* _return, const gchar * rd, GError **error);
gboolean
instance_bgp_configurator_handler_set_update_source (BgpConfiguratorIf *iface, gint32* _return, const gchar * peerIp,
                                                     const gchar * srcIp, GError **error);
gboolean
instance_bgp_configurator_handler_unset_update_source (BgpConfiguratorIf *iface, gint32* _return, 
                                                       const gchar * peerIp, GError **error);
gboolean
instance_bgp_configurator_handler_enable_address_family(BgpConfiguratorIf *iface, gint32* _return, const gchar * peerIp,
                                                        const af_afi afi, const af_safi safi, GError **error);
gboolean
instance_bgp_configurator_handler_disable_address_family(BgpConfiguratorIf *iface, gint32* _return, const gchar * peerIp,
                                                         const af_afi afi, const af_safi safi, GError **error);
gboolean
instance_bgp_configurator_handler_set_log_config (BgpConfiguratorIf *iface, gint32* _return, const gchar * logFileName,
                                                  const gchar * logLevel, GError **error);
gboolean
instance_bgp_configurator_handler_enable_graceful_restart (BgpConfiguratorIf *iface, gint32* _return,
                                                           const gint32 stalepathTime, GError **error);
gboolean
instance_bgp_configurator_handler_disable_graceful_restart (BgpConfiguratorIf *iface, gint32* _return, GError **error);
gboolean
instance_bgp_configurator_handler_enable_default_originate(BgpConfiguratorIf *iface, gint32* _return, const gchar * peerIp,
                                                           const af_afi afi, const af_safi safi, GError **error);
gboolean
instance_bgp_configurator_handler_disable_default_originate(BgpConfiguratorIf *iface, gint32* _return, const gchar * peerIp,
                                                            const af_afi afi, const af_safi safi, GError **error);
gboolean
instance_bgp_configurator_handler_get_routes (BgpConfiguratorIf *iface, Routes ** _return, const protocol_type p_type, 
                                              const gint32 optype, const gint32 winSize,
                                              const af_afi afi, GError **error);

gboolean
instance_bgp_configurator_handler_enable_multipath(BgpConfiguratorIf *iface, gint32* _return,
                                                   const af_afi afi, const af_safi safi, GError **error);
gboolean
instance_bgp_configurator_handler_disable_multipath(BgpConfiguratorIf *iface, gint32* _return,
                                                    const af_afi afi, const af_safi safi, GError **error);
gboolean
instance_bgp_configurator_handler_multipaths(BgpConfiguratorIf *iface, gint32* _return,
                                             const gchar * rd, const gint32 maxPath, GError **error);
static void instance_bgp_configurator_handler_finalize(GObject *object);

/*
 * utilities functions for thrift <-> capnproto exchange
 * some of those functions implement a cache mecanism for some objects
 * like VRF, and Neighbors
 */
static uint64_t
zrpc_bgp_configurator_find_vrf(struct zrpc_vpnservice *ctxt, struct zrpc_rd_prefix *rd, gint32* _return);

static struct zrpc_vpnservice_cache_peer * 
zrpc_bgp_configurator_find_peer(struct zrpc_vpnservice *ctxt, const gchar *peerIp, 
                                gint32* _return, int create);

/* enable/disable address family bgp neighbor, using capnp */
static gboolean
zrpc_bgp_afi_config(struct zrpc_vpnservice *ctxt,  gint32* _return, const gchar * peerIp,
                      const af_afi afi, const af_safi safi, gboolean value, GError **error);

static gboolean
zrpc_bgp_set_multihops(struct zrpc_vpnservice *ctxt,  gint32* _return, const gchar * peerIp, \
                          const gint32 nHops, GError **error);


static gboolean
zrpc_bgp_set_log_config(struct zrpc_vpnservice *ctxt, 
                           struct zrpc_vpnservice_bgp_context *bgp_ctxt,
                           gint32* _return,  GError **error);


/* The implementation of InstanceBgpConfiguratorHandler follows. */

G_DEFINE_TYPE (InstanceBgpConfiguratorHandler,
               instance_bgp_configurator_handler,
               TYPE_BGP_CONFIGURATOR_HANDLER)

/* Each of a handler's methods accepts at least two parameters: A
   pointer to the service-interface implementation (the handler object
   itself) and a handle to a GError structure to receive information
   about any error that occurs.
   On success, a handler method returns TRUE. A return value of FALSE
   indicates an error occurred and the error parameter has been
   set. (Methods should not return FALSE without first setting the
   error parameter.) */

/*
 * thrift error messages returned
 * in case bgp_configurator has to trigger a thrift exception
 */
#define ERROR_BGP_AS_STARTED g_error_new(1, 2, "BGP AS %u started", zrpc_vpnservice_get_bgp_context(ctxt)->asNumber);
#define ERROR_BGP_RD_NOTFOUND g_error_new(1, 3, "BGP RD %s not configured", rd);
#define ERROR_BGP_AS_NOT_STARTED g_error_new(1, 1, "BGP AS not started");
#define ERROR_BGP_AFISAFI_NOTSUPPORTED g_error_new(1, 5, "BGP Afi/Safi %d/%d not supported", afi, safi);
#define ERROR_BGP_PEER_NOTFOUND g_error_new(1, 4, "BGP Peer %s not configured", peerIp);
#define ERROR_BGP_NO_ROUTES_FOUND g_error_new(1, 6, "BGP GetRoutes: no routes");
#define ERROR_BGP_INVALID_MAXPATH g_error_new(1, 5, "BGP maxpaths: out of range value 0 < %d < 8", maxPath);
#define ERROR_BGP_INVALID_AD g_error_new(1, 5, "BGP [Push/Withdraw]Route: invalid parameter for Auto Discovery");
#define ERROR_BGP_INVALID_AD_PROCESSING g_error_new(1, 6, "BGP [Push/Withdraw]Route: error when processing Auto Discovery");


/*
 * capnproto node identifiers used for zrpc<->bgp exchange
 * those node identifiers identify which structure and which action
 * to perform on this structure
 * example of structure handled:
 * - bgp master, bgp main instance, bgp neighbor, bgp vrf, route entry
 * example of action done:
 * - creation of a structure, get structure, set structure, remove structure
 */
/* bgp well know number. identifier used to recognize peer qzc */
uint64_t bgp_bm_wkn = 0x37b64fdb20888a50;
/* bgp master context */
uint64_t bgp_bm_nid;
/* bgp AS instance context */
uint64_t bgp_inst_nid;
/* bgp datatype */
uint64_t bgp_datatype_bgp = 0xfd0316f1800ae916; /* create_bgp_master_1 , get_bgp_1, set_bgp_1 */
/* handling bgpvrf structure
 * functions called in bgp : create_bgp_3. bgp_vrf_create. get_bgp_vrf_1, set_bgp_vrf_1
 */
uint64_t bgp_datatype_bgpvrf = 0x912c4b0c412022b1;
/* handling peer structure
 * functions called in bgp : struct peer. get_peer_3, set_peer_3
 */
uint64_t bgp_datatype_peer_3 = 0x8a3b3cd8d134cad1;
/* functions using this node identifier : struct peer. get_peer_2, set_peer_2 */
uint64_t bgp_datatype_create_bgp_2 = 0xd1f1619cff93fcb9;
/* node identifier defining afi safi context type */
uint64_t bgp_ctxttype_afisafi= 0x9af9aec34821d76a;

/* handling bgpvrf routes*/
/* get_bgp_vrf_2 XXX itertype, get_bgp_vrf_3, [un]set_bgp_vrf_3 */
uint64_t bgp_datatype_bgpvrfroute = 0x8f217eb4bad6c06f;
/* node identifier defining afi safi context type */
uint64_t bgp_ctxttype_afisafi_set_bgp_vrf_3= 0xac25a73c3ff455c0;
/* handling getRoutes - node information for getRoutes() */
/* functions using this node identifier: get_bgp_vrf_2, get_bgp_vrf_3 */
uint64_t bgp_ctxtype_bgpvrfroute = 0xac25a73c3ff455c0;
/* functions using this node identifier : get_bgp_vrf_2, get_bgp_vrf_3 */
uint64_t bgp_itertype_bgpvrfroute = 0xeb8ab4f58b7753ee;

static const char* af_flag_str[] = {
  "SendCommunity",
  "SendExtCommunity",
  "NextHopSelf",
  "ReflectorClient",
  "RServerClient",
  "SoftReconfig",
  "AsPathUnchanged",
  "NextHopUnchanged",
  "MedUnchanged",
  "DefaultOriginate",
  "RemovePrivateAS",
  "AllowAsIn",
  "OrfPrefixSm",
  "OrfPrefixRm",
  "MaxPrefix",
  "MaxPrefixWarning",
  "NextHopLocalUnchanged",
  "NextHopSelfAll"
};

static const char*
zrpc_af_flag2str(guint32 af_flag)
{
  int i = 0;

  while(af_flag)
    {
      af_flag = af_flag >> 1;
      if(af_flag)
        i++;
    }
  return af_flag_str[i];
}

/*
 * lookup routine that searches for a matching vrf
 * it searches first in the zrpc cache, then if not found,
 * it searches in BGP a vrf context.
 * It returns the capnp node identifier related to peer context,
 * 0 otherwise.
 */
static uint64_t
zrpc_bgp_configurator_find_vrf(struct zrpc_vpnservice *ctxt, struct zrpc_rd_prefix *rd, gint32* _return)
{
  struct zrpc_vpnservice_cache_bgpvrf *entry_bgpvrf, *entry_bgpvrf_next;

  /* lookup in cache context, first */
  for (entry_bgpvrf = ctxt->bgp_vrf_list; entry_bgpvrf; entry_bgpvrf = entry_bgpvrf_next)
    {
      entry_bgpvrf_next = entry_bgpvrf->next;
      if(0 == zrpc_util_rd_prefix_cmp(&(entry_bgpvrf->outbound_rd), rd))
        {
          if(IS_ZRPC_DEBUG_CACHE)
            zrpc_log ("CACHE_VRF: match lookup entry %llx", (long long unsigned int)entry_bgpvrf->bgpvrf_nid);
          return entry_bgpvrf->bgpvrf_nid; /* match */
        }
    }
  return 0;
}

/*
 * lookup routine that searches for a matching peer
 * it searches first in the zrpc cache, then if not found,
 * it searches in BGP a peer context.
 * It returns the capnp node identifier related to peer context,
 * 0 otherwise.
 */
static struct zrpc_vpnservice_cache_peer * 
zrpc_bgp_configurator_find_peer(struct zrpc_vpnservice *ctxt, const gchar *peerIp, 
                                gint32* _return, int create)
{
  struct zrpc_vpnservice_cache_peer *entry_bgppeer, *entry_bgppeer_next, *entry;
  int i,j;

  /* lookup in cache context, first */
  for (entry_bgppeer = ctxt->bgp_peer_list; entry_bgppeer; entry_bgppeer = entry_bgppeer_next)
    {
      entry_bgppeer_next = entry_bgppeer->next;
      if(0 == strcmp(entry_bgppeer->peerIp, peerIp))
        {
          if(IS_ZRPC_DEBUG_CACHE)
            zrpc_log ("CACHE_PEER : match lookup entry %s", entry_bgppeer->peerIp);
          return entry_bgppeer; /* match */
        }
    }
  if(!create)
    return 0;
  entry = ZRPC_CALLOC (sizeof(struct zrpc_vpnservice_cache_peer));
  entry->peerIp = ZRPC_STRDUP (peerIp);
  entry->peer_nid = 0;
  entry->asNumber = 0;
  for(i = 0; i < AFI_MAX; i++)
    for(j = 0; j < SAFI_MAX; j++)
      entry->enableAddressFamily[i][j] = 0;
  if(IS_ZRPC_DEBUG_CACHE)
    zrpc_log ("CACHE_PEER : add entry peer %s", peerIp);
  entry->next = ctxt->bgp_peer_list;
  ctxt->bgp_peer_list = entry;
  return entry;
}

/* enable/disable address family bgp neighbor, using capnp */
static gboolean
zrpc_bgp_afi_config(struct zrpc_vpnservice *ctxt,  gint32* _return, const gchar * peerIp,
                    const af_afi afi, const af_safi safi, gboolean value, GError **error)
{
  uint64_t peer_nid;
  struct capn rc;
  struct capn_segment *cs;
  capn_ptr afisafi_ctxt, peer_ctxt;
  struct peer peer;
  int af, saf;
  int ret;
  struct QZCGetRep *grep_peer;
  struct zrpc_vpnservice_cache_peer *c_peer;

  if(zrpc_vpnservice_get_bgp_context(ctxt) == NULL || zrpc_vpnservice_get_bgp_context(ctxt)->asNumber == 0)
    {
      *_return = BGP_ERR_FAILED;
      *error = ERROR_BGP_AS_NOT_STARTED;
      return FALSE;
    }
  if(peerIp == NULL)
    {
      *_return = BGP_ERR_PARAM;
      return FALSE;
    }
  if (afi == AF_AFI_AFI_IP)
    af = ADDRESS_FAMILY_IP;
  else   if (afi == AF_AFI_AFI_IPV6)
    af = ADDRESS_FAMILY_IPV6;
  else if (afi == AF_AFI_AFI_L2VPN)
    af = ADDRESS_FAMILY_L2VPN;
  else
    {
      *error = ERROR_BGP_AFISAFI_NOTSUPPORTED;
      *_return = BGP_ERR_PARAM;
      return FALSE;
    }
  if (safi == AF_SAFI_SAFI_MPLS_VPN)
    saf = SUBSEQUENT_ADDRESS_FAMILY_MPLS_VPN;
  else if (safi == AF_SAFI_SAFI_EVPN)
    saf = SUBSEQUENT_ADDRESS_FAMILY_EVPN;
  else if (safi == AF_SAFI_SAFI_IP_LABELED_UNICAST)
    saf = SUBSEQUENT_ADDRESS_FAMILY_LABELED_UNICAST;
  else
    {
      *error = ERROR_BGP_AFISAFI_NOTSUPPORTED;
      *_return = BGP_ERR_PARAM;
      return FALSE;
    }
  c_peer = zrpc_bgp_configurator_find_peer(ctxt, peerIp, _return, 1);
  if(c_peer == NULL)
    {
      return FALSE;
    }
  c_peer->enableAddressFamily[af][saf] = value;
  /* config saved, but not propagated to bgp while 
   * bgp peer creation not done 
   */
  if(c_peer->peer_nid == 0)
    {
      if(IS_ZRPC_DEBUG)
        {
          if(TRUE == value)
            zrpc_info ("enableAddressFamily( %s, afi %d, safi %d) config OK", peerIp, afi, safi);
          else
            zrpc_info ("disableAddressFamily( %s, afi %d, safi %d) config OK", peerIp, afi, safi);
        }
      return TRUE;
    }
  peer_nid = c_peer->peer_nid;

  /* prepare afisafi context */
  capn_init_malloc(&rc);
  cs = capn_root(&rc).seg;
  afisafi_ctxt = qcapn_new_AfiSafiKey(cs);
  capn_write8(afisafi_ctxt, 0, af);
  capn_write8(afisafi_ctxt, 1, saf);
  /* retrieve peer context */
  grep_peer = qzcclient_getelem (ctxt->qzc_sock, &peer_nid, 3, \
                                 &afisafi_ctxt, &bgp_ctxttype_afisafi,\
                                 NULL, NULL);
  if(grep_peer == NULL)
    {
      *_return = BGP_ERR_FAILED;
      capn_free(&rc);
      return FALSE;
    }
  /* change address family local context of peer */
  memset(&peer, 0, sizeof(struct peer));
  qcapn_BGPPeerAfiSafi_read(&peer, grep_peer->data, af, saf);
  if(TRUE == value)
    peer.afc[af][saf] = 1;
  else
    peer.afc[af][saf] = 0;
  /* reset qzc reply and rc context */
  qzcclient_qzcgetrep_free( grep_peer);
  /* prepare QZCSetRequest context */
  peer_ctxt = qcapn_new_BGPPeerAfiSafi(cs);
  /* set address family for peer */
  qcapn_BGPPeerAfiSafi_write(&peer, peer_ctxt, af, saf);
  ret = qzcclient_setelem (ctxt->qzc_sock, &peer_nid, 3, \
                           &peer_ctxt, &bgp_datatype_peer_3, \
                           &afisafi_ctxt, &bgp_ctxttype_afisafi);
  if(ret == 0)
    {
      *_return = BGP_ERR_FAILED;
      capn_free(&rc);
      return FALSE;
    }
  if(IS_ZRPC_DEBUG)
    {
      if(TRUE == value)
        zrpc_info ("enableAddressFamily( %s, afi %d, safi %d) OK", peerIp, afi, safi);
      else
        zrpc_info ("disableAddressFamily( %s, afi %d, safi %d) OK", peerIp, afi, safi);
    }
  *_return = 0;
  capn_free(&rc);
  return TRUE;
}

/* enable/disable any af flag of bgp neighbor, using capnp */
static gboolean
zrpc_bgp_peer_af_flag_config(struct zrpc_vpnservice *ctxt,  gint32* _return,
                                const gchar * peerIp, const af_afi afi,
                                const af_safi safi, gint16 value, gboolean update,
                                GError **error)
{
  uint64_t peer_nid;
  struct capn rc;
  struct capn_segment *cs;
  capn_ptr afisafi_ctxt, peer_ctxt;
  struct peer peer;
  int af, saf;
  int ret;
  struct QZCGetRep *grep_peer;
  struct zrpc_vpnservice_cache_peer *c_peer;

  if(   zrpc_vpnservice_get_bgp_context(ctxt) == NULL
     || zrpc_vpnservice_get_bgp_context(ctxt)->asNumber == 0)
    {
      *_return = BGP_ERR_FAILED;
      *error = ERROR_BGP_AS_NOT_STARTED;
      return FALSE;
    }
  if(peerIp == NULL)
    {
      *_return = BGP_ERR_PARAM;
      return FALSE;
    }
  if (afi == AF_AFI_AFI_IP)
    af = ADDRESS_FAMILY_IP;
  else if (afi == AF_AFI_AFI_IPV6)
    af = ADDRESS_FAMILY_IPV6;
  else if (afi == AF_AFI_AFI_L2VPN)
    af = ADDRESS_FAMILY_L2VPN;
  else
    {
      *error = ERROR_BGP_AFISAFI_NOTSUPPORTED;
      *_return = BGP_ERR_PARAM;
      return FALSE;
    }
  if (safi == AF_SAFI_SAFI_MPLS_VPN)
    saf = SUBSEQUENT_ADDRESS_FAMILY_MPLS_VPN;
  else if (safi == AF_SAFI_SAFI_EVPN)
    saf = SUBSEQUENT_ADDRESS_FAMILY_EVPN;
  else if (safi == AF_SAFI_SAFI_IP_LABELED_UNICAST)
    saf = SUBSEQUENT_ADDRESS_FAMILY_LABELED_UNICAST;
  else
    {
      *error = ERROR_BGP_AFISAFI_NOTSUPPORTED;
      *_return = BGP_ERR_PARAM;
      return FALSE;
    }
  c_peer = zrpc_bgp_configurator_find_peer(ctxt, peerIp, _return, 0);
  if(c_peer == NULL || c_peer->peer_nid == 0)
    {
      *_return = BGP_ERR_PARAM;
      *error = ERROR_BGP_PEER_NOTFOUND;
      return FALSE;
    }
  peer_nid = c_peer->peer_nid;
  /* prepare afisafi context */
  capn_init_malloc(&rc);
  cs = capn_root(&rc).seg;
  afisafi_ctxt = qcapn_new_AfiSafiKey(cs);
  capn_write8(afisafi_ctxt, 0, af);
  capn_write8(afisafi_ctxt, 1, saf);
  /* retrieve peer context */
  grep_peer = qzcclient_getelem (ctxt->qzc_sock, &peer_nid, 3,
                                 &afisafi_ctxt, &bgp_ctxttype_afisafi,
                                 NULL, NULL);
  if(grep_peer == NULL)
    {
      *_return = BGP_ERR_FAILED;
      capn_free(&rc);
      return FALSE;
    }
  /* change address family local context of peer */
  memset(&peer, 0, sizeof(struct peer));
  qcapn_BGPPeerAfiSafi_read(&peer, grep_peer->data, af, saf);
  if(TRUE == update)
    peer.af_flags[af][saf] |= value;
  else
    peer.af_flags[af][saf] &= ~value;
  /* reset qzc reply and rc context */
  qzcclient_qzcgetrep_free( grep_peer);
  /* prepare QZCSetRequest context */
  capn_init_malloc(&rc);
  cs = capn_root(&rc).seg;
  peer_ctxt = qcapn_new_BGPPeerAfiSafi(cs);
  /* set address family for peer */
  qcapn_BGPPeerAfiSafi_write(&peer, peer_ctxt, af, saf);
  ret = qzcclient_setelem (ctxt->qzc_sock, &peer_nid, 3, &peer_ctxt,
                           &bgp_datatype_peer_3, &afisafi_ctxt, &bgp_ctxttype_afisafi);
  if(ret == 0)
    {
      *_return = BGP_ERR_FAILED;
      capn_free(&rc);
      return FALSE;
    }
  if(IS_ZRPC_DEBUG)
    {
      if(TRUE == update)
        zrpc_info ("enable%s for peer %s in af_flag[%d][%d] OK", zrpc_af_flag2str(value),
                    peerIp, afi, safi);
      else
        zrpc_info ("disable%s for peer %s in af_flag[%d][%d] OK", zrpc_af_flag2str(value),
                    peerIp, afi, safi);
    }
  _return = 0;
  capn_free(&rc);
  return TRUE;
}

static gboolean
zrpc_bgp_set_log_config(struct zrpc_vpnservice *ctxt,
                           struct zrpc_vpnservice_bgp_context*bgp_ctxt,  
                           gint32* _return,  GError **error)
{
  struct capn rc;
  struct capn_segment *cs;
  struct bgp inst;
  struct QZCGetRep *grep;
  struct capn_ptr bgp;

  /* get bgp_master configuration */
  grep = qzcclient_getelem (ctxt->qzc_sock, &bgp_inst_nid, 1, NULL, NULL, NULL, NULL);
  if(grep == NULL)
    {
      *_return = BGP_ERR_FAILED;
      return FALSE;
    }
  memset(&inst, 0, sizeof(struct bgp));
  qcapn_BGP_read(&inst, grep->data);
  qzcclient_qzcgetrep_free( grep);
  /* update bgp configuration with logLevel and logText */
  capn_init_malloc(&rc);
  cs = capn_root(&rc).seg;
  bgp = qcapn_new_BGP(cs);
  /* set default stalepath time */
  if (bgp_ctxt->logFile == NULL)
    {
      *_return = BGP_ERR_PARAM;
      return FALSE;
    }
  if (inst.logLevel)
    free ( inst.logLevel);
  if (inst.logFile)
    free ( inst.logFile);
  if(bgp_ctxt->logLevel)
    inst.logLevel = strdup (bgp_ctxt->logLevel);
  else
    inst.logLevel = NULL;
  if(bgp_ctxt->logFile)
    inst.logFile = strdup (bgp_ctxt->logFile);
  qcapn_BGP_write(&inst, bgp);
  qzcclient_setelem (ctxt->qzc_sock, &bgp_inst_nid, 1,          \
                     &bgp, &bgp_datatype_bgp, NULL, NULL);
  if(IS_ZRPC_DEBUG)
    zrpc_info ("setLogConfig(%s, %s) OK", 
              bgp_ctxt->logFile,
              bgp_ctxt->logLevel==NULL?"none":
              bgp_ctxt->logLevel);
  capn_free(&rc);
  if (inst.notify_zmq_url)
    free (inst.notify_zmq_url);
  if (inst.logLevel)
    free ( inst.logLevel);
  if (inst.logFile)
    free ( inst.logFile);
  return TRUE;
}


/* 
 * Enable and change EBGP maximum number of hops for a given bgp neighbor 
 * If Peer is not configured, it returns an error
 * If nHops is set to 0, then the EBGP peers must be connected
 */
static gboolean
zrpc_bgp_set_multihops(struct zrpc_vpnservice *ctxt,  gint32* _return, const gchar * peerIp, const gint32 nHops, GError **error)
{
  uint64_t peer_nid;
  struct capn rc;
  struct capn_segment *cs;
  capn_ptr peer_ctxt;
  struct peer peer;
  struct QZCGetRep *grep_peer;
  struct zrpc_vpnservice_cache_peer *c_peer;

  memset (&peer, 0, sizeof (struct peer));
  if(zrpc_vpnservice_get_bgp_context(ctxt) == NULL || zrpc_vpnservice_get_bgp_context(ctxt)->asNumber == 0)
    {
      *_return = BGP_ERR_FAILED;
      *error = ERROR_BGP_AS_NOT_STARTED;
      return FALSE;
    }
  if(peerIp == NULL)
    {
      *_return = BGP_ERR_PARAM;
      return FALSE;
    }
  c_peer  = zrpc_bgp_configurator_find_peer(ctxt, peerIp, _return, 0);
  if(c_peer == NULL || c_peer->peer_nid == 0)
    {
      *_return = BGP_ERR_PARAM;
      *error = ERROR_BGP_PEER_NOTFOUND;
      return FALSE;
    }
  peer_nid =c_peer->peer_nid;
  /* retrieve peer context */
  grep_peer = qzcclient_getelem (ctxt->qzc_sock, &peer_nid, 2, \
                                 NULL, NULL, NULL, NULL);
  if(grep_peer == NULL)
    {
      *_return = BGP_ERR_FAILED;
      return FALSE;
    }
  /* change nHops */
  qcapn_BGPPeer_read(&peer, grep_peer->data);
  peer.ttl = nHops;
  qzcclient_qzcgetrep_free( grep_peer);
  /* prepare QZCSetRequest context */
  capn_init_malloc(&rc);
  cs = capn_root(&rc).seg;
  peer_ctxt = qcapn_new_BGPPeer(cs);
  qcapn_BGPPeer_write(&peer, peer_ctxt);
  if(qzcclient_setelem (ctxt->qzc_sock, &peer_nid, \
                        2, &peer_ctxt, &bgp_datatype_create_bgp_2, \
                        NULL, NULL))
    {
      if(IS_ZRPC_DEBUG)
        {
          if(nHops == 0)
            zrpc_info ("unsetEbgpMultiHop(%s) OK", peerIp);
          else
            zrpc_info ("setEbgpMultiHop(%s, %d) OK", peerIp, nHops);
        }
    }
  if (peer.host)
    ZRPC_FREE (peer.host);
  if (peer.desc)
    ZRPC_FREE (peer.desc);
  capn_free(&rc);
  return TRUE;
}

/*
 * Start a Create a BGP neighbor for a given routerId, and asNumber
 * If BGP is already started, then an error is returned : BGP_ERR_ACTIVE
 */
static gboolean
instance_bgp_configurator_handler_start_bgp(BgpConfiguratorIf *iface, gint32* _return, const gint64 asNumber,
                                            const gchar * routerId, const gint32 port, const gint32 holdTime,
                                            const gint32 keepAliveTime, const gint32 stalepathTime,
                                            const gboolean announceFbit, GError **error)
{
  struct zrpc_vpnservice *ctxt = NULL;
  int ret = 0;
  struct bgp inst;
  pid_t pid;
  char s_port[16];
  char s_zmq_sock[64];
  struct QZCReply *rep;
  char *parmList[] =  {(char *)"",\
                       (char *)BGPD_ARGS_STRING_1,\
                       (char *)"",                \
                       (char *)BGPD_ARGS_STRING_3,\
                       (char *)"",
                       NULL};

  zrpc_vpnservice_get_context (&ctxt);
  if(!ctxt)
    {
      *_return = BGP_ERR_FAILED;
      return FALSE;
    }
  /* check bgp already started */
  if(zrpc_vpnservice_get_bgp_context(ctxt))
    {
      if(zrpc_vpnservice_get_bgp_context(ctxt)->asNumber)
        {
          *_return = BGP_ERR_ACTIVE;
          *error = ERROR_BGP_AS_STARTED;
          return FALSE;
        }
    }
  else
    {
      zrpc_vpnservice_setup_bgp_context(ctxt);
    }
  if (asNumber < 0)
    {
      *_return = BGP_ERR_PARAM;
      return FALSE;
    }
  if (asNumber < 0)
    {
      *_return = BGP_ERR_PARAM;
      return FALSE;
    }
  /* run BGP process */
  parmList[0] = ctxt->bgpd_execution_path;
  sprintf(s_port, "%d", port);
  sprintf(s_zmq_sock, "%s-%u", ctxt->zmq_sock, (uint32_t)asNumber);
  parmList[2] = s_port;
  parmList[4] = s_zmq_sock;
  if ((pid = fork()) ==-1)
    {
      *_return = BGP_ERR_FAILED;
      return FALSE;
    }
  else if (pid == 0)
    {
      ret = execve((const char *)ctxt->bgpd_execution_path, parmList, NULL);
      /* return not expected */
      if(IS_ZRPC_DEBUG)
        zrpc_log ("execve failed: bgpd return not expected (%d)", errno);
      exit(1);
    }
  /* store process id */
  zrpc_vpnservice_get_bgp_context(ctxt)->proc = pid;
  /* creation of capnproto context - bgp configurator */
  /* creation of qzc client context */
  ctxt->qzc_sock = qzcclient_connect(s_zmq_sock);
  if(ctxt->qzc_sock == NULL)
    {
      *_return = BGP_ERR_FAILED;
      return FALSE;
    }
  /* send ping msg. wait for pong */
  rep = qzcclient_do(ctxt->qzc_sock, NULL);
  if( rep == NULL || rep->which != QZCReply_pong)
    {
      *_return = BGP_ERR_FAILED;
      if (rep)
        qzcclient_qzcreply_free (rep);
      return FALSE;
    }
  if (rep)
    qzcclient_qzcreply_free (rep);
  /* check well known number agains node identifier */
  bgp_bm_nid = qzcclient_wkn(ctxt->qzc_sock, &bgp_bm_wkn);
  zrpc_vpnservice_get_bgp_context(ctxt)->asNumber = (uint32_t) asNumber;
  if(IS_ZRPC_DEBUG)
    zrpc_info ("startBgp. bgpd called (AS %u, proc %d, .., stalepath %u, announceFbit %s)",
              (uint32_t)asNumber, pid, stalepathTime, announceFbit == true?"true":"false");
  /* from bgp_master, create bgp and retrieve bgp as node identifier */
  {
    struct capn_ptr bgp;
    struct capn rc;
    struct capn_segment *cs;

    capn_init_malloc(&rc);
    cs = capn_root(&rc).seg;
    memset(&inst, 0, sizeof(struct bgp));
    inst.as = (uint32_t)asNumber;
    if(routerId)
      inet_aton(routerId, &inst.router_id_static);
    bgp = qcapn_new_BGP(cs);
    qcapn_BGP_write(&inst, bgp);
    bgp_inst_nid = qzcclient_createchild (ctxt->qzc_sock, &bgp_bm_nid, \
                                          1, &bgp, &bgp_datatype_bgp);
    capn_free(&rc);
    if (bgp_inst_nid == 0)
      {
        *_return = BGP_ERR_FAILED;
        return FALSE;
      }
  }
  zrpc_bgp_set_log_config (ctxt, zrpc_vpnservice_get_bgp_context(ctxt), _return, error);

  /* from bgp_master, inject configuration, and send zmq message to BGP */
  {
    struct capn_ptr bgp;
    struct capn rc;
    struct capn_segment *cs;

    inst.as = (uint32_t)asNumber;
    if(routerId)
      inet_aton (routerId, &inst.router_id_static);
    inst.notify_zmq_url = ZRPC_STRDUP(ctxt->zmq_subscribe_sock);
    inst.default_holdtime = holdTime;
    inst.default_keepalive= keepAliveTime;
    if (stalepathTime)
      inst.stalepath_time = stalepathTime;
    else
      inst.stalepath_time = BGP_DEFAULT_STALEPATH_TIME;
    inst.restart_time = 900;
    inst.flags |= BGP_FLAG_GRACEFUL_RESTART;
    if (announceFbit == TRUE)
      inst.flags |= BGP_FLAG_GR_PRESERVE_FWD;
    else
      inst.flags &= ~BGP_FLAG_GR_PRESERVE_FWD;
    inst.flags |= BGP_FLAG_ASPATH_MULTIPATH_RELAX;
    capn_init_malloc(&rc);
    cs = capn_root(&rc).seg;
    bgp = qcapn_new_BGP(cs);
    qcapn_BGP_write(&inst, bgp);
    ret = qzcclient_setelem (ctxt->qzc_sock, &bgp_inst_nid, 1, \
                             &bgp, &bgp_datatype_bgp, \
                             NULL, NULL);
    ZRPC_FREE(inst.notify_zmq_url);
    inst.notify_zmq_url = NULL;
    capn_free(&rc);
  }
  if(IS_ZRPC_DEBUG)
    {
      if(ret)
          zrpc_info ("startBgp(%u, %s, .., %u, %s) OK",(uint32_t)asNumber, routerId,
                  stalepathTime, announceFbit == true?"true":"false");
      else
        zrpc_info ("startBgp(%u, %s, .., %u, %s) NOK",(uint32_t)asNumber, routerId,
                  stalepathTime, announceFbit == true?"true":"false");
    }
 return ret;
}


/*
 * Enable and change EBGP maximum number of hops for a given bgp neighbor
 * If Peer is not configured, it returns an error
 * If nHops is set to 0, then the EBGP peers must be connected
 */
gboolean
instance_bgp_configurator_handler_set_ebgp_multihop(BgpConfiguratorIf *iface, gint32* _return, const gchar * peerIp,
                                                    const gint32 nHops, GError **error)
{
  struct zrpc_vpnservice *ctxt = NULL;

  zrpc_vpnservice_get_context (&ctxt);
  if(!ctxt)
    {
      *_return = BGP_ERR_FAILED;
      return FALSE;
    }
  return zrpc_bgp_set_multihops(ctxt, _return, peerIp, nHops, error);
}

/*
 * Disable EBGP multihop mode by setting the TTL between
 * EBGP neighbors to 0
 * If Peer is not configured, it returns an error
 */
gboolean
instance_bgp_configurator_handler_unset_ebgp_multihop(BgpConfiguratorIf *iface, gint32* _return,
                                                      const gchar * peerIp, GError **error)
{
  struct zrpc_vpnservice *ctxt = NULL;

  zrpc_vpnservice_get_context (&ctxt);
  if(!ctxt)
    {
      *_return = BGP_ERR_FAILED;
      return FALSE;
    }
  return zrpc_bgp_set_multihops(ctxt, _return, peerIp, 0, error);
}

/*
 * Push Route for a given Route Distinguisher.
 * This route contains an IPv4 prefix, as well as an IPv4 nexthop.
 * A label is also set in the given Route.
 * If no VRF has been found matching the route distinguisher, then
 * an error is returned
 */
gboolean
instance_bgp_configurator_handler_push_route(BgpConfiguratorIf *iface, gint32* _return, const protocol_type p_type, const gchar * prefix,
                                             const gchar * nexthop, const gchar * rd, const gint64 ethtag, const gchar * esi,
                                             const gchar * macaddress, const gint32 l3label, const gint32 l2label, 
                                             const encap_type enc_type, const gchar * routermac, const char *gatewayIp, const af_afi afi, GError **error)
{
  struct zrpc_vpnservice *ctxt = NULL;
  struct bgp_api_route inst;
  struct zrpc_rd_prefix rd_inst;
  uint64_t bgpvrf_nid = 0;
  address_family_t afi_int = ADDRESS_FAMILY_IP;
  struct capn_ptr bgpvrfroute;
  struct capn_ptr afikey;
  struct capn rc;
  struct capn_segment *cs;
  int ret;
  gboolean is_auto_discovery = FALSE;

  zrpc_vpnservice_get_context (&ctxt);
  if(!ctxt)
    {
      *_return = BGP_ERR_FAILED;
      return FALSE;
    }
  if(zrpc_vpnservice_get_bgp_context(ctxt) == NULL || zrpc_vpnservice_get_bgp_context(ctxt)->asNumber == 0)
    {
      *_return = BGP_ERR_FAILED;
      *error = ERROR_BGP_AS_NOT_STARTED;
      return FALSE;
    }
  /* get route distinguisher internal representation */
  memset(&rd_inst, 0, sizeof(struct zrpc_rd_prefix));
  if (rd && zrpc_util_str2rd_prefix((char *)rd, &rd_inst))
    {
      /* if vrf not found, return an error */
      bgpvrf_nid = zrpc_bgp_configurator_find_vrf(ctxt, &rd_inst, _return);
      if(bgpvrf_nid == 0)
        {
          *error = ERROR_BGP_RD_NOTFOUND;
          *_return = BGP_ERR_PARAM;
          return FALSE;
        }
    }
  else if (PROTOCOL_TYPE_PROTOCOL_LU != p_type)
    {
      *error = ERROR_BGP_RD_NOTFOUND;
      *_return = BGP_ERR_PARAM;
      return FALSE;
    }
  /* prepare route entry */
  memset(&inst, 0, sizeof(struct bgp_api_route));
  inst.label = l3label;
  inst.l2label = l2label;
  inst.prefix.family = AF_INET;

  /* detect Auto Discovery and then check parameters coherency */
  is_auto_discovery = (p_type == PROTOCOL_TYPE_PROTOCOL_EVPN)
                      && (prefix == NULL)
                      && (enc_type == ENCAP_TYPE_VXLAN);
  if (!is_auto_discovery && !prefix)
    {
      *_return = BGP_ERR_PARAM;
      ret = FALSE;
      goto error;
    }

  if (nexthop)
    {
      ret = zrpc_util_str2_prefix (nexthop, &inst.nexthop);
      if (ret == 0)
        {
          *_return = BGP_ERR_PARAM;
          ret = FALSE;
          goto error;
        }
    }
  else
    {
      *_return = BGP_ERR_PARAM;
      ret = FALSE;
      goto error;
    }

  if(p_type == PROTOCOL_TYPE_PROTOCOL_EVPN)
    {
      afi_int = ADDRESS_FAMILY_L2VPN;
      if (gatewayIp)
        inet_aton (gatewayIp, &inst.gatewayIp);

      inst.ethtag = (uint32_t ) ethtag;
      if( !esi || zrpc_util_str2esi (esi, NULL) == 0)
        {
          *_return = BGP_ERR_PARAM;
          return FALSE;
        }
      inst.esi = strdup(esi);

      if( !routermac || zrpc_util_str2mac (routermac, NULL) == 0)
        {
          *_return = BGP_ERR_PARAM;
          ret = FALSE;
          goto error;
        }
      inst.mac_router = strdup(routermac);

      if (is_auto_discovery)
        {
          struct zrpc_macipaddr *m = &inst.prefix.u.prefix_macip;

          /* ethtag must be 0 or MAX_ET */
          if( ((ethtag != 0 && ethtag != BGP_ETHTAG_MAX_ET)
              || (!esi) || (!rd) || (macaddress)
              || ( ethtag == 0 && l2label == LBL_NO_LABEL)
              || ( ethtag == BGP_ETHTAG_MAX_ET && l2label != LBL_NO_LABEL))
              || l3label )
            {
              *_return = BGP_ERR_PARAM;
              *error = ERROR_BGP_INVALID_AD;
              ret = FALSE;
              goto error;
            }
          inst.prefix.family = AF_L2VPN;
          inst.prefix.prefixlen = ZRPC_L2VPN_PREFIX_AD;
          m->eth_tag_id = ethtag;
          goto inst_filled;
        }
      if (macaddress && zrpc_util_str2mac (macaddress, NULL) != 0)
        {
          struct zrpc_macipaddr *m = &inst.prefix.u.prefix_macip;
          inst.prefix.family = AF_L2VPN;
          inst.prefix.prefixlen = ZRPC_L2VPN_IPV4_PREFIX_LEN;
          m->eth_tag_id = ethtag;
          zrpc_util_str2mac(macaddress, (char*) &m->mac);
          if (strncmp(prefix, "0.0.0.0/0", 9))
            {
              struct zrpc_ipv4_prefix dummy;

              zrpc_util_str2ipv4_prefix(prefix,&dummy);
              if (dummy.prefixlen != 0 && dummy.prefixlen != 32)
                {
                  *_return = BGP_ERR_PARAM;
                   ret = FALSE;
                   goto error;
                }
              memcpy(&m->ip.in4, &dummy.prefix, sizeof(struct in_addr));
              m->ip_len = 32;
            }
          else
            m->ip_len = 0;
          m->mac_len = ZRPC_MAC_LEN * 8;
        }
      else
        {
          ret = zrpc_util_str2_prefix (prefix, (struct zrpc_prefix *) &inst.prefix);
          if (ret == 0)
            {
              *_return = BGP_ERR_PARAM;
              ret = FALSE;
              goto error;
            }
          if ((afi == AF_AFI_AFI_IP && inst.prefix.family == AF_INET6) ||
              (afi == AF_AFI_AFI_IPV6 && inst.prefix.family == AF_INET))
            {
              *_return = BGP_ERR_PARAM;
              ret = FALSE;
              goto error;
            }
        }
    }
  else
    {
      ret = zrpc_util_str2_prefix (prefix, (struct zrpc_prefix *) &inst.prefix);
      if (ret == 0)
        {
          *_return = BGP_ERR_PARAM;
          ret = FALSE;
          goto error;
        }
      if ((afi == AF_AFI_AFI_IP && inst.prefix.family == AF_INET6) ||
          (afi == AF_AFI_AFI_IPV6 && inst.prefix.family == AF_INET))
        {
          *_return = BGP_ERR_PARAM;
          ret = FALSE;
          goto error;
        }
      if (inst.prefix.family == AF_INET)
        afi_int = ADDRESS_FAMILY_IP;
      else if (inst.prefix.family == AF_INET6)
        afi_int = ADDRESS_FAMILY_IPV6;
      /* reuse l2label to carry safi information for */
      if (PROTOCOL_TYPE_PROTOCOL_LU == p_type)
        {
          inst.l2label = SUBSEQUENT_ADDRESS_FAMILY_LABELED_UNICAST;
        }
    }

inst_filled:
  capn_init_malloc(&rc);
  cs = capn_root(&rc).seg;
  bgpvrfroute = qcapn_new_BGPVRFRoute(cs, 0);
  qcapn_BGPVRFRoute_write(&inst, bgpvrfroute);
  /* prepare afi context */
  afikey = qcapn_new_AfiKey(cs);
  capn_write8(afikey, 0, afi_int);
  /* set route within afi context using QZC set request */
  if (bgpvrf_nid != 0)
    {
      ret = qzcclient_setelem (ctxt->qzc_sock, &bgpvrf_nid,             \
                               3, &bgpvrfroute, &bgp_datatype_bgpvrfroute, \
                               &afikey, &bgp_ctxttype_afisafi_set_bgp_vrf_3);
    }
  else
    {
      struct QZCGetRep *grep;

      /* get bgp_master configuration */
      grep = qzcclient_getelem (ctxt->qzc_sock, &bgp_inst_nid, 1, NULL, NULL, NULL, NULL);
      if(grep == NULL)
        {
          *_return = BGP_ERR_FAILED;
          return FALSE;
        }
      qzcclient_qzcgetrep_free( grep);
      ret = qzcclient_setelem (ctxt->qzc_sock, &bgp_inst_nid,
                               3, &bgpvrfroute, &bgp_datatype_bgpvrfroute,
                               &afikey,  &bgp_ctxttype_afisafi_set_bgp_vrf_3);
    }
  if(ret == 0)
    {
      *_return = BGP_ERR_FAILED;
      if (is_auto_discovery)
        *error = ERROR_BGP_INVALID_AD_PROCESSING;
    }
  capn_free(&rc);
 error:
  if(IS_ZRPC_DEBUG)
    {
      if (p_type == PROTOCOL_TYPE_PROTOCOL_EVPN)
        zrpc_info ("pushRoute(prefix %s, nexthop %s, rd %s, l3label %d, l2label %d,"
                    " esi %s, ethtag %d, routermac %s, macaddress %s, enc_type %d) OK",
                    prefix, nexthop, rd==NULL?"<none>":rd, l3label, l2label, esi, ethtag,
                    routermac, macaddress, enc_type);
      else
        zrpc_info ("pushRoute(prefix %s, nexthop %s, rd %s, label %d) OK",
                  prefix, nexthop, rd==NULL?"<none>":rd, l3label);
    }
  if (inst.esi)
    free(inst.esi);
  if (inst.mac_router)
    free(inst.mac_router);
  return ret;
}

/*
 * Withdraw Route for a given Route Distinguisher and IPv4 prefix
 * If no VRF has been found matching the route distinguisher, then
 * an error is returned
 */
gboolean
instance_bgp_configurator_handler_withdraw_route(BgpConfiguratorIf *iface, gint32* _return, const protocol_type p_type, const gchar * prefix,
                                                 const gchar * rd,  const gint64 ethtag, const gchar * esi, const gchar * macaddress, const af_afi afi, GError **error)
{
  struct zrpc_vpnservice *ctxt = NULL;
  struct bgp_api_route inst;
  struct zrpc_rd_prefix rd_inst;
  uint64_t bgpvrf_nid = 0;
  address_family_t afi_int = ADDRESS_FAMILY_IP;
  struct capn_ptr bgpvrfroute;
  struct capn_ptr afikey;
  struct capn rc;
  struct capn_segment *cs;
  int ret;
  gboolean is_auto_discovery = FALSE;

  zrpc_vpnservice_get_context (&ctxt);
  if(!ctxt)
    {
      *_return = BGP_ERR_FAILED;
      return FALSE;
    }
  if(zrpc_vpnservice_get_bgp_context(ctxt) == NULL || zrpc_vpnservice_get_bgp_context(ctxt)->asNumber == 0)
    {
      *_return = BGP_ERR_FAILED;
      *error = ERROR_BGP_AS_NOT_STARTED;
      return FALSE;
    }
  if (rd && zrpc_util_str2rd_prefix((char *)rd, &rd_inst))
    {
      /* if vrf not found, return an error */
      bgpvrf_nid = zrpc_bgp_configurator_find_vrf(ctxt, &rd_inst, _return);
      if(bgpvrf_nid == 0)
        {
          *error = ERROR_BGP_RD_NOTFOUND;
          *_return = BGP_ERR_PARAM;
          return FALSE;
        }
    }
  else if (PROTOCOL_TYPE_PROTOCOL_LU != p_type)
    {
      *error = ERROR_BGP_RD_NOTFOUND;
      *_return = BGP_ERR_PARAM;
      return FALSE;
    }
  /* prepare route entry for AFI=IP */
  memset(&inst, 0, sizeof(struct bgp_api_route));
  inst.prefix.family = AF_INET;

  /* detect Auto Discovery and then check parameters coherency */
  is_auto_discovery = (p_type == PROTOCOL_TYPE_PROTOCOL_EVPN) && (prefix == NULL);
  if (!is_auto_discovery && !prefix)
  {
    *_return = BGP_ERR_PARAM;
    ret = FALSE;
    goto error;
  }

  if(p_type == PROTOCOL_TYPE_PROTOCOL_EVPN)
    {
      afi_int = ADDRESS_FAMILY_L2VPN;
      if( !esi || zrpc_util_str2esi (esi,NULL) == 0)
        {
          *_return = BGP_ERR_PARAM;
          return FALSE;
        }
      inst.esi = strdup(esi);
      inst.ethtag = ethtag;
      /* detect Auto Discovery and then check parameters coherency */
      if (is_auto_discovery)
        {
          struct zrpc_macipaddr *m = &inst.prefix.u.prefix_macip;

          /* labels must be 0, ethtag must be 0 or MAX_ET */
          if(( ethtag != 0 && ethtag != BGP_ETHTAG_MAX_ET)
              || (!esi) || (!rd) || (macaddress))
            {
              *error = ERROR_BGP_INVALID_AD;
              *_return = BGP_ERR_PARAM;
              ret = FALSE;
              goto error;
            }
          inst.prefix.family = AF_L2VPN;
          inst.prefix.prefixlen = ZRPC_L2VPN_PREFIX_AD;
          m->eth_tag_id = ethtag;
          goto inst_filled;
        }

      if (macaddress && zrpc_util_str2mac (macaddress, NULL) != 0)
        {
          struct zrpc_macipaddr *m = &inst.prefix.u.prefix_macip;
          inst.prefix.family = AF_L2VPN;
          inst.prefix.prefixlen = ZRPC_L2VPN_IPV4_PREFIX_LEN;
          m->eth_tag_id = ethtag;
          zrpc_util_str2mac(macaddress, (char*) &m->mac);
          if (strncmp(prefix, "0.0.0.0/0", 9))
            {
              struct zrpc_ipv4_prefix dummy;

              zrpc_util_str2ipv4_prefix(prefix,&dummy);
              memcpy(&m->ip.in4, &dummy.prefix, sizeof(struct in_addr));
              m->ip_len = 32;
            }
          else
            m->ip_len = 0;
          m->mac_len = ZRPC_MAC_LEN * 8;
        }
      else
        {
          ret = zrpc_util_str2_prefix (prefix, (struct zrpc_prefix *) &inst.prefix);
          if (ret == 0)
            {
              *_return = BGP_ERR_PARAM;
              ret = FALSE;
              goto error;
            }
          if ((afi == AF_AFI_AFI_IP && inst.prefix.family == AF_INET6) ||
              (afi == AF_AFI_AFI_IPV6 && inst.prefix.family == AF_INET))
            {
              *_return = BGP_ERR_PARAM;
              ret = FALSE;
              goto error;
            }
        }
    }
  else
    {
      ret = zrpc_util_str2_prefix (prefix, (struct zrpc_prefix *) &inst.prefix);
      if (ret == 0)
        {
          *_return = BGP_ERR_PARAM;
          ret = FALSE;
          goto error;
        }
      if ((afi == AF_AFI_AFI_IP && inst.prefix.family == AF_INET6) ||
          (afi == AF_AFI_AFI_IPV6 && inst.prefix.family == AF_INET))
        {
          *_return = BGP_ERR_PARAM;
          ret = FALSE;
          goto error;
        }
      if (inst.prefix.family == AF_INET)
        afi_int = ADDRESS_FAMILY_IP;
      else if (inst.prefix.family == AF_INET6)
        afi_int = ADDRESS_FAMILY_IPV6;
      /* reuse l2label to carry safi information for */
      if (PROTOCOL_TYPE_PROTOCOL_LU == p_type)
        {
          inst.l2label = SUBSEQUENT_ADDRESS_FAMILY_LABELED_UNICAST;
        }
    }

inst_filled:
  capn_init_malloc(&rc);
  cs = capn_root(&rc).seg;
  bgpvrfroute = qcapn_new_BGPVRFRoute(cs, 0);
  qcapn_BGPVRFRoute_write(&inst, bgpvrfroute);
  /* prepare afi context */
  afikey = qcapn_new_AfiKey(cs);
  capn_write8(afikey, 0, afi_int);

  if (bgpvrf_nid != 0)
    {
      /* set route within afi context using QZC set request */
      ret = qzcclient_unsetelem (ctxt->qzc_sock, &bgpvrf_nid, 3,      \
                                 &bgpvrfroute, &bgp_datatype_bgpvrfroute, \
                                 &afikey, &bgp_ctxttype_afisafi_set_bgp_vrf_3);
    }
  else
    {
      struct QZCGetRep *grep;

      /* get bgp_master configuration */
      grep = qzcclient_getelem (ctxt->qzc_sock, &bgp_inst_nid, 1, NULL, NULL, NULL, NULL);
      if(grep == NULL)
        {
          *_return = BGP_ERR_FAILED;
          return FALSE;
        }
      qzcclient_qzcgetrep_free( grep);
      ret = qzcclient_setelem (ctxt->qzc_sock, &bgp_inst_nid,
                               4, &bgpvrfroute, &bgp_datatype_bgpvrfroute,
                               &afikey,  &bgp_ctxttype_afisafi_set_bgp_vrf_3);
    }
  if(ret == 0)
    {
      *_return = BGP_ERR_FAILED;
      if (is_auto_discovery)
        *error = ERROR_BGP_INVALID_AD_PROCESSING;
    }
  capn_free(&rc);

error:
  if(IS_ZRPC_DEBUG)
    {
      if (p_type == PROTOCOL_TYPE_PROTOCOL_EVPN)
        zrpc_info ("withdrawRoute(prefix %s, rd %s,"
        " esi %s, ethtag %d, macaddress %s) OK",
        prefix, rd==NULL?"<none>":rd, esi, ethtag, macaddress);
      else
        zrpc_info ("withdrawRoute(prefix %s, rd %s) OK", prefix, rd);
    }
  free(inst.esi);
  return ret;
}

/* 
 * Stop BGP Router for a given AS Number
 * If BGP is already stopped, or give AS is not present, an error is returned
 */
gboolean
instance_bgp_configurator_handler_stop_bgp(BgpConfiguratorIf *iface, gint32* _return,
                                           const gint64 asNumber, GError **error)
{
  struct zrpc_vpnservice *ctxt = NULL;

  zrpc_vpnservice_get_context (&ctxt);
  if(!ctxt)
    {
      *_return = BGP_ERR_INACTIVE;
      *error = ERROR_BGP_AS_NOT_STARTED;
      return FALSE;
    }
  if(zrpc_vpnservice_get_bgp_context(ctxt) == NULL || zrpc_vpnservice_get_bgp_context(ctxt)->asNumber == 0)
    {
      *_return = BGP_ERR_INACTIVE;
      *error = ERROR_BGP_AS_NOT_STARTED;
      return FALSE;
    }
  if(asNumber < 0)
    {
      *_return = BGP_ERR_PARAM;
      return FALSE;
    }
  if((guint32)asNumber != zrpc_vpnservice_get_bgp_context(ctxt)->asNumber)
    {
      *_return = BGP_ERR_FAILED;
      return FALSE;
    }
  if (zrpc_kill_in_progress)
    return TRUE;
  zrpc_kill_in_progress = 1;
  /* kill BGP Daemon */
  zrpc_vpnservice_terminate_qzc(ctxt);
  zrpc_vpnservice_terminate_bgpvrf_cache(ctxt);
  zrpc_vpnservice_terminate_bgp_context(ctxt);
  /* creation of capnproto context */
  zrpc_vpnservice_setup_bgp_cache(ctxt);
  zrpc_vpnservice_setup_qzc(ctxt);
  if(IS_ZRPC_DEBUG)
    zrpc_info ("stopBgp(AS %u) OK", asNumber);
  zrpc_kill_in_progress = 0;
  return TRUE;
}

/*
 * Create a BGP neighbor for a given routerId, and asNumber
 * If Peer fails to be created, an error is returned.
 * If BGP Router is not started, BGP Peer creation fails,
 * and an error is returned.
 * VPNv4 address family is enabled by default with this neighbor.
 */
gboolean
instance_bgp_configurator_handler_create_peer(BgpConfiguratorIf *iface, gint32* _return,
                                              const gchar *routerId, const gint64 asNumber, GError **error)
{
  struct zrpc_vpnservice *ctxt = NULL;
  struct peer inst;
  struct capn_ptr bgppeer;
  struct capn rc;
  struct capn_segment *cs;
  struct zrpc_vpnservice_cache_peer *entry;
  uint64_t peer_nid;
  gboolean ret = FALSE;

  zrpc_vpnservice_get_context (&ctxt);
  if(!ctxt)
    {
      *_return = BGP_ERR_FAILED;
      return FALSE;
    }
  if(zrpc_vpnservice_get_bgp_context(ctxt) == NULL || zrpc_vpnservice_get_bgp_context(ctxt)->asNumber == 0)
    {
      *_return = BGP_ERR_FAILED;
      *error = ERROR_BGP_AS_NOT_STARTED;
      return FALSE;
    }
  if(asNumber < 0)
    {
      *_return = BGP_ERR_PARAM;
      return FALSE;
    }
  memset(&inst, 0, sizeof(struct peer));
  inst.host = ZRPC_STRDUP(routerId);
  inst.as = (uint32_t) asNumber;
  capn_init_malloc(&rc);
  cs = capn_root(&rc).seg;
  bgppeer = qcapn_new_BGPPeer(cs);
  qcapn_BGPPeer_write(&inst, bgppeer);

  peer_nid = qzcclient_createchild (ctxt->qzc_sock, &bgp_inst_nid, 2, \
                                  &bgppeer, &bgp_datatype_create_bgp_2);
  capn_free(&rc);
  ZRPC_FREE(inst.host);
  if (peer_nid == 0)
    {
      *_return = BGP_ERR_FAILED;
      ZRPC_FREE (inst.host);
      return FALSE;
    }
  if(IS_ZRPC_DEBUG)
    zrpc_info ("createPeer(%s,%u) OK", routerId, asNumber);
  /* add entry peer in cache */
  entry = zrpc_bgp_configurator_find_peer(ctxt, routerId, _return, 1);
  if(entry == NULL)
    {
      return FALSE;
    }
  entry->peer_nid = peer_nid;
  entry->asNumber = asNumber;
  if(IS_ZRPC_DEBUG_CACHE)
    zrpc_log ("CACHE_PEER : upgrade entry %llx", (long long unsigned int)peer_nid);  
  /* set aficfg */
   ret = zrpc_bgp_afi_config(ctxt, _return, routerId,                 \
                             AF_AFI_AFI_IP, AF_SAFI_SAFI_MPLS_VPN, TRUE, error);
   if(entry->enableAddressFamily[ADDRESS_FAMILY_L2VPN][SUBSEQUENT_ADDRESS_FAMILY_EVPN])
     {
       ret = zrpc_bgp_afi_config(ctxt, _return, routerId,             \
                                 AF_AFI_AFI_L2VPN, AF_SAFI_SAFI_EVPN, TRUE, error);
     }
   if(entry->enableAddressFamily[ADDRESS_FAMILY_IPV6][SUBSEQUENT_ADDRESS_FAMILY_MPLS_VPN])
     {
       ret = zrpc_bgp_afi_config(ctxt, _return, routerId,             \
                                 AF_AFI_AFI_IPV6, AF_SAFI_SAFI_MPLS_VPN, TRUE, error);
     }
   if(entry->enableAddressFamily[ADDRESS_FAMILY_IPV6][SUBSEQUENT_ADDRESS_FAMILY_LABELED_UNICAST])
     {
       ret = zrpc_bgp_afi_config(ctxt, _return, routerId,             \
                                 AF_AFI_AFI_IPV6, AF_SAFI_SAFI_IP_LABELED_UNICAST, TRUE, error);
     }
   if(entry->enableAddressFamily[ADDRESS_FAMILY_IP][SUBSEQUENT_ADDRESS_FAMILY_LABELED_UNICAST])
     {
       ret = zrpc_bgp_afi_config(ctxt, _return, routerId,             \
                                 AF_AFI_AFI_IP, AF_SAFI_SAFI_IP_LABELED_UNICAST, TRUE, error);
     }
   ret = zrpc_bgp_peer_af_flag_config(ctxt, _return, routerId,        \
                                      AF_AFI_AFI_IP, AF_SAFI_SAFI_MPLS_VPN,
                                      PEER_FLAG_NEXTHOP_UNCHANGED, TRUE,
                                      error);

   if(entry->enableAddressFamily[ADDRESS_FAMILY_L2VPN][SUBSEQUENT_ADDRESS_FAMILY_EVPN])
     {
       ret = zrpc_bgp_peer_af_flag_config(ctxt, _return, routerId,    \
                                          AF_AFI_AFI_L2VPN, AF_SAFI_SAFI_EVPN,
                                          PEER_FLAG_NEXTHOP_UNCHANGED, TRUE,
                                          error);
       ret = zrpc_bgp_peer_af_flag_config(ctxt, _return, routerId,    \
                                          AF_AFI_AFI_L2VPN, AF_SAFI_SAFI_EVPN,
                                          PEER_FLAG_SOFT_RECONFIG, TRUE,
                                          error);
     }

   if(entry->enableAddressFamily[ADDRESS_FAMILY_IPV6][AF_SAFI_SAFI_MPLS_VPN])
     {
       ret = zrpc_bgp_peer_af_flag_config(ctxt, _return, routerId,    \
                                          AF_AFI_AFI_IPV6, AF_SAFI_SAFI_MPLS_VPN,
                                          PEER_FLAG_NEXTHOP_UNCHANGED, TRUE,
                                          error);
     }
   if(entry->enableAddressFamily[ADDRESS_FAMILY_IPV6][SUBSEQUENT_ADDRESS_FAMILY_LABELED_UNICAST])
     {
       ret = zrpc_bgp_peer_af_flag_config(ctxt, _return, routerId,    \
                                          AF_AFI_AFI_IPV6, AF_SAFI_SAFI_IP_LABELED_UNICAST,
                                          PEER_FLAG_NEXTHOP_UNCHANGED, TRUE,
                                          error);
     }
   if(entry->enableAddressFamily[ADDRESS_FAMILY_IP][SUBSEQUENT_ADDRESS_FAMILY_LABELED_UNICAST])
     {
       ret = zrpc_bgp_peer_af_flag_config(ctxt, _return, routerId,    \
                                          AF_AFI_AFI_IP, AF_SAFI_SAFI_IP_LABELED_UNICAST,
                                          PEER_FLAG_NEXTHOP_UNCHANGED, TRUE,
                                          error);
     }
   return ret;
 }

 /*
  * Delete a BGP neighbor for a given IP
  * If BGP neighbor does not exist, an error is returned
  * It returns TRUE if operation succeeded.
  */
 gboolean
 instance_bgp_configurator_handler_delete_peer(BgpConfiguratorIf *iface, gint32* _return,
                                               const gchar * peerIp, GError **error)
 {
   struct zrpc_vpnservice *ctxt = NULL;
   uint64_t bgppeer_nid;
   struct zrpc_vpnservice_cache_peer *c_peer;

   zrpc_vpnservice_get_context (&ctxt);
   if(!ctxt)
     {
       *_return = BGP_ERR_FAILED;
       return FALSE;
     }
   if(zrpc_vpnservice_get_bgp_context(ctxt) == NULL || zrpc_vpnservice_get_bgp_context(ctxt)->asNumber == 0)
     {
       *_return = BGP_ERR_FAILED;
       *error = ERROR_BGP_AS_NOT_STARTED;
       return FALSE;
     }
   /* if vrf not found, return an error */
   c_peer = zrpc_bgp_configurator_find_peer(ctxt, peerIp, _return, 0);
   if(c_peer == NULL || c_peer->peer_nid == 0)
     {
       *_return = BGP_ERR_PARAM;
       *error = ERROR_BGP_PEER_NOTFOUND;
       return FALSE;
     }
   bgppeer_nid = c_peer->peer_nid;
   /* destroy node id */
   if( qzcclient_deletenode(ctxt->qzc_sock, &bgppeer_nid))
     {
       struct zrpc_vpnservice_cache_peer *entry_bgppeer, *entry_bgppeer_prev, *entry_bgppeer_next;      

       entry_bgppeer_prev = NULL;
       for (entry_bgppeer = ctxt->bgp_peer_list; entry_bgppeer; entry_bgppeer = entry_bgppeer_next)
         {
           entry_bgppeer_next = entry_bgppeer->next;
           if(0 == strcmp(entry_bgppeer->peerIp, peerIp))
             {
               if(IS_ZRPC_DEBUG_CACHE)
                 zrpc_log ("CACHE_PEER: del entry %llx", (long long unsigned int)entry_bgppeer->peer_nid);
               if (entry_bgppeer_prev)
                 entry_bgppeer_prev->next = entry_bgppeer_next;
               else
                 ctxt->bgp_peer_list = entry_bgppeer_next;
               ZRPC_FREE (entry_bgppeer->peerIp);
               entry_bgppeer->peerIp = NULL;
               ZRPC_FREE (entry_bgppeer);
               break;
             }
           else
             entry_bgppeer_prev = entry_bgppeer;
         }
       if(IS_ZRPC_DEBUG)
         zrpc_info ("deletePeer(%s) OK", peerIp);
       return TRUE;
     }
   return FALSE;
 }

 /*
  * Add a VRF entry for a given route distinguisher
  * Optionally, imported and exported route distinguisher are given.
  * An error is returned if VRF entry already exists.
  * VRF must be removed before being updated
  */
 gboolean
 instance_bgp_configurator_handler_add_vrf(BgpConfiguratorIf *iface, gint32* _return, const layer_type l_type, const gchar * rd, 
                                           const GPtrArray * irts, const GPtrArray * erts, GError **error)
 {
   struct zrpc_vpnservice *ctxt = NULL;
   struct bgp_vrf instvrf, *bgpvrf_ptr;
   int ret;
   unsigned int i;
   struct capn_ptr bgpvrf;
   struct capn rc;
   struct capn_segment *cs;
   uint64_t bgpvrf_nid;
   struct zrpc_vpnservice_cache_bgpvrf *entry;
   struct zrpc_rdrt *rdrt;

   /* setup context */
   *_return = 0;
   bgpvrf_ptr = &instvrf;
   zrpc_vpnservice_get_context (&ctxt);
   if(!ctxt)
     {
       *_return = BGP_ERR_FAILED;
       return FALSE;
     }
   if(zrpc_vpnservice_get_bgp_context(ctxt) == NULL || zrpc_vpnservice_get_bgp_context(ctxt)->asNumber == 0)
     {
       *_return = BGP_ERR_INACTIVE;
       *error = ERROR_BGP_AS_NOT_STARTED;
       return FALSE;
     }
   if(rd == NULL)
     {
       *error = ERROR_BGP_RD_NOTFOUND;
       *_return = BGP_ERR_PARAM;
       return FALSE;
     }
   memset(&instvrf, 0, sizeof(struct bgp_vrf));
   /* get route distinguisher internal representation */
   zrpc_util_str2rd_prefix((char *)rd, &instvrf.outbound_rd);
   instvrf.ltype = (l_type == LAYER_TYPE_LAYER_2) ? 
     ZRPC_BGP_LAYER_TYPE_2 : ZRPC_BGP_LAYER_TYPE_3;

   /* retrive bgpvrf context or create new bgpvrf context */
   bgpvrf_nid = zrpc_bgp_configurator_find_vrf(ctxt, &instvrf.outbound_rd, _return);
   if(bgpvrf_nid == 0)
     {
       /* allocate bgpvrf structure */
       capn_init_malloc(&rc);
       cs = capn_root(&rc).seg;
       bgpvrf = qcapn_new_BGPVRF(cs);
       qcapn_BGPVRF_write(&instvrf, bgpvrf);
       bgpvrf_nid = qzcclient_createchild (ctxt->qzc_sock, &bgp_inst_nid, 3, \
                                           &bgpvrf, &bgp_datatype_bgpvrf);
       capn_free(&rc);
       if (bgpvrf_nid == 0)
         {
           *_return = BGP_ERR_FAILED;
           return FALSE;
         }
       /* add vrf entry in zrpc list */
       entry = ZRPC_CALLOC (sizeof(struct zrpc_vpnservice_cache_bgpvrf));
       entry->outbound_rd = instvrf.outbound_rd;
       entry->ltype = instvrf.ltype;
       entry->bgpvrf_nid = bgpvrf_nid;
       if(IS_ZRPC_DEBUG_CACHE)
         zrpc_log ("CACHE_VRF: add entry %llx", (long long unsigned int)bgpvrf_nid);
       entry->next = ctxt->bgp_vrf_list;
       ctxt->bgp_vrf_list = entry;
       if(IS_ZRPC_DEBUG)
         zrpc_info ("addVrf(%s) OK", rd);
       /* max_mpath has been set in bgpd with a default value owned by bgpd itself
        * must get back this value before going further else max_mpath will be overwritten
        * by first bgpvrf read */
       {
         struct QZCGetRep *grep_vrf;

         grep_vrf = qzcclient_getelem (ctxt->qzc_sock, &bgpvrf_nid, 1, \
                                       NULL, NULL, NULL, NULL);
         if(grep_vrf == NULL)
           {
             *_return = BGP_ERR_FAILED;
             return FALSE;
           }
         memset(&instvrf, 0, sizeof(struct bgp_vrf));
         qcapn_BGPVRF_read(&instvrf, grep_vrf->data);
         if (instvrf.rt_import)
           zrpc_util_rdrt_free (instvrf.rt_import);
         if (instvrf.rt_export)
           zrpc_util_rdrt_free (instvrf.rt_export);
         /* reset qzc reply and rc context */
         qzcclient_qzcgetrep_free( grep_vrf);
       }
     }
   /* configuring bgp vrf with import and export communities */
   /* irts and erts have to be translated into u_char[8] entities, then put in a list */
   rdrt = ZRPC_CALLOC (sizeof(struct zrpc_rdrt));
   for(i = 0; i < irts->len; i++)
     {
       u_char tmp[8];
       int ret;
       ret = zrpc_util_str2rdrt ((char *)g_ptr_array_index(irts, i), tmp, ZRPC_UTIL_RDRT_TYPE_ROUTE_TARGET);
       if (ret)
         rdrt = zrpc_util_append_rdrt_to_list (tmp, rdrt);
     }
   if(irts->len)
     instvrf.rt_import = rdrt;
   else
     zrpc_util_rdrt_free (rdrt);

   i = 0;
   rdrt = ZRPC_CALLOC (sizeof(struct zrpc_rdrt));
   for (i = 0; i < erts->len; i++)
     {
       u_char tmp[8];
       int ret;
       ret = zrpc_util_str2rdrt ((char *)g_ptr_array_index(erts, i), tmp, ZRPC_UTIL_RDRT_TYPE_ROUTE_TARGET);
       if (ret)
         rdrt = zrpc_util_append_rdrt_to_list (tmp, rdrt);
     }
   if(erts->len)
     instvrf.rt_export = rdrt;
   else  
     zrpc_util_rdrt_free (rdrt);

   /* allocate bgpvrf structure for set */
   capn_init_malloc(&rc);
   cs = capn_root(&rc).seg;
   bgpvrf = qcapn_new_BGPVRF(cs);
   qcapn_BGPVRF_write(&instvrf, bgpvrf);
   ret = qzcclient_setelem (ctxt->qzc_sock, &bgpvrf_nid, 1, \
                            &bgpvrf, &bgp_datatype_bgpvrf,\
                            NULL, NULL);
   if(ret == 0)
       *_return = BGP_ERR_FAILED;
   if (bgpvrf_ptr->rt_import)
     zrpc_util_rdrt_free (bgpvrf_ptr->rt_import);
   if (bgpvrf_ptr->rt_export)
     zrpc_util_rdrt_free (bgpvrf_ptr->rt_export);
   capn_free(&rc);
   return ret;
 }

 /*
  * Delete a VRF entry for a given route distinguisher
  * An error is returned if VRF entry does not exist
  */
 gboolean instance_bgp_configurator_handler_del_vrf(BgpConfiguratorIf *iface, gint32* _return,
                                                    const gchar * rd, GError **error)
 {
   struct zrpc_vpnservice *ctxt = NULL;
   uint64_t bgpvrf_nid;
   struct zrpc_rd_prefix rd_inst;

   zrpc_vpnservice_get_context (&ctxt);
   if(!ctxt)
     {
       *_return = BGP_ERR_FAILED;
       return FALSE;
     }
   if(zrpc_vpnservice_get_bgp_context(ctxt) == NULL || zrpc_vpnservice_get_bgp_context(ctxt)->asNumber == 0)
     {
       *_return = BGP_ERR_FAILED;
       *error = ERROR_BGP_AS_NOT_STARTED;
       return FALSE;
     }
   /* get route distinguisher internal representation */
   memset(&rd_inst, 0, sizeof(struct zrpc_rd_prefix));
   zrpc_util_str2rd_prefix((char *)rd, &rd_inst);
   /* if vrf not found, return an error */
   bgpvrf_nid = zrpc_bgp_configurator_find_vrf(ctxt, &rd_inst, _return);
   if(bgpvrf_nid == 0)
     {
       *error = ERROR_BGP_RD_NOTFOUND;
       *_return = BGP_ERR_PARAM;
       return FALSE;
     }
   if( qzcclient_deletenode(ctxt->qzc_sock, &bgpvrf_nid))
     {
       struct zrpc_vpnservice_cache_bgpvrf *entry_bgpvrf, *entry_bgpvrf_prev, *entry_bgpvrf_next;      

       entry_bgpvrf_prev = NULL;
       for (entry_bgpvrf = ctxt->bgp_vrf_list; entry_bgpvrf; entry_bgpvrf = entry_bgpvrf_next)
         {
           entry_bgpvrf_next = entry_bgpvrf->next;
           if(0 == zrpc_util_rd_prefix_cmp(&entry_bgpvrf->outbound_rd, &rd_inst))
             {
               if(IS_ZRPC_DEBUG_CACHE)
                 zrpc_log ("CACHE_VRF: del entry %llx", (long long unsigned int)entry_bgpvrf->bgpvrf_nid);
               if (entry_bgpvrf_prev)
                 entry_bgpvrf_prev->next = entry_bgpvrf_next;
               else
                 ctxt->bgp_vrf_list = entry_bgpvrf_next;
               ZRPC_FREE (entry_bgpvrf);
               if(IS_ZRPC_DEBUG)
                 {
                   zrpc_info ("delVrf(%s) OK", rd);
                 }
               return TRUE;
             }
           entry_bgpvrf_prev = entry_bgpvrf;
         }
     }
   return FALSE;
 }

 /*
  * Force Source Address of BGP Speaker
  * An error is returned if neighbor is not configured
  * if srcIp is not set, then the command will unset
  * BGP Speaker Source address
  */
 gboolean
 instance_bgp_configurator_handler_set_update_source (BgpConfiguratorIf *iface, gint32* _return, const gchar * peerIp,
                                                      const gchar * srcIp, GError **error)
 {
   struct zrpc_vpnservice *ctxt = NULL;
   uint64_t peer_nid;
   capn_ptr peer_ctxt;
   struct QZCGetRep *grep_peer;
   struct peer peer;
   struct capn rc;
   struct capn_segment *cs;
   struct zrpc_vpnservice_cache_peer *c_peer;

   zrpc_vpnservice_get_context (&ctxt);
   if(!ctxt)
     {
       *error = g_error_new(0, 0, "BGP AS not started");
       *_return = BGP_ERR_FAILED;
       return FALSE;
     }
   if(zrpc_vpnservice_get_bgp_context(ctxt) == NULL || zrpc_vpnservice_get_bgp_context(ctxt)->asNumber == 0)
     {
       *_return = BGP_ERR_FAILED;
       *error = ERROR_BGP_AS_NOT_STARTED;
       return FALSE;
     }
   if(peerIp == NULL)
     {
       *_return = BGP_ERR_PARAM;
       return FALSE;
     }
   /* if peer not found, return an error */
   c_peer  = zrpc_bgp_configurator_find_peer(ctxt, peerIp, _return, 0);
   if(c_peer == NULL || c_peer->peer_nid == 0)
     {
       *_return = BGP_ERR_PARAM;
       *error = ERROR_BGP_PEER_NOTFOUND;
       return FALSE;
     }
   peer_nid = c_peer->peer_nid;
   /* retrieve peer context */
   grep_peer = qzcclient_getelem (ctxt->qzc_sock, &peer_nid, 2, \
                                  NULL, NULL, NULL, NULL);
   if(grep_peer == NULL)
     {
       *_return = BGP_ERR_FAILED;
       return FALSE;
     }
   memset(&peer, 0, sizeof(struct peer));
   qcapn_BGPPeer_read(&peer, grep_peer->data);
   /* change updateSource */
   if(srcIp)
     {
       peer.update_source = (char *)srcIp;
     }
   qzcclient_qzcgetrep_free( grep_peer);
   /* prepare QZCSetRequest context */
   capn_init_malloc(&rc);
   cs = capn_root(&rc).seg;
   peer_ctxt = qcapn_new_BGPPeer(cs);
   qcapn_BGPPeer_write(&peer, peer_ctxt);
   if(qzcclient_setelem (ctxt->qzc_sock, &peer_nid, 2, \
                         &peer_ctxt, &bgp_datatype_create_bgp_2, \
                         NULL, NULL))
     {
       if(IS_ZRPC_DEBUG)
         {
           if(srcIp == 0)
             zrpc_info ("unsetUpdateSource(%s) OK", peerIp);
           else
             zrpc_info ("setUpdateSource(%s, %s) OK", peerIp, srcIp);
         }
     }
   if (peer.host)
     ZRPC_FREE (peer.host);
   if (peer.desc)
     ZRPC_FREE (peer.desc);
   capn_free(&rc);
   return TRUE;
 }

 /*
  * Unset Source Address of BGP Speaker
  * An error is returned if neighbor is not configured
  */
 gboolean
 instance_bgp_configurator_handler_unset_update_source (BgpConfiguratorIf *iface, gint32* _return,
                                                        const gchar * peerIp, GError **error)
 {
   return instance_bgp_configurator_handler_set_update_source( iface, _return, peerIp, NULL, error);
 }

 /*
  * enable MP-BGP routing information exchange with a given neighbor
  * for a given address family identifier and subsequent address family identifier.
  */
 gboolean instance_bgp_configurator_handler_enable_address_family(BgpConfiguratorIf *iface, gint32* _return,
                                                                  const gchar * peerIp, const af_afi afi,
                                                                  const af_safi safi, GError **error)
 {
   struct zrpc_vpnservice *ctxt = NULL;
   gboolean ret;

   zrpc_vpnservice_get_context (&ctxt);
   if(!ctxt)
     {
       *_return = BGP_ERR_FAILED;
       return FALSE;
     }
   ret = zrpc_bgp_afi_config(ctxt, _return, peerIp, afi, safi, TRUE, error);
   if(ret == TRUE && 
      ((afi == AF_AFI_AFI_L2VPN && safi == AF_SAFI_SAFI_EVPN) ||
       (afi == AF_AFI_AFI_IPV6 && safi == AF_SAFI_SAFI_MPLS_VPN) ||
       (afi == AF_AFI_AFI_IPV6 && safi == AF_SAFI_SAFI_IP_LABELED_UNICAST) ||
       (afi == AF_AFI_AFI_IP && safi == AF_SAFI_SAFI_IP_LABELED_UNICAST)))
     {
       zrpc_bgp_peer_af_flag_config(ctxt, _return, peerIp,
                                    afi, safi,
                                    PEER_FLAG_NEXTHOP_UNCHANGED, TRUE,
                                    error);
     }
   if (ret == TRUE && 
       ((afi == AF_AFI_AFI_L2VPN && safi == AF_SAFI_SAFI_EVPN)))
     {
       zrpc_bgp_peer_af_flag_config(ctxt, _return, peerIp,
                                    afi, safi,
                                    PEER_FLAG_SOFT_RECONFIG, TRUE,
                                    error);
     }
  return ret;
}

/*
 * disable MP-BGP routing information exchange with a given neighbor
 * for a given address family identifier and subsequent address family identifier.
 */
gboolean
instance_bgp_configurator_handler_disable_address_family(BgpConfiguratorIf *iface, gint32* _return,
                                                         const gchar * peerIp, const af_afi afi,
                                                         const af_safi safi, GError **error)
{
  struct zrpc_vpnservice *ctxt = NULL;

  zrpc_vpnservice_get_context (&ctxt);
  if(!ctxt)
    {
      *_return = BGP_ERR_FAILED;
      return FALSE;
    }
  return zrpc_bgp_afi_config(ctxt, _return, peerIp, afi, safi, FALSE, error);
}

gboolean
instance_bgp_configurator_handler_set_log_config (BgpConfiguratorIf *iface, gint32* _return, const gchar * logFileName,
                                                  const gchar * logLevel, GError **error)
{
  struct zrpc_vpnservice *ctxt = NULL;

  zrpc_vpnservice_get_context (&ctxt);
  if(!ctxt)
    {
      *_return = BGP_ERR_FAILED;
      return FALSE;
    }
  if(zrpc_vpnservice_get_bgp_context(ctxt) == NULL)
    {
      zrpc_vpnservice_setup_bgp_context(ctxt);
    }
  if (zrpc_vpnservice_get_bgp_context(ctxt)->logFile)
    {
      free (zrpc_vpnservice_get_bgp_context(ctxt)->logFile);
      zrpc_vpnservice_get_bgp_context(ctxt)->logFile = NULL;
    }
  if (zrpc_vpnservice_get_bgp_context(ctxt)->logLevel)
    {
      free (zrpc_vpnservice_get_bgp_context(ctxt)->logLevel);
      zrpc_vpnservice_get_bgp_context(ctxt)->logLevel = NULL;
    }
  if (logFileName)
    {
      zrpc_vpnservice_get_bgp_context(ctxt)->logFile = strdup ( logFileName);
    }
  else
    {
      zrpc_vpnservice_get_bgp_context(ctxt)->logFile = strdup ( ZRPC_DEFAULT_LOG_FILE);
    }
  if (logLevel)
    {
      zrpc_vpnservice_get_bgp_context(ctxt)->logLevel = strdup ( logLevel);
    }
  else
    {
      zrpc_vpnservice_get_bgp_context(ctxt)->logLevel = strdup ( ZRPC_DEFAULT_LOG_LEVEL);
    }
  zrpc_debug_set_log_file_with_level (zrpc_vpnservice_get_bgp_context(ctxt)->logFile,
                                      zrpc_vpnservice_get_bgp_context(ctxt)->logLevel);
  /* config stored, but not sent to BGP. silently return */
  if (zrpc_vpnservice_get_bgp_context(ctxt)->asNumber == 0)
    {
      /* configure log settings to qthrift daemon too */
      zrpc_debug_set_log_file_with_level ((char *)logFileName, (char *)logLevel);
      return TRUE;
    }
  return zrpc_bgp_set_log_config (ctxt, zrpc_vpnservice_get_bgp_context(ctxt), _return, error);
}

/*
 * enable Graceful Restart for BGP Router, as well as stale path timer.
 * if the stalepathTime is set to 0, then the graceful restart feature will be disabled
 */
gboolean
instance_bgp_configurator_handler_enable_graceful_restart (BgpConfiguratorIf *iface, gint32* _return,
                                                           const gint32 stalepathTime, GError **error)
{
  struct zrpc_vpnservice *ctxt = NULL;
  struct capn_ptr bgp;
  struct capn rc;
  struct capn_segment *cs;
  struct bgp inst;
  struct QZCGetRep *grep;

  zrpc_vpnservice_get_context (&ctxt);
  if(!ctxt)
    {
      *_return = BGP_ERR_FAILED;
      return FALSE;
    }
  if(zrpc_vpnservice_get_bgp_context(ctxt) == NULL || zrpc_vpnservice_get_bgp_context(ctxt)->asNumber == 0)
    {
      *_return = BGP_ERR_FAILED;
      *error = ERROR_BGP_AS_NOT_STARTED;
      return FALSE;
    }
  /* get bgp_master configuration */
  grep = qzcclient_getelem (ctxt->qzc_sock, &bgp_inst_nid, 1, NULL, NULL, NULL, NULL);
  if(grep == NULL)
    {
      *_return = BGP_ERR_FAILED;
      return FALSE;
    }
  memset(&inst, 0, sizeof(struct bgp));
  qcapn_BGP_read(&inst, grep->data);
  qzcclient_qzcgetrep_free( grep);
  /* update bgp configuration with graceful status */
  capn_init_malloc(&rc);
  cs = capn_root(&rc).seg;
  bgp = qcapn_new_BGP(cs);
  /* set default stalepath time */
  inst.flags |= BGP_FLAG_GRACEFUL_RESTART;
  if(stalepathTime == 0)
    inst.stalepath_time = BGP_DEFAULT_STALEPATH_TIME;
  else if (stalepathTime == -1)
    inst.flags &= ~BGP_FLAG_GRACEFUL_RESTART;
  qcapn_BGP_write(&inst, bgp);
  qzcclient_setelem (ctxt->qzc_sock, &bgp_inst_nid, 1, \
                     &bgp, &bgp_datatype_bgp, NULL, NULL);
  capn_free(&rc);
  if (inst.name)
    ZRPC_FREE (inst.name);
  if (inst.notify_zmq_url)
    ZRPC_FREE (inst.notify_zmq_url);
  if (inst.logFile)
    ZRPC_FREE (inst.logFile);
  if (inst.logLevel)
    ZRPC_FREE (inst.logLevel);
  return TRUE;
}

/* fill in upd structure, from inst_route */
static void get_update_entry_from_context( struct bgp_api_route *inst_route,
                                    struct bgp_api_route *inst_multipath,
                                    Update *upd)
{
  char rdstr[ZRPC_UTIL_RDRT_LEN];

  upd->type = BGP_RT_ADD;
  upd->macaddress = NULL;
  if (inst_route->prefix.family == AF_INET)
    {
      upd->prefix = g_strdup(inet_ntop(AF_INET, &inst_route->prefix.u.prefix4, rdstr, ZRPC_UTIL_RDRT_LEN));
      upd->prefixlen = inst_route->prefix.prefixlen;
    }
  else if (inst_route->prefix.family == AF_INET6)
    {
      upd->prefix = g_strdup(inet_ntop(AF_INET6, &inst_route->prefix.u.prefix6, rdstr, ZRPC_UTIL_RDRT_LEN));
      upd->prefixlen = inst_route->prefix.prefixlen;
    }
  else if (inst_route->prefix.family == AF_L2VPN)
    {
      if (ZRPC_L2VPN_PREFIX_HAS_IPV4(&(inst_route->prefix)))
        {
          upd->prefix = g_strdup(inet_ntop (AF_INET, &(inst_route->prefix.u.prefix_macip.ip.in4), rdstr, ZRPC_UTIL_RDRT_LEN));
          upd->prefixlen = ZRPC_UTIL_IPV4_PREFIX_LEN_MAX;
        }
      else if (ZRPC_L2VPN_PREFIX_HAS_IPV6(&(inst_route->prefix)))
        {
          upd->prefix = g_strdup(inet_ntop (AF_INET6, &(inst_route->prefix.u.prefix_macip.ip.in6), rdstr, ZRPC_UTIL_RDRT_LEN));
          upd->prefixlen = ZRPC_UTIL_IPV6_PREFIX_LEN_MAX;
        }
      else
        {
          upd->prefix = NULL;
          upd->prefixlen = 0;
        }
      upd->macaddress = g_strdup(zrpc_util_mac2str((char*) &inst_route->prefix.u.prefix_macip.mac));
    }
  if(inst_multipath)
    {
      char nh_str[ZRPC_UTIL_IPV6_LEN_MAX];
      zrpc_util_prefix_2str (&(inst_multipath->nexthop), nh_str, ZRPC_UTIL_IPV6_LEN_MAX);
      upd->nexthop = g_strdup(nh_str);
      upd->l3label = inst_multipath->label;
      upd->l2label = inst_multipath->l2label;
      upd->ethtag = inst_multipath->ethtag;
      if (inst_multipath->gatewayIp.s_addr)
        upd->gatewayip = g_strdup (inet_ntop(AF_INET, &(inst_multipath->gatewayIp), rdstr, ZRPC_UTIL_RDRT_LEN));
      else
        upd->gatewayip = NULL;
      if(inst_multipath->esi)
        upd->esi = g_strdup(inst_multipath->esi);
      if(inst_multipath->mac_router)
        upd->routermac = g_strdup(inst_multipath->mac_router);
    }
  else
    {
      char nh_str[ZRPC_UTIL_IPV6_LEN_MAX];
      zrpc_util_prefix_2str (&(inst_route->nexthop), nh_str, ZRPC_UTIL_IPV6_LEN_MAX);
      upd->nexthop = g_strdup(nh_str);
      upd->l3label = inst_route->label;
      upd->l2label = inst_route->l2label;
      upd->ethtag = inst_route->ethtag;
      if (inst_route->gatewayIp.s_addr)
        upd->gatewayip = g_strdup (inet_ntop(AF_INET, &(inst_route->gatewayIp), rdstr, ZRPC_UTIL_RDRT_LEN));
      else
        upd->gatewayip = NULL;
      if(inst_route->esi)
        upd->esi = g_strdup(inst_route->esi);
      if(inst_route->mac_router)
        upd->routermac = g_strdup(inst_route->mac_router);

    }
  return;
}

/* disable Graceful Restart for BGP Router */
gboolean
instance_bgp_configurator_handler_disable_graceful_restart (BgpConfiguratorIf *iface, gint32* _return, GError **error)
{
  return instance_bgp_configurator_handler_enable_graceful_restart(iface, _return, -1, error);
}

struct zrpc_prefix *prev_iter_table_ptr = NULL;
struct zrpc_prefix prev_iter_table_entry;
gboolean
instance_bgp_configurator_handler_get_routes (BgpConfiguratorIf *iface, Routes ** _return, const protocol_type p_type, 
                                              const gint32 optype, const gint32 winSize, 
                                              const af_afi afi, GError **error)
{
  struct capn_ptr afikey, iter_table, *iter_table_ptr = NULL;
  struct capn rc;
  struct capn_segment *cs;
  address_family_t afi_int = ADDRESS_FAMILY_IP;
  struct zrpc_vpnservice *ctxt = NULL;
  uint64_t bgpvrf_nid = 0;
  struct QZCGetRep *grep_route = NULL;
  struct bgp_api_route inst_route;
  struct zrpc_vpnservice_cache_bgpvrf *entry, *entry_next, *entry2;
  char rdstr[ZRPC_UTIL_RDRT_LEN];
  int route_updates_max, route_updates;
  Update *upd;
  int do_not_parse_vrf = 0;

  if (afi == AF_AFI_AFI_IPV6)
    afi_int = ADDRESS_FAMILY_IPV6;
  if (p_type == PROTOCOL_TYPE_PROTOCOL_LU)
    {
      do_not_parse_vrf = 1;
    }
  zrpc_vpnservice_get_context (&ctxt);
  if(!ctxt)
    {
      (*_return)->errcode = BGP_ERR_FAILED;
      (*_return)->__isset_errcode = TRUE;
      return FALSE;
    }
  /* for first getRoutes, setup the list of bgpvrfs entries */
  if(optype == GET_RTS_INIT)
    {
      if (!do_not_parse_vrf)
        {
          for (entry = ctxt->bgp_get_routes_list; entry; entry = entry_next)
            {
              entry_next = entry->next;
              ZRPC_FREE (entry);
            }
          ctxt->bgp_get_routes_list = NULL;
          for (entry = ctxt->bgp_vrf_list; entry; entry = entry_next)
            {
              entry_next = entry->next;
              entry2 = ZRPC_CALLOC (sizeof(struct zrpc_vpnservice_cache_bgpvrf));
              entry2->outbound_rd = entry->outbound_rd;
              entry2->bgpvrf_nid = entry->bgpvrf_nid;
              entry2->next = ctxt->bgp_get_routes_list;
              ctxt->bgp_get_routes_list = entry2;
            }
        }
      prev_iter_table_ptr = NULL;
      memset(&prev_iter_table_entry, 0, sizeof(struct zrpc_prefix));
    }
  /* initialise context */
  route_updates_max = MAX(winSize/96, 1);
  route_updates = 0;
  (*_return)->more = 1;
  (*_return)->__isset_more = TRUE;
  (*_return)->errcode = 0;
  (*_return)->__isset_updates = TRUE;
  entry2 = NULL;

  /* parse current vrfs and vrfs not already parsed and global RIB */
  do
    {
      unsigned long mpath_iter_ptr = 0;
      if (do_not_parse_vrf == 0)
        {
          entry = ctxt->bgp_get_routes_list;
          entry_next = entry->next;
        }
      else
        {
          struct QZCGetRep *grep;

          entry = entry_next = NULL;
          /* get bgp_master configuration */
          grep = qzcclient_getelem (ctxt->qzc_sock, &bgp_inst_nid, 1, NULL, NULL, NULL, NULL);
          if(grep == NULL)
            {
              (*_return)->errcode = BGP_ERR_FAILED;
              (*_return)->__isset_errcode = TRUE;
              return FALSE;
            }
          qzcclient_qzcgetrep_free( grep);
        }
      /* remove current bgpvrf entry, all routes have been parsed */
      if(entry2 && (do_not_parse_vrf == 0))
        {
          struct zrpc_vpnservice_cache_bgpvrf *entry_curr, *entry_next, *entry_prev;
          entry_prev = NULL;
          for (entry_curr = ctxt->bgp_get_routes_list; entry_curr; 
               entry_curr = entry_next)
            {
              entry_next = entry_curr->next;
              if (entry_curr == entry2)
                {
                  if (entry_prev)
                    entry_prev->next = entry_next;
                  else
                    ctxt->bgp_get_routes_list = entry_next;
                  ZRPC_FREE (entry2);
                  entry2 = NULL;
                  break;
                }
            }
        }
      if (do_not_parse_vrf == 0)
        {
          if (entry == NULL)
            break;
          if(IS_ZRPC_DEBUG_CACHE)
            zrpc_log ("RTS: parsing vrf nid %llx", (long long unsigned int)entry->bgpvrf_nid);
          bgpvrf_nid = entry->bgpvrf_nid;
        }
      do
        {
          int prefix_addr_is_zero = 0;
           /* prepare afi context */
          capn_init_malloc(&rc);
          cs = capn_root(&rc).seg;
          if (!do_not_parse_vrf)
            {
              afikey = qcapn_new_AfiKey(cs);
              capn_resolve(&afikey);
              capn_write8(afikey, 0, afi_int);
            }
          else
            {
              afikey = qcapn_new_AfiSafiKey (cs);
              capn_resolve(&afikey);
              capn_write8(afikey, 0, afi_int);
              capn_write8(afikey, 1, SUBSEQUENT_ADDRESS_FAMILY_LABELED_UNICAST);
            }
	  if(prev_iter_table_ptr)
	  {
                 iter_table = qcapn_new_VRFTableIter(cs);
                 qcapn_VRFTableIter_write(&prev_iter_table_entry, iter_table);
                 iter_table_ptr = &iter_table;
	  }
	  else
	  {
                 iter_table_ptr = NULL;
	  }
          /* get route entry from the vrf rib table */
          /* currently entries from the vrf route table XXX */
          if (do_not_parse_vrf == 0)
            {
              grep_route = qzcclient_getelem (ctxt->qzc_sock, &bgpvrf_nid, 2, \
                                              &afikey, &bgp_ctxtype_bgpvrfroute, \
                                              iter_table_ptr, &bgp_itertype_bgpvrfroute);
            }
          else
            {
              grep_route = qzcclient_getelem (ctxt->qzc_sock, &bgp_inst_nid, 4,
                                              &afikey, &bgp_ctxtype_bgpvrfroute,
                                              iter_table_ptr, &bgp_itertype_bgpvrfroute);
            }
          if(grep_route == NULL || grep_route->datatype == 0)
            {
              /* goto next vrf */
              prev_iter_table_ptr = NULL;
              qzcclient_qzcgetrep_free(grep_route);
              capn_free(&rc);
              break;
            }
          memset(&inst_route, 0, sizeof(struct bgp_api_route));
          qcapn_BGPVRFRoute_read(&inst_route, grep_route->data);
          if(grep_route->datatype != 0)
            {
              /* this is possibly a multipath route, get additionnal data in the
               same grep_route->data exchange channel to get a pointer to the
               next bgp_info struct linked to that route.
               The offset of CAPN_BGPVRF_ROUTE_DEF_SIZE is because such data has a
               8 bytes offset with usual VRFRoute exchanged via capn'proto */
              qcapn_BGPVRFInfoIter_read(&mpath_iter_ptr, grep_route->data, CAPN_BGPVRF_ROUTE_DEF_SIZE);
            }

          if(grep_route->itertype != 0)
            {
              memset(&prev_iter_table_entry, 0, sizeof(prev_iter_table_entry));
              qcapn_VRFTableIter_read(&prev_iter_table_entry, grep_route->nextiter);
              prev_iter_table_ptr = &prev_iter_table_entry;
            }
          else
            {
              prev_iter_table_ptr = NULL;
            }
          qzcclient_qzcgetrep_free(grep_route);
          capn_free(&rc);
          switch(inst_route.prefix.family)
          {
            case AF_INET:
              prefix_addr_is_zero =  (inst_route.prefix.u.prefix4.s_addr == 0);
              break;
            case AF_INET6:
              prefix_addr_is_zero =  (inst_route.prefix.u.prefix6.s6_addr == 0);
              break;
            case AF_L2VPN:
              prefix_addr_is_zero =  (inst_route.prefix.u.prefix_macip.ip.in4.s_addr == 0);
              break;
            default:
              /* bypass route entries with family not taken into account */
              continue;
              break;
          }
          /* bypass route entries with zeroes */
          if ( (inst_route.nexthop.prefixlen == 0) &&
               (inst_route.prefix.prefixlen == 0) &&
               (prefix_addr_is_zero) &&
               (inst_route.label == 0) &&
               (inst_route.ethtag == 0) &&
               (inst_route.esi == NULL) &&
               (inst_route.mac_router == NULL))
            {
              if(prev_iter_table_ptr != NULL)
                {
                  continue;
                }
              else
                {
                  /* goto next vrf */
                  break;
                }
            }
          /* add entry in update */
          upd = g_object_new (TYPE_UPDATE, NULL);
          get_update_entry_from_context(&inst_route, NULL, upd);
          if (!do_not_parse_vrf)
            upd->rd = g_strdup(zrpc_util_rd_prefix2str(&(entry->outbound_rd), rdstr, ZRPC_UTIL_RDRT_LEN));
          else
            upd->rd = NULL;
          g_ptr_array_add((*_return)->updates, upd);
          route_updates++;
          if(inst_route.mac_router)
            free(inst_route.mac_router);
          inst_route.mac_router = NULL;
          if(inst_route.esi)
            free(inst_route.esi);
          inst_route.esi = NULL;

          /* multipath specific loop */
          while (mpath_iter_ptr)
            {
              struct QZCGetRep *grep_multipath_route = NULL;
              struct capn_ptr iter_table_bim;
              struct capn_segment *csi;
              struct bgp_api_route inst_multipath_route;

               /* prepare context, it will be dedicated to loop on multipath routes attached to a vpnv4 route */
              capn_init_malloc(&rc);
              csi = capn_root(&rc).seg;
              iter_table_bim = qcapn_new_BGPVRFInfoIter(csi);
              /* provide internal pointer value to the next struct bgp_info of a route is has one */
              qcapn_BGPVRFInfoIter_write(mpath_iter_ptr, iter_table_bim, 0);

              /* get route entry from the vrf rib table */
              if (do_not_parse_vrf == 0)
                {
                  grep_multipath_route = qzcclient_getelem (ctxt->qzc_sock, &bgpvrf_nid, 4, \
                                                            NULL, NULL, \
                                                            &iter_table_bim, &bgp_itertype_bgpvrfroute);
                }
              else
                {
                  grep_multipath_route = qzcclient_getelem (ctxt->qzc_sock, &bgp_inst_nid, 5,
                                                            NULL, NULL,
                                                            &iter_table_bim, &bgp_itertype_bgpvrfroute);
                }
              if(grep_multipath_route == NULL || grep_multipath_route->datatype == 0)
                {
                  /* goto next prefix */
                  qzcclient_qzcgetrep_free(grep_multipath_route);
                  capn_free(&rc);
                  break;
                }
              memset(&inst_multipath_route, 0, sizeof(struct bgp_api_route));
              qcapn_BGPVRFRoute_read(&inst_multipath_route, grep_multipath_route->data);
              mpath_iter_ptr = 0;
              /* look for another multipath entry with that check */
              if(grep_multipath_route->itertype != 0)
                {
                  /* there is another multipath entry after this one, store it into mpath_iter_ptr */
                  qcapn_BGPVRFInfoIter_read(&mpath_iter_ptr, grep_multipath_route->nextiter, 0);
                }
              qzcclient_qzcgetrep_free(grep_multipath_route);
              capn_free(&rc);

              switch(inst_route.prefix.family)
              {
                case AF_INET:
                  prefix_addr_is_zero =  (inst_multipath_route.prefix.u.prefix4.s_addr == 0);
                  break;
                case AF_INET6:
                  prefix_addr_is_zero =  (inst_multipath_route.prefix.u.prefix6.s6_addr == 0);
                  break;
                case AF_L2VPN:
                  prefix_addr_is_zero =  (inst_multipath_route.prefix.u.prefix_macip.ip.in4.s_addr == 0);
                  break;
                default:
                  continue;
                  break;
              }
              /* bypass route entries with zeroes */
              if ( (inst_multipath_route.nexthop.prefixlen == 0) &&
                   (inst_multipath_route.prefix.prefixlen == 0) &&
                   (prefix_addr_is_zero) &&
                   (inst_multipath_route.label == 0) &&
                   (inst_multipath_route.ethtag == 0) &&
                   (inst_multipath_route.esi == NULL) &&
                   (inst_multipath_route.mac_router == NULL))
                {
                  break;
                }
              /* add entry in update */
              upd = g_object_new (TYPE_UPDATE, NULL);
              get_update_entry_from_context(&inst_route, &inst_multipath_route, upd);
              if (!do_not_parse_vrf)
                upd->rd = g_strdup(zrpc_util_rd_prefix2str(&(entry->outbound_rd), rdstr, ZRPC_UTIL_RDRT_LEN));
              else
                upd->rd = NULL;
              g_ptr_array_add((*_return)->updates, upd);
              route_updates++;
              free(inst_multipath_route.mac_router);
              inst_multipath_route.mac_router = NULL;
              free(inst_multipath_route.esi);
              inst_multipath_route.esi = NULL;

              if (!mpath_iter_ptr)
                break; /* no more nexthop with MULTIPATH flag, go to next prefix */
            }

          /* prepare next extraction */
          if(prev_iter_table_ptr == NULL)
            {
              /* goto next vrf */
              break;
            }
          if(route_updates >= route_updates_max)
            {
              /* save last iteration table */
              return TRUE;
            }
        } while(1);
      entry2 = entry;
      entry = entry_next;
    }
  while ( entry && (do_not_parse_vrf == 0));

  if(route_updates == 0)
    {
      (*_return)->errcode = BGP_ERR_NOT_ITER;
      (*_return)->__isset_errcode = TRUE;
    }
  (*_return)->more = 0;
  (*_return)->__isset_more = TRUE;
  return TRUE;
}

/*
 * Enable/disable multipath feature for VPNv4 address family
 */
static gboolean
zrpc_bgp_set_multipath(struct zrpc_vpnservice *ctxt,  gint32* _return, const af_afi afi,
                          const af_safi safi, const gint32 enable, GError **error)
{
  struct capn rc;
  struct capn_segment *cs;
  struct bgp inst;
  struct QZCGetRep *grep;
  int af, saf;
  capn_ptr afisafi_ctxt, nctxt;

  if(zrpc_vpnservice_get_bgp_context(ctxt) == NULL || zrpc_vpnservice_get_bgp_context(ctxt)->asNumber == 0)
    {
      *_return = BGP_ERR_FAILED;
      *error = ERROR_BGP_AS_NOT_STARTED;
      return FALSE;
    }
  if (afi == AF_AFI_AFI_IP)
    af = ADDRESS_FAMILY_IP;
  else if (afi == AF_AFI_AFI_IPV6)
    af = ADDRESS_FAMILY_IPV6;
  else if (afi == AF_AFI_AFI_L2VPN)
    af = ADDRESS_FAMILY_L2VPN;
  else
    {
      *error = ERROR_BGP_AFISAFI_NOTSUPPORTED;
      *_return = BGP_ERR_PARAM;
      return FALSE;
    }
  if (safi == AF_SAFI_SAFI_MPLS_VPN)
    saf = SUBSEQUENT_ADDRESS_FAMILY_MPLS_VPN;
  else if (safi == AF_SAFI_SAFI_EVPN)
    saf = SUBSEQUENT_ADDRESS_FAMILY_EVPN;
  else if (safi == AF_SAFI_SAFI_IP_LABELED_UNICAST)
    saf = SUBSEQUENT_ADDRESS_FAMILY_LABELED_UNICAST;
  else
    {
      *error = ERROR_BGP_AFISAFI_NOTSUPPORTED;
      *_return = BGP_ERR_PARAM;
      return FALSE;
    }
  /* prepare afisafi context */
  capn_init_malloc(&rc);
  cs = capn_root(&rc).seg;
  afisafi_ctxt = qcapn_new_AfiSafiKey(cs);
  capn_write8(afisafi_ctxt, 0, af);
  capn_write8(afisafi_ctxt, 1, saf);
  /* retrieve bgp context */
  grep = qzcclient_getelem (ctxt->qzc_sock, &bgp_inst_nid, 3, \
                            &afisafi_ctxt, &bgp_ctxttype_afisafi,\
                            NULL, NULL);
  if(grep == NULL)
    {
      *_return = BGP_ERR_FAILED;
      capn_free(&rc);
      return FALSE;
    }
  memset(&inst, 0, sizeof(struct bgp));
  qcapn_BGPAfiSafi_read(&inst, grep->data, af, saf);
  /* set flag per afi/safi */
  if(enable)
    {
      inst.af_flags[af][saf] |= BGP_CONFIG_ASPATH_MULTIPATH_RELAX;
      inst.af_flags[af][saf] |= BGP_CONFIG_MULTIPATH;
    }
  else
    {
      inst.af_flags[af][saf] &= ~BGP_CONFIG_ASPATH_MULTIPATH_RELAX;
      inst.af_flags[af][saf] &= ~BGP_CONFIG_MULTIPATH;
    }

  /* reset qzc reply and rc context */
  qzcclient_qzcgetrep_free(grep);
  /* prepare QZCSetRequest context */
  nctxt = qcapn_new_BGPAfiSafi(cs);
  qcapn_BGPAfiSafi_write(&inst, nctxt, af, saf);
  /* put max value as a supplementary data in pipe */
  capn_write8(nctxt, 3, ZRPC_MAXPATH_DEFAULT_VAL);
  if(qzcclient_setelem (ctxt->qzc_sock, &bgp_inst_nid, 2, \
                        &nctxt, &bgp_datatype_bgp,\
                        &afisafi_ctxt, &bgp_ctxttype_afisafi))
  {
    if(IS_ZRPC_DEBUG)
      {
        if(enable)
          zrpc_info ("enableMultipath for afi:%d safi:%d OK", af, saf);
        else
          zrpc_info ("disableMultipath for afi:%d safi:%d OK", af, saf);
      }
  }

  capn_free(&rc);
  return TRUE;
}

gboolean
instance_bgp_configurator_handler_enable_multipath(BgpConfiguratorIf *iface, gint32* _return,
                                                   const af_afi afi, const af_safi safi, GError **error)
{
  struct zrpc_vpnservice *ctxt = NULL;

  zrpc_vpnservice_get_context (&ctxt);
  if(!ctxt)
    {
      *_return = BGP_ERR_FAILED;
      return FALSE;
    }
  return zrpc_bgp_set_multipath(ctxt, _return, afi, safi, 1, error);
}

gboolean
instance_bgp_configurator_handler_disable_multipath(BgpConfiguratorIf *iface, gint32* _return,
                                                    const af_afi afi, const af_safi safi, GError **error)
{
  struct zrpc_vpnservice *ctxt = NULL;

  zrpc_vpnservice_get_context (&ctxt);
  if(!ctxt)
    {
      *_return = BGP_ERR_FAILED;
      return FALSE;
    }
  return zrpc_bgp_set_multipath(ctxt, _return, afi, safi, 0, error);
}


/*
 * Enable/disable multipath feature for VPNv4 address family
 */
gboolean
instance_bgp_configurator_handler_multipaths(BgpConfiguratorIf *iface, gint32* _return,
                                             const gchar * rd, const gint32 maxPath, GError **error)
{
  struct zrpc_vpnservice *ctxt = NULL;
  struct capn_ptr bgpvrf;
  struct capn rc;
  struct capn_segment *cs;
  struct bgp_vrf instvrf;
  uint64_t bgpvrf_nid;
  struct zrpc_rd_prefix rd_inst;
  struct QZCGetRep *grep_vrf;
  int ret;

  zrpc_vpnservice_get_context (&ctxt);
  if(!ctxt)
  {
    *_return = BGP_ERR_FAILED;
    return FALSE;
  }

  if(zrpc_vpnservice_get_bgp_context(ctxt) == NULL || zrpc_vpnservice_get_bgp_context(ctxt)->asNumber == 0)
    {
      *_return = BGP_ERR_FAILED;
      *error = ERROR_BGP_AS_NOT_STARTED;
      return FALSE;
    }

  if(maxPath < 1 || maxPath > 64)
    {
      *error = ERROR_BGP_INVALID_MAXPATH;
      *_return = BGP_ERR_PARAM;
      return FALSE;
    }

  /* get route distinguisher internal representation */
  memset(&rd_inst, 0, sizeof(struct zrpc_rd_prefix));
  zrpc_util_str2rd_prefix((char *)rd, &rd_inst);
  /* if vrf not found, return an error */
  bgpvrf_nid = zrpc_bgp_configurator_find_vrf(ctxt, &rd_inst, _return);
  if(bgpvrf_nid == 0)
    {
      *error = ERROR_BGP_RD_NOTFOUND;
      *_return = BGP_ERR_PARAM;
      return FALSE;
    }

  grep_vrf = qzcclient_getelem (ctxt->qzc_sock, &bgpvrf_nid, 1, \
                                NULL, NULL, NULL, NULL);
  if(grep_vrf == NULL)
    {
      *_return = BGP_ERR_FAILED;
      return FALSE;
    }
  memset(&instvrf, 0, sizeof(struct bgp_vrf));
  qcapn_BGPVRF_read(&instvrf, grep_vrf->data);

  /* update max_mpath */
  instvrf.max_mpath = maxPath;
  /* reset qzc reply and rc context */
  qzcclient_qzcgetrep_free( grep_vrf);
  /* prepare QZCSetRequest context */
  capn_init_malloc(&rc);
  cs = capn_root(&rc).seg;
  bgpvrf = qcapn_new_BGPVRF(cs);
  qcapn_BGPVRF_write(&instvrf, bgpvrf);
  ret = qzcclient_setelem (ctxt->qzc_sock, &bgpvrf_nid, 1, \
                           &bgpvrf, &bgp_datatype_bgpvrf,\
                           NULL, NULL);
  capn_free(&rc);
  if(ret == 0)
  {
    *_return = BGP_ERR_FAILED;
    return FALSE;
  }
  else
  {
    if(IS_ZRPC_DEBUG)
      {
        zrpc_info ("maximum path for VRF %s set to %d", rd, maxPath);
      }
  }

  return TRUE;
}

static void
  instance_bgp_configurator_handler_finalize(GObject *object)
{
  G_OBJECT_CLASS (instance_bgp_configurator_handler_parent_class)->finalize (object);
}

/* InstanceBgpConfiguratorHandler's class initializer */
static void
instance_bgp_configurator_handler_class_init (InstanceBgpConfiguratorHandlerClass *klass)
{
  GObjectClass *gobject_class = G_OBJECT_CLASS (klass);
  BgpConfiguratorHandlerClass *bgp_configurator_handler_class = BGP_CONFIGURATOR_HANDLER_CLASS (klass);

  /* Register our destructor */
  gobject_class->finalize = instance_bgp_configurator_handler_finalize;

  /* Register our implementations of CalculatorHandler's methods */
  bgp_configurator_handler_class->create_peer =
    instance_bgp_configurator_handler_create_peer;
 
  bgp_configurator_handler_class->start_bgp =
    instance_bgp_configurator_handler_start_bgp;

  bgp_configurator_handler_class->stop_bgp =
    instance_bgp_configurator_handler_stop_bgp;

  bgp_configurator_handler_class->delete_peer =
    instance_bgp_configurator_handler_delete_peer;

  bgp_configurator_handler_class->add_vrf =
    instance_bgp_configurator_handler_add_vrf;

  bgp_configurator_handler_class->del_vrf =
    instance_bgp_configurator_handler_del_vrf;

  bgp_configurator_handler_class->push_route =
    instance_bgp_configurator_handler_push_route;

  bgp_configurator_handler_class->withdraw_route =
    instance_bgp_configurator_handler_withdraw_route;

 bgp_configurator_handler_class->set_ebgp_multihop =
   instance_bgp_configurator_handler_set_ebgp_multihop;

 bgp_configurator_handler_class->unset_ebgp_multihop =
   instance_bgp_configurator_handler_unset_ebgp_multihop;

 bgp_configurator_handler_class->set_update_source = 
   instance_bgp_configurator_handler_set_update_source;

 bgp_configurator_handler_class->unset_update_source = 
   instance_bgp_configurator_handler_unset_update_source;

 bgp_configurator_handler_class->enable_address_family =
   instance_bgp_configurator_handler_enable_address_family;

 bgp_configurator_handler_class->disable_address_family = 
   instance_bgp_configurator_handler_disable_address_family;

 bgp_configurator_handler_class->set_log_config = 
   instance_bgp_configurator_handler_set_log_config;

 bgp_configurator_handler_class->enable_graceful_restart = 
   instance_bgp_configurator_handler_enable_graceful_restart;

 bgp_configurator_handler_class->disable_graceful_restart = 
   instance_bgp_configurator_handler_disable_graceful_restart;

 bgp_configurator_handler_class->get_routes = 
   instance_bgp_configurator_handler_get_routes;

 bgp_configurator_handler_class->enable_multipath =
   instance_bgp_configurator_handler_enable_multipath;

 bgp_configurator_handler_class->disable_multipath =
   instance_bgp_configurator_handler_disable_multipath;

 bgp_configurator_handler_class->multipaths =
   instance_bgp_configurator_handler_multipaths;
}

/* InstanceBgpConfiguratorHandler's instance initializer (constructor) */
static void
instance_bgp_configurator_handler_init(InstanceBgpConfiguratorHandler *self)
{
  return;
}

