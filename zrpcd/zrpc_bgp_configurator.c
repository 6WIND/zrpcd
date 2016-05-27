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

/* ---------------------------------------------------------------- */

static gboolean
instance_bgp_configurator_handler_create_peer(BgpConfiguratorIf *iface,
                                              gint32* ret, const gchar *routerId,
                                              const gint32 asNumber, GError **error);
static gboolean
instance_bgp_configurator_handler_start_bgp(BgpConfiguratorIf *iface, gint32* _return, const gint32 asNumber,
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
instance_bgp_configurator_handler_push_route(BgpConfiguratorIf *iface, gint32* _return, const gchar * prefix,
                                             const gchar * nexthop, const gchar * rd, const gint32 label, GError **error);
gboolean
instance_bgp_configurator_handler_withdraw_route(BgpConfiguratorIf *iface, gint32* _return, const gchar * prefix,
                                                 const gchar * rd, GError **error);
gboolean
instance_bgp_configurator_handler_stop_bgp(BgpConfiguratorIf *iface, gint32* _return, const gint32 asNumber, GError **error);
gboolean
instance_bgp_configurator_handler_delete_peer(BgpConfiguratorIf *iface, gint32* _return, const gchar * ipAddress, GError **error);
gboolean
instance_bgp_configurator_handler_add_vrf(BgpConfiguratorIf *iface, gint32* _return, const gchar * rd,
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
instance_bgp_configurator_handler_get_routes (BgpConfiguratorIf *iface, Routes ** _return, const gint32 optype,
                                              const gint32 winSize, GError **error);

static void instance_bgp_configurator_handler_finalize(GObject *object);

/*
 * utilities functions for thrift <-> capnproto exchange
 * some of those functions implement a cache mecanism for some objects
 * like VRF
 */
static uint64_t
zrpc_bgp_configurator_find_vrf(struct zrpc_vpnservice *ctxt, struct zrpc_rd_prefix *rd, gint32* _return);


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
 * Start a Create a BGP neighbor for a given routerId, and asNumber
 * If BGP is already started, then an error is returned : BGP_ERR_ACTIVE
 */
static gboolean
instance_bgp_configurator_handler_start_bgp(BgpConfiguratorIf *iface, gint32* _return, const gint32 asNumber,
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
    zrpc_log ("startBgp. bgpd called (AS %u, proc %d)", \
                (uint32_t)asNumber, pid);
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
    inst.stalepath_time = stalepathTime;
    if(stalepathTime)
      inst.flags |= BGP_FLAG_GRACEFUL_RESTART;
    else
      inst.flags &= ~BGP_FLAG_GRACEFUL_RESTART;
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
        zrpc_log ("startBgp(%u, %s) OK",(uint32_t)asNumber, routerId);
      else
        zrpc_log ("startBgp(%u, %s) NOK",(uint32_t)asNumber, routerId);
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
  return TRUE;
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
  return TRUE;
}

/*
 * Push Route for a given Route Distinguisher.
 * This route contains an IPv4 prefix, as well as an IPv4 nexthop.
 * A label is also set in the given Route.
 * If no VRF has been found matching the route distinguisher, then
 * an error is returned
 */
gboolean
instance_bgp_configurator_handler_push_route(BgpConfiguratorIf *iface, gint32* _return,
                                             const gchar * prefix, const gchar * nexthop,
                                             const gchar * rd, const gint32 label, GError **error)
{
  return TRUE;
}

/*
 * Withdraw Route for a given Route Distinguisher and IPv4 prefix
 * If no VRF has been found matching the route distinguisher, then
 * an error is returned
 */
gboolean
instance_bgp_configurator_handler_withdraw_route(BgpConfiguratorIf *iface, gint32* _return,
                                                 const gchar * prefix, const gchar * rd, GError **error)
{
  return TRUE;
}

/* 
 * Stop BGP Router for a given AS Number
 * If BGP is already stopped, or give AS is not present, an error is returned
 */
gboolean
instance_bgp_configurator_handler_stop_bgp(BgpConfiguratorIf *iface, gint32* _return,
                                           const gint32 asNumber, GError **error)
{
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
                                              const gchar *routerId, const gint32 asNumber, GError **error)
{
  return TRUE;
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
  return TRUE;
}

/*
 * Add a VRF entry for a given route distinguisher
 * Optionally, imported and exported route distinguisher are given.
 * An error is returned if VRF entry already exists.
 * VRF must be removed before being updated
 */
gboolean
instance_bgp_configurator_handler_add_vrf(BgpConfiguratorIf *iface, gint32* _return, const gchar * rd,
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
  memset(&instvrf, 0, sizeof(struct bgp_vrf));
  /* get route distinguisher internal representation */
  zrpc_util_str2rd_prefix((char *)rd, &instvrf.outbound_rd);

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
      entry->bgpvrf_nid = bgpvrf_nid;
      if(IS_ZRPC_DEBUG_CACHE)
        zrpc_log ("CACHE_VRF: add entry %llx", (long long unsigned int)bgpvrf_nid);
      entry->next = ctxt->bgp_vrf_list;
      ctxt->bgp_vrf_list = entry;
      if(IS_ZRPC_DEBUG)
        zrpc_log ("addVrf(%s) OK", rd);
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
                  zrpc_log ("delVrf(%s) OK", rd);
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
  return TRUE;
}

/*
 * enable MP-BGP routing information exchange with a given neighbor
 * for a given address family identifier and subsequent address family identifier.
 */
gboolean instance_bgp_configurator_handler_enable_address_family(BgpConfiguratorIf *iface, gint32* _return,
                                                                 const gchar * peerIp, const af_afi afi,
                                                                 const af_safi safi, GError **error)
{
  return TRUE;
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
  return TRUE;
}

gboolean
instance_bgp_configurator_handler_set_log_config (BgpConfiguratorIf *iface, gint32* _return, const gchar * logFileName,
                                                  const gchar * logLevel, GError **error)
{
  return TRUE;
}

/*
 * enable Graceful Restart for BGP Router, as well as stale path timer.
 * if the stalepathTime is set to 0, then the graceful restart feature will be disabled
 */
gboolean
instance_bgp_configurator_handler_enable_graceful_restart (BgpConfiguratorIf *iface, gint32* _return,
                                                           const gint32 stalepathTime, GError **error)
{
  return TRUE;
}

/* disable Graceful Restart for BGP Router */
gboolean
instance_bgp_configurator_handler_disable_graceful_restart (BgpConfiguratorIf *iface, gint32* _return, GError **error)
{
  return TRUE;
}

gboolean
instance_bgp_configurator_handler_get_routes (BgpConfiguratorIf *iface, Routes ** _return,
                                              const gint32 optype, const gint32 winSize, GError **error)
{
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
}

/* InstanceBgpConfiguratorHandler's instance initializer (constructor) */
static void
instance_bgp_configurator_handler_init(InstanceBgpConfiguratorHandler *self)
{
  return;
}

