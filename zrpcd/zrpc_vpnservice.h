/* zrpc core structures and API
 * Copyright (c) 2016 6WIND,
 *
 * This file is part of ZRPC daemon.
 *
 * See the LICENSE file.
 */
#ifndef _ZRPC_VPNSERVICE_H
#define _ZRPC_VPNSERVICE_H

#include "zrpcd/zrpc_os_wrapper.h"
#include "zrpcd/zrpc_util.h"
#include "zrpcd/zrpc_bgp_capnp.h"
#include "prefix.h"
#include "table.h"

#define ZRPC_LISTEN_PORT	 7644
#define ZRPC_NOTIFICATION_PORT 6644
#define ZRPC_CLIENT_ADDRESS "0.0.0.0"
#define ZRPC_LISTEN_ADDRESS "0.0.0.0"
#define ZRPC_SELECT_TIME_SEC 2
#ifdef HAVE_THRIFT_V6
#define ZRPC_DEFAULT_UPDATE_RETRY_TIMES 5
#define ZRPC_DEFAULT_UPDATE_RETRY_TIME_GAP 100 /* millisecond */
#endif

#define ZMQ_SOCK "ipc:///tmp/qzc-vpn2bgp"
#define ZMQ_NOTIFY "ipc:///tmp/qzc-notify"

#define BGPD_ARGS_STRING_1  "-p"
#define BGPD_ARGS_STRING_3  "-Z"

#define BGPD_PATH_BGPD_PID "/opt/quagga/var/run/quagga/bgpd.pid"
#define BGPD_PATH_QUAGGA   "/opt/quagga"

#define ZMQ_BFDD_SOCK "ipc:///tmp/qzc-vpn2bfdd"
#define BFDD_PID "/opt/quagga/var/run/quagga/bfdd.pid"
#define BFDD_PATH "/opt/quagga/sbin/bfdd"
#define ZEBRA_PID "/opt/quagga/var/run/quagga/zebra.pid"
#define ZEBRA_PATH "/opt/quagga/sbin/zebra"

#define ZRPC_CONFIG_FILE   "zrpcd.conf"

#define ZRPC_DEFAULT_LOG_FILE "/opt/quagga/var/log/quagga/zrpcd.init.log"
#define ZRPC_DEFAULT_LOG_LEVEL "debugging"

#define STALEMARKER_TIMER_MAX 3600
#define STALEMARKER_TIMER_MIN 0
#define STALEMARKER_TIMER_DEFAULT 1800
#define BGP_CONFIG_FLAG_STALE (1 << 0)

struct thread;

struct zrpc_vpnservice_client
{
  ThriftProcessor *processor;
  ThriftTransport *transport;
  ThriftBufferedTransport *transport_buffered;
  ThriftProtocol *protocol;
  ThriftServer *server;
  ThriftSimpleServer *simple_server;
};

struct zrpc_vpnservice_bgp_context
{
  uint32_t asNumber;
  gint32 proc;
  char *logFile;
  char *logLevel;
  uint8_t multipath_on[AFI_MAX][SAFI_MAX];
};

struct zrpc_bgp_static
{
  struct zrpc_rd_prefix prd;
#if !defined(HAVE_THRIFT_V1)
  protocol_type p_type;
#endif
  uint16_t flags;
};

/* zrpc cache contexts */
struct zrpc_vpnservice_cache_bgpvrf
{
  uint64_t bgpvrf_nid;
  struct zrpc_rd_prefix outbound_rd;
  struct zrpc_rdrt *rdrt_export;
  struct zrpc_vpnservice_cache_bgpvrf *next;
  bgp_layer_type_t ltype;
  uint8_t afc[ADDRESS_FAMILY_MAX][SUBSEQUENT_ADDRESS_FAMILY_MAX];
  uint8_t stale_flags[ADDRESS_FAMILY_MAX][SUBSEQUENT_ADDRESS_FAMILY_MAX];
  /* Static route configuration.  */
  struct route_table *route[ADDRESS_FAMILY_MAX];
};

struct zrpc_vpnservice_cache_peer
{
  uint64_t peer_nid;
  uint32_t asNumber;
  uint16_t flags;
  char *peerIp;
  struct zrpc_vpnservice_cache_peer *next;
  uint8_t enableAddressFamily[ADDRESS_FAMILY_MAX][SUBSEQUENT_ADDRESS_FAMILY_MAX];
};

struct zrpc_vpnservice
{
  /* configuration part */
  /* zrpc listen port number.  */
  u_int16_t  zrpc_listen_port;

  /* zrpc notification port number.  */
  u_int16_t  zrpc_notification_port;

  /* zrpc BGP Contexts */
  ThriftServerTransport *bgp_configurator_server_transport;
  BgpConfiguratorProcessor *bgp_configurator_processor;
  InstanceBgpConfiguratorHandler *bgp_configurator_handler;

  /* zrpc Update Contexts */
  BgpUpdaterIf *bgp_updater_client;
  struct thread *bgp_updater_client_thread;
  gboolean bgp_updater_client_need_select;
  gboolean bgp_updater_select_in_progress;
  ThriftSocket *bgp_updater_socket;
  ThriftFramedTransport *bgp_updater_transport;
  ThriftProtocol *bgp_updater_protocol;

  /* bgp context */
  struct zrpc_vpnservice_bgp_context *bgp_context;

  /* if bfdd is enabled */
  uint8_t bfdd_enabled;
  uint8_t bfd_multihop;


  /* CapnProto Path */
  char      *zmq_sock;

  /* CapnProto Subscribe Path */
  char      *zmq_subscribe_sock;

  /* BGPD binay execution path */
  char     *bgpd_execution_path;

  /* QZC internal contexts */
  struct qzcclient_sock *qzc_sock;
  struct qzcclient_sock **p_qzc_sock;
  struct qzcclient_sock *qzc_subscribe_sock;
  struct qzcclient_sock *qzc_bfdd_sock;
  struct qzcclient_sock **p_qzc_bfdd_sock;
  
  /* zrpc cache context for VRF */
  struct zrpc_vpnservice_cache_bgpvrf *bgp_vrf_list;
  struct zrpc_vpnservice_cache_peer *bgp_peer_list;
  struct zrpc_vpnservice_cache_bgpvrf *bgp_get_routes_list;

  /* Timer thread for configs marked as STALE. If one STALE config
   * is received again before this timer expires, STALE flag will
   * be removed for this config. When this timer expires, all configs
   * marked as STALE will be deleted. */
  struct thread *config_stale_thread;

  /* bgp updater statistics */
  u_int32_t bgp_update_lost_msgs;
  u_int32_t bgp_update_monitor;
  u_int32_t bgp_update_retries;
  u_int32_t bgp_update_total;
  u_int32_t bgp_update_thrift_lost_msgs;
  u_int32_t bgp_update_thrift_retries;
  u_int32_t bgp_update_thrift_retries_successfull;
};

enum _zrpc_status
  {
    ZRPC_TO_SDN_UNKNOWN,
    ZRPC_TO_SDN_TRUE,
    ZRPC_TO_SDN_FALSE
  };
typedef enum _zrpc_status zrpc_status;

#define ZRPC_MAX_ERRNO 132
extern unsigned int notification_socket_errno[];

void zrpc_vpnservice_terminate(struct zrpc_vpnservice *setup);
void zrpc_vpnservice_terminate_thrift_bgp_configurator_server(struct zrpc_vpnservice *setup);
void zrpc_vpnservice_terminate_thrift_bgp_updater_client(struct zrpc_vpnservice *setup);
gboolean zrpc_vpnservice_setup_thrift_bgp_updater_client (struct zrpc_vpnservice *setup);
void zrpc_vpnservice_setup_thrift_bgp_configurator_server(struct zrpc_vpnservice *setup);
void zrpc_vpnservice_setup(struct zrpc_vpnservice *setup);
void zrpc_vpnservice_setup_bgp_cache(struct zrpc_vpnservice *ctxt);

void zrpc_vpnservice_get_context (struct zrpc_vpnservice **setup);
u_int16_t zrpc_vpnservice_get_thrift_bgp_configurator_server_port (struct zrpc_vpnservice *setup);
void zrpc_vpnservice_set_thrift_bgp_updater_client_port (struct zrpc_vpnservice *setup, \
                                                            u_int16_t thrift_notif_port);
u_int16_t zrpc_vpnservice_get_thrift_bgp_updater_client_port (struct zrpc_vpnservice *setup);
void zrpc_vpnservice_set_thrift_bgp_configurator_server_port (struct zrpc_vpnservice *setup, \
                                                                 u_int16_t thrift_listen_port);
void zrpc_vpnservice_setup_client(struct zrpc_vpnservice_client *peer,\
                                     struct zrpc_vpnservice *setup,  \
                                     ThriftTransport *transport);

void zrpc_vpnservice_terminate_client(struct zrpc_vpnservice_client *peer);
void zrpc_vpnservice_terminate_qzc(struct zrpc_vpnservice *setup);
void zrpc_vpnservice_terminate_qzc_bfdd(struct zrpc_vpnservice *setup);
void zrpc_vpnservice_terminate_bfd(struct zrpc_vpnservice *setup);
void zrpc_vpnservice_setup_qzc(struct zrpc_vpnservice *setup);
struct zrpc_vpnservice_bgp_context *zrpc_vpnservice_get_bgp_context(struct zrpc_vpnservice *setup);
void zrpc_vpnservice_setup_bgp_context(struct zrpc_vpnservice *setup);
void zrpc_vpnservice_terminate_bgp_context(struct zrpc_vpnservice *setup);
void zrpc_vpnservice_terminate_bgpvrf_cache (struct zrpc_vpnservice *setup);
gboolean zrpc_vpnservice_set_bgp_context_multipath (struct zrpc_vpnservice_bgp_context *bgp,
                                                    address_family_t afi, subsequent_address_family_t safi,
                                                    uint8_t on, gint32* _return, GError **error);
extern int zrpc_vpnservice_get_bgp_updater_socket (struct zrpc_vpnservice *setup);

extern void zrpc_config_stale_set(struct zrpc_vpnservice *setup);
extern void zrpc_delete_stale_vrf(struct zrpc_vpnservice *setup,
                                  struct zrpc_vpnservice_cache_bgpvrf *vrf);
extern void zrpc_config_stale_timer_flush(struct zrpc_vpnservice *setup, bool donotflush);
extern void zrpc_delete_stale_peer(struct zrpc_vpnservice *setup,
                                   struct zrpc_vpnservice_cache_peer *peer);
extern void zrpc_delete_stale_route(struct zrpc_vpnservice *setup,
                                    struct route_node *rn);
extern void zrpc_clear_vrf_route_table(struct zrpc_vpnservice_cache_bgpvrf *entry);

#endif /* _ZRPC_VPNSERVICE_H */
