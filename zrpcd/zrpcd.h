/* ZRPCD related values and structures.
 * Copyright (c) 2016 6WIND,
 *
 * This file is part of ZRPC daemon.
 *
 * See the LICENSE file.
 */


#ifndef _ZRPCD_H
#define _ZRPCD_H

#include "zrpcd/zrpc_memory.h"

#define ZRPC_VTY_PORT            2611

struct zrpc
{
  /* Thrift socket. */
  int sock;

  char *name;

  /* Thrift clients */
  struct zrpc_peer *peer;

  /* Thrift threads. */
  struct thread *t_read;
  struct thread *t_write;

  /* thrift server context */
  struct zrpc_vpnservice *zrpc_vpnservice;
};

/* Thrift Remote structure. */
struct zrpc_peer
{
  /* zrpc structure pointer */
  struct zrpc *zrpc;

  /* Peer information */
  int fd;			/* File descriptor */

  /* Threads. */
  struct thread *t_read;
  
  /* thrift context for one thrift connexion */
  struct zrpc_vpnservice_client *peer;

  struct zrpc_peer *next;

  /* information about peer */
  struct sockaddr_storage peerIp;
};

#include "zrpcd/zrpc_global.h"

/* Prototypes. */
extern void zrpc_init (void);
extern void zrpc_global_init (void);
extern void zrpc_terminate (void);
extern void zrpc_reset (void);
extern void  zrpc_create_context (struct zrpc **thrift_val);
struct zrpc_peer *zrpc_peer_create_accept(struct zrpc *zrpc);

extern int zrpc_delete (struct zrpc *);

extern void zrpc_bgp_configurator_create(struct zrpc *zrpc);
extern void zrpc_bgp_configurator_server_terminate(void);

#endif /* _ZRPC_H */
