/* ZRPC daemon program
 * Copyright (c) 2016 6WIND,
 *
 * This file is part of ZRPC daemon.
 *
 * See the LICENSE file.
 */
#include "thread.h"

#include "zrpcd/zrpc_thrift_wrapper.h"
#include "zrpcd/bgp_configurator.h"
#include "zrpcd/bgp_updater.h"
#include "zrpcd/zrpc_bgp_configurator.h"
#include "zrpcd/zrpc_vpnservice.h"
#include "zrpcd/zrpc_debug.h"
#include "zrpcd/zrpcd.h"
#include "zrpcd/zrpc_network.h"
#include "zrpcd/zrpc_debug.h"

/* zrpc process wide configuration.  */
static struct zrpc_global zrpc_global;

/* zrpc process wide configuration pointer to export.  */
struct zrpc_global *tm;

struct zrpc_peer *zrpc_peer_create_accept(struct zrpc *zrpc)
{
  struct zrpc_peer *peer;

  /* Allocate new peer. */
  peer = ZRPC_CALLOC (sizeof (struct zrpc_peer));
  memset (peer, 0, sizeof (struct zrpc_peer));

  peer->zrpc = zrpc;
  peer->next = zrpc->peer;
  zrpc->peer = peer;
  return peer;
}

static struct zrpc *
zrpc_create (void)
{
  struct zrpc *zrpc;

  if ( (zrpc = ZRPC_CALLOC (sizeof (struct zrpc))) == NULL)
    return NULL;
  memset (zrpc, 0, sizeof(struct zrpc));
  zrpc->peer = NULL;
  return zrpc;
}


/* Delete BGP instance. */
int
zrpc_delete (struct zrpc *zrpc)
{
  struct zrpc_peer *peer, *peer_next;

  for (peer = zrpc->peer; peer; peer = peer_next)
    {
      peer_next = peer->next;
      if(peer->fd)
        {
          if (IS_ZRPC_DEBUG)
            zrpc_log("zrpc_delete : close connection (fd %d)", peer->fd);
          zrpc_vpnservice_terminate_client(peer->peer);
          ZRPC_FREE (peer->peer);
          peer->peer = NULL;
          peer->fd=0;
        }
      peer->next = NULL;
      ZRPC_FREE (peer);
    }
  zrpc->peer = NULL;
  zrpc_vpnservice_terminate_bfd(zrpc->zrpc_vpnservice);
  zrpc_vpnservice_terminate_bgp_context (zrpc->zrpc_vpnservice);
  zrpc_vpnservice_terminate_qzc(zrpc->zrpc_vpnservice);
  zrpc_vpnservice_terminate_thrift_bgp_updater_client (zrpc->zrpc_vpnservice);
  zrpc_vpnservice_terminate_thrift_bgp_configurator_server (zrpc->zrpc_vpnservice);
  zrpc_vpnservice_terminate(zrpc->zrpc_vpnservice);
  if(zrpc->zrpc_vpnservice)
    ZRPC_FREE (zrpc->zrpc_vpnservice);
  zrpc->zrpc_vpnservice = NULL;
  return 0;
}

void
zrpc_global_init (void)
{
  memset (&zrpc_global, 0, sizeof (struct zrpc_global));

  tm = &zrpc_global;
  tm->listen_sockets = NULL;
  tm->global = thread_master_create ();
  tm->zrpc_listen_port = ZRPC_LISTEN_PORT;
  tm->zrpc_notification_port = ZRPC_NOTIFICATION_PORT;
  tm->zrpc_notification_address = strdup(ZRPC_CLIENT_ADDRESS);
  tm->zrpc_listen_address = strdup(ZRPC_LISTEN_ADDRESS);
}



/* Called from VTY commands. */
void  zrpc_create_context (struct zrpc **zrpc_val)
{
  struct zrpc *zrpc;
  zrpc = zrpc_create ();
  *zrpc_val = zrpc;

  tm->zrpc = zrpc;

  zrpc->zrpc_vpnservice = ZRPC_CALLOC (sizeof(struct zrpc_vpnservice));
  zrpc_vpnservice_setup(zrpc->zrpc_vpnservice);
  zrpc_vpnservice_set_thrift_bgp_configurator_server_port (zrpc->zrpc_vpnservice, tm->zrpc_listen_port);
  zrpc_vpnservice_set_thrift_bgp_updater_client_port (zrpc->zrpc_vpnservice, tm->zrpc_notification_port);

  /* creation of thrift contexts - configurator and updater */
  zrpc_server_socket(zrpc);

  /* creation of capnproto context - updater */
  zrpc_vpnservice_setup_qzc(zrpc->zrpc_vpnservice);

  zrpc_kill_child (BGPD_PATH_BGPD_PID, "BGP");
  zrpc_kill_child (BFDD_PID, "BFD");
  zrpc_kill_child (ZEBRA_PID, "ZEBRA");
  /* run bgp_configurator_server */ 
  if(zrpc_server_listen (zrpc) < 0)
    {
      /* exit on failure */
      exit(1);
    }

  return ;
}

void
zrpc_init (void)
{
}

void
zrpc_terminate (void)
{
}
