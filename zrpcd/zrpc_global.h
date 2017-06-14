/* zrpc global
 * Copyright (c) 2016 6WIND,
 *
 * This file is part of ZRPC daemon.
 *
 * See the LICENSE file.
 */
#ifndef _ZRPC_GLOBAL_H_
#define _ZRPC_GLOBAL_H_

#include <stdint.h>
#include "thread.h"

/* Thrift global for system wide configurations and variables.  */
struct zrpc_global
{
  /* ZRPC only instance  */
  struct zrpc *zrpc;

  /* BGP thread global.  */
  struct thread_master *global;

  /* Listening sockets */
  struct zrpc_listener *listen_sockets;

  /* Listener address */
  char *address;

  /* zrpcd parameters */
  uint16_t zrpc_notification_port;
  uint16_t zrpc_listen_port;
  char *zrpc_notification_address;
};

/* Global thread strucutre. */
extern struct thread_master *global;

extern struct zrpc_global *tm;

extern int zrpc_kill_in_progress;
extern int zrpc_disable_stdout;
extern int zrpc_stopbgp_called;

#endif /* _ZRPC_GLOBAL_H_ */
