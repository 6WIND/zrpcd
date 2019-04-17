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
  uint16_t zrpc_select_time;
#ifdef HAVE_THRIFT_V6
  /* how many iterations shall be tried to re-send udpate message */
  u_int16_t zrpc_bgp_updater_max_retries;
  /* time-gap between each iteration, in milliseconds */
  u_int16_t zrpc_bgp_updater_retry_time_gap;
  /* maximum size of bgp updater message queue */
  u_int32_t zrpc_bgp_updater_queue_maximum_size;
#endif

  char *zrpc_notification_address;
  char *zrpc_listen_address;
};

/* Global thread strucutre. */
extern struct thread_master *global;

extern struct zrpc_global *tm;

extern int zrpc_kill_in_progress;
extern int zrpc_disable_syslog;
extern int zrpc_disable_stdout;
extern int zrpc_stopbgp_called;
extern int zrpc_silent_leave;

#endif /* _ZRPC_GLOBAL_H_ */
