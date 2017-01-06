/* zrpc main program
 * Copyright (c) 2016 6WIND,
 *
 * This file is part of ZRPC daemon.
 *
 * See the LICENSE file.
 */


#include <stdio.h>
#include <signal.h>
#include <unistd.h>
//#include <getopt.h>

#include "thread.h"
#include "vector.h"
#include "vty.h"
#include "command.h"

#include "zrpcd/zrpc_debug.h"
#include "zrpcd/zrpcd.h"
#include "zrpcd/zrpc_network.h"

#include "zrpcd/zrpc_thrift_wrapper.h"
#include "zrpcd/bgp_configurator.h"
#include "zrpcd/bgp_updater.h"
#include "zrpcd/zrpc_bgp_configurator.h"
#include "zrpcd/zrpc_vpnservice.h"

static void zrpc_exit (int);
static void zrpc_sighup (void);
static void zrpc_sigint (void);
static void zrpc_sigpipe (void);

/* VTY port number and address.  */
int vty_port = ZRPC_VTY_PORT;
char *vty_addr = NULL;

/* Help information display. */
static void
zrpc_usage (int status)
{
  printf ("Usage : zrpcd [OPTION...]\n\n\
Daemon which manages rpc configuration/updates from/to quagga\n\n\
zrpc configuration across thrift defined model : vpnservice.\n\n\
-p, --thrift_port           Set thrift's config port number\n\
-P, --thrift_notif_port     Set thrift's notif update port number\n\
-N, --thrift_notif_address  Set thrift's notif update specified address\n\
-h, --help                  Display this help and exit\n\n");
  exit (status);
}

static void  zrpc_sigpipe (void)
{
  /* Do nothing */
}

static void  zrpc_sighup (void)
{
  zrpc_log (NULL, LOG_INFO, "SIGHUP received");

  /* Terminate all thread. */
  zrpc_terminate ();
  vty_reset ();
  zrpc_log ("zrpcd restarting!");
  /* Try to return to normal operation. */
}

/* SIGINT handler. */
static void zrpc_sigint (void)
{
  zrpc_log ("Terminating on signal");

  zrpc_terminate ();
  zrpc_debug_flush ();
  zrpc_exit (0);
}


/* signal handler. only sigup and sigint are handled */
static void zrpc_sig_handler(int signo)
{
  if (signo == SIGHUP)
    {
      zrpc_sighup ();
    }
  else if (signo ==  SIGINT)
    {
      zrpc_sigint ();
    }
  else if (signo ==  SIGPIPE)
    {
      zrpc_sigpipe ();
    }
}

/*
  exit from zrpc daemon
*/
static void
zrpc_exit (int status)
{
  /* it only makes sense for this to be called on a clean exit */
  assert (status == 0);

  /* reverse zrpc_global_init */
  if(tm->zrpc)
    {
      zrpc_delete (tm->zrpc);
      ZRPC_FREE (tm->zrpc);
      tm->zrpc = NULL;
    }
  
  cmd_terminate ();
  vty_terminate ();

  /* reverse zrpc_global_init */
  if (tm->global)
    thread_master_free (tm->global);

  exit (status);
}

/* Global routine of zrpcd. Treatment of argument and start zrpc finite
   state machine is handled here. */
int
main (int argc, char **argv)
{
  struct thread thread;
  struct zrpc *zrpc;
  int tmp_port;
  int option = 0;

  /* Set umask before anything for security */
  umask (0027);

  /* ZRPC main init. */
  zrpc_global_init ();

  /* Command line argument treatment. */
  while ((option = getopt (argc, argv, "A:P:p:N:n:h")) != -1)
    {
      switch (option)
	{
	case 'p':
	  tmp_port = atoi (optarg);
	  if (tmp_port <= 0 || tmp_port > 0xffff)
	    tm->zrpc_listen_port = ZRPC_LISTEN_PORT;
	  else
	    tm->zrpc_listen_port = tmp_port;
	  break;
	case 'N':
          if(tm->zrpc_notification_address)
            free(tm->zrpc_notification_address);
          tm->zrpc_notification_address = strdup(optarg);
          break;
	  /* listenon implies -n */
	case 'n':
	  tmp_port = atoi (optarg);
	  if (tmp_port <= 0 || tmp_port > 0xffff)
	    tm->zrpc_notification_port = ZRPC_NOTIFICATION_PORT;
	  else
	    tm->zrpc_notification_port = tmp_port;
	  break;
	case 'h':
	  zrpc_usage (0);
	  break;
	default:
	  zrpc_usage (1);
	}
    }

  /* Initializations. */
  srandom (time (NULL));

  if (signal(SIGINT, zrpc_sig_handler) == SIG_ERR)
    zrpc_log("can't catch SIGINT");
  if (signal(SIGHUP, zrpc_sig_handler) == SIG_ERR)
    zrpc_log("can't catch SIGHUP");
  if (signal(SIGPIPE, zrpc_sig_handler) == SIG_ERR)
    zrpc_log("can't catch SIGPIPE");

  cmd_init (1);
  memory_init ();
  vty_init (tm->global);

  host.password = ZRPC_STRDUP ("zebra");
  host.name = ZRPC_STRDUP ("zrpcd");

  /* BGP debug initialisation */
  zrpc_debug_init ();

  /* Create VTY's socket */
  vty_serv_sock (vty_addr, vty_port, ZRPC_VTYSH_PATH);

  /* Try to return to normal operation. */
  /* create listen context */
  zrpc_create_context (&zrpc);
  tm->zrpc = zrpc;

  /* Print banner. */
  zrpc_log ("zrpcd starting: zrpc@%s:%d pid %d",
	       (tm->address ? tm->address : "<all>"),
	       zrpc_vpnservice_get_thrift_bgp_configurator_server_port(zrpc->zrpc_vpnservice),
	       getpid ());

  /* Start finite state machine, here we go! */
  while (thread_fetch (tm->global, &thread))
    thread_call (&thread);

  /* Not reached. */
  return (0);
}
