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
#include <sys/types.h>
#include <sys/wait.h>
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
#include "zrpcd/zrpc_bgp_updater.h"
#include "zrpcd/zrpc_vpnservice.h"

static void zrpc_exit (int);
static void zrpc_sighup (void);
static void zrpc_sigint (void);
static void zrpc_sigpipe (void);
static void zrpc_sigchild (void);

/* VTY port number and address.  */
int vty_port = 0;
char *vty_addr = NULL;
int zrpc_kill_in_progress = 0;
int zrpc_disable_syslog = 0;
int zrpc_disable_stdout = 0;
int zrpc_stopbgp_called = 0;

/* Help information display. */
static void
zrpc_usage (int status)
{
  printf ("Usage : zrpcd [OPTION...]\n\n\
Daemon which manages rpc configuration/updates from/to quagga\n\n\
zrpc configuration across thrift defined model : vpnservice.\n\n\
-D                          Disable default logging to stdout \n\
-S                          Disable default logging to syslog \n\
-P, --thrift_port           Set thrift's config port number\n\
-N, --thrift_notif_address  Set thrift's notif update specified address\n\
-n, --thrift_notif_port     Set thrift's notif update \n\
-I, --thrift_listen_port    Set thrift's listen config port number\n\
-L, --thrift_listen_address Set thrift's listen config specified address\n\
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

/* SIGCHLD handler. */
static void zrpc_sigchild (void)
{
  pid_t p;
  int status;
  struct zrpc_vpnservice *ctxt = NULL;
  uint32_t asNumber;

  while ((p=waitpid(-1, &status, WNOHANG)) != -1)
    {
      if (p == 0)
        return;
      if (zrpc_kill_in_progress)
        return;
      /* Handle the death of pid p */
      zrpc_info ("BGPD terminated (%u)",p);
      zrpc_vpnservice_get_context (&ctxt);
      /* kill BGP Daemon */
      if(ctxt == NULL)
        /* nothing to be done - context not yet created */
        return;
      if(zrpc_vpnservice_get_bgp_context(ctxt) == NULL)
        /* nothing to be done - BGP config already flushed */
        return;
      zrpc_kill_in_progress = 1;
      asNumber = zrpc_vpnservice_get_bgp_context(ctxt)->asNumber;
      /* reset Thrift Context */
      zrpc_vpnservice_get_bgp_context(ctxt)->proc = 0;
      zrpc_vpnservice_terminate_bgp_context(ctxt);
      zrpc_vpnservice_terminate_bgpvrf_cache(ctxt);
      zrpc_vpnservice_terminate_qzc(ctxt);
      /* creation of capnproto context */
      zrpc_vpnservice_setup_bgp_cache(ctxt);
      zrpc_vpnservice_setup_qzc(ctxt);
      zrpc_vpnservice_setup_bgp_context(ctxt);
      if(asNumber)
        zrpc_info ("stopBgp(AS %u) OK", asNumber);
      zrpc_kill_in_progress = 0;
      if (zrpc_stopbgp_called == 0)
        zrpc_sigint();
      else
        zrpc_stopbgp_called = 0;
    }
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
  else if (signo ==  SIGCHLD)
    {
      zrpc_sigchild ();
    }
  else if (signo ==  SIGTERM)
    {
      zrpc_sigint ();
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
  char vtydisplay[20];
  struct in_addr server_addr;

  /* Set umask before anything for security */
  umask (0027);

  if (zrpc_util_proc_find(argv[0]) != -1)
    {
      printf("%s: pid %u already present. cancel execution\r\n",argv[0], zrpc_util_proc_find(argv[0]));
      return 0;
    }
  /* ZRPC main init. */
  zrpc_global_init ();

  /* Command line argument treatment. */
  while ((option = getopt (argc, argv, "A:P:p:N:L:I:n:DSh")) != -1)
    {
      switch (option)
	{
	case 'S':
          zrpc_disable_syslog = 1;
          break;
	case 'D':
          zrpc_disable_stdout = 1;
          break;
	case 'P':
	  tmp_port = atoi (optarg);
	  if (tmp_port < 0 || tmp_port > 0xffff)
            vty_port = 0;
          else
            vty_port = tmp_port;
	  break;
	case 'I':
	  tmp_port = atoi (optarg);
	  if (tmp_port < 0 || tmp_port > 0xffff)
	    tm->zrpc_listen_port = 0;
	  else
	    tm->zrpc_listen_port = tmp_port;
	  break;
	case 'N':
          if(tm->zrpc_notification_address)
            free(tm->zrpc_notification_address);
          tm->zrpc_notification_address = strdup(optarg);
          break;
	  /* listenon implies -n */
	case 'L':
          if (inet_pton (AF_INET, (const char *)optarg, &server_addr) != 1)
            {
              printf ("Invalid ip address %s\r\n", optarg);
              return -1;
            }

          if(tm->zrpc_listen_address)
            free(tm->zrpc_listen_address);
          tm->zrpc_listen_address = strdup(optarg);
          break;
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
  if (signal(SIGCHLD, zrpc_sig_handler) == SIG_ERR)
    zrpc_log("can't catch SIGCHLD");
  if (signal(SIGTERM, zrpc_sig_handler) == SIG_ERR)
    zrpc_log("can't catch SIGTERM");

  cmd_init (1);
  memory_init ();
  vty_init (tm->global);

  host.password = ZRPC_STRDUP ("zebra");
  host.name = ZRPC_STRDUP ("zrpcd");

  /* BGP debug initialisation */
  zrpc_debug_init ();

  /* Create VTY's socket */
  if (vty_port)
    {
      sprintf (vtydisplay, "vty@%d,", vty_port);
      vty_serv_sock (vty_addr, vty_port, ZRPC_VTYSH_PATH);
    }
  else
    sprintf (vtydisplay, "");
  /* Try to return to normal operation. */
  /* create listen context */
  zrpc_create_context (&zrpc);
  tm->zrpc = zrpc;

  /* Print banner. */
  zrpc_log ("zrpcd starting: %s zrpc@%s:%d pid %d",
            vtydisplay,
            (tm->address ? tm->address : "<all>"),
            zrpc_vpnservice_get_thrift_bgp_configurator_server_port(zrpc->zrpc_vpnservice),
            getpid ());

  /* connect updater server and send notification */
  struct zrpc_vpnservice *ctxt = NULL;
  zrpc_vpnservice_get_context (&ctxt);
  ctxt->bgp_updater_client_thread = NULL;
  THREAD_TIMER_MSEC_ON(tm->global, ctxt->bgp_updater_client_thread,    \
                       zrpc_bgp_updater_on_start_config_resync_notification, \
                       ctxt, 10);
  /* Start finite state machine, here we go! */
  while (thread_fetch (tm->global, &thread))
    thread_call (&thread);

  /* Not reached. */
  return (0);
}
