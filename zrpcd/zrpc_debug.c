/* zrpc debug routines
 * Copyright (c) 2016 6WIND,
 *
 * This file is part of ZRPC daemon.
 *
 * See the LICENSE file.
 */
#include <stdarg.h>
#include <stdio.h>
#include <time.h>

#include "vty.h"
#include "command.h"

#include "zrpcd/zrpc_debug.h"

#define ZRPC_STR "ZRPC Information\n"

/* For debug statement. */
unsigned long zrpc_debug = 0;

DEFUN (show_debugging_zrpc,
       show_debugging_zrpc_cmd,
       "show debugging zrpc",
       SHOW_STR
       DEBUG_STR
       ZRPC_STR)
{
  vty_out (vty, "ZRPC debugging status:%s", VTY_NEWLINE);

  if (IS_ZRPC_DEBUG)
    vty_out (vty, "  ZRPC debugging is on%s", VTY_NEWLINE);
  if (IS_ZRPC_DEBUG_NETWORK)
    vty_out (vty, "  ZRPC debugging network is on%s", VTY_NEWLINE);
  if (IS_ZRPC_DEBUG_NOTIFICATION)
    vty_out (vty, "  ZRPC debugging notification is on%s", VTY_NEWLINE);
  if (IS_ZRPC_DEBUG_CACHE)
    vty_out (vty, "  ZRPC debugging cache is on%s", VTY_NEWLINE);
  return CMD_SUCCESS;
}

DEFUN (debug_zrpc,
       debug_zrpc_cmd,
       "debug zrpc",
       DEBUG_STR
       ZRPC_STR
       "ZRPC\n")
{
  zrpc_debug |= ZRPC_DEBUG;
  return CMD_WARNING;
}

DEFUN (no_debug_zrpc,
       no_debug_zrpc_cmd,
       "no debug zrpc",
       NO_STR
       DEBUG_STR
       ZRPC_STR
       "ZRPC\n")
{
  zrpc_debug &= ~ZRPC_DEBUG;
  return CMD_SUCCESS;
}

DEFUN (debug_zrpc_notification,
       debug_zrpc_notification_cmd,
       "debug zrpc notification",
       DEBUG_STR
       ZRPC_STR
       "ZRPC\n")
{
  zrpc_debug |= ZRPC_DEBUG_NOTIFICATION;
  return CMD_WARNING;
}

DEFUN (no_debug_zrpc_notification,
       no_debug_zrpc_notification_cmd,
       "no debug zrpc notification",
       NO_STR
       DEBUG_STR
       ZRPC_STR
       "ZRPC\n")
{
  zrpc_debug &= ~ZRPC_DEBUG_NOTIFICATION;
  return CMD_SUCCESS;
}

DEFUN (debug_zrpc_network,
       debug_zrpc_network_cmd,
       "debug zrpc network",
       DEBUG_STR
       ZRPC_STR
       "ZRPC\n")
{
  zrpc_debug |= ZRPC_DEBUG_NETWORK;
  return CMD_WARNING;
}

DEFUN (no_debug_zrpc_network,
       no_debug_zrpc_network_cmd,
       "no debug zrpc network",
       NO_STR
       DEBUG_STR
       ZRPC_STR
       "ZRPC\n")
{
  zrpc_debug &= ~ZRPC_DEBUG_NETWORK;
  return CMD_SUCCESS;
}

DEFUN (debug_zrpc_cache,
       debug_zrpc_cache_cmd,
       "debug zrpc cache",
       DEBUG_STR
       ZRPC_STR
       "ZRPC\n")
{
  zrpc_debug |= ZRPC_DEBUG_CACHE;
  return CMD_WARNING;
}

DEFUN (no_debug_zrpc_cache,
       no_debug_zrpc_cache_cmd,
       "no debug zrpc cache",
       NO_STR
       DEBUG_STR
       ZRPC_STR
       "ZRPC\n")
{
  zrpc_debug &= ~ZRPC_DEBUG_CACHE;
  return CMD_SUCCESS;
}

/* Debug node. */
static struct cmd_node debug_node =
{
  DEBUG_NODE,
  "",				/* Debug node has no interface. */
  1
};

static int
config_write_debug (struct vty *vty)
{
  int write = 0;

  if (IS_ZRPC_DEBUG)
    {
      vty_out (vty, "debug zrpc%s", VTY_NEWLINE);
      write++;
    }
  if (IS_ZRPC_DEBUG_NOTIFICATION)
    {
      vty_out (vty, "debug zrpc notification%s", VTY_NEWLINE);
      write++;
    }
  if (IS_ZRPC_DEBUG_NETWORK)
    {
      vty_out (vty, "debug zrpc network%s", VTY_NEWLINE);
      write++;
    }
  if (IS_ZRPC_DEBUG_CACHE)
    {
      vty_out (vty, "debug zrpc cache%s", VTY_NEWLINE);
      write++;
    }
  return write;
}

void
zrpc_debug_reset (void)
{
  zrpc_debug = 0;
}

void
zrpc_debug_init (void)
{
  zrpc_debug = 0;

  install_node (&debug_node, config_write_debug);
  install_element (ENABLE_NODE, &show_debugging_zrpc_cmd);
  install_element (ENABLE_NODE, &debug_zrpc_cmd);
  install_element (ENABLE_NODE, &no_debug_zrpc_cmd);
  install_element (ENABLE_NODE, &debug_zrpc_notification_cmd);
  install_element (ENABLE_NODE, &no_debug_zrpc_notification_cmd);
  install_element (ENABLE_NODE, &debug_zrpc_network_cmd);
  install_element (ENABLE_NODE, &no_debug_zrpc_network_cmd);
  install_element (ENABLE_NODE, &debug_zrpc_cache_cmd);
  install_element (ENABLE_NODE, &no_debug_zrpc_cache_cmd);

  zrpc_debug |= ZRPC_DEBUG_NOTIFICATION;
  zrpc_debug |= ZRPC_DEBUG;
}

void
zrpc_log(const char *format, ...)
{
  time_t t;
  char buffer[50];
  struct tm* tm_info;
  static char dest[1024];
  va_list argptr;

  time (&t);
  tm_info = localtime(&t);
  strftime(buffer, 26, "%Y/%m/%d %H:%M:%S", tm_info);

  va_start(argptr, format);
  vsprintf(dest, format, argptr);
  va_end(argptr);
  fprintf(stderr, "%s ZRPC: %s\r\n", buffer, dest);
}
