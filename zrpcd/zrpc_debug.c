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

#include "zrpcd/zrpc_debug.h"

/* For debug statement. */
unsigned long zrpc_debug = 0;

void
zrpc_debug_reset (void)
{
  zrpc_debug = 0;
}

void
zrpc_debug_init (void)
{
  zrpc_debug = 0;

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
