/* zrpc debug routines
 * Copyright (c) 2016 6WIND,
 *
 * This file is part of ZRPC daemon.
 *
 * See the LICENSE file.
 */

#ifndef _ZRPC_DEBUG_H
#define _ZRPC_DEBUG_H

/* THRIFT debug event flags. */
#define ZRPC_DEBUG               0x01
#define ZRPC_DEBUG_NOTIFICATION  0x02
#define ZRPC_DEBUG_NETWORK       0x04
#define ZRPC_DEBUG_CACHE         0x08

/* Debug related macro. */
#define IS_ZRPC_DEBUG  (zrpc_debug & ZRPC_DEBUG)
#define IS_ZRPC_DEBUG_NOTIFICATION  (zrpc_debug & ZRPC_DEBUG_NOTIFICATION)
#define IS_ZRPC_DEBUG_NETWORK (zrpc_debug & ZRPC_DEBUG_NETWORK)
#define IS_ZRPC_DEBUG_CACHE  (zrpc_debug & ZRPC_DEBUG_CACHE)

extern void zrpc_log (const char *format, ...);
extern void zrpc_info (const char *format, ...);

extern unsigned long zrpc_debug;

extern void zrpc_debug_init (void);
extern void zrpc_debug_reset (void);
extern void
zrpc_debug_set_log_with_level (char *logFileName, char *logLevel);
extern void
zrpc_debug_configure_stdout (int on);
extern void
zrpc_debug_configure_syslog (int on);
extern void
zrpc_debug_flush (void);



#endif /* _ZRPC_DEBUG_H */
