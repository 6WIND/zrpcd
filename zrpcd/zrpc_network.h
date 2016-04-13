/* zrpc thrift network interface
 * Copyright (c) 2016 6WIND,
 *
 * This file is part of ZRPC daemon.
 *
 * See the LICENSE file.
 */
#ifndef _ZRPC_NETWORK_H
#define _ZRPC_NETWORK_H

extern void zrpc_server_socket (struct zrpc *zrpc);
extern int zrpc_server_listen (struct zrpc *zrpc);
extern void zrpc_close (void);
extern int zrpc_connect (struct zrpc_peer *);
extern void zrpc_getsockname (struct zrpc_peer *);
extern int zrpc_accept (struct thread *thread);
extern int zrpc_read_packet (struct thread *thread);

#endif /* _ZRPC_NETWORK_H */
