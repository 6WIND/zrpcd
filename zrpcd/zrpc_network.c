/* zrpc thrift network interface
 * Copyright (c) 2016 6WIND,
 *
 * This file is part of ZRPC daemon.
 *
 * See the LICENSE file.
 */
#include "thread.h"

#include <glib-object.h>
#include "zrpcd/zrpc_thrift_wrapper.h"
#include "zrpcd/zrpcd.h"
#include "zrpcd/zrpc_debug.h"
#include "zrpcd/zrpc_network.h"
#include "zrpcd/bgp_configurator.h"
#include "zrpcd/bgp_updater.h"
#include "zrpcd/zrpc_bgp_configurator.h"
#include "zrpcd/zrpc_bgp_updater.h"
#include "zrpcd/zrpc_vpnservice.h"

/* zrpc listening socket. */
struct zrpc_listener
{
  /* opaque pointer to zrpc structure */
  void *zrpc;
  struct thread *thread;
  struct zrpc_listener *next;
};

/* Update BGP socket send buffer size */
#define ZRPC_SOCKET_SNDBUF_SIZE    65536

static void
zrpc_update_sock_send_buffer_size (int fd)
{
  int size = ZRPC_SOCKET_SNDBUF_SIZE;
  int optval;
  socklen_t optlen = sizeof(optval);

  if (getsockopt(fd, SOL_SOCKET, SO_SNDBUF, &optval, &optlen) < 0)
    {
      zrpc_log("getsockopt of SO_SNDBUF failed %u\n", errno);
      return;
    }
  if (optval < size)
    {
      if (setsockopt(fd, SOL_SOCKET, SO_SNDBUF, &size, sizeof(size)) < 0)
        {
          zrpc_log("Couldn't increase send buffer: %u\n", errno);
        }
    }
}

/* Accept bgp connection. */
int 
zrpc_accept (struct thread *thread)
{
  struct zrpc_listener *listener = THREAD_ARG(thread);
  struct zrpc_peer *peer;
  GError *error = NULL;
  struct zrpc *zrpc = (struct zrpc *)(listener->zrpc);
  ThriftTransport *transport;
  ThriftSocket *socket;
  struct zrpc_peer *peer_to_parse, *peer_next, *peer_prev;
  socklen_t len;

  /* Register accept thread. */
  if( THREAD_FD (thread) < 0)
    {
      zrpc_log ("accept_sock is negative value %d", THREAD_FD (thread));
      return -1;
    }
  THREAD_OFF(listener->thread);
  THREAD_READ_ON (tm->global, listener->thread, zrpc_accept, listener, THREAD_FD(thread));

  transport = thrift_server_socket_accept(zrpc->zrpc_vpnservice->bgp_configurator_server_transport,
                                          &error);
  if (transport == NULL)
    {
      zrpc_log ("[Error] zrpc server socket accept failed (%u)", errno);
      return -1;
    }
  peer = zrpc_peer_create_accept(zrpc);
  socket = THRIFT_SOCKET (transport);
  peer->fd = socket->sd;
  len = sizeof(struct sockaddr_storage);
  getpeername(peer->fd, (struct sockaddr*)&peer->peerIp, &len);
  zrpc_update_sock_send_buffer_size (socket->sd);
  if(IS_ZRPC_DEBUG){
    char ipstr[INET6_ADDRSTRLEN];
    int port;
    if (peer->peerIp.ss_family == AF_INET) {
      struct sockaddr_in *s = (struct sockaddr_in *)&peer->peerIp;
      port = ntohs(s->sin_port);
      inet_ntop(AF_INET, &s->sin_addr, ipstr, sizeof ipstr);
    } else {
      struct sockaddr_in6 *s = (struct sockaddr_in6 *)&peer->peerIp;
      port = ntohs(s->sin6_port);
      inet_ntop(AF_INET6, &s->sin6_addr, ipstr, sizeof ipstr);
    }
    zrpc_info("zrpc_accept : new connection (fd %d) from %s:%u", socket->sd, ipstr, port);
  }
  //set_nonblocking (socket->sd);
  if (fcntl (socket->sd, F_SETFD, FD_CLOEXEC) == -1)
    zrpc_log ("zrpc_accept : fcntl failed (%s)", strerror (errno));

  peer->peer = ZRPC_CALLOC (sizeof(struct zrpc_vpnservice_client));
  zrpc_vpnservice_setup_client(peer->peer,
                                  zrpc->zrpc_vpnservice,
                                  transport);
  /* run a thread for reading on accepted socket */
  THREAD_READ_ON (tm->global, peer->t_read, zrpc_read_packet, peer, peer->fd);

  /* close previous thrift connections */
  peer_prev = NULL;
  for (peer_to_parse = zrpc->peer; peer_to_parse; peer_to_parse = peer_next)
    {
      peer_next = peer_to_parse->next;
      if (peer == peer_to_parse)
        {
          peer_prev = peer_to_parse;
          continue;
        }
      if (peer->peerIp.ss_family == peer_to_parse->peerIp.ss_family)
        {
          if (peer->peerIp.ss_family == AF_INET)
            {
              struct sockaddr_in *update = (struct sockaddr_in *)&peer->peerIp;
              struct sockaddr_in *orig = (struct sockaddr_in *)&peer_to_parse->peerIp;
              if (update->sin_addr.s_addr == orig->sin_addr.s_addr)
                {
                  zrpc_info("zrpc_accept : a new connection from same src IP. Ignoring it (fd %d)", peer_to_parse->fd);
                  continue;
                }
            } 
          else
            {
              struct sockaddr_in6 *update = (struct sockaddr_in6 *)&peer->peerIp;
              struct sockaddr_in6 *orig = (struct sockaddr_in6 *)&peer_to_parse->peerIp;
              if (0 == memcpy (&(update->sin6_addr), &(orig->sin6_addr), sizeof (struct sockaddr_in6)))
                {
                  zrpc_info("zrpc_accept : a new connection from same src IP. Ignoring it (fd %d)", peer_to_parse->fd);
                  continue;
                }
            }
        }
      break;
    }
  if (peer_to_parse == NULL)
    return 0;
  THREAD_OFF(peer_to_parse->t_read);
  if (peer_prev)
    peer_prev->next = peer_to_parse->next;
  else
    zrpc->peer = peer_to_parse->next;
  if(peer_to_parse->fd)
    {
      if (IS_ZRPC_DEBUG_NETWORK)
        zrpc_log("zrpc_accept : close connection (fd %d)", peer_to_parse->fd);
      zrpc_vpnservice_terminate_client(peer_to_parse->peer);
    }
  ZRPC_FREE(peer_to_parse->peer);
  peer_to_parse->peer = NULL;
  peer_to_parse->fd=0;
  ZRPC_FREE(peer_to_parse);
  return 0;
}

/* BGP read utility function. */
extern int
zrpc_read_packet (struct thread *thread)
{
  GError *error = NULL;
  struct zrpc_peer *peer = THREAD_ARG(thread);
  struct zrpc_peer *peer_to_parse, *peer_next, *peer_prev;

  thrift_dispatch_processor_process (peer->peer->server->processor,      \
                                    peer->peer->protocol,               \
                                    peer->peer->protocol,               \
                                    &error);
  if (error != NULL)
    {
      if(IS_ZRPC_DEBUG)
        zrpc_log("zrpcd_read_packet: close connection (fd %d)", peer->fd);
      g_clear_error (&error);
      zrpc_vpnservice_terminate_client(peer->peer); 
      ZRPC_FREE (peer->peer);
      peer->peer = NULL;
      peer->fd = 0;
      peer_prev = NULL;
      for (peer_to_parse = peer->zrpc->peer; peer_to_parse; peer_to_parse = peer_next)
        {
          peer_next = peer_to_parse->next;
          if (peer_to_parse != peer)
            continue;
          if (peer_prev)
            {
              peer_prev = peer_next;
            }
          else
            {
              peer->zrpc->peer = peer_next;
            }
          peer_to_parse->next = NULL;
          ZRPC_FREE (peer_to_parse);
          peer_prev = peer_to_parse;
          break;
        }
    }
  else 
    {
      peer->t_read = thread_add_read(tm->global, zrpc_read_packet, peer, peer->fd);
    }
  return 0;
}

int
zrpc_server_listen (struct zrpc *zrpc)
{
  struct zrpc_listener *listener;
  GError *error = NULL;
  gboolean ret;

  ret = thrift_server_socket_listen( zrpc->zrpc_vpnservice->bgp_configurator_server_transport, &error);
  if(ret == TRUE)
    {
      ThriftServerSocket *tsocket = \
        THRIFT_SERVER_SOCKET (zrpc->zrpc_vpnservice->bgp_configurator_server_transport);

      if (fcntl (tsocket->sd, F_SETFD, FD_CLOEXEC) == -1)
        zrpc_log ("zrpc_server_listen : fcntl failed (%s)", strerror (errno));

      listener = ZRPC_CALLOC (sizeof(*listener));
      listener->zrpc = zrpc;
      listener->thread = NULL;
      THREAD_READ_ON (tm->global, listener->thread, zrpc_accept, listener, tsocket->sd);
      
      listener->next = tm->listen_sockets;
      tm->listen_sockets = listener;
      return 0;
    }
  zrpc_log("zrpc_server_listen : %s (%d)", error?error->message:"", errno);
  return -1;
}

void
zrpc_close (void)
{
  struct zrpc_listener *listener, *listener_next;
  struct zrpc *zrpc;
  GError *error = NULL;

  for (listener = tm->listen_sockets; listener; listener = listener_next)
    {
      listener_next = listener->next;

      thread_cancel (listener->thread);
      zrpc = listener->zrpc;
      if(zrpc->zrpc_vpnservice->bgp_configurator_server_transport)
        {
          thrift_server_socket_close(zrpc->zrpc_vpnservice->bgp_configurator_server_transport, &error);
          g_object_unref(zrpc->zrpc_vpnservice->bgp_configurator_server_transport);
          zrpc->zrpc_vpnservice->bgp_configurator_server_transport = NULL;
        }
      listener->next = NULL;
      ZRPC_FREE (listener);
    }
  tm->listen_sockets = NULL;
}

void zrpc_server_socket(struct zrpc *zrpc)
{
#if (!GLIB_CHECK_VERSION (2, 36, 0))
  g_type_init ();
#endif
  zrpc_vpnservice_setup_thrift_bgp_configurator_server(zrpc->zrpc_vpnservice);
  return;
}

gboolean zrpc_client_transport_open (ThriftTransport *transport, GError **error, gboolean *needselect)
{
  struct sockaddr_in pin;
  int err;
  ThriftSocket *tsocket = THRIFT_SOCKET (transport);
  struct hostent *hp = NULL;

  if (tsocket->sd != THRIFT_INVALID_SOCKET)
    return FALSE;

  if ((hp = gethostbyname (tsocket->hostname)) == NULL && (err = h_errno))
    {
      /* host lookup failed, bail out with an error */
      g_set_error (error, THRIFT_TRANSPORT_ERROR, THRIFT_TRANSPORT_ERROR_HOST,
                   "host lookup failed for %s:%d - %s",
                   tsocket->hostname, tsocket->port,
                   hstrerror (err));
      return FALSE;
    }

  /* create a socket structure */
  memset (&pin, 0, sizeof(pin));
  pin.sin_family = AF_INET;
  pin.sin_addr.s_addr = ((struct in_addr *) (hp->h_addr))->s_addr;
  pin.sin_port = htons (tsocket->port);
  /* create the socket */
  if ((tsocket->sd = socket (AF_INET, SOCK_STREAM, 0)) == -1)
    {
      g_set_error (error, THRIFT_TRANSPORT_ERROR, THRIFT_TRANSPORT_ERROR_SOCKET,
                   "failed to create socket for host %s:%d - %s",
                   tsocket->hostname, tsocket->port,
                   strerror(errno));
      return FALSE;
    }

  /* set non blocking */
  set_nonblocking (tsocket->sd);
  /* open a connection */
  if (connect (tsocket->sd, (struct sockaddr *) &pin, sizeof(pin)) == -1)
    {
      if (errno == EINPROGRESS)
        {
          *needselect = TRUE;
        }
      g_set_error (error, THRIFT_TRANSPORT_ERROR, THRIFT_TRANSPORT_ERROR_CONNECT,
                   "failed to connect to host %s:%d - %s",
                   tsocket->hostname, tsocket->port, strerror(errno));
      return FALSE;
    }

  return TRUE;
}

void zrpc_client_transport_close(ThriftTransport *transport)
{
  ThriftSocket *tsocket = NULL;

  if (!transport)
    return;
  tsocket = THRIFT_SOCKET (transport);
  zrpc_log ("trying to close socket %u", tsocket->sd);
  if (tsocket && tsocket->sd != THRIFT_INVALID_SOCKET)
    {
      zrpc_log ("closing socket %u", tsocket->sd);
      close (tsocket->sd);
    }
  tsocket->sd = THRIFT_INVALID_SOCKET;
}
