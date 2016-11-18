/*
 * libzebra ZeroMQ bindings
 * Copyright (c) 2016 6WIND,
 *
 * This file is part of ZRPC daemon.
 *
 * See the LICENSE file.
 */
#include <zmq.h>

#include "thread.h"
#include "zrpcd/zrpc_memory.h"
#include "zrpcd/zrpc_debug.h"
#include "zrpcd/qzmqclient.h"

/* libzmq's context */
void *qzmqclient_context = NULL;

void qzmqclient_init (void)
{
  qzmqclient_context = zmq_ctx_new ();
  zmq_ctx_set (qzmqclient_context, ZMQ_IPV6, 1);
}

void qzmqclient_finish (void)
{
  zmq_ctx_term (qzmqclient_context);
  qzmqclient_context = NULL;
}

/* read callback integration */
struct qzmqclient_cb {
  struct thread *thread;
  void *zmqsock;
  void *arg;
  void (*cb_msg)(void *arg, void *zmqsock, zmq_msg_t *msg);
};


static int qzmqclient_read_msg (struct thread *t)
{
  struct qzmqclient_cb *cb = THREAD_ARG (t);
  zmq_msg_t msg;
  int ret;

  cb->thread = NULL;

  while (1)
    {
      zmq_pollitem_t polli = { .socket = cb->zmqsock, .events = ZMQ_POLLIN, .revents = 0 };
      ret = zmq_poll (&polli, 1, 0);

      if (ret < 0)
        goto out_err;
      if (!(polli.revents & ZMQ_POLLIN))
        break;

      if (zmq_msg_init (&msg))
        goto out_err;
      ret = zmq_msg_recv (&msg, cb->zmqsock, ZMQ_NOBLOCK);
      if (ret < 0)
        {
          if (errno == EAGAIN)
            break;

          zmq_msg_close (&msg);
          goto out_err;
        }
      cb->cb_msg (cb->arg, cb->zmqsock, &msg);
      zmq_msg_close (&msg);
    }

  cb->thread = funcname_thread_add_read (t->master, qzmqclient_read_msg, cb,
                                         t->u.fd, t->funcname, t->schedfrom, t->schedfrom_line);
  return 0;

out_err:
  zrpc_log ("ZeroMQ error: %s(%d)", strerror (errno), errno);
  return 0;
}

struct qzmqclient_cb *funcname_qzmqclient_thread_read_msg (
        struct thread_master *master,
        void (*func)(void *arg, void *zmqsock, zmq_msg_t *msg),
        void *arg, void *zmqsock, debugargdef)
{
  int fd;
  size_t fd_len = sizeof (fd);
  struct qzmqclient_cb *cb;

  if (zmq_getsockopt (zmqsock, ZMQ_FD, &fd, &fd_len))
   return NULL;
 cb = ZRPC_CALLOC (sizeof (struct qzmqclient_cb));
  if (!cb)
    return NULL;

  cb->arg = arg;
  cb->zmqsock = zmqsock;
  cb->cb_msg = func;
  cb->thread = funcname_thread_add_read (master, qzmqclient_read_msg, cb, fd,
                                         funcname, schedfrom, fromln);
  return cb;
}

void qzmqclient_thread_cancel (struct qzmqclient_cb *cb)
{
  thread_cancel (cb->thread);
  ZRPC_FREE (cb);
}
