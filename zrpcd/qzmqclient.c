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
#include "workqueue.h"
#include "linklist.h"

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

static int qzmqclient_read_msg (struct thread *t)
{
  struct qzmqclient_cb *cb = THREAD_ARG (t);
  struct zmq_msg_queue_node *node = NULL;
  int ret;
  struct qzcclient_sock *ctxt;

  ctxt = cb->zmqsock;
  cb->thread = NULL;

  while (1)
    {
      zmq_pollitem_t polli = { .socket = ctxt->zmq, .events = ZMQ_POLLIN};
      ret = zmq_poll (&polli, 1, 0);

      if (ret < 0)
        goto out_err;
      if (!(polli.revents & ZMQ_POLLIN))
        break;

      node = ZRPC_CALLOC (sizeof(struct zmq_msg_queue_node));
      if (!node)
        goto out_err;
      node->msg = ZRPC_CALLOC (sizeof(zmq_msg_t));
      if (!node->msg)
        goto out_err;

      node->cb = cb;
      node->retry_times = 0;
      if (zmq_msg_init (node->msg))
        goto out_err;
      ret = zmq_msg_recv (node->msg, ctxt->zmq, ZMQ_NOBLOCK);
      if (ret < 0)
        {
          if (errno == EAGAIN)
            break;

          zmq_msg_close (node->msg);
          goto out_err;
        }
#if 0
      cb->cb_msg (cb->arg, ctxt, node->msg);
      zmq_msg_close (node->msg);
#else
      if (cb->queue_size == 0)
        work_queue_add (cb->process_zmq_msg_queue, node);
      else if (listcount (cb->process_zmq_msg_queue->items) < cb->queue_size)
        work_queue_add (cb->process_zmq_msg_queue, node);
      else
        {
          zrpc_log ("BGP updater message queue limit(%u) reached, message ignored", cb->queue_size);
          zmq_msg_close (node->msg);
          ZRPC_FREE (node->msg);
          ZRPC_FREE (node);
        }
#endif
    }

  /* update ctxt if necessary */
  t->u.fd = ctxt->fd;
  cb->thread = funcname_thread_add_read (t->master, qzmqclient_read_msg, cb,
                                         t->u.fd, t->funcname, t->schedfrom, t->schedfrom_line);
  return 0;

out_err:
  if (node)
    ZRPC_FREE (node);
  zrpc_log ("ZeroMQ error: %s(%d)", strerror (errno), errno);
  return 0;
}

static wq_item_status
process_zmq_msg (struct work_queue *wq, void *data)
{
  struct zmq_msg_queue_node *node = data;
  struct qzmqclient_cb *cb = node->cb;
  struct qzcclient_sock *ctxt = cb->zmqsock;

  cb->cb_msg (cb->arg, ctxt, node);

  if (node->msg_not_sent)
    {
      zrpc_log ("process_zmq_msg: msg not sent, should retry later");
      return WQ_RETRY_LATER;
    }
  return WQ_SUCCESS;
}

static void
process_zmq_msg_del (struct work_queue *wq, void *data)
{
  struct zmq_msg_queue_node *node = data;

  zmq_msg_close (node->msg);
  ZRPC_FREE (node->msg);
  ZRPC_FREE (node);
  return;
}

struct qzmqclient_cb *funcname_qzmqclient_thread_read_msg (
        struct thread_master *master,
        void (*func)(void *arg, void *zmqsock, struct zmq_msg_queue_node *node),
        void *arg, void *zmqsock, debugargdef)
{
  int fd;
  size_t fd_len = sizeof (fd);
  struct qzmqclient_cb *cb;
  struct qzcclient_sock *ctxt = zmqsock;

  if (zmq_getsockopt (ctxt->zmq, ZMQ_FD, &fd, &fd_len))
   return NULL;
  ctxt->fd = fd;

  cb = ZRPC_CALLOC (sizeof (struct qzmqclient_cb));
  if (!cb)
    return NULL;

  cb->arg = arg;
  cb->zmqsock = zmqsock;
  cb->cb_msg = func;
  cb->process_zmq_msg_queue = work_queue_new (master, "process_zmq_msg_queue");
  cb->process_zmq_msg_queue->spec.workfunc = &process_zmq_msg;
  cb->process_zmq_msg_queue->spec.del_item_data = &process_zmq_msg_del;
  cb->thread = funcname_thread_add_read (master, qzmqclient_read_msg, cb, fd,
                                         funcname, schedfrom, fromln);
  return cb;
}

void qzmqclient_thread_cancel (struct qzmqclient_cb *cb)
{
  if (cb->process_zmq_msg_queue)
    {
      work_queue_free (cb->process_zmq_msg_queue);
      cb->process_zmq_msg_queue = NULL;
    }
  if (cb->thread) {
    thread_cancel (cb->thread);
    ZRPC_FREE (cb);
  }
}
