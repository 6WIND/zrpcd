/*
 * libzebra ZeroMQ bindings
 * Copyright (c) 2016 6WIND,
 *
 * This file is part of ZRPC daemon.
 *
 * See the LICENSE file.
 */
#ifndef _QUAGGA_QZMQCLIENT_H
#define _QUAGGA_QZMQCLIENT_H

#include "thread.h"
#ifdef HAVE_THRIFT_V6
#include "workqueue.h"
#endif
#include <zmq.h>

/* libzmq's context */
extern void *qzmqclient_context;

extern void qzmqclient_init (void);
extern void qzmqclient_finish (void);

#define debugargdef const char *funcname, const char *schedfrom, int fromln

#define qzmqclient_thread_read_msg(m,f,a,z) funcname_qzmqclient_thread_read_msg( \
                             m,f,a,z,#f,__FILE__,__LINE__)

#define DEFAULT_UPDATE_RETRY_TIMES 5
#define DEFAULT_UPDATE_RETRY_TIME_GAP 100 /* millisecond */

struct zmq_msg_queue_node
{
  zmq_msg_t *msg;
  struct qzmqclient_cb *cb;
#ifdef HAVE_THRIFT_V6
  unsigned short retry_times;	/* times to send this msg */
  int msg_not_sent;
#endif
};

/* read callback integration */
struct qzmqclient_cb {
  struct thread *thread;
  void *zmqsock;
  void *arg;
  void (*cb_msg)(void *arg, void *zmqsock, struct zmq_msg_queue_node *node);
#ifdef HAVE_THRIFT_V6
  /* work queues */
  struct work_queue *process_zmq_msg_queue;
#endif
};

struct qzcclient_sock {
	void *zmq;
	struct qzmqclient_cb *cb;
	char *path;
	uint32_t limit;
        int fd;
};

extern struct qzmqclient_cb *funcname_qzmqclient_thread_read_msg (
        struct thread_master *master,
        void (*func)(void *arg, void *zmqsock, struct zmq_msg_queue_node *node),
        void *arg, void *zmqsock, debugargdef);

extern void qzmqclient_thread_cancel (struct qzmqclient_cb *cb);

#endif
