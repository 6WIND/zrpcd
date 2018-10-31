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
#include <zmq.h>

/* libzmq's context */
extern void *qzmqclient_context;

extern void qzmqclient_init (void);
extern void qzmqclient_finish (void);

#define debugargdef const char *funcname, const char *schedfrom, int fromln

#define qzmqclient_thread_read_msg(m,f,a,z) funcname_qzmqclient_thread_read_msg( \
                             m,f,a,z,#f,__FILE__,__LINE__)

struct qzmqclient_cb;

struct qzcclient_sock {
	void *zmq;
	struct qzmqclient_cb *cb;
	char *path;
	uint32_t limit;
        int fd;
};

extern struct qzmqclient_cb *funcname_qzmqclient_thread_read_msg (
        struct thread_master *master,
        void (*func)(void *arg, void *zmqsock, zmq_msg_t *msg),
        void *arg, void *zmqsock, debugargdef);

extern void qzmqclient_thread_cancel (struct qzmqclient_cb *cb);

#endif
