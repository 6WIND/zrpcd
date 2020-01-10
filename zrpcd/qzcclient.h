/* QZC Client
 * Copyright (c) 2016 6WIND,
 *
 * This file is part of ZRPC daemon.
 *
 * See the LICENSE file.
 */
#ifndef _QZCCLIENT_H
#define _QZCCLIENT_H

#include <stdint.h>
#include <stdlib.h>
#include <stddef.h>

#include <zmq.h>
#include "thread.h"
#include "zrpcd/qzcclient.capnp.h"
#include "zrpcd/qzmqclient.h"

struct qzcclient_sock;

void qzcclient_init(void);

void qzcclient_close(struct qzcclient_sock *sock);

int qzcclient_setsockopt(struct qzcclient_sock *sock, int option,
                         const void *optval, size_t optvallen);

capn_ptr 
qzcclient_msg_to_notification(zmq_msg_t *msg, struct capn *rc);

#define QZC_CLIENT_ZMQ_LIMIT_TX     1500000
#define QZC_CLIENT_ZMQ_LIMIT_RX     1500000
struct qzcclient_sock *qzcclient_connect (const char *url, uint32_t limit);
struct qzcclient_sock *qzcclient_subscribe (struct thread_master *master, const char *url,
                                            void (*func)(void *arg, void *zmqsock,
                                                         struct zmq_msg_queue_node *node),
                                            void *bgp_updater,
                                            uint32_t limit);
struct QZCReply *qzcclient_do(struct qzcclient_sock **sock,
                              struct QZCRequest *req_ptr);
uint64_t
qzcclient_wkn(struct qzcclient_sock **sock, uint64_t *wkn);

uint64_t
qzcclient_createchild (struct qzcclient_sock **sock,
                       uint64_t *nid, int elem,
                       capn_ptr *p, uint64_t *dtypeid);

int
qzcclient_setelem (struct qzcclient_sock **sock, uint64_t *nid,
                   int elem, capn_ptr *data, uint64_t *type_data,
                   capn_ptr *ctxt, uint64_t *type_ctxt);

int
qzcclient_deletenode (struct qzcclient_sock **sock, uint64_t *nid);

struct QZCGetRep *qzcclient_getelem (struct qzcclient_sock **sock, uint64_t *nid,\
                                     int elem, \
                                     capn_ptr *ctxt, uint64_t *ctxt_type,\
                                     capn_ptr *iter, uint64_t *iter_type);

int
qzcclient_unsetelem (struct qzcclient_sock **sock, uint64_t *nid, int elem, \
                     capn_ptr *data, uint64_t *type_data, \
                     capn_ptr *ctxt, uint64_t *type_ctxt);

void
qzcclient_qzcreply_free(struct QZCReply *rep);

void
qzcclient_qzcgetrep_free(struct QZCGetRep *rep);

void qzcclient_configure_simulation_delay (unsigned int delay,
                                           unsigned int occurence);
#define QZC_SOCKET_SIZE_USER 200000
extern int qzcclient_get_nb_reconnect(void);

#endif /* _QZCCLIENT_H */
