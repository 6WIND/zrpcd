/* QZC Client
 * Copyright (c) 2016 6WIND,
 *
 * This file is part of ZRPC daemon.
 *
 * See the LICENSE file.
 */
#include "zrpcd/qzmqclient.h"
#include "thread.h"

#include "zrpcd/zrpc_debug.h"
#include "zrpcd/zrpc_memory.h"
#include "zrpcd/qzcclient.h"
#include "zrpcd/qzcclient.capnp.h"

/* This file local debug flag. */

static struct QZCReply *qzcclient_msg_to_reply(zmq_msg_t *msg);
static struct capn *rc_table_get_entry(void *data, size_t size);
static void rc_table_init();

struct qzcclient_sock {
	void *zmq;
	struct qzmqclient_cb *cb;
	char *path;
	uint32_t limit;
};

#define RC_TABLE_NB_ELEM 50
struct capn rc_table[RC_TABLE_NB_ELEM];
int rc_table_index = 0;
int rc_table_cnt = 0;
int rc_table_index_free = 0;
int rc_table_inited = 0;
int qzcclient_debug = 0;
/*
 * manages capnproto allocations for some routines
 * that need delayed free.
 * this is the case of qzcclient_do routine
 */
static void rc_table_init()
{
  int i=0;

  if(rc_table_inited)
    return;
  for (i=0; i<RC_TABLE_NB_ELEM; i++)
    memset(&rc_table[i], 0, sizeof(struct capn));
  rc_table_inited = 1;
}
/*
 * manages capnproto allocations for some routines
 * that need delayed free.
 * this is the case of qzcclient_do routine
 */
static struct capn *rc_table_get_entry(void *data, size_t size)
{
  struct capn *rc;
  rc = &rc_table[rc_table_index];
  if(data)
    capn_init_mem(rc, data, size, 0);
  else
    capn_init_malloc(rc);
  rc_table_cnt++;
  rc_table_index++;
  if(rc_table_index == RC_TABLE_NB_ELEM)
    {
      rc_table_index = 0;
    }
  if(rc_table_cnt >= RC_TABLE_NB_ELEM)
    {
      capn_free(&rc_table[rc_table_index_free]);
      rc_table_index_free++;
      if(rc_table_index_free == RC_TABLE_NB_ELEM)
        rc_table_index_free = 0;
    }
  return rc;
}

static struct QZCReply *qzcclient_msg_to_reply(zmq_msg_t *msg)
{
  void *data;
  size_t size;
  QZCReply_ptr root;
  struct QZCReply *rep;
  struct capn *ctx;

  data = zmq_msg_data (msg);
  size = zmq_msg_size (msg);

  rep = ZRPC_CALLOC( sizeof(struct QZCReply));
  ctx = rc_table_get_entry(data, size);
  root.p = capn_getp(capn_root(ctx), 0, 1);
  read_QZCReply(rep, root);
  zmq_msg_close(msg);
  return rep;
}

void qzcclient_init (void)
{
  qzmqclient_init ();

  rc_table_init();
}

void qzcclient_close (struct qzcclient_sock *sock)
{
  if(sock->cb)
    qzmqclient_thread_cancel (sock->cb);
  zmq_close (sock->zmq);
  if (sock->path) {
    ZRPC_FREE (sock->path);
    sock->path = NULL;
  }
  ZRPC_FREE( sock);
}

int qzcclient_setsockopt(struct qzcclient_sock *sock, int option,
                         const void *optval, size_t optvallen)
{
  if (!sock || !sock->zmq)
    return 0;

  if (zmq_setsockopt(sock->zmq, option, optval, optvallen))
    {
      zrpc_log ("zmq_setsockopt failed: %s (%d)", strerror (errno), errno);
      return -1;
    }

  return 0;
}

struct qzcclient_sock *qzcclient_connect (const char *url, uint32_t limit)
{
  void *qzc_sock;
  struct qzcclient_sock *ret;

  qzc_sock = zmq_socket (qzmqclient_context, ZMQ_REQ);
  if (!qzc_sock)
    {
      zrpc_log ("zmq_socket failed: %s (%d)", strerror (errno), errno);
      return NULL;
    }

  if (limit)
    zmq_setsockopt (qzc_sock, ZMQ_SNDHWM, &limit, sizeof(limit));

  if (zmq_connect (qzc_sock, url))
    {
      zrpc_log ("zmq_bind failed: %s (%d)", strerror (errno), errno);
      zmq_close (qzc_sock);
      return NULL;
    }
  ret = ZRPC_CALLOC(sizeof(*ret));
  ret->zmq = qzc_sock;
  ret->cb = NULL;
  ret->path = ZRPC_STRDUP (url);
  ret->limit = limit;
  return ret;
}

struct qzcclient_sock *qzcclient_subscribe (struct thread_master *master, const char *url,
                                            void (*func)(void *arg, void *zmqsock,
                                                         struct zmq_msg_t *msg),
                                            uint32_t limit)
{
  void *qzc_sock;
  struct qzcclient_sock *ret;

  qzc_sock = zmq_socket (qzmqclient_context, ZMQ_SUB);

  if (!qzc_sock)
    {
      zrpc_log ("zmq_socket failed: %s (%d)", strerror (errno), errno);
      return NULL;
    }
  if (zmq_connect (qzc_sock, url))
    {
      zrpc_log ("zmq_connect failed: %s (%d)", strerror (errno), errno);
      zmq_close (qzc_sock);
      return NULL;
    }
  if (zmq_setsockopt (qzc_sock, ZMQ_SUBSCRIBE,"",0))
    {
      zrpc_log ("zmq_setsockopt failed: %s (%d)", strerror (errno), errno);
      zmq_close (qzc_sock);
      return NULL;
    }

  if (limit)
    zmq_setsockopt (qzc_sock, ZMQ_RCVHWM, &limit, sizeof(limit));

  ret = ZRPC_CALLOC(sizeof(*ret));
  ret->zmq = qzc_sock;
  ret->cb = qzmqclient_thread_read_msg (master, func, NULL, qzc_sock);
  return ret;
}

/* send QZCrequest and return QZCreply or NULL if timeout */
struct QZCReply *
qzcclient_do(struct qzcclient_sock **p_sock,
             struct QZCRequest *req_ptr)
{
  struct capn *rc;
  struct capn_segment *cs;
  struct QZCRequest *req, rq;
  struct QZCReply *rep;
  QZCRequest_ptr p;
  zmq_msg_t msg;
  uint8_t buf[4096];
  ssize_t rs;
  int ret;
  struct qzcclient_sock *sock;

  if (!p_sock || *p_sock == NULL) {
    zrpc_log ("%s: sock null", __func__);
    return NULL;
  }
  sock = *p_sock;

  rc = rc_table_get_entry(NULL, 0);
  cs = capn_root(rc).seg;
  memset(buf, 0, 4096);
  if(req_ptr == NULL)
    {
      /* ping request */
      memset(&rq, 0, sizeof(struct QZCRequest));
      req = &rq;
    }
  else
    {
      req = req_ptr;
    }
  p = new_QZCRequest(cs);
  write_QZCRequest( req, p);
  capn_setp(capn_root(rc), 0, p.p);
  rs = capn_write_mem(rc, buf, sizeof(buf), 0);

  ret = zmq_send (sock->zmq, buf, rs, 0);
  if (ret < 0)
    {
      zrpc_log ("zmq_send failed: %s (%d)", strerror (errno), errno);
      return NULL;
    }

  if (zmq_msg_init (&msg))
    {
      zrpc_log ("zmq_msg_init failed: %s (%d)", strerror (errno), errno);
      return NULL;
    }
  do
    {
      ret = zmq_msg_recv (&msg, sock->zmq, 0);
      if (ret < 0)
        {
          zrpc_log ("zmq_msg_recv failed: %s (%d)", strerror (errno), errno);
          break;
        }
      if (ret >= 0)
          break;
    }
  while (1);

  if(ret < 0)
    {
      return NULL;
    }
  rep = qzcclient_msg_to_reply(&msg);
  if(rep == NULL)
    {
      if(qzcclient_debug)
        zrpc_log ("qzcclient_send. no message reply");
    }
  if(rep->error)
    {
      zrpc_log ("qzcclient_send. reply message error: (%d)", rep->error);
    }
  return rep;
}

/*
 * qzc client API. send QZCCreateReq
 * and return created node identifier if operation success
 * return 0 if set operation fails
 */
uint64_t
qzcclient_createchild (struct qzcclient_sock **sock,
                       uint64_t *nid, int elem, capn_ptr *p, uint64_t *type_data)

{
  struct QZCRequest req;
  struct QZCReply *rep;
  struct QZCCreateReq creq;
  struct QZCCreateRep crep;
  struct capn rc;
  struct capn_segment *cs;

  capn_init_malloc(&rc);
  cs = capn_root(&rc).seg;
  req.which = QZCRequest_create;
  req.create = new_QZCCreateReq(cs);
  memset(&creq, 0, sizeof(struct QZCCreateReq));
  creq.parentnid = *nid;
  creq.parentelem = elem;
  creq.datatype = *type_data;
  creq.data = *p;
  write_QZCCreateReq(&creq, req.create);
  rep = qzcclient_do(sock, &req);
  if (rep == NULL || rep->error)
    {
      return 0;
    }
  memset(&crep, 0, sizeof(struct QZCCreateRep));
  read_QZCCreateRep(&crep, rep->create);
  if(qzcclient_debug)
    zrpc_log ("CREATE nid:%llx/%d => %llx",(long long unsigned int)*nid, elem, (long long unsigned int)crep.newnid); 
  ZRPC_FREE(rep);
  capn_free(&rc);
  return crep.newnid;
}

/*
 * qzc client API. send a QZCSetReq message
 * return 1 if set operation is successfull
 */
int
qzcclient_setelem (struct qzcclient_sock **sock, uint64_t *nid,
                   int elem, capn_ptr *data, uint64_t *type_data,
                   capn_ptr *ctxt, uint64_t *type_ctxt)
{
  struct capn rc;
  struct capn_segment *cs;
  struct QZCRequest req;
  struct QZCReply *rep;
  struct QZCSetReq sreq;
  struct QZCSetRep *srep;
  int ret = 1;

  /* have to use  local capn_segment - otherwise segfault */
  srep = ZRPC_CALLOC (sizeof (struct QZCSetRep));
  capn_init_malloc(&rc);
  cs = capn_root(&rc).seg;

  req.which = QZCRequest_set;
  req.set = new_QZCSetReq(cs);
  memset(&sreq, 0, sizeof(struct QZCSetReq));
  sreq.nid = *nid;
  sreq.elem = elem;
  sreq.datatype = *type_data;
  sreq.data = *data;
  if(ctxt)
    {
      sreq.ctxdata = *ctxt;
      sreq.ctxtype = *type_ctxt;
    }
  write_QZCSetReq(&sreq, req.set);
  rep = qzcclient_do(sock, &req);
  if (rep == NULL)
    {
      ret = 0;
    }
  else
    {
      read_QZCSetRep (srep, rep->set);
      if (ret)
        {
          read_QZCSetRepReturnCode (&ret, srep->data);
        }
    }
  ZRPC_FREE (srep);
  ZRPC_FREE(rep);
  capn_free(&rc);
  return ret;
}

uint64_t
qzcclient_wkn(struct qzcclient_sock **sock, uint64_t *wkn)
{
  struct QZCRequest req;
  struct QZCWKNResolveReq wknreq;
  struct capn rc;
  struct capn_segment *cs;
  struct QZCReply *rep;
  struct QZCWKNResolveRep wknrep;

  capn_init_malloc(&rc);
  cs = capn_root(&rc).seg;
  req.wknresolve = new_QZCWKNResolveReq(cs);
  req.which = QZCRequest_wknresolve;

  memset(&wknreq, 0, sizeof(wknreq));
  wknreq.wid = *wkn;
  write_QZCWKNResolveReq(&wknreq, req.wknresolve);

  rep = qzcclient_do(sock, &req);
  if (rep == NULL)
    {
      return 0;
    }

  memset(&wknrep, 0, sizeof(wknrep));
  read_QZCWKNResolveRep(&wknrep, rep->wknresolve);
  ZRPC_FREE( rep);
  capn_free(&rc);
  return wknrep.nid;
}

/*
 * qzc client API. send QZCDelRequest
 * return 0 if set operation fails, 1 otherwise.
 */
int
qzcclient_deletenode (struct qzcclient_sock **sock, uint64_t *nid)
{
  struct QZCRequest req;
  struct QZCReply *rep;
  struct QZCDelReq dreq;
  struct capn rc;
  struct capn_segment *cs;
  int ret = 1;

  capn_init_malloc(&rc);
  cs = capn_root(&rc).seg;
  req.which = QZCRequest_del;
  req.del = new_QZCDelReq(cs);
  memset(&dreq, 0, sizeof(struct QZCDelReq));
  dreq.nid = *nid;
  write_QZCDelReq(&dreq, req.del);
  rep = qzcclient_do(sock, &req);
  if (rep == NULL || rep->error)
    ret = 0;
  else
    {
      if(qzcclient_debug)
        zrpc_log ("DELETE nid:%llx",(long long unsigned int)*nid);
    }
  if(rep)
    ZRPC_FREE(rep);
  capn_free(&rc);
  return ret;
}

/*
 * qzc client API. send a QZCGetReq message
 * return NULL if error; QZCGetRep pointer otherwise
 */
struct QZCGetRep *qzcclient_getelem (struct qzcclient_sock **sock, uint64_t *nid,\
                                     int elem, \
                                     capn_ptr *ctxt, uint64_t *ctxt_type, \
                                     capn_ptr *iter, uint64_t *iter_type)
{
  struct capn *rc;
  struct capn_segment *cs;  
  struct QZCRequest req;
  struct QZCReply *rep;
  struct QZCGetReq greq;
  struct QZCGetRep *grep;

  grep = ZRPC_CALLOC(sizeof(struct QZCGetRep));

  /* have to use  local capn_segment - otherwise segfault */
  rc = rc_table_get_entry(NULL, 0);
  cs = capn_root(rc).seg;

  req.which = QZCRequest_get;
  req.get = new_QZCGetReq(cs);
  memset(&greq, 0, sizeof(struct QZCGetReq));
  greq.nid = *nid;
  greq.elem = elem;
  if(ctxt != NULL)
    {
      greq.ctxtype = *ctxt_type;
      greq.ctxdata = *ctxt; 
    }
  if(iter_type)
    {
      if(iter == NULL)
        greq.itertype = 0;
      else
        {
          greq.itertype = *iter_type;
          greq.iterdata = *iter;
        }
    }
  write_QZCGetReq(&greq, req.get);
  rep = qzcclient_do(sock, &req);
  if (rep == NULL)
    {
      return NULL;
    }
  read_QZCGetRep(grep, rep->get);
  ZRPC_FREE(rep);
  if(qzcclient_debug)
    zrpc_log ("GET nid:%llx/%d => %llx",(long long unsigned int)*nid, elem, (long long unsigned int)grep->datatype); 
  return grep;
}

/*
 * qzc client API. send a QZCUnSetReq message
 * return 1 if set operation is successfull
 */
int
qzcclient_unsetelem (struct qzcclient_sock **sock, uint64_t *nid, int elem, \
                     capn_ptr *data, uint64_t *type_data, \
                     capn_ptr *ctxt, uint64_t *type_ctxt)
{
  struct capn rc;
  struct capn_segment *cs;
  struct QZCRequest req;
  struct QZCReply *rep;
  struct QZCSetReq sreq;
  struct QZCSetRep *srep;
  int ret = 1;

  srep = ZRPC_CALLOC (sizeof (struct QZCSetRep));

  /* have to use  local capn_segment - otherwise segfault */
  capn_init_malloc(&rc);
  cs = capn_root(&rc).seg;
  req.which = QZCRequest_unset;
  req.unset = new_QZCSetReq(cs);
  memset(&sreq, 0, sizeof(struct QZCSetReq));
  sreq.nid = *nid;
  sreq.elem = elem;
  sreq.datatype = *type_data;
  sreq.data = *data;
  if(ctxt)
    {
      sreq.ctxdata = *ctxt;
      sreq.ctxtype = *type_ctxt;
    }
  write_QZCSetReq(&sreq, req.unset);
  rep = qzcclient_do(sock, &req);
  if (rep == NULL || rep->error)
    {
      ret = 0;
    }
  read_QZCSetRep (srep, rep->set);
  ZRPC_FREE(rep);
  if (ret)
    {
      read_QZCSetRepReturnCode (&ret, srep->data);
    }
  ZRPC_FREE (srep);
  capn_free(&rc);
  return ret;
}

void
qzcclient_qzcgetrep_free(struct QZCGetRep *rep)
{
  if(rep)
    ZRPC_FREE(rep);
}

void
qzcclient_qzcreply_free(struct QZCReply *rep)
{
  if(rep)
    ZRPC_FREE(rep);

}

capn_ptr 
qzcclient_msg_to_notification(zmq_msg_t *msg, struct capn *rc)
{
  void *data;
  size_t size;

  data = zmq_msg_data (msg);
  size = zmq_msg_size (msg);

  capn_init_mem(rc, data, size, 0);

  return capn_getp(capn_root(rc), 0, 1);
}
