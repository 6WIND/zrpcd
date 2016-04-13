/* zrpc thrift BGP Configurator Server Part
 * Copyright (c) 2016 6WIND,
 *
 * This file is part of ZRPC daemon.
 *
 * See the LICENSE file.
 */
#ifndef _ZRPC_BGP_CONFIGURATOR_H
#define _ZRPC_BGP_CONFIGURATOR_H

G_BEGIN_DECLS

void zrpc_bgp_configurator_server_terminate(void);

#define TYPE_INSTANCE_BGP_CONFIGURATOR_HANDLER \
  (instance_bgp_configurator_handler_get_type())

#define INSTANCE_BGP_CONFIGURATOR_HANDLER(obj)  \
  (G_TYPE_CHECK_INSTANCE_CAST ((obj),     \
    TYPE_BGP_CONFIGURATOR_HANDLER,\
    InstanceBgpConfiguratorHandler))

#define INSTANCE_BGP_CONFIGURATOR_HANDLER_CLASS(c) \
  (G_TYPE_CHECK_CLASS_CAST ((c),             \
    TYPE_INSTANCE_BGP_CONFIGURATOR_HANDLER,   \
     InstanceBgpConfiguratorHandlerClass))

#define IS_INSTANCE_BGP_CONFIGURATOR_HANDLER(obj)  \
  (G_TYPE_CHECK_INSTANCE_TYPE ((obj),        \
    TYPE_INSTANCE_BGP_CONFIGURATOR_HANDLER))

#define IS_INSTANCE_BGP_CONFIGURATOR_HANDLER_CLASS(c)  \
  (G_TYPE_CHECK_CLASS_TYPE ((c),                 \
    TYPE_INSTANCE_BGP_CONFIGURATOR_HANDLER))

#define INSTANCE_BGP_CONFIGURATOR_HANDLER_GET_CLASS(obj)   \
  (G_TYPE_INSTANCE_GET_CLASS ((obj),                 \
    TYPE_INSTANCE_BGP_CONFIGURATOR_HANDLER, \
    InstanceBgpConfiguratorHandlerClass))

struct _InstanceBgpConfiguratorHandler {
  BgpConfiguratorHandler parent_instance;
};
typedef struct _InstanceBgpConfiguratorHandler InstanceBgpConfiguratorHandler;
  
struct _InstanceBgpConfiguratorHandlerClass {
  BgpConfiguratorHandlerClass parent_class;
};
typedef struct _InstanceBgpConfiguratorHandlerClass InstanceBgpConfiguratorHandlerClass;

GType instance_bgp_configurator_handler_get_type (void);

G_END_DECLS

#endif /*  _ZRPC_BGP_CONFIGURATOR_H */
