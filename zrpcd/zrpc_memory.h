/* zrpcd memory type declarations
 * Copyright (c) 2016 6WIND,
 *
 * This file is part of ZRPC daemon.
 *
 * See the LICENSE file.
 */

#ifndef _ZRPCD_MEMORY_H
#define _ZRPCD_MEMORY_H

#include <stdlib.h>
#include <string.h>

#define ZRPC_STRDUP(_size) strdup(_size)
#define ZRPC_MALLOC(_size) malloc(_size)
#define ZRPC_CALLOC(_size) calloc(1, _size)
#define ZRPC_FREE(_ptr) free(_ptr)

#endif /* _ZRPCD_MEMORY_H */
