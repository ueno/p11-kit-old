/*
 * Copyright (c) 2016 Red Hat Inc.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *
 *     * Redistributions of source code must retain the above
 *       copyright notice, this list of conditions and the
 *       following disclaimer.
 *     * Redistributions in binary form must reproduce the
 *       above copyright notice, this list of conditions and
 *       the following disclaimer in the documentation and/or
 *       other materials provided with the distribution.
 *     * The names of contributors to this software may not be
 *       used to endorse or promote products derived from this
 *       software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 * "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 * LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS
 * FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE
 * COPYRIGHT OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT,
 * INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING,
 * BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS
 * OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED
 * AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY,
 * OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF
 * THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH
 * DAMAGE.
 *
 * Author: Daiki Ueno <dueno@redhat.com>
 */

#include "config.h"

#include "debug.h"
#include "rpc.h"
#include "rpc-message.h"
#include "tpool.h"

#include <stdlib.h>
#include <string.h>

struct _p11_rpc_async_call {
	p11_rpc_async_server *server;
	p11_buffer buffer;
	uint32_t serial;
	p11_rpc_async_call_ready ready;
	void *data;
	p11_destroyer data_destroy;
};

struct _p11_rpc_async_server {
	p11_virtual virt;
	uint32_t serial;
	p11_tpool *tpool;
};

#define P11_RPC_ASYNC_SERVER_MAX_THREADS 10

static void
async_server_handle_call (p11_tpool *tpool, void *data)
{
	p11_rpc_async_call *call = data;
	p11_rpc_async_server *server = call->server;
	p11_rpc_status status;

	if (p11_rpc_server_handle (&server->virt.funcs,
				   &call->buffer,
				   &call->buffer))
		status = P11_RPC_OK;
	else
		status = P11_RPC_ERROR;

	call->ready (call, status, call->data);
}

p11_rpc_async_server *
p11_rpc_async_server_new (CK_FUNCTION_LIST *module)
{
	p11_rpc_async_server *server;

	server = calloc (1, sizeof (p11_rpc_async_server));
	return_val_if_fail (server != NULL, NULL);

	p11_virtual_init (&server->virt, &p11_virtual_base, module, NULL);

	server->serial = 1;

	server->tpool = p11_tpool_new (async_server_handle_call,
				       P11_RPC_ASYNC_SERVER_MAX_THREADS);
	return_val_if_fail (server->tpool != NULL, NULL);

	return server;
}

void
p11_rpc_async_server_free (p11_rpc_async_server *server)
{
	if (server->tpool)
		p11_tpool_free (server->tpool, false);

	p11_virtual_uninit (&server->virt);
}

p11_rpc_async_call *
p11_rpc_async_call_new (p11_rpc_async_server *server,
			p11_buffer *request,
			p11_rpc_async_call_ready ready,
			void *data,
			p11_destroyer data_destroy)
{
	p11_rpc_async_call *call;

	call = calloc (1, sizeof (p11_rpc_async_call));
	return_val_if_fail (call != NULL, NULL);

	call->server = server;

	if (!p11_buffer_init (&call->buffer, request->size))
		return_val_if_reached (NULL);
	p11_buffer_add (&call->buffer, request->data, request->len);

	call->serial = server->serial++;

	call->ready = ready;
	call->data = data;
	call->data_destroy = data_destroy;

	return call;
}

void
p11_rpc_async_call_free (p11_rpc_async_call *call)
{
	p11_buffer_uninit (&call->buffer);
	if (call->data_destroy)
		call->data_destroy (call->data);
	free (call);
}

bool
p11_rpc_async_call_invoke (p11_rpc_async_call *call)
{
	p11_rpc_async_server *server = call->server;

	return p11_tpool_push (server->tpool, call, NULL, NULL);
}

uint32_t
p11_rpc_async_call_get_serial (p11_rpc_async_call *call)
{
	return call->serial;
}

void
p11_rpc_async_call_steal_output (p11_rpc_async_call *call,
				 p11_buffer *buffer)
{
	p11_buffer_reset (buffer, call->buffer.len);
	p11_buffer_add (buffer, call->buffer.data, call->buffer.len);
}
