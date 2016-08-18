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

#ifndef P11_TPOOL_H_
#define P11_TPOOL_H_

#include "compat.h"

typedef struct _p11_tpool p11_tpool;

#ifndef P11_DESTROYER_DEFINED
#define P11_DESTROYER_DEFINED

typedef void         (*p11_destroyer)          (void *data);

#endif

typedef void         (*p11_tpool_dispatcher)   (p11_tpool *tpool, void *data);

p11_tpool *          p11_tpool_new             (p11_tpool_dispatcher dispatcher,
						size_t num_threads);

bool                 p11_tpool_push            (p11_tpool *tpool,
						void *data,
						p11_destroyer data_destroy_func,
						p11_destroyer data_cancel_func);

void                 p11_tpool_free            (p11_tpool *tpool,
						bool _wait);

#endif /* P11_TPOOL_H_ */
