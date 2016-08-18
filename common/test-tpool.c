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

#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>

#include "tpool.h"
#include "test.h"

struct _test_item {
	int duration;
	int value;
	bool cancelled;
};

static void
dispatcher (p11_tpool *tpool, void *data)
{
	struct _test_item *item = data;
	p11_sleep_ms (item->duration);
	item->value++;
}

static void
test_create (void)
{
	p11_tpool *tpool;

	tpool = p11_tpool_new (dispatcher, 10);
	assert (tpool != NULL);

	p11_tpool_free (tpool, false);
}

static void
test_push (void)
{
	p11_tpool *tpool;
	struct _test_item *item1, *item2;

	tpool = p11_tpool_new (dispatcher, 10);
	assert_ptr_not_null (tpool);

	item1 = calloc (1, sizeof (struct _test_item));
	assert_ptr_not_null (item1);
	item1->duration = 100;
	p11_tpool_push (tpool, item1, NULL, NULL);

	item2 = calloc (1, sizeof (struct _test_item));
	assert_ptr_not_null (item2);
	item2->duration = 200;
	p11_tpool_push (tpool, item2, NULL, NULL);

	p11_tpool_free (tpool, true);

	assert_num_eq (false, item1->cancelled);
	assert_num_eq (false, item2->cancelled);

	assert_num_eq (1, item1->value);
	assert_num_eq (1, item2->value);

	free (item1);
	free (item2);
}

int
main (int argc,
      char *argv[])
{
	p11_test (test_create, "/tpool/create");
	p11_test (test_push, "/tpool/push");
	return p11_test_run (argc, argv);
}
