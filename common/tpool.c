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

#include <assert.h>
#include <errno.h>
#include <pthread.h>
#include <stdlib.h>

#include "tpool.h"

struct _p11_tpool_task
{
	p11_tpool *tpool;
	void *data;
	p11_destroyer destroyer;
	p11_destroyer canceller;
	struct _p11_tpool_task *next;
};

struct _p11_tpool_task_queue
{
	pthread_mutex_t lock;
	pthread_cond_t cond;
	bool running;
	struct _p11_tpool_task *head;
	struct _p11_tpool_task *tail;
};

struct _p11_tpool
{
	pthread_t *threads;
	size_t num_threads;
	pthread_mutex_t startup_lock;
	pthread_cond_t startup_cond;
	size_t num_started;

	pthread_mutex_t wait_lock;
	pthread_cond_t wait_cond;

	p11_tpool_dispatcher dispatcher;
	struct _p11_tpool_task_queue queue;
};

static void
_p11_tpool_task_free (struct _p11_tpool_task *task)
{
	if (task && task->destroyer)
		task->destroyer (task->data);
	free (task);
}

static void
_p11_tpool_task_queue_init (struct _p11_tpool_task_queue *queue)
{
	pthread_mutex_init (&queue->lock, NULL);
	pthread_cond_init (&queue->cond, NULL);

	queue->head = queue->tail = NULL;
	queue->running = true;
}

static bool
_p11_tpool_task_queue_push (struct _p11_tpool_task_queue *queue,
			    struct _p11_tpool_task *task)
{
	pthread_mutex_lock (&queue->lock);

	if (!queue->running) {
		pthread_mutex_unlock (&queue->lock);
		return_val_if_reached (false);
	}

	task->next = NULL;
	if (queue->head == NULL)
		queue->head = queue->tail = task;
	else {
		assert (queue->tail != NULL);
		queue->tail->next = task;
		queue->tail = task;
	}

	pthread_cond_signal (&queue->cond);

	pthread_mutex_unlock (&queue->lock);

	return true;
}

static struct _p11_tpool_task *
_p11_tpool_task_queue_pop (struct _p11_tpool_task_queue *queue)
{
	struct _p11_tpool_task *task = NULL;

	pthread_mutex_lock (&queue->lock);

	while (queue->head == NULL && queue->running)
		pthread_cond_wait (&queue->cond, &queue->lock);

	if (queue->head != NULL) {
		task = queue->head;
		queue->head = queue->head->next;
	}

	pthread_mutex_unlock (&queue->lock);

	return task;
}

static void *
_p11_tpool_dispatch (void *data)
{
	p11_tpool *tpool = data;
	struct _p11_tpool_task_queue *queue = &tpool->queue;
	struct _p11_tpool_task *task;

	pthread_mutex_lock (&tpool->startup_lock);
	tpool->num_started++;
	pthread_cond_signal (&tpool->startup_cond);
	pthread_mutex_unlock (&tpool->startup_lock);

	while (queue->running) {
		task = _p11_tpool_task_queue_pop (queue);
		if (task == NULL)
			break;

		tpool->dispatcher (tpool, task->data);
		_p11_tpool_task_free (task);

		pthread_mutex_lock (&tpool->wait_lock);
		pthread_cond_signal (&tpool->wait_cond);
		pthread_mutex_unlock (&tpool->wait_lock);
	}

	return NULL;
}

p11_tpool *
p11_tpool_new (p11_tpool_dispatcher dispatcher, size_t num_threads)
{
	p11_tpool *tpool = NULL;
	size_t i;
	int retval;

	tpool = calloc (1, sizeof (p11_tpool));
	if (tpool == NULL) {
		errno = ENOMEM;
		goto fail;
	}

	_p11_tpool_task_queue_init (&tpool->queue);

	tpool->dispatcher = dispatcher;
	tpool->threads = calloc (num_threads, sizeof (pthread_t));
	if (tpool->threads == NULL) {
		errno = ENOMEM;
		goto fail;
	}
	tpool->num_threads = num_threads;

	pthread_mutex_init (&tpool->startup_lock, NULL);
	pthread_cond_init (&tpool->startup_cond, NULL);

	for (i = 0; i < num_threads; i++) {
		retval = pthread_create (&tpool->threads[i],
					 NULL,
					 _p11_tpool_dispatch,
					 tpool);
		if (retval != 0) {
			errno = retval;
			goto fail;
		}
	}

	pthread_mutex_init (&tpool->wait_lock, NULL);
	pthread_cond_init (&tpool->wait_cond, NULL);

	return tpool;

 fail:
	free (tpool->threads);
	free (tpool);

	return NULL;
}

bool
p11_tpool_push (p11_tpool *tpool,
                void *data,
		p11_destroyer data_destroy_func,
		p11_destroyer data_cancel_func)
{
	struct _p11_tpool_task *task;

	task = calloc (1, sizeof (struct _p11_tpool_task));
	if (task == NULL) {
		errno = ENOMEM;
		return_val_if_reached (false);
	}
	task->data = data;
	task->destroyer = data_destroy_func;
	task->canceller = data_cancel_func;

	return _p11_tpool_task_queue_push (&tpool->queue, task);
}

static void
_p11_tpool_wait (p11_tpool *tpool)
{
	struct _p11_tpool_task_queue *queue = &tpool->queue;

	pthread_mutex_lock (&tpool->startup_lock);
	while (tpool->num_started < tpool->num_threads) {
		pthread_cond_wait (&tpool->startup_cond,
				   &tpool->startup_lock);
	}
	pthread_mutex_unlock (&tpool->startup_lock);

	pthread_mutex_lock (&tpool->wait_lock);
	while (queue->head != NULL)
		pthread_cond_wait (&tpool->wait_cond, &tpool->wait_lock);
	pthread_mutex_unlock (&tpool->wait_lock);
}

void
p11_tpool_free (p11_tpool *tpool, bool _wait)
{
	struct _p11_tpool_task_queue *queue = &tpool->queue;
	struct _p11_tpool_task *head, *next;
	size_t i;

	if (_wait)
		_p11_tpool_wait (tpool);

	pthread_mutex_lock (&queue->lock);
	queue->running = false;
	pthread_cond_broadcast (&queue->cond);
	pthread_mutex_unlock (&queue->lock);

	for (i = 0; i < tpool->num_threads; i++)
		pthread_join (tpool->threads[i], NULL);

	for (head = queue->head; head; head = next) {
		next = head->next;
		if (head->canceller)
			head->canceller (head->data);
		_p11_tpool_task_free (head);
	}

	pthread_mutex_destroy (&tpool->startup_lock);
	pthread_cond_destroy (&tpool->startup_cond);

	pthread_mutex_destroy (&tpool->wait_lock);
	pthread_cond_destroy (&tpool->wait_cond);

	pthread_mutex_destroy (&queue->lock);
	pthread_cond_destroy (&queue->cond);

	free (tpool->threads);
	free (tpool);
}
