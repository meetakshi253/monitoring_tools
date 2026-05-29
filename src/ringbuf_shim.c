/* SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause) */
/* Copyright (c) 2026 Microsoft
 *
 * ringbuf_shim — thin C wrapper around libbpf ring_buffer for bulk
 * consumption from Python via ctypes.  Compiled as libringbuf_shim.so.
 *
 * Instead of calling a Python callback for every event (expensive FFI
 * crossing), the C callback memcpy's events directly into a caller-
 * provided buffer (e.g. a numpy array).  Python gets the batch with
 * zero extra copies.
 */

#include <stdlib.h>
#include <string.h>
#include <bpf/libbpf.h>
#include <bpf/bpf.h>
#include "aod_diag.h"

struct rb_context {
	struct ring_buffer *rb;
	void *ext_buf;        /* caller-owned buffer, set per poll call */
	int ext_capacity;     /* max events that fit in ext_buf         */
	int count;            /* events written so far this poll round  */
};

/* ------------------------------------------------------------------ */
/* ring buffer callback — copies each event into the external buffer. */
/* Returns -1 when full, which stops processing (remaining events     */
/* stay in the ring for the next poll).  One event is consumed but    */
/* not copied; acceptable at capacity >= MAX_ENTRIES.                 */
/* ------------------------------------------------------------------ */
static int _copy_event(void *ctx, void *data, size_t size)
{
	struct rb_context *c = ctx;

	if (size < sizeof(struct event))
		return 0;

	if (c->count >= c->ext_capacity)
		return -1;

	memcpy((char *)c->ext_buf + c->count * sizeof(struct event),
	       data, sizeof(struct event));
	c->count++;
	return 0;
}

/* ------------------------------------------------------------------ */
/* Public API                                                         */
/* ------------------------------------------------------------------ */

struct rb_context *rb_open(const char *pin_path)
{
	int map_fd = bpf_obj_get(pin_path);
	if (map_fd < 0)
		return NULL;

	struct rb_context *ctx = calloc(1, sizeof(*ctx));
	if (!ctx)
		return NULL;

	ctx->rb = ring_buffer__new(map_fd, _copy_event, ctx, NULL);
	if (!ctx->rb) {
		free(ctx);
		return NULL;
	}

	return ctx;
}

/**
 * rb_poll_into — poll the ring buffer and copy events into buf.
 *
 * @ctx:        opaque handle from rb_open()
 * @buf:        caller-owned buffer (e.g. numpy array data pointer)
 * @capacity:   maximum number of struct event entries buf can hold
 * @timeout_ms: epoll timeout (ms); 0 = non-blocking, -1 = infinite
 *
 * Returns the number of events written to buf, or a negative errno
 * on fatal error (only when zero events were captured).
 */
int rb_poll_into(struct rb_context *ctx, void *buf, int capacity,
		 int timeout_ms)
{
	ctx->ext_buf = buf;
	ctx->ext_capacity = capacity;
	ctx->count = 0;

	int err = ring_buffer__poll(ctx->rb, timeout_ms);

	/* If we captured any events, return the count regardless of
	 * whether poll itself returned an error (e.g. -1 from callback
	 * when buffer was full). */
	if (ctx->count > 0)
		return ctx->count;

	if (err < 0 && err != -4) /* -4 = EINTR */
		return err;

	return 0;
}

void rb_close(struct rb_context *ctx)
{
	if (ctx) {
		if (ctx->rb)
			ring_buffer__free(ctx->rb);
		free(ctx);
	}
}
