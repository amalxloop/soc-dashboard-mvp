/*
 * task_queue.h -- SilverCore SOC Dashboard: lock-free SPSC task queue
 *
 * Header-only. Include once per translation unit that needs it.
 */
#pragma once

#include "types.h"
#include <string.h>
#include <stdatomic.h>
#include <stdbool.h>

#define TASK_RING_SIZE  4096
#define TASK_RING_MASK  (TASK_RING_SIZE - 1)
#define TASK_PAYLOAD_SZ 128

typedef void (*TaskFn)(void *payload);

typedef struct {
    TaskFn fn;
    u8     payload[TASK_PAYLOAD_SZ];
} Task;

typedef struct {
    Task         ring[TASK_RING_SIZE];
    _Atomic(u32) write;   /* producer */
    u32          read;    /* consumer (main thread only) */
} TaskQueue;

static inline bool task_post(TaskQueue *q, TaskFn fn, const void *data, u32 len) {
    u32 w    = atomic_load_explicit(&q->write, memory_order_relaxed);
    u32 next = (w + 1) & TASK_RING_MASK;
    if (next == q->read) return false;  /* full - drop */
    Task *t = &q->ring[w & TASK_RING_MASK];
    t->fn = fn;
    if (data && len)
        memcpy(t->payload, data, len < TASK_PAYLOAD_SZ ? len : TASK_PAYLOAD_SZ);
    atomic_store_explicit(&q->write, (w + 1) & TASK_RING_MASK, memory_order_release);
    return true;
}

static inline u32 task_drain(TaskQueue *q) {
    u32 drained = 0;
    u32 w = atomic_load_explicit(&q->write, memory_order_acquire);
    while (q->read != w) {
        Task *t = &q->ring[q->read];
        t->fn(t->payload);
        q->read = (q->read + 1) & TASK_RING_MASK;
        drained++;
        w = atomic_load_explicit(&q->write, memory_order_acquire);
    }
    return drained;
}

static inline u32 task_depth(TaskQueue *q) {
    u32 w = atomic_load_explicit(&q->write, memory_order_relaxed);
    return (w - q->read) & TASK_RING_MASK;
}
