/*
 * rng.h -- SilverCore SOC Dashboard: thread-local LCG PRNG
 */
#pragma once

#include "types.h"

/* Seed the calling thread's RNG from /dev/urandom (fallback: clock + tid). */
void rng_seed(void);

u32  rng_u32(void);
u32  rng_range(u32 lo, u32 hi);
f32  rng_f32(void);
void rng_ip(char *buf);   /* writes "A.B.C.D\0" into buf (min 16 bytes) */

/* Direct access to the thread-local state (needed by net_init for a
 * deterministic fixed seed). Use with care.                            */
extern _Thread_local u64 t_rng;
