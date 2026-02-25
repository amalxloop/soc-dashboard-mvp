/*
 * rng.c -- SilverCore SOC Dashboard: thread-local LCG PRNG implementation
 */
#include "rng.h"

#include <time.h>
#include <pthread.h>
#include <unistd.h>
#include <fcntl.h>
#include <stdio.h>

/* =========================================================================
 * Thread-local state
 * ====================================================================== */
_Thread_local u64 t_rng = 0;

/* =========================================================================
 * Clock helper (used in fallback seeding only)
 * ====================================================================== */
static u64 rng_now_ns(void) {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (u64)ts.tv_sec * 1000000000ULL + (u64)ts.tv_nsec;
}

/* =========================================================================
 * Seed
 * Primary:  read 8 bytes from /dev/urandom.
 * Fallback: mix monotonic clock + thread-id with a Murmur-style finalizer.
 * ====================================================================== */
void rng_seed(void) {
    u64 s = 0;
    int fd = open("/dev/urandom", O_RDONLY);
    if (fd >= 0) {
        ssize_t n = read(fd, &s, sizeof(s));
        close(fd);
        if (n != (ssize_t)sizeof(s)) s = 0;
    }
    if (s == 0) {
        u64 ts  = rng_now_ns();
        u64 tid = (u64)(uintptr_t)pthread_self();
        s = ts ^ (tid * 0x9e3779b97f4a7c15ULL);
        s ^= s >> 30; s *= 0xbf58476d1ce4e5b9ULL;
        s ^= s >> 27; s *= 0x94d049bb133111ebULL;
        s ^= s >> 31;
    }
    t_rng = s ? s : 0xDEADBEEFCAFEBABEULL;
}

/* =========================================================================
 * Generators
 * ====================================================================== */
u32 rng_u32(void) {
    t_rng = t_rng * 6364136223846793005ULL + 1442695040888963407ULL;
    return (u32)(t_rng >> 32);
}

u32 rng_range(u32 lo, u32 hi) {
    return lo + rng_u32() % (hi - lo);
}

f32 rng_f32(void) {
    return (f32)(rng_u32() & 0x7FFFFFFF) / (f32)0x7FFFFFFF;
}

void rng_ip(char *buf) {
    snprintf(buf, 16, "%u.%u.%u.%u",
             rng_range(1, 255), rng_range(0, 256),
             rng_range(0, 256), rng_range(1, 255));
}
