/*
 * soc_dashboard.c -- SilverCore SOC Dashboard MVP
 * =================================================
 *
 * Build:
 *   cmake -S silvercore-kernel -B silvercore-kernel/build -DCMAKE_BUILD_TYPE=Release
 *   cmake --build silvercore-kernel/build --target soc_dashboard
 *   ./silvercore-kernel/build/soc_dashboard [options]
 *
 * Options:
 *   --log-size   N   Log ring capacity (power of 2, default 8192)
 *   --threat-max N   Max tracked alerts           (default 32)
 *   --nodes      N   Network nodes to simulate    (default 100)
 *   --fps-cap    N   Target frame rate            (default 60)
 *
 * Keys (while running):
 *   q   quit
 *   s   toggle session stats popup
 *   p   pause / resume event generator
 */

#include "types.h"
#include "rng.h"
#include "task_queue.h"
#include "render.h"

#include <ncurses.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <math.h>
#include <time.h>
#include <pthread.h>
#include <stdatomic.h>
#include <signal.h>
#include <unistd.h>

/* =========================================================================
 * Global singletons
 * ====================================================================== */
Config    g_cfg = {
    .log_ring_size = LOG_RING_SIZE,
    .threat_max    = THREAT_MAX,
    .net_nodes     = NET_MAX_NODES,
    .fps_cap       = TARGET_FPS,
};

Dashboard g_dash;

const char *k_sev_name[SEV_COUNT]     = {"INFO","LOW","MEDIUM","HIGH","CRITICAL"};
const char *k_evt_name[EVT_TYPE_COUNT] = {
    "PORT_SCAN","BRUTE_FORCE","SQL_INJECT","XSS",
    "DDoS","PRIV_ESC","LATERAL","EXFIL","MALWARE","RECON"
};
int sev_cp[SEV_COUNT] = {CP_INFO, CP_LOW, CP_MEDIUM, CP_HIGH, CP_CRITICAL};

/* =========================================================================
 * Clock
 * ====================================================================== */
static u64 now_ns(void) {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (u64)ts.tv_sec * 1000000000ULL + (u64)ts.tv_nsec;
}

/* =========================================================================
 * Alert helpers
 * ====================================================================== */
static void alert_sort(void) {
    Dashboard *d = &g_dash;
    for (u32 i = 1; i < d->alert_count; i++) {
        Alert tmp = d->alerts[i];
        i32 j = (i32)i - 1;
        while (j >= 0 && d->alerts[j].sev < tmp.sev) {
            d->alerts[j + 1] = d->alerts[j];
            j--;
        }
        d->alerts[j + 1] = tmp;
    }
}

/* =========================================================================
 * Task handlers (run on main thread via task_drain)
 * ====================================================================== */
typedef struct { LogEvent ev; } TLog;
typedef struct { Alert    al; } TAlert;

static void handle_log(void *p) {
    TLog *tl = (TLog *)p;
    Dashboard *d = &g_dash;
    u32 idx = atomic_fetch_add(&d->log_write, 1) & LOG_RING_MASK;
    d->log_ring[idx] = tl->ev;
}

static void handle_alert(void *p) {
    TAlert *ta = (TAlert *)p;
    Dashboard *d = &g_dash;
    u32 slot = d->alert_count < THREAT_MAX ? d->alert_count : (THREAT_MAX - 1);
    if (d->alert_count >= THREAT_MAX) {
        u32 min_sev = d->alerts[0].sev;
        slot = 0;
        for (u32 i = 1; i < THREAT_MAX; i++) {
            if (d->alerts[i].sev < min_sev) { min_sev = d->alerts[i].sev; slot = i; }
        }
    }
    d->alerts[slot] = ta->al;
    d->alerts[slot].flash_frames = 8;
    if (slot == d->alert_count && d->alert_count < THREAT_MAX) d->alert_count++;
    alert_sort();
}

/* =========================================================================
 * Network graph
 * ====================================================================== */
static void net_init(void) {
    Dashboard *d = &g_dash;
    u32 node_count = g_cfg.net_nodes;
    d->node_count  = node_count;

    for (u32 i = 0; i < node_count; i++) {
        NetNode *n  = &d->nodes[i];
        bool ext    = (i >= (node_count * 60) / 100);
        u32 ring_n  = ext ? (node_count - (node_count * 60) / 100)
                          : (node_count * 60) / 100;
        if (ring_n == 0) ring_n = 1;
        u32 ring_i  = ext ? (i - (node_count * 60) / 100) : i;
        f32 radius  = ext ? 0.28f : 0.42f;
        f32 angle   = (f32)ring_i / (f32)ring_n * 2.0f * (f32)M_PI;
        n->x         = 0.5f + radius * cosf(angle);
        n->y         = 0.5f + radius * sinf(angle);
        n->external  = ext;
        n->suspicious = false;
    }

    d->edge_count = NET_MAX_EDGES;
    /* Fixed seed for deterministic topology across restarts. */
    t_rng = 0xABCDEF1234567890ULL;
    for (u32 i = 0; i < NET_MAX_EDGES; i++) {
        d->edges[i].a = rng_range(0, node_count);
        d->edges[i].b = rng_range(0, node_count);
        d->edges[i].suspicious = false;
    }
}

static void net_mark_suspicious(u32 node_idx) {
    Dashboard *d = &g_dash;
    if (node_idx >= d->node_count) return;
    d->nodes[node_idx].suspicious = true;
    for (u32 i = 0; i < d->edge_count; i++) {
        if (d->edges[i].a == node_idx || d->edges[i].b == node_idx)
            d->edges[i].suspicious = true;
    }
}

static void net_render_canvas(void) {
    Dashboard *d = &g_dash;
    int cw = NET_COLS;
    int ch = NET_ROWS;

    for (int r = 0; r < ch; r++) {
        memset(d->canvas[r], ' ', cw);
        d->canvas[r][cw] = '\0';
        memset(d->canvas_susp[r], 0, cw);
    }

    for (u32 i = 0; i < d->edge_count; i++) {
        NetEdge *e  = &d->edges[i];
        NetNode *na = &d->nodes[e->a];
        NetNode *nb = &d->nodes[e->b];
        f32 mx = (na->x + nb->x) * 0.5f;
        f32 my = (na->y + nb->y) * 0.5f;
        int cx = (int)(mx * (cw - 1));
        int cy = (int)(my * (ch - 1));
        if (cx >= 0 && cx < cw && cy >= 0 && cy < ch) {
            if (d->canvas[cy][cx] == ' ') {
                d->canvas[cy][cx]       = e->suspicious ? '*' : '.';
                d->canvas_susp[cy][cx]  = e->suspicious;
            }
        }
    }

    for (u32 i = 0; i < d->node_count; i++) {
        NetNode *n  = &d->nodes[i];
        int cx = (int)(n->x * (cw - 1));
        int cy = (int)(n->y * (ch - 1));
        if (cx < 0) cx = 0;
        if (cx >= cw) cx = cw - 1;
        if (cy < 0) cy = 0;
        if (cy >= ch) cy = ch - 1;
        char glyph = n->suspicious ? 'X' : (n->external ? 'e' : 'h');
        d->canvas[cy][cx]      = glyph;
        d->canvas_susp[cy][cx] = n->suspicious;
    }
}

/* =========================================================================
 * Event generator thread
 * ====================================================================== */
typedef struct { Dashboard *d; } GenCtx;

static void *gen_thread_fn(void *arg) {
    GenCtx *ctx = (GenCtx *)arg;
    Dashboard *d = ctx->d;
    rng_seed();

    while (atomic_load(&d->gen_running)) {
        u32 batch = rng_range(EVT_PER_SEC_LO, EVT_PER_SEC_HI + 1);

        for (u32 i = 0; i < batch; i++) {
            TLog tl;
            LogEvent *ev = &tl.ev;
            ev->ts_ns = now_ns();
            ev->type  = (EvtType)rng_range(0, EVT_TYPE_COUNT);

            f32 r = rng_f32();
            if      (r < 0.50f) ev->sev = SEV_INFO;
            else if (r < 0.70f) ev->sev = SEV_LOW;
            else if (r < 0.85f) ev->sev = SEV_MEDIUM;
            else if (r < 0.95f) ev->sev = SEV_HIGH;
            else                ev->sev = SEV_CRITICAL;

            rng_ip(ev->src);
            rng_ip(ev->dst);
            task_post(&d->tasks, handle_log, &tl, sizeof(tl));

            if (ev->sev >= SEV_HIGH && rng_f32() < 0.25f) {
                TAlert ta;
                Alert *al   = &ta.al;
                al->id       = d->next_alert_id++;
                al->sev      = ev->sev;
                al->detected_ns = ev->ts_ns;
                al->active   = true;
                al->flash_frames = 8;
                snprintf(al->desc, sizeof(al->desc), "%s @ %s",
                         k_evt_name[ev->type], ev->src);
                task_post(&d->tasks, handle_alert, &ta, sizeof(ta));
                net_mark_suspicious(rng_range(0, NET_MAX_NODES));
            }
        }

        /* 1-second burst; check pause every 100ms */
        for (int slice = 0; slice < 10 && atomic_load(&d->gen_running); slice++) {
            while (atomic_load(&d->gen_paused) && atomic_load(&d->gen_running)) {
                struct timespec ps = {.tv_sec = 0, .tv_nsec = 50000000};
                nanosleep(&ps, NULL);
            }
            struct timespec ts = {.tv_sec = 0, .tv_nsec = 100000000};
            nanosleep(&ts, NULL);
        }
    }
    return NULL;
}

/* =========================================================================
 * p99 computation
 * ====================================================================== */
static int cmp_u64(const void *a, const void *b) {
    u64 x = *(const u64 *)a, y = *(const u64 *)b;
    return (x > y) - (x < y);
}

static f64 compute_p99(void) {
    Dashboard *d = &g_dash;
    u32 n = (u32)(d->frame_count < 300 ? d->frame_count : 300);
    if (n < 2) return 0.0;
    u64 tmp[300];
    memcpy(tmp, d->frame_times, n * sizeof(u64));
    qsort(tmp, n, sizeof(u64), cmp_u64);
    u32 idx = (u32)((n - 1) * 0.99);
    return (f64)tmp[idx] * 1e-6;
}

/* =========================================================================
 * Signal handling
 * ====================================================================== */
static volatile sig_atomic_t g_resize_pending = 0;

static void handle_sigwinch(int sig) {
    (void)sig;
    g_resize_pending = 1;
}

/* =========================================================================
 * CLI argument parsing
 * ====================================================================== */
static u32 next_pow2(u32 v) {
    if (v < 64) return 64;
    v--;
    v |= v >> 1; v |= v >> 2; v |= v >> 4;
    v |= v >> 8; v |= v >> 16;
    return v + 1;
}

static void parse_args(int argc, char **argv) {
    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "--help") == 0 || strcmp(argv[i], "-h") == 0) {
            printf("Usage: %s [options]\n\n"
                   "  --log-size   N   Log ring capacity (power of 2, default %u)\n"
                   "  --threat-max N   Max tracked alerts           (default %u)\n"
                   "  --nodes      N   Network nodes to simulate    (default %u)\n"
                   "  --fps-cap    N   Target frame rate            (default %u)\n",
                   argv[0], LOG_RING_SIZE, THREAT_MAX, NET_MAX_NODES, TARGET_FPS);
            exit(0);
        }
        if (i + 1 >= argc) continue;
        long val = strtol(argv[i + 1], NULL, 10);
        if (val <= 0) continue;
        if (strcmp(argv[i], "--log-size") == 0) {
            g_cfg.log_ring_size = next_pow2((u32)val);
            if (g_cfg.log_ring_size > LOG_RING_SIZE) g_cfg.log_ring_size = LOG_RING_SIZE;
            i++;
        } else if (strcmp(argv[i], "--threat-max") == 0) {
            g_cfg.threat_max = (u32)val > THREAT_MAX ? THREAT_MAX : (u32)val;
            i++;
        } else if (strcmp(argv[i], "--nodes") == 0) {
            g_cfg.net_nodes = (u32)val > NET_MAX_NODES ? NET_MAX_NODES : (u32)val;
            i++;
        } else if (strcmp(argv[i], "--fps-cap") == 0) {
            g_cfg.fps_cap = (u32)val < 1 ? 1 : ((u32)val > 240 ? 240 : (u32)val);
            i++;
        }
    }
}

/* =========================================================================
 * Main
 * ====================================================================== */
int main(int argc, char **argv) {
    parse_args(argc, argv);

    Dashboard *d = &g_dash;
    memset(d, 0, sizeof(*d));

    net_init();

    initscr();
    cbreak();
    noecho();
    keypad(stdscr, TRUE);
    nodelay(stdscr, TRUE);
    curs_set(0);

    if (!has_colors()) {
        endwin();
        fprintf(stderr, "Terminal has no color support.\n");
        return 1;
    }
    init_colors();

    signal(SIGWINCH, handle_sigwinch);
    layout_windows();

    atomic_store(&d->gen_running, true);
    atomic_store(&d->quit, false);
    GenCtx gen_ctx = {.d = d};
    if (pthread_create(&d->gen_thread, NULL, gen_thread_fn, &gen_ctx) != 0) {
        endwin();
        fprintf(stderr, "Failed to create generator thread.\n");
        return 1;
    }

    u64 last_ts     = now_ns();
    u64 last_fps_ts = last_ts;
    u32 fps_frames  = 0;

    while (!atomic_load(&d->quit)) {
        u64 frame_start = now_ns();

        int ch = getch();
        if (ch == 'q' || ch == 'Q') {
            atomic_store(&d->quit, true);
            break;
        }
        if (ch == 's' || ch == 'S') {
            d->stats_overlay = !d->stats_overlay;
        }
        if (ch == 'p' || ch == 'P') {
            bool cur = atomic_load(&d->gen_paused);
            atomic_store(&d->gen_paused, !cur);
        }
        if (ch == KEY_RESIZE || g_resize_pending) {
            g_resize_pending = 0;
            endwin();
            refresh();
            clear();
            layout_windows();
        }

        task_drain(&d->tasks);

        u64 ts_now = now_ns();
        f64 dt_ns  = (f64)(ts_now - last_ts);
        last_ts    = ts_now;
        fps_frames++;

        f64 elapsed_fps = (f64)(ts_now - last_fps_ts) * 1e-9;
        if (elapsed_fps >= 0.5) {
            d->last_fps    = (f32)((f64)fps_frames / elapsed_fps);
            last_fps_ts    = ts_now;
            fps_frames     = 0;
            d->last_p99_ms = compute_p99();
        }

        if (d->frame_count > 0) {
            d->frame_times[d->frame_idx % 300] = (u64)dt_ns;
            d->frame_idx++;
        }
        d->frame_count++;

        net_render_canvas();

        if (d->w_header) render_header();
        if (d->w_log)    render_log();
        if (d->w_threat) render_threats();
        if (d->w_net)    render_network();
        if (d->w_stats)  render_stats();

        render_stats_overlay();

        doupdate();

        u64 frame_us_cap     = (u64)(1000000u / g_cfg.fps_cap);
        u64 frame_elapsed_us = (now_ns() - frame_start) / 1000;
        if (frame_elapsed_us < frame_us_cap)
            usleep((useconds_t)(frame_us_cap - frame_elapsed_us));
    }

    /* Cleanup */
    atomic_store(&d->gen_running, false);
    pthread_join(d->gen_thread, NULL);

    if (d->w_header) delwin(d->w_header);
    if (d->w_log)    delwin(d->w_log);
    if (d->w_threat) delwin(d->w_threat);
    if (d->w_net)    delwin(d->w_net);
    if (d->w_stats)  delwin(d->w_stats);
    endwin();

    printf("\n=== SilverCore SOC Dashboard - Session Stats ===\n");
    printf("  Frames rendered : %llu\n", (unsigned long long)d->frame_count);
    printf("  Final FPS       : %.1f\n", (double)d->last_fps);
    printf("  p99 frame time  : %.2f ms  %s\n",
           d->last_p99_ms, d->last_p99_ms < 20.0 ? "[PASS]" : "[FAIL]");
    printf("  Total alerts    : %u\n", d->alert_count);
    printf("  Log ring writes : %llu\n",
           (unsigned long long)atomic_load(&d->log_write));
    printf("================================================\n");
    return 0;
}
