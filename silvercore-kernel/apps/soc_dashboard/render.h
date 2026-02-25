/*
 * render.h -- SilverCore SOC Dashboard: ncurses panel renderers + layout
 */
#pragma once

#include "types.h"
#include "task_queue.h"
#include <ncurses.h>
#include <stdatomic.h>
#include <pthread.h>

/* =========================================================================
 * Dashboard state (defined in soc_dashboard.c, used by render.c)
 * ====================================================================== */
typedef struct {
    /* Log ring buffer */
    LogEvent         log_ring[LOG_RING_SIZE];
    _Atomic(u32)     log_write;
    u32              log_read_snap;

    /* Alerts */
    Alert            alerts[THREAT_MAX];
    u32              alert_count;
    u32              next_alert_id;

    /* Network graph */
    NetNode          nodes[NET_MAX_NODES];
    NetEdge          edges[NET_MAX_EDGES];
    u32              node_count;
    u32              edge_count;
    char             canvas[NET_ROWS][NET_COLS + 1];
    bool             canvas_susp[NET_ROWS][NET_COLS];

    /* Task queue */
    TaskQueue        tasks;

    /* Perf stats */
    u64              frame_times[300];
    u32              frame_idx;
    u64              frame_count;
    f32              last_fps;
    f64              last_p99_ms;
    u64              last_fps_ts;
    u32              fps_frame_count;
    u64              arena_used;

    /* Generator thread */
    pthread_t        gen_thread;
    _Atomic(bool)    gen_running;

    /* ncurses windows */
    WINDOW          *w_root;
    WINDOW          *w_header;
    WINDOW          *w_log;
    WINDOW          *w_threat;
    WINDOW          *w_net;
    WINDOW          *w_stats;

    /* Terminal dimensions */
    int              term_rows;
    int              term_cols;

    /* Control flags */
    _Atomic(bool)    quit;
    bool             stats_overlay;
    _Atomic(bool)    gen_paused;
} Dashboard;

extern Dashboard g_dash;

/* =========================================================================
 * Public API
 * ====================================================================== */
void init_colors(void);
void layout_windows(void);

void render_header(void);
void render_log(void);
void render_threats(void);
void render_network(void);
void render_stats(void);
void render_stats_overlay(void);
