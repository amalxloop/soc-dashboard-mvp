/*
 * soc_dashboard.c  --  SilverCore SOC Dashboard MVP  (pure C + ncurses GUI)
 * ==========================================================================
 *
 * Build:
 *   cmake -S . -B build -DCMAKE_BUILD_TYPE=Release
 *   cmake --build build
 *   ./build/soc_dashboard
 *
 * Press 'q' to quit.
 *
 * Layout (80-column terminal, scales to wider):
 *
 *  ┌─[ SilverCore SOC Dashboard ]──────────────────────────────────────────┐
 *  │  FPS: 60   p99: 3.4ms   Arena: 0KB/8MB   Queue: 0   Ring: 1024/8192  │
 *  ├──────────────────────────────────────────┬────────────────────────────┤
 *  │  LIVE LOG STREAM                         │  ACTIVE THREATS            │
 *  │  TIMESTAMP  SRC IP         DST IP        │  #ID  SEV       DESC  AGE  │
 *  │  ...        ...            ...           │  ...                       │
 *  ├──────────────────────────────────────────┤                            │
 *  │  NETWORK GRAPH  (100 nodes, 200 edges)   │                            │
 *  │  [canvas: ascii nodes + edges]           │                            │
 *  └──────────────────────────────────────────┴────────────────────────────┘
 */

#include <ncurses.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <math.h>
#include <time.h>
#include <pthread.h>
#include <stdatomic.h>
#include <stdint.h>
#include <stdbool.h>
#include <signal.h>
#include <unistd.h>

/* =========================================================================
 * Portable types
 * ====================================================================== */
typedef uint8_t  u8;
typedef uint16_t u16;
typedef uint32_t u32;
typedef uint64_t u64;
typedef int32_t  i32;
typedef float    f32;
typedef double   f64;

/* =========================================================================
 * Constants
 * ====================================================================== */
#define TARGET_FPS          60
#define FRAME_US            (1000000 / TARGET_FPS)  /* microseconds/frame */

/* Log ring */
#define LOG_RING_SIZE       8192
#define LOG_RING_MASK       (LOG_RING_SIZE - 1)
#define LOG_VISIBLE_ROWS    20

/* Threats */
#define THREAT_MAX          32
#define THREAT_VISIBLE      12

/* Network graph */
#define NET_MAX_NODES       100
#define NET_MAX_EDGES       200
/* Canvas cell size in chars */
#define NET_COLS            42
#define NET_ROWS            16

/* Generator rate */
#define EVT_PER_SEC_LO      84
#define EVT_PER_SEC_HI      333

/* =========================================================================
 * Clock helper
 * ====================================================================== */
static u64 now_ns(void) {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (u64)ts.tv_sec * 1000000000ULL + (u64)ts.tv_nsec;
}

/* =========================================================================
 * LCG PRNG  (thread-local, no heap)
 * ====================================================================== */
static _Thread_local u64 t_rng = 0xDEADBEEFCAFEBABEULL;

static u32 rng_u32(void) {
    t_rng = t_rng * 6364136223846793005ULL + 1442695040888963407ULL;
    return (u32)(t_rng >> 32);
}
static u32 rng_range(u32 lo, u32 hi) { return lo + rng_u32() % (hi - lo); }
static f32 rng_f32(void) { return (f32)(rng_u32() & 0x7FFFFFFF) / (f32)0x7FFFFFFF; }
static void rng_ip(char *buf) {
    snprintf(buf, 16, "%u.%u.%u.%u",
             rng_range(1,255), rng_range(0,256),
             rng_range(0,256), rng_range(1,255));
}

/* =========================================================================
 * Domain types
 * ====================================================================== */
typedef enum { SEV_INFO=0, SEV_LOW, SEV_MEDIUM, SEV_HIGH, SEV_CRITICAL, SEV_COUNT } Severity;
typedef enum {
    EVT_PORT_SCAN=0, EVT_BRUTE_FORCE, EVT_SQL_INJECT, EVT_XSS,
    EVT_DDOS, EVT_PRIV_ESC, EVT_LATERAL, EVT_EXFIL, EVT_MALWARE, EVT_RECON,
    EVT_TYPE_COUNT
} EvtType;

static const char *k_sev_name[SEV_COUNT]  = {"INFO","LOW","MEDIUM","HIGH","CRITICAL"};
static const char *k_evt_name[EVT_TYPE_COUNT] = {
    "PORT_SCAN","BRUTE_FORCE","SQL_INJECT","XSS",
    "DDoS","PRIV_ESC","LATERAL","EXFIL","MALWARE","RECON"
};

/* ncurses color pair IDs */
#define CP_NORMAL    1
#define CP_INFO      2
#define CP_LOW       3
#define CP_MEDIUM    4
#define CP_HIGH      5
#define CP_CRITICAL  6
#define CP_HEADER    7
#define CP_BORDER    8
#define CP_TITLE     9
#define CP_DIM       10
#define CP_NET_NODE  11
#define CP_NET_EXT   12
#define CP_NET_SUSP  13
#define CP_ALERT_HI  14
#define CP_ALERT_CR  15
#define CP_STATS     16
#define CP_CANVAS_BG 17

/* Map severity to color pair */
static int sev_cp[SEV_COUNT] = {CP_INFO, CP_LOW, CP_MEDIUM, CP_HIGH, CP_CRITICAL};

typedef struct {
    u64     ts_ns;
    char    src[16];
    char    dst[16];
    EvtType type;
    Severity sev;
} LogEvent;

typedef struct {
    u32      id;
    Severity sev;
    char     desc[48];
    u64      detected_ns;
    bool     active;
    /* flash animation: remaining frames to show bright highlight */
    i32      flash_frames;
} Alert;

typedef struct {
    f32  x, y;      /* 0..1 normalized canvas position */
    bool suspicious;
    bool external;
} NetNode;

typedef struct {
    u32  a, b;
    bool suspicious;
} NetEdge;

/* =========================================================================
 * MPSC task (lock-free single-consumer)
 * Very simple: bounded ring of 4096 function+payload slots.
 * ====================================================================== */
#define TASK_RING_SIZE  4096
#define TASK_RING_MASK  (TASK_RING_SIZE - 1)
#define TASK_PAYLOAD_SZ 128

typedef void (*TaskFn)(void *payload);

typedef struct {
    TaskFn fn;
    u8     payload[TASK_PAYLOAD_SZ];
} Task;

typedef struct {
    Task             ring[TASK_RING_SIZE];
    _Atomic(u32)     write;   /* producer */
    u32              read;    /* consumer (main thread only) */
} TaskQueue;

static inline bool task_post(TaskQueue *q, TaskFn fn, const void *data, u32 len) {
    u32 w = atomic_load_explicit(&q->write, memory_order_relaxed);
    u32 next = (w + 1) & TASK_RING_MASK;
    if (next == q->read) return false;  /* full – drop */
    Task *t = &q->ring[w & TASK_RING_MASK];
    t->fn = fn;
    if (data && len) memcpy(t->payload, data, len < TASK_PAYLOAD_SZ ? len : TASK_PAYLOAD_SZ);
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

/* =========================================================================
 * Global dashboard state  (static allocation, zero heap on hot path)
 * ====================================================================== */
typedef struct {
    /* Log ring buffer */
    LogEvent            log_ring[LOG_RING_SIZE];
    _Atomic(u32)        log_write;      /* producer idx */
    u32                 log_read_snap;  /* consumer snapshot */

    /* Alerts */
    Alert               alerts[THREAT_MAX];
    u32                 alert_count;
    u32                 next_alert_id;

    /* Network graph */
    NetNode             nodes[NET_MAX_NODES];
    NetEdge             edges[NET_MAX_EDGES];
    u32                 node_count;
    u32                 edge_count;
    /* Rendered ASCII canvas (NET_ROWS x NET_COLS chars) */
    char                canvas[NET_ROWS][NET_COLS + 1];
    bool                canvas_susp[NET_ROWS][NET_COLS]; /* highlight cell? */

    /* Task queue */
    TaskQueue           tasks;

    /* Perf stats */
    u64                 frame_times[300];   /* rolling p99 window */
    u32                 frame_idx;
    u64                 frame_count;
    f32                 last_fps;
    f64                 last_p99_ms;
    u64                 last_fps_ts;
    u32                 fps_frame_count;
    u64                 arena_used;         /* simulated: bytes used this frame */

    /* Generator thread */
    pthread_t           gen_thread;
    _Atomic(bool)       gen_running;

    /* ncurses windows */
    WINDOW             *w_root;
    WINDOW             *w_header;
    WINDOW             *w_log;
    WINDOW             *w_threat;
    WINDOW             *w_net;
    WINDOW             *w_stats;

    /* Terminal dimensions */
    int                 term_rows;
    int                 term_cols;

    /* Quit flag */
    _Atomic(bool)       quit;

    /* Runtime flags */
    bool                stats_overlay;   /* 's' toggles detailed stats popup */
    _Atomic(bool)       gen_paused;      /* 'p' pauses/resumes generator     */
} Dashboard;

static Dashboard g_dash;

/* =========================================================================
 * Alert helpers
 * ====================================================================== */
static void alert_sort(void) {
    Dashboard *d = &g_dash;
    for (u32 i = 1; i < d->alert_count; i++) {
        Alert tmp = d->alerts[i];
        i32 j = (i32)i - 1;
        while (j >= 0 && d->alerts[j].sev < tmp.sev) {
            d->alerts[j+1] = d->alerts[j];
            j--;
        }
        d->alerts[j+1] = tmp;
    }
}

/* =========================================================================
 * Task handlers (run on main thread via task_drain)
 * ====================================================================== */
typedef struct { LogEvent ev; } TLog;
typedef struct { Alert al; }    TAlert;

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
    /* replace lowest-severity if full */
    if (d->alert_count >= THREAT_MAX) {
        u32 min_sev = d->alerts[0].sev;
        slot = 0;
        for (u32 i = 1; i < THREAT_MAX; i++) {
            if (d->alerts[i].sev < min_sev) { min_sev = d->alerts[i].sev; slot = i; }
        }
    }
    d->alerts[slot] = ta->al;
    d->alerts[slot].flash_frames = 8;  /* 8 frames of highlight animation */
    if (slot == d->alert_count && d->alert_count < THREAT_MAX) d->alert_count++;
    alert_sort();
}

/* =========================================================================
 * Network graph – precomputed positions
 * ====================================================================== */
static void net_init(void) {
    Dashboard *d = &g_dash;
    d->node_count = NET_MAX_NODES;
    for (u32 i = 0; i < NET_MAX_NODES; i++) {
        NetNode *n = &d->nodes[i];
        bool ext  = (i >= 60);
        u32  ring_n = ext ? 40 : 60;
        u32  ring_i = ext ? (i - 60) : i;
        f32  radius = ext ? 0.28f : 0.42f;
        f32  angle  = (f32)ring_i / (f32)ring_n * 2.0f * (f32)M_PI;
        n->x         = 0.5f + radius * cosf(angle);
        n->y         = 0.5f + radius * sinf(angle);
        n->external  = ext;
        n->suspicious = false;
    }
    d->edge_count = NET_MAX_EDGES;
    t_rng = 0xABCDEF1234567890ULL;
    for (u32 i = 0; i < NET_MAX_EDGES; i++) {
        d->edges[i].a = rng_range(0, NET_MAX_NODES);
        d->edges[i].b = rng_range(0, NET_MAX_NODES);
        d->edges[i].suspicious = false;
    }
}

static void net_mark_suspicious(u32 node_idx) {
    Dashboard *d = &g_dash;
    if (node_idx >= d->node_count) return;
    d->nodes[node_idx].suspicious = true;
    for (u32 i = 0; i < d->edge_count; i++) {
        if (d->edges[i].a == node_idx || d->edges[i].b == node_idx) {
            d->edges[i].suspicious = true;
        }
    }
}

/* Rasterize network graph into the ASCII canvas */
static void net_render_canvas(void) {
    Dashboard *d = &g_dash;
    int cw = NET_COLS;
    int ch = NET_ROWS;

    /* Clear canvas */
    for (int r = 0; r < ch; r++) {
        memset(d->canvas[r], ' ', cw);
        d->canvas[r][cw] = '\0';
        memset(d->canvas_susp[r], 0, cw);
    }

    /* Draw edges as dots/dashes */
    for (u32 i = 0; i < d->edge_count; i++) {
        NetEdge *e = &d->edges[i];
        NetNode *na = &d->nodes[e->a];
        NetNode *nb = &d->nodes[e->b];
        /* Bresenham-style midpoint dot */
        f32 mx = (na->x + nb->x) * 0.5f;
        f32 my = (na->y + nb->y) * 0.5f;
        int cx = (int)(mx * (cw - 1));
        int cy = (int)(my * (ch - 1));
        if (cx >= 0 && cx < cw && cy >= 0 && cy < ch) {
            if (d->canvas[cy][cx] == ' ') {
                d->canvas[cy][cx] = e->suspicious ? '*' : '.';
                d->canvas_susp[cy][cx] = e->suspicious;
            }
        }
    }

    /* Draw nodes */
    for (u32 i = 0; i < d->node_count; i++) {
        NetNode *n = &d->nodes[i];
        int cx = (int)(n->x * (cw - 1));
        int cy = (int)(n->y * (ch - 1));
        if (cx < 0) cx = 0;
        if (cx >= cw) cx = cw - 1;
        if (cy < 0) cy = 0;
        if (cy >= ch) cy = ch - 1;
        char ch_char = n->suspicious ? 'X' : (n->external ? 'e' : 'h');
        d->canvas[cy][cx] = ch_char;
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
    t_rng = now_ns() ^ 0xFEEDFACEDEADBEEFULL;

    while (atomic_load(&d->gen_running)) {
        u32 batch = rng_range(EVT_PER_SEC_LO, EVT_PER_SEC_HI + 1);

        for (u32 i = 0; i < batch; i++) {
            TLog tl;
            LogEvent *ev = &tl.ev;
            ev->ts_ns = now_ns();
            ev->type  = (EvtType)rng_range(0, EVT_TYPE_COUNT);
            /* Realistic severity distribution */
            f32 r = rng_f32();
            if      (r < 0.50f) ev->sev = SEV_INFO;
            else if (r < 0.70f) ev->sev = SEV_LOW;
            else if (r < 0.85f) ev->sev = SEV_MEDIUM;
            else if (r < 0.95f) ev->sev = SEV_HIGH;
            else                ev->sev = SEV_CRITICAL;
            rng_ip(ev->src);
            rng_ip(ev->dst);
            task_post(&d->tasks, handle_log, &tl, sizeof(tl));

            /* Promote HIGH/CRITICAL to alert */
            if (ev->sev >= SEV_HIGH && rng_f32() < 0.25f) {
                TAlert ta;
                Alert *al = &ta.al;
                al->id          = d->next_alert_id++;
                al->sev         = ev->sev;
                al->detected_ns = ev->ts_ns;
                al->active      = true;
                al->flash_frames = 8;
                snprintf(al->desc, sizeof(al->desc), "%s @ %s",
                         k_evt_name[ev->type], ev->src);
                task_post(&d->tasks, handle_alert, &ta, sizeof(ta));
                net_mark_suspicious(rng_range(0, NET_MAX_NODES));
            }
        }

        /* 1-second burst interval – check pause every 100ms */
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
 * p99 helper
 * ====================================================================== */
static int cmp_u64(const void *a, const void *b) {
    u64 x = *(const u64*)a, y = *(const u64*)b;
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
 * ncurses helpers
 * ====================================================================== */
static void init_colors(void) {
    start_color();
    use_default_colors();
    /* pair, fg, bg */
    init_pair(CP_NORMAL,   COLOR_WHITE,   -1);
    init_pair(CP_INFO,     COLOR_CYAN,    -1);
    init_pair(CP_LOW,      COLOR_GREEN,   -1);
    init_pair(CP_MEDIUM,   COLOR_YELLOW,  -1);
    init_pair(CP_HIGH,     COLOR_RED,     COLOR_BLACK);
    init_pair(CP_CRITICAL, COLOR_WHITE,   COLOR_RED);
    init_pair(CP_HEADER,   COLOR_CYAN,    COLOR_BLUE);
    init_pair(CP_BORDER,   COLOR_CYAN,    -1);
    init_pair(CP_TITLE,    COLOR_WHITE,   COLOR_BLUE);
    init_pair(CP_DIM,      COLOR_WHITE,   -1);
    init_pair(CP_NET_NODE, COLOR_CYAN,    -1);
    init_pair(CP_NET_EXT,  COLOR_GREEN,   -1);
    init_pair(CP_NET_SUSP, COLOR_WHITE,   COLOR_RED);
    init_pair(CP_ALERT_HI, COLOR_RED,     COLOR_BLACK);
    init_pair(CP_ALERT_CR, COLOR_WHITE,   COLOR_RED);
    init_pair(CP_STATS,    COLOR_GREEN,   COLOR_BLACK);
    init_pair(CP_CANVAS_BG,COLOR_BLUE,   -1);
}

/* Draw a titled box around a window */
static void draw_box_title(WINDOW *win, const char *title, int cp_border, int cp_title) {
    wattron(win, COLOR_PAIR(cp_border));
    box(win, 0, 0);
    wattroff(win, COLOR_PAIR(cp_border));

    int w = getmaxx(win);
    int tlen = (int)strlen(title);
    int tx = (w - tlen - 4) / 2;
    if (tx < 1) tx = 1;
    wattron(win, COLOR_PAIR(cp_title) | A_BOLD);
    mvwprintw(win, 0, tx, " %s ", title);
    wattroff(win, COLOR_PAIR(cp_title) | A_BOLD);
}

/* =========================================================================
 * Panel renderers
 * ====================================================================== */

/* --- Header bar -------------------------------------------------------- */
static void render_header(void) {
    Dashboard *d = &g_dash;
    WINDOW *w = d->w_header;
    werase(w);

    wattron(w, COLOR_PAIR(CP_HEADER) | A_BOLD);
    int cols = getmaxx(w);
    for (int i = 0; i < cols; i++) mvwaddch(w, 0, i, ' ');
    mvwprintw(w, 0, 2, "[ SilverCore SOC Dashboard MVP ]");
    wattroff(w, COLOR_PAIR(CP_HEADER) | A_BOLD);

    /* FPS */
    wattron(w, COLOR_PAIR(CP_LOW) | A_BOLD);
    mvwprintw(w, 0, 36, "FPS:%-4.0f", (double)d->last_fps);
    wattroff(w, COLOR_PAIR(CP_LOW) | A_BOLD);

    /* p99 */
    int p99_cp = d->last_p99_ms < 10.0 ? CP_LOW :
                 d->last_p99_ms < 20.0 ? CP_MEDIUM : CP_CRITICAL;
    wattron(w, COLOR_PAIR(p99_cp) | A_BOLD);
    mvwprintw(w, 0, 45, "p99:%.2fms", d->last_p99_ms);
    wattroff(w, COLOR_PAIR(p99_cp) | A_BOLD);

    /* Ring fill */
    u32 ring_fill = atomic_load(&d->log_write) & LOG_RING_MASK;
    wattron(w, COLOR_PAIR(CP_INFO));
    mvwprintw(w, 0, 56, "Ring:%u/%u", ring_fill, LOG_RING_SIZE);
    wattroff(w, COLOR_PAIR(CP_INFO));

    /* Queue depth */
    wattron(w, COLOR_PAIR(CP_MEDIUM));
    mvwprintw(w, 0, cols - 18, "Q:%-4u Events:%-6llu",
              task_depth(&d->tasks),
              (unsigned long long)atomic_load(&d->log_write));
    wattroff(w, COLOR_PAIR(CP_MEDIUM));

    wnoutrefresh(w);
}

/* --- Live Log Stream --------------------------------------------------- */
static void render_log(void) {
    Dashboard *d = &g_dash;
    WINDOW *w = d->w_log;
    int rows = getmaxy(w);
    int cols = getmaxx(w);
    werase(w);
    draw_box_title(w, "LIVE LOG STREAM", CP_BORDER, CP_TITLE);

    /* Column headers */
    wattron(w, COLOR_PAIR(CP_DIM) | A_UNDERLINE);
    mvwprintw(w, 1, 2, "%-8s %-15s %-15s %-12s %-8s",
              "AGE(s)", "SRC IP", "DST IP", "EVENT", "SEV");
    wattroff(w, COLOR_PAIR(CP_DIM) | A_UNDERLINE);

    int visible = rows - 3;  /* rows inside box minus header row */
    if (visible > LOG_VISIBLE_ROWS) visible = LOG_VISIBLE_ROWS;
    if (visible < 1) return;

    u64 now = now_ns();
    u32 write_pos = atomic_load(&d->log_write);

    for (int row = 0; row < visible; row++) {
        /* Newest event at top */
        u32 offset = (u32)(visible - 1 - row);
        u32 idx    = (write_pos - offset - 1) & LOG_RING_MASK;
        LogEvent *ev = &d->log_ring[idx];

        if (ev->ts_ns == 0) continue;

        f64 age = (f64)(now - ev->ts_ns) * 1e-9;
        if (age < 0.0) age = 0.0;

        int display_row = row + 2;
        if (display_row >= rows - 1) break;

        /* Row background for critical/high */
        if (ev->sev == SEV_CRITICAL) {
            wattron(w, COLOR_PAIR(CP_CRITICAL) | A_BOLD);
        } else if (ev->sev == SEV_HIGH) {
            wattron(w, COLOR_PAIR(CP_HIGH) | A_BOLD);
        } else {
            wattron(w, COLOR_PAIR(CP_NORMAL));
        }

        /* Print fixed-width columns, clipped to window */
        char line[128];
        snprintf(line, sizeof(line), "%-8.2f %-15s %-15s %-12s",
                 age, ev->src, ev->dst, k_evt_name[ev->type]);
        int llen = (int)strlen(line);
        if (llen > cols - 20) llen = cols - 20;
        if (llen > 0) mvwaddnstr(w, display_row, 2, line, llen);

        if (ev->sev == SEV_CRITICAL || ev->sev == SEV_HIGH) {
            wattroff(w, COLOR_PAIR(ev->sev == SEV_CRITICAL ? CP_CRITICAL : CP_HIGH) | A_BOLD);
        } else {
            wattroff(w, COLOR_PAIR(CP_NORMAL));
        }

        /* Severity badge */
        wattron(w, COLOR_PAIR(sev_cp[ev->sev]) | A_BOLD);
        mvwprintw(w, display_row, cols - 10, "%-8s", k_sev_name[ev->sev]);
        wattroff(w, COLOR_PAIR(sev_cp[ev->sev]) | A_BOLD);
    }

    wnoutrefresh(w);
}

/* --- Active Threat Panel ----------------------------------------------- */
static void render_threats(void) {
    Dashboard *d = &g_dash;
    WINDOW *w = d->w_threat;
    int rows = getmaxy(w);
    int cols = getmaxx(w);
    werase(w);
    draw_box_title(w, "ACTIVE THREATS", CP_ALERT_HI, CP_ALERT_CR);

    /* Count line */
    wattron(w, COLOR_PAIR(CP_MEDIUM) | A_BOLD);
    mvwprintw(w, 1, 2, "Total alerts: %-4u", d->alert_count);
    wattroff(w, COLOR_PAIR(CP_MEDIUM) | A_BOLD);

    /* Column headers */
    wattron(w, COLOR_PAIR(CP_DIM) | A_UNDERLINE);
    mvwprintw(w, 2, 2, "%-6s %-8s %-22s %-8s", "#ID", "SEV", "DESCRIPTION", "AGE");
    wattroff(w, COLOR_PAIR(CP_DIM) | A_UNDERLINE);

    u64 now = now_ns();
    int visible = rows - 4;
    if (visible > THREAT_VISIBLE) visible = THREAT_VISIBLE;
    if (visible < 1) return;

    u32 shown = d->alert_count < (u32)visible ? d->alert_count : (u32)visible;
    for (u32 r = 0; r < shown; r++) {
        Alert *al = &d->alerts[r];
        int display_row = (int)r + 3;
        if (display_row >= rows - 1) break;

        /* Flash animation: alternate bright/normal */
        bool flashing = al->flash_frames > 0;
        if (flashing) al->flash_frames--;

        int cp = (al->sev == SEV_CRITICAL) ? CP_ALERT_CR :
                 (al->sev == SEV_HIGH)     ? CP_ALERT_HI : CP_MEDIUM;
        attr_t attrs = COLOR_PAIR(cp) | (flashing ? A_REVERSE | A_BOLD : A_NORMAL);
        wattron(w, attrs);

        /* Pad row to full width */
        for (int c = 1; c < cols - 1; c++) mvwaddch(w, display_row, c, ' ');

        u64 age_ns = now - al->detected_ns;
        char age_buf[16];
        if (age_ns < 1000000000ULL)
            snprintf(age_buf, sizeof(age_buf), "%llums", (unsigned long long)(age_ns/1000000));
        else
            snprintf(age_buf, sizeof(age_buf), "%llus", (unsigned long long)(age_ns/1000000000));

        char desc_trunc[23];
        snprintf(desc_trunc, sizeof(desc_trunc), "%s", al->desc);

        mvwprintw(w, display_row, 2, "#%-5u %-8s %-22s %-8s",
                  al->id, k_sev_name[al->sev], desc_trunc, age_buf);

        wattroff(w, attrs);
    }

    wnoutrefresh(w);
}

/* --- Network Graph View ------------------------------------------------ */
static void render_network(void) {
    Dashboard *d = &g_dash;
    WINDOW *w = d->w_net;
    int rows = getmaxy(w);
    int cols = getmaxx(w);
    werase(w);
    draw_box_title(w, "NETWORK GRAPH  [h=host e=ext X=suspicious]", CP_BORDER, CP_TITLE);

    /* Legend */
    wattron(w, COLOR_PAIR(CP_NET_NODE));
    mvwaddstr(w, 1, 2, "h");
    wattroff(w, COLOR_PAIR(CP_NET_NODE));
    waddstr(w, "-internal  ");
    wattron(w, COLOR_PAIR(CP_NET_EXT));
    waddstr(w, "e");
    wattroff(w, COLOR_PAIR(CP_NET_EXT));
    waddstr(w, "-external  ");
    wattron(w, COLOR_PAIR(CP_NET_SUSP) | A_BOLD);
    waddstr(w, "X");
    wattroff(w, COLOR_PAIR(CP_NET_SUSP) | A_BOLD);
    waddstr(w, "-suspicious  ");
    wattron(w, COLOR_PAIR(CP_INFO));

    /* Count suspicious */
    u32 susp_nodes = 0, susp_edges = 0;
    for (u32 i = 0; i < d->node_count; i++) if (d->nodes[i].suspicious) susp_nodes++;
    for (u32 i = 0; i < d->edge_count; i++) if (d->edges[i].suspicious) susp_edges++;
    mvwprintw(w, 1, cols - 28, "suspicious: %u nodes / %u edges", susp_nodes, susp_edges);
    wattroff(w, COLOR_PAIR(CP_INFO));

    /* Canvas bounding box */
    int can_start_row = 2;
    int can_start_col = 2;
    int can_rows = rows - 3;
    int can_cols = cols - 4;
    if (can_rows < 1 || can_cols < 1) { wnoutrefresh(w); return; }

    /* Render canvas cells */
    for (int r = 0; r < NET_ROWS && r < can_rows; r++) {
        for (int c = 0; c < NET_COLS && c < can_cols; c++) {
            char ch = d->canvas[r][c];
            bool susp = d->canvas_susp[r][c];
            int pr = can_start_row + r;
            int pc = can_start_col + c;
            if (pr >= rows - 1 || pc >= cols - 1) continue;

            if (susp && (ch == 'X' || ch == '*')) {
                wattron(w, COLOR_PAIR(CP_NET_SUSP) | A_BOLD);
                mvwaddch(w, pr, pc, ch);
                wattroff(w, COLOR_PAIR(CP_NET_SUSP) | A_BOLD);
            } else if (ch == 'h') {
                wattron(w, COLOR_PAIR(CP_NET_NODE) | A_BOLD);
                mvwaddch(w, pr, pc, ch);
                wattroff(w, COLOR_PAIR(CP_NET_NODE) | A_BOLD);
            } else if (ch == 'e') {
                wattron(w, COLOR_PAIR(CP_NET_EXT));
                mvwaddch(w, pr, pc, ch);
                wattroff(w, COLOR_PAIR(CP_NET_EXT));
            } else if (ch == '.') {
                wattron(w, COLOR_PAIR(CP_CANVAS_BG));
                mvwaddch(w, pr, pc, ch);
                wattroff(w, COLOR_PAIR(CP_CANVAS_BG));
            } else if (ch != ' ') {
                mvwaddch(w, pr, pc, ch);
            }
        }
    }

    wnoutrefresh(w);
}

/* --- System Stats Overlay ---------------------------------------------- */
static void render_stats(void) {
    Dashboard *d = &g_dash;
    WINDOW *w = d->w_stats;
    int cols = getmaxx(w);
    werase(w);

    wattron(w, COLOR_PAIR(CP_STATS) | A_BOLD);
    for (int c = 0; c < cols; c++) mvwaddch(w, 0, c, ' ');
    mvwaddch(w, 0, 0, ACS_HLINE);

    int x = 1;
    /* FPS */
    mvwprintw(w, 0, x, " FPS:%.0f ", (double)d->last_fps);
    x += 10;
    /* p99 */
    int p99_cp = d->last_p99_ms < 10.0 ? CP_LOW :
                 d->last_p99_ms < 20.0 ? CP_MEDIUM : CP_CRITICAL;
    wattroff(w, COLOR_PAIR(CP_STATS) | A_BOLD);
    wattron(w, COLOR_PAIR(p99_cp) | A_BOLD);
    mvwprintw(w, 0, x, " p99:%.2fms ", d->last_p99_ms);
    x += 14;
    wattroff(w, COLOR_PAIR(p99_cp) | A_BOLD);

    wattron(w, COLOR_PAIR(CP_INFO) | A_BOLD);
    u32 ring_fill = atomic_load(&d->log_write) & LOG_RING_MASK;
    mvwprintw(w, 0, x, " Ring:%u/%u ", ring_fill, LOG_RING_SIZE);
    x += 18;

    wattron(w, COLOR_PAIR(CP_MEDIUM) | A_BOLD);
    mvwprintw(w, 0, x, " Queue:%u ", task_depth(&d->tasks));
    x += 12;

    wattron(w, COLOR_PAIR(CP_LOW) | A_BOLD);
    mvwprintw(w, 0, x, " Alerts:%u ", d->alert_count);
    x += 12;

    wattron(w, COLOR_PAIR(CP_DIM));
    mvwprintw(w, 0, x, " Frames:%llu ", (unsigned long long)d->frame_count);
    x += 16;

    /* Events/min estimate */
    wattron(w, COLOR_PAIR(CP_INFO));
    mvwprintw(w, 0, x, " ~%u–%u evt/min ",
              EVT_PER_SEC_LO * 60, EVT_PER_SEC_HI * 60);

    /* Pass/fail indicator on far right */
    bool pass = d->last_fps >= 55.0f && d->last_p99_ms < 20.0;
    wattron(w, pass ? (COLOR_PAIR(CP_LOW) | A_BOLD) : (COLOR_PAIR(CP_CRITICAL) | A_BOLD));
    mvwprintw(w, 0, cols - 10, pass ? " [PASS] " : " [FAIL] ");
    wattroff(w, A_BOLD);

    wnoutrefresh(w);
}

/* =========================================================================
 * Stats overlay popup  ('s' toggles)
 * Draws a centred popup window over everything with detailed session stats.
 * ====================================================================== */
static void render_stats_overlay(void) {
    Dashboard *d = &g_dash;
    if (!d->stats_overlay) return;

    int rows = d->term_rows;
    int cols = d->term_cols;

    /* Popup dimensions */
    int pop_h = 18;
    int pop_w = 60;
    int pop_y = (rows - pop_h) / 2;
    int pop_x = (cols - pop_w) / 2;
    if (pop_y < 0) pop_y = 0;
    if (pop_x < 0) pop_x = 0;

    WINDOW *pop = newwin(pop_h, pop_w, pop_y, pop_x);
    if (!pop) return;

    /* Shadow box */
    wbkgd(pop, COLOR_PAIR(CP_NORMAL));
    wattron(pop, COLOR_PAIR(CP_BORDER) | A_BOLD);
    box(pop, 0, 0);

    /* Title */
    wattron(pop, COLOR_PAIR(CP_TITLE) | A_BOLD | A_REVERSE);
    mvwprintw(pop, 0, (pop_w - 28) / 2, "  SESSION STATS  [s]=close  ");
    wattroff(pop, A_REVERSE);

    int ln = 2;
    /* FPS */
    bool fps_ok = d->last_fps >= 55.0f;
    wattron(pop, fps_ok ? COLOR_PAIR(CP_LOW) : COLOR_PAIR(CP_CRITICAL));
    mvwprintw(pop, ln++, 3, "  FPS              : %.1f %s",
              (double)d->last_fps, fps_ok ? "[OK]" : "[LOW]");

    /* p99 */
    bool p99_ok = d->last_p99_ms < 20.0;
    wattron(pop, p99_ok ? COLOR_PAIR(CP_LOW) : COLOR_PAIR(CP_CRITICAL));
    mvwprintw(pop, ln++, 3, "  p99 frame time   : %.2f ms %s",
              d->last_p99_ms, p99_ok ? "[PASS]" : "[FAIL]");

    /* frames */
    wattron(pop, COLOR_PAIR(CP_INFO));
    mvwprintw(pop, ln++, 3, "  Frames rendered  : %llu",
              (unsigned long long)d->frame_count);

    /* log ring */
    u32 log_write = atomic_load(&d->log_write);
    u32 ring_fill = log_write & LOG_RING_MASK;
    f32 ring_pct  = (f32)ring_fill / LOG_RING_SIZE * 100.0f;
    wattron(pop, COLOR_PAIR(CP_MEDIUM));
    mvwprintw(pop, ln++, 3, "  Log ring fill    : %u / %u  (%.1f%%)",
              ring_fill, LOG_RING_SIZE, (double)ring_pct);
    mvwprintw(pop, ln++, 3, "  Total log writes : %u", log_write);

    /* task queue */
    wattron(pop, COLOR_PAIR(CP_INFO));
    mvwprintw(pop, ln++, 3, "  Task queue depth : %u", task_depth(&d->tasks));

    /* alerts */
    wattron(pop, COLOR_PAIR(CP_HIGH));
    u32 crit = 0, high = 0, med = 0;
    for (u32 i = 0; i < d->alert_count && i < THREAT_MAX; i++) {
        if      (d->alerts[i].sev == SEV_CRITICAL) crit++;
        else if (d->alerts[i].sev == SEV_HIGH)     high++;
        else if (d->alerts[i].sev == SEV_MEDIUM)   med++;
    }
    mvwprintw(pop, ln++, 3, "  Total alerts     : %u  (CRIT:%u  HIGH:%u  MED:%u)",
              d->alert_count, crit, high, med);

    /* network */
    u32 susp_nodes = 0;
    for (u32 i = 0; i < NET_MAX_NODES; i++)
        if (d->nodes[i].suspicious) susp_nodes++;
    wattron(pop, COLOR_PAIR(CP_MEDIUM));
    mvwprintw(pop, ln++, 3, "  Network nodes    : %u  (suspicious: %u)",
              d->node_count, susp_nodes);

    /* generator state */
    bool paused = atomic_load(&d->gen_paused);
    wattron(pop, paused ? (COLOR_PAIR(CP_CRITICAL) | A_BOLD) : (COLOR_PAIR(CP_LOW) | A_BOLD));
    mvwprintw(pop, ln++, 3, "  Generator        : %s  [p]=toggle",
              paused ? "PAUSED" : "RUNNING");

    /* event rate */
    wattron(pop, COLOR_PAIR(CP_DIM));
    mvwprintw(pop, ln++, 3, "  Event rate       : ~%u – %u evt/min",
              EVT_PER_SEC_LO * 60, EVT_PER_SEC_HI * 60);

    ln++;
    /* overall verdict */
    bool pass = fps_ok && p99_ok;
    wattron(pop, pass ? (COLOR_PAIR(CP_LOW) | A_BOLD) : (COLOR_PAIR(CP_CRITICAL) | A_BOLD));
    mvwprintw(pop, ln++, 3, "  Overall          : %s",
              pass ? "[ PASS ]  All targets met" : "[ FAIL ]  Check FPS / p99");

    wattroff(pop, A_BOLD);
    wnoutrefresh(pop);
    doupdate();
    delwin(pop);
}

/* =========================================================================
 * Layout: create / resize all windows to fit terminal
 * ====================================================================== */
static void layout_windows(void) {
    Dashboard *d = &g_dash;
    getmaxyx(stdscr, d->term_rows, d->term_cols);

    int rows = d->term_rows;
    int cols = d->term_cols;

    /* Minimum size guard */
    if (rows < 24 || cols < 80) {
        clear();
        mvprintw(0, 0, "Terminal too small: need at least 80x24 (got %dx%d)", cols, rows);
        refresh();
        return;
    }

    /* Delete old windows */
    if (d->w_header) { delwin(d->w_header); d->w_header = NULL; }
    if (d->w_log)    { delwin(d->w_log);    d->w_log    = NULL; }
    if (d->w_threat) { delwin(d->w_threat); d->w_threat = NULL; }
    if (d->w_net)    { delwin(d->w_net);    d->w_net    = NULL; }
    if (d->w_stats)  { delwin(d->w_stats);  d->w_stats  = NULL; }

    /* Row allocations:
     *   header  : 1 row
     *   body    : rows - 3   (split: left = log+net, right = threats)
     *   stats   : 1 row
     *   borders : 1 row
     */
    int hdr_h   = 1;
    int stats_h = 1;
    int body_h  = rows - hdr_h - stats_h;

    /* Vertical split: left 60%, right 40% */
    int left_w  = (cols * 60) / 100;
    int right_w = cols - left_w;

    /* Left side: log panel on top (60% height), net graph below (40%) */
    int log_h = (body_h * 60) / 100;
    int net_h = body_h - log_h;

    d->w_header = newwin(hdr_h,   cols,    0,        0);
    d->w_log    = newwin(log_h,   left_w,  hdr_h,    0);
    d->w_net    = newwin(net_h,   left_w,  hdr_h + log_h, 0);
    d->w_threat = newwin(body_h,  right_w, hdr_h,    left_w);
    d->w_stats  = newwin(stats_h, cols,    rows - 1, 0);
}

/* =========================================================================
 * Signal handler
 * ====================================================================== */
static void handle_sigwinch(int sig) {
    (void)sig;
    /* terminal resize – re-layout on next frame */
    endwin();
    refresh();
    clear();
}

/* =========================================================================
 * Main
 * ====================================================================== */
int main(void) {
    Dashboard *d = &g_dash;
    memset(d, 0, sizeof(*d));

    /* Init network graph with precomputed positions */
    net_init();

    /* Init ncurses */
    initscr();
    cbreak();
    noecho();
    keypad(stdscr, TRUE);
    nodelay(stdscr, TRUE);   /* non-blocking getch */
    curs_set(0);             /* hide cursor */

    if (!has_colors()) {
        endwin();
        fprintf(stderr, "Terminal has no color support.\n");
        return 1;
    }
    init_colors();

    signal(SIGWINCH, handle_sigwinch);

    /* Initial layout */
    layout_windows();

    /* Start generator thread */
    atomic_store(&d->gen_running, true);
    atomic_store(&d->quit, false);
    GenCtx gen_ctx = {.d = d};
    pthread_create(&d->gen_thread, NULL, gen_thread_fn, &gen_ctx);

    /* Main loop */
    u64 last_ts = now_ns();
    u64 last_fps_ts = last_ts;
    u32 fps_frames  = 0;

    while (!atomic_load(&d->quit)) {
        u64 frame_start = now_ns();

        /* Input */
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
        if (ch == KEY_RESIZE) {
            endwin();
            refresh();
            clear();
            layout_windows();
        }

        /* Drain task queue */
        task_drain(&d->tasks);

        /* Compute dt & FPS */
        u64 ts_now = now_ns();
        f64 dt_ns = (f64)(ts_now - last_ts);
        last_ts = ts_now;
        fps_frames++;

        f64 elapsed_fps = (f64)(ts_now - last_fps_ts) * 1e-9;
        if (elapsed_fps >= 0.5) {
            d->last_fps  = (f32)((f64)fps_frames / elapsed_fps);
            last_fps_ts  = ts_now;
            fps_frames   = 0;
            d->last_p99_ms = compute_p99();
        }

        /* Record frame time */
        if (d->frame_count > 0) {
            d->frame_times[d->frame_idx % 300] = (u64)dt_ns;
            d->frame_idx++;
        }
        d->frame_count++;

        /* Re-render ASCII network canvas once per frame */
        net_render_canvas();

        /* Render all panels */
        if (d->w_header) render_header();
        if (d->w_log)    render_log();
        if (d->w_threat) render_threats();
        if (d->w_net)    render_network();
        if (d->w_stats)  render_stats();

        /* Stats overlay draws on top of everything */
        render_stats_overlay();

        /* Batch refresh */
        doupdate();

        /* Frame budget sleep */
        u64 frame_elapsed_us = (now_ns() - frame_start) / 1000;
        if (frame_elapsed_us < (u64)FRAME_US) {
            usleep((useconds_t)(FRAME_US - frame_elapsed_us));
        }
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

    /* Final report to stdout */
    printf("\n=== SilverCore SOC Dashboard – Session Stats ===\n");
    printf("  Frames rendered : %llu\n", (unsigned long long)d->frame_count);
    printf("  Final FPS       : %.1f\n", (double)d->last_fps);
    printf("  p99 frame time  : %.2f ms  %s\n",
           d->last_p99_ms,
           d->last_p99_ms < 20.0 ? "[PASS]" : "[FAIL]");
    printf("  Total alerts    : %u\n", d->alert_count);
    printf("  Log ring writes : %llu\n",
           (unsigned long long)atomic_load(&d->log_write));
    printf("================================================\n");
    return 0;
}
