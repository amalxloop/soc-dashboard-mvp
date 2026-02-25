/*
 * render.c -- SilverCore SOC Dashboard: ncurses panel renderers + layout
 */
#include "render.h"
#include "types.h"
#include "rng.h"

#include <ncurses.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdatomic.h>
#include <time.h>

/* =========================================================================
 * Clock
 * ====================================================================== */
static u64 now_ns(void) {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (u64)ts.tv_sec * 1000000000ULL + (u64)ts.tv_nsec;
}

/* =========================================================================
 * Color init
 * ====================================================================== */
void init_colors(void) {
    start_color();
    use_default_colors();
    init_pair(CP_NORMAL,    COLOR_WHITE,  -1);
    init_pair(CP_INFO,      COLOR_CYAN,   -1);
    init_pair(CP_LOW,       COLOR_GREEN,  -1);
    init_pair(CP_MEDIUM,    COLOR_YELLOW, -1);
    init_pair(CP_HIGH,      COLOR_RED,    COLOR_BLACK);
    init_pair(CP_CRITICAL,  COLOR_WHITE,  COLOR_RED);
    init_pair(CP_HEADER,    COLOR_CYAN,   COLOR_BLUE);
    init_pair(CP_BORDER,    COLOR_CYAN,   -1);
    init_pair(CP_TITLE,     COLOR_WHITE,  COLOR_BLUE);
    init_pair(CP_DIM,       COLOR_WHITE,  -1);
    init_pair(CP_NET_NODE,  COLOR_CYAN,   -1);
    init_pair(CP_NET_EXT,   COLOR_GREEN,  -1);
    init_pair(CP_NET_SUSP,  COLOR_WHITE,  COLOR_RED);
    init_pair(CP_ALERT_HI,  COLOR_RED,    COLOR_BLACK);
    init_pair(CP_ALERT_CR,  COLOR_WHITE,  COLOR_RED);
    init_pair(CP_STATS,     COLOR_GREEN,  COLOR_BLACK);
    init_pair(CP_CANVAS_BG, COLOR_BLUE,   -1);
}

/* =========================================================================
 * Layout
 * ====================================================================== */
void layout_windows(void) {
    Dashboard *d = &g_dash;
    getmaxyx(stdscr, d->term_rows, d->term_cols);

    int rows = d->term_rows;
    int cols = d->term_cols;

    if (rows < 24 || cols < 80) {
        clear();
        mvprintw(0, 0, "Terminal too small: need at least 80x24 (got %dx%d)", cols, rows);
        refresh();
        return;
    }

    if (d->w_header) { delwin(d->w_header); d->w_header = NULL; }
    if (d->w_log)    { delwin(d->w_log);    d->w_log    = NULL; }
    if (d->w_threat) { delwin(d->w_threat); d->w_threat = NULL; }
    if (d->w_net)    { delwin(d->w_net);    d->w_net    = NULL; }
    if (d->w_stats)  { delwin(d->w_stats);  d->w_stats  = NULL; }

    int hdr_h   = 1;
    int stats_h = 1;
    int body_h  = rows - hdr_h - stats_h;
    int left_w  = (cols * 60) / 100;
    int right_w = cols - left_w;
    int log_h   = (body_h * 60) / 100;
    int net_h   = body_h - log_h;

    d->w_header = newwin(hdr_h,   cols,    0,             0);
    d->w_log    = newwin(log_h,   left_w,  hdr_h,         0);
    d->w_net    = newwin(net_h,   left_w,  hdr_h + log_h, 0);
    d->w_threat = newwin(body_h,  right_w, hdr_h,         left_w);
    d->w_stats  = newwin(stats_h, cols,    rows - 1,      0);

    if (!d->w_header || !d->w_log || !d->w_net || !d->w_threat || !d->w_stats) {
        clear();
        if (!d->w_header) mvprintw(0, 0, "[warn] header window allocation failed");
        refresh();
    }
}

/* =========================================================================
 * Shared helper: draw titled border
 * ====================================================================== */
static void draw_box_title(WINDOW *win, const char *title,
                            int cp_border, int cp_title) {
    wattron(win, COLOR_PAIR(cp_border));
    box(win, 0, 0);
    wattroff(win, COLOR_PAIR(cp_border));

    int w    = getmaxx(win);
    int tlen = (int)strlen(title);
    int tx   = (w - tlen - 4) / 2;
    if (tx < 1) tx = 1;
    wattron(win, COLOR_PAIR(cp_title) | A_BOLD);
    mvwprintw(win, 0, tx, " %s ", title);
    wattroff(win, COLOR_PAIR(cp_title) | A_BOLD);
}

/* =========================================================================
 * Header bar
 * ====================================================================== */
void render_header(void) {
    Dashboard *d = &g_dash;
    WINDOW *w = d->w_header;
    werase(w);

    wattron(w, COLOR_PAIR(CP_HEADER) | A_BOLD);
    int cols = getmaxx(w);
    for (int i = 0; i < cols; i++) mvwaddch(w, 0, i, ' ');
    mvwprintw(w, 0, 2, "[ SilverCore SOC Dashboard MVP ]");
    wattroff(w, COLOR_PAIR(CP_HEADER) | A_BOLD);

    wattron(w, COLOR_PAIR(CP_LOW) | A_BOLD);
    mvwprintw(w, 0, 36, "FPS:%-4.0f", (double)d->last_fps);
    wattroff(w, COLOR_PAIR(CP_LOW) | A_BOLD);

    int p99_cp = d->last_p99_ms < 10.0 ? CP_LOW :
                 d->last_p99_ms < 20.0 ? CP_MEDIUM : CP_CRITICAL;
    wattron(w, COLOR_PAIR(p99_cp) | A_BOLD);
    mvwprintw(w, 0, 45, "p99:%.2fms", d->last_p99_ms);
    wattroff(w, COLOR_PAIR(p99_cp) | A_BOLD);

    u32 ring_fill = atomic_load(&d->log_write) & LOG_RING_MASK;
    wattron(w, COLOR_PAIR(CP_INFO));
    mvwprintw(w, 0, 56, "Ring:%u/%u", ring_fill, LOG_RING_SIZE);
    wattroff(w, COLOR_PAIR(CP_INFO));

    wattron(w, COLOR_PAIR(CP_MEDIUM));
    mvwprintw(w, 0, cols - 18, "Q:%-4u Events:%-6llu",
              task_depth(&d->tasks),
              (unsigned long long)atomic_load(&d->log_write));
    wattroff(w, COLOR_PAIR(CP_MEDIUM));

    wnoutrefresh(w);
}

/* =========================================================================
 * Live Log Stream
 * ====================================================================== */
void render_log(void) {
    Dashboard *d = &g_dash;
    WINDOW *w = d->w_log;
    int rows = getmaxy(w);
    int cols = getmaxx(w);
    werase(w);
    draw_box_title(w, "LIVE LOG STREAM", CP_BORDER, CP_TITLE);

    wattron(w, COLOR_PAIR(CP_DIM) | A_UNDERLINE);
    mvwprintw(w, 1, 2, "%-8s %-15s %-15s %-12s %-8s",
              "AGE(s)", "SRC IP", "DST IP", "EVENT", "SEV");
    wattroff(w, COLOR_PAIR(CP_DIM) | A_UNDERLINE);

    int visible = rows - 3;
    if (visible > LOG_VISIBLE_ROWS) visible = LOG_VISIBLE_ROWS;
    if (visible < 1) return;

    u64 now    = now_ns();
    u32 write_pos = atomic_load(&d->log_write);

    for (int row = 0; row < visible; row++) {
        u32 offset   = (u32)(visible - 1 - row);
        u32 idx      = (write_pos - offset - 1) & LOG_RING_MASK;
        LogEvent *ev = &d->log_ring[idx];
        if (ev->ts_ns == 0) continue;

        f64 age = (f64)(now - ev->ts_ns) * 1e-9;
        if (age < 0.0) age = 0.0;

        int display_row = row + 2;
        if (display_row >= rows - 1) break;

        if (ev->sev == SEV_CRITICAL) {
            wattron(w, COLOR_PAIR(CP_CRITICAL) | A_BOLD);
        } else if (ev->sev == SEV_HIGH) {
            wattron(w, COLOR_PAIR(CP_HIGH) | A_BOLD);
        } else {
            wattron(w, COLOR_PAIR(CP_NORMAL));
        }

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

        wattron(w, COLOR_PAIR(sev_cp[ev->sev]) | A_BOLD);
        mvwprintw(w, display_row, cols - 10, "%-8s", k_sev_name[ev->sev]);
        wattroff(w, COLOR_PAIR(sev_cp[ev->sev]) | A_BOLD);
    }

    wnoutrefresh(w);
}

/* =========================================================================
 * Active Threat Panel
 * ====================================================================== */
void render_threats(void) {
    Dashboard *d = &g_dash;
    WINDOW *w = d->w_threat;
    int rows = getmaxy(w);
    int cols = getmaxx(w);
    werase(w);
    draw_box_title(w, "ACTIVE THREATS", CP_ALERT_HI, CP_ALERT_CR);

    wattron(w, COLOR_PAIR(CP_MEDIUM) | A_BOLD);
    mvwprintw(w, 1, 2, "Total alerts: %-4u", d->alert_count);
    wattroff(w, COLOR_PAIR(CP_MEDIUM) | A_BOLD);

    wattron(w, COLOR_PAIR(CP_DIM) | A_UNDERLINE);
    mvwprintw(w, 2, 2, "%-6s %-8s %-22s %-8s", "#ID", "SEV", "DESCRIPTION", "AGE");
    wattroff(w, COLOR_PAIR(CP_DIM) | A_UNDERLINE);

    u64 now    = now_ns();
    int visible = rows - 4;
    if (visible > THREAT_VISIBLE) visible = THREAT_VISIBLE;
    if (visible < 1) return;

    u32 shown = d->alert_count < (u32)visible ? d->alert_count : (u32)visible;
    for (u32 r = 0; r < shown; r++) {
        Alert *al = &d->alerts[r];
        int display_row = (int)r + 3;
        if (display_row >= rows - 1) break;

        bool flashing = al->flash_frames > 0;
        if (flashing) al->flash_frames--;

        int cp = (al->sev == SEV_CRITICAL) ? CP_ALERT_CR :
                 (al->sev == SEV_HIGH)     ? CP_ALERT_HI : CP_MEDIUM;
        attr_t attrs = COLOR_PAIR(cp) | (flashing ? A_REVERSE | A_BOLD : A_NORMAL);
        wattron(w, attrs);

        for (int c = 1; c < cols - 1; c++) mvwaddch(w, display_row, c, ' ');

        u64 age_ns = now - al->detected_ns;
        char age_buf[16];
        if (age_ns < 1000000000ULL)
            snprintf(age_buf, sizeof(age_buf), "%llums",
                     (unsigned long long)(age_ns / 1000000));
        else
            snprintf(age_buf, sizeof(age_buf), "%llus",
                     (unsigned long long)(age_ns / 1000000000));

        char desc_trunc[23];
        snprintf(desc_trunc, sizeof(desc_trunc), "%s", al->desc);

        mvwprintw(w, display_row, 2, "#%-5u %-8s %-22s %-8s",
                  al->id, k_sev_name[al->sev], desc_trunc, age_buf);

        wattroff(w, attrs);
    }

    wnoutrefresh(w);
}

/* =========================================================================
 * Network Graph
 * ====================================================================== */
void render_network(void) {
    Dashboard *d = &g_dash;
    WINDOW *w = d->w_net;
    int rows = getmaxy(w);
    int cols = getmaxx(w);
    werase(w);
    draw_box_title(w, "NETWORK GRAPH  [h=host e=ext X=suspicious]",
                   CP_BORDER, CP_TITLE);

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

    u32 susp_nodes = 0, susp_edges = 0;
    for (u32 i = 0; i < d->node_count; i++) if (d->nodes[i].suspicious) susp_nodes++;
    for (u32 i = 0; i < d->edge_count; i++) if (d->edges[i].suspicious) susp_edges++;
    wattron(w, COLOR_PAIR(CP_INFO));
    mvwprintw(w, 1, cols - 28,
              "suspicious: %u nodes / %u edges", susp_nodes, susp_edges);
    wattroff(w, COLOR_PAIR(CP_INFO));

    int can_start_row = 2;
    int can_start_col = 2;
    int can_rows = rows - 3;
    int can_cols = cols - 4;
    if (can_rows < 1 || can_cols < 1) { wnoutrefresh(w); return; }

    for (int r = 0; r < NET_ROWS && r < can_rows; r++) {
        for (int c = 0; c < NET_COLS && c < can_cols; c++) {
            char ch   = d->canvas[r][c];
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

/* =========================================================================
 * Stats bar (bottom row)
 * ====================================================================== */
void render_stats(void) {
    Dashboard *d = &g_dash;
    WINDOW *w = d->w_stats;
    int cols = getmaxx(w);
    werase(w);

    wattron(w, COLOR_PAIR(CP_STATS) | A_BOLD);
    for (int c = 0; c < cols; c++) mvwaddch(w, 0, c, ' ');
    mvwaddch(w, 0, 0, ACS_HLINE);

    int x = 1;
    mvwprintw(w, 0, x, " FPS:%.0f ", (double)d->last_fps);
    x += 10;

    int p99_cp = d->last_p99_ms < 10.0 ? CP_LOW :
                 d->last_p99_ms < 20.0 ? CP_MEDIUM : CP_CRITICAL;
    wattroff(w, COLOR_PAIR(CP_STATS) | A_BOLD);
    wattron(w, COLOR_PAIR(p99_cp) | A_BOLD);
    mvwprintw(w, 0, x, " p99:%.2fms ", d->last_p99_ms);
    x += 14;
    wattroff(w, COLOR_PAIR(p99_cp) | A_BOLD);

    u32 ring_fill = atomic_load(&d->log_write) & LOG_RING_MASK;
    wattron(w, COLOR_PAIR(CP_INFO) | A_BOLD);
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

    wattron(w, COLOR_PAIR(CP_INFO));
    mvwprintw(w, 0, x, " ~%u-%u evt/min ",
              EVT_PER_SEC_LO * 60, EVT_PER_SEC_HI * 60);

    bool pass = d->last_fps >= 55.0f && d->last_p99_ms < 20.0;
    wattron(w, pass ? (COLOR_PAIR(CP_LOW) | A_BOLD) : (COLOR_PAIR(CP_CRITICAL) | A_BOLD));
    mvwprintw(w, 0, cols - 10, pass ? " [PASS] " : " [FAIL] ");
    wattroff(w, A_BOLD);

    wnoutrefresh(w);
}

/* =========================================================================
 * Stats overlay popup ('s' toggles)
 * ====================================================================== */
void render_stats_overlay(void) {
    Dashboard *d = &g_dash;
    if (!d->stats_overlay) return;

    int rows = d->term_rows;
    int cols = d->term_cols;

    int pop_h = 18;
    int pop_w = 60;
    int pop_y = (rows - pop_h) / 2;
    int pop_x = (cols - pop_w) / 2;
    if (pop_y < 0) pop_y = 0;
    if (pop_x < 0) pop_x = 0;

    WINDOW *pop = newwin(pop_h, pop_w, pop_y, pop_x);
    if (!pop) return;

    wbkgd(pop, COLOR_PAIR(CP_NORMAL));
    wattron(pop, COLOR_PAIR(CP_BORDER) | A_BOLD);
    box(pop, 0, 0);

    wattron(pop, COLOR_PAIR(CP_TITLE) | A_BOLD | A_REVERSE);
    mvwprintw(pop, 0, (pop_w - 28) / 2, "  SESSION STATS  [s]=close  ");
    wattroff(pop, A_REVERSE);

    int ln = 2;

    bool fps_ok = d->last_fps >= 55.0f;
    wattron(pop, fps_ok ? COLOR_PAIR(CP_LOW) : COLOR_PAIR(CP_CRITICAL));
    mvwprintw(pop, ln++, 3, "  FPS              : %.1f %s",
              (double)d->last_fps, fps_ok ? "[OK]" : "[LOW]");

    bool p99_ok = d->last_p99_ms < 20.0;
    wattron(pop, p99_ok ? COLOR_PAIR(CP_LOW) : COLOR_PAIR(CP_CRITICAL));
    mvwprintw(pop, ln++, 3, "  p99 frame time   : %.2f ms %s",
              d->last_p99_ms, p99_ok ? "[PASS]" : "[FAIL]");

    wattron(pop, COLOR_PAIR(CP_INFO));
    mvwprintw(pop, ln++, 3, "  Frames rendered  : %llu",
              (unsigned long long)d->frame_count);

    u32 log_write = atomic_load(&d->log_write);
    u32 ring_fill = log_write & LOG_RING_MASK;
    f32 ring_pct  = (f32)ring_fill / LOG_RING_SIZE * 100.0f;
    wattron(pop, COLOR_PAIR(CP_MEDIUM));
    mvwprintw(pop, ln++, 3, "  Log ring fill    : %u / %u  (%.1f%%)",
              ring_fill, LOG_RING_SIZE, (double)ring_pct);
    mvwprintw(pop, ln++, 3, "  Total log writes : %u", log_write);

    wattron(pop, COLOR_PAIR(CP_INFO));
    mvwprintw(pop, ln++, 3, "  Task queue depth : %u", task_depth(&d->tasks));

    wattron(pop, COLOR_PAIR(CP_HIGH));
    u32 crit = 0, high = 0, med = 0;
    for (u32 i = 0; i < d->alert_count && i < THREAT_MAX; i++) {
        if      (d->alerts[i].sev == SEV_CRITICAL) crit++;
        else if (d->alerts[i].sev == SEV_HIGH)     high++;
        else if (d->alerts[i].sev == SEV_MEDIUM)   med++;
    }
    mvwprintw(pop, ln++, 3, "  Total alerts     : %u  (CRIT:%u  HIGH:%u  MED:%u)",
              d->alert_count, crit, high, med);

    u32 susp_nodes = 0;
    for (u32 i = 0; i < NET_MAX_NODES; i++)
        if (d->nodes[i].suspicious) susp_nodes++;
    wattron(pop, COLOR_PAIR(CP_MEDIUM));
    mvwprintw(pop, ln++, 3, "  Network nodes    : %u  (suspicious: %u)",
              d->node_count, susp_nodes);

    bool paused = atomic_load(&d->gen_paused);
    wattron(pop, paused ? (COLOR_PAIR(CP_CRITICAL) | A_BOLD)
                        : (COLOR_PAIR(CP_LOW)      | A_BOLD));
    mvwprintw(pop, ln++, 3, "  Generator        : %s  [p]=toggle",
              paused ? "PAUSED" : "RUNNING");

    wattron(pop, COLOR_PAIR(CP_DIM));
    mvwprintw(pop, ln++, 3, "  Event rate       : ~%u - %u evt/min",
              EVT_PER_SEC_LO * 60, EVT_PER_SEC_HI * 60);

    ln++;
    bool pass = fps_ok && p99_ok;
    wattron(pop, pass ? (COLOR_PAIR(CP_LOW) | A_BOLD) : (COLOR_PAIR(CP_CRITICAL) | A_BOLD));
    mvwprintw(pop, ln++, 3, "  Overall          : %s",
              pass ? "[ PASS ]  All targets met" : "[ FAIL ]  Check FPS / p99");

    wattroff(pop, A_BOLD);
    wnoutrefresh(pop);
    doupdate();
    delwin(pop);
}
