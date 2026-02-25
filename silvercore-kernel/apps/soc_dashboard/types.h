/*
 * types.h -- SilverCore SOC Dashboard: shared types, constants, domain structs
 */
#pragma once

#include <stdint.h>
#include <stdbool.h>
#include <stdatomic.h>

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
 * Compile-time constants (upper bounds / defaults)
 * ====================================================================== */
#define TARGET_FPS          60
#define FRAME_US            (1000000 / TARGET_FPS)

#define LOG_RING_SIZE       8192
#define LOG_RING_MASK       (LOG_RING_SIZE - 1)
#define LOG_VISIBLE_ROWS    20

#define THREAT_MAX          32
#define THREAT_VISIBLE      12

#define NET_MAX_NODES       100
#define NET_MAX_EDGES       200
#define NET_COLS            42
#define NET_ROWS            16

#define EVT_PER_SEC_LO      84
#define EVT_PER_SEC_HI      333

/* =========================================================================
 * Runtime configuration (populated by parse_args, read-only after that)
 * ====================================================================== */
typedef struct {
    u32 log_ring_size;   /* --log-size   N  (power of 2, default LOG_RING_SIZE) */
    u32 threat_max;      /* --threat-max N  (default THREAT_MAX)                */
    u32 net_nodes;       /* --nodes      N  (max NET_MAX_NODES, default 100)    */
    u32 fps_cap;         /* --fps-cap    N  (default TARGET_FPS)                */
} Config;

extern Config g_cfg;

/* =========================================================================
 * Domain enums
 * ====================================================================== */
typedef enum {
    SEV_INFO = 0, SEV_LOW, SEV_MEDIUM, SEV_HIGH, SEV_CRITICAL, SEV_COUNT
} Severity;

typedef enum {
    EVT_PORT_SCAN = 0, EVT_BRUTE_FORCE, EVT_SQL_INJECT, EVT_XSS,
    EVT_DDOS, EVT_PRIV_ESC, EVT_LATERAL, EVT_EXFIL, EVT_MALWARE, EVT_RECON,
    EVT_TYPE_COUNT
} EvtType;

extern const char *k_sev_name[SEV_COUNT];
extern const char *k_evt_name[EVT_TYPE_COUNT];

/* =========================================================================
 * ncurses color pair IDs
 * ====================================================================== */
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

extern int sev_cp[SEV_COUNT];

/* =========================================================================
 * Domain structs
 * ====================================================================== */
typedef struct {
    u64      ts_ns;
    char     src[16];
    char     dst[16];
    EvtType  type;
    Severity sev;
} LogEvent;

typedef struct {
    u32      id;
    Severity sev;
    char     desc[48];
    u64      detected_ns;
    bool     active;
    i32      flash_frames;
} Alert;

typedef struct {
    f32  x, y;
    bool suspicious;
    bool external;
} NetNode;

typedef struct {
    u32  a, b;
    bool suspicious;
} NetEdge;
