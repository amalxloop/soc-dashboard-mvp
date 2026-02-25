# SilverSoc MVP

A proof-of-concept SOC (Security Operations Centre) dashboard built on top of the **SilverCore UI** engine. Written entirely in pure C with a live ncurses terminal GUI.

## What is this?

SilverSoc MVP demonstrates the SilverCore UI framework applied to a real-world security operations use case. It simulates a live SOC environment, ingesting log events, tracking active threats, visualising a network topology, and rendering everything at a target of 60 fps inside a standard terminal window.

This is a POC. There is no real network traffic or SIEM backend; all events are synthetically generated to stress-test the rendering pipeline and validate the SilverCore UI primitives under load.

## Architecture

```
silvercore-kernel/
└── apps/
    └── soc_dashboard/
        └── soc_dashboard.c     # entire dashboard, ~1100 lines, pure C11
```

Everything lives in a single translation unit on top of the kernel headers:

| Component | Role |
|---|---|
| **Event generator** | Background pthread producing log events and alerts at a configurable rate |
| **Log ring buffer** | Lock-free SPSC ring; holds the last 8192 log entries |
| **Threat tracker** | Fixed-size alert table sorted by severity; flash-animates new arrivals |
| **Network graph** | 100-node, 200-edge adjacency list rendered as ASCII canvas |
| **Renderer** | ncurses-based; 4 panels + status bar, dirty-flag updates, 60 fps rAF loop |
| **Stats overlay** | On-demand popup showing session metrics and a PASS/FAIL verdict |

---

## Building

Requires: `gcc` (or `clang`), `cmake >= 3.16`, `ncurses-devel`

```bash
cmake -S silvercore-kernel -B silvercore-kernel/build -DCMAKE_BUILD_TYPE=Release -DSC_TESTS=OFF
cmake --build silvercore-kernel/build --target soc_dashboard -j$(nproc)
```

---

## Running

```bash
./silvercore-kernel/build/soc_dashboard
```

Terminal must be at least **120 columns × 40 rows** for the full layout. Resize the window before launching for best results.

---

## Controls

| Key | Action |
|---|---|
| `s` | Toggle session stats overlay |
| `p` | Pause / resume the event generator |
| `q` | Quit (final session report printed to stdout) |

---

## Dashboard Layout

```
┌─[ SilverCore SOC Dashboard ]────────────────────────────────────────────────┐
│  FPS: 60.0   p99: 3.4ms [PASS]   Ring: 1024/8192   Queue: 0   Alerts: 12   │
├─────────────────────────────────────────────┬───────────────────────────────┤
│  LIVE LOG STREAM                            │  ACTIVE THREATS               │
│  AGE   SRC IP           DST IP      EVENT  │  #01  CRITICAL  Lateral Move  │
│  ...                                        │  #02  HIGH      Port Scan     │
├─────────────────────────────────────────────┤  ...                          │
│  NETWORK GRAPH  (100 nodes, 200 edges)      │                               │
│  h . e . h . X . h . e ...                 │                               │
└─────────────────────────────────────────────┴───────────────────────────────┘
│  FPS: 60.0  p99: 3.40ms [PASS]  Ring: 12%  Queue: 0  Alerts: 12  Frame: 360│
└─────────────────────────────────────────────────────────────────────────────┘
```

**Panel key:**

| Symbol / Colour | Meaning |
|---|---|
| `h` cyan | Internal host node |
| `e` green | External node |
| `X` white-on-red | Suspicious node |
| `.` | Network edge midpoint |
| Red row | CRITICAL severity log or alert |
| Amber row | HIGH severity |

---

## Session Stats Overlay (`s`)

Press `s` to open a centred popup showing:

- Live FPS and p99 frame time with PASS/FAIL verdict
- Total frames rendered
- Log ring fill percentage and total writes
- Task queue depth
- Alert breakdown by severity (CRITICAL / HIGH / MEDIUM / LOW)
- Suspicious network node count
- Generator state (RUNNING / PAUSED)

---

## Performance Targets

| Metric | Target | Typical |
|---|---|---|
| Frame rate | 60 fps | 59–60 fps |
| p99 frame time | < 20 ms | 3–5 ms |
| Log ring size | 8192 entries | |
| Network nodes | 100 | |
| Network edges | 200 | |

---

## SilverCore UI: POC Notes

**SilverCore Kernel:** [https://github.com/amalxloop/silvercore-kernel](https://github.com/amalxloop/silvercore-kernel)

SilverCore is a software-rasterised UI kernel designed for embedded and systems-level environments where no window system is available. Its primitives (arena allocator, dirty-flag widget tree, ring buffers, fixed-size layout engine) are proven here against a continuous-update workload representative of a real SOC feed.

Key findings from this POC:

- The arena allocator eliminates per-frame heap pressure entirely.
- Dirty-flag rendering keeps ncurses `refresh()` calls sub-millisecond even at 100 nodes.
- The lock-free SPSC ring sustains >200 events/sec without blocking the render thread.
- p99 frame time stays well under the 20 ms budget on a single core.
