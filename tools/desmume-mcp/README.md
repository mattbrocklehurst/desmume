# desmume-mcp

Tools for taking Nintendo DS games apart, and for testing against them, with
an AI agent (or by hand):

- **an MCP server** that lets Claude (or any MCP client) drive DeSmuME: play,
  pause, step frames, set breakpoints and watchpoints, read and search
  memory, disassemble with your labels, trace file loads, allocations, input
  and 3D commands, profile, and freeze the game into a dump for later;
- **a debugger toolkit** underneath it (Python), usable from scripts;
- **an oracle test runner** for using the original game as the reference
  implementation for a port: scripted and recorded input, frame-exact and
  deterministic replays, probes and assertions, headless on CI.

Everything talks to a modified `desmume-cli` (this repository) over two local
TCP ports: its gdb stub and a small control interface.

```
 Claude / MCP client ──stdio──> desmume_mcp.server ──┬─ gdb RSP ──> desmume-cli gdb stub (ARM9/ARM7)
 your scripts / CI ───────────> desmume_mcp.oracle ──┴─ control ──> desmume-cli control port
 gdb-multiarch (optional) ─────────────────────────── gdb RSP ──> (after dbg_detach)
```

Contents:

- [Setup](#setup)
- [Connecting Claude](#connecting-claude)
- [What you can do](#what-you-can-do) (workflows)
- [Oracle testing](docs/ORACLE.md) (separate document)
- [Tool reference](docs/TOOLS.md) (generated)
- [Control protocol](docs/PROTOCOL.md) (for scripting without Python)
- [Data directory](#data-directory), [Tests](#tests), [Limitations](#limitations)

## Setup

1. Build `desmume-cli` with the gdb stub (Debian/Ubuntu packages shown):

   ```sh
   sudo apt install meson ninja-build g++ pkg-config libsdl2-dev libglib2.0-dev \
                    libpcap-dev zlib1g-dev libx11-dev
   tools/desmume-mcp/scripts/build-desmume.sh
   ```

   The binary lands in `desmume/src/frontend/posix/build/cli/desmume-cli`,
   which is where the tools look first. Set `DESMUME_CLI` to use another one.

2. Install the Python side (Python 3.10+):

   ```sh
   pip install -e tools/desmume-mcp        # pulls in mcp and capstone
   ```

   Optional: `ffmpeg` (video recording), `gdb-multiarch` (manual debugging).

3. Try it without an agent:

   ```sh
   cd tools/desmume-mcp
   python3 scripts/e2e_test.py             # 80+ checks against the bundled test game
   ```

## Connecting Claude

Claude Code:

```sh
claude mcp add desmume -- desmume-mcp
# or, without pip install:
claude mcp add desmume -e PYTHONPATH=/path/to/desmume/tools/desmume-mcp -- python3 -m desmume_mcp
```

Other clients: run `desmume-mcp` (stdio transport). For example in a
`.mcp.json`:

```json
{ "mcpServers": { "desmume": { "command": "desmume-mcp" } } }
```

Then ask for things like *"start zelda.nds and find where Link's position is
stored"*. The server gives the agent an overview of the workflows; the full
list is in [docs/TOOLS.md](docs/TOOLS.md).

On a desktop the emulator opens a window, so you can play while the agent
watches and pokes. You can use the keyboard (x/z = A/B, arrows, Enter =
Start, Right Shift = Select, q/w = L/R, a/s = Y/X), plus two extra keys:
**F11** pauses and **F12** freezes the game into a dump. Without a display it
runs headless.

## What you can do

The examples use the bundled test game (`testgame/`, see below), whose
symbols are in `testgame/testgame.sym`. With a retail game you build that
symbol table yourself as you go (`label_set`).

### Play, pause, step, look

`emu_screenshot`, `emu_press(["a"], frames=4)`, `emu_touch(x, y)`,
`emu_pause`, `emu_frame_advance(1)`, savestates (`emu_savestate`), input
movies (`emu_movie`) and video (`emu_video`).

### Find a variable (value scanning)

The cheat-finder loop: `mem_scan_start(size=4, value=50)`, change the value
in game (take damage), `mem_scan_next("eq", 43)`. Repeat until one address is
left, then `label_set("0x02...", "player_hp", type="data")`.

### Find the code that touches it (watchpoints)

`dbg_watch("player_hp", 4, "write")`, play until it changes, and the report
shows the instruction that wrote it and the code around it. Watchpoints stop
right after the accessing instruction, the report names that instruction,
and `dbg_backtrace` walks the call stack.

### Breakpoints, stepping, tracing

`dbg_break(addr, condition="r0 == 5 and u16(r1+4) > 100")`, `dbg_step`,
`dbg_step(over=True)`, `dbg_finish`, `dbg_run_to`. `dbg_trace(addr)` logs a
function's arguments per call and `func_trace` does the same without
stopping (with return values). The debugger can be handed to your own gdb
with `dbg_detach` (see `desmume/src/gdbstub/README.md`).

### "Which file is this and who loaded it?" (asset tracing)

```
asset_trace_start()
... play: enter a room, open a menu ...
asset_report()
```

For every file load: the frame, the file name from the ROM's file system
(opaque names like `a.dat` included), how many bytes, **where it landed in
RAM**, **which allocation owns that buffer** (if `alloc_track` is on), and
**the call path that triggered it**. The report comes with a Mermaid flow
graph (functions → files) and an HTML page with the graph and a table. For
one file, `hook_set("card", "break", file="data/map.bin")` stops the game at
the moment it's read.

### Allocations: who allocates what, when, and what leaks

Find the allocator: it has many callers and returns a pointer (`func_list`,
`func_info`, or a watchpoint on a heap header). Then:

```
alloc_track("sub_02012345", "sub_02012400", size_arg="r1", free_ptr_arg="r1")
... play ...
alloc_report("summary")     # totals, peak, busiest call sites
alloc_report("leaks")       # call sites whose blocks pile up without being freed
alloc_report("live")        # everything outstanding right now
alloc_report("owner", address="0x0215a0c0")   # who allocated this buffer?
alloc_report("timeline") / alloc_report("graph")
```

### The 3D side: "how does the 2D tilemap become 3D?"

The DS has no GPU in the modern sense. The ARM9 feeds a fixed-function
geometry engine with commands (matrices, vertices, textures) through a FIFO,
usually by DMA from a display list the game builds in RAM, and
`SWAP_BUFFERS` ends a 3D frame. `gx_capture(frames=1)` records every
command of a frame, decoded (`VTX_16 (-0.5, 0.5, -1.0)`,
`TEXIMAGE_PARAM 64x64 4x4-compressed`, ...), together with **the RAM
address each one was DMA'd from**. So the workflow is:

1. `gx_capture` → the display list lives at, say, `0x0219a000`.
2. `dbg_watch("0x0219a010", 4, "write")` → stops in the function that
   writes vertices.
3. `dbg_backtrace`, `func_info` → that function reads the tilemap. Name it,
   watch the tilemap, repeat.

`hook_set("swap", "log")` / `hook_log` also show the call path of every
frame's `SWAP_BUFFERS`: the game's render loop.

### The game tick, and where the time goes

DS games are bare metal, but almost all commercial ones use Nintendo's SDK
(NitroSDK), which has threads, interrupts and a main loop that sleeps in
`OS_WaitVBlankIntr()` until the next 60 Hz VBlank. So the tick is usually a
function called **once per frame** from the main thread.

- `func_hot(frames=60)` counts calls to every function and lists the ones
  called exactly once per frame (tick/update/render candidates), how they
  nest, the busiest functions, and the IRQ handler.
- `perf_profile(frames=60)` samples the CPU: self time per function, who
  calls it, and the **stacks in use**. Each thread (and the IRQ mode) has
  its own stack, so this is also how you see a game's threads.

### Input: who reads the buttons

`input_trace_start()` then `input_trace_report()`: every input change by
frame, the code that reads `KEYINPUT` with its call path, and ARM7
touch-screen sampling. (On Nitro games X/Y and the touch screen come from the
ARM7 through shared memory.)

### Labelling unknown code (with or without an AI)

The pseudo-C from Ghidra is hard to read because nothing has a name. The
tools make naming systematic, and Claude can do most of the legwork:

- `nitro_scan()` finds SDK version markers and fingerprints every function
  by the hardware registers it touches (card I/O, IPC with the ARM7,
  interrupts, divide unit, DMA, 2D/3D registers). SDK code is statically
  linked but identical within an SDK version, so these low-level functions
  anchor everything above them. `apply=True` labels them.
- `func_list(unlabelled_only=True)` ranks unknown functions by number of
  callers (the most-called are library routines such as memcpy, divide and
  allocators); `func_info(addr)` gives an agent everything needed to name
  one: code, callers, callees, hardware, data and strings.
- Runtime evidence names the rest: what a function is called with
  (`func_trace`), what it touches (`dbg_watch`), and when it runs
  (`func_hot`, `asset_report`, `input_trace_report`).
- `label_set` stores names and comments per game, and they show up
  everywhere. `label_export("ghidra")` writes them for Ghidra's
  `ImportSymbolsScript.py`, so the pseudo-C gets the names too.
  `label_import` reads nm/linker-style symbol lists.

A good way to use this: ask Claude to "label the 30 most-called unlabelled
functions, verifying each with func_info and a trace", then export to
Ghidra.

### Freeze: a crash dump of the game

`freeze_dump(note)` (or **F12** in the window) pauses the game and writes a
directory with main RAM, ITCM/DTCM, shared/ARM7 WRAM, VRAM, palettes, OAM,
I/O registers, both CPUs' registers (banked ones too), a screenshot, a
manifest and **a savestate you can resume from**. Later, memory tools accept
`source="<dump>"`, `dump_info` summarises one (code at pc, call stack), and
`dump_resume` loads it back into the emulator.

### Offline ROM tools

`rom_info`, `rom_files`, `rom_overlays`, `rom_extract` (the ARM9 binary and
overlays come out BLZ-decompressed, ready for Ghidra), and memory tools with
`source="rom:arm9"` / `"rom:overlay:12"` to read code that isn't loaded yet.

### Oracle testing for a port

Record a run while playing (`desmume-oracle record` or `input_record_start`).
The input goes into a frame-indexed text file anchored to a savestate. Replay
it deterministically, run scripted tests with assertions headless on CI, and
feed the same input file to your engine. See **[docs/ORACLE.md](docs/ORACLE.md)**.

## The test game

`testgame/` is a small bare-metal DS program (C, stock `arm-none-eabi-gcc`,
no devkitPro) built to mirror real game structure so every tool can be
checked against known ground truth (`testgame.sym`):

- a player struct driven by input, drawn into a framebuffer,
- a file system reader over the game card (`fs_read_file` →
  `card_read_block`), a tilemap loaded from `data/level1.map`,
- `build_display_list` turns the tilemap into 3D quads that are DMA'd to the
  geometry engine, followed by `SWAP_BUFFERS`,
- an arena allocator and opaque assets (`assets/a.dat` to `d.dat`) loaded at
  boot, on START (level reload, which **leaks** `c.dat` on purpose) and on A,
- two overlays, one BLZ-compressed.

`make -C testgame` rebuilds it (`apt install gcc-arm-none-eabi`); the built
ROM is checked in.

## Data directory

`$DESMUME_MCP_HOME` (default `~/.local/share/desmume-mcp`):

```
labels/<GAMECODE>.json      your labels (edit, diff, version them)
dumps/<GAMECODE>/...        freeze dumps (also where F12 writes)
states/<GAMECODE>/*.dst     named savestates
recordings/<GAMECODE>/      input recordings
reports/                    HTML flow graphs
gx/                         full 3D command captures (JSON)
logs/                       emulator output per session
```

## Tests

```sh
python3 scripts/e2e_test.py          # everything, in-process and over the MCP protocol
python3 scripts/gen_tool_docs.py     # regenerate docs/TOOLS.md (--check in CI)
```

## Limitations

- Hooks, tracepoints, the profiler and breakpoints rely on the gdb stub's
  memory interface, which forces DeSmuME's interpreter (the JIT is off while
  debugging). Oracle runs without the debugger can use the JIT (about 3×
  faster).
- Tracepoints and the exec bitmap cover main RAM plus up to 64 addresses
  elsewhere (e.g. ITCM).
- Call chains come from return addresses found on the stack: tail calls
  don't appear, and stale values can occasionally add a frame.
- Card reads are mapped to files assuming files are 0x200-aligned in the ROM
  (true for ROMs built by Nintendo's tools).
- Asset destinations are found by searching RAM for the file's bytes, so
  data decompressed on load is reported as not found. Tracking the
  decompressor with `func_trace` gives you the destination instead.
- DSi-enhanced features are untested.
