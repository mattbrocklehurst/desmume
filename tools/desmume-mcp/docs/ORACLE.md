# Oracle testing: the original game as the reference

When porting a game to another engine, the original running in an emulator is
the best specification you have. The idea: give both the same input,
frame for frame, and compare what comes out (positions, health, RNG state,
screens). This document covers the pieces that make that practical:

1. [Reproducible runs](#reproducible-runs)
2. [Input scripts](#input-scripts): recorded or hand-written, frame-indexed input
3. [Recording a run](#recording-a-run)
4. [Replaying](#replaying)
5. [Test scripts](#test-scripts) with probes and assertions
6. [The Python API](#the-python-api)
7. [CI and headless farms](#ci-and-headless-farms)

## Reproducible runs

DeSmuME is deterministic given the same starting state, the same input and
the same CPU emulation mode. The tools take care of the rest:

- **Savestates as anchors.** Recordings and tests start from a savestate
  (or from power on with `reset`). A savestate holds all RAM, registers,
  hardware state and the frame counter.
- **`--deterministic`** (always used by the oracle tools) fixes the real-time
  clock to 2000-01-01 00:00:00 advancing with emulated time, and seeds the
  emulator's own randomness (e.g. microphone noise). Games commonly seed
  their RNG from the clock, frame counters or input timing, so with these
  fixed, the game's RNG follows the same sequence every run.
- **CPU mode.** The interpreter and the JIT count cycles slightly
  differently, so a recording replays exactly only under the mode it was
  recorded with. Input scripts store it (`cpu interp|jit`) and the runner
  enforces it. The debugger (gdb stub) forces the interpreter.
- **Rendering.** The software rasterizer is used, so screenshots are
  bit-identical across machines. A GPU renderer would vary with drivers.
- **Frames.** Input is applied at the start of a frame and every command
  counts emulated frames, never wall-clock time.

`desmume-oracle replay ROM run.inputs --check` replays twice and verifies the
results match. Use it on a new recording to confirm the run is
deterministic.

## Input scripts

A plain text, engine-agnostic description of a run (`.inputs`):

```
# desmume input script
rom MCPT d40460ff          # game code and ROM CRC32 (informational)
state run.dst              # start from this savestate (relative path); omit = power on
cpu interp                 # CPU mode of the recording
0 right                    # from frame 0, hold right
12 -                       # frame 12: nothing held
14 right+down
20 -
22 - touch 100 90          # touch the bottom screen at (100, 90), no buttons
25 -
end 32                     # the run lasts 32 frames
```

- `<frame> <held>` lines give the state **from that frame on** until the
  next line. Frame 0 is the first frame emulated after the start state.
- Buttons: `a b x y l r start select up down left right lid`, joined
  with `+`; `-` for none. `touch X Y` (0-255, 0-191) for the stylus.
- Only changes are listed, so a long run stays small and readable. It's
  also easy to generate or parse from your engine's side.

## Recording a run

Play it yourself, in a window:

```sh
desmume-oracle record zelda.nds dungeon1.inputs --state before-dungeon1.dst
```

The game starts from the state (or power on), everything you press is
recorded, and closing the window or pressing Ctrl-C writes
`dungeon1.inputs` plus `dungeon1.dst` (the exact start state). Keyboard:
arrows, x/z = A/B, a/s = Y/X, q/w = L/R, Enter = Start, Right Shift =
Select, mouse = stylus.

From an agent or script: `input_record_start()` ... `input_record_stop()`
(MCP), or `Recorder(session, path)` in Python. These record the agent's
input and anything the user presses in the window.

DeSmuME's own `.dsm` movies (`emu_movie`) also work for pure replays, but
the `.inputs` format is what the oracle tools and your engine share.

## Replaying

```sh
# replay and sample values every frame (labels from a symbol file or labels json)
desmume-oracle replay zelda.nds dungeon1.inputs --labels zelda-labels.json \
    --sample link_x:s32:link_pos --sample link_y:s32:link_pos+4 --out trace.json

# determinism check
desmume-oracle replay zelda.nds dungeon1.inputs --check
```

The JSON output has the per-frame series and a CRC of main RAM at the end,
a cheap "did anything at all diverge" signal. MCP: `input_replay(path,
sample=[...])`.

## Test scripts

`.oracle` files are line-based tests:

```
# the player walks right 5 frames: +2 px per frame
reset                             # or: state level1-start.dst
wait 10
expect s32 g_player == 100
sample x s32 g_player             # record x every frame from here on
press right 5
expect s32 g_player == 110
press down+right 3
expect s32 g_player+4 == 86
probe hp_before s32 g_player+8
press a 1
wait 1
expect s32 g_player+8 == 43
inputs dungeon1.inputs            # replay a recording from here (loads its state)
screenshot end.png
```

| command | meaning |
|---|---|
| `reset` / `state FILE` | start from power on / a savestate |
| `press BUTTONS [N]` | hold for N frames (default 1), then release |
| `hold BUTTONS` / `release` | hold until changed / let go |
| `touch X Y [N]` | touch the bottom screen for N frames |
| `wait N` | run N frames with the current input |
| `inputs FILE` | replay an input script (loads its start state) |
| `probe NAME TYPE ADDR` | record one value (`u8 s8 u16 s16 u32 s32`) |
| `sample NAME TYPE ADDR` | record NAME every frame from now on |
| `expect TYPE ADDR OP VALUE` | assertion; `== != < > <= >=` |
| `screenshot FILE` / `savestate FILE` | outputs, relative to the script |
| `write TYPE ADDR VALUE` | poke memory to set up a scenario |

Addresses are numbers, hex, labels or `label+offset` (from `--labels`).

```sh
desmume-oracle run zelda.nds tests/walk.oracle --labels zelda-labels.json --out walk.json
echo $?    # 0 passed, 1 an expectation failed, 2 error
```

The results JSON contains every step with its frame, the probes, the
per-frame series, the expectations with actual values, and timing. Your
engine's test harness can run the same `.inputs` files and compare its
values against the oracle's series frame by frame.

The bundled example: `testgame/tests/movement.oracle`.

## The Python API

```python
from desmume_mcp.oracle import Oracle, InputScript

with Oracle("zelda.nds", labels="zelda-labels.json", jit=True) as o:
    o.load("before-dungeon1.dst")
    o.press("left", 5)                      # hold 5 frames, release
    o.hold(["b", "up"]); o.advance(10); o.release()
    o.touch(128, 96, frames=2)
    x = o.read("link_pos", "s32")
    o.play(InputScript.load("dungeon1.inputs"),
           on_frame=lambda o, f: print(f, o.read("link_pos", "s32")))
    o.screenshot("end.png")
```

`Oracle.frame()` counts frames since the last `load()`/`reset()`. For
debugging features (tracepoints, breakpoints) pass `debugger=True` and use
`o.session` (the same object the MCP server uses).

## CI and headless farms

`desmume-cli --headless` needs no X server, window, GPU or audio device, and
runs without the 60 fps limiter, so it's as fast as the host allows. The
oracle tools always run this way unless you pass `--window`. That makes it a
good fit for LXC containers on small machines:

- Build once (`scripts/build-desmume.sh`) and copy the binary, or build in
  the container. Runtime needs SDL2, glib and zlib shared libraries, but no
  X11 server and no `/dev/dri`.
- Throughput on a 4-core VM: roughly 50 fps with the interpreter and 150 fps
  with `--jit` for a CPU-bound game. Real games are usually faster, since they
  sleep until VBlank. Runs are single-process: run several tests in parallel,
  one per core.
- The software rasterizer uses a few threads for 3D. On very small hosts,
  running tests in parallel is the better use of cores.
- Keep the ROM, savestates, input scripts and labels in your test assets.
  Paths inside `.inputs` files are relative, so a directory can be moved as a
  whole.

Example CI step:

```sh
for t in tests/*.oracle; do
  desmume-oracle run "$ROM" "$t" --labels labels.json --jit --out "results/$(basename "$t").json" || fail=1
done
exit ${fail:-0}
```
