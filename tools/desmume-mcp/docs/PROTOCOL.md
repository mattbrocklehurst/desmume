# desmume-cli control protocol

`desmume-cli --control-port PORT` listens on `127.0.0.1:PORT` (localhost
only). The protocol is line-based so it can be used from any language, or by
hand with `nc localhost PORT`:

- request: one line, a command followed by `key=value` arguments; values
  containing spaces are double quoted (`path="/tmp/my state.dst"`);
  numbers are decimal or `0x` hex.
- reply: one line of JSON, always with `"ok": true|false` (and `"error"`
  when false).

Commands are executed on the emulation thread between frames, or while the
gdb stub has the CPU halted, so they always see a consistent state. Several
clients may connect at once. The Python client is `desmume_mcp/control.py`.

Related command-line options: `--headless` (no window/X/audio, no frame
limiter), `--deterministic` (fixed clock and seeds), `--rtc-fixed`,
`--start-paused`, `--arm9gdb PORT` / `--arm7gdb PORT` (gdb stubs, needed for
`trace_*`, `profile_*` and `hook_set ... action=break`), `--jit-enable`.

## Emulation

| command | reply / effect |
|---|---|
| `status` | title, game code, frame, paused, halted_by_debugger, pcs, movie/video state, held input |
| `pause` / `resume` | pause at the next frame boundary / resume |
| `frame_advance [n=1]` | run n frames then pause; **the reply comes when done** (or early with `halted_by_debugger` if a breakpoint hits) |
| `reset` | reset the console |
| `quit` | exit the emulator |

## Input

| command | effect |
|---|---|
| `input buttons=a,b,up,... [frames=N]` | hold buttons for N frames (0 = until changed) |
| `touch x=X y=Y [frames=N]` | touch the bottom screen |
| `release` | release buttons and touch |

Buttons: `a b select start right left up down r l x y debug lid`. Input is
merged with the keyboard/joystick in the window.

## Memory and CPU

| command | reply |
|---|---|
| `registers [cpu=arm9\|arm7]` | r0-r14, pc (next instruction), cpsr, spsr, mode, thumb, banked registers |
| `read_memory addr=A len=N [cpu=...]` | `data` = base64; I/O registers read from their backing store (no side effects) |
| `write_memory addr=A hex=0102ff [cpu=...]` | |
| `memory_map` | main RAM size, ITCM/DTCM location, WRAMCNT |

## Screens, states, recordings

| command | effect |
|---|---|
| `screenshot [path=FILE]` | PNG of both screens (256x384); `png` = base64 if no path |
| `savestate_save path=FILE` / `savestate_load path=FILE` | (load is refused while the debugger holds the CPU mid-frame) |
| `movie_record path=F.dsm [from=now\|reset]` / `movie_play path=F.dsm` / `movie_stop` | DeSmuME input movies |
| `video_record path=F.mp4` / `video_stop` | via `ffmpeg` in PATH |
| `dump dir=DIR [note=TEXT]` | freeze: pause and write RAM/VRAM/IO/registers/screenshot/savestate + `manifest.json` |

## Event hooks

| command | effect |
|---|---|
| `hook_set event=E action=log\|break\|off [min=A] [max=A] [cmds=ID,..] [stack=W] [frames=N]` | configure a hook |
| `hook_status` | configuration and hit counts |
| `hook_log [since=SEQ] [limit=N]` | records after SEQ (`more` = true if truncated) |
| `hook_clear` | drop buffered records |

Events: `card` (game card command; filter on ROM address), `dma` (DMA
start; filter on source or destination), `gx` (geometry command; filter on
DMA source, `cmds`), `swap` (SWAP_BUFFERS), `input` (KEYINPUT/EXTKEYIN
reads), `touch` (ARM7 touch screen samples), `input_state` (input applied
to a frame changed). `action=break` halts the CPU through the gdb stub right
after the triggering instruction (stop reply `T05hook:<event>;`), or pauses
at the end of the frame if no debugger is attached. `stack=W` copies W words
from sp into each record for call chains. `frames=N` turns the hook off
after N frames.

Records are arrays:
`[seq, event, frame, cpu, pc, lr, sp, thumb, a, b, c, d, dma_src, [stack...]]`
with event ids `0 card, 1 dma, 2 gx, 3 swap, 4 exec, 5 input, 6 touch,
7 ret, 8 input_state` and `a..d`:

| event | a | b | c | d |
|---|---|---|---|---|
| card | cmd bytes 0-3 | cmd bytes 4-7 | length | ROM address (B7 reads) |
| dma | channel \| mode<<8 | source | destination | bytes |
| gx | command id | parameter | | |
| swap | parameter | | | |
| exec | r0 | r1 | r2 | r3 |
| ret | r0 | r1 | function address | entry seq |
| input | register | value (active low) | | |
| touch | TSC channel | ADC value | touching | x \| y<<16 |
| input_state | buttons | touch (bit 31 = down, x \| y<<16) | previous buttons | previous touch |

Buttons use the same bit order as `input`: bit 0 `a` ... bit 11 `y`,
bit 14 `lid`.

## Tracepoints and profiling (need the gdb stub for that CPU)

| command | effect |
|---|---|
| `trace_add addr=A [ret=0\|1] [stack=W] [name=TEXT]` | log calls to A (`exec` records) and, with ret=1, returns matched by stack pointer (`ret` records) |
| `trace_remove addr=A` / `trace_clear` / `trace_list` | |
| `trace_count_add addrs=A,B,...` / `trace_count_remove addrs=...` | count-only tracepoints (hits in `trace_list`) |
| `profile_start [interval=N]` / `profile_stop` | sample every N instructions |
| `profile_get` | `counts` = `[[cpu, pc, lr, samples, sp_bucket, mode], ...]` |

## Keyboard shortcuts in the window

F11 toggles pause. F12 writes a freeze dump to `$DESMUME_DUMP_DIR` (default
`./dumps`) and pauses.
