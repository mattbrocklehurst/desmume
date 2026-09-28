"""MCP server exposing DeSmuME (emulator control, gdb-backed debugger,
memory analysis, ROM tools, labels, freeze dumps, event hooks) to agents.

Run with:  python3 -m desmume_mcp   (stdio transport)
"""

import json
import os
import re
import struct
import time
from collections import Counter, OrderedDict, defaultdict

import functools

try:  # mcp >= 2
    from mcp.server.mcpserver import MCPServer as _Server, Image
    from mcp.server.mcpserver.exceptions import ToolError
except ImportError:  # mcp 1.x
    from mcp.server.fastmcp import FastMCP as _Server, Image
    from mcp.server.fastmcp.exceptions import ToolError

from .control import ControlError
from .gdbrsp import GdbError
from .hw import GX_COMMANDS, decode_gx, group_gx, io_name, region_name
from .memory import (DumpSource, LiveSource, ValueScan, call_graph, find_function_start, function_extent,
                     hexdump, search, words, xrefs)
from .rom import Rom
from .oracle import InputScript, Oracle, Recorder, TEST_SCRIPT_HELP, run_test_script
from .session import Session, SessionError, data_dir
from .tracking import (AllocTracker, by_site, call_path, find_destination, find_owner, group_loads,
                       mermaid_graph, write_html)

INSTRUCTIONS = """\
Drives the DeSmuME Nintendo DS emulator for reverse engineering and debugging.

Start with emu_start(rom_path). The ARM9 is the main CPU (game logic, 3D);
the ARM7 handles sound, touch and wifi. Addresses in every tool accept
numbers, hex strings, label names ('player_update+0x10'), and registers
('sp+8', 'lr').

Typical loops:
- Explore: emu_screenshot / emu_press to play; emu_pause + emu_frame_advance
  for precise control.
- Find a variable: mem_scan_start then mem_scan_next as the value changes in
  game; dbg_watch on the result to find the code that writes it.
- Find code: dbg_break, dbg_continue, dbg_step, dbg_backtrace, mem_disasm.
- File loading: hook_set(event='card', file='path/in/rom') then hook_log to
  see which files are read and by which call chain.
- 3D: gx_capture records every geometry command of a frame with the RAM
  address it was DMA'd from; watch that RAM to find the code building it.
- Freeze: freeze_dump writes RAM, registers, VRAM and a savestate to disk for
  offline analysis (dump_info, and source='<dump dir>' on memory tools).
- Name things as you learn them with label_set; labels persist per game and
  show up in all disassembly. func_list / func_info help label unknown code.
"""

mcp = _Server("desmume", instructions=INSTRUCTIONS)
EXPECTED_ERRORS = (SessionError, ControlError, GdbError, ValueError, KeyError, OSError, RuntimeError)


def tool():
    """Register a tool; expected failures are reported to the agent as tool
    errors with their message (instead of a generic 'unexpected error')."""
    def wrap(fn):
        @functools.wraps(fn)
        def inner(*args, **kwargs):
            try:
                return fn(*args, **kwargs)
            except ToolError:
                raise
            except EXPECTED_ERRORS as e:
                msg = str(e) or type(e).__name__
                if isinstance(e, KeyError) and e.args:
                    msg = str(e.args[0])
                raise ToolError(msg) from e
        mcp.tool()(inner)
        return inner
    return wrap

S = None          # the running Session
HOOK_CURSOR = {}  # last record shown by hook_log, per session
SCAN = None       # the current ValueScan
CALLS = {}        # cached call graphs per source name


def session():
    if S is None or not S.alive():
        raise SessionError("the emulator is not running; call emu_start first")
    return S


def rom_only():
    """A Rom for offline tools: the running session's, or error."""
    if S is not None:
        return S.rom
    raise SessionError("no ROM loaded; call emu_start first")


def screenshot_image():
    return Image(data=session().control.screenshot_png(), format="png")


def parse_int(v):
    if isinstance(v, int):
        return v
    return int(str(v), 0)


# ---------------------------------------------------------------------------
# session


@tool()
def emu_start(rom_path: str, headless: bool | None = None, debug_arm7: bool = False,
              start_halted: bool = False, sound: bool | None = None, extra_args: list[str] | None = None):
    """Launch desmume-cli with a ROM, the control port and the ARM9 gdb stub,
    and attach the debugger. headless=None picks automatically (a window if a
    display is available, else xvfb). start_halted=True leaves the CPU stopped
    at the entry point. debug_arm7 also attaches to the ARM7."""
    global S, SCAN
    if S is not None:
        S.stop()
    SCAN = None
    CALLS.clear()
    S = Session(rom_path, arm7=debug_arm7, headless=headless, start_halted=start_halted,
                extra_args=extra_args or [], sound=sound)
    S.start()
    r = S.rom
    return (f"Started {r.title} [{r.game_code}] ({'headless' if S.headless else 'window'}).\n"
            f"ARM9 entry {r.arm9_entry:#010x}, binary {r.arm9_addr:#010x}+{r.arm9_size:#x}, "
            f"{len([o for o in r.overlays if o.cpu == 'arm9'])} ARM9 overlays, {len(r.files)} files.\n"
            f"Labels: {len(S.labels.labels)} in {S.labels.path}\n"
            f"CPU is {'halted at the entry point' if start_halted else 'running'}.\n"
            f"Ports: control {S.ports['control']}, gdb arm9 {S.ports['arm9']}"
            + (f", gdb arm7 {S.ports['arm7']}" if 'arm7' in S.ports else "")
            + f"\nLog: {S.log_path}")


@tool()
def emu_stop():
    """Quit the emulator."""
    global S
    if S is None:
        return "not running"
    S.stop()
    S = None
    return "stopped"


@tool()
def emu_status():
    """Emulator state: frame counter, paused/halted, pcs, movie/video state."""
    s = session()
    st = s.status()
    return json.dumps({k: v for k, v in st.items() if k != "ok"}, indent=1)


# ---------------------------------------------------------------------------
# emulation control


@tool()
def emu_pause():
    """Pause at the next frame boundary (the debugger can still halt/step)."""
    session().control.call("pause")
    return "paused"


@tool()
def emu_resume():
    """Resume emulation (also continues the CPU if the debugger has it halted)."""
    s = session()
    s.control.call("resume")
    for cpu, g in s.gdb.items():
        if not g.is_running():
            g.cont()
    return "running"


@tool()
def emu_frame_advance(frames: int = 1, screenshot: bool = False):
    """Run exactly N frames, then pause. Optionally return a screenshot."""
    s = session()
    for g in s.gdb.values():
        if not g.is_running():
            g.cont()
    r = s.control.call("frame_advance", n=frames, timeout=max(30, frames / 10))
    text = (f"stopped by the debugger with {r['frames_remaining']} frames to go at pc {r['arm9_pc']}"
            if r.get("halted_by_debugger") else f"frame {r['frame']}, arm9 pc {r['arm9_pc']}")
    return [text, screenshot_image()] if screenshot else text


@tool()
def emu_reset():
    """Reset the console (reboots the game)."""
    s = session()
    for g in s.gdb.values():
        if not g.is_running():
            g.cont()
    s.control.call("reset")
    return "reset"


@tool()
def emu_screenshot(save_path: str | None = None):
    """Both screens (top above bottom, 256x384) as an image; optionally also
    saved to a PNG file."""
    png = session().control.screenshot_png()
    if save_path:
        with open(save_path, "wb") as f:
            f.write(png)
    return Image(data=png, format="png")


@tool()
def emu_press(buttons: list[str], frames: int = 6, screenshot: bool = True):
    """Hold buttons (a b x y l r start select up down left right lid) for N
    frames, advancing the emulation that many frames plus a couple more so
    the game reacts; returns a screenshot."""
    s = session()
    s.control.call("input", buttons=",".join(b.lower() for b in buttons), frames=frames)
    return emu_frame_advance(frames + 2, screenshot)


@tool()
def emu_touch(x: int, y: int, frames: int = 6, screenshot: bool = True):
    """Touch the bottom screen at (x 0-255, y 0-191) for N frames."""
    s = session()
    s.control.call("touch", x=x, y=y, frames=frames)
    return emu_frame_advance(frames + 2, screenshot)


def _state_path(name):
    s = session()
    if os.sep in name or name.endswith(".dst"):
        return os.path.abspath(name)
    os.makedirs(s.state_root, exist_ok=True)
    return os.path.join(s.state_root, name + ".dst")


@tool()
def emu_savestate(action: str, name: str):
    """action=save|load. name is a slot name (stored per game in the data
    directory) or a path to a .dst file. Loading requires the debugger not to
    have the CPU halted mid-frame (it is resumed and paused at a frame
    boundary automatically)."""
    s = session()
    path = _state_path(name)
    if action == "save":
        s.control.call("savestate_save", path=path)
        return f"saved {path}"
    if action == "load":
        _to_frame_boundary(s)
        s.control.call("savestate_load", path=path)
        return f"loaded {path} (paused)"
    raise SessionError("action must be save or load")


def _to_frame_boundary(s):
    """Get out of a debugger halt and pause at the next frame boundary."""
    s.control.call("pause")
    for g in s.gdb.values():
        if not g.is_running():
            g.cont()
    for _ in range(100):
        st = s.control.call("status")
        if not st["halted_by_debugger"]:
            return
        time.sleep(0.02)
    raise SessionError("the CPU did not reach a frame boundary (is a breakpoint being hit every frame?)")


@tool()
def emu_movie(action: str, path: str | None = None, from_reset: bool = False):
    """Input movies (.dsm): action=record|play|stop. Recording from the
    current state (default) also writes a .dst savestate next to the movie,
    so replays are deterministic: a way to reproduce a bug or a code path."""
    s = session()
    if action == "stop":
        s.control.call("movie_stop")
        return "movie stopped"
    if not path:
        raise SessionError("path required")
    path = os.path.abspath(path)
    if action == "record":
        s.control.call("movie_record", path=path, **{"from": "reset" if from_reset else "now"})
        return f"recording input to {path}"
    if action == "play":
        s.control.call("movie_play", path=path)
        return f"playing {path}"
    raise SessionError("action must be record, play or stop")


@tool()
def emu_video(action: str, path: str | None = None):
    """Record the screens to a video file with ffmpeg: action=start|stop."""
    s = session()
    if action == "start":
        if not path:
            raise SessionError("path required")
        s.control.call("video_record", path=os.path.abspath(path))
        return f"recording video to {path}"
    r = s.control.call("video_stop")
    return f"stopped: {r['frames']} frames written to {r['path']}"


# ---------------------------------------------------------------------------
# freeze dumps


@tool()
def freeze_dump(note: str = "", screenshot: bool = True):
    """Freeze the game and write a full dump (RAM, TCMs, VRAM, palettes, OAM,
    I/O, registers of both CPUs, screenshot and a loadable savestate) to the
    data directory. Returns a summary with the call stack. The game stays
    paused. The user can also press F12 in the emulator window."""
    s = session()
    r = s.freeze(note)
    text = f"Dump written to {r['dir']}\n\n" + _dump_summary(r["dir"])
    if screenshot:
        return [text, Image(path=os.path.join(r["dir"], "screen.png"))]
    return text


def _dump_summary(directory):
    s = S
    src = DumpSource(directory, "arm9")
    m = src.manifest
    lines = [f"{m['rom']['title']} [{m['rom']['game_code']}] frame {m['frame']}, created {m['created']}"]
    if m.get("note"):
        lines.append(f"note: {m['note']}")
    lines.append("halted by debugger" if m["halted_by_debugger"] else "stopped at a frame boundary")
    if s is not None:
        lines.append("")
        lines.append(s.context("arm9", src=src, regs=m["arm9"]))
        lines.append("\ncall stack (arm9, heuristic):")
        lines.append(s.call_stack(src, "arm9", m["arm9"]))
        a7 = m["arm7"]
        lines.append(f"\n[arm7] pc={a7['pc']} lr={a7['r14']} sp={a7['r13']} mode={a7['mode']}")
    return "\n".join(lines)


@tool()
def dump_list():
    """List freeze dumps for the current game (newest first)."""
    s = session() if S else None
    root = s.dump_root if s else os.path.join(data_dir(), "dumps")
    if not os.path.isdir(root):
        return "no dumps"
    out = []
    for d in sorted(os.listdir(root), reverse=True):
        mf = os.path.join(root, d, "manifest.json")
        if os.path.exists(mf):
            with open(mf) as f:
                m = json.load(f)
            out.append(f"{d}  frame {m['frame']}  pc {m['arm9']['pc']}  {m.get('note', '')}")
    return "\n".join(out) or "no dumps"


@tool()
def dump_info(dump: str):
    """Summary of a dump (name from dump_list or a directory path): registers,
    code around pc, and call stack. Memory tools accept source=<dump> too."""
    return _dump_summary(session().resolve_dump(dump))


@tool()
def dump_resume(dump: str):
    """Load a dump's savestate into the running emulator (paused), to carry
    on live analysis from that moment."""
    s = session()
    d = s.resolve_dump(dump)
    _to_frame_boundary(s)
    s.control.call("savestate_load", path=os.path.join(d, "state.dst"))
    return f"loaded {d}/state.dst (paused; use emu_resume or dbg_* to continue)"


# ---------------------------------------------------------------------------
# debugger


@tool()
def dbg_halt(cpu: str = "arm9"):
    """Stop the CPU now and show where it is."""
    s = session()
    s.g(cpu).halt()
    return s.context(cpu)


@tool()
def dbg_continue(timeout: float = 5.0, cpu: str = "arm9"):
    """Continue until a breakpoint/watchpoint/hook with action=break, or until
    timeout seconds pass (the CPU keeps running; use dbg_wait or dbg_halt)."""
    s = session()
    return s.stop_report(s.cont(cpu, timeout))


@tool()
def dbg_wait(timeout: float = 10.0, cpu: str = "arm9"):
    """Wait for a running CPU to stop."""
    s = session()
    g = s.g(cpu)
    stop = g.wait_stop(timeout)
    if stop is None:
        return "still running"
    info = s._classify_stop(cpu, stop)
    return s.stop_report(info)


@tool()
def dbg_step(count: int = 1, over: bool = False, cpu: str = "arm9"):
    """Single step N instructions. over=True steps over calls (bl/blx)."""
    s = session()
    return s.stop_report(s.step(cpu, count, over))


@tool()
def dbg_finish(cpu: str = "arm9", timeout: float = 5.0):
    """Run until the current function returns (uses lr, so it is reliable at
    the start of a function or in leaf functions)."""
    s = session()
    return s.stop_report(s.finish(cpu, timeout))


@tool()
def dbg_run_to(address: str, cpu: str = "arm9", timeout: float = 5.0):
    """Run until an address is executed (temporary breakpoint)."""
    s = session()
    s.add_breakpoint(s.resolve(address, cpu), cpu, temp=True)
    return s.stop_report(s.cont(cpu, timeout))


@tool()
def dbg_registers(cpu: str = "arm9", source: str | None = None):
    """Registers including banked ones, plus code around pc. source: a dump."""
    s = session()
    if source:
        src = s.source(source, cpu)
        return s.context(cpu, src=src, regs=src.registers(cpu))
    regs = s.registers(cpu)
    banked = "\n".join(f"  {k}={v}" for k, v in regs["banked"].items())
    return s.context(cpu) + "\n\nbanked:\n" + banked


@tool()
def dbg_set_register(register: str, value: str, cpu: str = "arm9"):
    """Set r0-r12, sp, lr, pc or cpsr (CPU must be halted)."""
    s = session()
    names = {f"r{i}": i for i in range(16)}
    names.update(sp=13, lr=14, pc=15, cpsr=25)
    reg = register.lower()
    if reg not in names:
        raise SessionError("register must be r0-r15, sp, lr, pc or cpsr")
    s.g(cpu).write_register(names[reg], s.resolve(value, cpu))
    return s.format_registers(s.registers(cpu), cpu)


@tool()
def dbg_break(address: str, condition: str | None = None, temporary: bool = False, cpu: str = "arm9"):
    """Set an execution breakpoint. condition is a Python expression over
    r0-r15, sp, lr, pc and u8/u16/u32/s8/s16/s32(addr), e.g.
    'r0 == 5 and u16(r1+4) > 100'; the CPU only stops when it is true."""
    s = session()
    bp = s.add_breakpoint(s.resolve(address, cpu), cpu, temp=temporary, condition=condition)
    return f"breakpoint {bp.describe(s.labels)}"


@tool()
def dbg_watch(address: str, length: int = 4, kind: str = "write", condition: str | None = None, cpu: str = "arm9"):
    """Set a data watchpoint (kind=write|read|access) on [address,
    address+length). The CPU stops right after the accessing instruction and
    the report names that instruction."""
    s = session()
    if kind not in ("write", "read", "access"):
        raise SessionError("kind must be write, read or access")
    bp = s.add_breakpoint(s.resolve(address, cpu), cpu, kind=kind, length=length, condition=condition)
    return f"watchpoint {bp.describe(s.labels)}"


@tool()
def dbg_delete(which: str = "all", cpu: str = "arm9"):
    """Delete breakpoints/watchpoints: 'all', a number ('#3') or an address."""
    s = session()
    if which == "all":
        n = len(s.breakpoints)
        for bp in list(s.breakpoints.values()):
            s.remove_breakpoint(bp)
        return f"deleted {n}"
    bp = s.find_breakpoint(which, cpu)
    s.remove_breakpoint(bp)
    return f"deleted {bp.describe(s.labels)}"


@tool()
def dbg_list():
    """List breakpoints and watchpoints with hit counts."""
    s = session()
    if not s.breakpoints:
        return "no breakpoints"
    return "\n".join(bp.describe(s.labels) for bp in s.breakpoints.values())


@tool()
def dbg_trace(address: str, count: int = 20, timeout: float = 10.0,
              registers: list[str] | None = None, cpu: str = "arm9"):
    """Log register values each time an address executes (e.g. a function's
    arguments r0-r3 and its caller lr), without stopping for good. Good for
    'what is this function called with?'."""
    s = session()
    addr = s.resolve(address, cpu)
    regs = registers or ["r0", "r1", "r2", "r3", "lr"]
    hits = s.trace(addr, cpu, count, timeout, tuple(regs))
    lines = [f"{len(hits)} hits at {s.fmt_addr(addr)}"]
    for h in hits:
        if "other_stop" in h:
            lines.append(f"  stopped for another reason ({h['other_stop']}) at {s.fmt_addr(h['pc'])}")
            continue
        parts = [f"frame {h['frame']}"]
        for r in regs:
            v = h[r]
            parts.append(f"{r}={v:08x}" + (f" <{s.labels.describe(v & ~1)}>" if r == "lr" and s.labels.describe(v & ~1) else ""))
        lines.append("  " + " ".join(parts))
    return "\n".join(lines)


@tool()
def dbg_backtrace(cpu: str = "arm9", source: str | None = None, depth: int = 256):
    """Best-effort call stack: lr plus return addresses found on the stack
    (checked against the call instruction before them). Works on dumps too."""
    s = session()
    src = s.source(source, cpu)
    regs = src.registers(cpu) if isinstance(src, DumpSource) else s.registers(cpu)
    head = f"pc {s.fmt_addr(int(regs['pc'], 16))}"
    return head + "\n" + s.call_stack(src, cpu, regs, depth)


@tool()
def dbg_detach(cpu: str = "arm9"):
    """Release the gdb connection so you can attach gdb yourself
    (target remote localhost:<port from emu_start>). Breakpoints are cleared
    and the game keeps running. dbg_attach takes it back."""
    s = session()
    s.detach(cpu)
    return f"detached from {cpu}; gdb port {s.ports[cpu]}"


@tool()
def dbg_attach(cpu: str = "arm9"):
    """Re-attach the debugger (halts the CPU; use dbg_continue to go on)."""
    s = session()
    s.attach(cpu)
    return s.context(cpu)


# ---------------------------------------------------------------------------
# memory


@tool()
def mem_read(address: str, length: int = 64, format: str = "hex", cpu: str = "arm9", source: str | None = None):
    """Read memory. format: hex (hexdump), u8/u16/u32 (words), ascii, s16/s32.
    source: None/live, a dump name/dir, or rom:arm9 / rom:overlay:N."""
    s = session()
    src = s.source(source, cpu)
    addr = s.resolve(address, cpu)
    data = src.read(addr, length)
    head = f"{s.fmt_addr(addr)} ({region_name(addr)}{', ' + io_name(addr) if io_name(addr) else ''})\n"
    if format == "hex":
        return head + hexdump(data, addr)
    if format in ("u8", "u16", "u32"):
        return head + words(data, addr, {"u8": 1, "u16": 2, "u32": 4}[format], 16 if format == "u8" else 8)
    if format in ("s16", "s32"):
        size = 2 if format == "s16" else 4
        vals = struct.unpack(f"<{len(data) // size}{'h' if size == 2 else 'i'}", data[:len(data) // size * size])
        return head + "\n".join(f"{addr + i * size:08x}  {v}" for i, v in enumerate(vals))
    if format == "ascii":
        return head + data.split(b"\0")[0].decode("latin-1")
    raise SessionError("format must be hex, u8, u16, u32, s16, s32 or ascii")


@tool()
def mem_write(address: str, hex_bytes: str | None = None, value: int | None = None, size: int = 4, cpu: str = "arm9"):
    """Write memory: raw hex_bytes ('0102ff'), or an integer value of size 1/2/4."""
    s = session()
    addr = s.resolve(address, cpu)
    if hex_bytes is not None:
        data = bytes.fromhex(hex_bytes.replace(" ", ""))
    elif value is not None:
        data = (value & ((1 << (size * 8)) - 1)).to_bytes(size, "little")
    else:
        raise SessionError("give hex_bytes or value")
    s.control.write_memory(addr, data, cpu)
    return f"wrote {len(data)} bytes at {s.fmt_addr(addr)}"


def _is_thumb_func(src, addr):
    """Is the code at an (even) address Thumb? Evidence, in order: called with
    BLX / Thumb BL, referenced by a pointer with bit 0 set (veneers, function
    pointers), or ARM decoding that looks like garbage."""
    if addr & 1:
        return True
    graph = _graph(src)
    if (addr | 1) in graph:
        return True
    if addr in graph:
        return False
    needle = struct.pack("<I", addr | 1)
    for _, start, end in src.code_regions():
        if needle in src.read(start, end - start):
            return True
    words_ = struct.unpack("<8I", src.read(addr, 32))
    conditional = sum(1 for w in words_ if w >> 28 not in (0xE, 0xF))
    return conditional >= 5


@tool()
def mem_disasm(address: str = "pc", count: int = 30, mode: str = "auto", cpu: str = "arm9", source: str | None = None):
    """Disassemble with labels, IO register names and literal-pool values.
    mode: auto (thumb if the address is odd, or current mode at pc), arm, thumb."""
    s = session()
    src = s.source(source, cpu)
    regs = None
    if not isinstance(src, LiveSource) and isinstance(src, DumpSource):
        regs = src.registers(cpu)
    elif isinstance(src, LiveSource):
        regs = s.registers(cpu)
    addr = s.resolve(address, cpu, regs=regs)
    if mode == "auto":
        if str(address).strip().lower() == "pc" and regs:
            thumb = regs["thumb"]
        else:
            thumb = _is_thumb_func(src, addr)
    else:
        thumb = mode == "thumb"
    pc = int(regs["pc"], 16) if regs else None
    return s.disassemble(src, addr | (1 if thumb else 0), count, thumb=thumb, pc=pc, cpu=cpu)


def _regions(src, region):
    regs = src.data_regions()
    if region and region != "all":
        regs = [r for r in regs if r[0] == region]
        if not regs:
            raise SessionError(f"unknown region; choose from {', '.join(r[0] for r in src.data_regions())}")
    return regs


@tool()
def mem_search(value: int | None = None, size: int = 4, hex_pattern: str | None = None, text: str | None = None,
               region: str = "all", cpu: str = "arm9", source: str | None = None, limit: int = 100):
    """Search memory for an integer value (size 1/2/4, little endian), a hex
    pattern with ?? wildcards ('e92d4ff0 ?? ?? a0e1'), or ASCII text.
    region: all, main_ram, dtcm, itcm, shared_wram, arm7_wram."""
    s = session()
    src = s.source(source, cpu)
    align = 1
    if value is not None:
        pattern = (value & ((1 << (size * 8)) - 1)).to_bytes(size, "little")
        align = size
    elif hex_pattern:
        toks = re.findall(r"\?\?|[0-9a-fA-F]{2}", hex_pattern.replace(" ", ""))
        pattern = [None if t == "??" else int(t, 16) for t in toks]
        if all(p is not None for p in pattern):
            pattern = bytes(pattern)
    elif text:
        pattern = text.encode("latin-1")
    else:
        raise SessionError("give value, hex_pattern or text")
    hits = search(src, pattern, _regions(src, region), align, limit)
    if not hits:
        return "not found"
    return f"{len(hits)} hits" + ("" if len(hits) < limit else " (limit reached)") + "\n" + \
        "\n".join(f"  {s.fmt_addr(a)} [{name}]" for name, a in hits)


@tool()
def mem_xrefs(target: str, size: int = 1, cpu: str = "arm9", source: str | None = None, limit: int = 100):
    """Find references to an address: direct calls/branches (ARM and Thumb
    BL/BLX/B) and pointers in literal pools/data to [target, target+size).
    Use size to catch pointers into a struct or table."""
    s = session()
    src = s.source(source, cpu)
    addr = s.resolve(target, cpu)
    refs = xrefs(src, addr, src.code_regions(), size, limit)
    if not refs:
        return f"no references to {s.fmt_addr(addr)} found"
    lines = [f"{len(refs)} references to {s.fmt_addr(addr)}"]
    for kind, a, detail in refs:
        func = s.labels.describe(a)
        if not func:
            start = find_function_start(src, a | (1 if kind.startswith("thumb") else 0))
            func = f"in function at {start:#010x}?" if start else ""
        lines.append(f"  {a:08x} {kind:10} {detail}  {func}")
    return "\n".join(lines)


@tool()
def mem_scan_start(size: int = 4, value: int | None = None, region: str = "all", signed: bool = False,
                   cpu: str = "arm9"):
    """Start a value scan (like a cheat finder) over RAM. With value, keep only
    addresses holding it; without, snapshot everything (unknown initial
    value). Then change the value in game and call mem_scan_next."""
    global SCAN
    s = session()
    src = s.source(None, cpu)
    SCAN = ValueScan(src, _regions(src, region), size, signed)
    n = SCAN.start(value)
    return f"{n} candidates"


@tool()
def mem_scan_next(condition: str, value: int | None = None):
    """Narrow the scan: eq/ne/gt/lt VALUE, changed, unchanged, increased,
    decreased, increased_by/decreased_by VALUE (compared with the previous
    scan). Shows the candidates once there are few."""
    if SCAN is None:
        raise SessionError("start a scan with mem_scan_start first")
    n = SCAN.next(condition, value)
    out = f"{n} candidates after: {' -> '.join(SCAN.history)}"
    if n <= 30:
        out += "\n" + mem_scan_results(30)
    return out


@tool()
def mem_scan_results(limit: int = 50):
    """Show current value scan candidates."""
    if SCAN is None:
        raise SessionError("no scan in progress")
    s = session()
    return "\n".join(f"  {s.fmt_addr(a)} = {v} ({v & 0xFFFFFFFF:#x})" for a, v in SCAN.results(limit)) or "none"


# ---------------------------------------------------------------------------
# ROM


@tool()
def rom_info():
    """ROM header summary: title, game code, ARM9/ARM7 binaries, overlay and
    file counts."""
    return json.dumps(rom_only().summary(), indent=1)


@tool()
def rom_files(filter: str = "", limit: int = 200):
    """List files in the ROM file system with their ROM offsets and sizes."""
    r = rom_only()
    out = []
    for fid, name in sorted(r.files.items(), key=lambda x: x[1]):
        if filter.lower() in name.lower():
            start, end = r.file_extent(fid)
            out.append(f"  #{fid:<5} {start:#010x} {end - start:>9}  {name}")
            if len(out) >= limit:
                break
    return f"{len(out)} files\n" + "\n".join(out)


@tool()
def rom_overlays():
    """List overlays (code loaded at runtime over shared RAM ranges). Code
    that is not in the ARM9 binary usually lives in one of these; use
    mem_disasm(source='rom:overlay:N') to read an overlay offline."""
    r = rom_only()
    lines = []
    for ov in r.overlays:
        lines.append(f"  {ov.cpu} #{ov.id:<3} {ov.ram_addr:#010x}-{ov.ram_addr + ov.ram_size:#010x} "
                     f"bss {ov.bss_size:#x} file #{ov.file_id}{' compressed' if ov.compressed else ''}")
    return f"{len(r.overlays)} overlays\n" + "\n".join(lines)


@tool()
def rom_extract(what: str, out_path: str):
    """Write a decompressed binary to disk for other tools (e.g. Ghidra):
    what = arm9 | arm7 | overlay:N | file:<path or #id>."""
    r = rom_only()
    if what == "arm9":
        data, base = r.arm9_binary(), r.arm9_addr
    elif what == "arm7":
        data, base = r.arm7_binary(), r.arm7_addr
    elif what.startswith("overlay:"):
        ov = r.overlay("arm9", int(what[8:], 0))
        data, base = r.overlay_binary("arm9", ov.id), ov.ram_addr
    elif what.startswith("file:"):
        spec = what[5:]
        fid = int(spec[1:]) if spec.startswith("#") else r.find_file(spec)
        data, base = r.file_data(fid), None
    else:
        raise SessionError("what must be arm9, arm7, overlay:N or file:<name>")
    with open(out_path, "wb") as f:
        f.write(data)
    return f"wrote {len(data)} bytes to {out_path}" + (f" (load address {base:#010x})" if base is not None else "")


# ---------------------------------------------------------------------------
# labels


@tool()
def label_set(address: str, name: str, type: str = "func", size: int = 0, comment: str = ""):
    """Name an address (type: func, data, code, struct, string, other).
    Labels persist per game and appear in all listings and reports."""
    s = session()
    addr = s.resolve(address) & ~1 if type == "func" else s.resolve(address)
    s.labels.set(addr, name, type, size, comment)
    return f"{addr:#010x} = {name}"


@tool()
def label_comment(address: str, text: str):
    """Attach a comment to an address (shown in disassembly)."""
    s = session()
    addr = s.resolve(address)
    s.labels.comment(addr, text)
    return f"comment set at {addr:#010x}"


@tool()
def label_delete(address: str):
    """Remove a label (by name or address)."""
    s = session()
    addr = s.resolve(address)
    e = s.labels.delete(addr)
    return f"deleted {e['name']}" if e else "no label there"


@tool()
def label_list(filter: str = "", type: str | None = None, limit: int = 300):
    """List labels, optionally filtered by text (name/comment) or type."""
    s = session()
    items = s.labels.search(filter, type)
    lines = [f"  {a:08x} {e['type']:6} {e['name']}" + (f"  ; {e['comment']}" if e.get('comment') else "")
             for a, e in items[:limit]]
    return f"{len(items)} labels ({s.labels.path})\n" + "\n".join(lines)


@tool()
def label_import(path: str | None = None, text: str | None = None):
    """Import labels from nm output ('02000000 T name'), 'name = 0x...;' linker
    style, or 'name 0x...' lines (e.g. a community symbol list)."""
    s = session()
    if path:
        with open(path) as f:
            text = f.read()
    if not text:
        raise SessionError("give path or text")
    return f"imported {s.labels.import_text(text)} labels"


@tool()
def label_export(format: str = "sym", path: str | None = None):
    """Export labels: sym (nm style), ghidra (for ImportSymbolsScript.py),
    ld (linker script) or gdb. Returns the text, or writes it to path."""
    s = session()
    text = s.labels.export_text(format)
    if path:
        with open(path, "w") as f:
            f.write(text)
        return f"wrote {len(s.labels.labels)} labels to {path}"
    return text


# ---------------------------------------------------------------------------
# function analysis (for labelling unknown code)


def _graph(src, refresh=False):
    key = src.name
    if refresh or key not in CALLS:
        CALLS[key] = call_graph(src, src.code_regions())
    return CALLS[key]


@tool()
def func_list(source: str | None = None, min_callers: int = 1, unlabelled_only: bool = False,
              limit: int = 100, refresh: bool = False, cpu: str = "arm9"):
    """Discover functions from direct call targets and rank them by number of
    callers. Heavily called unlabelled functions are the best labelling
    targets (they are usually library routines: memcpy, divide, allocators,
    file system). source: live (default), rom:arm9, rom:overlay:N, or a dump."""
    s = session()
    src = s.source(source, cpu)
    graph = _graph(src, refresh)
    items = sorted(graph.items(), key=lambda kv: -len(kv[1]))
    lines = []
    for target, sites in items:
        if len(sites) < min_callers:
            continue
        name = s.labels.labels.get(target & ~1, {}).get("name")
        if unlabelled_only and name:
            continue
        lines.append(f"  {target & ~1:08x} {'thumb' if target & 1 else 'arm  '} callers={len(sites):<4} {name or ''}")
        if len(lines) >= limit:
            break
    return f"{len(graph)} call targets in {src.name}\n" + "\n".join(lines)


@tool()
def func_info(address: str, max_instructions: int = 300, source: str | None = None, cpu: str = "arm9"):
    """Everything useful for naming a function: its disassembly (to the next
    known function), callers, callees, I/O registers and hardware it touches,
    pointers to RAM data and strings it references. Use label_set with what
    you conclude."""
    s = session()
    src = s.source(source, cpu)
    start = s.resolve(address, cpu)
    graph = _graph(src)
    thumb = _is_thumb_func(src, start)
    start &= ~1
    end = function_extent(src, start, thumb, graph.keys(), max_instructions)
    size = 2 if thumb else 4
    count = max(1, (end - start) // size)
    listing = s.disassemble(src, start | (1 if thumb else 0), count, thumb=thumb, cpu=cpu)

    callers = graph.get(start | (1 if thumb else 0), []) + graph.get(start if thumb else start | 1, [])
    callees = Counter()
    io = Counter()
    data_ptrs = Counter()
    strings = OrderedDict()
    for line in listing.splitlines():
        m = re.search(r"\bbl[x]? #(0x[0-9a-f]+)", line)
        if m:
            callees[int(m.group(1), 16)] += 1
        for name in re.findall(r"io:(\S+)", line):
            io[name.split("+")[0]] += 1
        m = re.search(r"=(0x[0-9a-f]{8})", line)
        if m:
            v = int(m.group(1), 16)
            if 0x02000000 <= v < 0x03000000 or 0x01FF8000 <= v < 0x02000000:
                data_ptrs[v] += 1
                raw = src.read(v, 64)
                txt = raw.split(b"\0")[0]
                if len(txt) >= 4 and all(32 <= c < 127 or c in (9, 10) for c in txt):
                    strings[v] = txt.decode("latin-1")
    out = [f"function {s.fmt_addr(start)} ({'thumb' if thumb else 'arm'}), ~{end - start} bytes"]
    out.append(f"callers ({len(callers)}): " + ", ".join(s.fmt_addr(c) for c in callers[:20])
               + (" ..." if len(callers) > 20 else ""))
    out.append("callees: " + (", ".join(f"{s.fmt_addr(c)}x{n}" if n > 1 else s.fmt_addr(c)
                                        for c, n in callees.most_common(30)) or "none (leaf)"))
    if io:
        out.append("hardware: " + ", ".join(f"{k}x{n}" if n > 1 else k for k, n in io.most_common()))
    if data_ptrs:
        out.append("data: " + ", ".join(s.fmt_addr(p) for p in list(data_ptrs)[:20]))
    if strings:
        out.append("strings: " + "; ".join(f"{a:#x}={t!r}" for a, t in list(strings.items())[:10]))
    out.append("")
    out.append(listing)
    return "\n".join(out)


# ---------------------------------------------------------------------------
# event hooks


@tool()
def hook_set(event: str, action: str = "log", file: str | None = None, min_address: str | None = None,
             max_address: str | None = None, gx_commands: list[str] | None = None, stack_words: int | None = None,
             frames: int | None = None):
    """Hook hardware events in the emulator core.
    event: card (game card reads; ROM offset is mapped to the file), dma (DMA
    starts), gx (every 3D geometry command, with the RAM address it was DMA'd
    from), swap (SWAP_BUFFERS: a 3D frame is finished).
    action: log (record pc/lr/stack and keep running), break (halt the CPU
    right after the triggering instruction, like a breakpoint), off.
    Filters: file='data/map.bin' (card only), or min/max address (card: ROM
    offset, dma: source/destination, gx: DMA source address); gx_commands
    e.g. ['VTX_16','TEXIMAGE_PARAM'] or ids. stack_words: how much stack to
    snapshot per event for call chains (default 48, 0 for gx). frames: turn
    the hook off after N frames."""
    s = session()
    lo = s.resolve(min_address) if min_address else None
    hi = s.resolve(max_address) if max_address else None
    if file:
        if event != "card":
            raise SessionError("file filters only apply to card hooks")
        fid = s.rom.find_file(file)
        start, end = s.rom.file_extent(fid)
        lo, hi = start, end - 1
    cmds = None
    if gx_commands:
        by_name = {n: i for i, (n, _) in GX_COMMANDS.items()}
        cmds = [by_name[c.upper()] if c.upper() in by_name else parse_int(c) for c in gx_commands]
    if stack_words is None and event in ("card", "dma", "swap", "input"):
        stack_words = 48  # deep enough for call chains through SDK layers
    r = s.hook_set(event, action, lo, hi, cmds, stack_words, frames)
    st = next(h for h in r["hooks"] if h["event"] == event)
    return f"hook {event}: {st['action']}" + (f" range {st.get('min')}-{st.get('max')}" if 'min' in st else "") + \
        (" (break needs the debugger attached; otherwise the game pauses at the end of the frame)" if action == "break" else "")


@tool()
def hook_status():
    """Show hook configuration, hit counts and buffered record count."""
    return json.dumps(session().control.call("hook_status"), indent=1)


@tool()
def hook_log(event: str | None = None, limit: int = 50, clear: bool = True, call_chains: bool = True):
    """Show hook events recorded since the last hook_log call (oldest first):
    frame, pc and caller chain, and for card reads the file and offset read.
    clear=False shows the same records again next time."""
    s = session()
    recs = s.records_after(HOOK_CURSOR.get(id(s), 0))
    if clear and recs:
        HOOK_CURSOR[id(s)] = recs[-1]["seq"]
    if event:
        recs = [r for r in recs if r["event"] == event]
    total = len(recs)
    lines = [f"{total} records" + (f", showing the first {limit}" if total > limit else "")]
    for r in recs[:limit]:
        a = r["args"]
        if r["event"] == "card":
            cmd = a[0] >> 24
            if cmd == 0xB7:
                kind, name, off = s.rom.file_at(a[3])
                what = f"card read {a[3]:#010x} len {a[2]:#x} -> {name} +{off:#x}"
            else:
                what = f"card command {a[0]:08x}{a[1]:08x}"
        elif r["event"] == "dma":
            modes = ["immediate", "vblank", "hblank", "display", "main-display", "card", "gba-slot", "gxfifo"]
            mode = (a[0] >> 8) & 0xFF
            what = (f"dma{a[0] & 3} {modes[mode] if mode < len(modes) else mode} {a[1]:#010x} -> "
                    f"{a[2]:#010x} ({io_name(a[2]) or region_name(a[2])}) {a[3]:#x} bytes")
        elif r["event"] == "gx":
            what = f"gx {decode_gx(a[0], [a[1]])}" + (f" from {s.fmt_addr(r['dma_src'])}" if r["dma_src"] else "")
        else:
            what = f"swap buffers"
        line = f"  #{r['seq']} frame {r['frame']} {r['cpu']}: {what}"
        if call_chains and r["event"] != "gx":
            line += "\n      " + " <- ".join(s.chain_from_snapshot(r))
        elif r["event"] == "gx" and not r["dma_src"]:
            line += f"  (cpu pc {s.fmt_addr(r['pc'])})"
        lines.append(line)
    return "\n".join(lines)


@tool()
def gx_capture(frames: int = 1, save_path: str | None = None, show: int = 80):
    """Capture every 3D geometry command for the next N frames: which commands
    ran, decoded parameters (vertices, matrices, textures), and where in RAM
    each came from (the display list buffers the game builds). Use dbg_watch
    on a source address to find the code that writes that part of the
    display list. The full capture is saved as JSON (save_path or the data
    directory)."""
    s = session()
    s.sync_records()
    first = s.records_seq
    s.hook_set("gx", "log", stack=0)
    s.hook_set("swap", "log", stack=16)
    # capture one extra frame and cut at SWAP_BUFFERS so that the result
    # holds whole 3D frames even when we start in the middle of one
    emu_frame_advance(frames + 1)
    s.hook_set("gx", "off")
    s.hook_set("swap", "off")
    recs = s.records_after(first)
    # geometry records are bulky and have been reported: drop them
    s.records = [r for r in s.records if r["event"] != "gx"]

    gx_all = [r for r in recs if r["event"] == "gx"]
    swap_idx = [i for i, r in enumerate(gx_all) if r["cmd"] == 0x50]
    if len(swap_idx) > frames:
        gx = gx_all[swap_idx[0] + 1:swap_idx[frames] + 1]
    else:
        gx = gx_all  # the game renders less often than every frame
    lo_seq = gx[0]["seq"] if gx else 0
    hi_seq = gx[-1]["seq"] if gx else 0
    swaps = [r for r in recs if r["event"] == "swap" and lo_seq <= r["seq"]]
    swaps = swaps[:frames]
    cmds = group_gx(gx)
    counts = Counter(GX_COMMANDS.get(c, (f"CMD_{c:02X}", 0))[0] for c, _, _ in cmds)

    # contiguous DMA source ranges = display list buffers
    ranges = []
    for r in gx:
        src = r["dma_src"]
        if not src:
            continue
        # packed command id words sit between parameter words, allow small gaps
        if ranges and 0 <= src - ranges[-1][1] <= 8:
            ranges[-1][1] = src
            ranges[-1][2] += 1
        else:
            ranges.append([src, src, 1])
    direct = sum(1 for r in gx if not r["dma_src"])

    out = [f"{len(cmds)} geometry commands in {frames} 3D frame(s)"]
    out.append("commands: " + ", ".join(f"{k}x{v}" for k, v in counts.most_common()))
    vtx = sum(v for k, v in counts.items() if k.startswith("VTX"))
    out.append(f"vertices: {vtx}")
    if ranges:
        out.append("display list sources (RAM the commands were DMA'd from):")
        for lo, hi, n in ranges[:20]:
            out.append(f"  {s.fmt_addr(lo)} - {hi + 3:#010x}  ({n} words)")
        if len(ranges) > 20:
            out.append(f"  ... {len(ranges) - 20} more ranges")
    if direct:
        pcs = Counter(r["pc"] for r in gx if not r["dma_src"])
        out.append(f"{direct} words written directly by the CPU, from: "
                   + ", ".join(s.fmt_addr(p) for p, _ in pcs.most_common(5)))
    for sw in swaps[:3]:
        out.append(f"swap in frame {sw['frame']} from: " + " <- ".join(s.chain_from_snapshot(sw)))

    out.append(f"\nfirst {min(show, len(cmds))} commands:")
    for c, params, rec in cmds[:show]:
        where = f"@{rec['dma_src']:08x}" if rec["dma_src"] else f"cpu {rec['pc']:08x}"
        out.append(f"  f{rec['frame']} {where}  {decode_gx(c, params)}")

    path = save_path or os.path.join(data_dir(), "gx", f"{s.rom.game_code}-{time.strftime('%Y%m%d-%H%M%S')}.json")
    os.makedirs(os.path.dirname(os.path.abspath(path)), exist_ok=True)
    with open(path, "w") as f:
        json.dump({"frames": frames, "commands": [
            {"frame": rec["frame"], "cmd": GX_COMMANDS.get(c, (f"CMD_{c:02X}", 0))[0], "id": c,
             "params": params, "decoded": decode_gx(c, params), "dma_src": rec["dma_src"], "pc": rec["pc"]}
            for c, params, rec in cmds]}, f)
    out.append(f"\nfull capture: {path}")
    return "\n".join(out)


# ---------------------------------------------------------------------------
# function tracepoints


def _fmt_regs(args, n=4):
    return " ".join(f"r{i}={v:08x}" for i, v in enumerate(args[:n]))


@tool()
def func_trace(address: str, capture_return: bool = True, stack_words: int = 16, name: str = ""):
    """Log every call to a function without stopping the game: arguments
    (r0-r3), caller chain (from a stack snapshot) and, with capture_return,
    the return value (r0/r1) matched by stack pointer. Read with
    func_trace_log. Costs little when not hit; works on the ARM9 (or the
    ARM7 if emu_start had debug_arm7)."""
    s = session()
    addr = s.resolve(address) & ~1
    s.control.call("trace_add", addr=hex(addr), ret=int(capture_return), stack=stack_words,
                   name=name or s.labels.describe(addr) or "")
    return f"tracing {s.fmt_addr(addr)}" + (" with return values" if capture_return else "")


@tool()
def func_trace_stop(address: str = "all"):
    """Stop tracing a function (or all)."""
    s = session()
    if address == "all":
        s.control.call("trace_clear")
        return "all tracepoints removed"
    s.control.call("trace_remove", addr=hex(s.resolve(address) & ~1))
    return "removed"


@tool()
def func_trace_log(address: str | None = None, limit: int = 40, since_frame: int | None = None):
    """Show traced calls (newest last): frame, arguments, return value and
    the call path. Also summarises the distinct callers."""
    s = session()
    src = s.source(None, "arm9")
    recs = s.records_after(0)
    want = s.resolve(address) & ~1 if address else None
    entries = {}
    calls = []
    for r in recs:
        if r["event"] == "exec" and (want is None or r["pc"] == want):
            if since_frame is not None and r["frame"] < since_frame:
                continue
            c = {"rec": r, "ret": None}
            entries[r["seq"] & 0xFFFFFFFF] = c
            calls.append(c)
        elif r["event"] == "ret" and r["args"][3] in entries:
            entries[r["args"][3]]["ret"] = r["args"][:2]
    if not calls:
        tl = s.control.call("trace_list")
        return "no calls recorded yet; tracepoints: " + ", ".join(
            f"{t['addr']} {t['name']} hits={t['hits']}" for t in tl["tracepoints"])
    callers = defaultdict(int)
    lines = []
    for c in calls:
        r = c["rec"]
        path = call_path(s, src, r)
        callers[" > ".join(path[-4:-1])] += 1
    for c in calls[-limit:]:
        r = c["rec"]
        path = call_path(s, src, r)
        ret = f" -> r0={c['ret'][0]:08x}" if c["ret"] else ""
        lines.append(f"  f{r['frame']} {s.fmt_addr(r['pc'])}({_fmt_regs(r['args'])}){ret}  "
                     f"from {' > '.join(path[-4:-1])}")
    head = [f"{len(calls)} calls; callers:"] + [f"  {n:5}x {k or '?'}" for k, n in
                                               sorted(callers.items(), key=lambda kv: -kv[1])[:15]]
    return "\n".join(head + ["", f"last {min(limit, len(calls))} calls:"] + lines)


# ---------------------------------------------------------------------------
# asset loads


ASSET_TRACE = {}   # session id -> first record seq


@tool()
def asset_trace_start(stack_words: int = 48):
    """Start recording game card reads (file loads) with call stacks, plus
    card DMA transfers. Play or run the game, then call asset_report."""
    s = session()
    s.sync_records()
    ASSET_TRACE[id(s)] = s.records_seq
    s.hook_set("card", "log", stack=stack_words)
    s.hook_set("dma", "log", min_addr=0x04100010, max_addr=0x04100010, stack=0)  # card -> RAM DMA
    return "recording file loads"


@tool()
def asset_report(stop: bool = False, graph: bool = True, html_path: str | None = None, limit: int = 60):
    """Report file loads since asset_trace_start: frame, file (name from the
    ROM file system), bytes, where the data landed in RAM, which allocation
    owns that buffer (if alloc_track is active), and the call path that
    triggered it. Also returns a Mermaid flow graph (functions -> files) and
    writes an HTML page with it."""
    s = session()
    if id(s) not in ASSET_TRACE:
        raise SessionError("call asset_trace_start first")
    recs = s.records_after(ASSET_TRACE[id(s)])
    if stop:
        s.hook_set("card", "off")
        s.hook_set("dma", "off")
    all_loads = group_loads(s, [r for r in recs if r["event"] == "card"], [r for r in recs if r["event"] == "dma"])
    # file system bookkeeping (FAT/FNT/header reads) is summarised separately
    meta = [ld for ld in all_loads if ld["kind"] not in ("file", "arm9", "arm7")]
    loads = [ld for ld in all_loads if ld["kind"] in ("file", "arm9", "arm7")]
    allocs = _alloc_analysis(s)["allocs"] if id(s) in ALLOC else []
    lines = [f"{len(loads)} file loads" + (f" (plus {sum(m['reads'] for m in meta)} reads of file system tables: "
                                            + ", ".join(sorted({m['file'].split(' (')[0] for m in meta})) + ")"
                                            if meta else "")]
    rows = []
    leaves = []
    found = []
    for ld in loads[:limit]:
        data = b""
        if ld["kind"] == "file":
            fid = next((i for i, n in s.rom.files.items() if n == ld["file"]), None)
            if fid is None:
                ov = re.match(r"overlay (\w+)#(\d+)", ld["file"])
                fid = s.rom.overlay(ov.group(1), int(ov.group(2))).file_id if ov else None
            if fid is not None:
                data = s.rom.file_data(fid)
        dests, how = find_destination(s, ld, data) if data else ([], "")
        found.append((ld, data, dests, how))
    # an address holding several different files is a staging buffer (e.g.
    # the card block buffer), not a destination
    seen = defaultdict(set)
    for ld, _, dests, _ in found:
        for d in dests:
            seen[d].add(ld["file"])
    for ld, data, dests, how in found:
        owner = None
        if allocs:
            # the buffer allocated most recently before this load started
            cands = [(find_owner([a for a in allocs if a["seq"] < ld["first_seq"]], d), d) for d in dests]
            cands = [(a, d) for a, d in cands if a]
            if cands:
                owner, best = max(cands, key=lambda ad: ad[0]["seq"])
                dests = [best]
        if owner is None:
            unique = [d for d in dests if len(seen[d]) == 1]
            if unique and len(unique) < len(dests):
                dests = unique
        dest_txt = ", ".join(f"{d:#010x}" for d in dests[:3]) or "?"
        lines.append(f"  f{ld['frame']}: {ld['file']} ({ld['bytes']:#x} bytes in {ld['reads']} reads)"
                     f" -> {dest_txt}  [{how}]")
        if owner:
            lines.append(f"      buffer allocated at f{owner['frame']}: {owner['size']:#x} bytes by "
                         f"{' > '.join(owner['path'][-3:])}")
        lines.append(f"      triggered by: {' > '.join(ld['path'])}")
        rows.append([ld["frame"], ld["file"], ld["bytes"], dest_txt, " > ".join(ld["path"])])
        leaves.append((ld["path"], f"{ld['file']} -> {dest_txt}", "file"))
    out = "\n".join(lines)
    if graph and leaves:
        g = mermaid_graph(leaves, "file loads")
        path = html_path or os.path.join(data_dir(), "reports", f"{s.rom.game_code}-assets.html")
        write_html(path, f"{s.rom.title}: file loads", g, rows, ["frame", "file", "bytes", "destination", "call path"])
        out += f"\n\nflow graph (mermaid):\n{g}\n\nHTML report: {path}"
    return out


# ---------------------------------------------------------------------------
# allocations


ALLOC = {}  # session id -> (AllocTracker, first seq)


def _alloc_analysis(s):
    tracker, first = ALLOC[id(s)]
    return tracker.analyse(s, s.records_after(first))


@tool()
def alloc_track(alloc_function: str, free_function: str | None = None, size_arg: str = "r0",
                free_ptr_arg: str = "r0", stack_words: int = 32):
    """Track a game's allocator: every allocation (size, returned pointer,
    call path, frame) and free. Point it at the game's malloc/new/arena alloc
    (find it with func_list/func_info: many callers, returns a pointer).
    size_arg: register holding the size (r1 for arena_alloc(arena, size)).
    Then use alloc_report."""
    s = session()
    a = s.resolve(alloc_function) & ~1
    f = s.resolve(free_function) & ~1 if free_function else None
    s.sync_records()
    s.control.call("trace_add", addr=hex(a), ret=1, stack=stack_words, name="alloc")
    if f is not None:
        s.control.call("trace_add", addr=hex(f), ret=0, stack=stack_words, name="free")
    ALLOC[id(s)] = (AllocTracker(a, f, size_arg, free_ptr_arg), s.records_seq)
    return f"tracking allocations through {s.fmt_addr(a)}" + (f" and frees through {s.fmt_addr(f)}" if f else "")


@tool()
def alloc_report(view: str = "summary", limit: int = 30, address: str | None = None, html_path: str | None = None):
    """Allocation report. view: summary (totals, peak, busiest call sites),
    sites (all call sites: count, bytes, still live), live (outstanding
    allocations), leaks (call sites whose allocations pile up without being
    freed), timeline (allocs/frees in order), owner (which allocation holds
    'address'), graph (Mermaid flow graph of call paths to allocations)."""
    s = session()
    if id(s) not in ALLOC:
        raise SessionError("call alloc_track first")
    res = _alloc_analysis(s)
    allocs, live = res["allocs"], res["live"]
    sites = by_site(allocs)
    if view == "owner":
        a = find_owner(allocs, s.resolve(address))
        if not a:
            return "no tracked allocation contains that address"
        return (f"{a['ptr']:#010x}+{a['size']:#x} allocated at frame {a['frame']} by {' > '.join(a['path'])}"
                + (f"; freed at frame {a['freed_frame']} by {' > '.join(a['freed_by'])}" if a['freed_frame'] is not None else "; still live"))
    if view == "summary":
        out = [f"{len(allocs)} allocations ({sum(a['size'] for a in allocs):#x} bytes), {len(res['frees'])} frees",
               f"live now: {len(live)} blocks, {res['current']:#x} bytes; peak {res['peak']:#x} bytes"]
        if res["bad_frees"]:
            out.append(f"{len(res['bad_frees'])} frees of pointers that were not allocated while tracking")
        out.append("busiest call sites:")
        for k, v in sorted(sites.items(), key=lambda kv: -kv[1]["bytes"])[:limit]:
            out.append(f"  {v['count']:4}x {v['bytes']:#8x} bytes, live {v['live']} ({v['live_bytes']:#x})  {k}")
        return "\n".join(out)
    if view == "sites":
        return "\n".join(f"{v['count']:4}x {v['bytes']:#8x} B live {v['live']:3} frames {v['frames'][:6]}  {k}"
                         for k, v in sorted(sites.items(), key=lambda kv: -kv[1]["count"])[:limit])
    if view == "live":
        return f"{len(live)} live allocations\n" + "\n".join(
            f"  {a['ptr']:#010x} {a['size']:#7x} f{a['frame']}  {' > '.join(a['path'][-4:])}" for a in live[:limit])
    if view == "leaks":
        out = []
        for k, v in sorted(sites.items(), key=lambda kv: -kv[1]["live"]):
            if v["live"] >= 2 or (v["live"] and v["count"] > v["live"] and False):
                frames = [a["frame"] for a in live if " > ".join(a["path"][-4:]) == k]
                out.append(f"  {v['live']} live of {v['count']} ({v['live_bytes']:#x} bytes), allocated at frames "
                           f"{frames[:10]}: {k}")
        return ("call sites with several allocations still live (likely leaks if they keep growing):\n"
                + "\n".join(out[:limit])) if out else "no call site has more than one live allocation"
    if view == "timeline":
        events = sorted([(a["seq"], f"f{a['frame']} alloc {a['size']:#x} -> {a['ptr']:#010x}  {' > '.join(a['path'][-3:])}")
                         for a in allocs] +
                        [(f["seq"], f"f{f['frame']} free  {f['ptr']:#010x}  {' > '.join(f['path'][-3:])}")
                         for f in res["frees"]])
        return "\n".join(e for _, e in events[-limit:])
    if view == "graph":
        leaves = [(a["path"], f"{a['size']:#x} bytes" + (" LIVE" if a["freed_frame"] is None else ""), "alloc")
                  for a in allocs]
        g = mermaid_graph(leaves, "allocations")
        path = html_path or os.path.join(data_dir(), "reports", f"{s.rom.game_code}-allocs.html")
        write_html(path, f"{s.rom.title}: allocations", g,
                   [[a["frame"], f"{a['ptr']:#010x}", a["size"], "live" if a["freed_frame"] is None else f"freed f{a['freed_frame']}",
                     " > ".join(a["path"])] for a in allocs], ["frame", "ptr", "size", "state", "call path"])
        return f"{g}\n\nHTML report: {path}"
    raise SessionError("view must be summary, sites, live, leaks, timeline, owner or graph")


@tool()
def alloc_stop():
    """Stop allocation tracking (the collected data stays available)."""
    s = session()
    if id(s) not in ALLOC:
        return "not tracking"
    tracker, _ = ALLOC[id(s)]
    s.control.call("trace_remove", addr=hex(tracker.alloc_addr))
    if tracker.free_addr is not None:
        s.control.call("trace_remove", addr=hex(tracker.free_addr))
    return "stopped"


# ---------------------------------------------------------------------------
# input


INPUT_TRACE = {}


@tool()
def input_trace_start(stack_words: int = 32):
    """Record user input: every change of the buttons/touch applied to the
    game (per frame), the code that reads the key registers (with call
    stacks), and ARM7 touch screen sampling. Report with input_trace_report."""
    s = session()
    s.sync_records()
    INPUT_TRACE[id(s)] = s.records_seq
    s.hook_set("input_state", "log")
    s.hook_set("input", "log", stack=stack_words)
    s.hook_set("touch", "log", stack=0)
    return "recording input"


@tool()
def input_trace_report(stop: bool = False, limit: int = 40):
    """Input timeline and who reads the input: which functions read
    KEYINPUT/EXTKEYIN (and how often), touch samples, and every change of
    the input by frame."""
    s = session()
    if id(s) not in INPUT_TRACE:
        raise SessionError("call input_trace_start first")
    recs = s.records_after(INPUT_TRACE[id(s)])
    if stop:
        for ev in ("input_state", "input", "touch"):
            s.hook_set(ev, "off")
    src = s.source(None, "arm9")
    readers = defaultdict(lambda: {"count": 0, "frames": set()})
    for r in recs:
        if r["event"] == "input":
            reg = "KEYINPUT" if r["args"][0] == 0x04000130 else "EXTKEYIN"
            key = (r["cpu"], reg, " > ".join(call_path(s, s.source(None, r["cpu"]), r)[-4:]))
            readers[key]["count"] += 1
            readers[key]["frames"].add(r["frame"])
    out = ["code reading the input registers:"]
    for (cpu, reg, path), v in sorted(readers.items(), key=lambda kv: -kv[1]["count"]):
        per = v["count"] / max(1, len(v["frames"]))
        out.append(f"  {cpu} {reg}: {v['count']} reads over {len(v['frames'])} frames ({per:.1f}/frame)  {path}")
    touches = [r for r in recs if r["event"] == "touch"]
    if touches:
        frames = sorted({r["frame"] for r in touches})
        out.append(f"touch screen sampled by the ARM7 in {len(frames)} frames "
                   f"(pc {s.fmt_addr(touches[0]['pc'])})")
    changes = [r for r in recs if r["event"] == "input_state"]
    out.append(f"\n{len(changes)} input changes:")
    for r in changes[-limit:]:
        mask, touch = r["args"][0], r["args"][1]
        held = "+".join(n for i, n in enumerate(["a", "b", "select", "start", "right", "left", "up", "down", "r", "l",
                                                 "x", "y", "debug", "", "lid"]) if n and mask & (1 << i)) or "-"
        t = f" touch ({touch & 0xFFFF},{(touch >> 16) & 0x7FFF})" if touch & 0x80000000 else ""
        out.append(f"  frame {r['frame']}: {held}{t}")
    return "\n".join(out)


RECORDERS = {}


@tool()
def input_record_start(path: str | None = None):
    """Record the input of this session (your emu_press/emu_touch calls and
    whatever the user plays in the window) into an input script anchored to
    a savestate taken now. Stop with input_record_stop; replay with
    input_replay or the oracle CLI, and feed the same file to another engine."""
    s = session()
    if path is None:
        d = os.path.join(data_dir(), "recordings", s.rom.game_code)
        os.makedirs(d, exist_ok=True)
        path = os.path.join(d, time.strftime("%Y%m%d-%H%M%S") + ".inputs")
    RECORDERS[id(s)] = Recorder(s, path)
    return f"recording input to {path} (start state {RECORDERS[id(s)].state_path}); the game is paused"


@tool()
def input_record_stop():
    """Finish the recording and write the input script."""
    s = session()
    rec = RECORDERS.pop(id(s), None)
    if rec is None:
        raise SessionError("not recording")
    script = rec.stop()
    with open(rec.out_path) as f:
        body = "\n".join(l for l in f.read().splitlines() if not l.startswith("#"))
    return f"wrote {rec.out_path}: {len(script.events)} changes over {script.end} frames\n{body[:3000]}"


@tool()
def input_replay(path: str, sample: list[str] | None = None, screenshot: bool = True):
    """Replay an input script in this session: load its start state and
    apply the input frame by frame. sample: values to record every frame,
    as 'name:type:address' (e.g. 'x:s32:g_player'). Deterministic when the
    CPU mode matches the recording (see the 'cpu' line)."""
    s = session()
    script = InputScript.load(path)
    o = Oracle.attach(s)
    if script.cpu != o.cpu_mode:
        raise SessionError(f"script recorded with cpu {script.cpu}, session uses {o.cpu_mode}")
    _to_frame_boundary(s)
    if script.state:
        o.load(script.state)
    series = {}
    probes = [p.split(":", 2) for p in sample or []]

    def on_frame(oracle, f):
        for name, type_, addr in probes:
            series.setdefault(name, []).append(oracle.read(addr, type_))

    o.play(script, on_frame if probes else None)
    text = f"replayed {script.length()} frames from {path}"
    for name, vals in series.items():
        text += f"\n{name}: {vals}"
    return [text, screenshot_image()] if screenshot else text


@tool()
def oracle_run(script_path: str):
    """Run an oracle test script (see oracle_help) in this session and
    return the results: probes, per-frame samples and expectations."""
    s = session()
    _to_frame_boundary(s)
    o = Oracle.attach(s)
    results = {"steps": [], "probes": [], "series": {}, "expects": [], "errors": []}
    run_test_script(o, script_path, results)
    results["passed"] = not results["errors"] and all(e["ok"] for e in results["expects"])
    return json.dumps({k: v for k, v in results.items() if k != "steps"}, indent=1)


@tool()
def oracle_help():
    """The oracle test script language and the input script format."""
    from .oracle import INPUT_SCRIPT_FORMAT
    return TEST_SCRIPT_HELP + "\n" + INPUT_SCRIPT_FORMAT


# ---------------------------------------------------------------------------
# performance: where the time goes, what runs every frame


MODE_NAMES = {0x10: "usr", 0x11: "fiq", 0x12: "irq", 0x13: "svc", 0x17: "abt", 0x1B: "und", 0x1F: "sys"}

# hardware fingerprints: (category, registers that must all be touched)
NITRO_RULES = [
    ("card", ("ROMCTRL",)), ("card", ("CARD_DATA",)), ("card", ("AUXSPICNT",)),
    ("pxi_ipc", ("IPCFIFOSEND",)), ("pxi_ipc", ("IPCFIFOCNT",)), ("pxi_ipc", ("IPCSYNC",)),
    ("irq", ("IME", "IE")), ("irq", ("IF",)), ("irq", ("IME",)),
    ("math_div", ("DIVCNT",)), ("math_div", ("DIV_NUMER",)), ("math_sqrt", ("SQRTCNT",)),
    ("pad_input", ("KEYINPUT",)), ("timer", ("TM0CNT",)), ("timer", ("TM1CNT",)), ("timer", ("TM2CNT",)),
    ("timer", ("TM3CNT",)),
    ("dma", ("DMA0CNT",)), ("dma", ("DMA1CNT",)), ("dma", ("DMA2CNT",)), ("dma", ("DMA3CNT",)),
    ("dma_fill", ("DMA0FILL",)), ("dma_fill", ("DMA1FILL",)), ("dma_fill", ("DMA2FILL",)), ("dma_fill", ("DMA3FILL",)),
    ("gx_vram", ("VRAMCNT_A",)), ("gx_vram", ("VRAMCNT_C",)), ("gx_vram", ("VRAMCNT_E",)), ("gx_wram", ("WRAMCNT",)),
    ("gx_power", ("POWCNT1",)), ("gx_disp", ("DISPCNT",)), ("gx_disp", ("DISPCNT_SUB",)), ("gx_disp", ("DISPSTAT",)),
    ("gx_bg", ("BG0CNT",)), ("gx_bg", ("BG0CNT_SUB",)), ("gx_blend", ("BLDCNT",)), ("gx_bright", ("MASTER_BRIGHT",)),
    ("g3_fifo", ("GXFIFO",)), ("g3_matrix", ("MTX_MODE",)), ("g3_matrix", ("MTX_PUSH",)), ("g3_matrix", ("MTX_LOAD_4x4",)),
    ("g3_matrix", ("MTX_MULT_4x3",)), ("g3_vtx", ("VTX_16",)), ("g3_vtx", ("BEGIN_VTXS",)), ("g3_tex", ("TEXIMAGE_PARAM",)),
    ("g3_swap", ("SWAP_BUFFERS",)), ("g3_state", ("DISP3DCNT",)), ("g3_state", ("GXSTAT",)), ("g3_state", ("CLEAR_COLOR",)),
    ("g3_result", ("POS_RESULT",)), ("g3_result", ("CLIPMTX_RESULT",)), ("g3_light", ("LIGHT_VECTOR",)),
    ("exmem", ("EXMEMCNT",)),
]


class FuncIndex:
    """Maps addresses to functions using labels plus the call graph (the
    function containing pc is the nearest call target at or below it)."""

    def __init__(self, s, src):
        import bisect
        self._bisect = bisect
        self.s = s
        graph = _graph(src)
        starts = {t & ~1 for t in graph}
        starts |= {a for a, e in s.labels.labels.items() if e["type"] == "func"}
        self.starts = sorted(starts)
        self.graph = graph

    def start_of(self, addr):
        i = self._bisect.bisect_right(self.starts, addr & ~1) - 1
        if i < 0:
            return None
        start = self.starts[i]
        return start if (addr & ~1) - start < 0x4000 else None

    def name(self, addr):
        start = self.start_of(addr)
        if start is None:
            return f"{addr:#010x}"
        label = self.s.labels.labels.get(start)
        return label["name"] if label else f"sub_{start:08x}"


def _irq_handler(s):
    """ARM9 IRQ handler: the BIOS jumps to the address stored at DTCM+0x3FFC."""
    try:
        dtcm = int(s.control.call("memory_map")["dtcm"], 16)
        return struct.unpack("<I", s.control.read_memory(dtcm + 0x3FFC, 4))[0]
    except (ControlError, KeyError, ValueError):
        return None


@tool()
def perf_profile(frames: int = 60, interval: int = 500, limit: int = 25, cpu: str = "arm9"):
    """Sampling profiler: run N frames sampling the CPU every `interval`
    instructions, then report the functions where the time goes (self time)
    and who calls them. Idle loops (waiting for VBlank) show up too, which
    tells you where the frame ends."""
    s = session()
    for g in s.gdb.values():
        if not g.is_running():
            g.cont()
    s.control.call("profile_start", interval=interval)
    try:
        emu_frame_advance(frames)
    finally:
        s.control.call("profile_stop")
    r = s.control.call("profile_get")
    want = 0 if cpu == "arm9" else 1
    counts = [c for c in r["counts"] if c[0] == want]
    total = sum(c[3] for c in counts) or 1
    idx = FuncIndex(s, s.source(None, cpu))
    self_time = Counter()
    callers = defaultdict(Counter)
    hot_pcs = defaultdict(Counter)
    stacks = defaultdict(lambda: [0, Counter(), Counter()])  # sp bucket -> [samples, funcs, modes]
    for _, pc, lr, n, sp, mode in counts:
        f = idx.name(pc)
        self_time[f] += n
        hot_pcs[f][pc] += n
        callers[f][idx.name(lr & ~1)] += n
        st = stacks[sp]
        st[0] += n
        st[1][f] += n
        st[2][MODE_NAMES.get(mode, hex(mode))] += n
    lines = [f"{total} samples over {frames} frames ({cpu}, every {interval} instructions)",
             "self time by function:"]
    for f, n in self_time.most_common(limit):
        top_pc = hot_pcs[f].most_common(1)[0][0]
        who = ", ".join(f"{c} {v * 100 // n}%" for c, v in callers[f].most_common(3))
        lines.append(f"  {n * 100 / total:5.1f}%  {f:<28} hottest {top_pc:#010x}  lr (approx.) in: {who}")
    # every thread (and the IRQ/SVC modes) runs on its own stack: cluster
    # the samples by stack pointer to see them
    clusters = []
    for sp in sorted(stacks):
        n, funcs, modes = stacks[sp]
        if clusters and sp - clusters[-1]["hi"] <= 0x1000 and set(modes) == set(clusters[-1]["modes"]):
            c = clusters[-1]
            c["hi"] = sp
            c["n"] += n
            c["funcs"].update(funcs)
            c["modes"].update(modes)
        else:
            clusters.append({"lo": sp, "hi": sp, "n": n, "funcs": Counter(funcs), "modes": Counter(modes)})
    lines.append(f"\nstacks in use ({len(clusters)}; each thread and each exception mode has its own):")
    for c in sorted(clusters, key=lambda c: -c["n"]):
        lines.append(f"  sp {c['lo']:#010x}-{c['hi'] + 0xFF:#010x} {c['n'] * 100 / total:5.1f}% "
                     f"mode {'/'.join(c['modes'])}: " + ", ".join(f for f, _ in c["funcs"].most_common(5)))
    return "\n".join(lines)


@tool()
def func_hot(frames: int = 60, limit: int = 25, source: str | None = None):
    """Count calls to every known function (all direct call targets plus
    labelled functions) over N frames. Reports functions called exactly once
    per frame (game tick / update / render candidates, with how they nest),
    the most called functions, and the IRQ handler. Slows emulation while
    it runs."""
    s = session()
    src = s.source(source, "arm9")
    idx = FuncIndex(s, src)
    targets = sorted({t & ~1 for t in idx.graph} | set(idx.starts))
    irq = _irq_handler(s)
    if irq and 0x01FF8000 <= (irq & ~1) < 0x02400000:
        targets.append(irq & ~1)
    added = []
    for i in range(0, len(targets), 400):
        chunk = targets[i:i + 400]
        s.control.call("trace_count_add", addrs=",".join(hex(a) for a in chunk))
        added.extend(chunk)
    try:
        before = {int(t["addr"], 16): t["hits"] for t in s.control.call("trace_list")["tracepoints"]}
        for g in s.gdb.values():
            if not g.is_running():
                g.cont()
        emu_frame_advance(frames)
        after = {int(t["addr"], 16): t["hits"] for t in s.control.call("trace_list")["tracepoints"]}
    finally:
        for i in range(0, len(added), 400):
            s.control.call("trace_count_remove", addrs=",".join(hex(a) for a in added[i:i + 400]))
    hits = {a: after.get(a, 0) - before.get(a, 0) for a in added}
    called = {a: n for a, n in hits.items() if n}

    def nm(a):
        label = s.labels.labels.get(a)
        return label["name"] if label else f"sub_{a:08x}"

    once = sorted(a for a, n in called.items() if n == frames)
    lines = [f"{len(called)} of {len(added)} functions ran during {frames} frames"]
    if irq:
        lines.append(f"IRQ handler (from DTCM+0x3FFC): {s.fmt_addr(irq & ~1)} ran {hits.get(irq & ~1, 0)} times "
                     f"({hits.get(irq & ~1, 0) / frames:.1f}/frame)")
    lines.append(f"\ncalled exactly once per frame ({len(once)}) - tick/update/render candidates:")
    once_set = set(once)
    for a in once[:limit * 2]:
        sites = idx.graph.get(a, []) + idx.graph.get(a | 1, [])
        callers_ = sorted({idx.name(site) for site in sites})
        callees = sorted({nm(t & ~1) for t, st in idx.graph.items()
                          if (t & ~1) in once_set and any(idx.start_of(x) == a for x in st)})
        lines.append(f"  {s.fmt_addr(a)}  called from {', '.join(callers_[:4]) or '?'}"
                     + (f"  -> calls per-frame {', '.join(callees[:6])}" if callees else ""))
    per_frame = sorted(((n / frames, a) for a, n in called.items() if n % frames == 0 and n > frames),
                       reverse=True)
    if per_frame:
        lines.append("\ncalled a whole number of times every frame (loops over objects/entities?):")
        for rate, a in per_frame[:limit]:
            lines.append(f"  {rate:6.0f}/frame  {s.fmt_addr(a)}")
    lines.append("\nmost called:")
    for a, n in sorted(called.items(), key=lambda kv: -kv[1])[:limit]:
        lines.append(f"  {n:8} ({n / frames:8.1f}/frame)  {s.fmt_addr(a)}")
    return "\n".join(lines)


@tool()
def nitro_scan(apply: bool = False, source: str | None = None, max_functions: int = 6000):
    """Identify the Nintendo SDK (NitroSDK/TwlSDK) and middleware in the
    game and fingerprint functions by the hardware they touch (card I/O,
    IPC with the ARM7, interrupts, divide unit, DMA, 2D/3D registers...).
    SDK code is statically linked, so these low level functions are the
    same in every game of an SDK version; knowing them names the layers
    above (file system, threads, graphics). apply=True labels unlabelled
    functions as <category>_<address> with the evidence as a comment."""
    s = session()
    src = s.source(source, "arm9")
    out = []
    # 1. version markers
    markers = set()
    for blob in (s.rom.arm9_binary(),) + tuple(s.rom.overlay_binary("arm9", o.id) for o in s.rom.overlays
                                                if o.cpu == "arm9")[:64]:
        for m in re.finditer(rb"\[SDK\+[ -~]{3,80}?\]", blob):
            markers.add(m.group(0).decode())
    out.append("SDK/middleware markers: " + (", ".join(sorted(markers)) if markers else
                                             "none found (not a Nitro SDK game, or stripped)"))

    # 2. hardware fingerprints
    idx = FuncIndex(s, src)
    starts = idx.starts[:max_functions]
    found = defaultdict(list)
    for i, start in enumerate(starts):
        end = starts[i + 1] if i + 1 < len(starts) else start + 0x400
        end = min(end, start + 0x1000)
        raw = src.read(start, end - start + 0x40)
        # cheap filter: only functions with an I/O address in reach
        if not any(0x04000000 <= w < 0x05000000 for w in struct.unpack(f"<{len(raw) // 4}I", raw[:len(raw) // 4 * 4])):
            continue
        thumb = _is_thumb_func(src, start)
        size = 2 if thumb else 4
        listing = s.disassemble(src, start | (1 if thumb else 0), max(1, min((end - start) // size, 400)),
                                thumb=thumb)
        regs = {n.split("+")[0] for n in re.findall(r"io:(\S+)", listing)}
        if not regs:
            continue
        cats = []
        for cat, need in NITRO_RULES:
            if all(r in regs for r in need) and cat not in cats:
                cats.append(cat)
        if cats:
            found[cats[0]].append((start, sorted(regs), cats))
    applied = 0
    for cat in sorted(found):
        items = found[cat]
        out.append(f"\n{cat} ({len(items)}):")
        for start, regs, cats in items[:25]:
            label = s.labels.labels.get(start)
            out.append(f"  {s.fmt_addr(start)}  touches {', '.join(regs[:8])}"
                       + (f"  (also {', '.join(cats[1:])})" if len(cats) > 1 else ""))
            if apply and not label:
                s.labels.set(start, f"{cat}_{start:08x}", "func", 0, "auto (nitro_scan): touches " + ", ".join(regs[:8]))
                applied += 1
    if apply:
        out.append(f"\nlabelled {applied} functions")
    irq = _irq_handler(s)
    if irq:
        out.append(f"\nIRQ handler (DTCM+0x3FFC): {s.fmt_addr(irq & ~1)}")
    return "\n".join(out)


def main():
    try:
        mcp.run()
    finally:
        if S is not None:
            S.stop()
