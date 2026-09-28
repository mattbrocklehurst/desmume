"""MCP server exposing DeSmuME (emulator control, gdb-backed debugger,
memory analysis, ROM tools, labels, freeze dumps, event hooks) to agents.

Run with:  python3 -m desmume_mcp   (stdio transport)
"""

import json
import os
import re
import struct
import time
from collections import Counter, OrderedDict

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
from .session import Session, SessionError, data_dir

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
    snapshot per event for call chains (default 16, 0 for gx). frames: turn
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
    """Show recorded hook events (oldest first): frame, pc and caller chain,
    and for card reads the file and offset read. clear=True removes them from
    the buffer afterwards."""
    s = session()
    recs = s.hook_records()
    if clear:
        s.control.call("hook_clear")
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
    s.control.call("hook_clear")
    s.hook_set("gx", "log", stack=0)
    s.hook_set("swap", "log", stack=16)
    # capture one extra frame and cut at SWAP_BUFFERS so that the result
    # holds whole 3D frames even when we start in the middle of one
    emu_frame_advance(frames + 1)
    recs = s.hook_records()
    s.hook_set("gx", "off")
    s.hook_set("swap", "off")
    s.control.call("hook_clear")

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


def main():
    try:
        mcp.run()
    finally:
        if S is not None:
            S.stop()
