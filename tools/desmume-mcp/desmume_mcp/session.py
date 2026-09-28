"""An emulator session: launches desmume-cli, owns the control and gdb
connections, and implements the debugger conveniences (temporary and
conditional breakpoints, step over, run to return, call tracing) on top of
the gdb stub."""

import os
import re
import shutil
import socket
import struct
import subprocess
import time

from .control import ControlClient, ControlError
from .gdbrsp import GdbClient, GdbError, SIGINT
from .hw import io_name
from .labels import LabelDB
from .memory import (Disassembler, DumpSource, LiveSource, RomSource, arm_branch_target,
                     branch_target, find_function_start, is_call_before, stack_scan,
                     thumb_bl_target)
from .rom import Rom

REPO_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "..", ".."))
REG_NAMES = [f"r{i}" for i in range(13)] + ["sp", "lr", "pc"]


class SessionError(RuntimeError):
    pass


def data_dir():
    d = os.environ.get("DESMUME_MCP_HOME") or os.path.join(
        os.environ.get("XDG_DATA_HOME") or os.path.expanduser("~/.local/share"), "desmume-mcp")
    os.makedirs(d, exist_ok=True)
    return d


def find_desmume():
    candidates = [os.environ.get("DESMUME_CLI"), shutil.which("desmume-cli"),
                  os.path.join(REPO_ROOT, "desmume/src/frontend/posix/build/cli/desmume-cli")]
    for c in candidates:
        if c and os.path.isfile(c) and os.access(c, os.X_OK):
            return c
    raise SessionError("desmume-cli not found: build it with tools/desmume-mcp/scripts/build-desmume.sh "
                       "or set DESMUME_CLI")


def free_port():
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    port = s.getsockname()[1]
    s.close()
    return port


def slug(text):
    return re.sub(r"[^A-Za-z0-9]+", "-", text).strip("-")[:40] or "dump"


REG_ALIAS = {"sb": "r9", "sl": "r10", "fp": "r11", "ip": "r12", "sp": "r13", "lr": "r14", "pc": "r15"}
CONDS = ("eq", "ne", "cs", "hs", "cc", "lo", "mi", "pl", "vs", "vc", "hi", "ls", "ge", "lt", "gt", "le")
NO_DEST = ("str", "cmp", "cmn", "tst", "teq", "b", "push", "stm", "pld", "svc", "swi", "bkpt", "nop", "mcr")


def _reg(name):
    return REG_ALIAS.get(name, name)


def _track_consts(consts, mnem, ops, lit_val):
    """Update known register values after one instruction (conservative)."""
    base = mnem.split(".")[0]
    cond = len(base) > 3 and base[-2:] in CONDS and base[:-2] in ("mov", "mvn", "add", "sub", "orr", "ldr", "movs", "adds", "subs")
    if cond:
        base = base[:-2]
    if base in ("bl", "blx") or base.startswith("bl"):
        for r in ("r0", "r1", "r2", "r3", "r12", "r14"):
            consts.pop(r, None)
        return
    if base in ("b", "bx") or base.startswith(("pop", "ldm")) and "pc" in ops:
        consts.clear()
        return
    if base.startswith(("pop", "ldm")):
        for r in re.findall(r"\b(r\d+|sb|sl|fp|ip|lr)\b", ops):
            consts.pop(_reg(r), None)
        return
    if base.startswith(NO_DEST) and not base.startswith(("sub", "strex")):
        if "]!" in ops or re.search(r"\], #", ops):  # writeback changes the base register
            m = re.search(r"\[(\w+)", ops)
            if m:
                consts.pop(_reg(m.group(1)), None)
        return
    toks = [t.strip() for t in ops.split(",")]
    if not toks or not toks[0]:
        return
    dest = _reg(toks[0])
    value = None
    try:
        if base.startswith("ldr") and lit_val is not None and base in ("ldr",):
            value = lit_val
        elif base in ("mov", "movs") and len(toks) == 2 and toks[1].startswith("#"):
            value = int(toks[1][1:], 0) & 0xFFFFFFFF
        elif base in ("mvn", "mvns") and len(toks) == 2 and toks[1].startswith("#"):
            value = ~int(toks[1][1:], 0) & 0xFFFFFFFF
        elif base in ("add", "adds", "sub", "subs", "orr", "orrs") and toks[-1].startswith("#"):
            src_reg = _reg(toks[1]) if len(toks) == 3 else dest
            if src_reg in consts:
                imm = int(toks[-1][1:], 0)
                v = consts[src_reg]
                value = (v + imm if base.startswith("add") else v - imm if base.startswith("sub") else v | imm) & 0xFFFFFFFF
        elif base in ("mov", "movs") and len(toks) == 2 and _reg(toks[1]) in consts:
            value = consts[_reg(toks[1])]
    except ValueError:
        value = None
    if value is None or cond:
        consts.pop(dest, None)
    else:
        consts[dest] = value


class Breakpoint:
    def __init__(self, num, cpu, kind, addr, length, temp=False, condition=None):
        self.num, self.cpu, self.kind, self.addr, self.length = num, cpu, kind, addr, length
        self.temp = temp
        self.condition = condition
        self.hits = 0

    def describe(self, labels):
        name = labels.describe(self.addr)
        where = f"{self.addr:#010x}" + (f" <{name}>" if name else "")
        what = "breakpoint" if self.kind == "exec" else f"{self.kind} watchpoint ({self.length} bytes)"
        extra = []
        if self.condition:
            extra.append(f"if {self.condition}")
        if self.temp:
            extra.append("temporary")
        extra.append(f"hits={self.hits}")
        return f"#{self.num} {self.cpu} {what} at {where} " + " ".join(extra)


class Session:
    def __init__(self, rom_path, desmume=None, arm7=False, headless=None, start_halted=False,
                 extra_args=(), sound=None):
        self.rom_path = os.path.abspath(rom_path)
        if not os.path.isfile(self.rom_path):
            raise SessionError(f"ROM not found: {rom_path}")
        self.rom = Rom(self.rom_path)
        self.desmume = desmume or find_desmume()
        self.arm7 = arm7
        if headless is None:
            headless = not (os.environ.get("DISPLAY") or os.environ.get("WAYLAND_DISPLAY"))
        self.headless = headless
        self.sound = (not headless) if sound is None else sound
        self.start_halted = start_halted
        self.extra_args = list(extra_args)
        self.data_dir = data_dir()
        self.labels = LabelDB(os.path.join(self.data_dir, "labels", f"{self.rom.game_code or 'UNKNOWN'}.json"))
        self.dump_root = os.path.join(self.data_dir, "dumps", self.rom.game_code or "UNKNOWN")
        self.state_root = os.path.join(self.data_dir, "states", self.rom.game_code or "UNKNOWN")
        self.proc = None
        self.control = None
        self.gdb = {}
        self.ports = {}
        self.breakpoints = {}
        self.next_bp = 1
        self.scan = None
        self._dis = None
        self.log_path = None

    # lifecycle --------------------------------------------------------------

    def start(self, timeout=20.0):
        self.ports = {"control": free_port(), "arm9": free_port()}
        if self.arm7:
            self.ports["arm7"] = free_port()
        cmd = [self.desmume, "--control-port", str(self.ports["control"]),
               "--arm9gdb", str(self.ports["arm9"])]
        if self.arm7:
            cmd += ["--arm7gdb", str(self.ports["arm7"])]
        if not self.sound:
            cmd.append("--disable-sound")
        cmd += self.extra_args + [self.rom_path]
        env = dict(os.environ)
        env["DESMUME_DUMP_DIR"] = self.dump_root
        if not self.sound:
            env.setdefault("SDL_AUDIODRIVER", "dummy")
        if self.headless:
            xvfb = shutil.which("xvfb-run")
            if not xvfb:
                raise SessionError("no display and xvfb-run is not installed (apt install xvfb), "
                                   "or start with headless=false on a desktop")
            cmd = [xvfb, "-a"] + cmd

        os.makedirs(os.path.join(self.data_dir, "logs"), exist_ok=True)
        os.makedirs(self.dump_root, exist_ok=True)
        self.log_path = os.path.join(self.data_dir, "logs", time.strftime("%Y%m%d-%H%M%S") + ".log")
        log = open(self.log_path, "wb")
        self.proc = subprocess.Popen(cmd, stdout=log, stderr=subprocess.STDOUT, stdin=subprocess.DEVNULL,
                                     env=env, start_new_session=True)

        deadline = time.time() + timeout
        while True:
            if self.proc.poll() is not None:
                raise SessionError(f"desmume-cli exited with code {self.proc.returncode}:\n{self.log_tail()}")
            try:
                self.control = ControlClient(port=self.ports["control"])
                break
            except OSError:
                if time.time() > deadline:
                    self.stop()
                    raise SessionError(f"timed out waiting for desmume-cli:\n{self.log_tail()}")
                time.sleep(0.2)

        # both CPUs start halted, waiting for the debugger
        for cpu in ("arm9", "arm7") if self.arm7 else ("arm9",):
            self.attach(cpu)
        if not self.start_halted:
            for cpu in list(self.gdb):
                self.gdb[cpu].cont()

    def alive(self):
        return self.proc is not None and self.proc.poll() is None

    def stop(self):
        for g in list(self.gdb.values()):
            g.close()
        self.gdb = {}
        if self.control:
            try:
                self.control.call("quit", timeout=3)
            except Exception:
                pass
            self.control.close()
            self.control = None
        if self.proc:
            try:
                self.proc.wait(timeout=5)
            except subprocess.TimeoutExpired:
                os.killpg(self.proc.pid, 15)
                try:
                    self.proc.wait(timeout=3)
                except subprocess.TimeoutExpired:
                    os.killpg(self.proc.pid, 9)
            self.proc = None

    def log_tail(self, lines=30):
        if not self.log_path or not os.path.exists(self.log_path):
            return ""
        with open(self.log_path, "rb") as f:
            text = f.read().decode("utf-8", "replace")
        text = "\n".join(l for l in text.splitlines() if not l.startswith("ALSA lib"))
        return "\n".join(text.splitlines()[-lines:])

    def attach(self, cpu="arm9"):
        if cpu in self.gdb:
            return self.gdb[cpu]
        if cpu not in self.ports:
            raise SessionError(f"{cpu} debugging was not enabled when the emulator was started")
        self.gdb[cpu] = GdbClient(port=self.ports[cpu])
        # re-install the breakpoints we know about (they are dropped on detach)
        for bp in self.breakpoints.values():
            if bp.cpu == cpu:
                self.gdb[cpu].set_break(bp.kind, bp.addr, bp.length)
        return self.gdb[cpu]

    def detach(self, cpu="arm9"):
        g = self.gdb.pop(cpu, None)
        if g:
            g.detach()

    # helpers ----------------------------------------------------------------

    @property
    def dis(self):
        if self._dis is None:
            self._dis = Disassembler()
        return self._dis

    def g(self, cpu="arm9"):
        if cpu not in self.gdb:
            raise SessionError(f"the debugger is not attached to {cpu} (use dbg_attach)")
        return self.gdb[cpu]

    def status(self):
        st = self.control.call("status")
        st["debugger"] = {cpu: ("running" if g.is_running() else "halted") for cpu, g in self.gdb.items()}
        return st

    def registers(self, cpu="arm9"):
        return self.control.registers(cpu)

    def source(self, spec=None, cpu="arm9"):
        """None/'live' -> emulator memory, 'rom:arm9'/'rom:overlay:N' -> ROM
        file, anything else -> path of a freeze dump directory."""
        if not spec or spec == "live":
            if not self.control:
                raise SessionError("the emulator is not running")
            return LiveSource(self.control, cpu)
        if spec.startswith("rom:"):
            return RomSource(self.rom, spec[4:])
        return DumpSource(self.resolve_dump(spec), cpu)

    def resolve_dump(self, spec):
        if spec.startswith("dump:"):
            spec = spec[5:]
        if os.path.isdir(spec):
            return spec
        cand = os.path.join(self.dump_root, spec)
        if os.path.isdir(cand):
            return cand
        raise SessionError(f"no dump directory {spec}")

    def resolve(self, expr, cpu="arm9", regs=None):
        """Evaluate 'label', 'label+0x10', 'sp+8', 'lr-4', '0x02000000', 1234."""
        if isinstance(expr, int):
            return expr
        expr = str(expr).strip()
        total = 0
        for sign, term in re.findall(r"([+-]?)\s*([^+\-\s]+)", expr):
            val = None
            t = term
            if re.fullmatch(r"0[xX][0-9a-fA-F]+|\d+", t):
                val = int(t, 0)
            elif re.fullmatch(r"[0-9a-fA-F]{8}", t):
                val = int(t, 16)
            else:
                addr = self.labels.lookup_name(t)
                if addr is not None:
                    val = addr
                elif t.lower() in REG_NAMES + ["r13", "r14", "r15", "cpsr"]:
                    if regs is None:
                        regs = self.registers(cpu)
                    key = {"sp": "r13", "lr": "r14", "r15": "pc"}.get(t.lower(), t.lower())
                    val = int(regs[key], 16) if key != "r13" and key != "r14" else int(regs[key], 16)
            if val is None:
                raise SessionError(f"cannot resolve '{t}' (not a number, label or register)")
            total += -val if sign == "-" else val
        return total & 0xFFFFFFFF

    def fmt_addr(self, addr):
        name = self.labels.describe(addr)
        return f"{addr:#010x}" + (f" <{name}>" if name else "")

    # disassembly -----------------------------------------------------------

    def disassemble(self, src, addr, count=20, thumb=None, pc=None, cpu="arm9"):
        """Listing with labels, literal pool values, and memory operands
        resolved through simple register constant tracking, so that code like
        'ldr r2, =0x04000100; str r3, [r2, #0xa4]' is annotated with ROMCTRL."""
        if thumb is None:
            thumb = bool(addr & 1)
        addr &= ~1 if thumb else ~3
        data = src.read(addr, count * 4 + 4)
        bps = {bp.addr for bp in self.breakpoints.values() if bp.kind == "exec" and bp.cpu == cpu}
        lines = [f"; {src.name} {'thumb' if thumb else 'arm'}"]
        consts = {}
        for a, sz, raw, mnem, ops in self.dis.disasm(data, addr, thumb=thumb, count=count):
            label = self.labels.labels.get(a)
            if label:
                lines.append(f"{label['name']}:" + (f"    ; {label['comment']}" if label.get("comment") else ""))
                if label["type"] == "func":
                    consts.clear()
            marker = "=>" if pc is not None and a == pc else "  "
            marker += "*" if a in bps else " "
            text = f"{mnem} {ops}".strip()
            notes = []
            t = branch_target(ops) if mnem.startswith(("b", "cb")) else None
            if t is not None:
                name = self.labels.describe(t & ~1)
                if name:
                    notes.append(f"<{name}>")
            lit_val = None
            m = re.search(r"\[pc, #(-?0x[0-9a-f]+|-?\d+)\]", ops)
            if m and mnem.startswith("ldr"):
                lit = ((a + (4 if thumb else 8)) & ~3) + int(m.group(1), 0)
                try:
                    lit_val = src.u32(lit)
                    name = self.labels.describe(lit_val)
                    notes.append(f"={lit_val:#010x}" + (f" <{name}>" if name else ""))
                except Exception:
                    pass
            else:
                mem = re.search(r"\[(\w+)(?:, #(-?0x[0-9a-f]+|-?\d+))?\]", ops)
                if mem and _reg(mem.group(1)) in consts:
                    target = (consts[_reg(mem.group(1))] + int(mem.group(2) or "0", 0)) & 0xFFFFFFFF
                    io = io_name(target)
                    name = self.labels.describe(target)
                    notes.append(f"io:{io}" if io else f"[{target:#010x}]" + (f" <{name}>" if name else ""))
            _track_consts(consts, mnem, ops, lit_val)
            lines.append(f"{marker}{a:08x}: {raw.hex():<8}  {text:<32}" + (" ; " + " ".join(notes) if notes else ""))
        return "\n".join(lines)

    def context(self, cpu="arm9", before=4, after=8, src=None, regs=None):
        """Registers plus disassembly around pc, for stop reports and dumps."""
        if regs is None:
            regs = self.registers(cpu) if src is None or isinstance(src, LiveSource) else src.registers(cpu)
        if src is None:
            src = self.source(None, cpu)
        pc = int(regs["pc"], 16)
        thumb = regs.get("thumb", False)
        size = 2 if thumb else 4
        lines = [self.format_registers(regs, cpu), ""]
        lines.append(self.disassemble(src, (pc - before * size) | (1 if thumb else 0), before + after,
                                      thumb=thumb, pc=pc, cpu=cpu))
        return "\n".join(lines)

    def format_registers(self, regs, cpu="arm9"):
        r = [int(regs[f"r{i}"], 16) for i in range(15)]
        pc = int(regs["pc"], 16)
        rows = []
        for i in range(0, 13, 4):
            rows.append("  ".join(f"{('r' + str(j)):>3}={r[j]:08x}" for j in range(i, min(i + 4, 13))))
        rows.append(f" sp={r[13]:08x}   lr={r[14]:08x} {self._lr_hint(r[14])}")
        rows.append(f" pc={pc:08x} {self.fmt_addr(pc)[10:]}  cpsr={regs['cpsr']} "
                    f"mode={regs['mode']} {'thumb' if regs['thumb'] else 'arm'}"
                    f"{' irq-off' if regs.get('irq_disabled') else ''}")
        return f"[{cpu}]\n" + "\n".join(rows)

    def _lr_hint(self, lr):
        name = self.labels.describe(lr & ~1)
        return f"<{name}>" if name else ""

    # breakpoints -------------------------------------------------------------

    def _with_halt(self, cpu, fn):
        """Run fn with the CPU halted (the stub only accepts packets while
        halted), resuming afterwards if it was running."""
        g = self.g(cpu)
        was_running = g.is_running()
        if was_running:
            g.halt()
        try:
            return fn(g)
        finally:
            if was_running:
                g.cont()

    def add_breakpoint(self, addr, cpu="arm9", kind="exec", length=None, temp=False, condition=None):
        if length is None:
            length = 4 if kind != "exec" else 4
        for bp in self.breakpoints.values():
            if (bp.cpu, bp.kind, bp.addr) == (cpu, kind, addr):
                bp.condition = condition
                bp.temp = temp
                return bp
        if condition:
            self._check_condition(condition)
        self._with_halt(cpu, lambda g: g.set_break(kind, addr, length))
        bp = Breakpoint(self.next_bp, cpu, kind, addr, length, temp, condition)
        self.breakpoints[bp.num] = bp
        self.next_bp += 1
        return bp

    def remove_breakpoint(self, bp):
        self.breakpoints.pop(bp.num, None)
        if bp.cpu in self.gdb:
            self._with_halt(bp.cpu, lambda g: g.clear_break(bp.kind, bp.addr, bp.length))

    def find_breakpoint(self, spec, cpu="arm9"):
        """By number ('#3' or 3) or by address expression."""
        s = str(spec).strip()
        if s.startswith("#") or (s.isdigit() and int(s) in self.breakpoints and len(s) < 6):
            num = int(s.lstrip("#"))
            if num in self.breakpoints:
                return self.breakpoints[num]
            raise SessionError(f"no breakpoint #{num}")
        addr = self.resolve(s, cpu)
        for bp in self.breakpoints.values():
            if bp.addr == addr and bp.cpu == cpu:
                return bp
        raise SessionError(f"no breakpoint at {addr:#010x}")

    def _condition_env(self, cpu, regs):
        env = {f"r{i}": regs[i] for i in range(16)}
        env.update(sp=regs[13], lr=regs[14], pc=regs[15])
        src = self.source(None, cpu)

        def rd(size, signed=False):
            fmt = {1: "b", 2: "h", 4: "i"}[size]
            return lambda a: struct.unpack("<" + (fmt if signed else fmt.upper()), src.read(a & 0xFFFFFFFF, size))[0]
        env.update(u8=rd(1), u16=rd(2), u32=rd(4), s8=rd(1, True), s16=rd(2, True), s32=rd(4, True))
        return env

    def _check_condition(self, cond):
        try:
            compile(cond, "<condition>", "eval")
        except SyntaxError as e:
            raise SessionError(f"bad condition: {e}")

    def _eval_condition(self, cond, cpu, regs):
        try:
            return bool(eval(cond, {"__builtins__": {}}, self._condition_env(cpu, regs)))
        except Exception as e:
            raise SessionError(f"condition '{cond}' failed: {e}")

    # execution ---------------------------------------------------------------

    def resume_frames(self):
        """The main loop must be running for the CPU to make progress."""
        try:
            self.control.call("resume")
        except ControlError:
            pass

    def cont(self, cpu="arm9", timeout=5.0):
        """Continue until a breakpoint/watchpoint (honouring conditions and
        temporary breakpoints) or until timeout. Returns a stop dict, or None
        if the CPU is still running."""
        g = self.g(cpu)
        self.resume_frames()
        deadline = time.time() + timeout
        g.cont()
        while True:
            stop = g.wait_stop(max(0.0, deadline - time.time()))
            if stop is None:
                return None
            info = self._classify_stop(cpu, stop)
            bp = info.get("breakpoint")
            if bp and bp.condition and not self._eval_condition(bp.condition, cpu, info["regs"]):
                bp.hits -= 1
                if time.time() >= deadline:
                    return None
                g.cont()
                continue
            if bp and bp.temp:
                self.remove_breakpoint(bp)
            return info

    def _classify_stop(self, cpu, stop):
        g = self.g(cpu)
        regs, cpsr = g.read_registers()
        pc = regs[15]
        info = {"cpu": cpu, "pc": pc, "regs": regs, "stop": stop}
        if stop.watch_kind:
            info["reason"] = f"{stop.watch_kind} watchpoint"
            for bp in self.breakpoints.values():
                if bp.cpu == cpu and bp.kind != "exec" and bp.addr == stop.watch_addr:
                    bp.hits += 1
                    info["breakpoint"] = bp
            info["watch_addr"] = stop.watch_addr
        elif stop.signal == SIGINT:
            info["reason"] = "interrupted"
        else:
            info["reason"] = "stopped"
            for bp in self.breakpoints.values():
                if bp.cpu == cpu and bp.kind == "exec" and bp.addr == pc:
                    bp.hits += 1
                    info["breakpoint"] = bp
                    info["reason"] = "breakpoint"
        return info

    def stop_report(self, info):
        if info is None:
            return "The CPU is still running (nothing was hit before the timeout). Use dbg_wait or dbg_halt."
        cpu = info["cpu"]
        head = f"Stopped ({info['reason']})"
        bp = info.get("breakpoint")
        if bp:
            head += f": {bp.describe(self.labels)}"
        if "watch_addr" in info:
            head += (f"\nWatched address {self.fmt_addr(info['watch_addr'])} was accessed. The CPU stops one or two "
                     f"instructions after the access, so look at the instructions just before pc.")
        return head + "\n\n" + self.context(cpu)

    def step(self, cpu="arm9", count=1, over=False):
        g = self.g(cpu)
        if g.is_running():
            raise SessionError("the CPU is running; halt it first")
        info = None
        for _ in range(count):
            if over:
                regs = self.registers(cpu)
                pc = int(regs["pc"], 16)
                nxt = self._call_return_addr(cpu, pc, regs["thumb"])
                if nxt is not None:
                    self.add_breakpoint(nxt, cpu, temp=True)
                    info = self.cont(cpu, timeout=5.0)
                    if info is None:
                        return None
                    if info.get("breakpoint") is None or info["breakpoint"].addr != nxt:
                        return info  # something else was hit inside the call
                    continue
            stop = g.step()
            info = self._classify_stop(cpu, stop)
            info["reason"] = "step"
        return info

    def _call_return_addr(self, cpu, pc, thumb):
        src = self.source(None, cpu)
        if thumb:
            hi, lo = struct.unpack("<HH", src.read(pc, 4))
            if thumb_bl_target(hi, lo, pc):
                return pc + 4
            if hi & 0xFF87 == 0x4780:
                return pc + 2
            return None
        w = src.u32(pc)
        br = arm_branch_target(w, pc)
        if (br and br[0] in ("bl", "blx")) or w & 0x0FFFFFF0 == 0x012FFF30:
            return pc + 4
        return None

    def finish(self, cpu="arm9", timeout=5.0):
        """Run until the current function returns (temporary breakpoint on lr).
        Only reliable at the start of a function or in leaf functions."""
        regs = self.registers(cpu)
        lr = int(regs["r14"], 16)
        target = lr & ~1
        self.add_breakpoint(target, cpu, temp=True)
        return self.cont(cpu, timeout)

    def trace(self, addr, cpu="arm9", count=10, timeout=10.0, regs=("r0", "r1", "r2", "r3", "lr")):
        """Collect register snapshots each time addr executes."""
        bp = self.add_breakpoint(addr, cpu)
        hits = []
        deadline = time.time() + timeout
        try:
            while len(hits) < count and time.time() < deadline:
                info = self.cont(cpu, timeout=max(0.05, deadline - time.time()))
                if info is None:
                    break
                if info.get("breakpoint") is not bp:
                    hits.append({"other_stop": info["reason"], "pc": info["pc"]})
                    break
                r = info["regs"]
                snap = {"frame": self.control.call("status")["frame"]}
                for name in regs:
                    key = {"sp": 13, "lr": 14, "pc": 15}.get(name)
                    idx = key if key is not None else int(name[1:])
                    snap[name] = r[idx]
                hits.append(snap)
        finally:
            self.remove_breakpoint(bp)
            g = self.gdb.get(cpu)
            if g is not None and not g.is_running() and hits and "other_stop" not in hits[-1]:
                g.cont()  # carry on, as before the trace
        return hits

    # dumps -----------------------------------------------------------------

    def freeze(self, note="", directory=None):
        if directory is None:
            directory = os.path.join(self.dump_root, time.strftime("%Y%m%d-%H%M%S") + "-" + slug(note or "freeze"))
        return self.control.call("dump", dir=os.path.abspath(directory), note=note)

    def call_stack(self, src, cpu, regs, depth=256):
        """Best-effort call chain from lr and return addresses on the stack."""
        lines = []
        lr = int(regs["r14"], 16)
        sp = int(regs["r13"], 16)
        code = src.code_regions()
        call = is_call_before(src, lr)
        if call:
            lines.append(f"  lr      {lr:08x}  called from {self.fmt_addr(call[0])}"
                         + (f" -> {self.fmt_addr(call[1])}" if call[1] else ""))
        try:
            frames = stack_scan(src, sp, depth, code)
        except Exception as e:
            return f"  (stack scan failed: {e})"
        for stack_addr, value, site, target, thumb in frames:
            lines.append(f"  [sp+{stack_addr - sp:#05x}] {value:08x}  called from {self.fmt_addr(site)}"
                         + (f" -> {self.fmt_addr(target)}" if target else ""))
        if not lines:
            return "  (no return addresses found)"
        return "\n".join(lines)

    def function_of(self, src, addr, thumb):
        start = find_function_start(src, addr | (1 if thumb else 0), thumb)
        return start

    # event hooks -------------------------------------------------------------

    HOOK_EVENTS = ("card", "dma", "gx", "swap")

    def hook_set(self, event, action="log", min_addr=None, max_addr=None, cmds=None, stack=None, frames=None):
        args = {"event": event, "action": action}
        if min_addr is not None:
            args["min"] = hex(min_addr)
        if max_addr is not None:
            args["max"] = hex(max_addr)
        if cmds:
            args["cmds"] = ",".join(hex(c) for c in cmds)
        if stack is not None:
            args["stack"] = stack
        if frames:
            args["frames"] = frames
        return self.control.call("hook_set", **args)

    def hook_records(self, since=0, limit=100000):
        """Fetch hook records as dicts."""
        out = []
        while True:
            r = self.control.call("hook_log", since=since, limit=min(limit - len(out), 20000))
            for x in r["records"]:
                out.append({
                    "seq": x[0], "event": self.HOOK_EVENTS[x[1]], "frame": x[2],
                    "cpu": "arm9" if x[3] == 0 else "arm7", "pc": x[4], "lr": x[5], "sp": x[6],
                    "thumb": bool(x[7]), "args": x[8:12], "dma_src": x[12], "stack": x[13],
                    # for gx records
                    "cmd": x[8], "param": x[9],
                })
            since = r["last_seq"]
            if not r["more"] or len(out) >= limit or not r["records"]:
                return out

    def chain_from_snapshot(self, rec, src=None):
        """Call chain for a hook record, from its pc/lr and stack snapshot."""
        src = src or self.source(None, rec["cpu"])
        chain = [self.fmt_addr(rec["pc"])]
        seen = set()
        lr_call = is_call_before(src, rec["lr"]) if rec["lr"] else None
        if lr_call:
            chain.append(self.fmt_addr(lr_call[0]))
            seen.add(lr_call[0])
        code = src.code_regions()
        for w in rec["stack"]:
            if not any(start <= (w & ~1) < end for _, start, end in code):
                continue
            call = is_call_before(src, w)
            if call and call[0] not in seen:
                seen.add(call[0])
                chain.append(self.fmt_addr(call[0]))
        return chain
