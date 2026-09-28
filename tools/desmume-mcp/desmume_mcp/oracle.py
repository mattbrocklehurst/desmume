"""Use the original game as an oracle: scripted, reproducible runs for
comparing a port (or anything else) against DeSmuME, headless on CI.

Three pieces:

* Input scripts (.inputs): the controller input of a run, frame by frame,
  anchored to a savestate. Recorded from a real play session or written by
  hand, replayed deterministically, and simple enough for another engine to
  consume (see INPUT_SCRIPT_FORMAT).
* Oracle: a small Python API (press, wait, read memory by label, probes,
  screenshots, states) on top of desmume-cli's control interface.
* Test scripts (.oracle): line based tests run by `python3 -m
  desmume_mcp.oracle run`, producing JSON results and a CI exit code.
"""

import argparse
import json
import os
import re
import shutil
import signal
import struct
import sys
import tempfile
import time

from .control import ControlError
from .labels import LabelDB
from .session import Session, SessionError, data_dir

BUTTONS = ["a", "b", "select", "start", "right", "left", "up", "down", "r", "l", "x", "y", "debug", None, "lid"]

INPUT_SCRIPT_FORMAT = """\
# desmume input script
# Lines: '<frame> <input>' where frame counts from the start state (0 = the
# first frame emulated after loading it) and input is what is held from that
# frame on: '-' for nothing, or buttons joined by '+' (a b x y l r start
# select up down left right lid), optionally followed by 'touch X Y'.
# Headers: 'state FILE' (savestate to start from, relative to this file;
# omitted = from power on), 'rom GAMECODE CRC32', 'cpu interp|jit' (replay
# with the same CPU mode as the recording), 'end FRAME' (length of the run).
"""


# ---------------------------------------------------------------------------
# input scripts


def mask_to_names(mask):
    return [b for i, b in enumerate(BUTTONS) if b and mask & (1 << i)]


def names_to_mask(names):
    mask = 0
    for n in names:
        n = n.strip().lower()
        if not n:
            continue
        if n not in BUTTONS:
            raise ValueError(f"unknown button {n!r}")
        mask |= 1 << BUTTONS.index(n)
    return mask


class InputScript:
    """Frame-indexed input changes: events = [(frame, button_mask, touch)]
    with touch None or (x, y)."""

    def __init__(self, events=None, state=None, end=None, rom=None, cpu="interp"):
        self.events = sorted(events or [], key=lambda e: e[0])
        self.state = state
        self.end = end
        self.rom = rom  # (game_code, crc32)
        self.cpu = cpu

    @classmethod
    def load(cls, path):
        script = cls()
        base = os.path.dirname(os.path.abspath(path))
        with open(path) as f:
            for lineno, raw in enumerate(f, 1):
                line = raw.split("#")[0].strip()
                if not line:
                    continue
                toks = line.split()
                key = toks[0].lower()
                try:
                    if key == "state":
                        script.state = os.path.join(base, " ".join(toks[1:]))
                    elif key == "rom":
                        script.rom = (toks[1], int(toks[2], 16) if len(toks) > 2 else None)
                    elif key == "cpu":
                        script.cpu = toks[1]
                    elif key == "end":
                        script.end = int(toks[1])
                    else:
                        frame = int(toks[0])
                        rest = toks[1:]
                        touch = None
                        if "touch" in rest:
                            i = rest.index("touch")
                            touch = (int(rest[i + 1]), int(rest[i + 2]))
                            rest = rest[:i]
                        names = [] if not rest or rest[0] == "-" else rest[0].split("+")
                        script.events.append((frame, names_to_mask(names), touch))
                except (IndexError, ValueError) as e:
                    raise ValueError(f"{path}:{lineno}: {e}")
        script.events.sort(key=lambda e: e[0])
        return script

    def save(self, path):
        base = os.path.dirname(os.path.abspath(path))
        lines = [INPUT_SCRIPT_FORMAT.rstrip()]
        if self.rom:
            lines.append(f"rom {self.rom[0]} {self.rom[1]:08x}" if self.rom[1] is not None else f"rom {self.rom[0]}")
        if self.state:
            lines.append(f"state {os.path.relpath(self.state, base)}")
        lines.append(f"cpu {self.cpu}")
        for frame, mask, touch in self.events:
            held = "+".join(mask_to_names(mask)) or "-"
            lines.append(f"{frame} {held}" + (f" touch {touch[0]} {touch[1]}" if touch else ""))
        if self.end is not None:
            lines.append(f"end {self.end}")
        with open(path, "w") as f:
            f.write("\n".join(lines) + "\n")

    def length(self):
        last = self.events[-1][0] + 1 if self.events else 0
        return max(self.end or 0, last)


# ---------------------------------------------------------------------------
# the oracle API


class Oracle:
    """Scriptable emulator for tests. Frames are counted from the last
    load()/reset(): after load(), frame() is 0 and the next frame emulated
    is frame 0."""

    def __init__(self, rom, headless=True, jit=False, debugger=False, labels=None, deterministic=True):
        # start paused at power on, so that runs from reset are reproducible
        self.session = Session(rom, headless=headless, debugger=debugger, jit=jit,
                               deterministic=deterministic, start_halted=False,
                               extra_args=["--start-paused"])
        self.session.start()
        self.control = self.session.control
        self.control.call("pause")
        self.base_frame = self.control.call("status")["frame"]
        if labels:
            if labels.endswith(".json"):
                self.session.labels = LabelDB(labels)
            else:  # nm style symbol file: use it without touching the saved labels
                self.session.labels = LabelDB(os.path.join(tempfile.mkdtemp(prefix="oracle-labels-"), "l.json"))
                with open(labels) as f:
                    self.session.labels.import_text(f.read())
        self.cpu_mode = "jit" if self.session.jit else "interp"

    @classmethod
    def attach(cls, session):
        """An Oracle driving an already running session (it is not stopped
        when the Oracle is closed)."""
        o = cls.__new__(cls)
        o.session = session
        o.control = session.control
        o.base_frame = o.control.call("status")["frame"]
        o.cpu_mode = "jit" if session.jit else "interp"
        o._owned = False
        return o

    def close(self):
        if getattr(self, "_owned", True):
            self.session.stop()

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        self.close()

    # time ---------------------------------------------------------------

    def frame(self):
        return self.control.call("status")["frame"] - self.base_frame

    def advance(self, frames=1):
        if frames <= 0:
            return
        r = self.control.call("frame_advance", n=frames, timeout=max(60, frames / 20))
        if r.get("halted_by_debugger"):
            raise SessionError("stopped by the debugger during frame_advance")

    wait = advance

    # input --------------------------------------------------------------

    def hold(self, buttons=(), touch=None):
        """Hold buttons (and optionally touch) until changed."""
        names = [buttons] if isinstance(buttons, str) else list(buttons)
        self.control.call("input", buttons=",".join(n for n in names if n), frames=0)
        if touch:
            self.control.call("touch", x=touch[0], y=touch[1], frames=0)
        else:
            self._release_touch()

    def _release_touch(self):
        st = self.control.call("status")
        if st.get("touching"):
            held = st["held_buttons"]
            self.control.call("release")
            if held:
                self.control.call("input", buttons=",".join(mask_to_names(held)), frames=0)

    def release(self):
        self.control.call("release")

    def press(self, buttons, frames=1):
        """Hold buttons for N frames, then release."""
        self.hold(buttons)
        self.advance(frames)
        self.release()

    def touch(self, x, y, frames=1):
        self.control.call("touch", x=x, y=y, frames=0)
        self.advance(frames)
        self.release()

    def play(self, script, on_frame=None):
        """Apply an InputScript from the current frame. on_frame(oracle, f)
        is called after every frame if given (for per-frame probes)."""
        start = self.frame()
        events = list(script.events)
        end = script.length()
        f = 0
        i = 0
        while f < end:
            while i < len(events) and events[i][0] <= f:
                _, mask, touch = events[i]
                self.control.call("release")
                if mask:
                    self.control.call("input", buttons=",".join(mask_to_names(mask)), frames=0)
                if touch:
                    self.control.call("touch", x=touch[0], y=touch[1], frames=0)
                i += 1
            nxt = events[i][0] if i < len(events) else end
            step = 1 if on_frame else max(1, min(nxt, end) - f)
            self.advance(step)
            f += step
            if on_frame:
                on_frame(self, self.frame() - start)
        self.control.call("release")

    # state --------------------------------------------------------------

    def load(self, path):
        self.control.call("savestate_load", path=os.path.abspath(path))
        self.control.call("release")
        self.base_frame = self.control.call("status")["frame"]

    def save(self, path):
        self.control.call("savestate_save", path=os.path.abspath(path))

    def reset(self):
        self.control.call("reset")
        self.control.call("release")
        self.base_frame = self.control.call("status")["frame"]

    # memory -------------------------------------------------------------

    def addr(self, expr):
        return self.session.resolve(expr)

    def read(self, expr, type="u32"):
        size = {"u8": 1, "s8": 1, "u16": 2, "s16": 2, "u32": 4, "s32": 4}[type]
        fmt = {"u8": "B", "s8": "b", "u16": "H", "s16": "h", "u32": "I", "s32": "i"}[type]
        data = self.control.read_memory(self.addr(expr), size)
        return struct.unpack("<" + fmt, data)[0]

    def read_bytes(self, expr, length):
        return self.control.read_memory(self.addr(expr), length)

    def write(self, expr, value, type="u32"):
        size = {"u8": 1, "s8": 1, "u16": 2, "s16": 2, "u32": 4, "s32": 4}[type]
        self.control.write_memory(self.addr(expr), (value & ((1 << (size * 8)) - 1)).to_bytes(size, "little"))

    def screenshot(self, path=None):
        png = self.control.screenshot_png()
        if path:
            with open(path, "wb") as f:
                f.write(png)
        return png


# ---------------------------------------------------------------------------
# recording


class Recorder:
    """Records the input of a running session into an input script. poll()
    collects input changes as they happen, so a recording survives the
    emulator window being closed; stop() writes the script."""

    def __init__(self, session, out_path, state_path=None):
        self.session = session
        self.out_path = os.path.abspath(out_path)
        self.state_path = os.path.abspath(state_path or os.path.splitext(self.out_path)[0] + ".dst")
        c = session.control
        c.call("pause")
        c.call("savestate_save", path=self.state_path)
        self.start = c.call("status")["frame"]
        self.last_frame = self.start
        self.seq = c.call("hook_status")["last_seq"]
        self.events = []
        c.call("hook_set", event="input_state", action="log", stack=0)

    def poll(self):
        c = self.session.control
        self.last_frame = c.call("status")["frame"]
        for r in self.session.hook_records(since=self.seq):
            self.seq = max(self.seq, r["seq"])
            if r["event"] != "input_state":
                continue
            mask, touch = r["args"][0], r["args"][1]
            t = ((touch & 0xFFFF), (touch >> 16) & 0x7FFF) if touch & 0x80000000 else None
            self.events.append((r["frame"] - self.start, mask, t))

    def stop(self, alive=True):
        if alive:
            self.session.control.call("pause")
            self.poll()
            self.session.control.call("hook_set", event="input_state", action="off")
        s = self.session
        script = InputScript(list(self.events), self.state_path, self.last_frame - self.start,
                             (s.rom.game_code, rom_crc(s)), "jit" if s.jit else "interp")
        if not script.events or script.events[0][0] > 0:
            script.events.insert(0, (0, 0, None))
        script.save(self.out_path)
        return script


def rom_crc(session):
    try:
        import zlib
        with open(session.rom_path, "rb") as f:
            return zlib.crc32(f.read())
    except OSError:
        return None


# ---------------------------------------------------------------------------
# test scripts


TEST_SCRIPT_HELP = """\
Oracle test script commands (one per line, '#' comments):
  reset | state FILE                  start from power on / a savestate
  press BUTTONS [FRAMES=1]            hold (e.g. left or a+b) for N frames, then release
  hold BUTTONS | release              hold until changed / let go of everything
  touch X Y [FRAMES=1]                touch the bottom screen
  wait FRAMES                         run N frames with the current input
  inputs FILE                         replay an input script from here
  probe NAME TYPE ADDR                record a value (TYPE u8/s8/u16/s16/u32/s32,
                                      ADDR a number, label or label+offset)
  sample NAME TYPE ADDR               record NAME every frame from now on
  expect TYPE ADDR OP VALUE           assertion, OP one of == != < > <= >=
  screenshot FILE | savestate FILE    outputs (relative to the script)
  write TYPE ADDR VALUE               poke memory (e.g. to set up a scenario)
"""


def run_test_script(oracle, path, results):
    base = os.path.dirname(os.path.abspath(path))
    samples = {}

    def sample_all(o, _f=None):
        for name, (type_, addr) in samples.items():
            results["series"].setdefault(name, []).append([o.frame(), o.read(addr, type_)])

    def advance(n):
        if samples:
            for _ in range(n):
                oracle.advance(1)
                sample_all(oracle)
        else:
            oracle.advance(n)

    with open(path) as f:
        lines = f.readlines()
    for lineno, raw in enumerate(lines, 1):
        line = raw.split("#")[0].strip()
        if not line:
            continue
        toks = line.split()
        cmd, args = toks[0].lower(), toks[1:]
        step = {"line": lineno, "cmd": line}
        try:
            if cmd == "reset":
                oracle.reset()
            elif cmd == "state":
                oracle.load(os.path.join(base, args[0]))
            elif cmd == "press":
                oracle.hold(args[0].split("+"))
                advance(int(args[1]) if len(args) > 1 else 1)
                oracle.release()
            elif cmd == "hold":
                oracle.hold(args[0].split("+"))
            elif cmd == "release":
                oracle.release()
            elif cmd == "touch":
                oracle.control.call("touch", x=int(args[0]), y=int(args[1]), frames=0)
                advance(int(args[2]) if len(args) > 2 else 1)
                oracle.release()
            elif cmd == "wait":
                advance(int(args[0]))
            elif cmd == "inputs":
                script = InputScript.load(os.path.join(base, args[0]))
                if script.cpu != oracle.cpu_mode:
                    raise SessionError(f"{args[0]} was recorded with cpu {script.cpu}, "
                                       f"this run uses {oracle.cpu_mode}; replays may diverge")
                if script.state:
                    oracle.load(script.state)
                oracle.play(script, sample_all if samples else None)
            elif cmd == "probe":
                name, type_, addr = args[0], args[1], " ".join(args[2:])
                value = oracle.read(addr, type_)
                results["probes"].append({"name": name, "frame": oracle.frame(), "value": value})
                step["value"] = value
            elif cmd == "sample":
                samples[args[0]] = (args[1], " ".join(args[2:]))
                sample_all(oracle)
            elif cmd == "expect":
                type_, addr, op, want = args[0], args[1], args[2], int(args[3], 0)
                got = oracle.read(addr, type_)
                ok = {"==": got == want, "!=": got != want, "<": got < want, ">": got > want,
                      "<=": got <= want, ">=": got >= want}[op]
                results["expects"].append({"line": lineno, "expect": line, "actual": got, "ok": ok,
                                           "frame": oracle.frame()})
                step["ok"] = ok
                step["actual"] = got
            elif cmd == "screenshot":
                oracle.screenshot(os.path.join(base, args[0]))
            elif cmd == "savestate":
                oracle.save(os.path.join(base, args[0]))
            elif cmd == "write":
                oracle.write(args[1], int(args[2], 0), args[0])
            else:
                raise SessionError(f"unknown command {cmd}")
        except (IndexError, KeyError, ValueError, SessionError, ControlError) as e:
            step["error"] = str(e) or type(e).__name__
            results["steps"].append(step)
            results["errors"].append(f"line {lineno}: {step['error']}")
            return
        step["frame"] = oracle.frame()
        results["steps"].append(step)


def cmd_run(args):
    results = {"rom": os.path.abspath(args.rom), "script": os.path.abspath(args.script), "steps": [],
               "probes": [], "series": {}, "expects": [], "errors": []}
    t0 = time.time()
    with Oracle(args.rom, headless=not args.window, jit=args.jit, labels=args.labels) as o:
        results["cpu"] = o.cpu_mode
        run_test_script(o, args.script, results)
        results["frames"] = o.frame()
    results["seconds"] = round(time.time() - t0, 3)
    results["passed"] = not results["errors"] and all(e["ok"] for e in results["expects"])
    text = json.dumps(results, indent=1)
    if args.out:
        with open(args.out, "w") as f:
            f.write(text)
    else:
        print(text)
    failed = [e for e in results["expects"] if not e["ok"]]
    for e in failed:
        print(f"FAIL line {e['line']}: {e['expect']} (actual {e['actual']})", file=sys.stderr)
    for e in results["errors"]:
        print(f"ERROR {e}", file=sys.stderr)
    print(f"{'PASSED' if results['passed'] else 'FAILED'}: {len(results['expects']) - len(failed)}/"
          f"{len(results['expects'])} expectations, {results['frames']} frames in {results['seconds']}s",
          file=sys.stderr)
    return 0 if results["passed"] else 1


def cmd_record(args):
    """Play in a window; the input is recorded until the window is closed."""
    # finish on Ctrl-C or SIGTERM; a flag, so a control request is never cut
    # in half (and background launches, which ignore SIGINT, can use TERM)
    stop = []
    for sig in (signal.SIGINT, signal.SIGTERM):
        signal.signal(sig, lambda *_: stop.append(True))
    s = Session(args.rom, headless=False, debugger=False, jit=args.jit, deterministic=True,
                extra_args=["--start-paused"])
    s.start()
    try:
        if args.state:
            s.control.call("savestate_load", path=os.path.abspath(args.state))
        rec = Recorder(s, args.out)
        s.control.call("resume")
        print(f"Recording input to {args.out}. Play, then close the emulator window "
              f"or press Ctrl-C here to finish.", file=sys.stderr)
        alive = True
        try:
            while s.alive() and not stop:
                time.sleep(0.2)
                rec.poll()
        except (ControlError, OSError):
            alive = False
        alive = alive and s.alive()
        script = rec.stop(alive)
        print(f"wrote {args.out}: {len(script.events)} input changes over {script.end} frames "
              f"(start state {script.state})", file=sys.stderr)
    finally:
        s.stop()
    return 0


def cmd_replay(args):
    """Replay an input script, optionally sampling values per frame; with
    --check, replay twice and verify both runs match (determinism check)."""
    script = InputScript.load(args.inputs)
    runs = 2 if args.check else 1
    outputs = []
    for _ in range(runs):
        with Oracle(args.rom, headless=not args.window, jit=script.cpu == "jit", labels=args.labels) as o:
            if script.state:
                o.load(script.state)
            series = {}
            probes = [p.split(":") for p in args.sample or []]

            def on_frame(oracle, f):
                for name, type_, addr in probes:
                    series.setdefault(name, []).append(oracle.read(addr, type_))

            o.play(script, on_frame if probes else None)
            if args.screenshot:
                o.screenshot(args.screenshot)
            ram = o.read_bytes(0x02000000, 0x400000)
            outputs.append({"frames": o.frame(), "series": series, "ram_crc": f"{__import__('zlib').crc32(ram):08x}"})
    result = outputs[0]
    if args.check:
        result["deterministic"] = outputs[0] == outputs[1]
    text = json.dumps(result, indent=1)
    if args.out:
        with open(args.out, "w") as f:
            f.write(text)
    else:
        print(text)
    return 0 if result.get("deterministic", True) else 1


def main(argv=None):
    p = argparse.ArgumentParser(prog="python3 -m desmume_mcp.oracle",
                                description="Scripted, reproducible DeSmuME runs for oracle testing.",
                                formatter_class=argparse.RawDescriptionHelpFormatter,
                                epilog=TEST_SCRIPT_HELP + "\n" + INPUT_SCRIPT_FORMAT)
    sub = p.add_subparsers(dest="command", required=True)

    r = sub.add_parser("run", help="run a test script, write JSON results, exit 1 on failure")
    r.add_argument("rom")
    r.add_argument("script")
    r.add_argument("--out", help="results JSON (default: stdout)")
    r.add_argument("--labels", help="symbol file (nm style) or labels .json for label names")
    r.add_argument("--jit", action="store_true", help="use the JIT (faster; input scripts must match)")
    r.add_argument("--window", action="store_true", help="show the emulator window")
    r.set_defaults(fn=cmd_run)

    rec = sub.add_parser("record", help="play in a window and record the input to an input script")
    rec.add_argument("rom")
    rec.add_argument("out", help="input script to write (a .dst start state is written next to it)")
    rec.add_argument("--state", help="savestate to start from (default: power on)")
    rec.add_argument("--jit", action="store_true")
    rec.set_defaults(fn=cmd_record)

    rp = sub.add_parser("replay", help="replay an input script and report values / RAM checksum")
    rp.add_argument("rom")
    rp.add_argument("inputs")
    rp.add_argument("--sample", action="append", metavar="NAME:TYPE:ADDR",
                    help="record a value every frame, e.g. x:s32:g_player")
    rp.add_argument("--labels")
    rp.add_argument("--screenshot")
    rp.add_argument("--check", action="store_true", help="replay twice and verify identical results")
    rp.add_argument("--out")
    rp.add_argument("--window", action="store_true")
    rp.set_defaults(fn=cmd_replay)

    args = p.parse_args(argv)
    try:
        return args.fn(args)
    except (SessionError, ControlError, ValueError, OSError) as e:
        print(f"error: {e}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    sys.exit(main())
