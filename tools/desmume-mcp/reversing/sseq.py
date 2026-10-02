#!/usr/bin/env python3
"""NitroSDK sequences (SSEQ, and the sequences inside SSAR archives) -> JSON events and MIDI.

SSEQ: "SSEQ" header (0x10), "DATA" block: u32 tag, u32 size, u32 offset of the event data
(from the file start). SSAR: "SSAR" header, "DATA": tag, size, u32 data offset, u32 count,
count x {u32 offset (relative to the data), u16 bank, u8 volume, u8 channel prio, u8 player
prio, u8 player, u16 -}; offset 0xFFFFFFFF = unused.

Event stream (one per track; track 0 starts at the data offset and opens the others).
48 ticks per quarter note. Variable-length numbers as in MIDI (7 bits per byte, MSB = more).
  0x00-0x7F  note: key, u8 velocity, var duration (ticks)
  0x80 rest var | 0x81 program var | 0x93 open track: u8 track, u24 offset
  0x94 jump u24 | 0x95 call u24 | 0xFD return | 0xFF end of track
  0xA0 random prefix: the next command's last argument is s16 min, s16 max
  0xA1 variable prefix: the next command's last argument is u8 variable number
  0xA2 if prefix: the next command runs only if the last compare was true
             (prefixes stack: if + random/variable + command)
  0xB0-0xBD variable ops: u8 variable, s16 value (set add sub mul div shift rand -
            eq ge gt le lt ne)
  0xC0 pan, C1 volume, C2 master volume, C3 transpose (s8), C4 pitch bend (s8),
  C5 bend range, C6 priority, C7 mono/poly, C8 tie, C9 portamento key, CA mod depth,
  CB mod speed, CC mod type, CD mod range, CE portamento on/off, CF portamento time,
  D0 attack, D1 decay, D2 sustain, D3 release, D4 loop start (u8 count, 0 = forever),
  D5 expression, D6 print variable (all u8)
  0xE0 mod delay, E1 tempo (BPM), E3 sweep pitch (s16) | 0xFC loop end | 0xFE track mask (u16)

The JSON keeps every event with its byte offset, so jumps/calls/loops can be followed;
the MIDI export plays each track once from its start, follows calls/returns and
loop blocks (a forever loop or a backward jump ends the track: loop points are written as
MIDI markers "loopStart"/"loopEnd"), and maps volume/pan/expression/pitch bend/program/tempo.
Envelopes, modulation, portamento and variables do not translate and are left out.

usage:
  sseq.py FILE.sseq|FILE.ssar [...] --out DIR [--midi]
  sseq.py --sdat-dir DIR --out DIR [--midi]   every .sseq/.ssar under an sdat.py --extract dir
"""

import argparse
import glob
import json
import os
import struct

ARGS = {0xC0 + i: "B" for i in range(0x17)}
ARGS.update({0xC3: "b", 0xC4: "b", 0xE0: "h", 0xE1: "h", 0xE3: "h", 0xFE: "H"})
NAMES = {0x80: "rest", 0x81: "program", 0x93: "open_track", 0x94: "jump", 0x95: "call", 0xA0: "random",
         0xA1: "variable", 0xA2: "if", 0xC0: "pan", 0xC1: "volume", 0xC2: "master_volume", 0xC3: "transpose",
         0xC4: "pitch_bend", 0xC5: "bend_range", 0xC6: "priority", 0xC7: "mono", 0xC8: "tie",
         0xC9: "portamento_key", 0xCA: "mod_depth", 0xCB: "mod_speed", 0xCC: "mod_type", 0xCD: "mod_range",
         0xCE: "portamento", 0xCF: "portamento_time", 0xD0: "attack", 0xD1: "decay", 0xD2: "sustain",
         0xD3: "release", 0xD4: "loop_start", 0xD5: "expression", 0xD6: "print_var", 0xE0: "mod_delay",
         0xE1: "tempo", 0xE3: "sweep_pitch", 0xFC: "loop_end", 0xFD: "return", 0xFE: "track_mask",
         0xFF: "end"}
VAROPS = ["set", "add", "sub", "mul", "div", "shift", "rand", "-", "eq", "ge", "gt", "le", "lt", "ne"]


def varlen(d, p):
    v = 0
    while True:
        b = d[p]
        p += 1
        v = (v << 7) | (b & 0x7F)
        if not b & 0x80:
            return v, p


def u24(d, p):
    return d[p] | d[p + 1] << 8 | d[p + 2] << 16


def decode_at(d, p, base):
    """One event at p -> (event dict, next p). base: data offset (jump targets are relative to it)."""
    op = d[p]
    e = {"at": p - base, "op": f"{op:02x}"}
    q = p + 1
    prefix, prefixes = None, []
    while op in (0xA0, 0xA1, 0xA2):     # prefixes stack: if + random/variable + command
        prefixes.append(NAMES[op])
        if op != 0xA2:
            prefix = op
        op = d[q]
        q += 1
    if prefixes:
        e["prefix"] = prefixes[0] if len(prefixes) == 1 else prefixes
        e["op"] = f"{op:02x}"

    def last_arg(kind):
        nonlocal q
        if prefix == 0xA0:
            lo, hi = struct.unpack_from("<hh", d, q)
            q += 4
            return {"random": [lo, hi]}
        if prefix == 0xA1:
            q += 1
            return {"var": d[q - 1]}
        if kind == "var":
            v, q = varlen(d, q)
            return v
        fmt = "<" + kind
        v = struct.unpack_from(fmt, d, q)[0]
        q += struct.calcsize(fmt)
        return v

    if op < 0x80:
        e.update(name="note", key=op, velocity=d[q])
        q += 1
        e["duration"] = last_arg("var")
    elif op in (0x80, 0x81):
        e.update(name=NAMES[op], value=last_arg("var"))
    elif op == 0x93:
        e.update(name="open_track", track=d[q], target=u24(d, q + 1))
        q += 4
    elif op in (0x94, 0x95):
        e.update(name=NAMES[op], target=u24(d, q))
        q += 3
    elif 0xB0 <= op <= 0xBD:
        e.update(name="var_" + VAROPS[op - 0xB0], var=d[q])
        q += 1
        e["value"] = last_arg("h")
    elif op in ARGS:
        e.update(name=NAMES.get(op, f"cmd_{op:02x}"), value=last_arg(ARGS[op]))
    elif op in (0xFC, 0xFD, 0xFF):
        e["name"] = NAMES[op]
    else:
        e["name"] = f"unknown_{op:02x}"
    return e, q


def tracks(d, base, start=0):
    """{track: [events]} reachable from the stream at base+start (track 0)."""
    starts, out, todo = {0: start}, {}, [0]
    while todo:
        t = todo.pop()
        p, evs, seen = base + starts[t], [], set()
        stack = [p]
        while stack:
            p = stack.pop()
            while p < len(d) and p not in seen:
                seen.add(p)
                e, q = decode_at(d, p, base)
                evs.append(e)
                if e["name"] == "open_track" and e["track"] not in starts:
                    starts[e["track"]] = e["target"]
                    todo.append(e["track"])
                if e["name"] in ("jump", "call"):
                    stack.append(base + e["target"])
                if e["name"] == "jump" and "prefix" not in e or e["name"] in ("end", "return"):
                    break
                if e["name"].startswith("unknown"):
                    break
                p = q
        out[t] = sorted(evs, key=lambda x: x["at"])
    return out


def to_midi(d, base, start=0, max_ticks=48 * 4 * 400):
    """Standard MIDI file (format 1) bytes, playing each track once."""
    by_at = {}
    for evs in tracks(d, base, start).values():
        for e in evs:
            by_at[e["at"]] = e
    keys = sorted(by_at)
    following = dict(zip(keys, keys[1:]))
    track_starts = {0: start}
    for e in by_at.values():
        if e["name"] == "open_track":
            track_starts.setdefault(e["track"], e["target"])
    mtracks = []
    for t, s in sorted(track_starts.items()):
        ch = t & 15
        events, tick, pc, stack, loops = [], 0, s, [], []
        steps = 0
        while pc in by_at and tick < max_ticks and steps < 200000:
            steps += 1
            e = by_at[pc]
            n = e["name"]
            v = e.get("value")
            fixed = not isinstance(v, dict)
            if n == "note":
                dur = e["duration"] if isinstance(e["duration"], int) else 48
                vel = max(1, e["velocity"])
                events += [(tick, bytes([0x90 | ch, e["key"], vel])), (tick + dur, bytes([0x80 | ch, e["key"], 0]))]
            elif n == "rest" and fixed:
                tick += v
            elif n == "program" and fixed:
                events.append((tick, bytes([0xC0 | ch, v & 0x7F])))
            elif n in ("volume", "pan", "expression") and fixed:
                cc = {"volume": 7, "pan": 10, "expression": 11}[n]
                events.append((tick, bytes([0xB0 | ch, cc, min(v, 127)])))
            elif n == "pitch_bend" and fixed:
                b = 0x2000 + v * 64
                events.append((tick, bytes([0xE0 | ch, b & 0x7F, (b >> 7) & 0x7F])))
            elif n == "tempo" and fixed and v > 0:
                us = 60000000 // v
                events.append((tick, b"\xff\x51\x03" + us.to_bytes(3, "big")))
            elif n == "loop_start":
                events.append((tick, b"\xff\x06\x09loopStart"))
                loops.append([pc, v if fixed else 1])
            elif n == "loop_end" and loops:
                if loops[-1][1] in (0, 1):
                    events.append((tick, b"\xff\x06\x07loopEnd"))
                    loops.pop()
                else:
                    loops[-1][1] -= 1
                    pc = loops[-1][0]
            elif n == "call":
                stack.append(pc)
                pc = e["target"]
                continue
            elif n == "return" and stack:
                pc = stack.pop()
            elif n == "jump" and "prefix" not in e:
                if e["target"] <= pc:
                    events.append((tick, b"\xff\x06\x07loopEnd"))
                    break
                pc = e["target"]
                continue
            elif n in ("end", "return"):
                break
            if pc not in following:
                break
            pc = following[pc]
        events.sort(key=lambda x: (x[0], x[1][0] & 0xF0 != 0x80))
        body, last = bytearray(), 0
        for tk, msg in events:
            delta = tk - last
            last = tk
            vl = [delta & 0x7F]
            delta >>= 7
            while delta:
                vl.append(0x80 | (delta & 0x7F))
                delta >>= 7
            body += bytes(reversed(vl)) + msg
        body += b"\x00\xff\x2f\x00"
        mtracks.append(b"MTrk" + struct.pack(">I", len(body)) + bytes(body))
    return b"MThd" + struct.pack(">IHHH", 6, 1, len(mtracks), 48) + b"".join(mtracks)


def parse_file(b):
    """[(name_suffix, data, base, start, info)] for an SSEQ or each sequence of an SSAR."""
    da = b.index(b"DATA")
    if b[:4] == b"SSEQ":
        return [("", b, struct.unpack_from("<I", b, da + 8)[0], 0, {})]
    base, n = struct.unpack_from("<II", b, da + 8)
    out = []
    for i in range(n):
        off, bank, vol, cpr, ppr, ply = struct.unpack_from("<IHBBBB", b, da + 16 + 12 * i)
        if off != 0xFFFFFFFF:
            out.append((f"_{i:03d}", b, base, off, {"index": i, "bank": bank, "volume": vol, "player": ply}))
    return out


def main():
    ap = argparse.ArgumentParser(description=__doc__.split("\n\n")[0],
                                 formatter_class=argparse.RawDescriptionHelpFormatter, epilog=__doc__)
    ap.add_argument("files", nargs="*")
    ap.add_argument("--sdat-dir")
    ap.add_argument("--out", required=True)
    ap.add_argument("--midi", action="store_true")
    args = ap.parse_args()
    files = list(args.files)
    if args.sdat_dir:
        files += sorted(glob.glob(os.path.join(args.sdat_dir, "**", "*.sseq"), recursive=True))
        files += sorted(glob.glob(os.path.join(args.sdat_dir, "**", "*.ssar"), recursive=True))
    os.makedirs(args.out, exist_ok=True)
    n = unknown = 0
    for f in files:
        b = open(f, "rb").read()
        for sfx, d, base, start, info in parse_file(b):
            name = os.path.splitext(os.path.basename(f))[0] + sfx
            trk = tracks(d, base, start)
            unknown += sum(1 for evs in trk.values() for e in evs if e["name"].startswith("unknown"))
            json.dump({"source": f, **info, "tracks": {str(k): v for k, v in trk.items()}},
                      open(os.path.join(args.out, name + ".json"), "w"), separators=(",", ":"))
            if args.midi:
                open(os.path.join(args.out, name + ".mid"), "wb").write(to_midi(d, base, start))
            n += 1
    print(f"{n} sequences -> {args.out} ({unknown} unknown events)")


if __name__ == "__main__":
    main()
