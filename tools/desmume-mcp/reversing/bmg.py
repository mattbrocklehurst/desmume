#!/usr/bin/env python3
"""BMG message files (Nintendo "MESGbmg1") -> Lua tables, losslessly.

Used by many Nintendo DS/GC/Wii games (PH and ST keep every string here).
Sections handled:
  INF1  message table: per message a DAT1 offset + attribute bytes
  DAT1  strings (encoding from the header: 1 cp1252, 2 UTF-16LE, 3 Shift-JIS, 4 UTF-8)
        control codes are 0x1A, u8 total length, u8 group, u16 type, params;
        they are written inline as {g:GROUP:TYPE:PARAMHEX} ("{" in text becomes "{{")
  MID1  message ids, when present
  FLW1  message flow (dialogue scripting): nodes (8 bytes each) and branch lists
  FLI1  flow labels: (message group, id) -> entry node
Unknown sections are kept as hex. Nothing is interpreted beyond the container,
so the output round-trips; meanings of control codes / node types are game specific.

usage:
  bmg.py FILE.bmg [...] --out DIR                       one .lua (+ .json) per file
  bmg.py --rom game.nds --prefix English/Message --out DIR   every .bmg under a ROM path
"""

import argparse
import json
import os
import struct
import sys

ENC = {1: "cp1252", 2: "utf-16-le", 3: "shift_jis", 4: "utf-8"}


def parse(d):
    if d[:8] != b"MESGbmg1":
        raise ValueError("not a BMG file")
    size, nsec, enc = struct.unpack_from("<IIB", d, 8)
    out = {"encoding": ENC.get(enc, enc), "sections": [], "messages": [], "flow": None, "labels": [], "ids": None,
           "unknown": {}}
    pos, secs = 32, {}
    for _ in range(nsec):
        tag = d[pos:pos + 4].decode("latin-1")
        sz = struct.unpack_from("<I", d, pos + 4)[0]
        secs[tag] = d[pos + 8:pos + sz]
        out["sections"].append(tag)
        pos += sz
        if sz == 0:
            break
    wide = enc == 2
    dat = secs.get("DAT1", b"")

    def string_at(off):
        parts, k = [], off
        buf = bytearray()

        def flush():
            if buf:
                parts.append(bytes(buf).decode(ENC.get(enc, "latin-1"), "replace").replace("{", "{{"))
                buf.clear()
        while k < len(dat):
            if wide:
                if k + 1 >= len(dat):
                    break
                u = dat[k] | dat[k + 1] << 8
                if u == 0:
                    break
                if u == 0x1A:
                    n = dat[k + 2]
                    blk = dat[k:k + n]
                    flush()
                    g, t = blk[3], struct.unpack_from("<H", blk, 4)[0] if n >= 6 else 0
                    parts.append(f"{{g:{g:02X}:{t:04X}:{blk[6:].hex().upper()}}}")
                    k += max(n, 2)
                    continue
                buf += dat[k:k + 2]
                k += 2
            else:
                c = dat[k]
                if c == 0:
                    break
                if c == 0x1A:
                    n = dat[k + 1]
                    blk = dat[k:k + n]
                    flush()
                    g, t = blk[2], struct.unpack_from("<H", blk, 3)[0] if n >= 5 else 0
                    parts.append(f"{{g:{g:02X}:{t:04X}:{blk[5:].hex().upper()}}}")
                    k += max(n, 1)
                    continue
                buf.append(c)
                k += 1
        flush()
        return "".join(parts)

    inf = secs.get("INF1")
    if inf:
        count, esize = struct.unpack_from("<HH", inf, 0)
        out["inf_group"] = struct.unpack_from("<I", inf, 4)[0]
        for i in range(count):
            e = inf[8 + i * esize:8 + (i + 1) * esize]
            off = struct.unpack_from("<I", e, 0)[0]
            out["messages"].append({"index": i, "attr": e[4:].hex().upper(), "text": string_at(off)})
    mid = secs.get("MID1")
    if mid:
        count = struct.unpack_from("<H", mid, 0)[0]
        out["ids"] = list(struct.unpack_from(f"<{count}I", mid, 8))
    flw = secs.get("FLW1")
    if flw:
        nn, nb = struct.unpack_from("<HH", flw, 0)
        nodes = []
        for i in range(nn):
            n = flw[8 + i * 8:16 + i * 8]
            nodes.append({"index": i, "type": n[0], "sub": n[1], "a": struct.unpack_from("<H", n, 2)[0],
                          "b": struct.unpack_from("<H", n, 4)[0], "c": struct.unpack_from("<H", n, 6)[0],
                          "raw": n.hex().upper()})
        bpos = 8 + nn * 8
        branches = list(struct.unpack_from(f"<{nb}H", flw, bpos)) if nb else []
        out["flow"] = {"nodes": nodes, "branches": branches}
    fli = secs.get("FLI1")
    if fli:
        count, esize = struct.unpack_from("<HH", fli, 0)
        for i in range(count):
            e = fli[8 + i * esize:8 + (i + 1) * esize]
            mid_, grp, node = struct.unpack_from("<HHH", e, 0)
            out["labels"].append({"id": mid_, "group": grp, "node": node, "raw": e.hex().upper()})
    for tag, body in secs.items():
        if tag not in ("INF1", "DAT1", "MID1", "FLW1", "FLI1"):
            out["unknown"][tag] = body.hex()
    return out


def lua_str(s):
    out = ['"']
    for ch in s:
        o = ord(ch)
        if ch == '"':
            out.append('\\"')
        elif ch == "\\":
            out.append("\\\\")
        elif ch == "\n":
            out.append("\\n")
        elif o < 32 or o == 127:
            out.append(f"\\{o}")
        else:
            out.append(ch)
    out.append('"')
    return "".join(out)


def to_lua(name, m):
    L = [f"-- {name}: generated by tools/desmume-mcp/reversing/bmg.py (control codes as {{g:GROUP:TYPE:PARAMS}})",
         "return {", f"  file = {lua_str(name)},", f"  encoding = {lua_str(str(m['encoding']))},",
         f"  group = {m.get('inf_group', 0)},", "  messages = {"]
    for msg in m["messages"]:
        L.append(f"    [{msg['index']}] = {{ attr = {lua_str(msg['attr'])}, text = {lua_str(msg['text'])} }},")
    L.append("  },")
    if m["ids"] is not None:
        L.append("  ids = { " + ", ".join(str(x) for x in m["ids"]) + " },")
    if m["flow"]:
        L.append("  flow = {")
        L.append("    nodes = {")
        for n in m["flow"]["nodes"]:
            L.append(f"      [{n['index']}] = {{ type = {n['type']}, sub = {n['sub']}, a = {n['a']}, b = {n['b']}, "
                     f"c = {n['c']} }},")
        L.append("    },")
        L.append("    branches = { " + ", ".join(str(x) for x in m["flow"]["branches"]) + " },")
        L.append("  },")
    if m["labels"]:
        L.append("  labels = {")
        for lb in m["labels"]:
            L.append(f"    {{ id = {lb['id']}, group = {lb['group']}, node = {lb['node']} }},")
        L.append("  },")
    if m["unknown"]:
        L.append("  unknown_sections = {")
        for t, h in m["unknown"].items():
            L.append(f"    [{lua_str(t)}] = {lua_str(h)},")
        L.append("  },")
    L.append("}")
    return "\n".join(L) + "\n"


def main():
    ap = argparse.ArgumentParser(description=__doc__.split("\n\n")[0],
                                 formatter_class=argparse.RawDescriptionHelpFormatter, epilog=__doc__)
    ap.add_argument("files", nargs="*")
    ap.add_argument("--rom")
    ap.add_argument("--prefix", default="")
    ap.add_argument("--out", required=True)
    args = ap.parse_args()
    items = []
    if args.rom:
        sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
        from desmume_mcp.rom import Rom
        rom = Rom(args.rom)
        for fid, path in sorted(rom.files.items(), key=lambda x: x[1]):
            if path.startswith(args.prefix) and path.lower().endswith(".bmg"):
                items.append((path, rom.file_data(fid)))
    items += [(f, open(f, "rb").read()) for f in args.files]
    total = 0
    for path, data in items:
        m = parse(data)
        rel = path[len(args.prefix):].lstrip("/") if args.rom else os.path.basename(path)
        base = os.path.join(args.out, os.path.splitext(rel)[0])
        os.makedirs(os.path.dirname(base) or ".", exist_ok=True)
        open(base + ".lua", "w", encoding="utf-8").write(to_lua(rel, m))
        json.dump(m, open(base + ".json", "w", encoding="utf-8"), ensure_ascii=False, indent=1)
        total += len(m["messages"])
        print(f"{rel}: {len(m['messages'])} messages, sections {m['sections']}"
              + (f", flow {len(m['flow']['nodes'])} nodes" if m["flow"] else ""))
    print(f"{len(items)} files, {total} messages -> {args.out}")


if __name__ == "__main__":
    main()
