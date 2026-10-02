#!/usr/bin/env python3
"""Zelda DS (Phantom Hourglass / Spirit Tracks) map containers -> JSON, losslessly.

Formats (all little-endian; FourCCs are stored as u32 multi-char constants, so
they read backwards in a hex dump: "BPAM" on disk is MAPB):

  .zmb  MAPB/ZMB1|ZMB2   map: rooms grid, warps, player starts, objects, NPCs...
  .zcb  MCLB/ZCB1        collision: vertices, triangles, attributes, lookup grid
  .zab  ZCAB             course arrangement (forward magic), sections CABM, CABI
  .zob  ZOLB             object/actor type lists (forward magic)
  .ztb  MTRB/ZTB1        (ST) train track network
  and any other file with the same 0x20-byte header (01020304 padding)

Container header (MAPB/MCLB, 0x20 bytes): u32 magic, u32 version, u32 file size,
u32 section count, 16 bytes of 0x01020304 padding. ZCAB: magic, size, count,
u32 0xFFFFFFFF (0x10 bytes). Sections: u32 tag, u32 size (header included),
then for table sections u16 count, u16 word (0xFFFF, 0x0304 or 0x0102), and
`count` fixed-size entries. Sections whose size does not divide evenly are kept
raw (hex) with their count.

Field names come from SCHEMA below: (tag, entry size) -> [(name, struct code)].
Entries without a schema are split into u32 words named w0, w1... so nothing is
lost; extend SCHEMA as fields are identified in the game code (see
docs/REVERSING.md, "Game data").

usage:
  zchunk.py FILE [...] [--out DIR]                    one .json per file (stdout if no --out)
  zchunk.py --rom game.nds --prefix Map/ --out DIR    every container under a ROM path,
                                                      looking into NARC archives and LZ77
"""

import argparse
import json
import os
import struct
import sys

# (tag, entry size) -> fields. "fx32" = 20.12 fixed point, written as a float.
SCHEMA = {
    ("VTXB", 12): [("x", "fx32"), ("y", "fx32"), ("z", "fx32")],
    ("NRMB", 6): [("nx", "h"), ("ny", "h"), ("nz", "h")],
    ("PCLB", 4): [("attr", "I")],
    ("TRIB", 8): [("v0", "H"), ("v1", "H"), ("v2", "H"), ("attr", "H")],
}

CODES = {"fx32": ("i", 4), "b": ("b", 1), "B": ("B", 1), "h": ("h", 2), "H": ("H", 2), "i": ("i", 4), "I": ("I", 4),
         "4cc": ("4s", 4)}


def fourcc(b):
    return b[::-1].decode("latin-1")


def decode_entry(tag, e):
    fields = SCHEMA.get((tag, len(e)))
    out = {}
    if fields:
        pos = 0
        for name, code in fields:
            fmt, n = CODES[code]
            v = struct.unpack_from("<" + fmt, e, pos)[0]
            out[name] = v / 4096 if code == "fx32" else fourcc(v) if code == "4cc" else v
            pos += n
        if pos < len(e):
            out["rest"] = e[pos:].hex()
        return out
    words = len(e) // 4
    for i, w in enumerate(struct.unpack_from(f"<{words}I", e)):
        out[f"w{i}"] = f"{w:08x}"
    if len(e) % 4:
        out["rest"] = e[words * 4:].hex()
    return out


def section(tag, body):
    """body = section bytes after the 8-byte tag/size header."""
    s = {"tag": tag, "size": len(body) + 8}
    if len(body) < 4:
        s["raw"] = body.hex()
        return s
    count, word = struct.unpack_from("<HH", body, 0)
    s["count"], s["word"] = count, f"{word:04x}"
    data = body[4:]
    if count and len(data) % count == 0:
        esz = len(data) // count
        s["entry_size"] = esz
        s["entries"] = [decode_entry(tag, data[i * esz:(i + 1) * esz]) for i in range(count)]
    elif count == 0 and not data:
        s["entries"] = []
    else:
        s["raw"] = data.hex()
    return s


def parse(d):
    head = d[:4]
    if fourcc(head) in ("MAPB", "MCLB") or d[16:32] == b"\x04\x03\x02\x01" * 4:   # any container of this family
        size, n = struct.unpack_from("<II", d, 8)
        out = {"magic": fourcc(head), "version": fourcc(d[4:8]), "sections": []}
        pos = 0x20
    elif head == b"ZCAB":
        size, n = struct.unpack_from("<II", d, 4)
        out = {"magic": "ZCAB", "sections": []}
        pos = 0x10
    elif head == b"ZOLB":
        size, a, b, count, word = struct.unpack_from("<IHHHH", d, 4)
        body = d[0x10:size]
        # npctype lists are actor FourCCs, motype lists numeric object types
        names = [fourcc(body[i:i + 4]) for i in range(0, count * 4, 4)]
        is_4cc = all(len(x) == 4 and all(c.isalnum() or c == "_" for c in x) for x in names) and count
        return {"magic": "ZOLB", "h0": a, "h1": b, "word": f"{word:04x}",
                "entries": names if is_4cc else list(struct.unpack_from(f"<{count}I", body))}
    else:
        raise ValueError(f"unknown container {head!r}")
    for _ in range(n):
        tag, ssz = fourcc(d[pos:pos + 4]), struct.unpack_from("<I", d, pos + 4)[0]
        out["sections"].append(section(tag, d[pos + 8:pos + ssz]))
        if ssz < 8:
            break
        pos += ssz
    if pos < len(d) and d[pos:].strip(b"\0"):
        out["trailing"] = d[pos:].hex()
    return out


def rom_items(rom_path, prefix):
    here = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    sys.path[:0] = [here, os.path.join(here, "scripts")]
    from desmume_mcp.rom import Rom
    import rom_inventory as ri
    rom = Rom(rom_path)
    for fid, path in sorted(rom.files.items(), key=lambda x: x[1]):
        if not path.startswith(prefix):
            continue
        fmt, _, _, plain = ri.classify(rom.file_data(fid))
        members = ri.narc_members(plain) if fmt == "NARC" else [(None, plain)]
        for name, md in members:
            _, _, _, mp = ri.classify(md)
            yield (path if name is None else f"{path}/{name}"), mp


def main():
    ap = argparse.ArgumentParser(description=__doc__.split("\n\n")[0],
                                 formatter_class=argparse.RawDescriptionHelpFormatter, epilog=__doc__)
    ap.add_argument("files", nargs="*")
    ap.add_argument("--rom")
    ap.add_argument("--prefix", default="")
    ap.add_argument("--out")
    args = ap.parse_args()
    items = list(rom_items(args.rom, args.prefix)) if args.rom else []
    items += [(f, open(f, "rb").read()) for f in args.files]
    n = 0
    for path, d in items:
        try:
            m = parse(d)
        except (ValueError, struct.error):
            continue
        n += 1
        if not args.out:
            print(json.dumps({"file": path, **m}, indent=1))
            continue
        rel = path[len(args.prefix):].lstrip("/") if args.rom else os.path.basename(path)
        dest = os.path.join(args.out, rel + ".json")
        os.makedirs(os.path.dirname(dest), exist_ok=True)
        json.dump({"file": path, **m}, open(dest, "w"), indent=1)
    if args.out:
        print(f"{n} containers -> {args.out}")


if __name__ == "__main__":
    main()
