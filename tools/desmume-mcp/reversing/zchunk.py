#!/usr/bin/env python3
"""Zelda DS (Phantom Hourglass / Spirit Tracks) map containers -> JSON, losslessly.

Formats (all little-endian; FourCCs are stored as u32 multi-char constants, so
they read backwards in a hex dump: "BPAM" on disk is MAPB):

  .zmb  MAPB/ZMB1|ZMB2   map: rooms grid, warps, player starts, objects, NPCs...
  .zcb  MCLB/ZCB1        collision: vertices, triangles, attributes, lookup grid
  .zab  ZCAB             course arrangement (forward magic), sections CABM, CABI
  .zob  ZOLB             object/actor type lists (forward magic)
  .ilb  ZILB             (PH) sea chart islands, like ZCAB: sections CIBI, CIBS, CIBC
  .clb  ZCLB, .cib ZCIB  course lists: size-prefixed records (+ room tables)
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

# Field layouts: zchunk_schema.json beside this file, {"KEY": [[name, code], ...]}.
# KEY is TAG/ENTRYSIZE, optionally qualified by game and/or container version:
#   "ph:ROOM/20", "ARAB/12@ZMB2", "st:WARP/24@ZMB1"; the most specific match wins.
# Codes: fx32 (20.12 fixed point, written as a float), b B h H i I (struct),
# 4cc (u32 FourCC), s16 (16-byte NUL-padded string).
SCHEMA_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), "zchunk_schema.json")
SCHEMA = json.load(open(SCHEMA_PATH)) if os.path.exists(SCHEMA_PATH) else {}

CODES = {"fx32": ("i", 4), "b": ("b", 1), "B": ("B", 1), "h": ("h", 2), "H": ("H", 2), "i": ("i", 4), "I": ("I", 4),
         "4cc": ("4s", 4), "s16": ("16s", 16)}
GAMES = {"AZE": "ph", "BKI": "st"}     # ROM game code prefix -> schema game key


def schema_for(tag, size, game=None, version=None):
    keys = []
    for g in ([game] if game else []) + [None]:
        for v in ([version] if version else []) + [None]:
            keys.append((f"{g}:" if g else "") + f"{tag}/{size}" + (f"@{v}" if v else ""))
    for k in keys:
        if k in SCHEMA:
            return SCHEMA[k]
    return None


def fourcc(b):
    return b[::-1].decode("latin-1")


def decode_fields(fields, e):
    out, pos = {}, 0
    for name, code in fields:
        fmt, n = CODES[code]
        v = struct.unpack_from("<" + fmt, e, pos)[0]
        if code == "fx32":
            v /= 4096
        elif code == "4cc":
            v = fourcc(v)
        elif code == "s16":
            v = v.split(b"\0")[0].decode("cp932", "replace")
        out[name] = v
        pos += n
    if pos < len(e):
        out["rest"] = e[pos:].hex()
    return out


def decode_entry(tag, e, game=None, version=None):
    fields = schema_for(tag, len(e), game, version)
    out = {}
    if fields:
        return decode_fields(fields, e)
    words = len(e) // 4
    for i, w in enumerate(struct.unpack_from(f"<{words}I", e)):
        out[f"w{i}"] = f"{w:08x}"
    if len(e) % 4:
        out["rest"] = e[words * 4:].hex()
    return out


def section(tag, body, game=None, version=None, magic=None):
    """body = section bytes after the 8-byte tag/size header."""
    s = {"tag": tag, "size": len(body) + 8}
    if tag == "ROMB" and len(body) >= 4:
        # tile grid: u16 width, u16 height, then width*height cells of 4 bytes
        # [misc, type, height (s8, steps of 1.2), flags], one row (constant z) after another
        w, h = struct.unpack_from("<HH", body, 0)
        s.update(width=w, height=h, cell_fields=["misc", "type", "height", "flags"])
        if w and h and len(body) - 4 == w * h * 4:
            s["rows"] = [[[body[o], body[o + 1], struct.unpack_from("b", body, o + 2)[0], body[o + 3]]
                          for o in range(4 + z * w * 4, 4 + (z + 1) * w * 4, 4)] for z in range(h)]
        else:
            s["raw"] = body[4:].hex()
        return s
    if len(body) < 4:
        s["raw"] = body.hex()
        return s
    if tag == "GRDB" and magic == "MCLB":
        # lookup grid: u16 cells along X, u16 cells along Z, then one record per cell,
        # x-major (for x: for z:), each u16 n + n u16 TRIB indices, padded to 4 bytes
        w, h = struct.unpack_from("<HH", body, 0)
        s.update(cells_x=w, cells_z=h, order="x-major: cells[x][z] = triangle indices")
        cells, pos = [], 4
        try:
            for _ in range(w):
                col = []
                for _ in range(h):
                    n = struct.unpack_from("<H", body, pos)[0]
                    col.append(list(struct.unpack_from(f"<{n}H", body, pos + 2)))
                    pos += (2 + 2 * n + 3) & ~3
                cells.append(col)
            s["cells"] = cells
            if body[pos:].strip(b"\0"):
                s["trailing"] = body[pos:].hex()
        except struct.error:
            s["raw"] = body[4:].hex()
        return s
    if tag == "RALB" and game in ("ph", "st") and len(body) >= 4:
        # rails: count, word, then per rail a header and its points (ST points are
        # variable: 0x18 bytes + {rail, point} junction pairs, size in the point itself)
        count, word = struct.unpack_from("<HH", body, 0)
        s.update(count=count, word=f"{word:04x}", rails=[])
        rk = next(k for k in SCHEMA if k.startswith(f"{game}:RALB.rail/"))
        pk = next(k for k in SCHEMA if k.startswith(f"{game}:RALB.point/"))
        rsz, psz = int(rk.split("/")[1]), int(pk.split("/")[1])
        pos = 4
        try:
            for _ in range(count):
                rail = decode_fields(SCHEMA[rk], body[pos:pos + rsz])
                pos += rsz
                pts = []
                for _ in range(rail["num_points"]):
                    pt = decode_fields(SCHEMA[pk], body[pos:pos + psz])
                    step = pt.get("point_size", psz)
                    if "link_count" in pt:
                        pt["links"] = [list(body[pos + psz + 2 * i:pos + psz + 2 * i + 2]) for i in range(pt["link_count"])]
                    pts.append(pt)
                    pos += step
                rail["points"] = pts
                s["rails"].append(rail)
            if body[pos:].strip(b"\0"):
                s["trailing"] = body[pos:].hex()
        except (struct.error, KeyError):
            s.pop("rails")
            s["raw"] = body[4:].hex()
        return s
    hdr = next(((int(k.split("/")[1]), v) for k, v in SCHEMA.items()
                if k.split(":")[-1].startswith(f"{tag}.HDR/")), None)
    if hdr:
        # section with its own header; its "count" field gives the number of entries
        hsize, fields = hdr
        s["header"] = decode_fields(fields, body[:hsize])
        count, data = s["header"].get("count", 0), body[hsize:]
    else:
        count, word = struct.unpack_from("<HH", body, 0)
        s["count"], s["word"] = count, f"{word:04x}"
        data = body[4:]
    sizes = sorted({int(k.split("/")[1].split("@")[0]) for k in SCHEMA
                    if k.split(":")[-1].split("/")[0] == tag})
    esz = len(data) // count if count and len(data) % count == 0 else None
    if count and esz not in sizes:
        # known entry size followed by padding (e.g. NRMB)
        esz = next((z for z in sizes if count * z <= len(data) < count * z + 4), esz)
    if count and esz:
        s["entry_size"] = esz
        s["entries"] = [decode_entry(tag, data[i * esz:(i + 1) * esz], game, version) for i in range(count)]
        if data[count * esz:].strip(b"\0"):
            s["trailing"] = data[count * esz:].hex()
    elif count == 0 and not data.strip(b"\0"):
        s["entries"] = []
    else:
        s["raw"] = data.hex()
    return s


def parse(d, game=None):
    """game: "ph"/"st" (selects game-specific layouts) or None."""
    head = d[:4]
    if fourcc(head) in ("MAPB", "MCLB") or d[16:32] == b"\x04\x03\x02\x01" * 4:   # any container of this family
        size, n = struct.unpack_from("<II", d, 8)
        out = {"magic": fourcc(head), "version": fourcc(d[4:8]), "sections": []}
        pos = 0x20
    elif head in (b"ZCLB", b"ZCIB"):
        # course lists: u32 size, u32 count, u32 count, then size-prefixed records
        size, n = struct.unpack_from("<II", d, 4)
        out, pos = {"magic": head.decode(), "records": []}, 0x10
        for _ in range(n):
            rsz = struct.unpack_from("<I", d, pos)[0]
            rec = d[pos + 4:pos + rsz]
            fixed = next(((int(k.split("/")[1]), v) for k, v in SCHEMA.items()
                          if k in (f"{game}:{head.decode()}/{len(rec)}",) or
                          (k.startswith(f"{game}:{head.decode()}/") and "." not in k)), None) if game else None
            r = {"size": rsz}
            if fixed and fixed[0] <= len(rec):
                r.update(decode_fields(fixed[1], rec[:fixed[0]]))
                r.pop("rest", None)
                rk = [k for k in SCHEMA if k.startswith(f"{game}:{head.decode()}.ROOM/")]
                tail = rec[fixed[0]:]
                if rk and "nrooms" in r:
                    rs = int(rk[0].split("/")[1])
                    r["rooms"] = [decode_fields(SCHEMA[rk[0]], tail[i * rs:(i + 1) * rs]) for i in range(r["nrooms"])]
                    tail = tail[r["nrooms"] * rs:]
                if tail:
                    r["rest"] = tail.hex()
            else:
                r["raw"] = rec.hex()
            out["records"].append(r)
            pos += rsz
        return out
    elif head in (b"ZCAB", b"ZILB"):
        size, n = struct.unpack_from("<II", d, 4)
        out = {"magic": head.decode(), "sections": []}
        pos = 0x10
    elif head == b"ZOLB":
        size, a, b, count, word = struct.unpack_from("<IHHHH", d, 4)
        body = d[0x10:size]
        # npctype lists are actor FourCCs, motype lists numeric object types
        names = [fourcc(body[i:i + 4]) for i in range(0, count * 4, 4)]
        is_4cc = all(len(x) == 4 and all(c.isalnum() or c == "_" for c in x) for x in names) and count
        # h0: allocation pool size in units (PH actors 0x80 bytes, PH objects 0x40; ST 0x100 / 0x80)
        # h1: instance table capacity. Lists are preload/sizing only: they never spawn anything.
        return {"magic": "ZOLB", "pool_units": a, "instances": b, "word": f"{word:04x}",
                "entries": names if is_4cc else list(struct.unpack_from(f"<{count}I", body))}
    else:
        raise ValueError(f"unknown container {head!r}")
    for _ in range(n):
        tag, ssz = fourcc(d[pos:pos + 4]), struct.unpack_from("<I", d, pos + 4)[0]
        out["sections"].append(section(tag, d[pos + 8:pos + ssz], game, out.get("version"), out["magic"]))
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
    game = GAMES.get(rom.game_code[:3])
    for fid, path in sorted(rom.files.items(), key=lambda x: x[1]):
        if not path.startswith(prefix):
            continue
        fmt, _, _, plain = ri.classify(rom.file_data(fid))
        members = ri.narc_members(plain) if fmt == "NARC" else [(None, plain)]
        for name, md in members:
            _, _, _, mp = ri.classify(md)
            yield (path if name is None else f"{path}/{name}"), mp, game


def main():
    ap = argparse.ArgumentParser(description=__doc__.split("\n\n")[0],
                                 formatter_class=argparse.RawDescriptionHelpFormatter, epilog=__doc__)
    ap.add_argument("files", nargs="*")
    ap.add_argument("--rom")
    ap.add_argument("--prefix", default="")
    ap.add_argument("--out")
    ap.add_argument("--game", help="ph or st: game-specific layouts (taken from the ROM header with --rom)")
    args = ap.parse_args()
    items = list(rom_items(args.rom, args.prefix)) if args.rom else []
    items += [(f, open(f, "rb").read(), args.game) for f in args.files]
    n = 0
    for path, d, game in items:
        try:
            m = parse(d, game or args.game)
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
