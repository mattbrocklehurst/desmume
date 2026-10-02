#!/usr/bin/env python3
"""Inventory of every file in a DS ROM by format: what an engine has to load.

For each file in the ROM file system: path, size, format (magic), looking
through LZ77 compression (types 0x10 / 0x11) and into NARC archives (each
member's format is counted too). Only names, sizes and formats are written:
no file contents, so the result can be shared.

usage:
  tools/desmume-mcp/scripts/rom_inventory.py rom.nds [--out DIR]
      [--push --dest-repo PATH]   commit DIR to that repo's current branch and push

Writes DIR/inventory.json (every file) and DIR/README.md (summary by format).
"""

import argparse
import collections
import json
import os
import struct
import subprocess
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.dirname(HERE))
from desmume_mcp.rom import Rom  # noqa: E402

# magic -> (format, what it is)
FORMATS = {
    b"BMD0": ("NSBMD", "3D model(s) + materials (NitroSystem G3D)"),
    b"BTX0": ("NSBTX", "3D textures + palettes"),
    b"BCA0": ("NSBCA", "skeletal (joint) animation"),
    b"BTP0": ("NSBTP", "texture pattern animation"),
    b"BTA0": ("NSBTA", "texture SRT animation"),
    b"BMA0": ("NSBMA", "material colour animation"),
    b"BVA0": ("NSBVA", "visibility animation"),
    b"RGCN": ("NCGR", "2D character graphics (tiles)"),
    b"RLCN": ("NCLR", "2D palette"),
    b"RCSN": ("NSCR", "2D screen (tile map)"),
    b"RECN": ("NCER", "2D cells (sprite layouts)"),
    b"RNAN": ("NANR", "2D cell animation"),
    b"RCMN": ("NMCR", "2D multi-cell"),
    b"RNMN": ("NMAR", "2D multi-cell animation"),
    b"RTFN": ("NFTR", "font"),
    b"SDAT": ("SDAT", "sound archive (sequences, banks, waves, streams)"),
    b"SSEQ": ("SSEQ", "sound sequence"),
    b"SBNK": ("SBNK", "instrument bank"),
    b"SWAR": ("SWAR", "wave archive"),
    b"STRM": ("STRM", "audio stream"),
    b"NARC": ("NARC", "file archive"),
    b"MESG": ("BMG", "message (text) file"),
    b"SPA ": ("SPA", "particle resources (SPL)"),
    b"BMG ": ("BMG", "message (text) file"),
}


def lz_decompress(d):
    """LZ77 type 0x10 / 0x11 (Nintendo), or None if it does not look like one."""
    if len(d) < 4 or d[0] not in (0x10, 0x11):
        return None
    size = d[1] | d[2] << 8 | d[3] << 16
    if size == 0 or size > 32 << 20:
        return None
    out, i, ext = bytearray(), 4, d[0] == 0x11
    try:
        while len(out) < size:
            flags = d[i]; i += 1
            for b in range(8):
                if len(out) >= size:
                    break
                if not flags & (0x80 >> b):
                    out.append(d[i]); i += 1
                    continue
                if ext:
                    t = d[i] >> 4
                    if t == 0:
                        n = ((d[i] & 0xF) << 4 | d[i + 1] >> 4) + 0x11; disp = ((d[i + 1] & 0xF) << 8 | d[i + 2]) + 1; i += 3
                    elif t == 1:
                        n = ((d[i] & 0xF) << 12 | d[i + 1] << 4 | d[i + 2] >> 4) + 0x111
                        disp = ((d[i + 2] & 0xF) << 8 | d[i + 3]) + 1; i += 4
                    else:
                        n = t + 1; disp = ((d[i] & 0xF) << 8 | d[i + 1]) + 1; i += 2
                else:
                    n = (d[i] >> 4) + 3; disp = ((d[i] & 0xF) << 8 | d[i + 1]) + 1; i += 2
                if disp > len(out):
                    return None
                for _ in range(n):
                    out.append(out[-disp])
    except IndexError:
        return None
    return bytes(out[:size])


def classify(data):
    """(format, description, compressed)"""
    comp = None
    if data[:1] in (b"\x10", b"\x11") and data[:4] not in FORMATS:
        dec = lz_decompress(data)
        if dec:
            data, comp = dec, "LZ77"
    m = data[:4]
    if m in FORMATS:
        return FORMATS[m][0], FORMATS[m][1], comp, data
    if data[:8] == b"MESGbmg1":
        return "BMG", "message (text) file", comp, data
    return None, None, comp, data


def narc_members(d):
    """[(name_or_index, bytes)] for a NARC archive."""
    try:
        hdr = struct.unpack_from("<HH", d, 12)[0]
        pos = hdr
        out = []
        assert d[pos:pos + 4] == b"BTAF"
        fatb_size, count = struct.unpack_from("<IH", d, pos + 4)
        entries = [struct.unpack_from("<II", d, pos + 12 + k * 8) for k in range(count)]
        pos += fatb_size
        assert d[pos:pos + 4] == b"BTNF"
        pos += struct.unpack_from("<I", d, pos + 4)[0]
        assert d[pos:pos + 4] == b"GMIF"
        img = pos + 8
        for k, (s, e) in enumerate(entries):
            out.append((k, d[img + s:img + e]))
        return out
    except (AssertionError, struct.error):
        return []


def main():
    ap = argparse.ArgumentParser(description=__doc__.split("\n\n")[0],
                                 formatter_class=argparse.RawDescriptionHelpFormatter, epilog=__doc__)
    ap.add_argument("rom")
    ap.add_argument("--out", default=None)
    ap.add_argument("--push", action="store_true")
    ap.add_argument("--dest-repo", default=None)
    args = ap.parse_args()
    rom = Rom(args.rom)
    out = os.path.abspath(args.out or f"rom-inventory-{rom.game_code}")
    if args.push:
        if not args.dest_repo:
            sys.exit("--push needs --dest-repo")
        out = os.path.join(os.path.abspath(args.dest_repo), "rom-inventory", rom.game_code)
    os.makedirs(out, exist_ok=True)

    files, by_fmt = [], collections.defaultdict(lambda: {"files": 0, "bytes": 0, "in_archives": 0, "dirs": collections.Counter()})
    ext_unknown = collections.Counter()
    for fid, path in sorted(rom.files.items(), key=lambda x: x[1]):
        data = rom.file_data(fid)
        fmt, desc, comp, plain = classify(data)
        entry = {"path": path, "size": len(data), "format": fmt, "compressed": comp,
                 "magic": plain[:4].hex() if fmt is None else None}
        top = path.split("/")[0] if "/" in path else "(root)"
        key = fmt or ("unknown ." + path.rsplit(".", 1)[-1].lower() if "." in path else "unknown")
        by_fmt[key]["files"] += 1
        by_fmt[key]["bytes"] += len(data)
        by_fmt[key]["dirs"][top] += 1
        if fmt is None:
            ext_unknown[path.rsplit(".", 1)[-1].lower() if "." in path else ""] += 1
        if fmt == "NARC":
            members = collections.Counter()
            for k, md in narc_members(plain):
                mf, _, mc, _ = classify(md)
                mk = mf or "unknown"
                members[mk + (" (LZ77)" if mc else "")] += 1
                by_fmt[mf or "unknown (in NARC)"]["in_archives"] += 1
            entry["members"] = dict(members)
        files.append(entry)

    json.dump({"game": rom.title, "game_code": rom.game_code, "files": files}, open(os.path.join(out, "inventory.json"), "w"), indent=1)
    desc = {v[0]: v[1] for v in FORMATS.values()}
    L = [f"# ROM inventory: {rom.title} [{rom.game_code}]", "",
         f"{len(files)} files in the ROM file system (plus {len(rom.overlays)} code overlays). Formats seen through "
         "LZ77 compression and inside NARC archives. Only names/sizes/formats, no contents.", "",
         "| format | what | files | bytes | inside NARCs | top-level dirs |", "|---|---|---|---|---|---|"]
    for k, v in sorted(by_fmt.items(), key=lambda x: -x[1]["bytes"]):
        L.append(f"| {k} | {desc.get(k, '')} | {v['files']} | {v['bytes']:,} | {v['in_archives']} | "
                 + ", ".join(f"{d} ({n})" for d, n in v["dirs"].most_common(5)) + " |")
    L += ["", "## Directory tree (file counts)", ""]
    dirs = collections.Counter("/".join(f["path"].split("/")[:-1]) or "(root)" for f in files)
    L += [f"- `{d}`: {n}" for d, n in sorted(dirs.items())]
    open(os.path.join(out, "README.md"), "w").write("\n".join(L) + "\n")
    print("\n".join(L[:40]))
    print(f"\nwritten to {out}")
    if args.push:
        repo = os.path.abspath(args.dest_repo)
        subprocess.run(["git", "-C", repo, "add", out], check=True)
        subprocess.run(["git", "-C", repo, "commit", "-q", "-m", f"ROM inventory {rom.game_code}"], check=True)
        if subprocess.run(["git", "-C", repo, "push", "-q"]).returncode != 0:
            subprocess.run(["git", "-C", repo, "pull", "-q", "--rebase"], check=True)
            subprocess.run(["git", "-C", repo, "push", "-q"], check=True)
        print("pushed")


if __name__ == "__main__":
    main()
