#!/usr/bin/env python3
"""Pull memory out of a DeSmuME savestate (.dst / .dsN) without the ROM.

Format (desmume/src/saves.cpp): 16-byte magic "DeSmuME SState\\0", version,
emulator version, uncompressed length, compressed length (0xFFFFFFFF = raw),
then (zlib) a list of chunks {u32 type, u32 size, data}. SFORMAT chunks are
lists of {char desc[4], u32 elem_size, u32 count, data}. Chunk 4 (SF_MEM) has
ITCM, DTCM, WRAM (main RAM, 4 MB) and WRAX (the upper 4 MB on debug units).

usage: dst_extract.py STATE OUTDIR   -> OUTDIR/{main.bin,itcm.bin,dtcm.bin,arm9_regs.json}
"""
import json
import os
import struct
import sys
import zlib


def chunks(path):
    data = open(path, "rb").read()
    if not data.startswith(b"DeSmuME SState\0"):
        sys.exit(f"{path}: not a DeSmuME savestate")
    ver, emu, ulen, clen = struct.unpack_from("<4I", data, 16)
    body = data[32:]
    body = zlib.decompress(body) if clen != 0xFFFFFFFF else body[:ulen]
    pos, out = 0, {}
    while pos + 4 <= len(body):
        typ, = struct.unpack_from("<I", body, pos)
        if typ == 0xFFFFFFFF:
            break
        size, = struct.unpack_from("<I", body, pos + 4)
        out[typ] = body[pos + 8:pos + 8 + size]
        pos += 8 + size
    return ver, out


def sformat(blob):
    pos, fields = 0, {}
    while pos + 12 <= len(blob):
        desc = blob[pos:pos + 4].decode("latin-1")
        sz, cnt = struct.unpack_from("<II", blob, pos + 4)
        fields[desc] = blob[pos + 12:pos + 12 + sz * cnt]
        pos += 12 + sz * cnt
    return fields


if __name__ == "__main__":
    path, outdir = sys.argv[1:3]
    os.makedirs(outdir, exist_ok=True)
    ver, ch = chunks(path)
    mem = sformat(ch[4])
    open(os.path.join(outdir, "main.bin"), "wb").write(mem["WRAM"])
    open(os.path.join(outdir, "itcm.bin"), "wb").write(mem["ITCM"])
    open(os.path.join(outdir, "dtcm.bin"), "wb").write(mem["DTCM"])
    arm9 = sformat(ch[1])
    regs = {k: struct.unpack("<%dI" % (len(v) // 4), v) if len(v) % 4 == 0 and len(v) <= 64 else len(v)
            for k, v in arm9.items()}
    json.dump({k: (list(v) if isinstance(v, tuple) else v) for k, v in regs.items()},
              open(os.path.join(outdir, "arm9_regs.json"), "w"))
    print(f"savestate v{ver}: main {len(mem['WRAM']):#x}, itcm {len(mem['ITCM']):#x}, dtcm {len(mem['DTCM']):#x}; "
          f"arm9 fields {list(arm9)[:12]}")
