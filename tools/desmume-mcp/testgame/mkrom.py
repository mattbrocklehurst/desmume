#!/usr/bin/env python3
"""Pack the test game binaries into a .nds ROM image.

Builds a ROM with a real header, an ARM9 and ARM7 binary, a file name table
(FNT), a file allocation table (FAT), and an ARM9 overlay table with a plain
and a BLZ compressed overlay (both at the same RAM address), so that the
ROM parsing tools have something realistic to chew on. No ndstool/devkitPro
is needed.

usage: mkrom.py arm9.bin overlay0.bin out.nds
"""

import os
import random
import struct
import sys

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), ".."))
from desmume_mcp.rom import blz_compress  # noqa: E402

ARM9_ADDR = 0x02000000
ARM7_ADDR = 0x02380000
OVERLAY0_ADDR = 0x02100000

# 4x4 tilemap, one byte per tile (0 = empty); read by the game with
# fs_read_file(4, ...) - keep the file id in sync with FILE_LEVEL1 in game.c
LEVEL1_MAP = bytes([
    1, 1, 1, 1,
    1, 0, 2, 1,
    1, 3, 0, 1,
    1, 1, 1, 1,
])

# opaque asset files of different sizes (the game identifies them by file
# id only; ids 5-8 must match FILE_*_DAT in game.c)
ASSET_NAMES = ["a.dat", "b.dat", "c.dat", "d.dat"]
ASSETS = [random.Random(1234 + i).randbytes(size) for i, size in enumerate((300, 1500, 700, 96))]

# ARM7: just spin (b .)
ARM7_CODE = struct.pack("<I", 0xEAFFFFFE)


def crc16(data):
    crc = 0xFFFF
    for b in data:
        crc ^= b
        for _ in range(8):
            crc = (crc >> 1) ^ 0xA001 if crc & 1 else crc >> 1
    return crc


def align(buf, n):
    buf.extend(b"\xff" * ((-len(buf)) % n))


def build_fnt(files_root, dirs):
    """files_root: [(name, file_id)], dirs: [(dirname, [(name, file_id)])]

    Returns the FNT bytes. Directory ids start at 0xF000 (root)."""
    ndirs = 1 + len(dirs)
    main = bytearray()
    subtables = []

    # root sub-table
    root = bytearray()
    for name, _ in files_root:
        root += bytes([len(name)]) + name.encode()
    for i, (dname, _) in enumerate(dirs):
        root += bytes([0x80 | len(dname)]) + dname.encode() + struct.pack("<H", 0xF001 + i)
    root += b"\0"
    subtables.append((root, files_root[0][1] if files_root else 0, ndirs))

    for dname, dfiles in dirs:
        sub = bytearray()
        for name, _ in dfiles:
            sub += bytes([len(name)]) + name.encode()
        sub += b"\0"
        subtables.append((sub, dfiles[0][1], 0xF000))

    offset = ndirs * 8
    body = bytearray()
    for sub, first_id, third in subtables:
        main += struct.pack("<IHH", offset + len(body), first_id, third)
        body += sub
    return bytes(main + body)


def main():
    if len(sys.argv) != 4:
        sys.exit(__doc__)
    arm9 = open(sys.argv[1], "rb").read()
    overlay0 = open(sys.argv[2], "rb").read()
    out = sys.argv[3]

    overlay1 = blz_compress(overlay0)
    if len(overlay1) >= len(overlay0):
        sys.exit("overlay did not compress, add more compressible data to overlay.c")

    # file ids: overlays first (as retail ROMs do), then regular files
    files = [
        overlay0,                                        # id 0: overlay 0
        overlay1,                                        # id 1: overlay 1 (compressed)
        b"DeSmuME MCP test game\n",                      # id 2: readme.txt
        b"hello from the data directory\n",              # id 3: data/hello.txt
        LEVEL1_MAP,                                      # id 4: data/level1.map
    ] + ASSETS                                           # id 5-8: assets/a.dat .. d.dat
    fnt = build_fnt([("readme.txt", 2)], [("data", [("hello.txt", 3), ("level1.map", 4)]),
                                          ("assets", [(n, 5 + i) for i, n in enumerate(ASSET_NAMES)])])

    rom = bytearray(0x4000)

    # ARM9 binary
    arm9_off = len(rom)
    rom += arm9
    align(rom, 0x200)
    # retail cards only serve data reads from 0x8000 up, so everything the
    # game loads at runtime goes above that (as in real ROMs)
    rom.extend(b"\xff" * max(0, 0x8000 - len(rom)))

    # ARM9 overlay table (y9), 32 bytes per entry; bit 24 of the last word
    # flags compression, the low 24 bits hold the compressed size
    ovt_off = len(rom)
    ovt = (struct.pack("<8I", 0, OVERLAY0_ADDR, len(overlay0), 0, 0, 0, 0, 0) +
           struct.pack("<8I", 1, OVERLAY0_ADDR, len(overlay0), 0, 0, 0, 1,
                       0x01000000 | len(overlay1)))
    rom += ovt
    align(rom, 0x200)

    # ARM7 binary
    arm7_off = len(rom)
    rom += ARM7_CODE
    align(rom, 0x200)

    # FNT
    fnt_off = len(rom)
    rom += fnt
    align(rom, 0x200)

    # FAT (placeholder, filled below)
    fat_off = len(rom)
    rom += b"\0" * (8 * len(files))
    align(rom, 0x200)

    fat = bytearray()
    for data in files:
        start = len(rom)
        rom += data
        fat += struct.pack("<II", start, start + len(data))
        align(rom, 0x200)
    rom[fat_off:fat_off + len(fat)] = fat

    # header
    struct.pack_into("<12s4s2sBBB", rom, 0x00, b"MCPTESTGAME", b"MCPT", b"01", 0, 0, 0)
    struct.pack_into("<4I", rom, 0x20, arm9_off, ARM9_ADDR, ARM9_ADDR, len(arm9))
    struct.pack_into("<4I", rom, 0x30, arm7_off, ARM7_ADDR, ARM7_ADDR, len(ARM7_CODE))
    struct.pack_into("<4I", rom, 0x40, fnt_off, len(fnt), fat_off, len(fat))
    struct.pack_into("<4I", rom, 0x50, ovt_off, len(ovt), 0, 0)
    struct.pack_into("<II", rom, 0x80, len(rom), 0x4000)
    struct.pack_into("<H", rom, 0x15E, crc16(rom[:0x15E]))

    open(out, "wb").write(rom)
    print(f"wrote {out}: {len(rom)} bytes, arm9 {len(arm9)} bytes, overlay0 {len(overlay0)} bytes")


if __name__ == "__main__":
    main()
