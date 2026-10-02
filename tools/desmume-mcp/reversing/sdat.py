#!/usr/bin/env python3
"""NitroSDK sound archives (SDAT) -> JSON listing of every sound, optionally the files.

Layout (all little-endian):
  header   "SDAT", u16 0xFEFF, u16 version, u32 file size, u16 header size, u16 block count,
           then (offset, size) of SYMB, INFO, FAT, FILE (SYMB may be absent: offset 0)
  SYMB     "SYMB", size, 8 record offsets (relative to SYMB): SEQ, SEQARC, BANK, WAVEARC,
           PLAYER, GROUP, PLAYER2, STRM. Each record: u32 count, count x u32 name offsets.
           The SEQARC record holds (archive name, sub-record) pairs; the sub-record names the
           sequences inside that archive (sound effects).
  INFO     "INFO", size, the same 8 record offsets (relative to INFO); each record: u32
           count, count x u32 entry offsets (0 = unused slot). Entries:
             SEQ     u16 file id, u16 -, u16 bank, u8 volume, u8 channel prio, u8 player prio,
                     u8 player, u16 -
             SEQARC  u16 file id, u16 -
             BANK    u16 file id, u16 -, u16 wave archives[4] (0xFFFF = none)
             WAVEARC u16 file id, u16 - (bit 24 of the u32: load individually)
             PLAYER  u8 max sequences, u8 -, u16 channel mask, u32 heap size
             GROUP   u32 count, count x {u8 type, u8 load flags, u16 -, u32 index}
             PLAYER2 u8 count, u8 channels[16], ...
             STRM    u16 file id, u16 -, u8 volume, u8 priority, u8 player, u8 -
  FAT      "FAT ", size, u32 count, count x {u32 offset (from file start), u32 size, 8 x 0}
  FILE     the files: SSEQ (sequence), SSAR (sequence archive), SBNK (instrument bank),
           SWAR (wave archive), STRM (stream)

A game refers to sounds by their index in these records (sequence 12, stream 3...);
the names are the developers' own (e.g. BGM_FIELD) when SYMB is present.

usage:
  sdat.py FILE.sdat [--out DIR] [--extract [--wav]]   listing to DIR/sdat.json (stdout without
                                               --out); --extract also writes every file, by name;
                                               --wav decodes STRM and SWAR (PCM8/16, IMA-ADPCM) to
                                               .wav (loop start as a 'smpl' chunk)
  sdat.py --rom game.nds [--out DIR] [--extract]   every SDAT in the ROM
"""

import argparse
import json
import os
import struct
import sys

RECORDS = ["seq", "seqarc", "bank", "wavearc", "player", "group", "player2", "strm"]
EXT = {b"SSEQ": "sseq", b"SSAR": "ssar", b"SBNK": "sbnk", b"SWAR": "swar", b"STRM": "strm"}


def cstr(d, off):
    return d[off:d.index(b"\0", off)].decode("latin-1")


def parse(d):
    if d[:4] != b"SDAT":
        raise ValueError("not an SDAT file")
    nblocks = struct.unpack_from("<H", d, 0xE)[0]
    blocks = [struct.unpack_from("<II", d, 0x10 + 8 * i) for i in range(4)]
    symb_off, info_off, fat_off = blocks[0][0], blocks[1][0], blocks[2][0]
    names = {r: [] for r in RECORDS}
    sub_names = []
    if symb_off and d[symb_off:symb_off + 4] == b"SYMB":
        for ri, r in enumerate(RECORDS):
            rec = symb_off + struct.unpack_from("<I", d, symb_off + 8 + 4 * ri)[0]
            if rec == symb_off:
                continue
            n = struct.unpack_from("<I", d, rec)[0]
            if r == "seqarc":
                for i in range(n):
                    no, so = struct.unpack_from("<II", d, rec + 4 + 8 * i)
                    names[r].append(cstr(d, symb_off + no) if no else None)
                    sub = []
                    if so:
                        sn = struct.unpack_from("<I", d, symb_off + so)[0]
                        for j in range(sn):
                            o = struct.unpack_from("<I", d, symb_off + so + 4 + 4 * j)[0]
                            sub.append(cstr(d, symb_off + o) if o else None)
                    sub_names.append(sub)
            else:
                for i in range(n):
                    o = struct.unpack_from("<I", d, rec + 4 + 4 * i)[0]
                    names[r].append(cstr(d, symb_off + o) if o else None)
    fat_n = struct.unpack_from("<I", d, fat_off + 8)[0]
    fat = [struct.unpack_from("<II", d, fat_off + 12 + 16 * i) for i in range(fat_n)]
    out = {"blocks": nblocks, "files": len(fat)}
    for ri, r in enumerate(RECORDS):
        rec = info_off + struct.unpack_from("<I", d, info_off + 8 + 4 * ri)[0]
        n = struct.unpack_from("<I", d, rec)[0]
        entries = []
        for i in range(n):
            eo = struct.unpack_from("<I", d, rec + 4 + 4 * i)[0]
            name = names[r][i] if i < len(names[r]) else None
            if not eo:
                entries.append(None)
                continue
            e = info_off + eo
            x = {"index": i, "name": name}
            if r in ("seq", "seqarc", "bank", "wavearc", "strm"):
                fid = struct.unpack_from("<H", d, e)[0]
                x["file"] = fid
                if fid < len(fat):
                    x["size"] = fat[fid][1]
            if r == "seq":
                bank, vol, cpr, ppr, ply = struct.unpack_from("<HBBBB", d, e + 4)
                x.update(bank=bank, volume=vol, channel_prio=cpr, player_prio=ppr, player=ply)
            elif r == "seqarc":
                x["sequences"] = sub_names[i] if i < len(sub_names) else []
            elif r == "bank":
                x["wavearcs"] = [w for w in struct.unpack_from("<4H", d, e + 4) if w != 0xFFFF]
            elif r == "wavearc":
                x["individual"] = bool(struct.unpack_from("<I", d, e)[0] >> 24 & 1)
            elif r == "player":
                ms, mask, heap = struct.unpack_from("<BxHI", d, e)
                x.update(max_seqs=ms, channel_mask=f"{mask:04x}", heap=heap)
            elif r == "group":
                cnt = struct.unpack_from("<I", d, e)[0]
                x["items"] = [dict(zip(("type", "load", "index"), struct.unpack_from("<BBxxI", d, e + 4 + 8 * k)))
                              for k in range(cnt)]
            elif r == "strm":
                vol, pri, ply = struct.unpack_from("<BBB", d, e + 4)
                x.update(volume=vol, priority=pri, player=ply)
            entries.append(x)
        out[r] = entries
    return out, fat


# --- audio decoding: STRM / SWAR(SWAV) -> WAV -----------------------------------------------
IMA_STEP = [7, 8, 9, 10, 11, 12, 13, 14, 16, 17, 19, 21, 23, 25, 28, 31, 34, 37, 41, 45, 50, 55, 60, 66, 73,
            80, 88, 97, 107, 118, 130, 143, 157, 173, 190, 209, 230, 253, 279, 307, 337, 371, 408, 449, 494,
            544, 598, 658, 724, 796, 876, 963, 1060, 1166, 1282, 1411, 1552, 1707, 1878, 2066, 2272, 2499,
            2749, 3024, 3327, 3660, 4026, 4428, 4871, 5358, 5894, 6484, 7132, 7845, 8630, 9493, 10442, 11487,
            12635, 13899, 15289, 16818, 18500, 20350, 22385, 24623, 27086, 29794, 32767]
IMA_INDEX = [-1, -1, -1, -1, 2, 4, 6, 8]


def ima_adpcm(b):
    """DS IMA-ADPCM block: s16 initial sample, u8 step index, u8 0, then nibbles low first."""
    pred, idx = struct.unpack_from("<hB", b, 0)
    idx = min(idx, 88)
    out = []
    for byte in b[4:]:
        for nib in (byte & 0xF, byte >> 4):
            step = IMA_STEP[idx]
            diff = step >> 3
            if nib & 1:
                diff += step >> 2
            if nib & 2:
                diff += step >> 1
            if nib & 4:
                diff += step
            pred = max(-0x8000, min(0x7FFF, pred - diff if nib & 8 else pred + diff))
            idx = max(0, min(88, idx + IMA_INDEX[nib & 7]))
            out.append(pred)
    return out


def pcm(kind, b):
    """kind 0 PCM8 (signed), 1 PCM16, 2 IMA-ADPCM -> list of s16 samples."""
    if kind == 0:
        return [x << 8 for x in struct.unpack(f"<{len(b)}b", b)]
    if kind == 1:
        return list(struct.unpack(f"<{len(b) // 2}h", b[:len(b) // 2 * 2]))
    return ima_adpcm(b)


def wav_bytes(channels, rate, loop=None):
    """channels: list of equal-length s16 lists. A loop start (in samples) is written as a 'smpl' chunk."""
    n = min(len(c) for c in channels)
    frames = bytearray()
    for i in range(n):
        for c in channels:
            frames += struct.pack("<h", c[i])
    nch = len(channels)
    fmt = struct.pack("<HHIIHH", 1, nch, rate, rate * 2 * nch, 2 * nch, 16)
    chunks = b"fmt " + struct.pack("<I", len(fmt)) + fmt
    if loop is not None:
        smpl = struct.pack("<9I", 0, 0, 1000000000 // max(rate, 1), 60, 0, 0, 0, 1, 0) + \
            struct.pack("<6I", 0, 0, loop, max(n - 1, loop), 0, 0)
        chunks += b"smpl" + struct.pack("<I", len(smpl)) + smpl
    chunks += b"data" + struct.pack("<I", len(frames)) + bytes(frames)
    return b"RIFF" + struct.pack("<I", 4 + len(chunks)) + b"WAVE" + chunks


def strm_to_wav(b):
    hd = b.index(b"HEAD")
    kind, loop, nch = b[hd + 8], b[hd + 9], b[hd + 10]
    rate = struct.unpack_from("<H", b, hd + 12)[0]
    loop_start, = struct.unpack_from("<I", b, hd + 16)
    data_off, nblocks, blen, _, last_len = struct.unpack_from("<5I", b, hd + 24)
    chans = [[] for _ in range(nch)]
    pos = data_off
    for blk in range(nblocks):
        ln = last_len if blk == nblocks - 1 else blen
        for c in range(nch):
            chans[c] += pcm(kind, b[pos:pos + ln])
            pos += blen if blk < nblocks - 1 else (last_len + 3) & ~3
    return wav_bytes(chans, rate, loop_start if loop else None)


def swar_to_wavs(b):
    """[(index, wav bytes)] for every SWAV in a wave archive."""
    da = b.index(b"DATA")
    n = struct.unpack_from("<I", b, da + 0x28)[0]
    offs = struct.unpack_from(f"<{n}I", b, da + 0x2C)
    out = []
    for i, o in enumerate(offs):
        kind, loop, rate, _, loop_off, nonloop = struct.unpack_from("<BBHHHI", b, o)
        end = o + 12 + (loop_off + nonloop) * 4
        samples = pcm(kind, b[o + 12:end])
        # loop offset is in 32-bit words of data; ADPCM data starts with the 4-byte header
        ls = {0: loop_off * 4, 1: loop_off * 2, 2: (loop_off - 1) * 8}[kind] if loop else None
        out.append((i, wav_bytes([samples], rate, ls)))
    return out


def extract(d, listing, fat, out_dir, wav=False):
    named = {}
    for r in ("seq", "seqarc", "bank", "wavearc", "strm"):
        for x in listing[r]:
            if x and "file" in x:
                name = x["name"] or f"{r}_{x['index']:04d}"
                named.setdefault(x["file"], f"{r}/{name}")
    for fid, (off, size) in enumerate(fat):
        blob = d[off:off + size]
        rel = named.get(fid, f"unnamed/file_{fid:04d}")
        path = os.path.join(out_dir, rel + "." + EXT.get(blob[:4], "bin"))
        os.makedirs(os.path.dirname(path), exist_ok=True)
        open(path, "wb").write(blob)
        if wav and blob[:4] == b"STRM":
            open(path[:-5] + ".wav", "wb").write(strm_to_wav(blob))
        elif wav and blob[:4] == b"SWAR":
            os.makedirs(path[:-5], exist_ok=True)
            for i, w in swar_to_wavs(blob):
                open(os.path.join(path[:-5], f"{i:04d}.wav"), "wb").write(w)


def main():
    ap = argparse.ArgumentParser(description=__doc__.split("\n\n")[0],
                                 formatter_class=argparse.RawDescriptionHelpFormatter, epilog=__doc__)
    ap.add_argument("files", nargs="*")
    ap.add_argument("--rom")
    ap.add_argument("--out")
    ap.add_argument("--extract", action="store_true")
    ap.add_argument("--wav", action="store_true", help="with --extract: also decode streams and wave archives to .wav")
    args = ap.parse_args()
    items = [(f, open(f, "rb").read()) for f in args.files]
    if args.rom:
        sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
        from desmume_mcp.rom import Rom
        rom = Rom(args.rom)
        items += [(p, rom.file_data(f)) for f, p in sorted(rom.files.items(), key=lambda x: x[1])
                  if rom.file_data(f)[:4] == b"SDAT"]
    for path, d in items:
        listing, fat = parse(d)
        listing = {"source": path, **listing}
        if not args.out:
            print(json.dumps(listing, indent=1))
            continue
        dest = os.path.join(args.out, os.path.splitext(os.path.basename(path))[0]) if len(items) > 1 else args.out
        os.makedirs(dest, exist_ok=True)
        json.dump(listing, open(os.path.join(dest, "sdat.json"), "w"), indent=1)
        if args.extract:
            extract(d, listing, fat, dest, args.wav)
        print(f"{path}: " + ", ".join(f"{len([x for x in listing[r] if x])} {r}" for r in RECORDS)
              + f", {listing['files']} files -> {dest}")


if __name__ == "__main__":
    main()
