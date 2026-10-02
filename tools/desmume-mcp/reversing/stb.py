#!/usr/bin/env python3
"""JStudio STB cutscene files (Nintendo JSystem "STB\\0", as used by Zelda PH / ST) -> JSON, losslessly.

Phantom Hourglass and Spirit Tracks keep their cutscenes in Event/*.bin archives, each holding
stb/*.stb.  The format is Nintendo's JStudio (same as Twilight Princess), little-endian on DS,
with every "float" stored as fx32 (20.12 fixed point).  Layout:

  header (0x20)   char[4] "STB\\0" | u16 byte_order 0xFEFF | u16 version (1..3, all files 3)
                  | u32 file_size | u32 block_count | char[8] "jstudio" | u16[3] (0) | u16 target_version (6)
  block           u32 size (incl. header) | u32 type (FourCC as a LE u32: 'JFVB' is stored "BVFJ")
     'JFVB'       body is an FVB file (function values = animation curves), see below
     'JCTB'       ignored by the DS games (not present in the samples)
     object       'JACT' actor, 'JCMR' camera, 'JPTC' particle, 'JSND' sound, 'JMSG' message,
                  0xFFFFFFFF control object (TObject_control; ST: id "ENV..." is a separate object)
                  u16 flag | u16 id_size | char id[id_size] (NUL incl.) padded to 4 | sequence stream
  sequence word   u32 = type<<24 | param(24)
                  0 end | 1 flag op (param>>16 = op 1 or/2 and/3 xor, low 16 = value)
                  2 wait param frames | 3 jump by signed param bytes from this word | 4 suspend += s24
                  0x80 paragraphs: param = byte length of the paragraph list that follows
  paragraph       u16 a; a&0x8000==0: size=a, type=u16 (4-byte head)
                         else size=((a&0x7fff)<<16)|u16, type=u32 at +4 (8-byte head)
                  content[size] padded to 4.  type<=0xff reserved: 1 flag(u32) 2 wait(u32)
                  3 jump(s32) 0x80 data 0x81 data-with-ID 0x82 nop.  type>0xff: command =
                  type>>5, operation = type&0x1f (1 void, 2 immediate, 3 time-rate, 0x10 FV by
                  name, 0x12 FV by index, 0x18 by name/string, 0x19 by number)
  0x81 content    u16 0 | u16 id_size | id[id_size] padded to 4 | data item
  data item       u8 status (bits0-2: element size code -> 0,1,2,4,8,16,32,64 bytes; bit3: a u8
                  element count follows (else 1); bits4-7: kind, 0x60 = string) | elements

FVB (inside 'JFVB'): char[4] "FVB\\0" | u16 0xFEFF | u16 version 0x100 | u32 size | u32 count, then
count blocks: u32 size | u16 type | u16 id_size | id padded | paragraphs (same var-uint head) up to
the block end, paragraph type 0 terminates.  Types: 1 composite, 2 constant, 3 transition, 4 list,
5 list_parameter, 6 hermite (the DS factories only build 2, 5 and 6).  Paragraph 1 = data (by
type), 0x10 refer-by-name, 0x11 refer-by-index, 0x12 range(begin,end), 0x13 progress,
0x14 adjust, 0x15 outside(u16 begin, u16 end), 0x16 interpolate.  Curve time is in seconds
(frames/30), see cutscene-stb.md.

Nothing game-specific is interpreted beyond command names (TP JStudio names); fx32 values are
written as raw/4096 floats (exact, so the bytes round-trip), unknown content as hex.

usage:
  stb.py FILE.stb [...] --out DIR        one .json per input
  stb.py --rom game.nds --out DIR        every .stb in a ROM
  stb.py FILE.stb [...] --stats          only print the decode coverage
"""

import argparse
import json
import os
import struct
import sys

FX = 4096.0

# --- command tables (command id = paragraph type >> 5), names from TP JStudio jstudio-object.cpp ---
_SRT = {9: "TRANSLATION_X", 10: "TRANSLATION_Y", 11: "TRANSLATION_Z", 12: "TRANSLATION_XYZ",
        13: "ROTATION_X", 14: "ROTATION_Y", 15: "ROTATION_Z", 16: "ROTATION_XYZ",
        17: "SCALING_X", 18: "SCALING_Y", 19: "SCALING_Z", 20: "SCALING_XYZ"}
_POS = {21: "POSITION_X", 22: "POSITION_Y", 23: "POSITION_Z", 24: "POSITION_XYZ"}
_TGT = {25: "TARGET_POSITION_X", 26: "TARGET_POSITION_Y", 27: "TARGET_POSITION_Z", 28: "TARGET_POSITION_XYZ"}
_COL = {29: "COLOR_R", 30: "COLOR_G", 31: "COLOR_B", 32: "COLOR_A", 33: "COLOR_RGB", 34: "COLOR_RGBA"}
_PAR = {48: "PARENT", 49: "PARENT_NODE", 50: "PARENT_ENABLE", 81: "PARENT_FUNCTION"}
_FADE = {46: "BEGIN_FADE_IN", 47: "END_FADE_OUT", 79: "BEGIN", 80: "END", 85: "ON_EXIT_NOT_END", 86: "REPEAT"}

COMMANDS = {
    "JACT": {**_SRT, **_PAR, 51: "RELATION", 52: "RELATION_NODE", 53: "RELATION_ENABLE", 57: "SHAPE",
             58: "ANIMATION", 59: "ANIMATION_FRAME", 67: "ANIMATION_MODE", 75: "ANIMATION_TRANSITION",
             76: "TEXTURE_ANIMATION", 77: "TEXTURE_ANIMATION_FRAME", 78: "TEXTURE_ANIMATION_MODE"},
    "JCMR": {**_POS, **_TGT, **_PAR, 38: "VIEW_ROLL", 39: "PROJECTION_FOVY", 40: "PROJECTION_NEAR",
             41: "PROJECTION_FAR", 42: "DISTANCE_NEAR_FAR", 82: "TARGET_PARENT", 83: "TARGET_PARENT_NODE",
             84: "TARGET_PARENT_ENABLE"},
    "JPTC": {**_SRT, **_COL, **_PAR, **_FADE, 68: "PARTICLE", 69: "COLOR1_R", 70: "COLOR1_G", 71: "COLOR1_B",
             72: "COLOR1_A", 73: "COLOR1_RGB", 74: "COLOR1_RGBA"},
    "JSND": {**_POS, **_PAR, **_FADE, 56: "LOCATED", 60: "SOUND", 61: "VOLUME", 62: "PAN", 63: "PITCH",
             64: "TEMPO", 65: "ECHO", 87: "CONTINUOUS"},
    "JMSG": {66: "MESSAGE"},
    "JLIT": {**_COL, **_POS, **_TGT, 35: "DIRECTION_THETA", 36: "DIRECTION_PHI", 37: "DIRECTION_THETA_PHI",
             54: "ENABLE", 55: "FACULTY"},
    "JFOG": {**_COL, 43: "RANGE_BEGIN", 44: "RANGE_END", 45: "RANGE_BEGIN_END"},
    "JABL": dict(_COL),
    "CTRL": {},
}
# commands whose DS handler reads an IMMEDIATE (op 2) as a plain integer, not fx32 (ov040 handlers)
INT_IMMEDIATE = {"PARENT_ENABLE", "TARGET_PARENT_ENABLE", "RELATION_ENABLE", "REPEAT", "CONTINUOUS",
                 "LOCATED", "ON_EXIT_NOT_END", "ANIMATION_MODE", "TEXTURE_ANIMATION_MODE", "ENABLE"}
OPS = {1: "void", 2: "immediate", 3: "time", 0x10: "fv_name", 0x11: "fv_name_11", 0x12: "fv_index",
       0x18: "name", 0x19: "number"}
SEQ = {0: "end", 1: "flag", 2: "wait", 3: "jump", 4: "suspend", 0x80: "paragraphs"}
RESERVED = {1: "flag", 2: "wait", 3: "jump", 0x80: "data", 0x81: "data_id", 0x82: "nop"}
FVB_TYPES = {1: "composite", 2: "constant", 3: "transition", 4: "list", 5: "list_parameter", 6: "hermite"}
COMPOSITE = {0: "none", 1: "raw", 2: "index", 3: "parameter", 4: "add", 5: "sub", 6: "mul", 7: "div"}
FVB_PARA = {0: "end", 1: "data", 0x10: "refer_name", 0x11: "refer_index", 0x12: "range", 0x13: "progress",
            0x14: "adjust", 0x15: "outside", 0x16: "interpolate"}
DATA_SIZES = [0, 1, 2, 4, 8, 16, 32, 64]


def fourcc(v):
    return "CTRL" if v == 0xFFFFFFFF else struct.pack(">I", v).decode("latin-1")


def fx(raw):
    return raw / FX


def cstr(b):
    s = b.split(b"\0")[0]
    return s.decode("latin-1")


def id_field(b):
    """id string plus hex when the bytes are not 'string, NUL, zero padding'."""
    s = cstr(b)
    out = {"id": s}
    rest = b[len(s.encode("latin-1")):]
    if rest.strip(b"\0") or (b and b"\0" not in b):
        out["id_hex"] = b.hex()
    return out


def var_head(d, p):
    """parseVariableUInt_16_32_following (ov000 0x020a0004 PH): returns size, type, head length."""
    a, b = struct.unpack_from("<HH", d, p)
    if not a & 0x8000:
        return a, b, 4
    return ((a & 0x7FFF) << 16) | b, struct.unpack_from("<I", d, p + 4)[0], 8


def pad4(n):
    return (n + 3) & ~3


class Stats:
    def __init__(self):
        self.para = 0
        self.decoded = 0
        self.hex = 0
        self.unknown = {}

    def miss(self, key):
        self.hex += 1
        self.unknown[key] = self.unknown.get(key, 0) + 1


# --- data items (TParse_TParagraph_data) ---------------------------------------------------------

def data_item(b):
    if not b:
        return None
    st = b[0]
    out = {"status": f"{st:#04x}"}
    if st == 0:
        if b[1:].strip(b"\0"):
            out["rest_hex"] = b[1:].hex()
        return out
    p, n = 1, 1
    if st & 8:
        n = b[1]
        p = 2
    size = DATA_SIZES[st & 7]
    kind = st & 0xF0
    out["kind"] = f"{kind:#04x}"
    body = b[p:p + size * n]
    if kind == 0x60 or size == 0:
        out["string"] = cstr(b[p:])
        end = p + len(out["string"]) + 1
    else:
        vals = []
        for i in range(n):
            e = body[i * size:(i + 1) * size]
            vals.append(int.from_bytes(e, "little") if size <= 8 else e.hex())
        out["values"] = vals
        out["size"] = size
        if kind == 0x40 and size == 4:     # real number: fx32 on DS (camera data, e.g. 819 = 0.2)
            out["fx"] = [fx(struct.unpack("<i", body[i * 4:i * 4 + 4])[0]) for i in range(n)]
        end = p + size * n
    if b[end:].strip(b"\0"):
        out["rest_hex"] = b[end:].hex()
    return out


# --- STB paragraphs -------------------------------------------------------------------------------

def decode_command(kind, ptype, c, st):
    cmd, op = ptype >> 5, ptype & 0x1F
    table = COMMANDS.get(kind, {})
    name = table.get(cmd)
    out = {"cmd": cmd, "name": name or f"cmd_{cmd}", "op": OPS.get(op, f"op_{op:#x}")}
    ok = name is not None and op in OPS
    if op == 1:
        if c:
            out["hex"] = c.hex()
    elif op in (2, 3) and len(c) % 4 == 0:
        raw = struct.unpack_from(f"<{len(c) // 4}i", c)
        if name in INT_IMMEDIATE and op == 2:
            out["int"] = list(raw)
        else:
            out["fx"] = [fx(v) for v in raw]
    elif op == 0x12 and len(c) % 4 == 0:
        out["fv_index"] = list(struct.unpack_from(f"<{len(c) // 4}I", c))
    elif op in (0x10, 0x18):
        out["string"] = cstr(c)
        if c[len(out["string"]) + 1:].strip(b"\0"):
            out["hex"] = c.hex()
    elif op == 0x19 and len(c) % 4 == 0:
        out["u32"] = [f"{v:#010x}" for v in struct.unpack_from(f"<{len(c) // 4}I", c)]
    else:
        out["hex"] = c.hex()
        ok = False
    if ok:
        st.decoded += 1
    else:
        st.miss(f"{kind}:{cmd}:{op:#x}")
    return out


def decode_paragraphs(kind, d, p, end, st):
    out = []
    while p < end:
        size, ptype, hl = var_head(d, p)
        c = d[p + hl:p + hl + size]
        nxt = p + hl + pad4(size)
        st.para += 1
        e = {"type": f"{ptype:#x}", "size": size}
        if ptype <= 0xFF:
            e["reserved"] = RESERVED.get(ptype, f"reserved_{ptype:#x}")
            if ptype in (1, 2) and size == 4:
                e["value"] = struct.unpack("<I", c)[0]
                st.decoded += 1
            elif ptype == 3 and size == 4:
                e["value"] = struct.unpack("<i", c)[0]
                st.decoded += 1
            elif ptype == 0x80:
                e["data"] = data_item(c)
                st.decoded += 1
            elif ptype == 0x81 and size >= 4:
                z, idn = struct.unpack_from("<HH", c)
                idb = c[4:4 + idn]
                body = c[4 + pad4(idn):]
                if idn == 4:
                    e["data_id"] = struct.unpack("<I", idb)[0]
                else:
                    e.update(id_field(idb))
                if z:
                    e["head0"] = z
                e["data"] = data_item(body)
                st.decoded += 1
            elif ptype == 0x82:
                st.decoded += 1
                if c:
                    e["hex"] = c.hex()
            else:
                e["hex"] = c.hex()
                st.miss(f"reserved:{ptype:#x}")
        else:
            e.update(decode_command(kind, ptype, c, st))
        padb = d[p + hl + size:nxt]
        if padb.strip(b"\0"):
            e["pad_hex"] = padb.hex()
        out.append(e)
        p = nxt
    return out, p


def decode_sequence(kind, d, p, end, st):
    seq = []
    while p + 4 <= end:
        head = struct.unpack_from("<I", d, p)[0]
        t, param = head >> 24, head & 0xFFFFFF
        e = {"at": p, "seq": SEQ.get(t, f"seq_{t:#x}")}
        p += 4
        if t == 0:
            if param:
                e["param"] = param
            seq.append(e)
            break
        if t <= 0x7F:
            if t == 1:
                e.update(op=param >> 16, value=param & 0xFFFF)
            elif t in (3, 4):
                e["value"] = param - 0x1000000 if param & 0x800000 else param
            else:
                e["value"] = param
            if t > 4:
                st.miss(f"seq:{t:#x}")
        else:
            e["length"] = param
            if t == 0x80:
                e["paragraphs"], q = decode_paragraphs(kind, d, p, p + param, st)
            else:
                e["hex"] = d[p:p + param].hex()
                st.miss(f"seq:{t:#x}")
            p += param
        seq.append(e)
    return seq, p


# --- FVB ------------------------------------------------------------------------------------------

def fvb_data(otype, c):
    n4 = len(c) // 4
    w = struct.unpack_from(f"<{n4}I", c) if n4 else ()
    s = struct.unpack_from(f"<{n4}i", c) if n4 else ()
    if otype == 2 and n4 >= 1:
        return {"value": fx(s[0])}, 4
    if otype == 3 and n4 >= 2:
        return {"values": [fx(s[0]), fx(s[1])]}, 8
    if otype == 1 and n4 >= 2:
        return {"composite": COMPOSITE.get(w[0], w[0]), "data": f"{w[1]:#010x}", "data_fx": fx(s[1])}, 8
    if otype == 4 and n4 >= 2:
        cnt = w[1]
        return {"interval": fx(s[0]), "count": cnt, "values": [fx(v) for v in s[2:2 + cnt]]}, 8 + 4 * cnt
    if otype == 5 and n4 >= 1:
        cnt = w[0]
        keys = [[fx(s[1 + 2 * i]), fx(s[2 + 2 * i])] for i in range(cnt)]
        return {"count": cnt, "keys": keys}, 4 + 8 * cnt
    if otype == 6 and n4 >= 1:
        cnt, stride = w[0] & 0xFFFFFFF, w[0] >> 28
        keys = [[fx(v) for v in s[1 + stride * i:1 + stride * (i + 1)]] for i in range(cnt)]
        return {"count": cnt, "stride": stride, "keys": keys}, 4 + 4 * stride * cnt
    return None, 0


def parse_fvb(d, st):
    sig, bom, ver, size, cnt = struct.unpack_from("<4sHHII", d, 0)
    out = {"signature": sig.decode("latin-1"), "byte_order": f"{bom:#06x}", "version": f"{ver:#x}",
           "size": size, "count": cnt, "objects": []}
    p = 0x10
    for i in range(cnt):
        bsz, otype, idn = struct.unpack_from("<IHH", d, p)
        o = {"index": i, "offset": p, "size": bsz, "type": otype, "type_name": FVB_TYPES.get(otype, "unknown")}
        o.update(id_field(d[p + 8:p + 8 + idn]) if idn else {})
        q, end = p + 8 + pad4(idn), p + bsz
        paras = []
        while q < end:
            size, ptype, hl = var_head(d, q)
            c = d[q + hl:q + hl + size]
            st.para += 1
            e = {"type": FVB_PARA.get(ptype, f"{ptype:#x}")}
            if ptype == 0:
                paras.append(e)
                st.decoded += 1
                q += hl
                break
            dec, used = None, 0
            if ptype == 1:
                dec, used = fvb_data(otype, c)
            elif ptype == 0x12 and size == 8:
                dec, used = {"begin": fx(struct.unpack_from("<i", c)[0]), "end": fx(struct.unpack_from("<i", c, 4)[0])}, 8
            elif ptype in (0x13, 0x14, 0x16) and size == 4:
                dec, used = {"value": struct.unpack("<I", c)[0]}, 4
            elif ptype == 0x15 and size == 4:
                dec, used = {"begin": struct.unpack_from("<H", c)[0], "end": struct.unpack_from("<H", c, 2)[0]}, 4
            elif ptype == 0x11 and size >= 4:
                n = struct.unpack_from("<I", c)[0]
                dec, used = {"indices": list(struct.unpack_from(f"<{n}I", c, 4))}, 4 + 4 * n
            elif ptype == 0x10 and size >= 4:
                n = struct.unpack_from("<I", c)[0]
                names, k = [], 4
                for _ in range(n):
                    ln = struct.unpack_from("<I", c, k)[0]
                    names.append(cstr(c[k + 4:k + 4 + ln]))
                    k += 4 + pad4(ln)
                dec, used = {"names": names}, k
            if dec is None:
                e["hex"] = c.hex()
                st.miss(f"fvb:{otype}:{ptype:#x}")
            else:
                e.update(dec)
                st.decoded += 1
                if c[used:].strip(b"\0"):
                    e["rest_hex"] = c[used:].hex()
            paras.append(e)
            q += hl + pad4(size)
        if q < end:
            o["trailing_hex"] = d[q:end].hex()
        o["paragraphs"] = paras
        out["objects"].append(o)
        p = end
    if p < len(d) and d[p:].strip(b"\0"):
        out["trailing_hex"] = d[p:].hex()
    return out


# --- STB ------------------------------------------------------------------------------------------

def parse(d, stats=None):
    st = stats or Stats()
    if d[:4] != b"STB\0":
        raise ValueError("not an STB file")
    bom, ver, size, nblk = struct.unpack_from("<HHII", d, 4)
    tgt = d[0x10:0x20]
    out = {"header": {"signature": "STB", "byte_order": f"{bom:#06x}", "version": ver, "file_size": size,
                      "file_size_ok": size == len(d), "block_count": nblk,
                      "target": cstr(tgt[:8]), "target_u16": list(struct.unpack_from("<3H", tgt, 8)),
                      "target_version": struct.unpack_from("<H", tgt, 14)[0]},
           "blocks": []}
    p = 0x20
    for _ in range(nblk):
        bsz, btype = struct.unpack_from("<II", d, p)
        kind = fourcc(btype)
        b = {"offset": p, "size": bsz, "type": kind}
        end = p + bsz
        if kind == "JFVB":
            b["fvb"] = parse_fvb(d[p + 8:end], st)
        elif kind == "JCTB" or btype == 0:
            b["hex"] = d[p + 8:end].hex()
        else:
            flag, idn = struct.unpack_from("<HH", d, p + 8)
            b["flag"] = flag
            b.update(id_field(d[p + 12:p + 12 + idn]))
            b["sequence"], q = decode_sequence(kind, d, p + 12 + pad4(idn), end, st)
            if d[q:end].strip(b"\0"):
                b["trailing_hex"] = d[q:end].hex()
        out["blocks"].append(b)
        p = end
    if p < len(d):
        out["trailing_hex"] = d[p:].hex()
    return out


def main():
    ap = argparse.ArgumentParser(description=__doc__.split("\n\n")[0],
                                 formatter_class=argparse.RawDescriptionHelpFormatter, epilog=__doc__)
    ap.add_argument("files", nargs="*")
    ap.add_argument("--rom", help="take every .stb out of this ROM (through NARC archives and LZ77)")
    ap.add_argument("--out")
    ap.add_argument("--stats", action="store_true")
    args = ap.parse_args()
    if not args.out and not args.stats:
        ap.error("give --out DIR or --stats")
    items = [(f, open(f, "rb").read()) for f in args.files]
    if args.rom:
        from zchunk import rom_items
        items += [(p, d) for p, d, _ in rom_items(args.rom, "") if p.lower().endswith(".stb")]
    total = Stats()
    for path, data in items:
        st = Stats()
        m = parse(data, st)
        total.para += st.para
        total.decoded += st.decoded
        total.hex += st.hex
        for k, v in st.unknown.items():
            total.unknown[k] = total.unknown.get(k, 0) + v
        if args.out:
            os.makedirs(args.out, exist_ok=True)
            base = os.path.join(args.out, os.path.splitext(os.path.basename(path))[0])
            json.dump(m, open(base + ".json", "w", encoding="utf-8"), ensure_ascii=False, indent=1)
        kinds = {}
        for b in m["blocks"]:
            kinds[b["type"]] = kinds.get(b["type"], 0) + 1
        print(f"{os.path.basename(path)}: {len(m['blocks'])} blocks {kinds}, {st.para} paragraphs, "
              f"{st.hex} as hex")
    print(f"{len(items)} files: {total.para} paragraphs, {total.decoded} decoded, {total.hex} left as hex")
    for k, v in sorted(total.unknown.items(), key=lambda x: -x[1]):
        print(f"  undecoded {k}: {v}")


if __name__ == "__main__":
    sys.exit(main())
