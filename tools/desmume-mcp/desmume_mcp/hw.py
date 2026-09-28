"""Nintendo DS hardware knowledge: I/O register names and the 3D geometry
command set, used to annotate disassembly and decode GX captures."""

import struct

# ARM9 I/O registers (ARM7-only ones are marked in the name)
IO_NAMES = {
    0x04000000: "DISPCNT", 0x04000004: "DISPSTAT", 0x04000006: "VCOUNT",
    0x04000008: "BG0CNT", 0x0400000A: "BG1CNT", 0x0400000C: "BG2CNT", 0x0400000E: "BG3CNT",
    0x04000010: "BG0HOFS", 0x04000012: "BG0VOFS", 0x04000014: "BG1HOFS", 0x04000016: "BG1VOFS",
    0x04000018: "BG2HOFS", 0x0400001A: "BG2VOFS", 0x0400001C: "BG3HOFS", 0x0400001E: "BG3VOFS",
    0x04000020: "BG2PA", 0x04000028: "BG2X", 0x0400002C: "BG2Y", 0x04000030: "BG3PA",
    0x04000038: "BG3X", 0x0400003C: "BG3Y", 0x04000040: "WIN0H", 0x04000048: "WININ",
    0x0400004A: "WINOUT", 0x0400004C: "MOSAIC", 0x04000050: "BLDCNT", 0x04000052: "BLDALPHA",
    0x04000054: "BLDY", 0x04000060: "DISP3DCNT", 0x04000064: "DISPCAPCNT", 0x04000068: "DISP_MMEM_FIFO",
    0x0400006C: "MASTER_BRIGHT",
    0x040000B0: "DMA0SAD", 0x040000B4: "DMA0DAD", 0x040000B8: "DMA0CNT",
    0x040000BC: "DMA1SAD", 0x040000C0: "DMA1DAD", 0x040000C4: "DMA1CNT",
    0x040000C8: "DMA2SAD", 0x040000CC: "DMA2DAD", 0x040000D0: "DMA2CNT",
    0x040000D4: "DMA3SAD", 0x040000D8: "DMA3DAD", 0x040000DC: "DMA3CNT",
    0x040000E0: "DMA0FILL", 0x040000E4: "DMA1FILL", 0x040000E8: "DMA2FILL", 0x040000EC: "DMA3FILL",
    0x04000100: "TM0CNT", 0x04000104: "TM1CNT", 0x04000108: "TM2CNT", 0x0400010C: "TM3CNT",
    0x04000130: "KEYINPUT", 0x04000132: "KEYCNT", 0x04000136: "EXTKEYIN(arm7)",
    0x04000180: "IPCSYNC", 0x04000184: "IPCFIFOCNT", 0x04000188: "IPCFIFOSEND",
    0x040001A0: "AUXSPICNT", 0x040001A2: "AUXSPIDATA", 0x040001A4: "ROMCTRL", 0x040001A8: "CARDCMD",
    0x04000204: "EXMEMCNT", 0x04000208: "IME", 0x04000210: "IE", 0x04000214: "IF",
    0x04000240: "VRAMCNT_A", 0x04000241: "VRAMCNT_B", 0x04000242: "VRAMCNT_C", 0x04000243: "VRAMCNT_D",
    0x04000244: "VRAMCNT_E", 0x04000245: "VRAMCNT_F", 0x04000246: "VRAMCNT_G", 0x04000247: "WRAMCNT",
    0x04000248: "VRAMCNT_H", 0x04000249: "VRAMCNT_I",
    0x04000280: "DIVCNT", 0x04000290: "DIV_NUMER", 0x04000298: "DIV_DENOM", 0x040002A0: "DIV_RESULT",
    0x040002A8: "DIVREM_RESULT", 0x040002B0: "SQRTCNT", 0x040002B4: "SQRT_RESULT", 0x040002B8: "SQRT_PARAM",
    0x04000300: "POSTFLG", 0x04000304: "POWCNT1",
    0x04000320: "RDLINES_COUNT", 0x04000330: "EDGE_COLOR", 0x04000340: "ALPHA_TEST_REF",
    0x04000350: "CLEAR_COLOR", 0x04000354: "CLEAR_DEPTH", 0x04000358: "FOG_COLOR", 0x0400035C: "FOG_OFFSET",
    0x04000360: "FOG_TABLE", 0x04000380: "TOON_TABLE",
    0x04000400: "GXFIFO", 0x04000440: "MTX_MODE", 0x04000444: "MTX_PUSH", 0x04000448: "MTX_POP",
    0x0400044C: "MTX_STORE", 0x04000450: "MTX_RESTORE", 0x04000454: "MTX_IDENTITY",
    0x04000458: "MTX_LOAD_4x4", 0x0400045C: "MTX_LOAD_4x3", 0x04000460: "MTX_MULT_4x4",
    0x04000464: "MTX_MULT_4x3", 0x04000468: "MTX_MULT_3x3", 0x0400046C: "MTX_SCALE", 0x04000470: "MTX_TRANS",
    0x04000480: "COLOR", 0x04000484: "NORMAL", 0x04000488: "TEXCOORD", 0x0400048C: "VTX_16",
    0x04000490: "VTX_10", 0x04000494: "VTX_XY", 0x04000498: "VTX_XZ", 0x0400049C: "VTX_YZ",
    0x040004A0: "VTX_DIFF", 0x040004A4: "POLYGON_ATTR", 0x040004A8: "TEXIMAGE_PARAM", 0x040004AC: "PLTT_BASE",
    0x040004C0: "DIF_AMB", 0x040004C4: "SPE_EMI", 0x040004C8: "LIGHT_VECTOR", 0x040004CC: "LIGHT_COLOR",
    0x040004D0: "SHININESS", 0x04000500: "BEGIN_VTXS", 0x04000504: "END_VTXS",
    0x04000540: "SWAP_BUFFERS", 0x04000580: "VIEWPORT", 0x040005C0: "BOX_TEST", 0x040005C4: "POS_TEST",
    0x040005C8: "VEC_TEST", 0x04000600: "GXSTAT", 0x04000604: "RAM_COUNT",
    0x04000620: "POS_RESULT", 0x04000630: "VEC_RESULT", 0x04000640: "CLIPMTX_RESULT", 0x04000680: "VECMTX_RESULT",
    0x04001000: "DISPCNT_SUB", 0x04001008: "BG0CNT_SUB",
    0x04100000: "IPCFIFORECV", 0x04100010: "CARD_DATA",
}


def io_name(addr):
    if addr in IO_NAMES:
        return IO_NAMES[addr]
    if 0x04000000 <= addr < 0x05000000:
        base = max((a for a in IO_NAMES if a <= addr and addr - a < 0x40), default=None)
        if base is not None:
            return f"{IO_NAMES[base]}+{addr - base:#x}"
        return "IO"
    return None


def region_name(addr):
    top = addr >> 24
    if addr < 0x02000000:
        return "itcm/bios"
    return {0x02: "main_ram", 0x03: "wram", 0x04: "io", 0x05: "palette", 0x06: "vram",
            0x07: "oam", 0x08: "gba_slot", 0xFF: "bios"}.get(top, "?")


# id: (name, number of parameter words)
GX_COMMANDS = {
    0x00: ("NOP", 0), 0x10: ("MTX_MODE", 1), 0x11: ("MTX_PUSH", 0), 0x12: ("MTX_POP", 1),
    0x13: ("MTX_STORE", 1), 0x14: ("MTX_RESTORE", 1), 0x15: ("MTX_IDENTITY", 0),
    0x16: ("MTX_LOAD_4x4", 16), 0x17: ("MTX_LOAD_4x3", 12), 0x18: ("MTX_MULT_4x4", 16),
    0x19: ("MTX_MULT_4x3", 12), 0x1A: ("MTX_MULT_3x3", 9), 0x1B: ("MTX_SCALE", 3), 0x1C: ("MTX_TRANS", 3),
    0x20: ("COLOR", 1), 0x21: ("NORMAL", 1), 0x22: ("TEXCOORD", 1), 0x23: ("VTX_16", 2),
    0x24: ("VTX_10", 1), 0x25: ("VTX_XY", 1), 0x26: ("VTX_XZ", 1), 0x27: ("VTX_YZ", 1),
    0x28: ("VTX_DIFF", 1), 0x29: ("POLYGON_ATTR", 1), 0x2A: ("TEXIMAGE_PARAM", 1), 0x2B: ("PLTT_BASE", 1),
    0x30: ("DIF_AMB", 1), 0x31: ("SPE_EMI", 1), 0x32: ("LIGHT_VECTOR", 1), 0x33: ("LIGHT_COLOR", 1),
    0x34: ("SHININESS", 32), 0x40: ("BEGIN_VTXS", 1), 0x41: ("END_VTXS", 0), 0x50: ("SWAP_BUFFERS", 1),
    0x60: ("VIEWPORT", 1), 0x70: ("BOX_TEST", 3), 0x71: ("POS_TEST", 2), 0x72: ("VEC_TEST", 1),
}

MTX_MODES = {0: "projection", 1: "position", 2: "position&vector", 3: "texture"}
PRIMITIVES = {0: "triangles", 1: "quads", 2: "triangle strip", 3: "quad strip"}
TEX_FORMATS = {0: "none", 1: "a3i5", 2: "4-color", 3: "16-color", 4: "256-color",
               5: "4x4 compressed", 6: "a5i3", 7: "direct"}


def _s(v, bits):
    v &= (1 << bits) - 1
    return v - (1 << bits) if v & (1 << (bits - 1)) else v


def fx(v, bits=16, frac=12):
    return _s(v, bits) / (1 << frac)


def decode_gx(cmd, params):
    """Human readable description of one geometry command."""
    name = GX_COMMANDS.get(cmd, (f"CMD_{cmd:02X}", 0))[0]
    p = params
    try:
        if cmd == 0x10:
            return f"{name} {MTX_MODES.get(p[0] & 3)}"
        if cmd in (0x12, 0x13, 0x14):
            return f"{name} {_s(p[0], 6 if cmd == 0x12 else 5)}"
        if cmd == 0x20:
            c = p[0]
            return f"{name} rgb=({c & 31},{(c >> 5) & 31},{(c >> 10) & 31})"
        if cmd == 0x21:
            n = p[0]
            return f"{name} ({fx(n, 10, 9):.3f},{fx(n >> 10, 10, 9):.3f},{fx(n >> 20, 10, 9):.3f})"
        if cmd == 0x22:
            return f"{name} s={fx(p[0], 16, 4):.2f} t={fx(p[0] >> 16, 16, 4):.2f}"
        if cmd == 0x23:
            return f"{name} ({fx(p[0]):.4f},{fx(p[0] >> 16):.4f},{fx(p[1]):.4f})"
        if cmd == 0x24:
            v = p[0]
            return f"{name} ({fx(v, 10, 6):.4f},{fx(v >> 10, 10, 6):.4f},{fx(v >> 20, 10, 6):.4f})"
        if cmd in (0x25, 0x26, 0x27):
            axes = {0x25: "xy", 0x26: "xz", 0x27: "yz"}[cmd]
            return f"{name} {axes}=({fx(p[0]):.4f},{fx(p[0] >> 16):.4f})"
        if cmd == 0x28:
            v = p[0]
            return f"{name} d=({fx(v, 10, 12):.5f},{fx(v >> 10, 10, 12):.5f},{fx(v >> 20, 10, 12):.5f})"
        if cmd in (0x1B, 0x1C):
            return f"{name} ({', '.join(f'{fx(x, 32, 12):.4f}' for x in p[:3])})"
        if cmd in (0x16, 0x17, 0x18, 0x19, 0x1A):
            return f"{name} [{', '.join(f'{fx(x, 32, 12):.3f}' for x in p)}]"
        if cmd == 0x29:
            a = p[0]
            return (f"{name} lights={a & 15:04b} mode={(a >> 4) & 3} back={(a >> 6) & 1} front={(a >> 7) & 1} "
                    f"alpha={(a >> 16) & 31} id={(a >> 24) & 63}")
        if cmd == 0x2A:
            t = p[0]
            return (f"{name} vram_offset={(t & 0xFFFF) * 8:#x} size={8 << ((t >> 20) & 7)}x{8 << ((t >> 23) & 7)} "
                    f"format={TEX_FORMATS[(t >> 26) & 7]} repeat_s={(t >> 16) & 1} repeat_t={(t >> 17) & 1} "
                    f"color0_transparent={(t >> 29) & 1}")
        if cmd == 0x2B:
            return f"{name} offset={(p[0] & 0x1FFF) * 16:#x}"
        if cmd == 0x40:
            return f"{name} {PRIMITIVES.get(p[0] & 3)}"
        if cmd == 0x50:
            return f"{name} sort={'manual' if p[0] & 1 else 'auto'} depth={'w' if p[0] & 2 else 'z'}"
        if cmd == 0x60:
            v = p[0]
            return f"{name} ({v & 255},{(v >> 8) & 255})-({(v >> 16) & 255},{(v >> 24) & 255})"
    except (IndexError, KeyError):
        pass
    if not p:
        return name
    return f"{name} " + " ".join(f"{x:08x}" for x in p)


def group_gx(records):
    """Group per-parameter FIFO entries (one hook record per parameter word)
    into whole commands: [(cmd, params, first_record)]."""
    out = []
    i = 0
    n = len(records)
    while i < n:
        rec = records[i]
        cmd = rec["cmd"]
        nparams = GX_COMMANDS.get(cmd, ("", 1))[1]
        take = max(1, nparams)
        group = [rec]
        j = i + 1
        while len(group) < take and j < n and records[j]["cmd"] == cmd:
            group.append(records[j])
            j += 1
        params = [r["param"] for r in group] if nparams else []
        out.append((cmd, params, rec))
        i = j
    return out
