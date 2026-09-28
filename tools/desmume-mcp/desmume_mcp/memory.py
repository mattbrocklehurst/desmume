"""Memory sources (live emulator, freeze dump on disk, ROM file) and the
analysis helpers that work on any of them: hexdump, disassembly, search,
cross references, stack scanning and cheat-search style value scanning.
"""

import array
import json
import os
import struct

try:
    import capstone
except ImportError:  # pragma: no cover - reported when disassembly is used
    capstone = None


def s32(v):
    return v - (1 << 32) if v & 0x80000000 else v


# ---------------------------------------------------------------------------
# memory sources


class MemorySource:
    """read(addr, length) -> bytes as the given CPU sees memory."""
    name = "?"
    cpu = "arm9"

    def read(self, addr, length):
        raise NotImplementedError

    def u32(self, addr):
        return struct.unpack("<I", self.read(addr, 4))[0]

    def u16(self, addr):
        return struct.unpack("<H", self.read(addr, 2))[0]

    def code_regions(self):
        """[(name, start, end)] of memory worth scanning for code/pointers."""
        raise NotImplementedError

    def data_regions(self):
        return self.code_regions()


class LiveSource(MemorySource):
    def __init__(self, control, cpu="arm9"):
        self.control = control
        self.cpu = cpu
        self.name = f"live:{cpu}"
        self._map = None

    def read(self, addr, length):
        out = b""
        while length > 0:
            chunk = min(length, 4 * 1024 * 1024)
            out += self.control.read_memory(addr, chunk, cpu=self.cpu)
            addr += chunk
            length -= chunk
        return out

    def memory_map(self):
        if self._map is None:
            self._map = self.control.call("memory_map")
        return self._map

    def code_regions(self):
        m = self.memory_map()
        if self.cpu == "arm7":
            return [("main_ram", 0x02000000, 0x02000000 + m["main_ram_size"]),
                    ("arm7_wram", 0x03800000, 0x03810000)]
        return [("main_ram", 0x02000000, 0x02000000 + m["main_ram_size"]),
                ("itcm", 0x01FF8000, 0x02000000)]

    def data_regions(self):
        m = self.memory_map()
        regions = [("main_ram", 0x02000000, 0x02000000 + m["main_ram_size"])]
        if self.cpu == "arm9":
            dtcm = int(m["dtcm"], 16)
            regions += [("dtcm", dtcm, dtcm + m["dtcm_size"]), ("itcm", 0x01FF8000, 0x02000000)]
        else:
            regions += [("arm7_wram", 0x03800000, 0x03810000)]
        regions.append(("shared_wram", 0x03000000, 0x03008000))
        return regions


class DumpSource(MemorySource):
    """A freeze dump written by the 'dump' control command."""

    def __init__(self, directory, cpu="arm9"):
        self.dir = directory
        self.cpu = cpu
        self.name = f"dump:{directory}:{cpu}"
        with open(os.path.join(directory, "manifest.json")) as f:
            self.manifest = json.load(f)
        self.blobs = {}
        for r in self.manifest["regions"]:
            with open(os.path.join(directory, r["file"]), "rb") as f:
                self.blobs[r["name"]] = f.read()
        self.dtcm = int(self.manifest["mmu"]["dtcm_region"], 16)
        self.main_mask = int(self.manifest["mmu"]["main_mem_mask"], 16)

    def registers(self, cpu=None):
        return self.manifest[cpu or self.cpu]

    def _byte(self, addr):
        b = self.blobs
        if self.cpu == "arm9":
            if self.dtcm <= addr < self.dtcm + 0x4000:
                return b["dtcm"][addr - self.dtcm]
            if addr < 0x02000000:
                return b["itcm"][addr & 0x7FFF]
        top = addr >> 24
        if top == 0x02:
            return b["main_ram"][addr & self.main_mask]
        if top == 0x03:
            if self.cpu == "arm7" and addr >= 0x03800000:
                return b["arm7_wram"][addr & 0xFFFF]
            return b["shared_wram"][addr & 0x7FFF]
        if top == 0x04:
            blob = b["arm9_io" if self.cpu == "arm9" else "arm7_io"]
            off = addr & 0xFFFFFF
            return blob[off] if off < len(blob) else 0
        if self.cpu == "arm9":
            if top == 0x05:
                return b["palette"][addr & 0x7FF]
            if 0x06800000 <= addr < 0x06800000 + len(b["vram"]):
                return b["vram"][addr - 0x06800000]
            if top == 0x07:
                return b["oam"][addr & 0x7FF]
        return 0

    def read(self, addr, length):
        # fast paths for the common contiguous regions
        if self.cpu == "arm9" and self.dtcm <= addr and addr + length <= self.dtcm + 0x4000:
            o = addr - self.dtcm
            return self.blobs["dtcm"][o:o + length]
        if (addr >> 24) == 0x02 and (addr & self.main_mask) + length <= self.main_mask + 1 \
                and not (self.cpu == "arm9" and addr < self.dtcm + 0x4000 and addr + length > self.dtcm):
            o = addr & self.main_mask
            return self.blobs["main_ram"][o:o + length]
        return bytes(self._byte((addr + i) & 0xFFFFFFFF) for i in range(length))

    def code_regions(self):
        regions = [("main_ram", 0x02000000, 0x02000000 + self.main_mask + 1)]
        if self.cpu == "arm9":
            regions.append(("itcm", 0x01FF8000, 0x02000000))
        else:
            regions.append(("arm7_wram", 0x03800000, 0x03810000))
        return regions

    def data_regions(self):
        regions = self.code_regions()
        if self.cpu == "arm9":
            regions.append(("dtcm", self.dtcm, self.dtcm + 0x4000))
        regions.append(("shared_wram", 0x03000000, 0x03008000))
        return regions


class RomSource(MemorySource):
    """The ARM9/ARM7 binary or one overlay from the ROM file, placed at its
    RAM load address (ARM9 binary and overlays are BLZ decompressed)."""

    def __init__(self, rom, what="arm9"):
        self.rom = rom
        self.name = f"rom:{what}"
        if what == "arm9":
            self.base, self.data, self.cpu = rom.arm9_addr, rom.arm9_binary(), "arm9"
        elif what == "arm7":
            self.base, self.data, self.cpu = rom.arm7_addr, rom.arm7_binary(), "arm7"
        elif what.startswith("overlay:") or what.startswith("overlay7:"):
            cpu = "arm7" if what.startswith("overlay7:") else "arm9"
            ov_id = int(what.split(":", 1)[1], 0)
            ov = rom.overlay(cpu, ov_id)
            self.base, self.data, self.cpu = ov.ram_addr, rom.overlay_binary(cpu, ov_id), cpu
        else:
            raise ValueError("rom source must be arm9, arm7, overlay:N or overlay7:N")

    def read(self, addr, length):
        out = bytearray(length)
        lo = max(addr, self.base)
        hi = min(addr + length, self.base + len(self.data))
        if lo < hi:
            out[lo - addr:hi - addr] = self.data[lo - self.base:hi - self.base]
        return bytes(out)

    def code_regions(self):
        return [(self.name, self.base, self.base + len(self.data))]


# ---------------------------------------------------------------------------
# formatting


def hexdump(data, base, width=16):
    lines = []
    for off in range(0, len(data), width):
        chunk = data[off:off + width]
        hexpart = " ".join(f"{b:02x}" for b in chunk)
        text = "".join(chr(b) if 32 <= b < 127 else "." for b in chunk)
        lines.append(f"{base + off:08x}  {hexpart:<{width * 3}} {text}")
    return "\n".join(lines)


def words(data, base, size=4, per_line=4):
    fmt = {1: "B", 2: "H", 4: "I"}[size]
    vals = struct.unpack(f"<{len(data) // size}{fmt}", data[:len(data) // size * size])
    lines = []
    for i in range(0, len(vals), per_line):
        row = " ".join(f"{v:0{size * 2}x}" for v in vals[i:i + per_line])
        lines.append(f"{base + i * size:08x}  {row}")
    return "\n".join(lines)


class Disassembler:
    def __init__(self):
        if capstone is None:
            raise RuntimeError("capstone is not installed: pip install capstone")
        self.arm = capstone.Cs(capstone.CS_ARCH_ARM, capstone.CS_MODE_ARM)
        self.thumb = capstone.Cs(capstone.CS_ARCH_ARM, capstone.CS_MODE_THUMB)

    def disasm(self, data, addr, thumb=False, count=0):
        """Yields (addr, size, bytes, mnemonic, op_str). Undecodable words
        are emitted as .word/.hword so that the listing never stops early."""
        md = self.thumb if thumb else self.arm
        step = 2 if thumb else 4
        off = 0
        n = 0
        while off < len(data) and (not count or n < count):
            got = False
            for insn in md.disasm(data[off:], addr + off):
                yield insn.address, insn.size, bytes(insn.bytes), insn.mnemonic, insn.op_str
                off += insn.size
                n += 1
                got = True
                if count and n >= count:
                    return
            if off < len(data):
                # capstone stopped on something it does not understand
                chunk = data[off:off + step]
                if len(chunk) < step:
                    break
                val = int.from_bytes(chunk, "little")
                yield addr + off, step, chunk, ".hword" if thumb else ".word", f"{val:#x}"
                off += step
                n += 1
            elif not got:
                break


def branch_target(op_str):
    """Absolute target of a direct branch operand like '#0x2000100'."""
    s = op_str.strip()
    if s.startswith("#"):
        try:
            return int(s[1:], 0)
        except ValueError:
            return None
    return None


# ---------------------------------------------------------------------------
# instruction pattern helpers (no capstone needed)


def arm_branch_target(word, addr):
    """(kind, target) for ARM B/BL/BLX(imm) at addr, else None."""
    if (word >> 25) & 7 != 0b101:
        return None
    off = (word & 0xFFFFFF)
    if off & 0x800000:
        off -= 0x1000000
    target = (addr + 8 + off * 4) & 0xFFFFFFFF
    if word >> 28 == 0xF:
        return "blx", (target + (((word >> 24) & 1) << 1)) | 1
    return ("bl" if word & 0x01000000 else "b"), target


def thumb_bl_target(hi, lo, addr):
    """(kind, target) for a Thumb BL/BLX pair at addr, else None."""
    if hi & 0xF800 != 0xF000 or lo & 0xE800 != 0xE800:
        return None
    off = ((hi & 0x7FF) << 12) | ((lo & 0x7FF) << 1)
    if off & 0x400000:
        off -= 0x800000
    target = (addr + 4 + off) & 0xFFFFFFFF
    if lo & 0xF800 == 0xE800:
        return "blx", target & ~3
    return "bl", target | 1


def is_call_before(src, ret_addr):
    """If ret_addr (a value from the stack or LR) is a plausible return
    address, return (call_site, target_or_None, thumb)."""
    try:
        if ret_addr & 1:  # thumb return address
            ra = ret_addr & ~1
            hi, lo = struct.unpack("<HH", src.read(ra - 4, 4))
            bl = thumb_bl_target(hi, lo, ra - 4)
            if bl:
                return ra - 4, bl[1], True
            if lo & 0xFF87 == 0x4780:  # blx rN
                return ra - 2, None, True
            return None
        if ret_addr & 3:
            return None
        w = src.u32(ret_addr - 4)
        br = arm_branch_target(w, ret_addr - 4)
        if br and br[0] in ("bl", "blx"):
            return ret_addr - 4, br[1], False
        if w & 0x0FFFFFF0 == 0x012FFF30:  # blx rN
            return ret_addr - 4, None, False
        # 'mov lr, pc' followed by 'bx rN' / 'ldr pc, ...' (pre-ARMv5 style call)
        w2 = src.u32(ret_addr - 8)
        if w2 & 0x0FFFFFFF == 0x01A0E00F:
            return ret_addr - 4, None, False
    except (struct.error, Exception):
        return None
    return None


def in_regions(addr, regions):
    return any(start <= addr < end for _, start, end in regions)


def find_function_start(src, addr, thumb=None, max_back=0x2000):
    """Heuristic: walk backwards to the nearest 'push {..., lr}' /
    'stmdb sp!, {..., lr}'. Returns the address (with bit 0 set for thumb)
    or None."""
    if thumb is None:
        thumb = bool(addr & 1)
    addr &= ~1
    start = max(addr - max_back, 0)
    data = src.read(start, addr - start + 4)
    if thumb:
        for a in range(addr & ~1, start - 1, -2):
            hw = struct.unpack_from("<H", data, a - start)[0]
            if hw & 0xFF00 == 0xB500:  # push {..., lr}
                return a | 1
    else:
        for a in range(addr & ~3, start - 1, -4):
            w = struct.unpack_from("<I", data, a - start)[0]
            if w & 0xFFFF4000 == 0xE92D4000:  # stmdb sp!, {..., lr}
                return a
    return None


# ---------------------------------------------------------------------------
# analyses


def search(src, pattern, regions, align=1, limit=200):
    """pattern: bytes, or list of int/None (None = wildcard)."""
    results = []
    if isinstance(pattern, (bytes, bytearray)):
        pat = bytes(pattern)
        wild = None
    else:
        pat = None
        wild = pattern
    for name, start, end in regions:
        data = src.read(start, end - start)
        if pat is not None:
            i = data.find(pat)
            while i >= 0:
                if (start + i) % align == 0:
                    results.append((name, start + i))
                    if len(results) >= limit:
                        return results
                i = data.find(pat, i + 1)
        else:
            n = len(wild)
            first = next((j for j, b in enumerate(wild) if b is not None), None)
            for i in range(0, len(data) - n + 1, align):
                if first is not None and data[i + first] != wild[first]:
                    continue
                if all(b is None or data[i + j] == b for j, b in enumerate(wild)):
                    results.append((name, start + i))
                    if len(results) >= limit:
                        return results
    return results


def xrefs(src, target, regions, size=1, limit=200):
    """Find direct calls/branches to target and 32-bit words pointing into
    [target, target+size). Returns [(kind, addr, detail)]."""
    target_even = target & ~1
    out = []
    for name, start, end in regions:
        data = src.read(start, end - start)
        n = len(data)
        # ARM branches and literal pointers
        for off in range(0, n - 3, 4):
            w = struct.unpack_from("<I", data, off)[0]
            a = start + off
            br = arm_branch_target(w, a)
            if br and (br[1] & ~1) == target_even:
                out.append((f"arm {br[0]}", a, f"{br[0]} {target:#010x}"))
            elif target_even <= (w & ~1) < target_even + max(size, 1) and w != 0:
                out.append(("pointer", a, f".word {w:#010x}"))
            if len(out) >= limit:
                return out
        # Thumb BL/BLX pairs
        for off in range(0, n - 3, 2):
            hi, lo = struct.unpack_from("<HH", data, off)
            bl = thumb_bl_target(hi, lo, start + off)
            if bl and (bl[1] & ~1) == target_even:
                out.append((f"thumb {bl[0]}", start + off, f"{bl[0]} {target:#010x}"))
                if len(out) >= limit:
                    return out
    return out


def stack_scan(src, sp, depth, regions):
    """Walk the stack looking for return addresses. Returns
    [(stack_addr, value, call_site, call_target, thumb)]."""
    data = src.read(sp, depth * 4)
    frames = []
    for i in range(len(data) // 4):
        v = struct.unpack_from("<I", data, i * 4)[0]
        if not in_regions(v & ~1, regions):
            continue
        call = is_call_before(src, v)
        if call:
            frames.append((sp + i * 4, v, call[0], call[1], call[2]))
    return frames


class ValueScan:
    """Cheat-engine style narrowing search over RAM for a value of 1, 2 or 4
    bytes (little endian). Candidates are kept per region as index arrays so
    that an unknown-value first scan over all of main RAM stays cheap."""

    FMT = {1: "B", 2: "H", 4: "I"}

    def __init__(self, src, regions, size=4, signed=False):
        if size not in self.FMT:
            raise ValueError("size must be 1, 2 or 4")
        self.src = src
        self.size = size
        self.signed = signed
        self.regions = regions
        self.cands = None  # {region_start: (array of indices, list of last values)}
        self.history = []

    def _snapshot(self):
        fmt = self.FMT[self.size].lower() if self.signed else self.FMT[self.size]
        snap = {}
        for _, start, end in self.regions:
            data = self.src.read(start, end - start)
            count = len(data) // self.size
            snap[start] = struct.unpack(f"<{count}{fmt}", data[:count * self.size])
        return snap

    def count(self):
        return sum(len(idx) for idx, _ in self.cands.values()) if self.cands else 0

    def results(self, limit=100):
        out = []
        for start in sorted(self.cands):
            idx, vals = self.cands[start]
            for i, v in zip(idx, vals):
                out.append((start + i * self.size, v))
                if len(out) >= limit:
                    return out
        return out

    def start(self, value=None):
        snap = self._snapshot()
        self.cands = {}
        for start, vals in snap.items():
            if value is None:
                self.cands[start] = (array.array("I", range(len(vals))), list(vals))
            else:
                idx = array.array("I", (i for i, v in enumerate(vals) if v == value))
                self.cands[start] = (idx, [value] * len(idx))
        self.history = [f"start value={value}"]
        return self.count()

    def next(self, condition, value=None):
        if self.cands is None:
            raise RuntimeError("no scan in progress, start one first")
        tests = {
            "eq": lambda old, new: new == value,
            "ne": lambda old, new: new != value,
            "gt": lambda old, new: new > value,
            "lt": lambda old, new: new < value,
            "changed": lambda old, new: new != old,
            "unchanged": lambda old, new: new == old,
            "increased": lambda old, new: new > old,
            "decreased": lambda old, new: new < old,
            "increased_by": lambda old, new: new - old == value,
            "decreased_by": lambda old, new: old - new == value,
        }
        if condition not in tests:
            raise ValueError(f"condition must be one of {', '.join(tests)}")
        if condition in ("eq", "ne", "gt", "lt", "increased_by", "decreased_by") and value is None:
            raise ValueError(f"condition {condition} needs a value")
        test = tests[condition]
        snap = self._snapshot()
        for start, (idx, olds) in list(self.cands.items()):
            new = snap[start]
            keep_idx = array.array("I")
            keep_vals = []
            for i, old in zip(idx, olds):
                v = new[i]
                if test(old, v):
                    keep_idx.append(i)
                    keep_vals.append(v)
            self.cands[start] = (keep_idx, keep_vals)
        self.history.append(f"{condition} {value if value is not None else ''}".strip())
        return self.count()
