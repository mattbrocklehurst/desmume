"""Offline parsing of .nds ROM images: header, ARM9/ARM7 binaries, overlay
tables, and the file system (FNT/FAT). Handles BLZ ("backwards LZ")
compression, which most retail games use for the ARM9 binary and overlays.
"""

import struct


def blz_decompress(data):
    """Decompress a BLZ buffer as produced by the Nintendo SDK. Returns the
    input unchanged if it is not compressed."""
    data = bytes(data)
    if len(data) < 8:
        return data
    extra = struct.unpack_from("<I", data, len(data) - 4)[0]
    if extra == 0:
        return data
    header_len = data[-5]
    comp_len = int.from_bytes(data[-8:-5], "little")
    if header_len < 8 or comp_len < header_len or comp_len > len(data):
        raise ValueError("not a valid BLZ compressed buffer")
    comp_start = len(data) - comp_len
    out = bytearray(len(data) + extra)
    out[:len(data)] = data
    in_pos = len(data) - header_len
    out_pos = len(out)
    while in_pos > comp_start and out_pos > comp_start:
        in_pos -= 1
        control = data[in_pos]
        for _ in range(8):
            if in_pos <= comp_start or out_pos <= comp_start:
                break
            if control & 0x80:
                in_pos -= 2
                info = data[in_pos] | (data[in_pos + 1] << 8)
                disp = (info & 0xFFF) + 3
                for _ in range((info >> 12) + 3):
                    out_pos -= 1
                    out[out_pos] = out[out_pos + disp]
            else:
                in_pos -= 1
                out_pos -= 1
                out[out_pos] = data[in_pos]
            control = (control << 1) & 0xFF
    return bytes(out)


def blz_compress(data):
    """Simple greedy BLZ compressor (used to build test ROMs). The whole
    buffer is compressed; returns data unchanged if it does not shrink."""
    data = bytes(data)
    n = len(data)
    stream = []  # bytes in reading order (highest address first)
    pos = n
    while pos > 0:
        ctrl_index = len(stream)
        stream.append(0)
        ctrl = 0
        for bit in range(8):
            if pos <= 0:
                break
            best_len, best_disp = 0, 0
            for disp in range(3, min(0x1002, n - pos) + 1):
                length = 0
                while (length < 18 and pos - 1 - length >= 0 and
                       data[pos - 1 - length] == data[pos - 1 - length + disp]):
                    length += 1
                if length > best_len:
                    best_len, best_disp = length, disp
                    if length == 18:
                        break
            if best_len >= 3:
                info = ((best_len - 3) << 12) | (best_disp - 3)
                stream += [info >> 8, info & 0xFF]
                ctrl |= 0x80 >> bit
                pos -= best_len
            else:
                stream.append(data[pos - 1])
                pos -= 1
        stream[ctrl_index] = ctrl
    body = bytes(reversed(stream))
    pad = (-len(body)) % 4
    header_len = 8 + pad
    total = len(body) + header_len
    extra = n - total
    if extra <= 0:
        return data
    return (body + b"\xff" * pad + (total | (header_len << 24)).to_bytes(4, "little")
            + extra.to_bytes(4, "little"))


class Overlay:
    def __init__(self, cpu, entry):
        (self.id, self.ram_addr, self.ram_size, self.bss_size,
         self.sinit_start, self.sinit_end, self.file_id, flags) = entry
        self.cpu = cpu
        self.compressed = bool(flags & 0x01000000)
        self.compressed_size = flags & 0xFFFFFF

    def to_dict(self):
        return {
            "cpu": self.cpu, "id": self.id, "ram_addr": f"{self.ram_addr:#010x}",
            "ram_end": f"{self.ram_addr + self.ram_size:#010x}",
            "ram_size": self.ram_size, "bss_size": self.bss_size, "file_id": self.file_id,
            "compressed": self.compressed,
            "static_init": f"{self.sinit_start:#010x}-{self.sinit_end:#010x}",
        }


class Rom:
    def __init__(self, path):
        self.path = path
        with open(path, "rb") as f:
            self.data = f.read()
        d = self.data
        if len(d) < 0x200:
            raise ValueError("file too small to be an NDS ROM")
        self.title = d[0:12].split(b"\0")[0].decode("ascii", "replace")
        self.game_code = d[12:16].decode("ascii", "replace")
        self.maker_code = d[16:18].decode("ascii", "replace")
        self.version = d[0x1E]
        (self.arm9_off, self.arm9_entry, self.arm9_addr, self.arm9_size,
         self.arm7_off, self.arm7_entry, self.arm7_addr, self.arm7_size,
         self.fnt_off, self.fnt_size, self.fat_off, self.fat_size,
         self.ovt9_off, self.ovt9_size, self.ovt7_off, self.ovt7_size) = struct.unpack_from("<16I", d, 0x20)
        self.overlays = (self._overlay_table("arm9", self.ovt9_off, self.ovt9_size) +
                         self._overlay_table("arm7", self.ovt7_off, self.ovt7_size))
        self.files = self._file_names()

    # tables -----------------------------------------------------------------

    def _overlay_table(self, cpu, off, size):
        out = []
        for i in range(size // 32):
            out.append(Overlay(cpu, struct.unpack_from("<8I", self.data, off + i * 32)))
        return out

    def file_extent(self, file_id):
        start, end = struct.unpack_from("<II", self.data, self.fat_off + file_id * 8)
        return start, end

    def file_data(self, file_id):
        start, end = self.file_extent(file_id)
        return self.data[start:end]

    def _file_names(self):
        """Returns {file_id: path} from the FNT."""
        names = {}
        if not self.fnt_size or self.fnt_off + 8 > len(self.data):
            return names
        d = self.data
        base = self.fnt_off
        ndirs = struct.unpack_from("<H", d, base + 6)[0]
        if ndirs == 0 or ndirs > 4096:
            return names

        def walk(dir_id, prefix, depth=0):
            if depth > 32:
                return
            entry = base + (dir_id & 0xFFF) * 8
            sub_off, first_id = struct.unpack_from("<IH", d, entry)
            pos = base + sub_off
            file_id = first_id
            while pos < len(d):
                length = d[pos]
                pos += 1
                if length == 0:
                    break
                name = d[pos:pos + (length & 0x7F)].decode("latin-1")
                pos += length & 0x7F
                if length & 0x80:
                    sub_id = struct.unpack_from("<H", d, pos)[0]
                    pos += 2
                    walk(sub_id, prefix + name + "/", depth + 1)
                else:
                    names[file_id] = prefix + name
                    file_id += 1

        walk(0xF000, "")
        return names

    # binaries ---------------------------------------------------------------

    def arm9_binary(self, decompress=True):
        """The ARM9 static binary as it looks in RAM after the game's own
        start-up code has decompressed it."""
        raw = self.data[self.arm9_off:self.arm9_off + self.arm9_size]
        if not decompress:
            return raw
        # the SDK's module parameters are tagged with the "nitrocode" magic
        idx = raw.find(b"\x21\x06\xc0\xde\xde\xc0\x06\x21")
        if idx >= 0x1C:
            params = struct.unpack_from("<7I", raw, idx - 0x1C)
            comp_end = params[5]
            if comp_end and self.arm9_addr < comp_end <= self.arm9_addr + len(raw):
                split = comp_end - self.arm9_addr
                return blz_decompress(raw[:split]) + raw[split:]
        return raw

    def arm7_binary(self):
        return self.data[self.arm7_off:self.arm7_off + self.arm7_size]

    def overlay(self, cpu, overlay_id):
        for ov in self.overlays:
            if ov.cpu == cpu and ov.id == overlay_id:
                return ov
        raise KeyError(f"no {cpu} overlay {overlay_id}")

    def overlay_binary(self, cpu, overlay_id):
        ov = self.overlay(cpu, overlay_id)
        data = self.file_data(ov.file_id)
        if ov.compressed:
            data = blz_decompress(data[:ov.compressed_size] if ov.compressed_size else data)
        return data

    def file_at(self, rom_offset):
        """Map a ROM offset to what lives there: (kind, name, offset_within)."""
        o = rom_offset
        if o < 0x200:
            return "header", "header", o
        if self.arm9_off <= o < self.arm9_off + self.arm9_size:
            return "arm9", "arm9 binary", o - self.arm9_off
        if self.arm7_off <= o < self.arm7_off + self.arm7_size:
            return "arm7", "arm7 binary", o - self.arm7_off
        if self.fnt_off <= o < self.fnt_off + self.fnt_size:
            return "fnt", "file name table", o - self.fnt_off
        if self.fat_off <= o < self.fat_off + self.fat_size:
            return "fat", f"file allocation table (entry {(o - self.fat_off) // 8})", o - self.fat_off
        if self.ovt9_off <= o < self.ovt9_off + self.ovt9_size:
            return "ovt", "arm9 overlay table", o - self.ovt9_off
        for fid in range(self.fat_size // 8):
            start, end = self.file_extent(fid)
            if start <= o < end:
                name = self.files.get(fid)
                if name is None:
                    ov = next((x for x in self.overlays if x.file_id == fid), None)
                    name = f"overlay {ov.cpu}#{ov.id}" if ov else f"file#{fid}"
                return "file", name, o - start
        return "unknown", "unknown", 0

    def find_file(self, name):
        """File id by path (case-insensitive, suffix match allowed)."""
        name = name.lower().lstrip("/")
        exact = [fid for fid, n in self.files.items() if n.lower() == name]
        if exact:
            return exact[0]
        partial = [fid for fid, n in self.files.items() if n.lower().endswith(name)]
        if len(partial) == 1:
            return partial[0]
        if partial:
            raise KeyError(f"'{name}' is ambiguous: " + ", ".join(self.files[f] for f in partial[:10]))
        raise KeyError(f"no file named {name}")

    def overlays_at(self, addr, cpu="arm9"):
        return [ov for ov in self.overlays
                if ov.cpu == cpu and ov.ram_addr <= addr < ov.ram_addr + ov.ram_size]

    def summary(self):
        return {
            "path": self.path, "title": self.title, "game_code": self.game_code,
            "maker_code": self.maker_code, "version": self.version, "size": len(self.data),
            "arm9": {"rom_offset": f"{self.arm9_off:#x}", "entry": f"{self.arm9_entry:#010x}",
                     "load_addr": f"{self.arm9_addr:#010x}", "size": self.arm9_size},
            "arm7": {"rom_offset": f"{self.arm7_off:#x}", "entry": f"{self.arm7_entry:#010x}",
                     "load_addr": f"{self.arm7_addr:#010x}", "size": self.arm7_size},
            "overlay_count": {"arm9": sum(o.cpu == "arm9" for o in self.overlays),
                              "arm7": sum(o.cpu == "arm7" for o in self.overlays)},
            "file_count": len(self.files),
        }
