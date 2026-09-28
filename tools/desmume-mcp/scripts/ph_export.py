#!/usr/bin/env python3
"""Export an annotated disassembly of Zelda: Phantom Hourglass for labelling.

Takes your own ROM dump and the zeldaret/ph decompilation's symbol tables
(config/<version>/arm9) and writes, for every function of the main binary,
ITCM and all overlays: its code with calls, pointers and literal pool values
resolved to symbol names, I/O register names and referenced strings, plus
an index with callers/callees. That is what is needed to propose names for
the functions the decomp has not named yet.

Before writing anything the export is verified: every call the decomp
knows about (relocs.txt) must match the instruction actually in your ROM.
A wrong region/revision or a bad extraction stops the export.

The output contains the game's code, so it is encrypted (AES-256 via
openssl) before it is committed: a random passphrase is printed, and only
the ciphertext is pushed. Pushing unencrypted is only allowed when GitHub
confirms the target repository is private.

usage:
  tools/desmume-mcp/scripts/ph_export.py rom.nds [--push] [--dest-repo PATH]
      [--ph PATH_TO_zeldaret_ph]   (default: shallow clone into ~/.cache)
      [--version usa|eur]          (default: detected from the ROM)
      [--out DIR] [--force] [--no-encrypt]

Needs: python3, capstone (pip install capstone), git, openssl.
"""

import argparse
import bisect
import collections
import datetime
import hashlib
import json
import os
import re
import secrets
import shutil
import struct
import subprocess
import sys
import tarfile
import urllib.request

HERE = os.path.dirname(os.path.abspath(__file__))
PKG = os.path.dirname(HERE)
REPO = os.path.abspath(os.path.join(PKG, "..", ".."))
sys.path.insert(0, PKG)

from desmume_mcp.hw import io_name  # noqa: E402
from desmume_mcp.memory import arm_branch_target, thumb_bl_target  # noqa: E402
from desmume_mcp.rom import Rom, blz_decompress  # noqa: E402

try:
    import capstone
except ImportError:
    sys.exit("capstone is missing: pip install capstone")

SYM_RE = re.compile(r"^(\S+) kind:(\w+)(?:\(([^)]*)\))? addr:(0x[0-9a-fA-F]+)(.*)$")
RELOC_RE = re.compile(r"^from:(0x[0-9a-fA-F]+) kind:(\S+) to:(0x[0-9a-fA-F]+)(?: add:(-?0x[0-9a-fA-F]+|-?\d+))? module:(\S+)")
AUTO_RE = re.compile(r"^(func|data|jumptable|FUN|DAT|sub)_(ov\d+_)?[0-9a-fA-F]{8}$")
CALL_KINDS = {"arm_call", "thumb_call", "arm_call_thumb", "thumb_call_arm"}


def log(msg):
    print(msg, file=sys.stderr, flush=True)


# ---------------------------------------------------------------------------
# inputs


def get_ph(path):
    if path:
        return os.path.abspath(path)
    cache = os.path.expanduser("~/.cache/desmume-mcp/ph")
    if not os.path.isdir(os.path.join(cache, "config")):
        log(f"cloning zeldaret/ph into {cache} ...")
        os.makedirs(os.path.dirname(cache), exist_ok=True)
        subprocess.run(["git", "clone", "-q", "--depth", "1", "https://github.com/zeldaret/ph", cache], check=True)
    else:
        subprocess.run(["git", "-C", cache, "pull", "-q", "--ff-only"], check=False)
    return cache


def detect_version(ph, rom_bytes, rom, forced):
    sha1 = hashlib.sha1(rom_bytes).hexdigest()
    known = {}
    for v in ("usa", "eur"):
        p = os.path.join(ph, f"ph_{v}.sha1")
        if os.path.exists(p):
            known[open(p).read().split()[0].lower()] = v
    by_code = {"AZEE": "usa", "AZEP": "eur"}
    version = forced or known.get(sha1) or by_code.get(rom.game_code)
    return version, sha1, sha1 in known


def module_key(mod):
    m = re.match(r"^overlay\((\d+)\)$", mod)
    if m:
        return [f"ov{int(m.group(1)):03d}"]
    m = re.match(r"^overlays\(([\d,]+)\)$", mod)
    if m:
        return [f"ov{int(x):03d}" for x in m.group(1).split(",")]
    return [mod]


class Module:
    def __init__(self, name, cfg_dir, base, data):
        self.name = name
        self.base = base
        self.data = data
        self.symbols = []
        for line in open(os.path.join(cfg_dir, "symbols.txt")):
            m = SYM_RE.match(line.strip())
            if not m:
                continue
            sname, kind, attrs, addr, _ = m.groups()
            attrs = attrs or ""
            size = re.search(r"size=(0x[0-9a-fA-F]+)", attrs)
            self.symbols.append({"name": sname, "kind": kind, "addr": int(addr, 16),
                                 "thumb": "thumb" in attrs, "size": int(size.group(1), 16) if size else 0})
        self.symbols.sort(key=lambda s: s["addr"])
        self.by_addr = {}
        for s in self.symbols:
            self.by_addr.setdefault(s["addr"], s)
        self.funcs = [s for s in self.symbols if s["kind"] == "function"]
        self.func_starts = [s["addr"] for s in self.funcs]
        self.all_starts = [s["addr"] for s in self.symbols]
        self.relocs = {}
        rp = os.path.join(cfg_dir, "relocs.txt")
        if os.path.exists(rp):
            for line in open(rp):
                m = RELOC_RE.match(line.strip())
                if m:
                    frm, kind, to, add, mod = m.groups()
                    self.relocs[int(frm, 16)] = (kind, int(to, 16), int(add, 0) if add else 0, module_key(mod))
        self.sections = []
        dp = os.path.join(cfg_dir, "delinks.txt")
        if os.path.exists(dp):
            for line in open(dp):
                m = re.match(r"\s*(\S+)\s+start:(0x[0-9a-f]+) end:(0x[0-9a-f]+) kind:(\w+)", line)
                if m:
                    self.sections.append((m.group(1), int(m.group(2), 16), int(m.group(3), 16), m.group(4)))
                else:
                    break  # the per-file section lists follow

    def contains(self, addr):
        return self.base <= addr < self.base + len(self.data)

    def read(self, addr, n):
        o = addr - self.base
        return self.data[o:o + n] if 0 <= o and o + n <= len(self.data) else None

    def func_containing(self, addr):
        i = bisect.bisect_right(self.func_starts, addr) - 1
        if i >= 0:
            f = self.funcs[i]
            if addr < f["addr"] + max(f["size"], 2):
                return f
        return None

    def symbol_for(self, addr):
        """Exact symbol, or 'sym+off' inside a sized/nearby symbol."""
        s = self.by_addr.get(addr) or self.by_addr.get(addr & ~1)
        if s:
            return s["name"]
        i = bisect.bisect_right(self.all_starts, addr) - 1
        if i >= 0:
            s = self.symbols[i]
            off = addr - s["addr"]
            if (s["size"] and off < s["size"]) or (not s["size"] and off < 0x1000):
                return f"{s['name']}+{off:#x}"
        return None


def extract_modules(rom, ph_cfg):
    """main binary, ITCM, DTCM (autoloads) and overlays as (base, bytes)."""
    arm9 = rom.arm9_binary()
    base = rom.arm9_addr
    out = {}
    idx = arm9.find(b"\x21\x06\xc0\xde\xde\xc0\x06\x21")
    if idx < 0x1C:
        log("  no module parameters in the ARM9 binary: treating it as one module (no ITCM/DTCM)")
        list_start = list_end = auto_start = base + len(arm9)
    else:
        list_start, list_end, auto_start = struct.unpack_from("<3I", arm9, idx - 0x1C)
    main_end = auto_start - base
    out["main"] = (base, arm9[:main_end])
    pos = main_end
    names = {0x01FF8000: "itcm", 0x027E0000: "dtcm"}
    for i in range((list_end - list_start) // 12):
        addr, size, bss = struct.unpack_from("<3I", arm9, list_start - base + i * 12)
        name = names.get(addr & 0xFFFFF000, "itcm" if addr < 0x02000000 else "dtcm")
        out[name] = (addr, arm9[pos:pos + size])
        pos += size
    for ov in rom.overlays:
        if ov.cpu == "arm9":
            out[f"ov{ov.id:03d}"] = (ov.ram_addr, rom.overlay_binary("arm9", ov.id))
    return out


# ---------------------------------------------------------------------------
# verification


def verify(modules):
    """Check the decomp's call relocations against the ROM's instructions."""
    stats = {}
    for m in modules.values():
        ok = bad = 0
        samples = []
        for frm, (kind, to, add, mods) in m.relocs.items():
            if kind not in CALL_KINDS or not m.contains(frm):
                continue
            if kind.startswith("arm"):
                raw = m.read(frm, 4)
                if raw is None:
                    continue
                br = arm_branch_target(struct.unpack("<I", raw)[0], frm)
                got = br[1] & ~1 if br else None
            else:
                raw = m.read(frm, 4)
                if raw is None:
                    continue
                hi, lo = struct.unpack("<HH", raw)
                bl = thumb_bl_target(hi, lo, frm)
                got = bl[1] & ~1 if bl else None
            if got is not None and got == (to & ~1):
                ok += 1
            else:
                bad += 1
                if len(samples) < 5:
                    samples.append(f"{frm:#010x}: decomp says call {to:#010x}, ROM has "
                                   + (f"{got:#010x}" if got is not None else "no call"))
        stats[m.name] = {"ok": ok, "bad": bad, "samples": samples}
    return stats


# ---------------------------------------------------------------------------
# disassembly


class Exporter:
    def __init__(self, modules):
        self.modules = modules
        self.arm = capstone.Cs(capstone.CS_ARCH_ARM, capstone.CS_MODE_ARM)
        self.thumb = capstone.Cs(capstone.CS_ARCH_ARM, capstone.CS_MODE_THUMB)
        self.callers = collections.defaultdict(set)   # (module, func addr) -> {(module, caller func)}
        self.callees = collections.defaultdict(set)

    def resolve(self, addr, mods, prefer=None):
        """Symbol name for addr in one of the given modules."""
        order = list(mods)
        if prefer and prefer in order:
            order.remove(prefer)
            order.insert(0, prefer)
        for name in order:
            m = self.modules.get(name)
            if m:
                s = m.symbol_for(addr)
                if s:
                    return s, name
        return None, None

    def modules_for(self, addr, home):
        """Where an unrelocated address may point: home module first, then
        main/itcm/dtcm."""
        cands = [home, "main", "itcm", "dtcm"]
        return [c for c in cands if c in self.modules and self.modules[c].contains(addr)]

    def string_at(self, addr, mods):
        for name in mods:
            m = self.modules.get(name)
            if m and m.contains(addr):
                raw = m.read(addr, min(96, m.base + len(m.data) - addr)) or b""
                txt = raw.split(b"\0")[0]
                if len(txt) >= 4 and all(32 <= c < 127 or c in (9, 10) for c in txt):
                    return txt.decode("latin-1")
        return None

    def build_call_graph(self):
        for m in self.modules.values():
            for frm, (kind, to, add, mods) in m.relocs.items():
                if kind not in CALL_KINDS:
                    continue
                caller = m.func_containing(frm)
                for tm in mods:
                    t = self.modules.get(tm)
                    if t and t.by_addr.get(to & ~1) and t.by_addr[to & ~1]["kind"] == "function":
                        if caller:
                            self.callers[(tm, to & ~1)].add((m.name, caller["addr"]))
                            self.callees[(m.name, caller["addr"])].add((tm, to & ~1))
                        break

    def func_name(self, key):
        m = self.modules.get(key[0])
        s = m.by_addr.get(key[1]) if m else None
        return f"{s['name']}" if s else f"{key[0]}:{key[1]:#x}"

    def disassemble(self, m, f):
        start, size, thumb = f["addr"], f["size"], f["thumb"]
        if not size:
            nxt = bisect.bisect_right(m.func_starts, start)
            size = min((m.func_starts[nxt] if nxt < len(m.func_starts) else start + 0x40) - start, 0x2000)
        code = m.read(start, size)
        if code is None:
            return [f"    ; outside the extracted module ({size:#x} bytes)"]
        md = self.thumb if thumb else self.arm
        step = 2 if thumb else 4

        # pass 1: literal pool words (targets of pc relative loads, relocated words)
        pool = set()
        for frm in m.relocs:
            if start <= frm < start + size and m.relocs[frm][0] == "load":
                pool.add(frm)
        off = 0
        while off < size:
            if start + off in pool:
                off += 4
                continue
            insns = list(md.disasm(code[off:off + 4], start + off, 1))
            if not insns:
                off += step
                continue
            i = insns[0]
            mm = re.search(r"\[pc, #(-?0x[0-9a-f]+|-?\d+)\]", i.op_str)
            if mm and i.mnemonic.startswith("ldr"):
                lit = ((i.address + (4 if thumb else 8)) & ~3) + int(mm.group(1), 0)
                if start <= lit < start + size:
                    pool.add(lit)
                    if i.mnemonic in ("ldrd",):
                        pool.add(lit + 4)
            off += i.size

        # pass 2: listing
        lines = []
        off = 0
        while off < size:
            addr = start + off
            if addr in pool:
                word = struct.unpack("<I", code[off:off + 4].ljust(4, b"\0"))[0]
                lines.append(f"{addr:08x}: .word {word:#010x}" + self.note_word(m, addr, word))
                off += 4
                continue
            insns = list(md.disasm(code[off:off + 4], addr, 1))
            if not insns:
                val = int.from_bytes(code[off:off + step], "little")
                lines.append(f"{addr:08x}: .{'hword' if thumb else 'word'} {val:#x}")
                off += step
                continue
            i = insns[0]
            text = f"{i.mnemonic} {i.op_str}".strip()
            note = ""
            rel = m.relocs.get(addr)
            if rel and rel[0] in CALL_KINDS:
                name, _ = self.resolve(rel[1] & ~1, rel[3], m.name)
                note = f"  ; -> {name or hex(rel[1])}"
            else:
                mm = re.search(r"\[pc, #(-?0x[0-9a-f]+|-?\d+)\]", i.op_str)
                if mm and i.mnemonic.startswith("ldr"):
                    lit = ((addr + (4 if thumb else 8)) & ~3) + int(mm.group(1), 0)
                    raw = m.read(lit, 4)
                    if raw:
                        word = struct.unpack("<I", raw)[0]
                        note = "  ;" + self.note_word(m, lit, word, prefix="=")
                elif i.mnemonic in ("b", "bl", "blx") or i.mnemonic.startswith("b") and i.op_str.startswith("#"):
                    try:
                        tgt = int(i.op_str.lstrip("#"), 0)
                        f2 = m.func_containing(tgt)
                        if f2 and f2["addr"] != start:
                            note = f"  ; -> {f2['name']}" + (f"+{tgt - f2['addr']:#x}" if tgt != f2["addr"] else "")
                    except ValueError:
                        pass
            lines.append(f"{addr:08x}: {text}{note}")
            off += i.size
        return lines

    def note_word(self, m, at, word, prefix=""):
        rel = m.relocs.get(at)
        if rel:
            kind, to, add, mods = rel
            name, where = self.resolve(to, mods, m.name)
            s = self.string_at(to, [where] if where else mods)
            label = name or f"{to:#010x}"
            return (f" {prefix}{label}" + (f" (add {add:#x})" if add else "")
                    + (f' "{s[:60]}"' if s else ""))
        io = io_name(word)
        if io:
            return f" {prefix}{word:#010x} <{io}>" if prefix else f" <{io}>"
        if 0x01FF8000 <= word < 0x02400000 or 0x027E0000 <= word < 0x027E4000:
            mods = self.modules_for(word, m.name)
            name, where = self.resolve(word, mods, m.name) if mods else (None, None)
            s = self.string_at(word, mods) if mods else None
            if name or s:
                return (f" {prefix}{word:#010x}" if prefix else "") + (f" <{name}>" if name else "") \
                    + (f' "{s[:60]}"' if s else "")
        return f" {prefix}{word:#010x}" if prefix else ""


# ---------------------------------------------------------------------------
# output


def write_export(out_dir, exp, modules, meta):
    os.makedirs(os.path.join(out_dir, "asm"), exist_ok=True)
    index = ["module\taddr\tkind\tmode\tsize\tname\tnamed\tcallers\tcallees"]
    counts = collections.Counter()
    for name in sorted(modules, key=lambda n: (n != "main", n)):
        m = modules[name]
        lines = [f"; {name}: base {m.base:#010x}, {len(m.data):#x} bytes, "
                 f"{len(m.funcs)} functions", ""]
        for f in m.funcs:
            key = (name, f["addr"])
            named = not AUTO_RE.match(f["name"])
            counts["named" if named else "unnamed"] += 1
            callers = sorted(exp.callers.get(key, ()))
            callees = sorted(exp.callees.get(key, ()))
            index.append("\t".join([name, f"{f['addr']:#010x}", "function", "thumb" if f["thumb"] else "arm",
                                    f"{f['size']:#x}", f["name"], "1" if named else "0",
                                    str(len(callers)), str(len(callees))]))
            lines.append(f"## {f['name']}  [{name} {f['addr']:#010x} {'thumb' if f['thumb'] else 'arm'} "
                         f"size {f['size']:#x}{'' if named else ' UNNAMED'}]")
            if callers:
                lines.append("; called by: " + ", ".join(exp.func_name(c) for c in callers[:20])
                             + (f" (+{len(callers) - 20})" if len(callers) > 20 else ""))
            if callees:
                lines.append("; calls: " + ", ".join(exp.func_name(c) for c in callees[:30])
                             + (f" (+{len(callees) - 30})" if len(callees) > 30 else ""))
            lines.extend(exp.disassemble(m, f))
            lines.append("")
        for s in m.symbols:
            if s["kind"] != "function":
                named = not AUTO_RE.match(s["name"])
                raw = m.read(s["addr"], 16) if m.contains(s["addr"]) else None
                index.append("\t".join([name, f"{s['addr']:#010x}", s["kind"], "", f"{s['size']:#x}", s["name"],
                                        "1" if named else "0", "", raw.hex() if raw else ""]))
        with open(os.path.join(out_dir, "asm", f"{name}.s"), "w") as fh:
            fh.write("\n".join(lines) + "\n")
        log(f"  {name}: {len(m.funcs)} functions")
    with open(os.path.join(out_dir, "index.tsv"), "w") as fh:
        fh.write("\n".join(index) + "\n")
    meta["functions"] = dict(counts)
    with open(os.path.join(out_dir, "summary.json"), "w") as fh:
        json.dump(meta, fh, indent=1)
    with open(os.path.join(out_dir, "README.txt"), "w") as fh:
        fh.write("Phantom Hourglass export for labelling (see tools/desmume-mcp/scripts/ph_export.py).\n"
                 "asm/<module>.s: every function, with calls, pointers, literal values and strings resolved\n"
                 "against the zeldaret/ph symbols; index.tsv: all symbols with caller/callee counts\n"
                 "(for data: the first 16 bytes); summary.json: versions and the verification results.\n")


def repo_is_public(repo_dir):
    """True / False from GitHub, None if it cannot tell."""
    try:
        url = subprocess.run(["git", "-C", repo_dir, "remote", "get-url", "origin"], capture_output=True,
                             text=True, check=True).stdout.strip()
    except (subprocess.CalledProcessError, OSError):
        return None
    m = re.search(r"github\.com[:/]([^/]+)/([^/.]+)", url)
    if not m:
        return None
    try:
        with urllib.request.urlopen(f"https://api.github.com/repos/{m.group(1)}/{m.group(2)}", timeout=10) as r:
            return not json.load(r).get("private", False)
    except Exception:
        # private repositories answer 404 to anonymous requests
        return None


def main():
    ap = argparse.ArgumentParser(description=__doc__.split("\n\n")[0],
                                 formatter_class=argparse.RawDescriptionHelpFormatter, epilog=__doc__)
    ap.add_argument("rom")
    ap.add_argument("--ph", help="path to a zeldaret/ph checkout (default: clone into ~/.cache)")
    ap.add_argument("--version", choices=["usa", "eur"])
    ap.add_argument("--out", default=None, help="output directory (default: ./ph-export-<version>)")
    ap.add_argument("--push", action="store_true", help="commit the encrypted export to a repo's current branch and push")
    ap.add_argument("--dest-repo", default=REPO,
                    help="git checkout to commit to (default: this desmume checkout)")
    ap.add_argument("--force", action="store_true", help="export even if verification fails")
    ap.add_argument("--no-encrypt", action="store_true", help="only allowed when the repo is confirmed private")
    args = ap.parse_args()

    for tool in ("git", "openssl"):
        if not shutil.which(tool):
            sys.exit(f"{tool} is needed")

    rom_bytes = open(args.rom, "rb").read()
    rom = Rom(args.rom)
    ph = get_ph(args.ph)
    version, sha1, exact = detect_version(ph, rom_bytes, rom, args.version)
    if not version:
        sys.exit(f"cannot tell the ROM version (game code {rom.game_code}); pass --version usa|eur")
    log(f"ROM {rom.title} [{rom.game_code}] sha1 {sha1}: {version}"
        + ("" if exact else " (sha1 does not match the decomp's reference dump; verifying against the code)"))
    cfg = os.path.join(ph, "config", version, "arm9")
    if not os.path.isdir(cfg):
        sys.exit(f"{cfg} not found")

    log("extracting modules ...")
    raw_modules = extract_modules(rom, cfg)
    modules = {}
    for name, (base, data) in raw_modules.items():
        d = cfg if name == "main" else os.path.join(cfg, name) if name in ("itcm", "dtcm") \
            else os.path.join(cfg, "overlays", name)
        if os.path.exists(os.path.join(d, "symbols.txt")):
            modules[name] = Module(name, d, base, data)
        else:
            log(f"  no symbols for {name}, skipped")

    log("verifying against the decomp's call relocations ...")
    stats = verify(modules)
    total_ok = sum(s["ok"] for s in stats.values())
    total_bad = sum(s["bad"] for s in stats.values())
    rate = total_ok / max(1, total_ok + total_bad)
    for name, s in stats.items():
        if s["bad"] > max(3, 0.02 * (s["ok"] + s["bad"])):
            log(f"  {name}: {s['ok']} ok, {s['bad']} mismatched, e.g. {s['samples'][:2]}")
    log(f"  {total_ok}/{total_ok + total_bad} calls match ({100 * rate:.2f}%)")
    if rate < 0.98 and not args.force:
        sys.exit("verification failed: this ROM does not match the decomp's addresses (wrong region/revision?). "
                 "Nothing was written. --force to export anyway.")

    exp = Exporter(modules)
    log("building the call graph ...")
    exp.build_call_graph()
    out_dir = os.path.abspath(args.out or f"ph-export-{version}")
    if os.path.exists(out_dir):
        shutil.rmtree(out_dir)
    ph_rev = subprocess.run(["git", "-C", ph, "rev-parse", "HEAD"], capture_output=True, text=True).stdout.strip()
    meta = {"created": datetime.datetime.now().isoformat(timespec="seconds"), "rom_sha1": sha1,
            "rom_matches_decomp_reference": exact, "game_code": rom.game_code, "version": version,
            "ph_commit": ph_rev, "verification": {"calls_ok": total_ok, "calls_bad": total_bad,
                                                  "per_module": {k: {"ok": v["ok"], "bad": v["bad"]}
                                                                 for k, v in stats.items()}}}
    log(f"disassembling into {out_dir} ...")
    write_export(out_dir, exp, modules, meta)

    archive = out_dir + ".tar.xz"
    with tarfile.open(archive, "w:xz") as tar:
        tar.add(out_dir, arcname=os.path.basename(out_dir))
    log(f"archive {archive}: {os.path.getsize(archive) / 1e6:.1f} MB")

    to_push = archive
    passphrase = None
    dest_repo = os.path.abspath(args.dest_repo)
    public = repo_is_public(dest_repo)
    if args.no_encrypt:
        if public is not False:
            sys.exit("--no-encrypt refused: GitHub does not confirm that this repository is private "
                     "(the export contains the game's code)")
    else:
        passphrase = secrets.token_urlsafe(24)
        enc = archive + ".enc"
        env = dict(os.environ, PH_EXPORT_PASS=passphrase)
        subprocess.run(["openssl", "enc", "-aes-256-cbc", "-pbkdf2", "-iter", "200000", "-salt",
                        "-in", archive, "-out", enc, "-pass", "env:PH_EXPORT_PASS"], check=True, env=env)
        with open(out_dir + ".passphrase", "w") as fh:
            fh.write(passphrase + "\n")
        to_push = enc

    if args.push:
        branch = subprocess.run(["git", "-C", dest_repo, "rev-parse", "--abbrev-ref", "HEAD"], capture_output=True,
                                text=True, check=True).stdout.strip()
        dest_dir = os.path.join(dest_repo, "labelling")
        os.makedirs(dest_dir, exist_ok=True)
        dest = os.path.join(dest_dir, os.path.basename(to_push))
        shutil.copyfile(to_push, dest)
        with open(os.path.join(dest_dir, f"ph-export-{version}.json"), "w") as fh:
            json.dump({k: v for k, v in meta.items() if k != "rom_sha1"} | {"file": os.path.basename(dest),
                       "encrypted": passphrase is not None}, fh, indent=1)
        subprocess.run(["git", "-C", dest_repo, "add", "labelling"], check=True)
        subprocess.run(["git", "-C", dest_repo, "commit", "-q", "-m",
                        f"labelling: {'encrypted ' if passphrase else ''}PH {version} export for naming functions"],
                       check=True)
        subprocess.run(["git", "-C", dest_repo, "push", "-q", "origin", branch], check=True)
        log(f"pushed {os.path.relpath(dest, dest_repo)} to {branch} in {dest_repo}")

    print()
    if passphrase:
        print(f"Passphrase (paste this to Claude; it is also in {out_dir}.passphrase):\n\n    {passphrase}\n")
    print(f"Export: {to_push}")
    if not args.push:
        print("Run again with --push to commit it to this repository's current branch.")


if __name__ == "__main__":
    main()
