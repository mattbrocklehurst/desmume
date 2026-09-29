#!/usr/bin/env python3
"""Export an annotated disassembly of Pokemon Platinum (US) from pret/pokeplatinum,
in the same format as ph_export.py, for cross-game matching: Platinum's
NitroSDK 4.2 / NitroSystem / NitroWiFi / NitroDWC are fully named in
Nintendo's own names.

pokeplatinum builds a byte-identical ROM from source. This script builds it
(or uses an existing build), checks that the built ROM is exactly your dump
(SHA-1), takes every symbol from the linker output (build/main.nef: names,
addresses, sizes, module), the code from your ROM, derives the call graph
from the code, and writes the export with ph_export.py's exporter. It is
encrypted and pushed exactly like ph_export.py's exports.

usage:
  tools/desmume-mcp/scripts/plat_export.py platinum.nds [--push] [--dest-repo PATH]
      [--platinum PATH_TO_pokeplatinum]   (default: clone into ~/.cache and build)
      [--no-build]                        (use the existing build as is)
      [--out DIR] [--no-encrypt]

Build dependencies (see pokeplatinum's INSTALL.md), Arch: enable multilib, then
  sudo pacman -S arm-none-eabi-gcc bison flex gcc git make ninja python wget xz lib32-glibc libpng
Debian/Ubuntu: sudo dpkg --add-architecture i386 && sudo apt install bison flex g++
  gcc-arm-none-eabi git make ninja-build pkg-config wget python3 xz-utils nasm libc6:i386 libpng-dev
Plus capstone and openssl as for ph_export.py.
"""

import argparse
import datetime
import glob
import hashlib
import os
import re
import shutil
import struct
import subprocess
import sys
import tempfile

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
import ph_export as px  # noqa: E402

URL = "https://github.com/pret/pokeplatinum"
REVISIONS = {"0862ec35b24de5c7e2dcb88c9eea0873110d755c": "1",   # retail rev 1 (repo default)
             "ce81046eda7d232513069519cb2085349896dec7": "0"}   # first North American shipment
# pokeplatinum's placeholder names: sub_0201D640, ov5_021D0F84 (plus the usual func_/data_)
px.AUTO_RE = re.compile(r"^(func|data|jumptable|FUN|DAT|sub|unk)_(ov\d+_)?[0-9a-fA-F]{8}$|^ov\d+_[0-9A-Fa-f]{8}$")
log = px.log


# ---------------------------------------------------------------------------
# build


def get_repo(path):
    if path:
        return os.path.abspath(path)
    cache = os.path.expanduser("~/.cache/desmume-mcp/pokeplatinum")
    if not os.path.isdir(os.path.join(cache, ".git")):
        log(f"cloning {URL} into {cache} ...")
        os.makedirs(os.path.dirname(cache), exist_ok=True)
        subprocess.run(["git", "clone", "-q", "--depth", "1", URL, cache], check=True)
    return cache


def build(repo, revision):
    log(f"building pokeplatinum (ROM_REVISION={revision}); the first build downloads its toolchain "
        "and takes a while ...")
    env = dict(os.environ, ROM_REVISION=revision)
    r = subprocess.run(["make", "rom"], cwd=repo, env=env)
    if r.returncode != 0:
        sys.exit("pokeplatinum build failed (see its INSTALL.md for the dependencies). If you switched "
                 "revisions, try `make distclean` in the repo first.")


def find_nef(repo):
    cands = [p for p in glob.glob(os.path.join(repo, "build", "**", "*.nef"), recursive=True)
             if os.path.basename(p) != "debug.nef" and os.path.basename(p).startswith("main")]
    if not cands:
        sys.exit(f"no main*.nef under {repo}/build: build first (or drop --no-build)")
    return max(cands, key=os.path.getmtime)


# ---------------------------------------------------------------------------
# ELF (the .nef is a plain ELF32 ARM file)


def read_elf(path):
    data = open(path, "rb").read()
    if data[:4] != b"\x7fELF" or data[4] != 1:
        sys.exit(f"{path} is not an ELF32 file")
    shoff, = struct.unpack_from("<I", data, 0x20)
    shentsize, shnum, shstrndx = struct.unpack_from("<HHH", data, 0x2E)
    secs = []
    for i in range(shnum):
        name, typ, flags, addr, off, size, link, info, align, entsize = \
            struct.unpack_from("<IIIIIIIIII", data, shoff + i * shentsize)
        secs.append(dict(name_off=name, type=typ, flags=flags, addr=addr, off=off, size=size, link=link,
                         entsize=entsize))
    shstr = secs[shstrndx]

    def cstr(base, off):
        end = data.index(b"\0", base + off)
        return data[base + off:end].decode("latin-1")

    for s in secs:
        s["name"] = cstr(shstr["off"], s["name_off"])
    syms = []
    for s in secs:
        if s["type"] != 2:          # SHT_SYMTAB
            continue
        strtab = secs[s["link"]]
        for j in range(s["size"] // 16):
            name, value, size, info, other, shndx = struct.unpack_from("<IIIBBH", data, s["off"] + j * 16)
            syms.append(dict(name=cstr(strtab["off"], name), value=value, size=size, type=info & 0xF,
                             bind=info >> 4, shndx=shndx))
    return secs, syms


# ---------------------------------------------------------------------------
# modules


def lsf_overlays(repo):
    """Overlay names in linker-spec order (= overlay id)."""
    names = []
    for lsf in glob.glob(os.path.join(repo, "platinum.us", "main.lsf")):
        for line in open(lsf):
            m = re.match(r"^\s*Overlay\s+(\S+)", line)
            if m:
                names.append(m.group(1))
    return names


def assign_modules(rom, secs, syms, ov_names, raw_modules):
    """section index -> module name ('main', 'itcm', 'dtcm', 'ovNNN')."""
    ovs = {f"ov{ov.id:03d}": ov for ov in rom.overlays if ov.cpu == "arm9"}
    by_name = {n: i for i, n in enumerate(ov_names)}
    out, problems = {}, []
    for i, s in enumerate(secs):
        if not s["flags"] & 2 or not any(x["shndx"] == i and x["type"] in (1, 2) for x in syms):
            continue                                   # not loaded, or no functions/data in it
        name, addr = s["name"], s["addr"]
        base = name.split(".")[0].split("$")[0] if name else name
        mod = None
        if base in by_name:
            mod = f"ov{by_name[base]:03d}"
            ov = ovs.get(mod)
            if ov is None or not (ov.ram_addr <= addr <= ov.ram_addr + ov.ram_size + ov.bss_size):
                # linker spec order does not give the id: match the ROM's overlay table by address and size
                hits = [k for k, o in ovs.items() if o.ram_addr == addr]
                hits = [k for k in hits if ovs[k].ram_size in (s["size"], s["size"] - ovs[k].bss_size)] or hits
                if len(hits) == 1:
                    mod = hits[0]
                else:
                    problems.append(f"section {name} at {addr:#x}: overlay id unclear")
                    continue
        else:
            # main / autoloads never overlap each other or the overlays' addresses
            if 0x01FF8000 <= addr < 0x02000000:
                mod = "itcm"
            elif 0x027C0000 <= addr < 0x02800000:
                mod = "dtcm"
            elif 0x02000000 <= addr < 0x02400000 and not rom.overlays_at(addr):
                mod = "main"
        if mod:
            out[i] = mod
        elif s["size"]:
            problems.append(f"section {name!r} at {addr:#x} (+{s['size']:#x}) not mapped")
    return out, problems


def is_thumb(sym, mapping):
    if sym["value"] & 1:
        return True
    return mapping.get((sym["shndx"], sym["value"])) == "t"


def write_config(cfg, modules_syms, relocs):
    for mod, lines in modules_syms.items():
        d = cfg if mod == "main" else os.path.join(cfg, mod) if mod in ("itcm", "dtcm") \
            else os.path.join(cfg, "overlays", mod)
        os.makedirs(d, exist_ok=True)
        with open(os.path.join(d, "symbols.txt"), "w") as fh:
            fh.write("\n".join(lines) + "\n")
        with open(os.path.join(d, "relocs.txt"), "w") as fh:
            fh.write("\n".join(relocs.get(mod, [])) + "\n")


def collect(rom, secs, syms, ov_names):
    """Modules from the ROM, symbols per module from the ELF, call relocations from the code."""
    raw_modules = px.extract_modules(rom, None)
    sec_mod, problems = assign_modules(rom, secs, syms, ov_names, raw_modules)
    for p in problems[:20]:
        log("  " + p)
    if problems and len(problems) > 3:
        log("  sections: " + ", ".join(f"{s['name']}@{s['addr']:#x}+{s['size']:#x}" for s in secs if s["size"])[:3000])
        sys.exit("could not map the linker output's sections to the ROM's modules; paste this output to Claude")

    # mapping symbols ($a / $t) mark ARM / Thumb code
    mapping = {}
    for s in syms:
        if s["name"] in ("$a", "$t") or s["name"].startswith(("$a.", "$t.")):
            mapping[(s["shndx"], s["value"] & ~1)] = s["name"][1]

    per_mod = {}
    for s in syms:
        mod = sec_mod.get(s["shndx"])
        if not mod or not s["name"] or s["name"].startswith("$") or s["type"] not in (1, 2):
            continue
        addr = s["value"] & ~1
        base, data = raw_modules.get(mod, (None, None))
        if base is None or not base <= addr < base + len(data) + 0x10000:
            continue
        if s["type"] == 2:
            mode = "thumb" if is_thumb(s, mapping) else "arm"
            kind = f"function({mode},size={s['size']:#x})"
        else:
            kind = "data(any)"
        per_mod.setdefault(mod, {})[addr, s["type"]] = f"{s['name']} kind:{kind} addr:{addr:#010x}"

    # static functions/data can share a name across files: names are keys downstream,
    # so repeated ones get @address appended
    seen = {}
    for mod, d in per_mod.items():
        for key, line in d.items():
            seen.setdefault(line.split(" ", 1)[0], []).append((mod, key))
    for name, where in seen.items():
        if len(where) > 1:
            for mod, key in where:
                line = per_mod[mod][key]
                per_mod[mod][key] = f"{name}@{key[0]:08x}" + line[len(name):]

    # functions the linker gave no size: up to the next function
    for mod, d in per_mod.items():
        fs = sorted(a for a, t in d if t == 2)
        for i, a in enumerate(fs):
            line = d[a, 2]
            if "size=0x0)" in line:
                nxt = fs[i + 1] if i + 1 < len(fs) else a + 0x40
                d[a, 2] = line.replace("size=0x0)", f"size={min(nxt - a, 0x2000):#x})")

    # call relocations from the code: every bl/blx that lands on a known function start
    starts = {m: {a for (a, t) in d if t == 2} for m, d in per_mod.items()}
    thumb_at = {m: {a for (a, t), line in d.items() if t == 2 and "thumb" in line} for m, d in per_mod.items()}
    relocs = {}
    n_calls = 0
    for mod, d in per_mod.items():
        base, data = raw_modules[mod]
        for (addr, t), line in sorted(d.items()):
            if t != 2:
                continue
            size = int(re.search(r"size=(0x[0-9a-f]+)", line).group(1), 16)
            thumb = "thumb" in line
            off = addr - base
            step = 2 if thumb else 4
            o = off
            while o + 4 <= min(off + size, len(data)):
                frm = base + o
                if thumb:
                    hi, lo = struct.unpack_from("<HH", data, o)
                    r = px.thumb_bl_target(hi, lo, frm)
                else:
                    r = px.arm_branch_target(struct.unpack_from("<I", data, o)[0], frm)
                    if r and r[0] not in ("bl", "blx"):
                        r = None
                if r:
                    to = r[1] & ~1
                    for tm in (mod, "main", "itcm", "dtcm"):
                        if to in starts.get(tm, ()):
                            dst_thumb = to in thumb_at[tm]
                            kind = ("thumb_call" if dst_thumb else "thumb_call_arm") if thumb \
                                else ("arm_call_thumb" if dst_thumb else "arm_call")
                            tmod = f"overlay({int(tm[2:])})" if tm.startswith("ov") else tm
                            relocs.setdefault(mod, []).append(f"from:{frm:#010x} kind:{kind} to:{to:#010x} module:{tmod}")
                            n_calls += 1
                            break
                    o += 4 if thumb else step
                    continue
                o += step
    log(f"{sum(len(d) for d in per_mod.values())} symbols in {len(per_mod)} modules, {n_calls} calls")
    return raw_modules, per_mod, relocs


def main():
    ap = argparse.ArgumentParser(description=__doc__.split("\n\n")[0],
                                 formatter_class=argparse.RawDescriptionHelpFormatter, epilog=__doc__)
    ap.add_argument("rom")
    ap.add_argument("--platinum", help="pokeplatinum checkout (default: clone into ~/.cache)")
    ap.add_argument("--no-build", action="store_true", help="use the existing build")
    ap.add_argument("--out", default=None, help="output directory (default: ./platinum-export-usa)")
    ap.add_argument("--push", action="store_true", help="commit the encrypted export to a repo's branch and push")
    ap.add_argument("--dest-repo", default=px.REPO, help="git checkout to commit to")
    ap.add_argument("--no-encrypt", action="store_true", help="only allowed when the repo is confirmed private")
    args = ap.parse_args()

    for tool in ("git", "openssl", "make"):
        if not shutil.which(tool):
            sys.exit(f"{tool} is needed")
    if args.push:
        check = subprocess.run(["git", "-C", args.dest_repo, "symbolic-ref", "--short", "HEAD"],
                               capture_output=True, text=True)
        if check.returncode != 0:
            sys.exit(f"--dest-repo {args.dest_repo} is not a git checkout ({check.stderr.strip()})")

    rom_bytes = open(args.rom, "rb").read()
    sha1 = hashlib.sha1(rom_bytes).hexdigest()
    rom = px.Rom(args.rom)
    log(f"ROM {rom.title} [{rom.game_code}] sha1 {sha1}")
    revision = REVISIONS.get(sha1)
    if rom.game_code != "CPUE" or revision is None:
        sys.exit("this is not a Pokemon Platinum (US) dump pokeplatinum builds (expected sha1 "
                 + " or ".join(REVISIONS) + ")")

    repo = get_repo(args.platinum)
    if not args.no_build:
        build(repo, revision)
    built = os.path.join(repo, "build", "pokeplatinum.us.nds")
    if not os.path.exists(built):
        sys.exit(f"{built} missing: the build did not produce a ROM")
    bsha1 = hashlib.sha1(open(built, "rb").read()).hexdigest()
    if bsha1 != sha1:
        sys.exit(f"the build ({bsha1}) is not identical to your ROM ({sha1}); nothing written. "
                 f"Wrong revision? (this dump is revision {revision}; run `make distclean` in {repo} and retry)")
    log("built ROM is byte-identical to your dump")
    nef = find_nef(repo)
    log(f"symbols from {os.path.relpath(nef, repo)}")
    secs, syms = read_elf(nef)

    raw_modules, per_mod, relocs = collect(rom, secs, syms, lsf_overlays(repo))

    with tempfile.TemporaryDirectory() as tmp:
        cfg = os.path.join(tmp, "arm9")
        write_config(cfg, {m: [line for _, line in sorted(d.items())] for m, d in per_mod.items()}, relocs)
        modules = {}
        for name, (base, data) in raw_modules.items():
            dd = cfg if name == "main" else os.path.join(cfg, name) if name in ("itcm", "dtcm") \
                else os.path.join(cfg, "overlays", name)
            if os.path.exists(os.path.join(dd, "symbols.txt")):
                modules[name] = px.Module(name, dd, base, data)
        stats = px.verify(modules)
        exp = px.Exporter(modules)
        exp.build_call_graph()
        out_dir = os.path.abspath(args.out or "platinum-export-usa")
        if os.path.exists(out_dir):
            shutil.rmtree(out_dir)
        rev = subprocess.run(["git", "-C", repo, "rev-parse", "HEAD"], capture_output=True, text=True).stdout.strip()
        meta = {"game": "platinum", "game_title": "Pokemon Platinum", "created":
                datetime.datetime.now().isoformat(timespec="seconds"), "rom_sha1": sha1,
                "rom_matches_decomp_reference": True, "game_code": rom.game_code, "version": "usa",
                "rom_revision": revision, "decomp": URL, "decomp_commit": rev, "skipped_modules": [],
                "sdk": "NitroSDK 4.2 (2008-01-18), NitroWiFi 2.1, NitroDWC 2.2",
                "verification": {"method": "built ROM sha1 == dump sha1",
                                 "calls_ok": sum(v["ok"] for v in stats.values()),
                                 "calls_bad": sum(v["bad"] for v in stats.values())}}
        log(f"disassembling into {out_dir} ...")
        px.write_export(out_dir, exp, modules, meta)
    px.package_and_push(out_dir, meta, "platinum", "usa", args)


if __name__ == "__main__":
    main()
