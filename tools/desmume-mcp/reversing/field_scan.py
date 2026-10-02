#!/usr/bin/env python3
"""Who touches which field of the game's global singletons.

Walks every function of a ph_export listing, following registers that hold a
global pointer (`ldr rX, =gItemManager` then `ldr rY, [rX]`) through moves,
`add rY, rZ, #k` and up to two pointer hops (gMapManager->mCourse->field), and
records each load/store `[reg, #off]` as an access to GLOBAL/off1/off2. Calls
made with such an object in r0 are recorded too: the callee receives it as
`this`, and a second pass scans those callees (their r0 starts as that object).

usage: field_scan.py EXPORT_DIR OUT.json GLOBAL [GLOBAL ...]
"""
import collections
import glob
import json
import os
import re
import sys

exp, out_path, *GLOBALS = sys.argv[1:]
GLOBALS = set(GLOBALS)
HDR = re.compile(r"^## (\S+)  \[(\S+) (0x[0-9a-f]+) (arm|thumb) size (0x[0-9a-f]+)( UNNAMED)?\]")
REGN = {**{f"r{i}": f"r{i}" for i in range(16)}, "sb": "r9", "sl": "r10", "fp": "r11", "ip": "r12",
        "sp": "r13", "lr": "r14", "pc": "r15"}
MEM = re.compile(r"^(\w+), \[(\w+)(?:, #(-?0x[0-9a-f]+|-?\d+))?\](!?)$")

funcs = {}
for path in sorted(glob.glob(os.path.join(exp, "asm", "*.s"))):
    cur = None
    for line in open(path, errors="replace"):
        line = line.rstrip("\n")
        m = HDR.match(line)
        if m:
            cur = funcs[m.group(1)] = dict(name=m.group(1), module=m.group(2), unnamed=bool(m.group(6)), ins=[])
            continue
        if cur is None or not line or line[8:10] != ": ":
            continue
        text, _, comment = line[10:].partition("  ;")
        if text.startswith("."):
            continue
        cur["ins"].append((int(line[:8], 16), text.strip(), comment.strip()))


def width(mn):
    b = mn.rstrip("s")
    return 1 if b.endswith(("b", "sb")) else 2 if b.endswith(("h", "sh")) else 4


def scan(f, entry_this=None):
    """-> accesses [(global_path, off, 'r'/'w', width, addr)], this_calls [(callee, global_path)]"""
    targets = set()
    for a, t, c in f["ins"]:
        m = re.match(r"^b\w*\s+#0x([0-9a-f]+)$", t)
        if m:
            targets.add(int(m.group(1), 16))
    st = {}
    if entry_this:
        st["r0"] = ("obj", entry_this, 0)
    acc, calls = [], []
    for a, t, c in f["ins"]:
        if a in targets:
            st = {}
        mn, _, ops = t.partition(" ")
        mn = mn.split(".")[0]
        ops = ops.strip()
        for k, v in REGN.items():
            ops = re.sub(rf"\b{k}\b", v, ops)
        m_lit = re.match(r"^=(\w+)$", c)
        if mn.startswith("ldr") and "[r15" in ops:
            rd = ops.split(",")[0]
            st.pop(rd, None)
            if m_lit and m_lit.group(1) in GLOBALS:
                st[rd] = ("addr", m_lit.group(1), 0)
            continue
        if mn in ("bl", "blx") or (mn == "b" and "->" in c):
            if "r0" in st and st["r0"][0] == "obj":
                callee = c.split("-> ", 1)[1].split()[0] if "-> " in c else None
                if callee:
                    calls.append((callee, st["r0"][1], st["r0"][2]))
            for r in ("r0", "r1", "r2", "r3", "r12", "r14"):
                st.pop(r, None)
            continue
        mm = MEM.match(ops)
        if mm and (mn.startswith("ldr") or mn.startswith("str")):
            rd, rb, off, wb = mm.groups()
            off = int(off, 0) if off else 0
            src = st.get(rb)
            if src:
                kind, gpath, adj = src
                if kind == "addr" and off + adj == 0 and mn == "ldr":
                    st[rd] = ("obj", gpath, 0)
                    continue
                if kind == "obj":
                    fo = adj + off
                    acc.append((gpath, fo, "r" if mn.startswith("ldr") else "w", width(mn), a))
                    if mn.startswith("ldr"):
                        if mn == "ldr" and gpath.count("/") < 2:
                            st[rd] = ("obj", f"{gpath}/{fo:#x}", 0)
                        else:
                            st.pop(rd, None)
                    continue
            if mn.startswith("ldr"):
                st.pop(rd, None)
            continue
        parts = [p.strip() for p in ops.split(",")]
        if not parts or not parts[0].startswith("r"):
            continue
        rd = parts[0]
        if mn in ("mov", "movs") and len(parts) == 2 and parts[1] in st:
            st[rd] = st[parts[1]]
            continue
        if mn in ("add", "adds") and len(parts) == 3 and parts[1] in st and parts[2].startswith("#"):
            kind, gpath, adj = st[parts[1]]
            if kind == "obj":
                st[rd] = (kind, gpath, adj + int(parts[2][1:], 0))
                continue
        if mn in ("adds", "add") and len(parts) == 2 and parts[1].startswith("#") and rd in st:
            kind, gpath, adj = st[rd]
            st[rd] = (kind, gpath, adj + int(parts[1][1:], 0))
            continue
        if mn.startswith(("cmp", "cmn", "tst", "teq", "push", "pop", "stm", "ldm")):
            if mn.startswith(("pop", "ldm")):
                for r in re.findall(r"r\d+", ops):
                    st.pop(r, None)
            continue
        st.pop(rd, None)
    return acc, calls


result = {"accesses": collections.defaultdict(list), "this": collections.defaultdict(set)}
receivers = {}
for f in funcs.values():
    acc, calls = scan(f)
    for g, off, rw, w, a in acc:
        result["accesses"][f"{g}+{off:#x}"].append((f["name"], rw, w, f"{a:#010x}"))
    for callee, g, adj in calls:
        if adj == 0:
            result["this"][callee].add(g)
            receivers.setdefault(callee, set()).add(g)
# second pass: callees receiving a singleton as `this` (only when it is always the same one)
for callee, gs in receivers.items():
    if len(gs) != 1 or callee not in funcs:
        continue
    g = next(iter(gs))
    acc, _ = scan(funcs[callee], entry_this=g)
    for gg, off, rw, w, a in acc:
        result["accesses"][f"{gg}+{off:#x}"].append((callee, rw, w, f"{a:#010x}", "this"))
out = {"accesses": {k: v for k, v in sorted(result["accesses"].items())},
       "this": {k: sorted(v) for k, v in result["this"].items()},
       "unnamed": sorted(n for n, f in funcs.items() if f["unnamed"])}
json.dump(out, open(out_path, "w"), indent=0)
n_unnamed_this = sum(1 for k in out["this"] if k in funcs and funcs[k]["unnamed"])
print(f"{len(out['accesses'])} distinct fields, "
      f"{sum(len(v) for v in out['accesses'].values())} accesses; {len(out['this'])} functions receive a singleton "
      f"as this ({n_unnamed_this} unnamed)")
