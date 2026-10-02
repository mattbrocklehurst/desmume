#!/usr/bin/env python3
"""Naming batches: the most-called still-unnamed functions, with their code and call sites.
usage: make_batches.py EXPORT_DIR REPO OUTDIR N_BATCHES BATCH_SIZE [SKIP_NAMES.txt] [EVIDENCE.json] [N_EVIDENCE_PICKS]"""
import collections
import glob
import os
import re
import subprocess
import sys

exp, repo, outdir, nb, bs = sys.argv[1:6]
nb, bs = int(nb), int(bs)
skip = set(open(sys.argv[6]).read().split()) if len(sys.argv) > 6 else set()
import json
evidence = json.load(open(sys.argv[7])) if len(sys.argv) > 7 else {}
n_ev = int(sys.argv[8]) if len(sys.argv) > 8 else 0
os.makedirs(outdir, exist_ok=True)
HDR = re.compile(r"^## (\S+)  \[(\S+) (0x[0-9a-f]+) (arm|thumb) size (0x[0-9a-f]+)( UNNAMED)?\]")
funcs, order = {}, []
for path in sorted(glob.glob(os.path.join(exp, "asm", "*.s"))):
    cur = None
    for line in open(path, errors="replace"):
        line = line.rstrip("\n")
        m = HDR.match(line)
        if m:
            cur = funcs[m.group(1)] = dict(name=m.group(1), module=m.group(2), addr=m.group(3), mode=m.group(4),
                                            size=m.group(5), unnamed=bool(m.group(6)), lines=[line])
            order.append(m.group(1))
        elif cur is not None and line:
            cur["lines"].append(line)
sites = collections.defaultdict(list)
for f in funcs.values():
    for i, l in enumerate(f["lines"]):
        m = re.search(r"-> (\S+)", l)
        if m and not l.startswith(";"):
            sites[m.group(1)].append((f["name"], i))
refs = set(subprocess.run(["grep", "-rhoE", r"\bfunc_[0-9a-z_]+\b", os.path.join(repo, "src"), os.path.join(repo, "include")],
                          capture_output=True, text=True).stdout.split())
cands = [f for f in funcs.values() if f["unnamed"] and f["name"] not in refs and f["name"] not in skip]
cands.sort(key=lambda f: (-len({c for c, _ in sites[f["name"]]}), f["name"]))
with_ev = [f for f in cands if any("this" in e for e in evidence.get(f["name"], []))]
picked = with_ev[:n_ev]
seen_names = {f["name"] for f in picked}
chosen = picked + [f for f in cands if f["name"] not in seen_names][:nb * bs - len(picked)]
chosen.sort(key=lambda f: (-len({c for c, _ in sites[f["name"]]}), f["name"]))
for b in range(nb):
    out = []
    for f in chosen[b * bs:(b + 1) * bs]:
        callers = {c for c, _ in sites[f["name"]]}
        out += ["=" * 100, f"FUNCTION {f['name']}  module={f['module']} usa_addr={f['addr']} mode={f['mode']} "
                f"size={f['size']} callers={len(callers)}"]
        for e in evidence.get(f["name"], []):
            out.append("; EVIDENCE: " + e)
        out += f["lines"][:160] + ([f"    ... ({len(f['lines']) - 160} more lines)"] if len(f["lines"]) > 160 else [])
        seen = set()
        for caller, i in sites[f["name"]]:
            if caller in seen or len(seen) >= 4:
                continue
            seen.add(caller)
            cl = funcs[caller]["lines"]
            out.append(f"--- call site in {caller} ({funcs[caller]['module']}):")
            out += ["    " + x for x in cl[max(1, i - 8):i + 4] if not x.startswith(";")]
        out.append("")
    open(os.path.join(outdir, f"batch{b + 1}.txt"), "w").write("\n".join(out) + "\n")
print(f"{len(cands)} candidates; wrote {nb} batches of {bs}: callers {len({c for c, _ in sites[chosen[0]['name']]})}"
      f"..{len({c for c, _ in sites[chosen[-1]['name']]})}")
