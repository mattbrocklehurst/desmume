#!/usr/bin/env python3
"""Official NitroSDK/NitroSystem/DWC names from a reference export (Pokemon Platinum)
onto a decomp, on top of earlier rename rounds.

usage: transfer_official.py PAIRS.json REPO OUTDIR LABEL GAME_DEFS.txt [EARLIER_PROPOSALS.json ...]
PAIRS.json from `XM_EXACT=1 xmatch.py TARGET_EXPORT PLATINUM_EXPORT` (keys: ph = target, st = reference).
REPO must already have the earlier rounds' patches applied.

For every exactly matched function:
  current name == official            -> confirmed
  current name is a placeholder        -> renamed to the official name
  current name came from our rounds    -> corrected to the official name
  current name chosen by the decomp    -> listed as a suggestion (not applied)
"""
import collections
import glob
import json
import os
import re
import subprocess
import sys

pairs_path, repo, outdir, label, game_defs_path = sys.argv[1:6]
earlier_paths = sys.argv[6:]
# functions defined in the reference game's own code (pokeplatinum src/ and asm/): not library names
GAME_DEFS = set(open(game_defs_path).read().split())
os.makedirs(outdir, exist_ok=True)
PLACEHOLDER = re.compile(r"(?i)^(func|FUN|sub|data)_(ov\d+_)?[0-9a-f]{8}$|^ov\d+_[0-9a-f]{8}$|_func_\d+$|"
                         r"(^|_)func_(ov\d+_)?[0-9a-f]{4,8}$|^__sinit_")
strip = lambda n: n.split("@")[0]

cur = {}            # export name -> current name after the earlier rounds
ours = set()        # names introduced by our rounds
for p in earlier_paths:
    for x in json.load(open(p)):
        for k, v in list(cur.items()):
            if v == x["old"]:
                cur[k] = x["new"]
        cur.setdefault(x["old"], x["new"])
        ours.add(x["new"])

files = glob.glob(os.path.join(repo, "config", "*", "arm9", "**", "symbols.txt"), recursive=True) + \
    glob.glob(os.path.join(repo, "config", "arm9", "**", "symbols.txt"), recursive=True)
existing = collections.Counter()
for f in files:
    for line in open(f):
        existing[line.split(" ", 1)[0]] += 0 or 1
srcrefs = set(subprocess.run(["grep", "-rhoE", r"\b[A-Za-z_][A-Za-z0-9_]*\b",
                              *[os.path.join(repo, d) for d in ("src", "include") if os.path.isdir(os.path.join(repo, d))]],
                             capture_output=True, text=True).stdout.split())

pairs = json.load(open(pairs_path))
official_count = collections.Counter(strip(p["st"]) for p in pairs)
confirmed, renames, suggestions, skipped = [], [], [], []
taken = {}
for p in pairs:
    off = strip(p["st"])
    if not p["st_informative"] or PLACEHOLDER.search(off):
        continue
    c = cur.get(p["ph"], p["ph"])
    rec = dict(module=p["ph_module"], addr=p["ph_addr"], old=c, new=off, how=p["how"], n=p["n"],
               platinum=p["st"], platinum_addr=p["st_addr"])
    if c == off:
        confirmed.append(rec)
        continue
    why = None
    if off in GAME_DEFS:
        why = "Pokemon Platinum game function, not a library one"
    elif p["n"] < 4 and p["how"] in ("fp:unique", "fp1:unique", "fp2:unique"):
        why = "3 instructions or fewer: identical code proves little"
    elif off in existing and off != c:
        why = f"{off} is already the name of another function in the decomp"
    elif off in taken and official_count[off] > 1:
        # a static function present in several libraries: number the copies
        k = 2
        while f"{off}_{k}" in taken or f"{off}_{k}" in existing:
            k += 1
        off = rec["new"] = f"{off}_{k}"
        rec["note"] = "static function present in several libraries; copies numbered"
    elif off in taken:
        why = f"{off} also matched {taken[off]}"
    if PLACEHOLDER.search(c) or c.startswith(("OS_func_", "GX_func_")):
        kind = "placeholder"
    elif c in ours:
        kind = "corrected (our earlier round)"
    else:
        kind = "decomp name"
    rec["kind"] = kind
    rec["confidence"] = "high" if p["how"].split(":")[0] in ("fp", "fp1", "samename", "group") else "medium"
    if why:
        rec["why"] = why
        skipped.append(rec)
    elif kind == "decomp name" or c in srcrefs:
        rec["note"] = "used in the decomp source" if c in srcrefs else "name chosen by the decomp"
        suggestions.append(rec)
    else:
        taken[off] = c
        renames.append(rec)

ren = {r["old"]: r["new"] for r in renames}
changed = 0
for f in files:
    lines = open(f).read().split("\n")
    out = []
    for line in lines:
        name = line.split(" ", 1)[0]
        if name in ren:
            line = ren[name] + line[len(name):]
            changed += 1
        out.append(line)
    open(f, "w").write("\n".join(out))
for n, v in (("renames", renames), ("suggestions", suggestions), ("skipped", skipped), ("confirmed", confirmed)):
    json.dump(v, open(os.path.join(outdir, f"{label}-{n}.json"), "w"), indent=1)
k = collections.Counter(r["kind"] for r in renames)
print(f"{label}: {len(renames)} renames {dict(k)}, {changed} symbol lines; {len(confirmed)} confirmed; "
      f"{len(suggestions)} suggestions; {len(skipped)} skipped")
