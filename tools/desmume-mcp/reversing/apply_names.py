#!/usr/bin/env python3
"""Rewrite a ph_export-style export with names from later rename rounds.

usage: apply_names.py EXPORT_DIR OUT_DIR ROUND.json [ROUND.json ...]
Each ROUND.json is a list of {"old": ..., "new": ...} in the order applied
(merge_names / transfer / transfer_official output). Names are replaced as
whole tokens everywhere (headers, calls, pointers, caller lists, index.tsv);
renamed functions lose their UNNAMED mark.
"""
import json
import os
import re
import shutil
import sys

src, dst, *rounds = sys.argv[1:]
final = {}                      # export name -> final name
for path in rounds:
    for x in json.load(open(path)):
        old, new = x["old"], x["new"]
        hit = [k for k, v in final.items() if v == old]
        for k in hit:
            final[k] = new
        if not hit:
            final[old] = new
final = {k: v for k, v in final.items() if k != v}
TOK = re.compile(r"[A-Za-z_][A-Za-z0-9_@]*")
sub = lambda s: TOK.sub(lambda m: final.get(m.group(0), m.group(0)), s)

if os.path.exists(dst):
    shutil.rmtree(dst)
os.makedirs(os.path.join(dst, "asm"))
for name in sorted(os.listdir(os.path.join(src, "asm"))):
    out = []
    for line in open(os.path.join(src, "asm", name), errors="replace"):
        if line.startswith("## "):
            fname = line[3:].split(" ", 1)[0]
            if fname in final:
                line = line.replace(" UNNAMED]", "]")
        out.append(sub(line))
    open(os.path.join(dst, "asm", name), "w").write("".join(out))
rows = []
for i, line in enumerate(open(os.path.join(src, "index.tsv"))):
    r = line.rstrip("\n").split("\t")
    if i and len(r) > 6 and r[5] in final:
        r[5], r[6] = final[r[5]], "1"
    rows.append("\t".join(r))
open(os.path.join(dst, "index.tsv"), "w").write("\n".join(rows) + "\n")
for extra in ("summary.json", "README.txt"):
    if os.path.exists(os.path.join(src, extra)):
        shutil.copy(os.path.join(src, extra), dst)
print(f"{len(final)} names applied -> {dst}")
