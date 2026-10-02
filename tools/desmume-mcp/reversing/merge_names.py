#!/usr/bin/env python3
"""Merge naming proposals (results*.json) into a zeldaret/ph checkout.

Validates names (C identifiers, not an existing symbol, no duplicates), applies
them by name to config/usa and config/eur symbols.txt, and writes a markdown
report. usage: merge_names.py PH_CHECKOUT RESULTS_DIR OUT_REPORT [--min medium]
"""

import glob
import json
import os
import re
import sys

ph, results_dir, report_path = sys.argv[1:4]
min_conf = sys.argv[sys.argv.index("--min") + 1] if "--min" in sys.argv else "low"
RANK = {"high": 3, "medium": 2, "low": 1}

proposals = []
for p in sorted(glob.glob(os.path.join(results_dir, "results*.json"))):
    try:
        proposals += [dict(x, batch=os.path.basename(p)) for x in json.load(open(p))]
    except (ValueError, OSError) as e:
        print(f"skipping {p}: {e}")

files = glob.glob(os.path.join(ph, "config", "*", "arm9", "**", "symbols.txt"), recursive=True)
existing = set()
for f in files:
    for line in open(f):
        existing.add(line.split(" ", 1)[0])

accepted, rejected = [], []
seen_old, seen_new = {}, {}
for p in proposals:
    old, new, conf = p.get("old", ""), p.get("new", ""), p.get("confidence", "low")
    why = None
    if not re.match(r"^func_(ov\d+_)?[0-9a-f]{8}$", old) or old not in existing:
        why = "unknown old name"
    elif not re.match(r"^[A-Za-z_][A-Za-z0-9_]*$", new) or new.startswith(("func_", "data_")):
        why = "invalid new name"
    elif new in existing:
        why = f"{new} already exists"
    elif RANK.get(conf, 0) < RANK[min_conf]:
        why = f"confidence {conf} below {min_conf}"
    elif old in seen_old:
        why = f"duplicate proposal for {old}"
    elif new in seen_new:
        why = f"{new} also proposed for {seen_new[new]}"
    if why:
        rejected.append((p, why))
        continue
    seen_old[old] = p
    seen_new[new] = old
    accepted.append(p)

renames = {p["old"]: p["new"] for p in accepted}
changed = 0
for f in files:
    lines = open(f).read().split("\n")
    out = []
    for line in lines:
        name = line.split(" ", 1)[0]
        if name in renames:
            line = renames[name] + line[len(name):]
            changed += 1
        out.append(line)
    open(f, "w").write("\n".join(out))

by_conf = {c: [p for p in accepted if p["confidence"] == c] for c in ("high", "medium", "low")}
lines = ["# Round 1: names for the most-called unnamed functions", "",
         f"{len(accepted)} names accepted ({len(by_conf['high'])} high, {len(by_conf['medium'])} medium, "
         f"{len(by_conf['low'])} low confidence), {len(rejected)} rejected; {changed} symbol lines renamed "
         f"(USA and EU configs).", "",
         "Confidence: **high** = behaviour certain and the name says exactly that; **medium** = behaviour "
         "clear, purpose in the game inferred; **low** = reasonable guess. Every name carries its evidence "
         "so it can be checked in the disassembly.", ""]
for conf in ("high", "medium", "low"):
    if not by_conf[conf]:
        continue
    lines += [f"## {conf.capitalize()} confidence ({len(by_conf[conf])})", "",
              "| module | old | new | kind | class | evidence |", "|---|---|---|---|---|---|"]
    for p in sorted(by_conf[conf], key=lambda p: (p.get("module", ""), p["old"])):
        ev = p.get("evidence", "").replace("|", "\\|").replace("\n", " ")
        lines.append(f"| {p.get('module', '')} | {p['old']} | `{p['new']}` | {p.get('kind', '')} | "
                     f"{p.get('class') or ''} | {ev} |")
    lines.append("")
if rejected:
    lines += ["## Rejected by validation", "", "| old | proposed | reason |", "|---|---|---|"]
    lines += [f"| {p.get('old')} | {p.get('new')} | {why} |" for p, why in rejected]
open(report_path, "w").write("\n".join(lines) + "\n")
print(f"accepted {len(accepted)} ({len(by_conf['high'])} high / {len(by_conf['medium'])} medium / "
      f"{len(by_conf['low'])} low), rejected {len(rejected)}, renamed {changed} lines")
