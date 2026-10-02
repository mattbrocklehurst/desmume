#!/usr/bin/env python3
"""One exact-matching transfer pass. Candidates come from XM_EXACT xmatch pair files.

Rules (all must hold):
  - the target function still has a placeholder name; the source name is real
  - code identical (addresses / immediates masked), or call-graph / group evidence
  - fewer than 8 instructions: at least one supporting neighbour (a matched caller/callee,
    or an address neighbour matched next to the partner)
  - across different engines (anything but PH<->ST) only library names (NitroSDK,
    NitroSystem, WiFi/DWC/GameSpy, SPL, MSL) move; ctor/dtor and placeholder-ish names never
usage: pass_exact.py CONFIG.json
"""
import collections
import json
import re
import sys

cfg = json.load(open(sys.argv[1]))
LIB = set(open(cfg["lib_names"]).read().split())
PL = re.compile(r"(?i)^(func|FUN|sub|data)_(ov\d+_)?[0-9a-f]{8}$|^ov\d+_[0-9a-f]{8}$|_func_\d+$|"
                r"(^|_)func_(ov\d+_)?[0-9a-f]{4,8}$|^__sinit_|^_Z.*func_|^_Z.*Unk_[0-9a-f]{8}|Func_[0-9A-Fa-f]{8}|"
                r"_0[0-9a-f]{7}(_|$)|_ov\d+_[0-9a-f]{8}")
strip = lambda n: n.split("@")[0]


def ctor_dtor(n):
    return bool(re.search(r"C[12]E|D[012]E", n)) if n.startswith("_Z") else False


out = collections.defaultdict(list)
for job in cfg["jobs"]:
    pairs = json.load(open(job["pairs"]))
    for p in pairs:
        for tgt_key, src_key, tgt_game, src_game in (("ph", "st", job["a"], job["b"]), ("st", "ph", job["b"], job["a"])):
            if tgt_game not in cfg["targets"]:
                continue
            old, src = p[tgt_key], strip(p[src_key])
            if not PL.search(old) or PL.search(src) or ctor_dtor(src) or ctor_dtor(old):
                continue
            same_engine = {tgt_game, src_game} <= {"ph", "st"}
            if not same_engine and src not in LIB:
                continue
            if same_engine and src.startswith("_Z") and not src in LIB:
                continue           # engine methods: class names differ between the decomps
            n, how, sup = p["n"], p["how"], p.get("support", 0)
            if n < 4 and not how.endswith("callgraph") and not how.startswith(("group", "samename")):
                continue
            if n < 8 and sup == 0 and how in ("fp:unique", "fp1:unique", "struct:graph", "struct:calls"):
                continue
            out[tgt_game].append(dict(old=old, new=src, source_game=src_game, source_name=p[src_key], how=how,
                                      n=n, support=sup, module=p[tgt_key + "_module"], addr=p[tgt_key + "_addr"],
                                      confidence="high"))
res = {}
for g, lst in out.items():
    by_old = collections.defaultdict(list)
    for r in lst:
        by_old[r["old"]].append(r)
    keep, conflicts = [], []
    for old, rs in by_old.items():
        names = {r["new"] for r in rs}
        if len(names) == 1:
            r = dict(rs[0])
            r["sources"] = sorted({x["source_game"] for x in rs})
            keep.append(r)
        else:
            conflicts.append({"old": old, "candidates": sorted(names), "sources": [(x["source_game"], x["new"]) for x in rs]})
    cnt = collections.Counter(r["new"] for r in keep)
    dup = [r for r in keep if cnt[r["new"]] > 1]
    keep = [r for r in keep if cnt[r["new"]] == 1]
    res[g] = keep
    json.dump(keep, open(f"{cfg['out']}/{g}-pass.json", "w"), indent=1)
    json.dump({"conflicts": conflicts, "duplicate_new_names": dup}, open(f"{cfg['out']}/{g}-pass-rejected.json", "w"), indent=1)
    print(f"{g}: {len(keep)} names ({collections.Counter(s for r in keep for s in r['sources'])}), "
          f"{len(conflicts)} conflicting, {len(dup)} duplicate names dropped")
