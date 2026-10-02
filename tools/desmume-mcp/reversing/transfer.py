#!/usr/bin/env python3
"""Turn xmatch pairs into rename proposals for both decomps and apply them.

usage: transfer.py PAIRS.json PH_CHECKOUT ST_CHECKOUT OUTDIR
Writes OUTDIR/{ph,st}-proposals.json, OUTDIR/{ph,st}-source-renames.json
(names only usable with a source change), and applies the plain renames to the
checkouts' config/*/arm9/**/symbols.txt.
"""

import glob
import json
import os
import re
import subprocess
import sys

pairs_path, ph_repo, st_repo, outdir = sys.argv[1:5]
pairs = json.load(open(pairs_path))
# optional: PH names from earlier rounds (merge_names proposals) count as PH names
RANK = {"low": 1, "medium": 2, "high": 3}
earlier = {}
for path in sys.argv[5:]:
    earlier.update({x["old"]: x for x in json.load(open(path))})
for p in pairs:
    if p["ph"] in earlier:
        e = earlier[p["ph"]]
        p["ph_orig"], p["ph"], p["ph_named"], p["ph_informative"] = p["ph"], e["new"], True, True
        p["cap"] = e["confidence"]
os.makedirs(outdir, exist_ok=True)

PLACEHOLDER = re.compile(r"(^|_)func_(ov\d+_)?[0-9a-f]{4,8}$|_func_\d+$|^func_|^ZMB_|^__sinit_|_0[0-9a-f]{7}(_|$)|_ov\d+_[0-9a-f]{8}")
ST_ONLY = re.compile(r"Profile|Unk[A-Z0-9]{4}\b|Unk[A-Z0-9]{4}::")
RUNTIME_TYPES = re.compile(r"ThrowContext|ExceptionInfo|ActionIterator|ExceptionTableIndex|ex_specification|^std::|__cxa|operator ")
PLAIN_OLD = re.compile(r"^(func_(ov\d+_)?[0-9a-f]{8}|[A-Za-z0-9]+_func_(\d{4}|[0-9a-f]{8}))$")


def demangle(names):
    out = subprocess.run(["c++filt"], input="\n".join(names), capture_output=True, text=True).stdout
    return dict(zip(names, out.split("\n")))


dem = demangle(sorted({p["ph"] for p in pairs} | {p["st"] for p in pairs} | {e["new"] for e in earlier.values()}))


def to_plain(name):
    """Name to use in the other decomp, or None if not transferable."""
    d = dem.get(name, name)
    if not name.startswith("_Z"):
        return None if PLACEHOLDER.search(name) else name
    if RUNTIME_TYPES.search(d):
        return name                              # C++ runtime: identical symbol in both toolchains
    m = re.match(r"^(?:(.*)::)?(~?[A-Za-z0-9_]+)\(", d)
    if not m:
        return None
    cls, meth = m.groups()
    if meth.startswith("~") or (cls and meth == cls.split("::")[-1]):
        return None                              # ctor/dtor: shape-alike across classes
    if PLACEHOLDER.search(meth) or meth.startswith("vfunc_"):
        return None
    cls = (cls or "").split("::")[-1].split("<")[0]
    if not cls or cls.startswith("Unk") or PLACEHOLDER.search(cls):
        return meth
    return f"{cls}_{meth}"


def confidence(p):
    how, n, s = p["how"], p["n"], p["sim"]
    lib = p["ph_module"] in ("main", "itcm")
    if how.startswith("samename") or how.startswith("group") or how == "fp:unique":
        return "high" if n >= 3 else None
    if how in ("fp1:unique", "fp2:unique"):
        return ("high" if n >= 8 else "medium") if n >= 4 else None
    if how.endswith("callgraph"):
        return "high" if s >= 0.8 else "medium" if s >= 0.6 else "low"
    s2 = float(how.split(":")[1])
    if n < 6:
        return None
    return "high" if s2 >= 0.8 and lib else "medium" if s2 >= 0.7 else "low"


def symbols(repo):
    files = glob.glob(os.path.join(repo, "config", "*", "arm9", "**", "symbols.txt"), recursive=True)
    names = set()
    for f in files:
        for line in open(f):
            names.add(line.split(" ", 1)[0])
    return files, names


def source_refs(repo):
    out = subprocess.run(["grep", "-rhoE", r"\b[A-Za-z_][A-Za-z0-9_]*func_[A-Za-z0-9_]+\b",
                          os.path.join(repo, "src"), os.path.join(repo, "include")],
                         capture_output=True, text=True).stdout
    return set(out.split())


def build(direction):
    if direction == "ph":
        old_k, new_k, repo, other = "ph", "st", ph_repo, "ST"
        want = lambda p: not p["ph_informative"] and p["st_informative"]
    else:
        old_k, new_k, repo, other = "st", "ph", st_repo, "PH"
        want = lambda p: not p["st_informative"] and p["ph_informative"]
    files, existing = symbols(repo)
    srcrefs = source_refs(repo)
    props, source_only, skipped = [], [], []
    used = set()
    for p in pairs:
        if not want(p):
            continue
        old, src = p[old_k], p[new_k]
        new = to_plain(src)
        conf = confidence(p)
        if conf and p.get("cap") and RANK[p["cap"]] < RANK[conf]:
            conf = p["cap"]
        why = None
        if new is None:
            why = "not transferable (placeholder, ctor/dtor or game-specific class)"
        elif direction == "ph" and ST_ONLY.search(dem.get(src, src)):
            why = "Spirit Tracks specific actor/profile name"
        elif conf is None:
            why = "too short to trust"
        elif new in existing or new in used:
            why = f"{new} already used"
        if why:
            skipped.append(dict(old=old, other=src, why=why, how=p["how"]))
            continue
        if p.get("cap"):
            src_note = f" (PH name from round 1, {p['cap']} confidence)"
        else:
            src_note = ""
        ev = (f"matches {other} `{dem.get(src, src)}` ({p[new_k + '_module']} {p[new_k + '_addr']}); "
              f"match: {p['how']}, similarity {p['sim']:.2f}, {p['n']} instructions{src_note}")
        rec = dict(module=p[old_k + "_module"], addr=p[old_k + "_addr"], old=old, new=new,
                   confidence=conf, kind="cross-game", **{"from": src}, evidence=ev)
        used.add(new)
        if PLAIN_OLD.match(old) and old not in srcrefs:
            props.append(rec)
        else:
            rec["note"] = "old name is used in the decomp source (or is a mangled method); rename there too"
            source_only.append(rec)
    # apply
    ren = {p["old"]: p["new"] for p in props}
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
    json.dump(props, open(os.path.join(outdir, f"{direction}-proposals.json"), "w"), indent=1)
    json.dump(source_only, open(os.path.join(outdir, f"{direction}-source-renames.json"), "w"), indent=1)
    json.dump(skipped, open(os.path.join(outdir, f"{direction}-skipped.json"), "w"), indent=1)
    c = {k: sum(1 for p in props if p["confidence"] == k) for k in ("high", "medium", "low")}
    print(f"{direction}: {len(props)} renames {c}, {changed} symbol lines changed; "
          f"{len(source_only)} need a source change; {len(skipped)} skipped")
    return props, source_only, skipped


build("ph")
build("st")
