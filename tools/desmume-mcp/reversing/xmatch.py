#!/usr/bin/env python3
"""Cross-game function matching between two ph_export.py exports (PH <-> ST).

Stages (each followed by call-graph propagation):
  0. anchors: functions both decomps already give the same (real) name
  1. exact code (addresses masked), unique on both sides
  2. immediates masked, then mnemonic sequence only
  3. identical code groups split by what the functions reference / who calls them
  4. fuzzy: bag-of-instructions similarity, candidates sharing a rare anchor
     (string, I/O register, constant, matched callee/caller); accepted only when
     mutual best with a margin over the runner-up. Iterated with 3.
Call-graph propagation: in a matched pair whose reference lists have equal
length, the n-th call / function pointer of one lines up with the n-th of the
other; aligned targets with compatible code are matched.

usage: xmatch.py PH_EXPORT ST_EXPORT OUT.json
"""

import collections
import glob
import hashlib
import json
import os
import re
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import structsig  # noqa: E402

HDR = re.compile(r"^## (\S+)  \[(\S+) (0x[0-9a-f]+) (arm|thumb) size (0x[0-9a-f]+)( UNNAMED)?\]")
CC = "eq|ne|cs|hs|cc|lo|mi|pl|vs|vc|hi|ls|ge|lt|gt|le|al"
BR = re.compile(rf"^(b|bl|blx)({CC})?(\.[nw])?$")
IMM = re.compile(r"#-?(0x[0-9a-f]+|\d+)")
IMM_TGT = re.compile(r"#0x([0-9a-f]+)")
REG = re.compile(r"\b(r\d+|ip|sp|lr|pc|sb|sl|fp)\b")
PLACEHOLDER = re.compile(r"(?i)(?:^FUN_|^sub_)|(^|_)func_(ov\d+_)?[0-9a-f]{4,8}$|_func_\d+$|^func_|^ZMB_|^__sinit_")


def is_addr(v):
    return 0x02000000 <= v < 0x02400000 or 0x027e0000 <= v < 0x02800000 or 0x01ff8000 <= v < 0x02000000


def load(export):
    funcs = {}
    for path in sorted(glob.glob(os.path.join(export, "asm", "*.s"))):
        cur = None
        for line in open(path, errors="replace"):
            line = line.rstrip("\n")
            m = HDR.match(line)
            if m:
                name, mod, addr, mode, size, un = m.groups()
                cur = funcs[name] = dict(name=name, module=mod, addr=int(addr, 16), mode=mode,
                                         size=int(size, 16), named=not un, ins=[], refs=[],
                                         anchors=set(), callers=set(), raw=[])
                continue
            if cur is None or not line or line.startswith(";") or line.startswith("##"):
                continue
            if ": " not in line[:10]:
                continue
            text = line[10:]
            comment = ""
            if "  ;" in text:
                text, comment = text.split("  ;", 1)
            for s in re.findall(r'"([^"]{4,})"', line):
                cur["anchors"].add("S:" + s)
            for r in re.findall(r"\b(REG_[A-Z0-9_]+)", line):
                cur["anchors"].add("IO:" + r)
            ref = None
            if "-> " in comment:
                ref = comment.split("-> ", 1)[1].split()[0]
            cur["raw"].append((int(line[:8], 16), text.strip(), comment, ref))
            if text.startswith(".word"):
                v = int(text.split()[1], 16)
                body = text[:text.index("<")].strip() if "<" in text else text.strip()
                if is_addr(v):
                    norm = ".word A"
                    rname = None
                    mm = re.search(r"<([^>]+)>", text)
                    if mm and "+" not in mm.group(1):
                        rname = mm.group(1)
                    else:
                        parts = body.split()
                        if len(parts) >= 3:
                            rname = parts[2]
                    cur["refs"].append(rname)
                else:
                    norm = ".word " + body.split()[1]
                    if v > 0xff and not 0x04000000 <= v < 0x04200000:
                        cur["anchors"].add(f"K:{v:x}")
            else:
                op = text.split(" ", 1)[0]
                norm = text.strip()
                if BR.match(op):
                    m2 = IMM_TGT.search(norm)
                    if m2:
                        t = int(m2.group(1), 16)
                        base = cur["addr"]
                        if base <= t < base + cur["size"]:
                            norm = norm[:m2.start()] + f"#L{t - base:x}"
                        else:
                            norm = norm[:m2.start()] + "#X"
                            cur["refs"].append(ref)
                elif ref:
                    cur["refs"].append(ref)
                else:
                    for k in IMM.findall(norm):
                        v = int(k, 0)
                        if v > 0xff and not is_addr(v):
                            cur["anchors"].add(f"K:{v:x}")
            cur["ins"].append(norm)
    for f in funcs.values():
        ins = f["ins"]
        f["n"] = len(ins)
        h = lambda xs: hashlib.sha1("\n".join(xs).encode()).hexdigest()[:16]
        f["fp"] = (f["mode"], f["size"], h(ins))
        f["fp1"] = (f["mode"], h(IMM.sub("#I", x) if not x.startswith(".word") else ".word" for x in ins))
        f["fp2"] = (f["mode"], h(x.split(" ", 1)[0] for x in ins))
        del f["ins"]
    for f in funcs.values():
        for r in f["refs"]:
            if r in funcs:
                funcs[r]["callers"].add(f["name"])
    # return value: does any caller read r0 after the call before writing it?
    for f in funcs.values():
        f["ret"] = None
    for f in funcs.values():
        raw = [x for x in f["raw"] if not x[1].startswith(".word")]
        for i, (a, t, c, ref) in enumerate(raw):
            if ref not in funcs or not re.match(r"^(bl|blx) #", t):
                continue
            for a2, t2, c2, r2 in raw[i + 1:i + 8]:
                mn, _, ops = t2.partition(" ")
                if mn.startswith("b") and len(mn) <= 3 and mn not in ("bic", "bics"):
                    break
                rd, wr = structsig.rw(structsig.split_cond(mn, BASES)[0], ops)
                if 0 in rd:
                    funcs[ref]["ret"] = True
                    break
                if 0 in wr:
                    if funcs[ref]["ret"] is None:
                        funcs[ref]["ret"] = False
                    break
    return funcs


BASES = set()


def add_bases(*exports):
    for e in exports:
        for path in glob.glob(os.path.join(e, "asm", "*.s")):
            for line in open(path, errors="replace"):
                if len(line) > 10 and line[8:10] == ": " and not line[10:].startswith("."):
                    BASES.add(line[10:].split(" ", 1)[0].strip())


def compute_sigs(funcs, names, ref_id):
    for n in names:
        f = funcs[n]
        try:
            f["sig"] = structsig.signature(f, f["raw"], BASES, ref_id)
        except (IndexError, ValueError, KeyError):
            f["sig"] = None


def informative(name):
    """Names worth transferring (not address/number placeholders)."""
    if name.startswith("_Z"):
        return not re.search(r"(?i)func_|vfunc_", name) and not re.search(r"Unk\w*C[12]E|Unk\w*D[012]E", name)
    return not PLACEHOLDER.search(name)


EXACT = bool(os.environ.get("XM_EXACT"))
HOLDOUT = bool(os.environ.get("XM_HOLDOUT"))   # blind test: half of side A may only match structurally


def held(name):
    import zlib
    return HOLDOUT and zlib.crc32(name.encode()) % 2 == 0


def main():
    ph_dir, st_dir, out = sys.argv[1:4]
    add_bases(ph_dir, st_dir)
    ph, st = load(ph_dir), load(st_dir)
    print(f"PH {len(ph)} functions, ST {len(st)} functions")

    pairs, rev = {}, {}
    bad_ph, bad_st = set(), set()

    def add(a, b, how):
        if a in bad_ph or b in bad_st:
            return False
        if held(a) and not how.startswith("struct"):
            return False
        if a in pairs or b in rev:
            if pairs.get(a, (None,))[0] != b:
                for x in (a, rev.get(b)):
                    if x in pairs:
                        y = pairs.pop(x)[0]
                        rev.pop(y, None)
                        bad_ph.add(x)
                        bad_st.add(y)
                bad_ph.add(a)
                bad_st.add(b)
            return False
        pairs[a] = (b, how)
        rev[b] = a
        return True

    def refresh(all_=False):
        """(Re)compute structural signatures; calls to matched functions carry the pair's id."""
        compute_sigs(ph, [n for n in ph if all_ or n not in pairs], lambda n: pairs[n][0] if n in pairs else None)
        compute_sigs(st, [n for n in st if all_ or n not in rev], lambda n: n if n in rev else None)

    def sim(fx, fy):
        """Structural agreement: 1.0 same graph and constants, 0.95 same graph with immediates masked,
        else the share of identical blocks (x0.8 if the graph shape differs). ABI must agree."""
        a, b = fx.get("sig"), fy.get("sig")
        if not a or not b or fx["mode"] != fy["mode"]:
            return 0.0
        if a["arity"] != b["arity"]:
            return 0.0
        if fx["ret"] is not None and fy["ret"] is not None and fx["ret"] != fy["ret"]:
            return 0.0
        if a["strict"] == b["strict"]:
            return 1.0
        if a["loose"] == b["loose"]:
            return 0.95
        ov = structsig.block_overlap(a, b)
        return ov if a["shape"] == b["shape"] else 0.8 * ov

    def compatible(x, y):
        fx, fy = ph[x], st[y]
        if fx["mode"] != fy["mode"] or fx["n"] < 2:
            return False
        if EXACT:
            return fx["fp1"] == fy["fp1"]          # identical code (addresses/immediates masked) only
        if fx["fp1"] == fy["fp1"] and not held(x):
            return True
        a, b = fx.get("sig"), fy.get("sig")
        if not a or not b or a["arity"] != b["arity"] or \
                (fx["ret"] is not None and fy["ret"] is not None and fx["ret"] != fy["ret"]):
            return False
        return (a["sketch"] == b["sketch"] and a["info"] >= 2) or (a["flat"] == b["flat"] and a["known_calls"] >= 2)

    def propagate(tag):
        changed, total = True, 0
        while changed:
            changed = False
            for a, (b, _) in list(pairs.items()):
                ra, rb = ph[a]["refs"], st[b]["refs"]
                if len(ra) != len(rb):
                    continue
                for x, y in zip(ra, rb):
                    if x in ph and y in st and x not in pairs and y not in rev and compatible(x, y):
                        if add(x, y, tag):
                            changed = True
                            total += 1
        return total

    if not EXACT:
        refresh(True)
    n = 0
    for name, f in ph.items():
        if f["named"] and name in st and st[name]["named"] and informative(name) and f["mode"] == st[name]["mode"]:
            n += add(name, name, "samename")
    g = propagate("samename:callgraph")
    print(f"samename: {n}, {g} via call graph")

    for key, minlen in (("fp", 1), ("fp1", 4)):
        by_ph, by_st = collections.defaultdict(list), collections.defaultdict(list)
        for f in ph.values():
            if f["name"] not in pairs and f["n"] >= minlen:
                by_ph[f[key]].append(f["name"])
        for f in st.values():
            if f["name"] not in rev and f["n"] >= minlen:
                by_st[f[key]].append(f["name"])
        n0 = len(pairs)
        for fp, names in by_ph.items():
            if len(names) == 1 and len(by_st.get(fp, ())) == 1:
                add(names[0], by_st[fp][0], key + ":unique")
        n1 = len(pairs)
        g = propagate(key + ":callgraph")
        print(f"{key}: {n1 - n0} unique, {g} via call graph -> {len(pairs)} pairs")

    def sig_ph(f, which):
        if which == 0:
            return tuple(pairs[r][0] if r in pairs else None for r in f["refs"])
        return frozenset(pairs[c][0] for c in f["callers"] if c in pairs)

    def sig_st(f, which):
        if which == 0:
            return tuple(r if r in rev else None for r in f["refs"])
        return frozenset(c for c in f["callers"] if c in rev)

    for it in range(10):
        n0 = len(pairs)
        by_ph, by_st = collections.defaultdict(list), collections.defaultdict(list)
        for f in ph.values():
            if f["name"] not in pairs:
                by_ph[f["fp"]].append(f)
        for f in st.values():
            if f["name"] not in rev:
                by_st[f["fp"]].append(f)
        for fp, fs in by_ph.items():
            gs = by_st.get(fp)
            if not gs:
                continue
            for which in (0, 1):
                sa, sb = collections.defaultdict(list), collections.defaultdict(list)
                for f in fs:
                    s = sig_ph(f, which)
                    if any(x is not None for x in s):
                        sa[s].append(f["name"])
                for f in gs:
                    s = sig_st(f, which)
                    if any(x is not None for x in s):
                        sb[s].append(f["name"])
                for s, xs in sa.items():
                    ys = sb.get(s, ())
                    if len(xs) == 1 and len(ys) == 1 and xs[0] not in pairs and ys[0] not in rev:
                        add(xs[0], ys[0], "group:" + ("refs" if which == 0 else "callers"))
        n1 = len(pairs)
        if EXACT:
            print(f"iter {it}: {n1 - n0} group splits -> {len(pairs)} pairs")
            if len(pairs) == n0:
                break
            continue

        refresh()
        for key, tag, ok in (
                (lambda f: (f["mode"], f["sig"]["sketch"], f["sig"]["arity"], f["ret"]), "struct:graph",
                 lambda s: s["info"] >= 3 and s["known_calls"] >= 1),
                (lambda f: (f["mode"], f["sig"]["flat"], f["sig"]["arity"], f["ret"]), "struct:calls",
                 lambda s: s["known_calls"] >= 2)):
            ka, kb = collections.defaultdict(list), collections.defaultdict(list)
            for f in ph.values():
                if f["name"] not in pairs and f.get("sig") and ok(f["sig"]):
                    ka[key(f)].append(f["name"])
            for f in st.values():
                if f["name"] not in rev and f.get("sig") and ok(f["sig"]):
                    kb[key(f)].append(f["name"])
            for k, xs in ka.items():
                if len(xs) == 1 and len(kb.get(k, ())) == 1:
                    add(xs[0], kb[k][0], tag)
        n1b = len(pairs)

        n2 = len(pairs)
        g = propagate("struct:callgraph")      # tagged struct: held-out functions may join here
        print(f"iter {it}: {n1 - n0} group splits, {n1b - n1} structurally unique, {n2 - n1b} structural "
              f"best match, {g} via call graph -> {len(pairs)} pairs")
        if len(pairs) == n0:
            break
    print(f"{len(bad_ph)} PH / {len(bad_st)} ST dropped as conflicting")

    def order(funcs):
        by_mod = collections.defaultdict(list)
        for f in funcs.values():
            by_mod[f["module"]].append((f["addr"], f["name"]))
        pos = {}
        seq = {}
        for m, lst in by_mod.items():
            lst.sort()
            seq[m] = [n for _, n in lst]
            for i, (_, n) in enumerate(lst):
                pos[n] = (m, i)
        return pos, seq

    pos_a, seq_a = order(ph)
    pos_b, seq_b = order(st)

    def support(a, b):
        """Evidence beyond a's own code: callers/callees matched to b's callers/callees, plus
        address neighbours (linker keeps each object file's functions together, in order)
        matched to functions next to b."""
        na = set(r for r in ph[a]["refs"] if r in ph) | ph[a]["callers"]
        nb = set(r for r in st[b]["refs"] if r in st) | st[b]["callers"]
        s = sum(1 for x in na if x in pairs and pairs[x][0] in nb)
        (ma, ia), (mb, ib) = pos_a[a], pos_b[b]
        for d in (-2, -1, 1, 2):
            j = ia + d
            if 0 <= j < len(seq_a[ma]):
                x = seq_a[ma][j]
                if x in pairs:
                    y = pairs[x][0]
                    if pos_b[y][0] == mb and 0 < abs(pos_b[y][1] - ib) <= 3:
                        s += 1
        return s

    res = []
    for a, (b, how) in pairs.items():
        fa, fb = ph[a], st[b]
        res.append(dict(ph=a, st=b, how=how, ph_module=fa["module"], ph_addr=hex(fa["addr"]),
                        st_module=fb["module"], st_addr=hex(fb["addr"]), mode=fa["mode"],
                        size=fa["size"], st_size=fb["size"], n=fa["n"],
                        sim=1.0 if EXACT else round(sim(fa, fb), 3),
                        support=support(a, b), ph_named=fa["named"], st_named=fb["named"],
                        ph_informative=fa["named"] and informative(a),
                        st_informative=fb["named"] and informative(b)))
    json.dump(res, open(out, "w"), indent=0)
    print(f"wrote {out}")


if __name__ == "__main__":
    main()
