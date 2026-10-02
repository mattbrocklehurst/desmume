#!/usr/bin/env python3
"""Resolve RAM addresses to heap objects and pointer paths, from a RAM snapshot.

- heap blocks: 16-byte headers {u16 'UD'=0x5544, u16 attr, u32 size, u32 prev, u32 next}
  right before each allocation; every header whose list links are consistent is taken
- class of an object: its first word when that is a vtable (`_ZTV...` symbol)
- paths: breadth-first from the named globals (DTCM / static data pointers) through
  pointer-sized fields of heap objects, up to MAXDEPTH hops

usage: heap_map.py SNAPSHOT_DIR SYMBOL_CONFIG_DIR ADDRESSES.json OUT.json
  ADDRESSES.json: [{"name": ..., "addr": "0x021b6fac", "size": N}, ...] (addresses in this snapshot's version)
"""
import bisect
import collections
import glob
import json
import os
import re
import struct
import sys

snap, cfg, addr_path, out_path = sys.argv[1:5]
MAXDEPTH = 4
main = open(os.path.join(snap, "main.bin"), "rb").read()
dtcm = open(os.path.join(snap, "dtcm.bin"), "rb").read()
MAIN, DTCM = 0x02000000, 0x027E0000


def rd32(a):
    if MAIN <= a < MAIN + len(main) - 3:
        return struct.unpack_from("<I", main, a - MAIN)[0]
    if DTCM <= a < DTCM + len(dtcm) - 3:
        return struct.unpack_from("<I", dtcm, a - DTCM)[0]
    return None


# symbols: vtables and globals (all modules; overlays may overlap, keep every candidate)
syms = collections.defaultdict(list)
for f in glob.glob(os.path.join(cfg, "**", "symbols.txt"), recursive=True):
    mod = os.path.basename(os.path.dirname(f)) if "/overlays/" in f or f.endswith(("itcm/symbols.txt", "dtcm/symbols.txt")) else "main"
    for line in open(f):
        m = re.match(r"(\S+) kind:(\w+)(?:\(([^)]*)\))? addr:(0x[0-9a-fA-F]+)", line)
        if m:
            size = re.search(r"size=(0x[0-9a-f]+)", m.group(3) or "")
            syms[int(m.group(4), 16)].append((m.group(1), m.group(2), mod, int(size.group(1), 16) if size else 0))
vtables = {a: [s[0] for s in v if s[0].startswith("_ZTV")] for a, v in syms.items()}
vtables = {a: v for a, v in vtables.items() if v}

# heap blocks
blocks = {}
for off in range(0, len(main) - 16, 4):
    if main[off:off + 4] != b"\x44\x55\x00\x00":
        continue
    size, prev, nxt = struct.unpack_from("<III", main, off + 4)
    a = MAIN + off
    if not (0 < size < 0x400000):
        continue
    ok = 0
    for link, back in ((prev, 12), (nxt, 8)):
        if link == 0:
            ok += 1
        elif MAIN <= link < MAIN + len(main) and rd32(link + back) == a:
            ok += 1
    if ok == 2:
        blocks[a + 16] = size
starts = sorted(blocks)


def block_of(addr):
    i = bisect.bisect_right(starts, addr) - 1
    if i >= 0 and addr < starts[i] + blocks[starts[i]]:
        return starts[i]
    return None


def klass(obj):
    """Class names from the object's vtable pointer (it points 8 bytes into _ZTV...: after
    offset-to-top and typeinfo), or None."""
    v = rd32(obj)
    if v is None:
        return None
    return vtables.get(v - 8) or vtables.get(v)


# roots: globals (DTCM / static data) whose first word points into a live heap block.
# Named singletons (gXxx) first, then DTCM data, then the rest, so the shortest path
# prefers the names code actually uses.
roots = []
for a, v in syms.items():
    for name, kind, mod, size in v:
        if kind not in ("data", "bss") or not (0x02000000 <= a < 0x02400000 or DTCM <= a < DTCM + 0x4000):
            continue
        p = rd32(a)
        if p is not None and block_of(p) is not None:
            rank = 0 if re.match(r"^g[A-Z]", name) else 1 if DTCM <= a else 2
            roots.append((rank, name, p))
roots.sort()
# BFS over pointer values, in the form the code scanner records accesses:
# key = ROOT/off1/off2 + final, every offset relative to the pointer value held in a register
paths = {}                      # pointer value -> (root, (off1, off2, ...))
queue = collections.deque()
for rank, name, p in roots:
    if p not in paths:
        paths[p] = (name, ())
        queue.append(p)
while queue:
    p = queue.popleft()
    root, hops = paths[p]
    if len(hops) >= MAXDEPTH:
        continue
    b = block_of(p)
    for f in range(0, b + min(blocks[b], 0x1000) - p, 4):
        q = rd32(p + f)
        if q is not None and q not in paths and block_of(q) is not None:
            paths[q] = (root, hops + (f,))
            queue.append(q)
by_block = collections.defaultdict(list)
for q, pv in paths.items():
    by_block[block_of(q)].append((len(pv[1]), q, pv))

res = []
for e in json.load(open(addr_path)):
    a = int(e["addr"], 16)
    b = block_of(a)
    r = dict(e)
    if b is None:
        r["where"] = "not in a live heap block"
    else:
        r.update(block=hex(b), block_size=hex(blocks[b]), offset=hex(a - b), cls=klass(b))
        cands = sorted(x for x in by_block.get(b, []) if x[1] <= a)
        if cands:
            _, q, (root, hops) = cands[0]
            r["key"] = root + "".join(f"/{h:#x}" for h in hops) + f"+{a - q:#x}"
            r["hops"] = len(hops)
    res.append(r)
census = collections.defaultdict(lambda: {"count": 0, "sizes": set(), "paths": []})
for b0 in starts:
    k = klass(b0)
    if not k:
        continue
    c = census[" / ".join(k)]
    c["count"] += 1
    c["sizes"].add(blocks[b0])
    for x in sorted(by_block.get(b0, [])):
        if x[1] == b0 and len(c["paths"]) < 3:
            c["paths"].append(x[2][0] + "".join(f"/{h:#x}" for h in x[2][1]))
json.dump({"addresses": res, "classes": {k: {"count": v["count"], "sizes": sorted(hex(z) for z in v["sizes"]),
                                             "paths": v["paths"]} for k, v in sorted(census.items())}},
          open(out_path, "w"), indent=1)
print(f"{len(census)} classes identified on the heap")
reach = sum(1 for r in res if r.get("key"))
print(f"{len(blocks)} heap blocks, {len(roots)} roots, {len(paths)} blocks reachable; "
      f"{sum(1 for r in res if 'block' in r)}/{len(res)} addresses in a block, {reach} with a path")
