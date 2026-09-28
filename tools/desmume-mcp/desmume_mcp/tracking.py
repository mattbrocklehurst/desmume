"""Higher level analyses over hook records: asset (file) loads, allocation
tracking, and flow graphs of what triggered what."""

import html
import os
import re
from collections import OrderedDict, defaultdict

from .memory import find_function_start

REGS = {"r0": 0, "r1": 1, "r2": 2, "r3": 3}


def func_name(session, src, addr):
    """Name of the function containing addr: a label, else sub_XXXXXXXX
    (from the nearest preceding push), else the address."""
    d = session.labels.describe(addr & ~1)
    if d:
        return d.split("+")[0]
    start = find_function_start(src, addr)
    if start is None:
        start = find_function_start(src, addr | 1)
    if start is not None:
        name = session.labels.describe(start & ~1)
        return name.split("+")[0] if name else f"sub_{start & ~1:08x}"
    return f"{addr & ~1:#010x}"


def call_path(session, src, rec, depth=8):
    """[outermost function, ..., innermost function] for a record."""
    names = []
    for site in session.chain_sites(rec, src)[:depth]:
        n = func_name(session, src, site)
        if not names or names[-1] != n:
            names.append(n)
    return list(reversed(names))


# ---------------------------------------------------------------------------
# asset loads


def group_loads(session, card_records, dma_records):
    """Group card reads into file loads. Consecutive reads of the same file
    from the same call path (ignoring the innermost frames that read one
    block) make one load."""
    src = session.source(None, "arm9")
    loads = []
    for r in card_records:
        a = r["args"]
        if a[0] >> 24 != 0xB7:
            continue
        kind, name, offset = session.rom.file_at(a[3])
        path = call_path(session, src, r)
        key_path = path[:-2] if len(path) > 2 else path
        last = loads[-1] if loads else None
        if (last and last["file"] == name and last["key"] == key_path
                and r["seq"] - last["last_seq"] < 64):
            last["reads"] += 1
            last["bytes"] += a[2]
            last["last_seq"] = r["seq"]
            last["last_frame"] = r["frame"]
            last["offsets"].append(offset)
            continue
        loads.append({"file": name, "kind": kind, "rom_offset": a[3], "offsets": [offset], "reads": 1,
                      "bytes": a[2], "frame": r["frame"], "last_frame": r["frame"], "first_seq": r["seq"],
                      "last_seq": r["seq"], "path": path, "key": key_path, "record": r,
                      "dma_dst": None})
    # card DMA transfers write straight into the destination
    for load in loads:
        for d in dma_records:
            mode = (d["args"][0] >> 8) & 0xFF
            if mode == 5 and load["first_seq"] <= d["seq"] <= load["last_seq"] + 2:
                load["dma_dst"] = d["args"][2]
                break
    return loads


def find_destination(session, load, file_data):
    """Where did the file's bytes end up? Searches RAM for the data that was
    read (works unless the game decompresses or overwrites it)."""
    if load["dma_dst"]:
        return [load["dma_dst"]], "card DMA destination"
    # ROM files are 0x200 aligned in practice, so the first read starts at
    # the beginning of the file
    lo = max(0, min(load["offsets"]))
    chunk = file_data[lo:lo + 64]
    if len(chunk) < 8:
        return [], "file too small to search for"
    src = session.source(None, "arm9")
    hits = []
    for name, start, end in src.data_regions():
        data = src.read(start, end - start)
        i = data.find(chunk)
        while i >= 0 and len(hits) < 8:
            hits.append(start + i - lo)
            i = data.find(chunk, i + 1)
    # drop copies in the card block buffer: keep hits whose full file matches
    n = min(len(file_data), 4096)
    full = [h for h in hits if src.read(h, n) == file_data[:n]]
    if full:
        return full, "RAM holding the whole file"
    if hits:
        return hits, "RAM holding the start of the file (partial copy, staging buffer, or since modified)"
    return [], "not found in RAM (decompressed on load, or already overwritten)"


# ---------------------------------------------------------------------------
# allocations


class AllocTracker:
    """Pairs tracepoint records of an allocator and a free function."""

    def __init__(self, alloc_addr, free_addr=None, size_arg="r0", free_arg="r0", name="alloc"):
        self.alloc_addr = alloc_addr
        self.free_addr = free_addr
        self.size_idx = REGS[size_arg]
        self.free_idx = REGS[free_arg]
        self.name = name

    def analyse(self, session, records):
        src = session.source(None, "arm9")
        entries = {}
        allocs = []
        frees = []
        path_cache = {}
        for r in records:
            if r["event"] == "exec" and r["pc"] == self.alloc_addr:
                entries[r["seq"] & 0xFFFFFFFF] = r
            elif r["event"] == "ret" and r["args"][2] == self.alloc_addr:
                e = entries.pop(r["args"][3], None)
                if e is None:
                    continue
                key = tuple(e["stack"][:16]) + (e["lr"],)
                if key not in path_cache:
                    path_cache[key] = call_path(session, src, e)
                allocs.append({"ptr": r["args"][0], "size": e["args"][self.size_idx], "frame": e["frame"],
                               "seq": e["seq"], "args": e["args"], "path": path_cache[key][:-1] or path_cache[key],
                               "freed_frame": None, "freed_by": None})
            elif r["event"] == "exec" and self.free_addr is not None and r["pc"] == self.free_addr:
                key = tuple(r["stack"][:16]) + (r["lr"],)
                if key not in path_cache:
                    path_cache[key] = call_path(session, src, r)
                frees.append({"ptr": r["args"][self.free_idx], "frame": r["frame"], "seq": r["seq"],
                              "path": path_cache[key][:-1] or path_cache[key]})
        # replay the timeline
        live = OrderedDict()
        timeline = []
        peak = cur = 0
        events = sorted([("a", a["seq"], a) for a in allocs] + [("f", f["seq"], f) for f in frees],
                        key=lambda x: x[1])
        bad_frees = []
        for kind, _, ev in events:
            if kind == "a":
                if ev["ptr"]:
                    live[ev["ptr"]] = ev
                    cur += ev["size"]
                    peak = max(peak, cur)
                timeline.append(ev)
            else:
                a = live.pop(ev["ptr"], None)
                if a:
                    a["freed_frame"] = ev["frame"]
                    a["freed_by"] = ev["path"]
                    cur -= a["size"]
                elif ev["ptr"]:
                    bad_frees.append(ev)
                timeline.append(ev)
        return {"allocs": allocs, "frees": frees, "live": list(live.values()), "peak": peak, "current": cur,
                "bad_frees": bad_frees, "pending_entries": len(entries)}


def by_site(allocs):
    sites = defaultdict(lambda: {"count": 0, "bytes": 0, "live": 0, "live_bytes": 0, "frames": []})
    for a in allocs:
        key = " > ".join(a["path"][-4:])
        s = sites[key]
        s["count"] += 1
        s["bytes"] += a["size"]
        s["frames"].append(a["frame"])
        if a["freed_frame"] is None:
            s["live"] += 1
            s["live_bytes"] += a["size"]
    return sites


def find_owner(allocs, addr):
    """The allocation containing addr (latest first)."""
    for a in reversed(allocs):
        if a["ptr"] <= addr < a["ptr"] + max(a["size"], 1):
            return a
    return None


# ---------------------------------------------------------------------------
# flow graphs


def _node_id(name, ids):
    if name not in ids:
        ids[name] = f"n{len(ids)}"
    return ids[name]


def mermaid_graph(paths_to_leaves, title=None):
    """paths_to_leaves: [(path [outer..inner], leaf_label, leaf_kind)].
    Returns Mermaid flowchart text (caller -> callee -> leaf)."""
    ids = {}
    edges = OrderedDict()
    leaves = OrderedDict()
    for path, leaf, kind in paths_to_leaves:
        for a, b in zip(path, path[1:]):
            edges[(a, b)] = edges.get((a, b), 0) + 1
        if path:
            leaves.setdefault((path[-1], leaf, kind), 0)
            leaves[(path[-1], leaf, kind)] += 1
    lines = ["flowchart LR"]
    if title:
        lines.insert(0, f"%% {title}")
    for name in {n for e in edges for n in e} | {k[0] for k in leaves}:
        lines.append(f'  {_node_id(name, ids)}["{_esc(name)}"]')
    for (a, b), n in edges.items():
        lines.append(f"  {_node_id(a, ids)} -->{'|x' + str(n) + '|' if n > 1 else ''} {_node_id(b, ids)}")
    for i, ((fn, leaf, kind), n) in enumerate(leaves.items()):
        leaf_id = f"L{i}"
        shape = f'[("{_esc(leaf)}")]' if kind == "file" else f'{{{{"{_esc(leaf)}"}}}}'
        lines.append(f"  {leaf_id}{shape}")
        lines.append(f"  {_node_id(fn, ids)} -.->{'|x' + str(n) + '|' if n > 1 else ''} {leaf_id}")
    return "\n".join(lines)


def _esc(text):
    return str(text).replace('"', "'").replace("\n", " ")


HTML_TEMPLATE = """<!doctype html>
<html><head><meta charset="utf-8"><title>{title}</title>
<style>body{{font-family:sans-serif;margin:16px}} pre{{background:#f4f4f4;padding:8px;overflow:auto}}
table{{border-collapse:collapse}} td,th{{border:1px solid #ccc;padding:2px 6px;font-family:monospace}}</style>
<script type="module">import mermaid from "https://cdn.jsdelivr.net/npm/mermaid@11/dist/mermaid.esm.min.mjs";
mermaid.initialize({{startOnLoad:true, maxTextSize:500000, flowchart:{{useMaxWidth:false}}}});</script>
</head><body><h2>{title}</h2>
<pre class="mermaid">{graph}</pre>
{table}
</body></html>
"""


def write_html(path, title, graph, rows, headers):
    table = ""
    if rows:
        table = "<table><tr>" + "".join(f"<th>{html.escape(h)}</th>" for h in headers) + "</tr>"
        for row in rows:
            table += "<tr>" + "".join(f"<td>{html.escape(str(c))}</td>" for c in row) + "</tr>"
        table += "</table>"
    os.makedirs(os.path.dirname(os.path.abspath(path)), exist_ok=True)
    with open(path, "w") as f:
        f.write(HTML_TEMPLATE.format(title=html.escape(title), graph=html.escape(graph), table=table))
