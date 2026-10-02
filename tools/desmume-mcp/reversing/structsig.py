"""Structural function signatures for cross-game matching.

Walks a function's disassembly (ph_export.py format), builds its control-flow
graph and reduces it to something the compiler version does not change:

- blocks that only jump elsewhere are threaded through, straight-line chains
  are merged (an extra jump or a different block layout disappears);
- branch polarity is ignored (beq X / bne Y with swapped arms look the same);
- block contents are compared as multisets (scheduling inside a block does
  not matter), with registers masked except sp/lr/pc;
- ABI facts, which register allocation cannot change: which of r0-r3 the
  function reads before writing (arity), and the constants loaded into r0-r3
  right before each call (call(r1=0x20)).

The graph is hashed Weisfeiler-Lehman style: strict (immediates kept) and
loose (immediates masked, e.g. struct offsets that moved), plus per-block
labels for partial comparison.
"""

import collections
import hashlib
import re

CC = {"eq", "ne", "cs", "hs", "cc", "lo", "mi", "pl", "vs", "vc", "hi", "ls", "ge", "lt", "gt", "le", "al"}
REGNUM = {**{f"r{i}": i for i in range(16)}, "sb": 9, "sl": 10, "fp": 11, "ip": 12, "sp": 13, "lr": 14, "pc": 15}
REG = re.compile(r"\b(r\d+|ip|sp|lr|pc|sb|sl|fp)\b")
IMM = re.compile(r"#-?(0x[0-9a-f]+|\d+)")
NO_DEST = {"cmp", "cmn", "tst", "teq", "str", "strb", "strh", "strd", "stm", "stmia", "stmdb", "stmib", "stmda",
           "push", "b", "bl", "blx", "bx", "mcr", "msr", "svc", "swi", "bkpt", "pld", "nop"}
NO_READ_DEST = {"mov", "movs", "mvn", "mvns", "ldr", "ldrb", "ldrh", "ldrsb", "ldrsh", "ldrd", "mrs", "mrc",
                "adr", "neg", "negs", "rsbs", "rsb", "pop", "ldm", "ldmia", "ldmdb", "ldmib", "ldmda"}


def h(x):
    return hashlib.sha1(repr(x).encode()).hexdigest()[:16]


def split_cond(mn, bases):
    """movne -> (mov, ne); bls -> (b, ls); movs stays movs."""
    if len(mn) > 2 and mn[-2:] in CC and mn[:-2] in bases:
        return mn[:-2], mn[-2:]
    # s-suffixed conditional (addseq) or width suffix (b.w)
    mn = mn.split(".")[0]
    if len(mn) > 3 and mn[-2:] in CC and mn[:-2].rstrip("s") in bases:
        return mn[:-2], mn[-2:]
    return mn, None


def regs_in(s):
    out = []
    for m in REG.finditer(s):
        out.append(REGNUM[m.group(1)])
    # register ranges in lists: {r4-r7}
    for a, b in re.findall(r"r(\d+)-r(\d+)", s):
        out += list(range(int(a), int(b) + 1))
    return out


def rw(base, ops):
    """(read regs, written regs) of one instruction, from its text."""
    parts = [p.strip() for p in re.split(r",(?![^{]*})(?![^\[]*\])", ops)] if ops else []
    if base == "push" or (base.startswith("stm") and ops.startswith("sp")):
        return set(), set()                    # saving registers (r3 is often pushed only for alignment)
    if base in ("stm", "stmia", "stmdb", "stmib", "stmda") or base.startswith("st"):
        return set(regs_in(ops)), set()
    if base in ("pop",):
        return {13}, set(regs_in(ops))
    if base.startswith("ldm"):
        return set(regs_in(parts[0])) if parts else set(), set(regs_in(ops))
    if base in ("bl", "blx") and "#" in ops:
        return set(), {0, 1, 2, 3, 12, 14}
    if base in ("bx", "blx"):
        return set(regs_in(ops)), ({0, 1, 2, 3, 12, 14} if base == "blx" else set())
    if base in NO_DEST or base.startswith("b") and len(base) <= 3 and base[1:] in CC | {""}:
        return set(regs_in(ops)), set()
    if base in ("umull", "smull", "umlal", "smlal", "umulls", "smulls") and len(parts) >= 2:
        return set(regs_in(",".join(parts[2:]))) | (set(regs_in(",".join(parts[:2]))) if "la" in base else set()), \
            set(regs_in(",".join(parts[:2])))
    if not parts:
        return set(), set()
    dest = set(regs_in(parts[0].rstrip("!")))
    reads = set(regs_in(",".join(parts[1:])))
    if base.startswith("ldr") or base.startswith("ldm"):
        if "!" in ops or "], " in ops:        # writeback: base register also written
            pass
        return reads, dest
    if len(parts) == 2 and base not in NO_READ_DEST and not base.startswith("mov") and not base.startswith("mvn"):
        reads |= dest                          # thumb two-operand form: rd = rd op rm
    if base in ("mla", "mlas"):
        pass
    return reads, dest


class Insn:
    __slots__ = ("addr", "base", "cond", "ops", "comment", "text", "ref")

    def __init__(self, addr, text, comment, ref, bases):
        self.addr, self.comment, self.text, self.ref = addr, comment, text, ref
        mn, _, ops = text.partition(" ")
        self.base, self.cond = split_cond(mn, bases)
        self.ops = ops.strip()


def literal_token(ins):
    """ldr rX, [pc, #n] -> =K:value / =A (address) from the export's comment."""
    c = ins.comment.strip()
    if not c.startswith("="):
        return "=?"
    v = c[1:].split()[0]
    if v.startswith("0x"):
        n = int(v, 16)
        if 0x02000000 <= n < 0x02400000 or 0x027e0000 <= n < 0x02800000 or 0x01ff8000 <= n < 0x02000000:
            return "=A"
        return f"=K:{n:x}"
    return "=A"


def is_terminator(ins, start, end):
    b, ops = ins.base, ins.ops
    if b == "b":
        return True
    if b == "bx" or (b in ("pop",) and "pc" in ops) or (b.startswith("ldm") and "pc" in ops):
        return True
    if b in ("mov", "ldr", "add") and ops.startswith("pc"):
        return True
    return False


def branch_target(ins):
    m = re.match(r"#0x([0-9a-f]+)$", ins.ops)
    return int(m.group(1), 16) if m else None


def signature(func, raw, bases, ref_id=None):
    """raw: list of (addr, text, comment, ref). Returns dict of signature parts.
    ref_id(name) -> stable id for a called function (e.g. its matched partner) or None."""
    start, end = func["addr"], func["addr"] + func["size"]
    code = [Insn(a, t, c, r, bases) for a, t, c, r in raw if not t.startswith(".word")]
    if not code:
        return None
    # leaders
    leaders = {code[0].addr}
    for i, ins in enumerate(code):
        if ins.base == "b":
            t = branch_target(ins)
            if t is not None and start <= t < end:
                leaders.add(t)
            if i + 1 < len(code):
                leaders.add(code[i + 1].addr)
        elif is_terminator(ins, start, end) or (ins.cond and ins.base in ("pop", "bx", "ldm", "ldmia")):
            if i + 1 < len(code):
                leaders.add(code[i + 1].addr)
    blocks, cur = [], []
    for ins in code:
        if ins.addr in leaders and cur:
            blocks.append(cur)
            cur = []
        cur.append(ins)
    if cur:
        blocks.append(cur)
    idx = {b[0].addr: i for i, b in enumerate(blocks)}
    succ = [[] for _ in blocks]
    for i, b in enumerate(blocks):
        last = b[-1]
        falls = True
        if last.base == "b":
            t = branch_target(last)
            if t is not None and t in idx:
                succ[i].append(idx[t])
            elif t is not None:
                succ[i].append(-1)                      # tail call out of the function
            falls = last.cond is not None
        elif is_terminator(last, start, end):
            falls = last.cond is not None
        if falls and i + 1 < len(blocks):
            succ[i].append(i + 1)
    # block contents: normalised tokens, calls with argument constants
    content_s, content_l, sketch = [], [], []
    for b in blocks:
        cs, cl = [], []
        sk = []
        argk = {}
        for ins in b:
            if ins.base == "b" and branch_target(ins) is not None and start <= branch_target(ins) < end:
                continue                                 # internal jump: an edge, not content
            if ins.base in ("bl", "blx") and "#" in ins.ops or (ins.base == "b" and ins.ref):
                callee = ref_id(ins.ref) if ref_id and ins.ref else None
                args = ",".join(f"r{r}={v}" for r, v in sorted(argk.items()))
                cs.append(f"call({args})" + (f"->{callee}" if callee else ""))
                cl.append("call" + (f"->{callee}" if callee else ""))
                sk.append("C:" + (callee or "?"))
                argk = {}
                continue
            ops = ins.ops
            if ins.base.startswith("ldr") and "[pc" in ops:
                tok = f"{ins.base} R, {literal_token(ins)}"
                rd = regs_in(ops.split(",")[0])
                if rd and rd[0] <= 3:
                    argk[rd[0]] = literal_token(ins)[1:]
                cs.append(tok)
                cl.append(f"{ins.base} R, =" + ("A" if tok.endswith("=A") else "K"))
                lt = literal_token(ins)
                if lt.startswith("=K:"):
                    sk.append("K:" + lt[3:])
                continue
            if ins.base in ("push", "pop") or ins.base.startswith("ldm") or ins.base.startswith("stm"):
                keep = [x for x in ("lr", "pc") if re.search(rf"\b{x}\b", ops)]
                tok = f"{ins.base} {{{','.join(keep)}}}"
                cs.append(tok)
                cl.append(tok)
                continue
            m = re.match(r"^(r[0-3]), #(-?(?:0x[0-9a-f]+|\d+))$", ops)
            if ins.base in ("mov", "movs", "mvn", "mvns") and m:
                v = int(m.group(2), 0)
                argk[int(m.group(1)[1:])] = f"{'~' if ins.base.startswith('mvn') else ''}{v:x}"
            else:
                for r in regs_in(ops.split(",")[0]) if ops else []:
                    if r <= 3:
                        argk.pop(r, None)
            for k in IMM.findall(ops):
                v = int(k, 0)
                if v > 0xff and not ops.startswith("sp"):
                    sk.append(f"K:{v & 0xffffffff:x}")
            norm = REG.sub(lambda mm: mm.group(1) if mm.group(1) in ("sp", "lr", "pc") else "R", ops)
            cs.append(f"{ins.base} {norm}")
            cl.append(f"{ins.base} {IMM.sub('#I', norm)}")
        content_s.append(collections.Counter(cs))
        content_l.append(collections.Counter(cl))
        sketch.append(collections.Counter(sk))
    # thread jump-only blocks
    def resolve(j, seen=()):
        if j < 0 or j in seen:
            return j
        if not content_s[j] and len(succ[j]) == 1:
            return resolve(succ[j][0], seen + (j,))
        return j
    succ = [[resolve(j) for j in s] for s in succ]
    # reachable blocks from the entry
    reach, stack = set(), [0]
    while stack:
        j = stack.pop()
        if j < 0 or j in reach:
            continue
        reach.add(j)
        stack.extend(succ[j])
    preds = collections.defaultdict(list)
    for i in reach:
        for j in succ[i]:
            preds[j].append(i)
    # merge straight-line chains: i -> j where i has one successor and j one predecessor
    alias = {}
    order = sorted(reach)
    for i in order:
        if i in alias:
            continue
        while len(succ[i]) == 1 and succ[i][0] >= 0 and succ[i][0] != 0 and len(preds[succ[i][0]]) == 1 \
                and succ[i][0] not in alias and succ[i][0] != i:
            j = succ[i][0]
            content_s[i] = content_s[i] + content_s[j]
            content_l[i] = content_l[i] + content_l[j]
            sketch[i] = sketch[i] + sketch[j]
            succ[i] = succ[j]
            alias[j] = i
    nodes = [i for i in order if i not in alias and (content_s[i] or i == 0)]
    # blocks that only jump were threaded above; empty blocks keep no content
    nodeset = set(nodes)
    def fix(j):
        while j in alias:
            j = alias[j]
        return j
    esucc = {i: sorted({fix(j) for j in succ[i] if j < 0 or fix(j) in nodeset}) for i in nodes}
    epred = collections.defaultdict(list)
    for i in nodes:
        for j in esucc[i]:
            if j >= 0:
                epred[j].append(i)

    def wl(content, rounds=3):
        lab = {i: h(sorted(content[i].items())) for i in nodes}
        first = dict(lab)
        for _ in range(rounds):
            lab = {i: h((lab[i], sorted(lab[j] if j >= 0 else "EXIT" for j in esucc[i]),
                         sorted(lab[j] for j in epred[i]), i == 0)) for i in nodes}
        return h(sorted(lab.values())), first, lab

    strict, _, _ = wl(content_s)
    sk_hash, _, _ = wl(sketch)
    info = sum(sum(sketch[i].values()) for i in nodes)
    total = collections.Counter()
    for i in nodes:
        total += sketch[i]
    flat = h(sorted(total.items()))
    known_calls = sum(v for i in nodes for k, v in sketch[i].items() if k.startswith("C:") and k != "C:?")
    loose, first_l, _ = wl(content_l)
    shape, _, _ = wl({i: collections.Counter() for i in nodes})
    # arity: r0-r3 read before written along the CFG from the entry
    arity = set()
    seen = set()
    stack = [(0, frozenset())]
    while stack:
        j, written = stack.pop()
        if j < 0 or (j, written) in seen or len(seen) > 400:
            continue
        seen.add((j, written))
        w = set(written)
        for ins in blocks[j]:
            r, wr = rw(ins.base, ins.ops)
            for x in r:
                if x <= 3 and x not in w:
                    arity.add(x)
            if ins.cond is None:
                w |= wr
        for k in succ[j]:
            stack.append((k, frozenset(w)))
    return dict(strict=strict, loose=loose, shape=shape, sketch=sk_hash, flat=flat, info=info, known_calls=known_calls,
                nblocks=len(nodes),
                blocks=collections.Counter(first_l.values()), arity=max(arity) + 1 if arity else 0)


def block_overlap(a, b):
    inter = sum((a["blocks"] & b["blocks"]).values())
    return inter / max(sum(a["blocks"].values()), sum(b["blocks"].values()), 1)
