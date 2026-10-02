#!/usr/bin/env python3
"""Engine requirements: every call from game code into SDK/NitroSystem/runtime code.
usage: engine_reqs.py EXPORT_DIR LIB_NAMES.txt OUT.json"""
import collections, glob, json, os, re, sys
exp, libf, out = sys.argv[1:4]
LIB = set(open(libf).read().split())
HDR = re.compile(r"^## (\S+)  \[(\S+) ")
AREAS = [  # (area, engine feature, regex on the library function name)
 ("3D models & animation", "NitroSystem G3D: NSBMD/NSBCA/NSBTP/NSBTA/NSBMA playback, render objects, material/lighting",
  r"^NNSi?_G3d|^G3BS_|^NNSi_G3d"),
 ("3D immediate mode", "raw DS geometry engine commands (custom-drawn geometry, matrices, lights, fog, toon/edge)",
  r"^G3[A-Zi_]|^G3_|^GXi?_.*(3D|Geom|Mtx)|^G3X_"),
 ("2D graphics", "NitroSystem G2D: NCGR/NCLR/NSCR/NCER/NANR cells, OAM, char canvas/fonts", r"^NNSi?_G2d"),
 ("graphics hardware setup", "VRAM banks, BG/OBJ modes, palettes, blending, master brightness, display capture",
  r"^G[XS]*_|^G2[SX]?_|^GXS?_|^GX_"),
 ("VRAM/texture managers", "NitroSystem GFD texture/palette VRAM managers, VRAM transfer queue", r"^NNS_Gfd|^NNSi_Gfd"),
 ("sound", "NitroSystem SND: SDAT archive, SSEQ sequencer, SBNK/SWAR, STRM streams, players, capture effects",
  r"^NNSi?_Snd|^SNDi?_"),
 ("file system", "ROM file system, overlays, archives (NARC), async reads", r"^FSi?_|^CARDi?_"),
 ("compression", "LZ77/Huffman/RLE decompression", r"^MIi?_Uncomp|^MI_Uncompress|^SVC_Uncomp|^MIi_Uncomp"),
 ("memory & heaps", "heaps (expanded/frame/unit), allocators, memory copy/fill, DMA", r"^NNS_Fnd|^NNSi_Fnd|^MIi?_|^OS_(Alloc|Free|.*Arena|.*Heap)"),
 ("math", "fixed-point math, matrices, vectors, trig tables, RNG", r"^FX_|^MTX_|^VEC_|^MATH|^CP_|^FX32|^Quat"),
 ("OS / threads / timers", "threads, alarms, ticks, interrupts, V-blank sync, mutexes, messages",
  r"^OSi?_|^PXI|^PM_|^PMi_"),
 ("input", "buttons, touch screen, microphone", r"^TPi?_|^PAD_|^MIC_|^MICi_|KEY"),
 ("clock", "real-time clock", r"^RTCi?_"),
 ("save data", "card backup (EEPROM/flash) read/write", r"^CARD_.*Backup|^CARDi_.*Backup"),
 ("local wireless", "WM / multiboot / download play (multiplayer modes)", r"^WMi?_|^MBi?_|^MBP|^WH_|^WCM"),
 ("online (Wi-Fi Connection)", "DWC/GameSpy/sockets/SSL (service is offline: stub)",
  r"^DWC|^gt2|^gp[A-Z]|^qr2|^SB|^SOC|^CPS|^SSL|^ghi|^gti|^AOSS|^APC|^ServerBrowser"),
 ("particles", "SPL particle library", r"^SPL"),
 ("C/C++ runtime", "libc / C++ runtime (provided by Lua/host)", r".*"),
]
funcs, calls = {}, collections.defaultdict(collections.Counter)
for path in sorted(glob.glob(os.path.join(exp, "asm", "*.s"))):
    cur = None
    for line in open(path, errors="replace"):
        m = HDR.match(line)
        if m:
            cur = m.group(1); funcs[cur] = m.group(2); continue
        if cur and "-> " in line and not line.startswith(";"):
            calls[cur][line.split("-> ", 1)[1].split()[0].split("+")[0]] += 1
is_lib = lambda n: n.split("@")[0] in LIB
def area(n):
    for a, feat, rx in AREAS:
        if re.search(rx, n): return a
res = collections.defaultdict(lambda: {"functions": collections.Counter(), "callers": set(), "modules": collections.Counter()})
for f, cs in calls.items():
    if is_lib(f): continue                      # library-internal calls are the library's business
    for t, n in cs.items():
        if not is_lib(t): continue
        a = area(t)
        r = res[a]; r["functions"][t] += n; r["callers"].add(f); r["modules"][funcs.get(f, "?")] += n
feat = {a: d for a, d, _ in AREAS}
outj = {a: {"feature": feat[a], "call_sites": sum(r["functions"].values()), "distinct_functions": len(r["functions"]),
            "game_functions_calling": len(r["callers"]), "top_modules": r["modules"].most_common(8),
            "functions": r["functions"].most_common()} for a, r in res.items()}
json.dump(outj, open(out, "w"), indent=1)
for a, _, _ in AREAS:
    if a in outj:
        o = outj[a]; print(f"{a:28} {o['distinct_functions']:4} fns {o['call_sites']:6} sites  from {o['game_functions_calling']:5} game fns")
