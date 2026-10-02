#!/usr/bin/env python3
"""REPORT.md for transfer_official.py output. usage: report_official.py OUTDIR"""
import collections, json, re, sys
O = sys.argv[1]
J = lambda n: json.load(open(f'{O}/{n}'))
esc = lambda s: str(s).replace('|', '\\|')
def pfx(n):
    m = re.match(r'_*([A-Za-z0-9]+?)_', n)
    return m.group(1) if m else re.match(r'_*[A-Za-z]*', n).group(0) or n[:6]
def stats(g):
    r = J(f'{g}-renames.json')
    return len(r), collections.Counter(x['module'] for x in r), collections.Counter(pfx(x['new']) for x in r)
def tab(rows, cols, hdr):
    return ["| " + " | ".join(hdr) + " |", "|" + "---|" * len(hdr)] + \
        ["| " + " | ".join(esc(r.get(c, '')) for c in cols) + " |" for r in rows]
L = ["# Official SDK names from Pokémon Platinum", "",
     "pret/pokeplatinum builds a byte-identical Platinum (US) ROM; its NitroSDK 4.2, NitroSystem, NitroWiFi 2.1, "
     "NitroDWC 2.2 (with the GameSpy libraries DWC bundles) and the MSL runtime carry Nintendo's official names "
     "(ntrtwl/NitroSDK etc.). Nintendo shipped these as prebuilt libraries, so games on the same SDK release contain "
     "byte-identical copies.", "",
     "**Exact matching only.** A pair is accepted only when the two functions' code is identical with addresses masked "
     "(`fp`), or identical with immediates also masked (`fp1`), unique in both games; or reached through the call graph "
     "from such a pair with identical code on both sides; or split out of an identical-code group by identical "
     "callers/callees. No similarity scores, no mnemonic-only matches.", "",
     "Only **library** names are transferred: a name defined in Platinum's own game code (`src/`, `asm/`) is never used "
     "(PH has code identical to some generic Pokémon helpers such as `CommManager_GetParty`). Functions of 3 "
     "instructions or fewer need call-graph evidence.", ""]
for g, G, patch, base in (('ph', 'PH', 'ph-round3-from-platinum.patch', 'zeldaret/ph 29e3578 + ph-round1 + ph-round2-from-st'),
                          ('st', 'ST', 'st-round2-from-platinum.patch', 'zeldaret/st 9712128 + st-round1-from-ph')):
    n, mods, pre = stats(g)
    L += [f"## {G}: {n} names (`{patch}`, applies on {base})", "",
          "- by module: " + ", ".join(f"{m} {c}" for m, c in mods.most_common(8)),
          "- by library prefix: " + ", ".join(f"`{p}` {c}" for p, c in pre.most_common(24)),
          f"- {len(J(f'{g}-confirmed.json'))} functions already carried the official name.",
          f"- {sum(1 for x in J(f'{g}-renames.json') if x['kind'].startswith('corr'))} of our own earlier names are "
          "replaced by the official one (table below).",
          f"- {len(J(f'{g}-suggestions.json'))} functions the decomp itself named differently: suggestions only, not applied.", ""]
L += ["## Findings", "",
      "- PH's `IrqDisable` actually **enables** IRQs (`bic r1, r0, #0x80; msr cpsr_c, r1`): it is `OS_EnableInterrupts`. "
      "Likewise `IrqFiqEnable` = `OS_DisableInterrupts_IrqAndFiq` and `IrqFiqSet` = `OS_RestoreInterrupts_IrqAndFiq` "
      "(the SM64DS decomp independently agrees). The ST patch replaces the copies of these names that ST round 1 took from PH.",
      "- PH's ov061 is the Wi-Fi stack: NitroDWC plus GameSpy (`gt2`, `gp`, `qr2`, `ServerBrowser`), sockets (`SOC`/`SOCL`, "
      "`CPS`) and SSL; ov011 holds DWC setup (`DWC`, `AOSS`, `APC`); ov001 the wireless manager.",
      "- PH ov011 has functions byte-identical to Platinum's `WirelessManager_*` / `CommManager_*`, which is Platinum game "
      "code: both games apparently built their local-wireless layer on the same Nintendo sample code. Not transferred "
      "(Pokémon names); listed under skipped.",
      "- Round 2 (PH↔ST, which used fuzzy matching) re-checked: of its 55 fuzzy-matched PH names, 43 are confirmed exactly "
      "by Platinum, 1 refined (`GX_TrySetBank…ExtPltt` → `GX_SetBank…ExtPltt`), none contradicted, 11 not coverable.", ""]
for g, G in (('ph', 'PH'), ('st', 'ST')):
    corr = [x for x in J(f'{g}-renames.json') if x['kind'].startswith('corr')]
    L += [f"## {G}: earlier names of ours replaced ({len(corr)})", ""] + \
        tab(corr, ['addr', 'old', 'new', 'how'], ['addr', 'earlier name', 'official', 'match']) + [""]
    sg = J(f'{g}-suggestions.json')
    L += [f"## {G}: official names for functions the decomp named itself ({len(sg)})", "",
          "Not applied; for the maintainers.", ""] + \
        tab(sg, ['module', 'addr', 'old', 'new', 'note', 'how'], ['module', 'addr', 'decomp name', 'official', 'note', 'match']) + [""]
for g, G in (('ph', 'PH'), ('st', 'ST')):
    r = sorted(J(f'{g}-renames.json'), key=lambda x: (x['module'], x['addr']))
    L += [f"## {G}: all renames ({len(r)})", ""] + \
        tab(r, ['module', 'addr', 'old', 'new', 'how', 'n'], ['module', 'addr', 'old', 'new', 'match', 'insns']) + [""]
    sk = J(f'{g}-skipped.json')
    L += [f"## {G}: skipped ({len(sk)})", ""] + \
        tab(sk, ['module', 'addr', 'old', 'new', 'why'], ['module', 'addr', 'old', 'Platinum name', 'reason']) + [""]
open(f'{O}/REPORT.md', 'w').write("\n".join(L) + "\n")
