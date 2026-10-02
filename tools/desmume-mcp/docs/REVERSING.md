# Reverse-engineering workflow (DS games)

How the Phantom Hourglass / Spirit Tracks work was done, written so it can be
repeated for another DS game (or another version of these). Every tool here is
generic; none contains game code or data. **Game-derived output (exports,
disassembly, text, RAM dumps, ROMs) never goes in this public repo**: keep it
in a private repo, encrypted where the tools say so.

Tools live in two places:

- `scripts/`: entry points that take a ROM (export, inventory, ROM vault).
- `reversing/`: analysis steps that work on the exports and RAM snapshots.

Needs python3, `pip install capstone`, git, openssl, xz.

## 0. Getting the ROMs onto a machine

`scripts/rom_vault.py` keeps your own dumps in a private repo branch,
encrypted (tar.xz → openssl AES-256-CBC, PBKDF2 200 000 rounds → 45 MB parts,
since GitHub refuses files over 100 MB).

```sh
ROM_VAULT_PASS=... scripts/rom_vault.py push  --repo ~/dev/private ph.nds st.nds   # branch "roms"
ROM_VAULT_PASS=... scripts/rom_vault.py fetch --repo ~/dev/private --out roms/
```

`push` writes a manifest (name, size, SHA-1, header title/code) next to the
parts and `fetch` checks it. A branch made by hand
(`tar -cJf - *.nds | openssl enc -aes-256-cbc -pbkdf2 -iter 200000 -salt | split -b 45M - roms/roms.tar.xz.enc.part-`)
is accepted too, just without the SHA-1 check.

## 1. What is in the ROM

```sh
scripts/rom_inventory.py rom.nds --out inv/        # inv/README.md, inv/inventory.json
```

Every file by format, looking through LZ77 (0x10/0x11) and into NARC archives
(member names from their BTNF tables). Unrecognised formats are listed by
(extension, first 4 bytes): that list is the to-do list of custom formats an
engine has to parse. Only names/sizes/formats are written, never contents.

## 2. Annotated disassembly export

```sh
scripts/ph_export.py rom.nds --game ph|st|sm64ds [--version usa] [--push --dest-repo ~/dev/private]
scripts/plat_export.py platinum.nds [--push ...]      # reference: fully named NitroSDK
```

For a game with a decomp in the zeldaret/pret layout (`config/<ver>/arm9/**/symbols.txt`,
`relocs.txt`), `ph_export.py` writes one `asm/<module>.s` per module (main,
ITCM, every overlay) with calls, pointers, literal pool values, I/O registers
and strings resolved, plus `index.tsv` with callers/callees. It first checks
every known call against the instructions in *your* ROM, so a wrong
region/revision stops it. Output is encrypted with a printed random
passphrase before it is committed. To add a game, add an entry to `GAMES`
(decomp URL, config layout, game codes).

`plat_export.py` builds pret/pokeplatinum, insists the build is byte-identical
to your dump, and exports from the linker symbols. Platinum uses the same
NitroSDK/NitroSystem/NitroWiFi/DWC generation as PH/ST with Nintendo's own
names, which makes it the reference for library code.

Export format, one function:

```
## func_0200107c  [main 0x0200107c arm size 0x4c UNNAMED]
; called by: func_ov018_02162db8, func_ov018_021638e0
0200107c: bic r3, r1, #0x80000000
02001080: ldr r2, [pc, #0x3c]  ; =0x0000041e
...: bl #0x2001234  -> OS_GetTick
```

A call from main into an address range shared by several overlays (whichever
is loaded at the time) names every candidate: `-> func_ov017_x | func_ov018_x`;
tools reading the first token after `->` get the first candidate.

## 3. Matching functions between games (no fuzzy matching)

```sh
XM_EXACT=1 reversing/xmatch.py A_EXPORT B_EXPORT pairs.json
```

`xmatch.py` pairs functions of two exports. With `XM_EXACT=1` it only uses
evidence that cannot be wrong by similarity:

1. anchors: same real name on both sides;
2. identical code with addresses masked (fp), then immediates masked too (fp1),
   unique on both sides;
3. identical-code groups split by what they reference and who calls them;
4. call-graph propagation: in a matched pair whose call lists have the same
   length, the n-th call of one is the n-th call of the other, accepted when the
   callees' code is compatible;
5. `structsig.py` structural signatures: the CFG with jump-only blocks threaded
   through and chains merged, branch polarity ignored, block contents as
   multisets, registers masked, plus ABI facts (which of r0-r3 are read before
   written = arity; constants loaded into r0-r3 before each call), hashed
   Weisfeiler-Lehman style. Survives an extra jump, a different block order or
   different register allocation. Blind test (`XM_HOLDOUT=1`: half of one side
   may only match structurally): 597/598 correct.

Then turn pairs into names:

```sh
reversing/pass_exact.py config.json
```

```json
{"lib_names": "lib_names.txt", "targets": ["ph", "st"], "out": "pass/",
 "jobs": [{"pairs": "ph-st.json", "a": "ph", "b": "st"},
          {"pairs": "ph-plat.json", "a": "ph", "b": "plat"}]}
```

Rules: the target must still be a placeholder and the source name real;
functions under 8 instructions need a supporting neighbour (a matched
caller/callee, or a linker-order neighbour matched next to the partner);
across different engines only library names move (`lib_names.txt`: the
NitroSDK/NitroSystem/NitroWiFi/DWC/SPL/MSL names, e.g. every function name in
the SDK sources plus the reference game's non-game names), never ctor/dtor
names. Output `<game>-pass.json` (`[{old, new, how, support, ...}]`) and
the rejected conflicts.

Other steps on pairs:

- `transfer.py PAIRS PH_CHECKOUT ST_CHECKOUT OUT`: proposals for both decomps,
  applied to the checkouts' symbols.txt; names that need a source change are
  listed separately.
- `transfer_official.py PAIRS REPO OUT LABEL GAME_DEFS.txt [EARLIER.json...]`:
  official names from the reference game: confirms, renames placeholders,
  corrects names from earlier rounds, lists differences with the decomp's
  own names as suggestions. `report_official.py OUT` writes its REPORT.md.

## 4. Applying names

- `apply_names.py EXPORT OUT ROUND.json...` rewrites an export with the names
  from later rounds (whole-token replace everywhere), so the next pass sees them.
  Each pass makes the next one better: more named callees means more evidence.
- Changes to a decomp checkout are committed there and shipped as
  `git format-patch` files, one per round, applied in order.

## 5. RAM: globals, heap objects, classes

From the emulator: `savestate_save` / the MCP memory tools, or any DeSmuME
savestate (`~/.config/desmume/*.dsN`):

```sh
reversing/dst_extract.py state.ds1 snap/       # main.bin itcm.bin dtcm.bin arm9_regs.json
reversing/heap_map.py snap/ DECOMP/config/usa ADDRESSES.json out.json
reversing/field_scan.py EXPORT out.json gItemManager gMapManager ...
```

- `dst_extract.py`: savestate format is zlib chunks; chunk 4 (SF_MEM) has
  ITCM, DTCM and main RAM.
- `heap_map.py`: finds the Nitro heap blocks (16-byte header `'UD'` 0x5544,
  attr, size, prev, next; links cross-checked), the class of every object
  whose first word is a vtable (the pointer is `_ZTV...` + 8), and the
  shortest pointer path from a named global to each address in ADDRESSES.json
  (e.g. addresses from a cheat list or a randomizer). Turns "0x021B6FAC" into
  `gAdventureFlags/0x4+0x10`, which is what code accesses look like.
- `field_scan.py`: who reads/writes which field of a global singleton
  (following `ldr rX, =gFoo; ldr rY, [rX]; ldr rZ, [rY, #off]`, two hops,
  and into callees that get the object as `this`). Combined with heap_map this
  names the functions that touch a known variable.

Save files: `backup_import path=` / `backup_export path=` control commands
(docs/PROTOCOL.md) load a raw .sav into the emulator; diffing saves taken at
known story points gives the story flag bits.

## 6. AI-assisted naming of what is left

```sh
reversing/make_batches.py EXPORT DECOMP_CHECKOUT batches/ N SIZE [SKIP.txt] [EVIDENCE.json] [N_EVIDENCE]
reversing/merge_names.py DECOMP_CHECKOUT results_dir/ report.md [--min medium]
```

`make_batches.py` picks the most-called unnamed functions not referenced in
the decomp's source, with their code and up to 4 call sites; EVIDENCE.json
(`{func: ["this = gFoo (class X)", ...]}` from field_scan/heap_map) is
printed with them. Each batch goes to one agent with instructions in this
shape: material (batch, whole export, decomp headers/docs, overlay map),
the project's naming conventions (official SDK names only when unmistakable,
otherwise descriptive PascalCase with a subsystem prefix), evidence first,
confidence high/medium/low, skip rather than guess, and output
`results<N>.json` = `[{"old", "new", "confidence", "class", "why"}]`.
`merge_names.py` validates (C identifier, unused, no duplicates) and applies.

## 7. What the engine has to provide

```sh
reversing/engine_reqs.py EXPORT lib_names.txt reqs.json
```

Every call from game code into library code, grouped by area (G3D, 2D, GX,
sound, FS, compression, heap, math, OS, input, RTC, wireless): the API
surface a reimplementation must cover.

## 8. Game data

```sh
reversing/bmg.py --rom rom.nds --prefix English/Message --out text/   # all .bmg under a path
reversing/bmg.py file.bmg ... --out text/
```

BMG (`MESGbmg1`) message files to Lua tables + JSON, lossless:

- INF1: per message a DAT1 offset + attribute bytes (written as hex).
- DAT1: strings in the header's encoding (1 cp1252, 2 UTF-16LE, 3 Shift-JIS,
  4 UTF-8). Control codes are `0x1A, u8 length, u8 group, u16 type, params`
  and are written inline as `{g:GROUP:TYPE:PARAMHEX}`; a literal `{` becomes `{{`.
- MID1: message ids. FLW1: flow nodes (8 bytes: type, sub, a, b, c) and the
  branch table. FLI1: labels (id, group, entry node). Unknown sections kept as hex.

Tally the control codes of an extraction (to work out what they mean):

```sh
python3 - text/ <<'EOF'
import json, glob, re, sys, collections
c = collections.Counter()
for f in glob.glob(sys.argv[1] + "/**/*.json", recursive=True):
    for m in json.load(open(f))["messages"]:
        c.update(re.findall(r"(?<!\{)\{g:(\w\w:\w{4})", m["text"]))
print(c.most_common())
EOF
```

## Order, for a new game

1. `rom_vault.py push` (once), `rom_inventory.py`.
2. Export the game and a fully named reference with the same SDK generation.
3. `XM_EXACT=1 xmatch.py` against the reference and any sibling game →
   `pass_exact.py` → apply to the decomp → `apply_names.py` → repeat until a
   pass finds nothing new.
4. RAM snapshots at known points → `dst_extract` → `heap_map` / `field_scan`.
5. `make_batches` → agents → `merge_names` → `apply_names`; repeat.
6. `engine_reqs.py`, `bmg.py` and format parsers for the custom formats from step 1.
