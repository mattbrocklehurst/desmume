#!/usr/bin/env python3
"""End-to-end test of the DeSmuME MCP tools against the bundled test game.

Part 1 calls the tool functions in-process and checks the results against
the ground truth in testgame/testgame.sym. Part 2 runs the real MCP server
over stdio and drives it with an MCP client.

usage: scripts/e2e_test.py [--only-protocol] [--keep-data]

Needs a built desmume-cli (scripts/build-desmume.sh), Python packages mcp and
capstone, and xvfb-run when there is no display. Uses a throwaway data
directory unless --keep-data is given.
"""

import asyncio
import os
import re
import shutil
import struct
import sys
import tempfile
import traceback

HERE = os.path.dirname(os.path.abspath(__file__))
PKG = os.path.dirname(HERE)
sys.path.insert(0, PKG)

ROM = os.path.join(PKG, "testgame", "testgame.nds")
SYMS = os.path.join(PKG, "testgame", "testgame.sym")

results = []


def check(name, cond, detail=""):
    results.append((name, bool(cond)))
    print(f"{'PASS' if cond else 'FAIL'}  {name}" + ("\n" + "\n".join("      " + l for l in str(detail).splitlines()[:40]) if not cond and detail else ""))
    return cond


def symbols():
    syms = {}
    for line in open(SYMS):
        addr, _, name = line.split()
        syms[name] = int(addr, 16)
    return syms


def text_of(result):
    if isinstance(result, list):
        return "\n".join(r for r in result if isinstance(r, str))
    return result if isinstance(result, str) else ""


def part1():
    from desmume_mcp import server as T

    sym = symbols()
    player = sym["g_player"]

    def u32(addr):
        return struct.unpack("<I", T.S.control.read_memory(addr, 4))[0]

    print("== emulator ==")
    out = T.emu_start(ROM, headless=True)
    check("emu_start", "MCPTESTGAME" in out, out)
    img = T.emu_screenshot()
    check("emu_screenshot returns a PNG", getattr(img, "data", b"")[:4] == b"\x89PNG")
    check("label_import from the .sym file", "imported" in T.label_import(path=SYMS))
    T.emu_pause()
    x0 = u32(player)
    r = T.emu_press(["right"], frames=10, screenshot=False)
    check("emu_press moves the player", u32(player) - x0 == 20, f"x {x0} -> {u32(player)}")
    st = T.emu_status()
    check("emu_status", '"paused": true' in st, st)
    r = T.mem_read("g_player", 24, format="u32")
    check("mem_read by label", "g_player" in r and "00000078" in r, r)

    print("== value scan: find the HP variable ==")
    T.mem_scan_start(size=4, value=50, region="main_ram")
    T.emu_press(["a"], frames=2, screenshot=False)
    r = T.mem_scan_next("eq", 43)
    check("mem_scan finds g_player.hp", f"{player + 8:08x}" in r or "g_player+0x8" in r, r)

    print("== watchpoint ==")
    r = T.dbg_watch("g_player+8", 4, "write")
    check("dbg_watch", "watchpoint" in r, r)
    T.S.control.call("input", buttons="a", frames=2)
    T.S.control.call("release")
    T.S.control.call("input", buttons="a", frames=2)
    r = T.dbg_continue(timeout=5)
    check("watchpoint hit in apply_damage (thumb)", "watchpoint" in r and "apply_damage" in r, r)
    pc = int(re.search(r"pc=([0-9a-f]{8})", r).group(1), 16)
    check("watchpoint stops inside apply_damage", sym["apply_damage"] <= pc < sym["handle_input"], hex(pc))
    T.dbg_delete("all")

    print("== breakpoints, stepping, backtrace ==")
    r = T.dbg_break("build_display_list")
    r = T.dbg_continue(timeout=5)
    check("breakpoint at build_display_list", "breakpoint" in r and "=>" in r and "build_display_list" in r, r)
    r = T.dbg_backtrace()
    check("backtrace reaches game_main", "game_main" in r, r)
    r = T.dbg_step(3)
    check("dbg_step", "step" in r, r)
    r = T.dbg_finish()
    check("dbg_finish returns to game_main", "game_main" in r.split("\n\n")[0] + r, r)
    T.dbg_delete("all")
    r = T.dbg_run_to("submit_display_list")
    check("dbg_run_to", "submit_display_list" in r, r)
    r = T.dbg_step(20, over=True)
    check("dbg_step over", "Stopped" in r, r)
    r = T.dbg_trace("fill_rect", count=4)
    check("dbg_trace collects calls with arguments", "4 hits" in r and "r0=" in r, r)
    r = T.dbg_break("handle_input", condition="u32(0x%x) > 0" % (player + 16))
    T.S.control.call("input", buttons="a", frames=2)
    r = T.dbg_continue(timeout=5)
    check("conditional breakpoint (score > 0)", "handle_input" in r and "if u32" in r, r)
    r = T.dbg_list()
    check("dbg_list shows hit counts", "hits=" in r, r)
    T.dbg_delete("all")
    # fill_rect(x, y, w, h, colour): setting h (r3) to 0 at entry is harmless
    T.dbg_run_to("fill_rect")
    r = T.dbg_set_register("r3", "0")
    check("dbg_set_register", "r3=00000000" in r, r)
    T.emu_resume()

    print("== disassembly and analysis ==")
    r = T.mem_disasm("card_read_block", 30)
    check("mem_disasm names IO registers via base+offset", "io:ROMCTRL" in r and "io:CARDCMD" in r
          and "card_read_block:" in r, r)
    r = T.mem_disasm("apply_damage", 6)
    check("mem_disasm detects thumb functions", r.split("\n")[0].endswith("thumb") and "subs" in r, r)
    r = T.mem_xrefs("load_level")
    check("mem_xrefs finds both callers", r.count("bl") >= 2, r)
    r = T.mem_search(text="hello", region="all", source="rom:arm9")
    check("mem_search (no match expected in code)", "not found" in r or "hits" in r, r)
    r = T.func_list(limit=20)
    check("func_list ranks fill_rect", "fill_rect" in r, r)
    r = T.func_info("card_read_block")
    check("func_info reports the card hardware", "CARD_DATA" in r and "ROMCTRL" in r, r)
    r = T.label_set("0x02000838", "g_tilemap_copy", type="data", size=16, comment="4x4 tiles")
    check("label_set", "g_tilemap_copy" in r)
    r = T.label_list("tilemap")
    check("label_list", "g_tilemap_copy" in r, r)
    T.label_delete("g_tilemap_copy")
    check("label_export ghidra", f"fs_read_file {sym['fs_read_file']:#010x} f" in T.label_export("ghidra"))

    print("== ROM ==")
    r = T.rom_files()
    check("rom_files", "data/level1.map" in r, r)
    r = T.rom_overlays()
    check("rom_overlays", "2 overlays" in r and "compressed" in r, r)
    tmp = tempfile.mkdtemp()
    T.rom_extract("overlay:1", os.path.join(tmp, "ov1.bin"))
    ov1 = open(os.path.join(tmp, "ov1.bin"), "rb").read()
    check("rom_extract decompresses overlays", ov1[:16] == T.S.rom.overlay_binary("arm9", 0)[:16] and len(ov1) > 200)
    r = T.mem_disasm("0x02100000", 8, mode="arm", source="rom:overlay:1")
    check("disassemble an overlay offline", "rom:overlay:1" in r and "02100000" in r, r)

    print("== hooks ==")
    r = T.hook_set("card", "log", file="data/level1.map")
    check("hook_set card with file filter", "card: log" in r, r)
    T.emu_pause()
    T.emu_press(["start"], frames=2, screenshot=False)
    r = T.hook_log()
    check("card hook names the file", "data/level1.map" in r, r)
    check("card hook call chain", "fs_read_file" in r and "load_level" in r and "handle_input" in r, r)
    T.hook_set("card", "off")
    r = T.hook_set("card", "break", file="data/level1.map")
    T.S.control.call("input", buttons="start", frames=2)
    T.S.control.call("resume")
    r = T.dbg_wait(timeout=5)
    check("card hook with action=break halts in card_read_block", "card_read_block" in r, r)
    T.hook_set("card", "off")
    T.dbg_delete("all")
    r = T.gx_capture(frames=1)
    # the level has 14 non-empty tiles, one quad (4 vertices) each
    check("gx_capture decodes vertices", "VTX_16x56" in r and "VTX_16 (" in r, r)
    check("gx_capture finds the display list", "g_display_list+0x4" in r and "1 words written directly" in r, r)
    check("gx_capture traces SWAP_BUFFERS", "submit_display_list" in r, r)
    r = T.hook_set("dma", "log")
    T.emu_frame_advance(1)
    r = T.hook_log("dma")
    check("dma hook", "gxfifo" in r and "GXFIFO" in r, r)
    T.hook_set("dma", "off")

    print("== freeze dumps, states, movies ==")
    r = T.freeze_dump("e2e test", screenshot=False)
    check("freeze_dump", "Dump written" in r and "call stack" in r, r)
    d = re.search(r"Dump written to (\S+)", r).group(1)
    r = T.dump_list()
    check("dump_list", os.path.basename(d) in r, r)
    r = T.mem_read("g_player", 16, source=d)
    check("mem_read from a dump", "g_player" in r, r)
    r = T.dbg_registers(source=d)
    check("dbg_registers from a dump", "pc=" in r, r)
    r = T.dbg_backtrace(source=d)
    check("dbg_backtrace from a dump", "pc" in r, r)
    hp_before = u32(player + 8)
    T.emu_press(["a"], frames=2, screenshot=False)
    r = T.dump_resume(os.path.basename(d))
    check("dump_resume restores state", u32(player + 8) == hp_before, f"{u32(player + 8)} vs {hp_before}")
    T.emu_savestate("save", "e2e")
    T.emu_press(["a"], frames=2, screenshot=False)
    T.emu_savestate("load", "e2e")
    check("savestates", u32(player + 8) == hp_before)
    mv = os.path.join(tmp, "test.dsm")
    T.emu_movie("record", mv)
    T.emu_press(["right"], frames=5, screenshot=False)
    T.emu_movie("stop")
    check("movie recorded", os.path.getsize(mv) > 0)
    if shutil.which("ffmpeg"):
        vid = os.path.join(tmp, "v.mp4")
        T.emu_video("start", vid)
        T.emu_frame_advance(30)
        r = T.emu_video("stop")
        check("video recording", "30 frames" in r and os.path.getsize(vid) > 0, r)

    print("== detach / attach ==")
    r = T.dbg_detach()
    check("dbg_detach", "detached" in r)
    r = T.dbg_attach()
    check("dbg_attach halts the CPU", "pc=" in r, r)
    T.emu_resume()
    check("emu_stop", T.emu_stop() == "stopped")


def part3():
    """Tracing, profiling, recording and the oracle runner."""
    import subprocess
    from desmume_mcp import server as T

    print("== tracing and profiling ==")
    T.emu_start(ROM, headless=True, start_halted=True)
    T.label_import(path=SYMS)
    r = T.alloc_track("arena_alloc", "arena_free", size_arg="r1", free_ptr_arg="r1")
    check("alloc_track", "arena_alloc" in r, r)
    T.asset_trace_start()
    T.input_trace_start()
    r = T.func_trace("fs_read_file")
    check("func_trace", "fs_read_file" in r, r)
    T.emu_resume()
    T.emu_pause()
    for _ in range(3):
        T.emu_press(["start"], frames=2, screenshot=False)
    T.emu_press(["a"], frames=2, screenshot=False)

    r = T.asset_report()
    check("asset_report names the files", all(f in r for f in ("assets/a.dat", "assets/b.dat", "assets/c.dat",
                                                               "assets/d.dat", "data/level1.map")), r)
    check("asset_report finds destinations in allocated buffers", "buffer allocated at" in r, r)
    check("asset_report call paths", "load_level_assets" in r and "handle_input" in r, r)
    html = re.search(r"HTML report: (\S+)", r)
    check("asset_report writes an HTML flow graph", html and os.path.exists(html.group(1)), r)
    check("asset_report mermaid graph", "flowchart LR" in r, r)

    r = T.alloc_report("summary")
    check("alloc_report summary", "allocations" in r and "peak" in r, r)
    r = T.alloc_report("leaks")
    check("alloc_report finds the c.dat leak", "load_level" in r and "live of" in r, r)
    ui = T.S.control.read_memory(T.S.labels.lookup_name("g_player") - 0x100, 4)  # just exercise reads
    r = T.alloc_report("live")
    first_ptr = re.search(r"(0x[0-9a-f]{8})", r.split("\n", 1)[1]).group(1)
    r = T.alloc_report("owner", address=first_ptr)
    check("alloc_report owner", "allocated at frame" in r, r)
    r = T.alloc_report("graph")
    check("alloc_report graph", "flowchart LR" in r, r)
    T.alloc_stop()

    r = T.func_trace_log("fs_read_file", limit=5)
    check("func_trace_log shows arguments, returns and callers", "calls; callers" in r and "-> r0=" in r
          and "load_level" in r, r)
    T.func_trace_stop()

    r = T.input_trace_report(stop=True)
    check("input_trace_report timeline", "frame" in r and "start" in r and ": a" in r, r)
    check("input_trace_report finds the KEYINPUT reader", "KEYINPUT" in r and "game_main" in r, r)

    r = T.perf_profile(frames=20)
    check("perf_profile", "self time" in r and "game_main" in r and "stacks in use" in r, r)
    r = T.func_hot(frames=20)
    check("func_hot finds per-frame functions", "once per frame" in r and "handle_input" in r
          and "build_display_list" in r, r)
    r = T.nitro_scan()
    check("nitro_scan fingerprints the card code", "card (" in r and "card_read_block" in r, r)

    print("== record and replay ==")
    tmp = tempfile.mkdtemp()
    inputs = os.path.join(tmp, "run.inputs")
    r = T.input_record_start(inputs)
    check("input_record_start", "recording" in r, r)
    T.emu_press(["right"], frames=12, screenshot=False)
    T.emu_press(["down", "right"], frames=6, screenshot=False)
    T.emu_touch(100, 90, frames=3, screenshot=False)
    T.emu_frame_advance(5)
    r = T.input_record_stop()
    check("input_record_stop writes a script", "right" in r and "right+down" in r and "touch 100 90" in r, r)
    x_after = struct.unpack("<i", T.S.control.read_memory(symbols()["g_player"], 4))[0]
    r = T.input_replay(inputs, sample=["x:s32:g_player"], screenshot=False)
    xs = [int(v) for v in re.search(r"x: \[([^\]]*)\]", r).group(1).split(",")]
    check("input_replay reproduces the run", xs[-1] == x_after, f"{xs[-3:]} vs {x_after}")
    T.emu_stop()

    print("== oracle CLI (headless, no display) ==")
    env = dict(os.environ)
    env.pop("DISPLAY", None)
    env.pop("WAYLAND_DISPLAY", None)
    env["PYTHONPATH"] = PKG
    test = os.path.join(PKG, "testgame", "tests", "movement.oracle")
    res = os.path.join(tmp, "res.json")
    p = subprocess.run([sys.executable, "-m", "desmume_mcp.oracle", "run", ROM, test, "--labels", SYMS,
                        "--out", res], env=env, capture_output=True, text=True, timeout=300)
    check("oracle run passes the movement test", p.returncode == 0 and "PASSED" in p.stderr, p.stderr[-2000:])
    import json
    data = json.load(open(res))
    check("oracle results include per-frame samples", len(data["series"]["x"]) > 10, str(data)[:500])
    bad = os.path.join(tmp, "bad.oracle")
    with open(bad, "w") as f:
        f.write("reset\nwait 10\nexpect s32 g_player == 999\n")
    p = subprocess.run([sys.executable, "-m", "desmume_mcp.oracle", "run", ROM, bad, "--labels", SYMS,
                        "--out", res], env=env, capture_output=True, text=True, timeout=300)
    check("oracle run fails a wrong expectation (exit 1)", p.returncode == 1 and "FAIL line 3" in p.stderr,
          p.stderr[-2000:])
    p = subprocess.run([sys.executable, "-m", "desmume_mcp.oracle", "replay", ROM, inputs, "--check",
                        "--labels", SYMS, "--sample", "x:s32:g_player"], env=env, capture_output=True,
                       text=True, timeout=300)
    ok = p.returncode == 0 and '"deterministic": true' in p.stdout
    check("oracle replay --check is deterministic", ok, p.stdout[-1000:] + p.stderr[-1000:])


async def part2():
    from mcp import ClientSession, StdioServerParameters
    from mcp.client.stdio import stdio_client

    env = dict(os.environ)
    env["PYTHONPATH"] = PKG + os.pathsep + env.get("PYTHONPATH", "")
    params = StdioServerParameters(command=sys.executable, args=["-m", "desmume_mcp"], env=env)
    async with stdio_client(params) as (read, write):
        async with ClientSession(read, write) as session:
            await session.initialize()
            tools = (await session.list_tools()).tools
            names = {t.name for t in tools}
            check(f"MCP lists tools ({len(names)})", {"emu_start", "dbg_break", "gx_capture", "freeze_dump"} <= names)

            async def call(name, **args):
                r = await session.call_tool(name, args)
                err = getattr(r, "is_error", None)
                if err is None:
                    err = getattr(r, "isError", False)
                return r, err

            r, err = await call("emu_start", rom_path=ROM, headless=True)
            check("MCP emu_start", not err and "MCPTESTGAME" in r.content[0].text, r.content[0].text)
            r, err = await call("emu_screenshot")
            check("MCP image content", not err and r.content[0].type == "image")
            target = symbols()["build_display_list"]
            r, err = await call("dbg_break", address=hex(target))
            r, err = await call("dbg_continue", timeout=5)
            check("MCP breakpoint", not err and f"{target:08x}" in r.content[0].text, r.content[0].text)
            r, err = await call("mem_read", address="nonexistent_label")
            check("MCP reports errors", err)
            await call("emu_stop")


def main():
    only_protocol = "--only-protocol" in sys.argv
    if "--keep-data" not in sys.argv:
        os.environ["DESMUME_MCP_HOME"] = tempfile.mkdtemp(prefix="desmume-mcp-test-")
    for part in ([] if only_protocol else [part1, part3]):
        try:
            part()
        except Exception:
            traceback.print_exc()
            check(f"{part.__name__} completed without exceptions", False)
            from desmume_mcp import server as T
            if T.S is not None:
                print(T.S.log_tail())
                T.S.stop()
                T.S = None
    print("== MCP protocol ==")
    try:
        asyncio.run(part2())
    except Exception:
        traceback.print_exc()
        check("part 2 completed without exceptions", False)
    failed = [n for n, ok in results if not ok]
    print(f"\n{len(results) - len(failed)}/{len(results)} checks passed")
    sys.exit(1 if failed else 0)


if __name__ == "__main__":
    main()
