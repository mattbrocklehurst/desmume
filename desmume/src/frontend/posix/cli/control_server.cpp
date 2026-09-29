/* control_server.cpp - this file is part of DeSmuME
 *
 * Copyright (C) 2026 DeSmuME Team
 *
 * This file is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2, or (at your option)
 * any later version.
 *
 * This file is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 */

/*
 * Commands (one per line, arguments are key=value, values may be quoted):
 *
 *   status
 *   pause | resume
 *   frame_advance [n=1]           run n frames then pause, replies when done
 *   reset
 *   quit
 *   input buttons=a,b,up,... [frames=N]   hold buttons (N=0: until release)
 *   touch x=X y=Y [frames=N]              touch the bottom screen
 *   release                               release held buttons and touch
 *   registers [cpu=arm9|arm7]
 *   memory_map                    main RAM size, TCM locations, WRAMCNT
 *   read_memory addr=A len=N [cpu=arm9|arm7]    reply "data" is base64
 *   write_memory addr=A hex=BYTES [cpu=arm9|arm7]
 *   screenshot [path=FILE]        PNG of both screens, base64 if no path
 *   savestate_save path=FILE | savestate_load path=FILE
 *   movie_record path=FILE.dsm [from=now|reset] | movie_play path=FILE.dsm | movie_stop
 *   video_record path=FILE.mp4 | video_stop       (needs ffmpeg in PATH)
 *   dump dir=DIR [note=TEXT]      freeze the emulator and write a full state dump
 *   hook_set event=card|dma|gx|swap action=log|break|off [min=A] [max=A]
 *            [cmds=ID,ID..] [stack=WORDS] [frames=N]
 *                                 card: filter on ROM address, dma: on source or
 *                                 destination, gx: on command id and DMA source.
 *                                 break halts the CPU via the gdb stub right after
 *                                 the instruction that caused the event.
 *            input: KEYINPUT/EXTKEYIN reads, touch: ARM7 touch screen samples,
 *            input_state: the input applied to a frame changed
 *   hook_status | hook_clear
 *   trace_add addr=A [ret=0|1] [stack=WORDS] [name=TEXT]
 *                                 log calls to A (r0-r3, lr, stack) and, with
 *                                 ret=1, the matching return (r0, r1) without
 *                                 stopping; needs the gdb stub for that CPU
 *   trace_remove addr=A | trace_clear | trace_list
 *   trace_count_add addrs=A,B,.. | trace_count_remove addrs=A,B,..
 *                                 count-only tracepoints (hits in trace_list)
 *   profile_start [interval=N] | profile_stop | profile_get
 *                                 sample (cpu, pc, lr) every N instructions
 *   hook_log [since=SEQ] [limit=N]  records as arrays:
 *            [seq, event, frame, cpu, pc, lr, sp, thumb, a, b, c, d, dma_src, [stack words]]
 *
 * Numbers accept decimal or 0x prefixed hex.
 */

#include "control_server.h"

#include <errno.h>
#include <fcntl.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/select.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <time.h>
#include <zlib.h>

#include <map>
#include <string>
#include <vector>

#include "../NDSSystem.h"
#include "../MMU.h"
#include "../armcpu.h"
#include "../GPU.h"
#include "../saves.h"
#include "../movie.h"
#include "../debug_hooks.h"
#include <deque>
#include <map>

#ifdef GDB_STUB
#include "../gdbstub.h"
#define CTL_LOCK() gdbstub_mutex_lock()
#define CTL_UNLOCK() gdbstub_mutex_unlock()
#else
#define CTL_LOCK()
#define CTL_UNLOCK()
#endif

namespace {

typedef std::map<std::string, std::string> Args;

struct Client {
	int fd;
	std::string inbuf;
};

int listen_fd = -1;
std::vector<Client> clients;

bool paused = false;
bool quit_requested = false;
u64 frames_emulated = 0;

/* pending frame_advance request */
int advance_remaining = 0;
int advance_client = -1;

/* scripted input */
u16 held_buttons = 0;
int held_frames = 0; /* 0 = until release */
bool touch_active = false;
bool touch_applied = false;
u16 touch_x = 0, touch_y = 0;
int touch_frames = 0;

/* video recording */
FILE *video_pipe = NULL;
std::string video_path;
u64 video_frames = 0;

/* event hooks. Record event ids beyond the core's are produced here:
 * "ret" (a traced function returned) and "input_state" (the user input
 * applied to a frame changed). */
enum { HOOK_RET = DEBUG_HOOK_COUNT, HOOK_INPUT_STATE, HOOK_TOTAL };
const char *hook_names[HOOK_TOTAL] = { "card", "dma", "gx", "swap", "exec", "input", "touch", "ret", "input_state" };

struct HookConfig {
	HookConfig() : action(OFF), min(0), max(0xFFFFFFFF), have_range(false), stack_words(0), frames_left(0), hits(0) {}
	enum { OFF, LOG, BREAK } action;
	u32 min, max;
	bool have_range;
	std::vector<bool> cmds; /* gx command filter, empty = all */
	u32 stack_words;
	u32 frames_left; /* 0 = unlimited */
	u64 hits;
};
HookConfig hooks[HOOK_TOTAL];

/* function tracepoints (exec hook) */
struct TracePoint {
	std::string name;
	bool count_only;
	bool capture_ret;
	u32 stack_words;
	u64 hits;
};
std::map<u32, TracePoint> tracepoints;

struct PendingReturn {
	u32 ret_addr, sp, entry_addr;
	u64 entry_seq;
	int cpu;
};
std::deque<PendingReturn> pending_returns;
std::map<u32, int> return_refs;
const size_t PENDING_RETURNS_MAX = 20000;

/* sampling profiler: (cpu, pc, lr) -> samples */
struct ProfileKey {
	u32 cpu, pc, lr, sp_bucket, mode;
	bool operator<(const ProfileKey &o) const {
		if (cpu != o.cpu) return cpu < o.cpu;
		if (pc != o.pc) return pc < o.pc;
		if (lr != o.lr) return lr < o.lr;
		if (sp_bucket != o.sp_bucket) return sp_bucket < o.sp_bucket;
		return mode < o.mode;
	}
};
std::map<ProfileKey, u32> profile_samples;
u64 profile_total = 0;

void profile_handler(int cpu_num, u32 pc) {
	armcpu_t &cpu = cpu_num == ARMCPU_ARM9 ? NDS_ARM9 : NDS_ARM7;
	/* the stack pointer (in 256 byte buckets) tells threads apart */
	ProfileKey k = { (u32)cpu_num, pc & ~1u, cpu.R[14], cpu.R[13] >> 8, cpu.CPSR.bits.mode };
	profile_samples[k]++;
	profile_total++;
}

u16 last_input_mask = 0;
u32 last_touch = 0;

struct HookRecord {
	u64 seq;
	u8 event, cpu, thumb;
	s32 frame;
	u32 pc, lr, sp;
	u32 args[4];
	u32 dma_src;
	std::vector<u32> stack;
};
std::deque<HookRecord> hook_records;
u64 hook_seq = 0;
const size_t HOOK_LOG_MAX = 500000;
int (*hook_break_fn)(int cpu, const char *name) = NULL;

const int SCREEN_W = 256;
const int SCREEN_H = 384; /* both screens stacked */

/* ------------------------------------------------------------------ */
/* JSON helpers */

std::string json_escape(const std::string &s) {
	std::string out;
	for (size_t i = 0; i < s.size(); i++) {
		unsigned char c = s[i];
		switch (c) {
		case '"': out += "\\\""; break;
		case '\\': out += "\\\\"; break;
		case '\n': out += "\\n"; break;
		case '\r': out += "\\r"; break;
		case '\t': out += "\\t"; break;
		default:
			if (c < 0x20) {
				char buf[8];
				snprintf(buf, sizeof(buf), "\\u%04x", c);
				out += buf;
			} else {
				out += (char)c;
			}
		}
	}
	return out;
}

class Json {
public:
	Json() : first(true) { s = "{"; }
	Json &str(const char *k, const std::string &v) { key(k); s += "\"" + json_escape(v) + "\""; return *this; }
	Json &num(const char *k, s64 v) { key(k); char b[32]; snprintf(b, sizeof(b), "%lld", (long long)v); s += b; return *this; }
	Json &hex(const char *k, u32 v) { key(k); char b[16]; snprintf(b, sizeof(b), "\"0x%08x\"", v); s += b; return *this; }
	Json &boolean(const char *k, bool v) { key(k); s += v ? "true" : "false"; return *this; }
	Json &raw(const char *k, const std::string &v) { key(k); s += v; return *this; }
	std::string done() const { return s + "}"; }
private:
	void key(const char *k) { if (!first) s += ","; first = false; s += "\""; s += k; s += "\":"; }
	std::string s;
	bool first;
};

std::string error_reply(const std::string &msg) {
	return Json().boolean("ok", false).str("error", msg).done();
}

/* ------------------------------------------------------------------ */
/* encoding helpers */

std::string base64_encode(const u8 *data, size_t len) {
	static const char tbl[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
	std::string out;
	out.reserve(((len + 2) / 3) * 4);
	for (size_t i = 0; i < len; i += 3) {
		u32 v = data[i] << 16;
		if (i + 1 < len) v |= data[i + 1] << 8;
		if (i + 2 < len) v |= data[i + 2];
		out += tbl[(v >> 18) & 63];
		out += tbl[(v >> 12) & 63];
		out += (i + 1 < len) ? tbl[(v >> 6) & 63] : '=';
		out += (i + 2 < len) ? tbl[v & 63] : '=';
	}
	return out;
}

bool parse_hex_bytes(const std::string &s, std::vector<u8> &out) {
	if (s.size() % 2) return false;
	for (size_t i = 0; i < s.size(); i += 2) {
		char b[3] = { s[i], s[i + 1], 0 };
		char *end;
		long v = strtol(b, &end, 16);
		if (*end) return false;
		out.push_back((u8)v);
	}
	return true;
}

bool parse_u32(const std::string &s, u32 &out) {
	if (s.empty()) return false;
	char *end;
	unsigned long long v = strtoull(s.c_str(), &end, 0);
	if (*end || v > 0xFFFFFFFFULL) return false;
	out = (u32)v;
	return true;
}

bool arg_u32(const Args &args, const char *name, u32 &out, bool required, u32 def = 0) {
	Args::const_iterator it = args.find(name);
	if (it == args.end()) {
		out = def;
		return !required;
	}
	return parse_u32(it->second, out);
}

std::string arg_str(const Args &args, const char *name, const std::string &def = "") {
	Args::const_iterator it = args.find(name);
	return it == args.end() ? def : it->second;
}

/* split a request line into a command and key=value arguments */
bool parse_line(const std::string &line, std::string &cmd, Args &args) {
	size_t i = 0;
	std::vector<std::string> tokens;
	while (i < line.size()) {
		while (i < line.size() && (line[i] == ' ' || line[i] == '\t')) i++;
		if (i >= line.size()) break;
		std::string tok;
		while (i < line.size() && line[i] != ' ' && line[i] != '\t') {
			if (line[i] == '"') {
				i++;
				while (i < line.size() && line[i] != '"') {
					if (line[i] == '\\' && i + 1 < line.size()) i++;
					tok += line[i++];
				}
				if (i >= line.size()) return false;
				i++;
			} else {
				tok += line[i++];
			}
		}
		tokens.push_back(tok);
	}
	if (tokens.empty()) return false;
	cmd = tokens[0];
	for (size_t t = 1; t < tokens.size(); t++) {
		size_t eq = tokens[t].find('=');
		if (eq == std::string::npos) return false;
		args[tokens[t].substr(0, eq)] = tokens[t].substr(eq + 1);
	}
	return true;
}

/* ------------------------------------------------------------------ */
/* screen capture */

void screen_rgb24(std::vector<u8> &rgb) {
	const u16 *src = GPU->GetDisplayInfo().masterNativeBuffer16;
	rgb.resize(SCREEN_W * SCREEN_H * 3);
	for (int i = 0; i < SCREEN_W * SCREEN_H; i++) {
		u16 c = src[i];
		u8 r = c & 0x1F, g = (c >> 5) & 0x1F, b = (c >> 10) & 0x1F;
		rgb[i * 3 + 0] = (r << 3) | (r >> 2);
		rgb[i * 3 + 1] = (g << 3) | (g >> 2);
		rgb[i * 3 + 2] = (b << 3) | (b >> 2);
	}
}

void png_chunk(std::string &out, const char *type, const std::string &data) {
	u8 len[4] = { (u8)(data.size() >> 24), (u8)(data.size() >> 16), (u8)(data.size() >> 8), (u8)data.size() };
	out.append((const char *)len, 4);
	std::string body = std::string(type, 4) + data;
	out += body;
	uLong crc = crc32(0L, (const Bytef *)body.data(), body.size());
	u8 c[4] = { (u8)(crc >> 24), (u8)(crc >> 16), (u8)(crc >> 8), (u8)crc };
	out.append((const char *)c, 4);
}

std::string encode_png(const std::vector<u8> &rgb, int w, int h) {
	std::string raw;
	raw.reserve((w * 3 + 1) * h);
	for (int y = 0; y < h; y++) {
		raw += '\0';
		raw.append((const char *)&rgb[y * w * 3], w * 3);
	}
	uLongf zlen = compressBound(raw.size());
	std::vector<u8> z(zlen);
	compress2(&z[0], &zlen, (const Bytef *)raw.data(), raw.size(), 6);

	std::string png("\x89PNG\r\n\x1a\n", 8);
	u8 ihdr[13] = { (u8)(w >> 24), (u8)(w >> 16), (u8)(w >> 8), (u8)w,
	                (u8)(h >> 24), (u8)(h >> 16), (u8)(h >> 8), (u8)h,
	                8, 2, 0, 0, 0 };
	png_chunk(png, "IHDR", std::string((const char *)ihdr, 13));
	png_chunk(png, "IDAT", std::string((const char *)&z[0], zlen));
	png_chunk(png, "IEND", "");
	return png;
}

std::string screenshot_png() {
	std::vector<u8> rgb;
	screen_rgb24(rgb);
	return encode_png(rgb, SCREEN_W, SCREEN_H);
}

bool write_file(const std::string &path, const void *data, size_t len) {
	FILE *f = fopen(path.c_str(), "wb");
	if (!f) return false;
	bool ok = fwrite(data, 1, len, f) == len;
	return (fclose(f) == 0) && ok;
}

/* ------------------------------------------------------------------ */
/* CPU and memory access */

bool arg_cpu(const Args &args, int &proc) {
	std::string c = arg_str(args, "cpu", "arm9");
	if (c == "arm9" || c == "9") { proc = ARMCPU_ARM9; return true; }
	if (c == "arm7" || c == "7") { proc = ARMCPU_ARM7; return true; }
	return false;
}

armcpu_t &cpu_for(int proc) {
	return proc == ARMCPU_ARM9 ? NDS_ARM9 : NDS_ARM7;
}

/* Reads through the CPU's view of the bus. I/O registers are read from their
 * backing store so that inspecting them has no side effects (e.g. popping a
 * FIFO). */
u8 debug_read8(int proc, u32 addr) {
	if ((addr & 0xFF000000) == 0x04000000) {
		u32 off = addr & 0x00FFFFFF;
		if (proc == ARMCPU_ARM9) return MMU.ARM9_REG[off];
		return off < sizeof(MMU.ARM7_REG) ? MMU.ARM7_REG[off] : 0;
	}
	return _MMU_read08(proc, MMU_AT_DEBUG, addr);
}

const char *mode_name(u32 mode) {
	switch (mode) {
	case 0x10: return "usr";
	case 0x11: return "fiq";
	case 0x12: return "irq";
	case 0x13: return "svc";
	case 0x17: return "abt";
	case 0x1B: return "und";
	case 0x1F: return "sys";
	default: return "unknown";
	}
}

std::string registers_json(armcpu_t &cpu) {
	const u32 mode = cpu.CPSR.bits.mode;
	Json j;
	char name[8];
	for (int i = 0; i < 15; i++) {
		snprintf(name, sizeof(name), "r%d", i);
		j.hex(name, cpu.R[i]);
	}
	/* same convention as the gdb stub: the address of the next instruction */
	j.hex("pc", cpu.instruct_adr);
	j.hex("cpsr", cpu.CPSR.val);
	j.hex("spsr", cpu.SPSR.val);
	j.str("mode", mode_name(mode));
	j.boolean("thumb", cpu.CPSR.bits.T != 0);
	j.boolean("irq_disabled", cpu.CPSR.bits.I != 0);

	/* banked registers; the ones of the current mode live in R[] */
	u32 usr13 = cpu.R13_usr, usr14 = cpu.R14_usr;
	u32 svc13 = cpu.R13_svc, svc14 = cpu.R14_svc;
	u32 abt13 = cpu.R13_abt, abt14 = cpu.R14_abt;
	u32 und13 = cpu.R13_und, und14 = cpu.R14_und;
	u32 irq13 = cpu.R13_irq, irq14 = cpu.R14_irq;
	u32 fiq13 = cpu.R13_fiq, fiq14 = cpu.R14_fiq;
	switch (mode) {
	case 0x10: case 0x1F: usr13 = cpu.R[13]; usr14 = cpu.R[14]; break;
	case 0x13: svc13 = cpu.R[13]; svc14 = cpu.R[14]; break;
	case 0x17: abt13 = cpu.R[13]; abt14 = cpu.R[14]; break;
	case 0x1B: und13 = cpu.R[13]; und14 = cpu.R[14]; break;
	case 0x12: irq13 = cpu.R[13]; irq14 = cpu.R[14]; break;
	case 0x11: fiq13 = cpu.R[13]; fiq14 = cpu.R[14]; break;
	}
	Json banked;
	banked.hex("r13_usr", usr13).hex("r14_usr", usr14)
	      .hex("r13_svc", svc13).hex("r14_svc", svc14).hex("spsr_svc", cpu.SPSR_svc.val)
	      .hex("r13_irq", irq13).hex("r14_irq", irq14).hex("spsr_irq", cpu.SPSR_irq.val)
	      .hex("r13_abt", abt13).hex("r14_abt", abt14).hex("spsr_abt", cpu.SPSR_abt.val)
	      .hex("r13_und", und13).hex("r14_und", und14).hex("spsr_und", cpu.SPSR_und.val)
	      .hex("r13_fiq", fiq13).hex("r14_fiq", fiq14).hex("spsr_fiq", cpu.SPSR_fiq.val);
	j.raw("banked", banked.done());
	j.boolean("halted_by_debugger", cpu.stalled != 0);
	j.boolean("waiting_for_irq", cpu.freeze != 0);
	return j.done();
}

/* ------------------------------------------------------------------ */
/* buttons */

int button_bit(const std::string &name) {
	/* bit positions match the keypad mask used by update_keypad() */
	static const char *names[] = { "a", "b", "select", "start", "right", "left", "up", "down",
	                               "r", "l", "x", "y", "debug", NULL, "lid" };
	for (int i = 0; i < 15; i++) {
		if (names[i] && name == names[i]) return i;
	}
	return -1;
}

bool parse_buttons(const std::string &list, u16 &mask, std::string &bad) {
	mask = 0;
	size_t start = 0;
	while (start <= list.size()) {
		size_t comma = list.find(',', start);
		std::string b = list.substr(start, comma == std::string::npos ? std::string::npos : comma - start);
		for (size_t i = 0; i < b.size(); i++) b[i] = tolower(b[i]);
		if (!b.empty()) {
			int bit = button_bit(b);
			if (bit < 0) { bad = b; return false; }
			mask |= 1 << bit;
		}
		if (comma == std::string::npos) break;
		start = comma + 1;
	}
	return true;
}

/* ------------------------------------------------------------------ */
/* video */

void video_stop() {
	if (video_pipe) {
		pclose(video_pipe);
		video_pipe = NULL;
	}
}

std::string shell_quote(const std::string &s) {
	std::string out = "'";
	for (size_t i = 0; i < s.size(); i++) {
		if (s[i] == '\'') out += "'\\''";
		else out += s[i];
	}
	return out + "'";
}

/* ------------------------------------------------------------------ */
/* the freeze / crash dump */

struct DumpRegion {
	const char *name;
	const char *file;
	const char *cpu;
	u32 base;
	const u8 *data;
	u32 size;
	const char *note;
};

bool mkdir_p(const std::string &path) {
	std::string cur;
	for (size_t i = 0; i < path.size(); i++) {
		cur += path[i];
		if (path[i] == '/' || i + 1 == path.size()) {
			if (mkdir(cur.c_str(), 0755) != 0 && errno != EEXIST) return false;
		}
	}
	return true;
}

std::string do_dump(const std::string &dir, const std::string &note, bool debugger_halted) {
	if (!mkdir_p(dir)) return error_reply("cannot create directory " + dir);

	/* freeze: stop at the next frame boundary if we are not halted by gdb */
	paused = true;

	const DumpRegion regions[] = {
		{ "main_ram", "main_ram.bin", "both", 0x02000000, MMU.MAIN_MEM, _MMU_MAIN_MEM_MASK + 1, "mirrored up to 0x02FFFFFF" },
		{ "itcm", "itcm.bin", "arm9", 0x00000000, MMU.ARM9_ITCM, sizeof(MMU.ARM9_ITCM), "mirrored every 32KB below 0x02000000" },
		{ "dtcm", "dtcm.bin", "arm9", MMU.DTCMRegion, MMU.ARM9_DTCM, sizeof(MMU.ARM9_DTCM), "base from CP15 DTCM region" },
		{ "shared_wram", "shared_wram.bin", "both", 0x03000000, MMU.SWIRAM, sizeof(MMU.SWIRAM), "split between CPUs by WRAMCNT" },
		{ "arm7_wram", "arm7_wram.bin", "arm7", 0x03800000, MMU.ARM7_ERAM, sizeof(MMU.ARM7_ERAM), "" },
		{ "arm9_io", "arm9_io.bin", "arm9", 0x04000000, MMU.ARM9_REG, 0x2000, "raw register backing store" },
		{ "arm7_io", "arm7_io.bin", "arm7", 0x04000000, MMU.ARM7_REG, 0x2000, "raw register backing store" },
		{ "palette", "palette.bin", "arm9", 0x05000000, MMU.ARM9_VMEM, sizeof(MMU.ARM9_VMEM), "" },
		{ "vram", "vram_lcdc.bin", "arm9", 0x06800000, MMU.ARM9_LCD, 0xA4000, "all VRAM banks in LCDC layout (A-I)" },
		{ "oam", "oam.bin", "arm9", 0x07000000, MMU.ARM9_OAM, sizeof(MMU.ARM9_OAM), "" },
	};

	std::string regions_json = "[";
	for (size_t i = 0; i < sizeof(regions) / sizeof(regions[0]); i++) {
		const DumpRegion &r = regions[i];
		if (!write_file(dir + "/" + r.file, r.data, r.size))
			return error_reply(std::string("failed to write ") + r.file);
		if (i) regions_json += ",";
		regions_json += Json().str("name", r.name).str("file", r.file).str("cpu", r.cpu)
		                      .hex("base", r.base).num("size", r.size).str("note", r.note).done();
	}
	regions_json += "]";

	std::string png = screenshot_png();
	write_file(dir + "/screen.png", png.data(), png.size());

	bool state_ok = savestate_save((dir + "/state.dst").c_str());

	char timebuf[64];
	time_t now = time(NULL);
	strftime(timebuf, sizeof(timebuf), "%Y-%m-%dT%H:%M:%S%z", localtime(&now));

	const NDS_header *hdr = NDS_getROMHeader();
	char gamecode[5] = { 0 };
	char title[13] = { 0 };
	memcpy(gamecode, hdr->gameCode, 4);
	memcpy(title, hdr->gameTile, 12);

	Json rom;
	rom.str("title", title).str("game_code", gamecode).hex("crc32", gameInfo.crc)
	   .hex("arm9_entry", hdr->ARM9exe).hex("arm9_load", hdr->ARM9cpy).num("arm9_size", hdr->ARM9binSize)
	   .hex("arm7_entry", hdr->ARM7exe).hex("arm7_load", hdr->ARM7cpy).num("arm7_size", hdr->ARM7binSize);

	Json mmu;
	mmu.hex("dtcm_region", MMU.DTCMRegion).hex("itcm_region", MMU.ITCMRegion)
	   .num("wramcnt", MMU.WRAMCNT).hex("main_mem_mask", _MMU_MAIN_MEM_MASK)
	   .hex("arm9_ie", MMU.reg_IE[ARMCPU_ARM9]).hex("arm9_if", MMU.gen_IF<ARMCPU_ARM9>())
	   .hex("arm7_ie", MMU.reg_IE[ARMCPU_ARM7]).hex("arm7_if", MMU.gen_IF<ARMCPU_ARM7>())
	   .num("arm9_ime", MMU.reg_IME[ARMCPU_ARM9]).num("arm7_ime", MMU.reg_IME[ARMCPU_ARM7]);

	Json manifest;
	manifest.str("format", "desmume-dump-1")
	        .str("created", timebuf)
	        .str("note", note)
	        .num("frame", currFrameCounter)
	        .num("frames_emulated", (s64)frames_emulated)
	        .boolean("halted_by_debugger", debugger_halted)
	        .raw("rom", rom.done())
	        .raw("arm9", registers_json(NDS_ARM9))
	        .raw("arm7", registers_json(NDS_ARM7))
	        .raw("mmu", mmu.done())
	        .raw("regions", regions_json)
	        .str("screenshot", "screen.png")
	        .str("savestate", state_ok ? "state.dst" : "");

	std::string m = manifest.done();
	if (!write_file(dir + "/manifest.json", m.data(), m.size()))
		return error_reply("failed to write manifest.json");

	return Json().boolean("ok", true).str("dir", dir).str("manifest", dir + "/manifest.json")
	             .boolean("savestate", state_ok).boolean("paused", true).done();
}

/* ------------------------------------------------------------------ */
/* event hooks */

u64 add_record(int event, int cpu_num, u32 pc, const u32 *args, u32 dma_src, u32 stack_words) {
	armcpu_t &cpu = cpu_for(cpu_num);
	HookRecord r;
	r.seq = ++hook_seq;
	r.event = event;
	r.cpu = cpu_num;
	r.frame = currFrameCounter;
	r.pc = pc;
	r.lr = cpu.R[14];
	r.sp = cpu.R[13];
	r.thumb = cpu.CPSR.bits.T;
	memcpy(r.args, args, sizeof(r.args));
	r.dma_src = dma_src;
	for (u32 i = 0; i < stack_words; i++) {
		u32 addr = r.sp + i * 4;
		u32 w = 0;
		for (int b = 0; b < 4; b++) w |= (u32)debug_read8(cpu_num, addr + b) << (b * 8);
		r.stack.push_back(w);
	}
	hook_records.push_back(r);
	if (hook_records.size() > HOOK_LOG_MAX) hook_records.pop_front();
	return r.seq;
}

void exec_update_enabled() {
	debug_hooks_enabled[DEBUG_HOOK_EXEC] = !tracepoints.empty() || !pending_returns.empty();
}

void release_return(u32 ret_addr) {
	if (--return_refs[ret_addr] <= 0) {
		return_refs.erase(ret_addr);
		if (!tracepoints.count(ret_addr)) debug_exec_trace_set(ret_addr, false);
	}
}

/* a traced address is about to execute: function entries and pending returns */
void exec_handler(const DebugHookInfo &info) {
	const u32 addr = info.args[0];
	armcpu_t &cpu = cpu_for(info.cpu);

	/* returns first: the caller's continuation may itself be traced */
	for (size_t i = pending_returns.size(); i-- > 0;) {
		const PendingReturn &p = pending_returns[i];
		if (p.ret_addr == addr && p.cpu == info.cpu && p.sp == cpu.R[13]) {
			u32 args[4] = { cpu.R[0], cpu.R[1], p.entry_addr, (u32)p.entry_seq };
			add_record(HOOK_RET, info.cpu, addr, args, 0, 0);
			pending_returns.erase(pending_returns.begin() + i);
			release_return(addr);
			break;
		}
	}

	std::map<u32, TracePoint>::iterator it = tracepoints.find(addr);
	if (it != tracepoints.end()) {
		TracePoint &t = it->second;
		t.hits++;
		if (t.count_only) {
			exec_update_enabled();
			return;
		}
		u32 args[4] = { cpu.R[0], cpu.R[1], cpu.R[2], cpu.R[3] };
		u64 seq = add_record(DEBUG_HOOK_EXEC, info.cpu, addr, args, 0, t.stack_words);
		if (t.capture_ret) {
			PendingReturn p;
			p.ret_addr = cpu.R[14] & ~1;
			p.sp = cpu.R[13];
			p.entry_addr = addr;
			p.entry_seq = seq;
			p.cpu = info.cpu;
			pending_returns.push_back(p);
			if (return_refs[p.ret_addr]++ == 0) debug_exec_trace_set(p.ret_addr, true);
			if (pending_returns.size() > PENDING_RETURNS_MAX) {
				/* never returned (longjmp, task switch...): forget the oldest */
				release_return(pending_returns.front().ret_addr);
				pending_returns.pop_front();
			}
		}
	}
	exec_update_enabled();
}

void hook_handler(const DebugHookInfo &info) {
	if (info.event == DEBUG_HOOK_EXEC) {
		exec_handler(info);
		return;
	}
	HookConfig &h = hooks[info.event];
	if (h.action == HookConfig::OFF) return;

	const u32 *a = info.args;
	if (h.have_range) {
		bool in = false;
		switch (info.event) {
		case DEBUG_HOOK_CARD: in = a[3] >= h.min && a[3] <= h.max; break;
		case DEBUG_HOOK_DMA: in = (a[1] >= h.min && a[1] <= h.max) || (a[2] >= h.min && a[2] <= h.max); break;
		case DEBUG_HOOK_GX: in = info.dma_source >= h.min && info.dma_source <= h.max; break;
		default: in = true; break;
		}
		if (!in) return;
	}
	if (info.event == DEBUG_HOOK_GX && !h.cmds.empty() && !h.cmds[a[0] & 0xFF]) return;

	h.hits++;
	add_record(info.event, info.cpu, cpu_for(info.cpu).instruct_adr, info.args, info.dma_source, h.stack_words);

	if (h.action == HookConfig::BREAK) {
		if (!hook_break_fn || !hook_break_fn(info.cpu, hook_names[info.event])) {
			/* no debugger attached: pause at the end of the frame instead */
			paused = true;
		}
	}
}

void hooks_update_enabled() {
	for (int i = 0; i < DEBUG_HOOK_COUNT; i++)
		debug_hooks_enabled[i] = hooks[i].action != HookConfig::OFF;
	debug_hook_handler = hook_handler;
	exec_update_enabled();
}

std::string hook_status_json() {
	std::string arr = "[";
	for (int i = 0; i < HOOK_TOTAL; i++) {
		if (i == DEBUG_HOOK_EXEC || i == HOOK_RET) continue; /* see trace_list */
		const HookConfig &h = hooks[i];
		if (arr.size() > 1) arr += ",";
		Json j;
		j.str("event", hook_names[i])
		 .str("action", h.action == HookConfig::OFF ? "off" : h.action == HookConfig::LOG ? "log" : "break")
		 .num("hits", (s64)h.hits).num("stack", h.stack_words).num("frames_left", h.frames_left);
		if (h.have_range) j.hex("min", h.min).hex("max", h.max);
		arr += j.done();
	}
	arr += "]";
	return Json().boolean("ok", true).raw("hooks", arr).num("records", hook_records.size())
	             .num("last_seq", (s64)hook_seq).done();
}

/* ------------------------------------------------------------------ */
/* command dispatch */

std::string status_json(bool debugger_halted) {
	const NDS_header *hdr = NDS_getROMHeader();
	char gamecode[5] = { 0 };
	char title[13] = { 0 };
	memcpy(gamecode, hdr->gameCode, 4);
	memcpy(title, hdr->gameTile, 12);

	const char *movie = "inactive";
	switch (movieMode) {
	case MOVIEMODE_RECORD: movie = "recording"; break;
	case MOVIEMODE_PLAY: movie = "playing"; break;
	case MOVIEMODE_FINISHED: movie = "finished"; break;
	default: break;
	}

	return Json().boolean("ok", true)
	             .str("title", title).str("game_code", gamecode)
	             .num("frame", currFrameCounter)
	             .num("frames_emulated", (s64)frames_emulated)
	             .boolean("paused", paused)
	             .boolean("halted_by_debugger", debugger_halted)
	             .hex("arm9_pc", NDS_ARM9.instruct_adr)
	             .hex("arm7_pc", NDS_ARM7.instruct_adr)
	             .str("movie", movie)
	             .str("video", video_pipe ? video_path : "")
	             .num("held_buttons", held_buttons)
	             .boolean("touching", touch_active)
	             .done();
}

/* returns an empty string when the reply is deferred */
std::string handle(int client_fd, const std::string &cmd, const Args &args, bool debugger_halted) {
	if (cmd == "status") return status_json(debugger_halted);

	if (cmd == "pause") {
		paused = true;
		return Json().boolean("ok", true).boolean("paused", true).done();
	}

	if (cmd == "resume") {
		paused = false;
		advance_remaining = 0;
		return Json().boolean("ok", true).boolean("paused", false)
		             .boolean("halted_by_debugger", debugger_halted).done();
	}

	if (cmd == "frame_advance") {
		u32 n;
		if (!arg_u32(args, "n", n, false, 1) || n == 0) return error_reply("bad n");
		if (debugger_halted) return error_reply("CPU is halted by the debugger, continue it first");
		if (advance_client != -1) return error_reply("a frame_advance is already in progress");
		advance_remaining = n;
		advance_client = client_fd;
		paused = false;
		return "";
	}

	if (cmd == "reset") {
		if (debugger_halted) return error_reply("CPU is halted by the debugger, continue or detach it first");
		NDS_Reset();
		return Json().boolean("ok", true).done();
	}

	if (cmd == "backup_import") {
		/* load a battery save (.sav raw / no$gba / .dsv) into the cartridge backup
		   memory, then reset so the game boots with it */
		std::string path = arg_str(args, "path");
		u32 size;
		if (path.empty()) return error_reply("missing path");
		if (!arg_u32(args, "size", size, false, 0)) return error_reply("bad size");
		if (debugger_halted) return error_reply("CPU is halted by the debugger, continue or detach it first");
		if (!MMU_new.backupDevice.importData(path.c_str(), size)) return error_reply("importing the save failed");
		NDS_Reset();
		return Json().boolean("ok", true).str("path", path).done();
	}

	if (cmd == "backup_export") {
		std::string path = arg_str(args, "path");
		if (path.empty()) return error_reply("missing path");
		if (!MMU_new.backupDevice.exportData(path.c_str())) return error_reply("exporting the save failed");
		return Json().boolean("ok", true).str("path", path).done();
	}

	if (cmd == "quit") {
		quit_requested = true;
		execute = false; /* also leaves the debugger idle loop */
		return Json().boolean("ok", true).done();
	}

	if (cmd == "input") {
		u16 mask;
		std::string bad;
		u32 frames;
		if (!parse_buttons(arg_str(args, "buttons"), mask, bad)) return error_reply("unknown button " + bad);
		if (!arg_u32(args, "frames", frames, false, 0)) return error_reply("bad frames");
		held_buttons = mask;
		held_frames = frames;
		return Json().boolean("ok", true).num("held_buttons", held_buttons).num("frames", frames).done();
	}

	if (cmd == "touch") {
		u32 x, y, frames;
		if (!arg_u32(args, "x", x, true) || x > 255) return error_reply("bad x (0-255)");
		if (!arg_u32(args, "y", y, true) || y > 191) return error_reply("bad y (0-191)");
		if (!arg_u32(args, "frames", frames, false, 0)) return error_reply("bad frames");
		touch_active = true;
		touch_x = x;
		touch_y = y;
		touch_frames = frames;
		return Json().boolean("ok", true).done();
	}

	if (cmd == "release") {
		held_buttons = 0;
		held_frames = 0;
		touch_active = false;
		return Json().boolean("ok", true).done();
	}

	if (cmd == "memory_map") {
		return Json().boolean("ok", true)
		             .hex("main_ram", 0x02000000).num("main_ram_size", _MMU_MAIN_MEM_MASK + 1)
		             .hex("itcm", 0x00000000).num("itcm_size", sizeof(MMU.ARM9_ITCM))
		             .hex("itcm_region", MMU.ITCMRegion)
		             .hex("dtcm", MMU.DTCMRegion).num("dtcm_size", sizeof(MMU.ARM9_DTCM))
		             .num("wramcnt", MMU.WRAMCNT).done();
	}

	if (cmd == "registers") {
		int proc;
		if (!arg_cpu(args, proc)) return error_reply("bad cpu");
		return Json().boolean("ok", true).raw("registers", registers_json(cpu_for(proc))).done();
	}

	if (cmd == "read_memory") {
		int proc;
		u32 addr, len;
		if (!arg_cpu(args, proc)) return error_reply("bad cpu");
		if (!arg_u32(args, "addr", addr, true)) return error_reply("bad addr");
		if (!arg_u32(args, "len", len, true) || len > 16 * 1024 * 1024) return error_reply("bad len (max 16MB)");
		std::vector<u8> buf(len);
		for (u32 i = 0; i < len; i++) buf[i] = debug_read8(proc, addr + i);
		return Json().boolean("ok", true).hex("addr", addr).num("len", len)
		             .str("data", len ? base64_encode(&buf[0], len) : "").done();
	}

	if (cmd == "write_memory") {
		int proc;
		u32 addr;
		std::vector<u8> data;
		if (!arg_cpu(args, proc)) return error_reply("bad cpu");
		if (!arg_u32(args, "addr", addr, true)) return error_reply("bad addr");
		if (!parse_hex_bytes(arg_str(args, "hex"), data)) return error_reply("bad hex");
		for (size_t i = 0; i < data.size(); i++) _MMU_write08(proc, MMU_AT_DEBUG, addr + i, data[i]);
		return Json().boolean("ok", true).num("written", data.size()).done();
	}

	if (cmd == "screenshot") {
		std::string png = screenshot_png();
		std::string path = arg_str(args, "path");
		if (path.empty())
			return Json().boolean("ok", true).num("width", SCREEN_W).num("height", SCREEN_H)
			             .str("png", base64_encode((const u8 *)png.data(), png.size())).done();
		if (!write_file(path, png.data(), png.size())) return error_reply("cannot write " + path);
		return Json().boolean("ok", true).str("path", path).done();
	}

	if (cmd == "savestate_save") {
		std::string path = arg_str(args, "path");
		if (path.empty()) return error_reply("missing path");
		if (!savestate_save(path.c_str())) return error_reply("savestate_save failed");
		return Json().boolean("ok", true).str("path", path).done();
	}

	if (cmd == "savestate_load") {
		std::string path = arg_str(args, "path");
		if (path.empty()) return error_reply("missing path");
		if (debugger_halted) return error_reply("CPU is halted by the debugger mid-frame; continue or detach it first");
		if (!savestate_load(path.c_str())) return error_reply("savestate_load failed");
		return Json().boolean("ok", true).str("path", path).done();
	}

	if (cmd == "movie_record") {
		std::string path = arg_str(args, "path");
		std::string from = arg_str(args, "from", "now");
		if (path.size() < 4) return error_reply("missing path (should end in .dsm)");
		if (debugger_halted) return error_reply("CPU is halted by the debugger; continue it first");
		START_FROM start;
		if (from == "now") start = START_SAVESTATE;
		else if (from == "reset") start = START_BLANK;
		else return error_reply("from must be now or reset");
		FCEUI_SaveMovie(path.c_str(), L"", start, "", FCEUI_MovieGetRTCDefault());
		return Json().boolean("ok", true).str("path", path).str("from", from).done();
	}

	if (cmd == "movie_play") {
		std::string path = arg_str(args, "path");
		if (path.empty()) return error_reply("missing path");
		if (debugger_halted) return error_reply("CPU is halted by the debugger; continue it first");
		const char *err = FCEUI_LoadMovie(path.c_str(), true, false, -1);
		if (err) return error_reply(err);
		return Json().boolean("ok", true).str("path", path).done();
	}

	if (cmd == "movie_stop") {
		FCEUI_StopMovie();
		return Json().boolean("ok", true).done();
	}

	if (cmd == "video_record") {
		std::string path = arg_str(args, "path");
		if (path.empty()) return error_reply("missing path");
		video_stop();
		std::string cmdline = "ffmpeg -loglevel error -y -f rawvideo -pixel_format bgr555le -video_size 256x384"
		                      " -framerate 60 -i - -pix_fmt yuv420p " + shell_quote(path);
		video_pipe = popen(cmdline.c_str(), "w");
		if (!video_pipe) return error_reply("could not start ffmpeg");
		video_path = path;
		video_frames = 0;
		return Json().boolean("ok", true).str("path", path).done();
	}

	if (cmd == "video_stop") {
		std::string path = video_path;
		u64 n = video_frames;
		bool was = video_pipe != NULL;
		video_stop();
		return Json().boolean("ok", true).boolean("was_recording", was).str("path", path).num("frames", (s64)n).done();
	}

	if (cmd == "hook_set") {
		std::string ev = arg_str(args, "event");
		int idx = -1;
		for (int i = 0; i < HOOK_TOTAL; i++) if (ev == hook_names[i]) idx = i;
		if (idx < 0 || idx == DEBUG_HOOK_EXEC || idx == HOOK_RET)
			return error_reply("event must be card, dma, gx, swap, input, touch or input_state (use trace_add for code)");
		HookConfig h;
		std::string action = arg_str(args, "action", "log");
		if (action == "off") h.action = HookConfig::OFF;
		else if (action == "log") h.action = HookConfig::LOG;
		else if (action == "break") h.action = HookConfig::BREAK;
		else return error_reply("action must be log, break or off");
		h.have_range = args.count("min") || args.count("max");
		if (!arg_u32(args, "min", h.min, false, 0)) return error_reply("bad min");
		if (!arg_u32(args, "max", h.max, false, 0xFFFFFFFF)) return error_reply("bad max");
		const bool no_stack = idx == DEBUG_HOOK_GX || idx == HOOK_INPUT_STATE || idx == DEBUG_HOOK_TOUCH;
		if (!arg_u32(args, "stack", h.stack_words, false, no_stack ? 0 : 16) || h.stack_words > 256)
			return error_reply("bad stack (0-256 words)");
		if (!arg_u32(args, "frames", h.frames_left, false, 0)) return error_reply("bad frames");
		std::string cmds = arg_str(args, "cmds");
		if (!cmds.empty()) {
			h.cmds.assign(256, false);
			size_t start = 0;
			while (start < cmds.size()) {
				size_t comma = cmds.find(',', start);
				std::string one = cmds.substr(start, comma == std::string::npos ? std::string::npos : comma - start);
				u32 id;
				if (!parse_u32(one, id) || id > 255) return error_reply("bad command id " + one);
				h.cmds[id] = true;
				if (comma == std::string::npos) break;
				start = comma + 1;
			}
		}
		h.hits = 0;
		hooks[idx] = h;
		if (idx == HOOK_INPUT_STATE) {
			/* make the first frame report the input that is already held */
			last_input_mask = 0xFFFF;
			last_touch = 0xFFFFFFFF;
		}
		hooks_update_enabled();
		return hook_status_json();
	}

	if (cmd == "hook_status") return hook_status_json();

	if (cmd == "trace_add") {
		u32 addr, ret, stack;
		if (!arg_u32(args, "addr", addr, true)) return error_reply("bad addr");
		if (!arg_u32(args, "ret", ret, false, 1)) return error_reply("bad ret");
		if (!arg_u32(args, "stack", stack, false, 16) || stack > 256) return error_reply("bad stack (0-256 words)");
		addr &= ~1;
		if ((addr & 0xFFC00000) != 0x02000000 && debug_exec_other_count >= 64)
			return error_reply("too many tracepoints outside main RAM");
		TracePoint t;
		t.name = arg_str(args, "name");
		t.count_only = false;
		t.capture_ret = ret != 0;
		t.stack_words = stack;
		t.hits = 0;
		tracepoints[addr] = t;
		debug_exec_trace_set(addr, true);
		debug_hook_handler = hook_handler;
		exec_update_enabled();
		return Json().boolean("ok", true).hex("addr", addr).num("tracepoints", tracepoints.size()).done();
	}

	if (cmd == "trace_remove" || cmd == "trace_clear") {
		if (cmd == "trace_clear") {
			tracepoints.clear();
			pending_returns.clear();
			return_refs.clear();
			debug_exec_trace_clear();
		} else {
			u32 addr;
			if (!arg_u32(args, "addr", addr, true)) return error_reply("bad addr");
			addr &= ~1;
			if (!tracepoints.erase(addr)) return error_reply("no tracepoint there");
			if (!return_refs.count(addr)) debug_exec_trace_set(addr, false);
		}
		exec_update_enabled();
		return Json().boolean("ok", true).num("tracepoints", tracepoints.size()).done();
	}

	if (cmd == "trace_count_add" || cmd == "trace_count_remove") {
		/* many count-only tracepoints at once: addrs=A,B,C... */
		std::string list = arg_str(args, "addrs");
		size_t start = 0;
		u32 n = 0;
		while (start < list.size()) {
			size_t comma = list.find(',', start);
			std::string one = list.substr(start, comma == std::string::npos ? std::string::npos : comma - start);
			u32 addr;
			if (!parse_u32(one, addr)) return error_reply("bad address " + one);
			addr &= ~1;
			if (cmd == "trace_count_add") {
				if (!tracepoints.count(addr) && ((addr & 0xFFC00000) == 0x02000000 || debug_exec_other_count < 64)) {
					TracePoint t;
					t.count_only = true;
					t.capture_ret = false;
					t.stack_words = 0;
					t.hits = 0;
					tracepoints[addr] = t;
					debug_exec_trace_set(addr, true);
					n++;
				}
			} else {
				std::map<u32, TracePoint>::iterator it = tracepoints.find(addr);
				if (it != tracepoints.end() && it->second.count_only) {
					tracepoints.erase(it);
					if (!return_refs.count(addr)) debug_exec_trace_set(addr, false);
					n++;
				}
			}
			if (comma == std::string::npos) break;
			start = comma + 1;
		}
		debug_hook_handler = hook_handler;
		exec_update_enabled();
		return Json().boolean("ok", true).num("changed", n).num("tracepoints", tracepoints.size()).done();
	}

	if (cmd == "profile_start") {
		u32 interval;
		if (!arg_u32(args, "interval", interval, false, 1000) || interval == 0) return error_reply("bad interval");
		profile_samples.clear();
		profile_total = 0;
		debug_profile_handler = profile_handler;
		debug_profile_countdown[0] = debug_profile_countdown[1] = interval;
		debug_profile_interval = interval;
		return Json().boolean("ok", true).num("interval", interval).done();
	}

	if (cmd == "profile_stop") {
		debug_profile_interval = 0;
		return Json().boolean("ok", true).num("samples", (s64)profile_total).done();
	}

	if (cmd == "profile_get") {
		/* [[cpu, pc, lr, count, sp_bucket << 8, mode], ...] */
		std::string out = "[";
		char buf[64];
		for (std::map<ProfileKey, u32>::iterator it = profile_samples.begin(); it != profile_samples.end(); ++it) {
			snprintf(buf, sizeof(buf), "%s[%u,%u,%u,%u,%u,%u]", out.size() > 1 ? "," : "",
			         it->first.cpu, it->first.pc, it->first.lr, it->second, it->first.sp_bucket << 8, it->first.mode);
			out += buf;
		}
		out += "]";
		return Json().boolean("ok", true).num("samples", (s64)profile_total)
		             .boolean("running", debug_profile_interval != 0).raw("counts", out).done();
	}

	if (cmd == "trace_list") {
		std::string arr = "[";
		for (std::map<u32, TracePoint>::iterator it = tracepoints.begin(); it != tracepoints.end(); ++it) {
			if (arr.size() > 1) arr += ",";
			arr += Json().hex("addr", it->first).str("name", it->second.name).boolean("ret", it->second.capture_ret)
			             .num("stack", it->second.stack_words).num("hits", (s64)it->second.hits).done();
		}
		arr += "]";
		return Json().boolean("ok", true).raw("tracepoints", arr).num("pending_returns", pending_returns.size()).done();
	}

	if (cmd == "hook_clear") {
		size_t n = hook_records.size();
		hook_records.clear();
		return Json().boolean("ok", true).num("cleared", n).done();
	}

	if (cmd == "hook_log") {
		u32 since, limit;
		if (!arg_u32(args, "since", since, false, 0)) return error_reply("bad since");
		if (!arg_u32(args, "limit", limit, false, 10000)) return error_reply("bad limit");
		std::string out = "[";
		u32 n = 0;
		u64 last = since;
		for (size_t i = 0; i < hook_records.size() && n < limit; i++) {
			const HookRecord &r = hook_records[i];
			if (r.seq <= since) continue;
			char buf[256];
			snprintf(buf, sizeof(buf), "%s[%llu,%u,%d,%u,%u,%u,%u,%u,%u,%u,%u,%u,%u,[",
			         n ? "," : "", (unsigned long long)r.seq, r.event, r.frame, r.cpu, r.pc, r.lr, r.sp,
			         r.thumb, r.args[0], r.args[1], r.args[2], r.args[3], r.dma_src);
			out += buf;
			for (size_t k = 0; k < r.stack.size(); k++) {
				snprintf(buf, sizeof(buf), "%s%u", k ? "," : "", r.stack[k]);
				out += buf;
			}
			out += "]]";
			last = r.seq;
			n++;
		}
		out += "]";
		bool more = !hook_records.empty() && hook_records.back().seq > last;
		return Json().boolean("ok", true).num("count", n).num("last_seq", (s64)last)
		             .boolean("more", more).raw("records", out).done();
	}

	if (cmd == "dump") {
		std::string dir = arg_str(args, "dir");
		if (dir.empty()) return error_reply("missing dir");
		return do_dump(dir, arg_str(args, "note"), debugger_halted);
	}

	return error_reply("unknown command " + cmd);
}

void send_line(int fd, const std::string &line) {
	std::string out = line + "\n";
	size_t sent = 0;
	while (sent < out.size()) {
		ssize_t n = send(fd, out.data() + sent, out.size() - sent, MSG_NOSIGNAL);
		if (n < 0) {
			if (errno == EINTR) continue;
			if (errno == EAGAIN || errno == EWOULDBLOCK) {
				fd_set w;
				FD_ZERO(&w);
				FD_SET(fd, &w);
				select(fd + 1, NULL, &w, NULL, NULL);
				continue;
			}
			return;
		}
		sent += n;
	}
}

void close_client(size_t idx) {
	if (clients[idx].fd == advance_client) advance_client = -1;
	close(clients[idx].fd);
	clients.erase(clients.begin() + idx);
}

} // namespace

bool ctl_init(int port) {
	signal(SIGPIPE, SIG_IGN);

	listen_fd = socket(AF_INET, SOCK_STREAM, 0);
	if (listen_fd < 0) return false;
	int one = 1;
	setsockopt(listen_fd, SOL_SOCKET, SO_REUSEADDR, &one, sizeof(one));

	struct sockaddr_in addr;
	memset(&addr, 0, sizeof(addr));
	addr.sin_family = AF_INET;
	addr.sin_port = htons(port);
	addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
	if (bind(listen_fd, (struct sockaddr *)&addr, sizeof(addr)) != 0 || listen(listen_fd, 4) != 0) {
		close(listen_fd);
		listen_fd = -1;
		return false;
	}
	fcntl(listen_fd, F_SETFL, O_NONBLOCK);
	return true;
}

void ctl_shutdown() {
	video_stop();
	while (!clients.empty()) close_client(0);
	if (listen_fd >= 0) close(listen_fd);
	listen_fd = -1;
}

void ctl_poll(int timeout_ms, bool in_debugger_idle) {
	if (listen_fd < 0) {
		if (timeout_ms > 0) usleep(timeout_ms * 1000);
		return;
	}

	/* gdb may already have resumed the CPUs while the emulation thread is
	 * still on its way out of the idle loop */
	const bool debugger_halted = in_debugger_idle && (NDS_ARM9.stalled || NDS_ARM7.stalled);

	/* a frame_advance cannot finish while gdb holds the CPU */
	if (debugger_halted && advance_client != -1) {
		send_line(advance_client, Json().boolean("ok", true).boolean("halted_by_debugger", true)
		                              .num("frames_remaining", advance_remaining)
		                              .hex("arm9_pc", NDS_ARM9.instruct_adr).done());
		advance_client = -1;
		advance_remaining = 0;
		paused = true;
	}

	fd_set rset;
	FD_ZERO(&rset);
	FD_SET(listen_fd, &rset);
	int maxfd = listen_fd;
	for (size_t i = 0; i < clients.size(); i++) {
		FD_SET(clients[i].fd, &rset);
		if (clients[i].fd > maxfd) maxfd = clients[i].fd;
	}
	struct timeval tv = { timeout_ms / 1000, (timeout_ms % 1000) * 1000 };
	if (select(maxfd + 1, &rset, NULL, NULL, &tv) <= 0) return;

	if (FD_ISSET(listen_fd, &rset)) {
		int fd = accept(listen_fd, NULL, NULL);
		if (fd >= 0) {
			int one = 1;
			setsockopt(fd, IPPROTO_TCP, TCP_NODELAY, &one, sizeof(one));
			Client c;
			c.fd = fd;
			clients.push_back(c);
		}
	}

	for (size_t i = 0; i < clients.size();) {
		if (!FD_ISSET(clients[i].fd, &rset)) { i++; continue; }
		char buf[4096];
		ssize_t n = recv(clients[i].fd, buf, sizeof(buf), 0);
		if (n <= 0) { close_client(i); continue; }
		clients[i].inbuf.append(buf, n);

		size_t nl;
		while ((nl = clients[i].inbuf.find('\n')) != std::string::npos) {
			std::string line = clients[i].inbuf.substr(0, nl);
			clients[i].inbuf.erase(0, nl + 1);
			if (!line.empty() && line[line.size() - 1] == '\r') line.erase(line.size() - 1);
			if (line.empty()) continue;

			std::string cmd;
			Args args;
			std::string reply;
			if (!parse_line(line, cmd, args)) {
				reply = error_reply("could not parse request");
			} else {
				CTL_LOCK();
				reply = handle(clients[i].fd, cmd, args, debugger_halted);
				CTL_UNLOCK();
			}
			if (!reply.empty()) send_line(clients[i].fd, reply);
		}
		i++;
	}
}

void ctl_input_applied() {
	if (hooks[HOOK_INPUT_STATE].action == HookConfig::OFF) return;
	const UserInput &in = NDS_getFinalUserInput();
	const UserButtons &b = in.buttons;
	/* same bit order as the input command: a b select start right left up down r l x y debug - lid */
	u16 mask = (b.A << 0) | (b.B << 1) | (b.T << 2) | (b.S << 3) | (b.R << 4) | (b.L << 5) | (b.U << 6) | (b.D << 7)
	         | (b.E << 8) | (b.W << 9) | (b.X << 10) | (b.Y << 11) | (b.G << 12) | (b.F << 14);
	/* the core keeps touch coordinates in 12.4 fixed point */
	u32 touch = in.touch.isTouch ? (0x80000000u | (in.touch.touchX >> 4) | ((in.touch.touchY >> 4) << 16)) : 0;
	if (mask == last_input_mask && touch == last_touch) return;
	u32 args[4] = { mask, touch, last_input_mask, last_touch };
	last_input_mask = mask;
	last_touch = touch;
	hooks[HOOK_INPUT_STATE].hits++;
	add_record(HOOK_INPUT_STATE, ARMCPU_ARM9, NDS_ARM9.instruct_adr, args, 0, 0);
}

void ctl_set_hook_break_fn(int (*fn)(int cpu, const char *name)) {
	hook_break_fn = fn;
}

bool ctl_is_paused() {
	return paused;
}

void ctl_toggle_pause() {
	paused = !paused;
	fprintf(stderr, "%s\n", paused ? "Paused (F11 to resume)" : "Resumed");
}

void ctl_hotkey_dump() {
	const char *base = getenv("DESMUME_DUMP_DIR");
	char stamp[32];
	time_t now = time(NULL);
	strftime(stamp, sizeof(stamp), "%Y%m%d-%H%M%S", localtime(&now));
	std::string dir = std::string(base && *base ? base : "dumps") + "/" + stamp + "-hotkey";

	std::string reply = do_dump(dir, "user pressed the freeze hotkey", false);
	if (reply.find("\"ok\":true") != std::string::npos)
		fprintf(stderr, "Frozen: state dumped to %s (F11 to resume)\n", dir.c_str());
	else
		fprintf(stderr, "Freeze dump failed: %s\n", reply.c_str());
}

bool ctl_quit_requested() {
	return quit_requested;
}

u16 ctl_pre_frame(u16 keypad) {
	if (touch_active) {
		NDS_setTouchPos(touch_x, touch_y);
		touch_applied = true;
	} else if (touch_applied) {
		NDS_releaseTouch();
		touch_applied = false;
	}
	return keypad | held_buttons;
}

void ctl_frame_done() {
	frames_emulated++;

	bool hooks_changed = false;
	for (int i = 0; i < HOOK_TOTAL; i++) {
		if (hooks[i].action != HookConfig::OFF && hooks[i].frames_left && --hooks[i].frames_left == 0) {
			hooks[i].action = HookConfig::OFF;
			hooks_changed = true;
		}
	}
	if (hooks_changed) hooks_update_enabled();

	if (held_buttons && held_frames > 0 && --held_frames == 0) held_buttons = 0;
	if (touch_active && touch_frames > 0 && --touch_frames == 0) touch_active = false;

	if (video_pipe) {
		const u16 *src = GPU->GetDisplayInfo().masterNativeBuffer16;
		if (fwrite(src, 2, SCREEN_W * SCREEN_H, video_pipe) != (size_t)(SCREEN_W * SCREEN_H)) {
			fprintf(stderr, "video recording stopped: ffmpeg is not accepting frames\n");
			video_stop();
		} else {
			video_frames++;
		}
	}

	if (advance_remaining > 0 && --advance_remaining == 0) {
		paused = true;
		if (advance_client != -1) {
			send_line(advance_client, Json().boolean("ok", true).num("frame", currFrameCounter)
			                              .num("frames_emulated", (s64)frames_emulated)
			                              .hex("arm9_pc", NDS_ARM9.instruct_adr).done());
			advance_client = -1;
		}
	}
}
