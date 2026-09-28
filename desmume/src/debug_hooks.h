/*
	Copyright (C) 2026 DeSmuME team

	This file is free software: you can redistribute it and/or modify
	it under the terms of the GNU General Public License as published by
	the Free Software Foundation, either version 2 of the License, or
	(at your option) any later version.

	This file is distributed in the hope that it will be useful,
	but WITHOUT ANY WARRANTY; without even the implied warranty of
	MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
	GNU General Public License for more details.

	You should have received a copy of the GNU General Public License
	along with the this software.  If not, see <http://www.gnu.org/licenses/>.
*/

/*
 * Event hooks for debugging tools. The emulator core reports interesting
 * hardware events here; a frontend installs a handler and enables the events
 * it cares about. When an event is disabled the cost is a single flag test.
 *
 * The definitions live in debug.cpp.
 */

#ifndef DEBUG_HOOKS_H
#define DEBUG_HOOKS_H

#include "types.h"

enum DebugHookEvent
{
	DEBUG_HOOK_CARD = 0,	// game card command started: a = cmd bytes 0-3 (big endian), b = bytes 4-7, c = transfer length, d = ROM address for B7 reads
	DEBUG_HOOK_DMA,			// DMA copy started: a = channel | startmode << 8, b = source, c = destination, d = byte count
	DEBUG_HOOK_GX,			// geometry command queued for the 3D engine: a = command id, b = parameter
	DEBUG_HOOK_SWAP,		// SWAP_BUFFERS executed (a 3D frame is complete): a = parameter
	DEBUG_HOOK_COUNT
};

struct DebugHookInfo
{
	DebugHookEvent event;
	int cpu;			// ARMCPU_ARM9 or ARMCPU_ARM7
	u32 args[4];
	u32 dma_source;		// address of the word being transferred when the event comes from a DMA, else 0
};

typedef void (*DebugHookHandler)(const DebugHookInfo &info);

extern bool debug_hooks_enabled[DEBUG_HOOK_COUNT];
extern DebugHookHandler debug_hook_handler;

// set by the DMA controller while it copies, so that events caused by a DMA
// (e.g. geometry commands sent to the GX FIFO) can report where the data came from
extern u32 debug_hook_dma_source;

void debug_hook_dispatch(DebugHookEvent event, int cpu, u32 a, u32 b, u32 c, u32 d);

static inline void debug_hook(DebugHookEvent event, int cpu, u32 a, u32 b = 0, u32 c = 0, u32 d = 0)
{
	if (debug_hooks_enabled[event])
		debug_hook_dispatch(event, cpu, a, b, c, d);
}

#endif
