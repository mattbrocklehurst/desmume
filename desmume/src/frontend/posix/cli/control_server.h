/* control_server.h - this file is part of DeSmuME
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
 * A small line based TCP control interface for desmume-cli, intended to be
 * driven by scripts and agents (see tools/desmume-mcp).
 *
 * Each request is one line: a command name followed by key=value arguments
 * (values may be double quoted). Each reply is one line of JSON that always
 * contains "ok". See control_server.cpp for the list of commands.
 *
 * All emulator state is only touched from the emulation thread: the main loop
 * calls ctl_poll() between frames, and the debugger idle hook calls it while
 * the CPUs are halted by the gdb stub.
 */

#ifndef DESMUME_CLI_CONTROL_SERVER_H
#define DESMUME_CLI_CONTROL_SERVER_H

#include "types.h"

/* start listening on 127.0.0.1:port, returns false on failure */
bool ctl_init(int port);
void ctl_shutdown();

/* service pending connections and commands, waiting up to timeout_ms for
 * activity. in_debugger_idle is true when called from inside the gdb idle loop. */
void ctl_poll(int timeout_ms, bool in_debugger_idle);

/* true when the main loop should not emulate frames */
bool ctl_is_paused();

/* keyboard shortcuts: F11 toggles pause, F12 writes a freeze dump to
 * $DESMUME_DUMP_DIR (default ./dumps) and pauses */
void ctl_toggle_pause();
void ctl_hotkey_dump();

/* true when a client asked the emulator to exit */
bool ctl_quit_requested();

/* called before a frame is emulated: merges held buttons into the keypad
 * mask and applies/releases touch screen input */
u16 ctl_pre_frame(u16 keypad);

/* called after a frame has been emulated and drawn */
void ctl_frame_done();

#endif
