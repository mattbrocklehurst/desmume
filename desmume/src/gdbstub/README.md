# DeSmuME GDB stub

DeSmuME can expose the ARM9 and/or ARM7 CPU as a GDB remote target over TCP.
DeSmuME listens; gdb connects with `target remote`.

## Building (Linux, meson)

```sh
cd desmume/src/frontend/posix
meson setup build -Dgdb-stub=true
ninja -C build
```

This builds `build/cli/desmume-cli` (and `build/gtk/desmume` if GTK3 is
available) with the stub enabled. JIT is turned off automatically when a stub
is active.

## Running

```sh
./build/cli/desmume-cli --arm9gdb 20000 --arm7gdb 20001 game.nds
```

Each enabled CPU starts **halted** and waits for gdb. If you enable both stubs
you have to attach to (and `continue`) both, otherwise the other CPU stays
stalled. Usually you only want `--arm9gdb`.

## Connecting

Use `gdb-multiarch` (Debian/Ubuntu package `gdb-multiarch`) or `arm-none-eabi-gdb`:

```
$ gdb-multiarch
(gdb) set architecture armv5te        # ARM946E-S; use armv4t for the ARM7
(gdb) target remote localhost:20000
(gdb) break *0x02000800
(gdb) continue
(gdb) info registers
(gdb) x/8i $pc
(gdb) stepi
(gdb) watch *(int*)0x02100000        # also rwatch / awatch
(gdb) detach                          # clears breakpoints, game keeps running
```

Supported: register read/write (`g`/`G`/`P`), memory read/write (`m`/`M`),
continue, single step, Ctrl-C break-in, instruction breakpoints (`Z0`/`Z1`),
write/read/access watchpoints (`Z2`/`Z3`/`Z4`), detach (`D`), and reattaching
to a running game (the CPU is halted when gdb connects).

Notes:

* No symbols are available, so use `break *ADDR`, `x/i`, and `display/i $pc`.
* Watchpoints stop a few instructions after the access, not exactly on it.
* Breakpoints are checked on instruction fetch, so they work in any memory
  region, including code copied to RAM or ITCM at runtime.

## Scripted / non-interactive use

`gdb -batch -x script.gdb` works well for automation. A `continue` in a batch
script blocks until a breakpoint or watchpoint is hit, so always set one first.
