# DeSmuME
[![AppVeyor CI Build Status](https://ci.appveyor.com/api/projects/status/abfd7jm09wnmxyvu?svg=true)](https://ci.appveyor.com/project/zeromus/desmume)

DeSmuME is a Nintendo DS emulator.

http://desmume.org/download

## Debugging, automation and AI tooling (this fork)

- `desmume-cli` has a gdb stub (`--arm9gdb`/`--arm7gdb`, see
  [desmume/src/gdbstub/README.md](desmume/src/gdbstub/README.md)), a control
  port for scripting (`--control-port`), a headless mode (`--headless`) and
  reproducible runs (`--deterministic`).
- [tools/desmume-mcp](tools/desmume-mcp) is an MCP server that lets Claude
  (or any MCP client) play, debug and reverse engineer DS games, and an
  oracle test runner for comparing a port against the original game.
