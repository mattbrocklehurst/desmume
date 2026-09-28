#!/bin/sh
# Build desmume-cli with the gdb stub and the control interface enabled.
#
# Debian/Ubuntu dependencies:
#   sudo apt install meson ninja-build g++ pkg-config libsdl2-dev libglib2.0-dev \
#                    libpcap-dev zlib1g-dev libx11-dev
# Optional: xvfb (headless runs), ffmpeg (video recording), gdb-multiarch.
#
# The binary ends up in desmume/src/frontend/posix/build/cli/desmume-cli,
# which is where the MCP server looks for it by default.
set -e

repo=$(cd "$(dirname "$0")/../../.." && pwd)
src="$repo/desmume/src/frontend/posix"
build="$src/build"

if [ ! -f "$build/build.ninja" ]; then
    meson setup "$build" "$src" -Dgdb-stub=true -Dfrontend-cli=true -Dfrontend-gtk=false "$@"
fi
ninja -C "$build" cli/desmume-cli

echo
echo "built $build/cli/desmume-cli"
