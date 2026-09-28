"""Client for desmume-cli's --control-port line protocol.

Requests are one line: ``command key=value ...``; replies are one line of JSON
that always contains ``ok``. See desmume/src/frontend/posix/cli/control_server.cpp.
"""

import base64
import json
import socket


class ControlError(RuntimeError):
    pass


def _quote(value):
    s = str(value)
    if s and not any(c in s for c in ' \t"\\'):
        return s
    return '"' + s.replace("\\", "\\\\").replace('"', '\\"') + '"'


class ControlClient:
    def __init__(self, host="127.0.0.1", port=0, timeout=30.0):
        self.sock = socket.create_connection((host, port), timeout=timeout)
        self.sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
        self.file = self.sock.makefile("rwb")
        self.timeout = timeout

    def close(self):
        try:
            self.file.close()
            self.sock.close()
        except OSError:
            pass

    def call(self, command, timeout=None, **args):
        """Send one command and return the decoded reply; raises ControlError
        when the emulator reports a failure."""
        line = command
        for key, value in args.items():
            if value is None:
                continue
            if isinstance(value, bool):
                value = int(value)
            line += f" {key}={_quote(value)}"
        self.sock.settimeout(timeout if timeout is not None else self.timeout)
        try:
            self.file.write((line + "\n").encode())
            self.file.flush()
            raw = self.file.readline()
        except socket.timeout:
            raise ControlError(f"timed out waiting for reply to '{command}'")
        if not raw:
            raise ControlError("emulator closed the control connection")
        reply = json.loads(raw)
        if not reply.get("ok"):
            raise ControlError(reply.get("error", "unknown error"))
        return reply

    # convenience wrappers -------------------------------------------------

    def read_memory(self, addr, length, cpu="arm9"):
        reply = self.call("read_memory", addr=hex(addr), len=length, cpu=cpu)
        return base64.b64decode(reply["data"])

    def write_memory(self, addr, data, cpu="arm9"):
        return self.call("write_memory", addr=hex(addr), hex=bytes(data).hex(), cpu=cpu)

    def registers(self, cpu="arm9"):
        return self.call("registers", cpu=cpu)["registers"]

    def screenshot_png(self):
        return base64.b64decode(self.call("screenshot")["png"])
