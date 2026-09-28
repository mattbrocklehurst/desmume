"""Minimal GDB remote serial protocol client for DeSmuME's gdb stub.

Only what the stub implements is used: ?, g, P, m, M, c, s, Z/z 0-4, D and
the Ctrl-C break byte. A reader thread splits the incoming stream into acks
and packets so that asynchronous stop replies (after a continue) are never
lost.
"""

import queue
import socket
import struct
import threading
import time


class GdbError(RuntimeError):
    pass


# gdb signal numbers used by the stub
SIGINT = 2
SIGTRAP = 5


class StopEvent:
    def __init__(self, packet):
        self.packet = packet
        self.signal = None
        self.watch_kind = None  # "write", "read" or "access"
        self.watch_addr = None
        if packet[:1] in ("S", "T"):
            self.signal = int(packet[1:3], 16)
        if packet[:1] == "T":
            for field in packet[3:].split(";"):
                if ":" not in field:
                    continue
                key, value = field.split(":", 1)
                kind = {"watch": "write", "rwatch": "read", "awatch": "access"}.get(key)
                if kind:
                    self.watch_kind = kind
                    self.watch_addr = int(value, 16)

    def __repr__(self):
        return f"StopEvent({self.packet!r})"


class GdbClient:
    def __init__(self, host="127.0.0.1", port=0, timeout=10.0):
        self.sock = socket.create_connection((host, port), timeout=timeout)
        self.sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
        self.sock.settimeout(None)
        self.timeout = timeout
        self.acks = queue.Queue()
        self.packets = queue.Queue()
        self.lock = threading.Lock()
        self.closed = False
        self.running = False
        self.last_stop = None
        self.reader = threading.Thread(target=self._reader, daemon=True)
        self.reader.start()

        # the stub halts the CPU when gdb connects; find out why it stopped
        self.last_stop = StopEvent(self.request("?"))

    # transport ------------------------------------------------------------

    def _reader(self):
        buf = b""
        try:
            while True:
                data = self.sock.recv(4096)
                if not data:
                    break
                buf += data
                while buf:
                    c = buf[:1]
                    if c in (b"+", b"-"):
                        self.acks.put(c)
                        buf = buf[1:]
                    elif c == b"$":
                        end = buf.find(b"#")
                        if end < 0 or len(buf) < end + 3:
                            break
                        body = buf[1:end]
                        buf = buf[end + 3:]
                        self.sock.sendall(b"+")
                        self.packets.put(body.decode("latin-1"))
                    else:
                        buf = buf[1:]
        except OSError:
            pass
        self.closed = True
        self.acks.put(None)
        self.packets.put(None)

    def close(self):
        self.closed = True
        try:
            self.sock.shutdown(socket.SHUT_RDWR)
        except OSError:
            pass
        self.sock.close()

    def _send(self, data):
        """Send a packet and wait for it to be acknowledged. The stub NAKs
        packets while the CPU is running, so retry for a little while."""
        payload = data.encode("latin-1")
        frame = b"$" + payload + b"#" + b"%02x" % (sum(payload) & 0xFF)
        deadline = time.time() + self.timeout
        while True:
            if self.closed:
                raise GdbError("gdb connection closed")
            self.sock.sendall(frame)
            try:
                ack = self.acks.get(timeout=self.timeout)
            except queue.Empty:
                raise GdbError(f"no ack for packet {data[:20]!r}")
            if ack == b"+":
                return
            if ack is None:
                raise GdbError("gdb connection closed")
            if time.time() > deadline:
                raise GdbError(f"stub keeps refusing {data[:20]!r} (is the CPU running?)")
            time.sleep(0.02)

    def _recv(self, timeout):
        try:
            pkt = self.packets.get(timeout=timeout)
        except queue.Empty:
            return None
        if pkt is None:
            raise GdbError("gdb connection closed")
        return pkt

    def request(self, data, timeout=None):
        with self.lock:
            self._drain_stops()
            if self.running:
                raise GdbError("the CPU is running; halt it first")
            self._send(data)
            reply = self._recv(timeout or self.timeout)
            if reply is None:
                raise GdbError(f"no reply to {data[:20]!r}")
            return reply

    def _drain_stops(self):
        """Pick up a stop reply that arrived while we were not waiting."""
        if self.running:
            try:
                pkt = self.packets.get_nowait()
            except queue.Empty:
                return
            if pkt is None:
                raise GdbError("gdb connection closed")
            self.running = False
            self.last_stop = StopEvent(pkt)

    # execution control ------------------------------------------------------

    def is_running(self):
        with self.lock:
            self._drain_stops()
            return self.running

    def cont(self):
        with self.lock:
            self._drain_stops()
            if self.running:
                return
            self._send("c")
            self.running = True

    def wait_stop(self, timeout):
        """Wait up to timeout seconds for the CPU to stop. Returns the
        StopEvent, or None if it is still running."""
        with self.lock:
            if not self.running:
                return self.last_stop
            pkt = self._recv(timeout)
            if pkt is None:
                return None
            self.running = False
            self.last_stop = StopEvent(pkt)
            return self.last_stop

    def halt(self, timeout=5.0):
        with self.lock:
            self._drain_stops()
            if not self.running:
                return self.last_stop
            self.sock.sendall(b"\x03")
        stop = self.wait_stop(timeout)
        if stop is None:
            raise GdbError("CPU did not stop after the break request")
        return stop

    def step(self, timeout=5.0):
        with self.lock:
            self._drain_stops()
            if self.running:
                raise GdbError("the CPU is running; halt it first")
            self._send("s")
            self.running = True
        stop = self.wait_stop(timeout)
        if stop is None:
            raise GdbError("single step did not complete")
        return stop

    def detach(self):
        with self.lock:
            self._drain_stops()
            if self.running:
                self.sock.sendall(b"\x03")
                pkt = self._recv(5.0)
                self.running = False
                if pkt is not None:
                    self.last_stop = StopEvent(pkt)
            self._send("D")
            self._recv(2.0)
        self.close()

    # registers and memory ---------------------------------------------------

    def read_registers(self):
        """Returns (r0..r15 list, cpsr). r15 is the address of the next
        instruction to execute."""
        data = self.request("g")
        if data.startswith("E") or len(data) < 16 * 8:
            raise GdbError(f"bad register reply {data[:20]!r}")
        regs = [struct.unpack("<I", bytes.fromhex(data[i * 8:i * 8 + 8]))[0] for i in range(16)]
        cpsr_off = 16 * 8 + 8 * 24 + 8
        cpsr = struct.unpack("<I", bytes.fromhex(data[cpsr_off:cpsr_off + 8]))[0]
        return regs, cpsr

    def write_register(self, num, value):
        """num: 0-15 for r0-pc, 25 for cpsr (gdb's ARM numbering)."""
        reply = self.request(f"P{num:x}={struct.pack('<I', value & 0xFFFFFFFF).hex()}")
        if reply != "OK":
            raise GdbError(f"register write failed: {reply}")

    def read_memory(self, addr, length):
        out = b""
        while length > 0:
            chunk = min(length, 0x400)
            reply = self.request(f"m{addr:x},{chunk:x}")
            if reply.startswith("E"):
                raise GdbError(f"memory read failed at {addr:#x}: {reply}")
            out += bytes.fromhex(reply)
            addr += chunk
            length -= chunk
        return out

    # breakpoints ------------------------------------------------------------

    KINDS = {"exec": 0, "write": 2, "read": 3, "access": 4}

    def set_break(self, kind, addr, length=4):
        reply = self.request(f"Z{self.KINDS[kind]},{addr:x},{length:x}")
        if reply != "OK":
            raise GdbError(f"could not set {kind} breakpoint at {addr:#x}: {reply or 'unsupported'}")

    def clear_break(self, kind, addr, length=4):
        reply = self.request(f"z{self.KINDS[kind]},{addr:x},{length:x}")
        if reply != "OK":
            raise GdbError(f"could not remove {kind} breakpoint at {addr:#x}: {reply or 'unsupported'}")
