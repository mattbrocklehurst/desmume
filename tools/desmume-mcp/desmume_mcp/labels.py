"""Per-game label database: the symbol table you build up while reversing.

Stored as JSON in <data_dir>/labels/<GAMECODE>.json so that it survives
sessions and can be edited by hand or kept under version control.
"""

import json
import os
import re
import time

LABEL_TYPES = ("func", "data", "code", "struct", "string", "other")
NAME_RE = re.compile(r"^[A-Za-z_.$][A-Za-z0-9_.$@]*$")


class LabelDB:
    def __init__(self, path):
        self.path = path
        self.labels = {}  # addr -> {"name", "type", "size", "comment", "cpu"}
        if os.path.exists(path):
            with open(path) as f:
                raw = json.load(f)
            for addr, entry in raw.get("labels", {}).items():
                self.labels[int(addr, 16)] = entry
        self._rebuild()

    def _rebuild(self):
        self.by_name = {e["name"]: a for a, e in self.labels.items()}
        self.sorted_addrs = sorted(self.labels)

    def save(self):
        os.makedirs(os.path.dirname(self.path), exist_ok=True)
        data = {
            "updated": time.strftime("%Y-%m-%dT%H:%M:%S"),
            "labels": {f"{a:#010x}": self.labels[a] for a in self.sorted_addrs},
        }
        tmp = self.path + ".tmp"
        with open(tmp, "w") as f:
            json.dump(data, f, indent=1)
        os.replace(tmp, self.path)

    # editing ----------------------------------------------------------------

    def set(self, addr, name, type="func", size=0, comment="", cpu="arm9"):
        if not NAME_RE.match(name):
            raise ValueError(f"invalid label name {name!r} (use letters, digits, _ . $ @)")
        if type not in LABEL_TYPES:
            raise ValueError(f"type must be one of {', '.join(LABEL_TYPES)}")
        other = self.by_name.get(name)
        if other is not None and other != addr:
            raise ValueError(f"label {name} already exists at {other:#010x}")
        old = self.labels.get(addr, {})
        self.labels[addr] = {
            "name": name, "type": type, "size": int(size or old.get("size", 0)),
            "comment": comment if comment else old.get("comment", ""), "cpu": cpu,
        }
        self._rebuild()
        self.save()
        return self.labels[addr]

    def comment(self, addr, text):
        """Attach a comment to an address; creates an anonymous label if needed."""
        if addr in self.labels:
            self.labels[addr]["comment"] = text
        else:
            self.labels[addr] = {"name": f"loc_{addr:08x}", "type": "other", "size": 0,
                                 "comment": text, "cpu": "arm9"}
        self._rebuild()
        self.save()

    def delete(self, addr):
        entry = self.labels.pop(addr, None)
        self._rebuild()
        self.save()
        return entry

    # lookup -----------------------------------------------------------------

    def lookup_name(self, name):
        return self.by_name.get(name)

    def describe(self, addr, max_offset=0x1000):
        """'name' for an exact hit, 'name+0x10' inside/near a function or data
        label, else None."""
        if addr in self.labels:
            return self.labels[addr]["name"]
        best = None
        for a in reversed(self.sorted_addrs):
            if a <= addr:
                best = a
                break
        if best is None:
            return None
        e = self.labels[best]
        off = addr - best
        if (e["size"] and off < e["size"]) or (not e["size"] and off < max_offset):
            return f"{e['name']}+{off:#x}"
        return None

    def search(self, text="", type=None):
        text = text.lower()
        out = []
        for a in self.sorted_addrs:
            e = self.labels[a]
            if type and e["type"] != type:
                continue
            if text and text not in e["name"].lower() and text not in e.get("comment", "").lower():
                continue
            out.append((a, e))
        return out

    # import / export --------------------------------------------------------

    def import_text(self, text, default_type="func"):
        """Accepts nm output ('02000000 T name'), 'name = 0x02000000;' linker
        style, or 'name 0x02000000' / '0x02000000 name' pairs."""
        count = 0
        for line in text.splitlines():
            line = line.split("//")[0].split("#")[0].strip().rstrip(";")
            if not line:
                continue
            m = (re.match(r"^([0-9a-fA-F]{8})\s+([A-Za-z])\s+(\S+)$", line) or
                 re.match(r"^(\S+)\s*=\s*(0x[0-9a-fA-F]+)$", line) or
                 re.match(r"^(0x[0-9a-fA-F]+)\s+(\S+)$", line) or
                 re.match(r"^(\S+)\s+(0x[0-9a-fA-F]+)$", line))
            if not m:
                continue
            g = m.groups()
            if len(g) == 3:
                addr, kind, name = int(g[0], 16), g[1], g[2]
                type = "func" if kind in "Tt" else "data"
            elif g[0].startswith("0x"):
                addr, name, type = int(g[0], 16), g[1], default_type
            else:
                name, addr, type = g[0], int(g[1], 16), default_type
            if not NAME_RE.match(name) or name.startswith("$"):
                continue
            if name in self.by_name and self.by_name[name] != addr:
                continue
            self.labels[addr] = {"name": name, "type": type, "size": 0, "comment": "", "cpu": "arm9"}
            self.by_name[name] = addr
            count += 1
        self._rebuild()
        self.save()
        return count

    def export_text(self, fmt="sym"):
        lines = []
        for a in self.sorted_addrs:
            e = self.labels[a]
            if fmt == "sym":        # nm style, also readable by import_text
                lines.append(f"{a:08x} {'T' if e['type'] == 'func' else 'D'} {e['name']}")
            elif fmt == "ghidra":   # for Ghidra's ImportSymbolsScript.py
                lines.append(f"{e['name']} {a:#010x} {'f' if e['type'] == 'func' else 'l'}")
            elif fmt == "ld":       # linker script symbol definitions
                lines.append(f"{e['name']} = {a:#010x};")
            elif fmt == "gdb":      # gdb convenience variables
                lines.append(f"set ${e['name']} = {a:#010x}")
            else:
                raise ValueError("format must be sym, ghidra, ld or gdb")
        return "\n".join(lines) + "\n"
