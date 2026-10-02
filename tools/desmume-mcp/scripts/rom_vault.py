#!/usr/bin/env python3
"""Keep your own ROM dumps in a private git repo, encrypted, so another machine
(or a cloud session) can use them.

  push   ROM files -> tar.xz -> AES-256 (openssl, PBKDF2) -> 45 MB parts, committed
         to a dedicated branch (default `roms`) of the given repo, replacing what
         was there. A manifest with each ROM's name, size and SHA-1 is committed
         next to the parts (no ROM data in clear).
  fetch  that branch's parts -> decrypt -> extract into a directory, then check
         the SHA-1s against the manifest.

usage:
  rom_vault.py push  --repo ~/dev/revwork ph.nds st.nds [more.nds ...] [--branch roms]
  rom_vault.py fetch --repo ~/dev/revwork --out DIR [--branch roms]

The passphrase is read from $ROM_VAULT_PASS, else asked for. GitHub refuses files
over 100 MB, hence the parts; the branch keeps the large blobs out of `main`.
Needs git, openssl, tar, xz.
"""

import argparse
import getpass
import glob
import hashlib
import json
import os
import shutil
import subprocess
import sys
import tempfile

PART = 45 * 1024 * 1024


def run(*cmd, **kw):
    return subprocess.run(cmd, check=True, **kw)


def passphrase(confirm):
    p = os.environ.get("ROM_VAULT_PASS")
    if p:
        return p
    p = getpass.getpass("passphrase: ")
    if confirm and getpass.getpass("again: ") != p:
        sys.exit("passphrases differ")
    return p


def sha1(path):
    h = hashlib.sha1()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def game_info(path):
    with open(path, "rb") as f:
        hdr = f.read(16)
    clean = lambda b: "".join(chr(c) for c in b if 32 <= c < 127)
    return clean(hdr[:12].split(b"\0")[0]), clean(hdr[12:16])


def push(args):
    roms = [os.path.abspath(r) for r in args.roms]
    for r in roms:
        if not os.path.isfile(r):
            sys.exit(f"not found: {r}")
    names = [os.path.basename(r) for r in roms]
    if len(set(names)) != len(names):
        sys.exit("two ROMs share a file name")
    pw = passphrase(confirm=True)
    repo = os.path.abspath(args.repo)
    with tempfile.TemporaryDirectory() as tmp:
        wt = os.path.join(tmp, "wt")
        # a separate worktree of the vault branch: the user's checkout is left alone
        have = subprocess.run(["git", "-C", repo, "ls-remote", "--exit-code", "--heads", "origin", args.branch],
                              capture_output=True).returncode == 0
        if have:
            run("git", "-C", repo, "fetch", "-q", "origin", args.branch)
            run("git", "-C", repo, "worktree", "add", "-q", "-B", args.branch, wt, f"origin/{args.branch}")
        else:
            run("git", "-C", repo, "worktree", "add", "-q", "--orphan", "-b", args.branch, wt)
        try:
            vault = os.path.join(wt, "roms")
            shutil.rmtree(vault, ignore_errors=True)
            os.makedirs(vault)
            manifest = []
            for r in roms:
                title, code = game_info(r)
                manifest.append({"file": os.path.basename(r), "size": os.path.getsize(r), "sha1": sha1(r),
                                 "title": title, "game_code": code})
                print(f"  {os.path.basename(r)}: {title} [{code}] {manifest[-1]['size']:,} bytes")
            print("compressing and encrypting (takes a few minutes) ...")
            tar = subprocess.Popen(["tar", "-cJf", "-", "-C", "/", *[r.lstrip("/") for r in roms]],
                                   stdout=subprocess.PIPE)
            enc = subprocess.Popen(["openssl", "enc", "-aes-256-cbc", "-pbkdf2", "-iter", "200000", "-salt",
                                    "-pass", "env:ROM_VAULT_PASS"], stdin=tar.stdout, stdout=subprocess.PIPE,
                                   env=dict(os.environ, ROM_VAULT_PASS=pw))
            tar.stdout.close()
            n = 0
            while True:
                chunk = enc.stdout.read(PART)
                if not chunk:
                    break
                with open(os.path.join(vault, f"roms.tar.xz.enc.part-{n:03d}"), "wb") as f:
                    f.write(chunk)
                n += 1
            if enc.wait() or tar.wait():
                sys.exit("tar/openssl failed")
            json.dump({"roms": manifest, "parts": n, "format": "tar.xz | openssl aes-256-cbc pbkdf2 200000 | split"},
                      open(os.path.join(vault, "manifest.json"), "w"), indent=1)
            open(os.path.join(vault, "README.md"), "w").write(
                "Encrypted ROM dumps for private research. Restore with\n"
                "`tools/desmume-mcp/scripts/rom_vault.py fetch --repo <this repo> --out DIR` (desmume repo).\n")
            run("git", "-C", wt, "add", "-A", "roms")
            run("git", "-C", wt, "commit", "-q", "-m", f"ROM vault: {', '.join(m['game_code'] for m in manifest)}")
            run("git", "-C", wt, "push", "-q", "-u", "origin", f"{args.branch}:{args.branch}")
            print(f"pushed {n} parts to branch {args.branch}")
        finally:
            subprocess.run(["git", "-C", repo, "worktree", "remove", "--force", wt])


def fetch(args):
    repo = os.path.abspath(args.repo)
    run("git", "-C", repo, "fetch", "-q", "origin", args.branch)
    out = os.path.abspath(args.out)
    os.makedirs(out, exist_ok=True)
    with tempfile.TemporaryDirectory() as tmp:
        run("git", "-C", repo, "worktree", "add", "-q", "--detach", os.path.join(tmp, "wt"), f"origin/{args.branch}")
        try:
            vault = os.path.join(tmp, "wt", "roms")
            manifest = json.load(open(os.path.join(vault, "manifest.json")))
            parts = sorted(glob.glob(os.path.join(vault, "roms.tar.xz.enc.part-*")))
            pw = passphrase(confirm=False)
            cat = subprocess.Popen(["cat", *parts], stdout=subprocess.PIPE)
            dec = subprocess.Popen(["openssl", "enc", "-d", "-aes-256-cbc", "-pbkdf2", "-iter", "200000",
                                    "-pass", "env:ROM_VAULT_PASS"], stdin=cat.stdout, stdout=subprocess.PIPE,
                                   env=dict(os.environ, ROM_VAULT_PASS=pw))
            cat.stdout.close()
            # flatten: the archive stores absolute paths from the pushing machine
            tar = subprocess.run(["tar", "-xJf", "-", "-C", out, "--transform", "s,.*/,,"], stdin=dec.stdout)
            if dec.wait() or tar.returncode:
                sys.exit("decrypt/extract failed (wrong passphrase?)")
        finally:
            subprocess.run(["git", "-C", repo, "worktree", "remove", "--force", os.path.join(tmp, "wt")])
    for m in manifest["roms"]:
        p = os.path.join(out, m["file"])
        ok = os.path.exists(p) and sha1(p) == m["sha1"]
        print(f"  {m['file']}: {m['title']} [{m['game_code']}] {'OK' if ok else 'SHA-1 MISMATCH'}")


def main():
    ap = argparse.ArgumentParser(description=__doc__.split("\n\n")[0],
                                 formatter_class=argparse.RawDescriptionHelpFormatter, epilog=__doc__)
    sub = ap.add_subparsers(dest="cmd", required=True)
    p = sub.add_parser("push"); p.add_argument("roms", nargs="+"); p.add_argument("--repo", required=True)
    p.add_argument("--branch", default="roms")
    f = sub.add_parser("fetch"); f.add_argument("--repo", required=True); f.add_argument("--out", required=True)
    f.add_argument("--branch", default="roms")
    args = ap.parse_args()
    for tool in ("git", "openssl", "tar", "xz"):
        if not shutil.which(tool):
            sys.exit(f"{tool} is needed")
    (push if args.cmd == "push" else fetch)(args)


if __name__ == "__main__":
    main()
