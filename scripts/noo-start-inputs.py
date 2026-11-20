#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-only
# Copyright 2026 PersonifAI LLC
"""noo-start-inputs.py: which services' FILE inputs changed since the last start.

Compose recreates a container when its config hash changes. That hash covers
the resolved compose config (image, env values, mount PATHS, labels), but NOT
the CONTENTS of a bind-mounted file or of a `secrets: file:` source. So the
launcher used to run every full start with `--force-recreate` (13 containers
recreated on a start where nothing changed, dropping the node agent's NATS
link and tunnel), because a rotated secret or an edited config file would
otherwise never reach its container.

This helper makes compose's OWN hash see those contents. For every service it
computes ONE keyed value over the service's file inputs and the launcher puts
it on the service as the label `noo.inputs` (a small generated override,
lib-start-inputs.sh). Compose then recreates exactly the services whose
inputs changed and leaves the rest running. No state is needed for that,
except for a file a service reloads live (below).

Inputs of a service (classification, see classify_mount):
  * every `secrets:` source file (`file:` under NOO_SECRET_RUNDIR, and any
    other `file:`), and every `configs:` source file;
  * every bind mount whose source is a regular FILE;
  * a bind-mounted DIRECTORY only when it is read-only AND under the install
    root or the PKI dir, and not under a data root; capped at --cap bytes
    (default 16 MiB): an oversized one is skipped and said;
  * never: named volumes, read-write directories (data, spools, prompts),
    data roots (models, images, hf-cache, ollama, state), system paths.

Secrecy (the label is readable by anyone with docker read access, and both
the label and the state file can land in support bundles):
  * the label is HMAC-SHA256(key, sorted "path\\tvalue" lines), one per
    service; never a per-file digest and never an unkeyed one;
  * each per-file value is itself HMAC(key, path || content-sha256): the raw
    content digest of a short secret never leaves this process;
  * the key is 32 random bytes in a 0600 file (created on first use), read
    by THIS helper from its path; it is never on a command line, never
    printed. An unreadable key refuses (exit 3); there is no unkeyed mode.

The secret files themselves belong to the containers' uids (0400) after the
launcher writes them, so the operator usually cannot read them back: the
launcher calls `secret-digests` on its own temp copies BEFORE handing them
over, and `fingerprint` reads those keyed values (--secret-digests).

A file input that can be read neither way gets a fresh random value: that
service is recreated on every start (the old, safe behaviour) and it is said.

A service that RELOADS a file live (nats re-reads users.conf on SIGHUP) is not
recreated for it once the reload is recorded. `noo` writes the record when a
HUP is CONFIRMED (nats_users.rs hup_nats: the server logged "Reloaded server
configuration" and the file did not move meanwhile) into this state file:
  "reloaded": {SERVICE: {"container": ID, "paths": {REALPATH: VALUE|null}}}
VALUE = HMAC(key, "reloaded" || realpath || content-sha256); null = a HUP was
delivered but not confirmed. fingerprint (--containers: who is running now)
then labels that input with the value the running container was MADE on, as
long as the file still holds what the container has loaded (apply_reloads).
A record for another container id (a recreated nats) is not used, and a later
hand edit with no reload does not match it: both recreate, as before.

Subcommands (exit 0 ok, 2 usage/input error, 3 key refused):
  secret-digests --key-file K --dir D --out F NAME=TMPNAME...
  fingerprint    --key-file K --root R [--pki-dir P] [--data-dir X]...
                 [--secret-digests F] [--cap BYTES] [--old-state S] [--only SVC]...
                 [--containers SNAPSHOT]
                 --override-out O --state-out S2      < compose-config.json
  report         --before B --after A [--old-state S] --new-state S2 [--root R]
"""
from __future__ import annotations

import argparse
import hashlib
import hmac
import json
import os
import secrets as _secrets
import stat
import sys

KEY_BYTES = 32
DEFAULT_CAP = 16 * 1024 * 1024
LABEL = "noo.inputs"
STATE_VERSION = 1
SKIP_DIR_NAMES = {"__pycache__", ".git"}
SYSTEM_PREFIXES = ("/proc", "/sys", "/dev", "/run/docker", "/var/run/docker")


class KeyRefused(Exception):
    pass


def note(msg: str) -> None:
    print(f"  start-inputs: {msg}", file=sys.stderr)


# ── the key ────────────────────────────────────────────────────────────────

def load_key(path: str) -> bytes:
    """The per-install key: created (0600, parent 0700) when absent; refused
    when it cannot be read, is not a regular file, or is open to others and
    cannot be closed. Never an unkeyed fallback."""
    try:
        st = os.lstat(path)
    except FileNotFoundError:
        parent = os.path.dirname(os.path.abspath(path))
        try:
            os.makedirs(parent, mode=0o700, exist_ok=True)
            fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        except FileExistsError:
            return load_key(path)  # a concurrent creator won; read theirs
        except OSError as e:
            raise KeyRefused(f"cannot create the start-inputs key {path}: {e.strerror}")
        try:
            os.write(fd, _secrets.token_bytes(KEY_BYTES))
        finally:
            os.close(fd)
        st = os.lstat(path)
    if not stat.S_ISREG(st.st_mode):
        raise KeyRefused(f"the start-inputs key {path} is not a regular file")
    if st.st_mode & 0o077:
        if st.st_uid != os.getuid():
            raise KeyRefused(f"the start-inputs key {path} is readable by others and not ours to fix (chmod 600 it)")
        os.chmod(path, 0o600)
    try:
        with open(path, "rb") as f:
            key = f.read()
    except OSError as e:
        raise KeyRefused(f"cannot read the start-inputs key {path}: {e.strerror}")
    if len(key) < KEY_BYTES:
        raise KeyRefused(f"the start-inputs key {path} is shorter than {KEY_BYTES} bytes (remove it; the next start makes a new one)")
    return key


def keyed(key: bytes, msg: str) -> str:
    return hmac.new(key, msg.encode("utf-8", "surrogateescape"), hashlib.sha256).hexdigest()


def file_value(key: bytes, path: str, content_sha: str) -> str:
    """The per-file value: HMAC(key, path || content-sha256). Never the raw digest."""
    return keyed(key, f"file\0{path}\0{content_sha}")


def service_label(key: bytes, inputs: dict[str, str]) -> str:
    body = "\n".join(f"{p}\t{v}" for p, v in sorted(inputs.items()))
    return keyed(key, f"service\0{body}")


def reload_value(key: bytes, real: str, content_sha: str) -> str:
    """What `noo` records for a file a running container has re-read
    (nats_users.rs reload_value): keyed, never the raw digest."""
    return keyed(key, f"reloaded\0{real}\0{content_sha}")


def stale_value(key: bytes, value: str) -> str:
    """The label value for a file whose content equals what the container was
    made on while the container has since loaded something else (a reload,
    then a hand revert with no reload): differs from the made-on value, so the
    container is recreated, and stays stable for the container that results."""
    return keyed(key, f"reload-stale\0{value}")


# ── contents ───────────────────────────────────────────────────────────────

def sha256_file(path: str) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


class Oversize(Exception):
    pass


def sha256_dir(path: str, cap: int) -> str:
    """A digest over (relative path, content digest) of every regular file
    under `path`, in sorted order. Raises Oversize past `cap` bytes, OSError
    on an unreadable file."""
    entries: list[tuple[str, str]] = []
    total = 0
    for dirpath, dirnames, filenames in os.walk(path, followlinks=False):
        dirnames[:] = sorted(d for d in dirnames if d not in SKIP_DIR_NAMES)
        for name in sorted(filenames):
            full = os.path.join(dirpath, name)
            try:
                st = os.stat(full)
            except OSError:
                continue  # a dangling link: nothing the container can read either
            if not stat.S_ISREG(st.st_mode):
                continue
            total += st.st_size
            if total > cap:
                raise Oversize(total)
            entries.append((os.path.relpath(full, path), sha256_file(full)))
    h = hashlib.sha256()
    for rel, d in sorted(entries):
        h.update(f"{rel}\0{d}\n".encode("utf-8", "surrogateescape"))
    return h.hexdigest()


def _under(path: str, root: str) -> bool:
    if not root:
        return False
    root = os.path.normpath(root)
    path = os.path.normpath(path)
    return path == root or path.startswith(root.rstrip("/") + "/")


def classify_mount(vol: dict, root: str, pki_dir: str, data_dirs: list[str]) -> str:
    """'file', 'dir' or a reason it is not an input ('skip:<why>')."""
    if vol.get("type") != "bind":
        return "skip:not a bind mount"
    src = vol.get("source") or ""
    if not src.startswith("/"):
        return "skip:unresolved source"
    if src == "/" or any(_under(src, p) for p in SYSTEM_PREFIXES):
        return "skip:system path"
    if any(_under(src, d) for d in data_dirs if d):
        return "skip:data root"
    try:
        st = os.stat(src)
    except OSError:
        return "skip:missing"  # the bind-source check refuses a missing one first
    if stat.S_ISREG(st.st_mode):
        return "file"
    if not stat.S_ISDIR(st.st_mode):
        return "skip:not a file or directory"
    if not vol.get("read_only"):
        return "skip:read-write directory (data)"
    if _under(src, root) or _under(src, pki_dir):
        return "dir"
    return "skip:directory outside the install root and the PKI dir"


# ── subcommands ────────────────────────────────────────────────────────────

def write_private(path: str, text: str) -> None:
    tmp = f"{path}.{os.getpid()}.tmp"
    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "w") as f:
        f.write(text)
    os.chmod(tmp, 0o600)
    os.replace(tmp, path)


def cmd_secret_digests(a) -> int:
    key = load_key(a.key_file)
    d = os.path.abspath(a.dir)
    lines = []
    for pair in a.pairs:
        name, _, tmp = pair.partition("=")
        if not name or not tmp or "/" in name or "/" in tmp:
            print(f"bad NAME=TMPNAME pair: {pair!r}", file=sys.stderr)
            return 2
        final = os.path.join(d, name)
        try:
            v = file_value(key, final, sha256_file(os.path.join(d, tmp)))
        except OSError:
            continue  # absent from the cache: fingerprint says it and forces that service
        lines.append(f"{final}\t{v}\n")
    write_private(a.out, "".join(lines))
    return 0


def _read_secret_digests(path: str | None) -> dict[str, str]:
    out: dict[str, str] = {}
    if not path:
        return out
    try:
        with open(path) as f:
            for line in f:
                p, _, v = line.rstrip("\n").partition("\t")
                if p and v:
                    out[p] = v
    except OSError:
        pass
    return out


def _load_state(path: str | None) -> dict:
    if not path:
        return {}
    try:
        with open(path) as f:
            s = json.load(f)
        return s if isinstance(s, dict) and s.get("version") == STATE_VERSION else {}
    except (OSError, ValueError):
        return {}


def service_inputs(name: str, svc: dict, cfg: dict, key: bytes, a, cached: dict[str, str],
                   said: set) -> dict[str, str]:
    """path -> keyed value for every file input of one service."""
    inputs: dict[str, str] = {}

    def add_file(path: str, what: str) -> None:
        path = os.path.normpath(path)
        if path in cached:
            inputs[path] = cached[path]
            return
        try:
            inputs[path] = file_value(key, path, sha256_file(path))
        except OSError:
            # Neither readable nor in the launcher's cache: recreate this
            # service on every start, as before, and say so once per path.
            inputs[path] = "unreadable:" + _secrets.token_hex(16)
            if path not in said:
                said.add(path)
                note(f"cannot read {what} {path}; {name} is recreated on every start until it can be read")

    for ref in svc.get("secrets") or []:
        src = ref if isinstance(ref, str) else (ref or {}).get("source")
        f = ((cfg.get("secrets") or {}).get(src) or {}).get("file")
        if f:
            add_file(f, "secret")
    for ref in svc.get("configs") or []:
        src = ref if isinstance(ref, str) else (ref or {}).get("source")
        f = ((cfg.get("configs") or {}).get(src) or {}).get("file")
        if f:
            add_file(f, "config")
    for vol in svc.get("volumes") or []:
        if not isinstance(vol, dict):
            continue
        kind = classify_mount(vol, a.root, a.pki_dir or "", a.data_dir or [])
        src = os.path.normpath(vol.get("source") or "")
        if kind == "file":
            add_file(src, "config file")
        elif kind == "dir":
            try:
                inputs[src] = file_value(key, src, "dir:" + sha256_dir(src, a.cap))
            except Oversize:
                inputs[src] = "oversize"
                if src not in said:
                    said.add(src)
                    note(f"not fingerprinted: {src} is over {a.cap // (1024 * 1024)} MiB; "
                         f"a change there needs `noo stack start --recreate`")
            except OSError:
                inputs[src] = "unreadable:" + _secrets.token_hex(16)
                if src not in said:
                    said.add(src)
                    note(f"cannot read every file under {src}; {name} is recreated on every start until it can be read")
    return inputs


def key_id(key: bytes) -> str:
    """Which key made a state file: a keyed value, so it names no key."""
    return keyed(key, "key-id")[:16]


_STALE = object()  # the running container has loaded something this file does not hold


def apply_reloads(key: bytes, inputs: dict[str, str], old_svc: dict | None, record: dict | None,
                  running_id: str | None) -> tuple[dict[str, str], dict[str, str]]:
    """The values one service is LABELLED with, and what its container has
    loaded (kept in the state as "loaded"), given:
      inputs      this start's value of every file input (service_inputs);
      old_svc     the state's entry: "inputs" = what the running container was
                  labelled with (its label basis), "loaded" = what it has
                  re-read since, when that differs;
      record      the reload record `noo` wrote for this service, used only
                  when its container id is the one running now;
    For each input whose content the container has loaded (a recorded
    confirmed reload of exactly this content, or the state's "loaded"), the
    label keeps the basis: compose leaves the container alone. Otherwise the
    normal value, except that a file put back to the basis content after the
    container loaded something else gets stale_value (so it IS recreated)."""
    old_svc = old_svc if isinstance(old_svc, dict) else {}
    basis_all = old_svc.get("inputs") if isinstance(old_svc.get("inputs"), dict) else {}
    carried = old_svc.get("loaded") if isinstance(old_svc.get("loaded"), dict) else {}
    rec_paths: dict = {}
    if isinstance(record, dict) and running_id and record.get("container") == running_id:
        rec_paths = record.get("paths") if isinstance(record.get("paths"), dict) else {}
    out, loaded = dict(inputs), {}
    for p, cur in inputs.items():
        basis = basis_all.get(p)
        if not isinstance(basis, str) or cur.startswith("unreadable:") or cur == "oversize":
            continue
        real = os.path.realpath(p)
        have: object = carried.get(p)
        if real in rec_paths:
            rv = rec_paths[real]
            try:
                now = reload_value(key, real, sha256_file(p))
            except OSError:
                now = ""
            have = cur if isinstance(rv, str) and now and hmac.compare_digest(rv, now) else _STALE
        if have == cur:
            out[p], loaded[p] = basis, cur
        elif have is not None and basis == cur:
            out[p] = stale_value(key, cur)
        elif basis == stale_value(key, cur):
            out[p] = basis
    return out, loaded


def cmd_fingerprint(a) -> int:
    new_key = not os.path.lexists(a.key_file)
    key = load_key(a.key_file)
    if new_key:
        note(f"made a new start-inputs key ({a.key_file}): every service's label changes once, "
             "so this start recreates every container")
    try:
        cfg = json.load(sys.stdin)
    except ValueError as e:
        print(f"the compose config is not JSON: {e}", file=sys.stderr)
        return 2
    services = cfg.get("services") or {}
    cached = _read_secret_digests(a.secret_digests)
    a.root = os.path.abspath(a.root)
    a.data_dir = [os.path.normpath(d) for d in (a.data_dir or []) if d]
    said: set = set()
    old = _load_state(a.old_state)
    same_key = old.get("key_id") == key_id(key)
    old_services = (old.get("services") or {}) if same_key else {}
    reloaded = old.get("reloaded") if same_key and isinstance(old.get("reloaded"), dict) else {}
    running = {s: cid for s, (cid, _) in _read_snapshot(a.containers).items()} if a.containers else {}
    new: dict[str, dict] = {}
    for name in sorted(services):
        inputs = service_inputs(name, services[name] or {}, cfg, key, a, cached, said)
        inputs, loaded = apply_reloads(key, inputs, old_services.get(name), reloaded.get(name), running.get(name))
        new[name] = {"label": service_label(key, inputs), "inputs": inputs, "loaded": loaded}
    # The override compose merges over the stack: one label per service.
    lines = ["# Generated by scripts/noo-start-inputs.py at every start; do not edit.",
             "# noo.inputs is a keyed digest of each service's file inputs (secrets,",
             "# mounted config): compose recreates a service when it changes.",
             "services:"]
    for name in sorted(new):
        lines += [f"  {json.dumps(name)}:", "    labels:", f"      {LABEL}: {json.dumps(new[name]['label'])}"]
    write_private(a.override_out, "\n".join(lines) + "\n")
    # The state (the message, and the label basis apply_reloads keeps for a
    # reloaded file): this start's services replace theirs; a
    # targeted start keeps every other service's entry. --only (a recreate
    # outside a start, noomesh-restart.sh): only the services it recreates
    # are recorded, the others keep the inputs their containers were made on.
    def entry(rec: dict) -> dict:
        e = {"inputs": dict(rec["inputs"])}
        if rec["loaded"]:
            e["loaded"] = dict(rec["loaded"])
        return e

    merged = dict(old.get("services") or {})
    for name, rec in new.items():
        if a.only and name not in a.only:
            continue
        merged[name] = entry(rec)
    if old.get("key_id") not in (None, key_id(key)):
        # Values made with another key compare as "everything changed".
        merged = {name: entry(rec) for name, rec in new.items()}
    # Reload records stay until their container is replaced (a record for a
    # container that is no longer the service's is never used again).
    kept = {s: r for s, r in reloaded.items()
            if isinstance(r, dict) and (s not in running or r.get("container") == running[s])}
    out = {"version": STATE_VERSION, "key_id": key_id(key), "services": merged}
    if kept:
        out["reloaded"] = kept
    write_private(a.state_out, json.dumps(out, indent=1, sort_keys=True) + "\n")
    return 0


def _read_snapshot(path: str) -> dict[str, tuple[str, str]]:
    """service -> (container id, status) from 'service id status' lines."""
    out: dict[str, tuple[str, str]] = {}
    try:
        with open(path) as f:
            for line in f:
                parts = line.split()
                if len(parts) >= 2 and parts[0]:
                    out.setdefault(parts[0], (parts[1], parts[2] if len(parts) > 2 else ""))
    except OSError:
        pass
    return out


def describe(path: str, root: str, secret_dir: str) -> str:
    if secret_dir and _under(path, secret_dir):
        return f"secret {os.path.basename(path)}"
    if root and _under(path, root):
        return f"config {os.path.relpath(path, root)}"
    return f"config {path}"


def changed_paths(old: dict, new: dict) -> list[str]:
    o, n = old.get("inputs") or {}, new.get("inputs") or {}
    return sorted(p for p in set(o) | set(n)
                  if o.get(p) != n.get(p) or str(n.get(p, "")).startswith("unreadable:"))


def report_lines(before: dict, after: dict, old_state: dict, new_state: dict,
                 root: str = "", secret_dir: str = "", forced: bool = False) -> list[str]:
    running = sum(1 for _, (_, st) in after.items() if st == "running")
    recreated = sorted(s for s, (cid, _) in after.items() if s in before and before[s][0] != cid)
    created = sorted(s for s in after if s not in before)
    lines = [f"{running} running, {len(recreated)} recreated" + (f", {len(created)} created" if created else "")]
    olds = (old_state or {}).get("services") or {}
    if not olds:
        # Missing or unreadable: it only NAMES files, so nothing is recreated
        # on its account; the next start has one again.
        lines.append("cannot name what changed: no previous record")
    if not recreated:
        return lines
    if forced:
        lines.append("recreated: " + ", ".join(recreated) + " (forced: every container)")
        return lines
    news = (new_state or {}).get("services") or {}
    old_id, new_id = (old_state or {}).get("key_id"), (new_state or {}).get("key_id")
    if old_id and new_id and old_id != new_id:
        lines.append("recreated: " + ", ".join(recreated) + " (the start-inputs key is new, so every label changed once)")
        return lines
    if not olds:
        lines.append("recreated: " + ", ".join(recreated))
        return lines
    for s in recreated:
        if s in olds and s in news:
            paths = changed_paths(olds[s], news[s])
            if paths:
                what = ", ".join(describe(p, root, secret_dir) for p in paths)
                lines.append(f"recreated {s}: its inputs changed ({what})")
                continue
            lines.append(f"recreated {s}: its compose config or image changed")
        else:
            lines.append(f"recreated {s}")
    return lines


def cmd_report(a) -> int:
    for line in report_lines(_read_snapshot(a.before), _read_snapshot(a.after),
                             _load_state(a.old_state), _load_state(a.new_state),
                             os.path.abspath(a.root) if a.root else "", a.secret_dir or "", a.forced):
        print(line)
    return 0


def main(argv: list[str]) -> int:
    # allow_abbrev=False: no prefix of --key-file (say `--key`) may stand for it.
    p = argparse.ArgumentParser(prog="noo-start-inputs.py", allow_abbrev=False)
    sub = p.add_subparsers(dest="cmd", required=True)
    s = sub.add_parser("secret-digests", allow_abbrev=False)
    s.add_argument("--key-file", required=True)
    s.add_argument("--dir", required=True)
    s.add_argument("--out", required=True)
    s.add_argument("pairs", nargs="*")
    f = sub.add_parser("fingerprint", allow_abbrev=False)
    f.add_argument("--key-file", required=True)
    f.add_argument("--root", required=True)
    f.add_argument("--pki-dir", default="")
    f.add_argument("--data-dir", action="append", default=[])
    f.add_argument("--secret-digests", default="")
    f.add_argument("--cap", type=int, default=DEFAULT_CAP)
    f.add_argument("--old-state", default="")
    f.add_argument("--only", action="append", default=[])
    f.add_argument("--containers", default="")
    f.add_argument("--override-out", required=True)
    f.add_argument("--state-out", required=True)
    r = sub.add_parser("report", allow_abbrev=False)
    r.add_argument("--before", required=True)
    r.add_argument("--after", required=True)
    r.add_argument("--old-state", default="")
    r.add_argument("--new-state", default="")
    r.add_argument("--root", default="")
    r.add_argument("--secret-dir", default="")
    r.add_argument("--forced", action="store_true")
    a = p.parse_args(argv)
    try:
        if a.cmd == "secret-digests":
            return cmd_secret_digests(a)
        if a.cmd == "fingerprint":
            return cmd_fingerprint(a)
        return cmd_report(a)
    except KeyRefused as e:
        print(f"ERROR: {e}", file=sys.stderr)
        return 3


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
