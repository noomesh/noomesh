#!/usr/bin/env python3
"""secret_check.py FILE...: exit 3 when any credential of this node or of its
gateway, or its sha256, occurs in a FILE; 0 when none does; 2 when the
credentials cannot be read (not checked is never clean). A companion to the
upload scan (`cell.py scan`, which finds secret-SHAPED text): this one knows
the actual values.

Values are chosen by key NAME, the redactor's own `SECRET_NAME`
(…PASSWORD, …PASSPHRASE, …TOKEN, …SECRET, …KEY), from every `KEY=value` in
the node agent's and the harness's env files and in the gateway container's
environment, plus the password of any `scheme://user:pass@` URL value
(whatever its key). A `…_FILE` pointer is followed (a gateway path through the
container's mounts to the host file). A value shorter than 8 characters, or
an absolute path, is not a credential. They are compared in memory and never
printed: the output names only the file."""
import hashlib
import json
import os
import re
import subprocess
import sys
import urllib.parse

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from cell import SECRET_NAME  # noqa: E402
from harness_e2e import root_read  # noqa: E402

ENVS = ("/etc/noo-node-agent.env", "/etc/noo-harness.env")


def env_pairs(text: str) -> list[tuple[str, str]]:
    out = []
    for raw in text.splitlines():
        line = raw.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        if line.startswith("export "):
            line = line[len("export "):]
        k, v = line.split("=", 1)
        v = v.strip()
        if len(v) >= 2 and v[0] == v[-1] and v[0] in "\"'":
            v = v[1:-1]
        out.append((k.strip(), v))
    return out


def gateway_env() -> tuple[list[str], list[dict]] | None:
    """The gateway container's Env and Mounts, in memory; None if unreadable."""
    for docker in (["docker"], ["sudo", "-n", "docker"]):
        try:
            p = subprocess.run(docker + ["inspect", "-f", "{{json .Config.Env}}\t{{json .Mounts}}", "noo-gateway"],
                               capture_output=True, text=True, timeout=30)
        except (OSError, subprocess.SubprocessError):
            continue
        if p.returncode == 0 and "\t" in p.stdout:
            env, mounts = p.stdout.strip().split("\t", 1)
            try:
                return json.loads(env) or [], json.loads(mounts) or []
            except ValueError:
                return None
    return None


def host_path(path: str, mounts: list[dict]) -> str | None:
    """A container path's file on the host, through the bind mounts."""
    best = None
    for m in mounts:
        dst, src = m.get("Destination", ""), m.get("Source", "")
        if dst and src and (path == dst or path.startswith(dst.rstrip("/") + "/")):
            if best is None or len(dst) > len(best[0]):
                best = (dst, src)
    if best is None:
        return None
    return best[1] + path[len(best[0]):]


# A credential that reaches the gateway only inside a URL value, under a key
# whose name is not a secret's (`DATABASE_URL`, `PGVECTOR_URL`: the app and
# postgres passwords, secrets.rs): the URL's password, whatever the key.
URL_PASS = re.compile(r"^[a-z][a-z0-9+.-]*://[^/:@\s]+:([^@\s/]+)@")


def usable(v: str) -> bool:
    # Not an absolute path: every generated secret here is URL-safe base64 or
    # alphanumeric (token_urlsafe, mint_password, fernet_key), so none starts
    # with "/". A path-valued key (NOO_TLS_KEY=/app/pki/...) names a file, and
    # paths are logged constantly. A standard-base64 secret could start with
    # "/": if one is ever generated, this rule must change.
    return len(v) >= 8 and not v.startswith("/")


def pick(pairs: list[tuple[str, str]], resolve) -> list[str]:
    vals = []
    for k, v in pairs:
        if not v:
            continue
        m = URL_PASS.match(v)
        if m:
            for pw in {m.group(1), urllib.parse.unquote(m.group(1))}:
                if usable(pw):
                    vals.append(pw)
        if not SECRET_NAME.match(k):
            continue
        if k.endswith("_FILE"):
            p = resolve(v)
            b = root_read(p) if p else None
            v = b.decode(errors="replace").strip() if b else ""
        if usable(v):
            vals.append(v)
    return vals


def values() -> list[str] | None:
    vals: list[str] = []
    readable = False
    for path in ENVS:
        b = root_read(path)
        if b is None:
            continue
        readable = True
        vals += pick(env_pairs(b.decode(errors="replace")), lambda p: p)
    gw = gateway_env()
    if gw is None or not readable:
        return None
    env, mounts = gw
    vals += pick([tuple(e.split("=", 1)) for e in env if "=" in e], lambda p: host_path(p, mounts))
    return vals


def main(paths: list[str]) -> int:
    secrets = values()
    if secrets is None:
        print("secret-check: this node's or its gateway's credentials are not readable here; not checked")
        return 2
    hashes = [hashlib.sha256(s.encode()).hexdigest() for s in secrets]
    bad = []
    for p in paths:
        blob = open(p, errors="replace").read()
        if any(s in blob for s in secrets) or any(h in blob for h in hashes):
            bad.append(os.path.basename(p))
    if bad:
        print("secret-check: a credential of this node or its gateway occurs in " + ", ".join(bad) + "; withheld")
        return 3
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
