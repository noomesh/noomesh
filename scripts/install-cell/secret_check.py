#!/usr/bin/env python3
"""secret_check.py FILE...: exit 3 when any of this node's own credentials,
or its sha256, occurs in a FILE; 0 when none does; 2 when the credentials
cannot be read. A companion to the upload scan (`cell.py scan`, which finds
secret-SHAPED text): this one knows the actual values. They are read from the
node agent's and the harness's env files (a `KEY_FILE` pointer is followed),
compared in memory, and never printed: the output names only the file."""
import hashlib
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from harness_e2e import agent_secret, root_read  # noqa: E402

KEYS = ("NOO_NODE_AGENT_TOKEN", "NOO_CLUSTER_SECRET", "NATS_NODE_PASSWORD", "NATS_PASSWORD")
ENVS = ("/etc/noo-node-agent.env", "/etc/noo-harness.env")


def values() -> list[str] | None:
    found: list[str] = []
    readable = False
    for path in ENVS:
        b = root_read(path)
        if b is None:
            continue
        readable = True
        text = b.decode(errors="replace")
        found += [v for v in (agent_secret(text, k) for k in KEYS) if len(v) >= 8]
    return found if readable else None


def main(paths: list[str]) -> int:
    secrets = values()
    if secrets is None:
        print("secret-check: the node's env files are not readable here (sudo -n); not checked")
        return 2
    hashes = [hashlib.sha256(s.encode()).hexdigest() for s in secrets]
    bad = []
    for p in paths:
        blob = open(p, errors="replace").read()
        if any(s in blob for s in secrets) or any(h in blob for h in hashes):
            bad.append(os.path.basename(p))
    if bad:
        print("secret-check: a credential of this node occurs in " + ", ".join(bad) + "; withheld")
        return 3
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
