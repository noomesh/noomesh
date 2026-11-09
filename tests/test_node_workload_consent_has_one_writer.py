# SPDX-License-Identifier: AGPL-3.0-only
# Copyright 2026 PersonifAI LLC

"""The node's consent store has ONE writer: the node owner (i573).

`<NOO_AGENT_STATE>/addon-workload-approvals.json` is what lets an add-on's
node workload run on a node. Unset NOO_ADDON_WORKLOADS is `approve`, which
is closed only while nothing approved exists: the store is the whole of
consent. The node agent is what the controller drives, so if the agent could
write the store, the controller could grant consent to itself.

So:
  1. outside tests and docs, the store's name appears in exactly two
     sources: the agent's READER (nodepolicy/consent.go) and the owner's
     WRITER (`sudo noo node workloads approve|revoke`, noo-cli
     node_workloads.rs);
  2. no other agent source names the reader's constant (ApprovalsFile);
  3. the reader writes nothing: no file-writing call in consent.go, and
     Approvals has only read, List and Has.

The owner's opt-in to controller approvals (i596),
`<NOO_AGENT_STATE>/controller-approvals-optin`, is held the same way. The
controller's approval set is signed by the fleet key, which also signs every
bundle, so an opt-in that the agent, a bundle, provision or noo-apply.sh could
write would be no opt-in. So:
  4. outside tests and docs, its name appears in exactly two sources: the
     agent's READER (nodepolicy/optin.go) and the owner's WRITER
     (`noo node workloads controller allow|deny`, which `noo enroll
     --controller-approvals` runs, in node_workloads.rs);
  5. no other agent source names the reader's constant (OptInFile);
  6. the reader writes nothing: no file-writing call in optin.go.
"""

from __future__ import annotations

import re
import subprocess
from pathlib import Path

REPO = Path(__file__).resolve().parents[1]
STORE = "addon-workload-approvals"
READER = "node-agent-go/internal/nodepolicy/consent.go"
WRITER = "noo-cli/src/commands/node_workloads.rs"

# Ways Go code changes a file or a directory entry.
WRITE_CALLS = re.compile(
    r"\bos\.(WriteFile|Create|CreateTemp|OpenFile|Rename|Remove|RemoveAll|Mkdir|MkdirAll|Chmod|Chown|Lchown|"
    r"Symlink|Link|Truncate)\b|\bioutil\.(WriteFile|TempFile)\b|\bsyscall\.|\bunix\.|\.Write(String)?\("
)
READER_METHODS = {"read", "List", "Has"}
OPTIN = "controller-approvals-optin"
OPTIN_READER = "node-agent-go/internal/nodepolicy/optin.go"


def _source_files() -> list[str]:
    out = subprocess.run(["git", "ls-files"], cwd=REPO, check=True, capture_output=True, text=True).stdout
    keep = []
    for f in out.splitlines():
        if not f.endswith((".go", ".rs", ".py", ".sh", ".ts", ".tsx", ".js")):
            continue
        if f.startswith(("tests/", "docs/")) or f.endswith("_test.go") or "/testdata/" in f or "/tests/" in f:
            continue
        keep.append(f)
    return keep


def _text(f: str) -> str:
    try:
        return (REPO / f).read_text(encoding="utf-8", errors="replace")
    except FileNotFoundError:
        return ""


def test_only_the_reader_and_the_owners_command_name_the_store() -> None:
    files = _source_files()
    assert len(files) > 500, f"the source listing found only {len(files)} files"
    naming = sorted(f for f in files if STORE in _text(f))
    assert naming == sorted([READER, WRITER]), (
        f"the consent store is named outside its reader and the owner's command: {naming}. "
        "Only `sudo noo node workloads approve|revoke` may write it; the agent only reads it."
    )


def test_no_other_agent_code_reaches_the_store_through_the_readers_constant() -> None:
    users = sorted(
        f
        for f in _source_files()
        if f.startswith("node-agent-go/") and f != READER and re.search(r"\bApprovalsFile\b", _text(f))
    )
    assert users == [], f"agent code reaches the consent store's name: {users}"


def test_the_agent_reads_the_store_and_never_writes_it() -> None:
    src = _text(READER)
    assert "func (a *Approvals) read()" in src, "the reader moved; point this guard at it"
    writes = sorted({m.group(0) for m in WRITE_CALLS.finditer(src)})
    assert writes == [], f"{READER} writes files ({writes}); the agent must only read the consent store"
    methods = set(re.findall(r"^func \(\w+ \*Approvals\) (\w+)\(", src, re.M))
    assert methods == READER_METHODS, f"Approvals has methods {sorted(methods)}; only {sorted(READER_METHODS)} (reads)"


def test_only_the_optin_reader_and_the_owners_command_name_the_optin() -> None:
    naming = sorted(f for f in _source_files() if OPTIN in _text(f))
    assert naming == sorted([OPTIN_READER, WRITER]), (
        f"the controller-approvals opt-in is named outside its reader and the owner's command: {naming}. "
        "Only local root (`noo node workloads controller allow|deny`, or `noo enroll --controller-approvals`) "
        "may write it; the agent, provision, bundles and noo-apply.sh never do."
    )


def test_no_other_agent_code_reaches_the_optin_through_the_readers_constant() -> None:
    users = sorted(
        f
        for f in _source_files()
        if f.startswith("node-agent-go/") and f != OPTIN_READER and re.search(r"\bOptInFile\b", _text(f))
    )
    assert users == [], f"agent code reaches the opt-in's name: {users}"


def test_the_agent_reads_the_optin_and_never_writes_it() -> None:
    src = _text(OPTIN_READER)
    assert "func optedIn(" in src and "os.Lstat(" in src, "the opt-in reader moved; point this guard at it"
    writes = sorted({m.group(0) for m in WRITE_CALLS.finditer(src)})
    assert writes == [], f"{OPTIN_READER} writes files ({writes}); the agent must only read the opt-in"
