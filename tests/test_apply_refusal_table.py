# SPDX-License-Identifier: AGPL-3.0-only
# Copyright 2026 PersonifAI LLC

"""Every refusal code the node applier exits with has a row in the CLI's table.

`noo cluster provision` and `noo upgrade --nodes` turn a node's applier exit
code into a stable code, a plain reason and the next command through ONE
function, `apply_refusal` in noo-cli/src/commands/provision.rs. A code the
script gains without a row there would fall back to the generic
`apply_failed_unknown_rc` text. This guard reads the script's own `exit N`
set (and noo-fetch.sh's gzip refusal, 69) and the table's `N => Some(` arms,
and holds them equal. The Rust unit tests check the rows themselves.
"""

from __future__ import annotations

import re
import subprocess
from pathlib import Path

REPO = Path(__file__).resolve().parents[1]
APPLIER = (REPO / "scripts" / "noo-apply.sh").read_text()
FETCHER = (REPO / "scripts" / "noo-fetch.sh").read_text()
PROVISION = (REPO / "noo-cli" / "src" / "commands" / "provision.rs").read_text()


def _code_lines(src: str) -> list[str]:
    return [line for line in src.splitlines() if not line.lstrip().startswith("#")]


def script_refusal_codes() -> set[int]:
    """`exit N` outside comments; 0 is success and 1 is set -e's generic failure."""
    codes = {int(n) for line in _code_lines(APPLIER) for n in re.findall(r"\bexit (\d+)", line)}
    codes |= {int(n) for line in _code_lines(FETCHER) for n in re.findall(r"\breturn (69)\b", line)}
    return {c for c in codes if c > 1}


def table_codes() -> set[int]:
    start = PROVISION.index("pub(crate) fn apply_refusal(rc: i64) -> ApplyRefusal {")
    end = PROVISION.index("\n}\n", start)
    body = PROVISION[start:end]
    return {int(n) for n in re.findall(r"^\s*(\d+) => Some\(ApplyRefusal \{", body, re.M)}


def test_the_script_codes_were_read():
    codes = script_refusal_codes()
    assert {65, 75, 76, 77} <= codes, codes


def test_every_script_refusal_has_a_row():
    missing = script_refusal_codes() - table_codes()
    assert not missing, f"applier exit codes with no row in apply_refusal: {sorted(missing)}"


def test_no_row_for_a_code_the_scripts_never_exit_with():
    stale = table_codes() - script_refusal_codes()
    assert not stale, f"apply_refusal rows for codes no script exits with: {sorted(stale)}"


# ── refusal names (the applier's last line, `noo-apply: refusal=<name> (exit N)`) ──
#
# A code says which family a refusal is in; the NAME says which remedy it
# needs. The applier's `refusal_table` block is the one list of names and
# their codes; every refusal site assigns `NOO_REFUSAL=<name>` right before
# its `exit N` / `return N`, and the exit trap prints the line only when the
# name's code is the code the applier exits with.

# Propagations: a caller that exits with the code a checking function already
# returned, after that function named the refusal itself.
PROPAGATING_CALLS = (
    "bundle_tar_ok", "manifest_ok", "vendor_manifest_ok", "text_payload_ok",
    "vendor_check", "env_payload_ok", "unit_payload_ok",
)
# Helpers that print and return; their callers name the refusal.
HELPERS = ("_shape_refuse() {", "_vendor_refuse() {", "release_refuse() {")
NAME_RE = r"[a-z][a-z0-9_]{0,47}"


def sh_refusal_table(src: str = APPLIER) -> dict[str, int]:
    block = src[src.index("# BEGIN refusal_table"):src.index("# END refusal_table")]
    rows = re.findall(r"^\s*([a-z][a-z0-9_]*)\) echo (\d+) ;;$", block, re.M)
    table = {n: int(c) for n, c in rows}
    assert len(table) == len(rows), "a name is listed twice"
    return table


def _helper_lines(src: str) -> set[int]:
    """Line numbers (1-based) inside the bodies of HELPERS."""
    out: set[int] = set()
    lines = src.splitlines()
    for i, l in enumerate(lines):
        if l.startswith(HELPERS):
            j = i
            while lines[j] != "}":
                out.add(j + 1)
                j += 1
    return out


def test_the_refusal_table_was_read():
    t = sh_refusal_table()
    assert len(t) >= 40, t
    assert t["bundle_shape"] == 65 and t["node_ahead_of_controller"] == 75 and t["signature_invalid"] == 77
    assert t["payload_for_other_node"] == 76 and t["applier_too_old"] == 76
    for n in t:
        assert re.fullmatch(NAME_RE, n), n


def test_every_table_code_is_a_code_the_scripts_exit_with():
    assert set(sh_refusal_table().values()) <= script_refusal_codes()


def test_every_assignment_names_a_table_entry():
    table = sh_refusal_table()
    for src, what in ((APPLIER, "noo-apply.sh"),):
        names = re.findall(r"\bNOO_REFUSAL=([A-Za-z0-9_\"$]*)", "\n".join(_code_lines(src)))
        assert names, f"{what}: no NOO_REFUSAL assignment read"
        for n in names:
            assert n in table or n == '""', f"{what}: NOO_REFUSAL={n} is not in the refusal table"


def test_every_refusal_site_names_its_refusal_with_the_same_code():
    """Every `exit N` / `return N` (N >= 65) outside comments and the helpers is
    `NOO_REFUSAL=<name>; exit N` with the name's code N, or a propagation of a
    checking function that named it."""
    table = sh_refusal_table()
    helpers = _helper_lines(APPLIER)
    bad, sites = [], 0
    for no, line in enumerate(APPLIER.splitlines(), 1):
        if line.lstrip().startswith("#") or no in helpers:
            continue
        for m in re.finditer(r"\b(exit|return) (6[5-9]|7[0-9])\b", line):
            sites += 1
            code = int(m.group(2))
            named = re.search(rf"NOO_REFUSAL=({NAME_RE}); $", line[:m.start()])
            if named:
                if table.get(named.group(1)) != code:
                    bad.append(f"{no}: {named.group(1)} is {table.get(named.group(1))}, the site exits {code}")
                continue
            if re.search(rf"\b({'|'.join(PROPAGATING_CALLS)}) .*\|\| (\{{ .*)?$", line[:m.start()]):
                continue
            bad.append(f"{no}: {line.strip()}")
    assert sites > 100, sites
    assert not bad, "refusal sites without a name (or with another code's name):\n" + "\n".join(bad)


def test_every_release_refuse_call_names_a_75():
    table = sh_refusal_table()
    calls = 0
    for no, line in enumerate(_code_lines(APPLIER), 1):
        for m in re.finditer(r"\brelease_refuse ", line):
            calls += 1
            named = re.search(rf"NOO_REFUSAL=({NAME_RE}); $", line[:m.start()])
            assert named, f"release_refuse without a name: {line.strip()}"
            assert table[named.group(1)] == 75, line
    assert calls >= 17, calls


def _run_trap(tail: str) -> subprocess.CompletedProcess:
    """The real table and trap, lifted from the applier, then `tail`."""
    head = APPLIER[APPLIER.index("# BEGIN refusal_table"):APPLIER.index("trap noo_apply_on_exit EXIT")]
    script = f"set -eu\nlogger() {{ :; }}\n{head}trap noo_apply_on_exit EXIT\n{tail}\n"
    return subprocess.run(["bash", "-c", script], capture_output=True, text=True, timeout=30)


def test_the_trap_names_only_a_refusal_whose_code_is_the_exit_code():
    r = _run_trap("NOO_REFUSAL=bundle_shape; exit 65")
    assert (r.returncode, r.stderr) == (65, "noo-apply: refusal=bundle_shape (exit 65)\n")
    r = _run_trap("NOO_REFUSAL=bundle_shape; exit 77")
    assert (r.returncode, r.stderr) == (77, ""), "a name of another code says nothing"
    r = _run_trap("NOO_REFUSAL=no_such_refusal; exit 65")
    assert (r.returncode, r.stderr) == (65, "")
    r = _run_trap("NOO_REFUSAL=bundle_shape; exit 1")
    assert (r.returncode, r.stderr) == (1, ""), "1 is set -e's failure, never a refusal"
    r = _run_trap("NOO_REFUSAL=bundle_shape; exit 0")
    assert (r.returncode, r.stderr) == (0, "")
    r = _run_trap("exit 65")
    assert (r.returncode, r.stderr) == (65, ""), "no name, no line"


def _trap_body() -> str:
    start = APPLIER.index("noo_apply_on_exit() {")
    return APPLIER[start:APPLIER.index("\n}\n", start)]


def test_the_trap_prints_the_one_line_and_keeps_the_code():
    body = _trap_body()
    assert 'echo "noo-apply: refusal=$NOO_REFUSAL (exit $_oe)" >&2' in body
    assert '[ "$_oe" -gt 1 ]' in body and '[ "$(refusal_code "$NOO_REFUSAL")" = "$_oe" ]' in body
    assert 'return "$_oe"' in body
    # No literal exit (the code table guard above reads `exit N`, and an exit
    # in a trap replaces the code), no REFUSED (the rehearsal counts those
    # lines), no bare `(NN)` (cluster_verify cuts the release line at `(75)`).
    assert not re.search(r"\bexit [0-9]", body), body
    assert not re.search(r"(^|[;&|{]) *exit\b", body, re.M), body
    assert "REFUSED" not in body
    assert not re.search(r"\(\d+\)", body), body
    assert "trap noo_apply_on_exit EXIT" in APPLIER
    # Installed before the first refusal (no trusted CA, exit 78).
    assert APPLIER.index("trap noo_apply_on_exit EXIT") < APPLIER.index('[ -f "$CA" ] ||')
    # One EXIT trap: the old cleanup trap is folded into it.
    assert APPLIER.count(" EXIT\n") == 1 + APPLIER.count("trap - EXIT\n"), "a second EXIT trap replaces this one"


def test_the_trap_removes_nothing_before_mktemp():
    body = _trap_body()
    assert '[ -z "$WORK" ] || rm -rf "$WORK"' in body and '[ -z "$KEYS" ] || rm -rf "$KEYS"' in body
    head = APPLIER[:APPLIER.index("trap noo_apply_on_exit EXIT")]
    assert '\nWORK=""\n' in head and '\nKEYS=""\n' in head, "an inherited WORK would be removed as root"
