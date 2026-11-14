# SPDX-License-Identifier: AGPL-3.0-only
# Copyright 2026 PersonifAI LLC
"""The launcher's add-on declaration directories (.noo-addon-systems,
-workloads, -routes) after a start run as another user.

0.6.24-rc.5 rehearsal, A-afterboot.start: the dirs were made by a root start;
the install owner may write into them (ACL) but does not own them, and the
launcher's unconditional `chmod 0755` failed with "Operation not permitted",
refusing with "could not create the add-on declaration directories" for dirs
that existed with the right mode. A stack once started with sudo and then run
as the user is something strangers will do.

scripts/lib-dist.sh::_decl_dirs_ready runs for real; `stat`, `chmod` and
`touch` are fakes on PATH so the cases hold when the suite runs as root
(which may chmod and write anything). Old code: no _decl_dirs_ready, so
every test fails."""
from __future__ import annotations

import os
import stat
import subprocess
from pathlib import Path

REPO = Path(__file__).resolve().parents[1]

FAKES = {
    # stat -c '%U %a' <path>: owner and mode from FAKE_OWNER_<basename>/FAKE_MODE_<basename>.
    "stat": """#!/bin/sh
p=""; for a in "$@"; do p="$a"; done
b=$(basename "$p" | tr -c 'a-zA-Z0-9\\n' '_')
eval "o=\\${FAKE_OWNER_$b:-me}; m=\\${FAKE_MODE_$b:-755}"
echo "$o $m"
""",
    # chmod fails (EPERM) for any path whose basename is in FAKE_CHMOD_DENY.
    "chmod": """#!/bin/sh
for a in "$@"; do for d in $FAKE_CHMOD_DENY; do [ "$(basename "$a")" = "$d" ] && { echo "chmod: changing permissions of '$a': Operation not permitted" >&2; exit 1; }; done; done
echo "$@" >> "$FAKE_LOG"
exit 0
""",
    # touch fails for any dir in FAKE_TOUCH_DENY.
    "touch": """#!/bin/sh
for a in "$@"; do for d in $FAKE_TOUCH_DENY; do [ "$(basename "$(dirname "$a")")" = "$d" ] && exit 1; done; done
exec /usr/bin/touch "$@"
""",
}

DIRS = (".noo-addon-systems", ".noo-addon-workloads", ".noo-addon-routes")


def _run(tmp_path: Path, **env: str) -> subprocess.CompletedProcess:
    bindir = tmp_path / "bin"
    bindir.mkdir(exist_ok=True)
    for name, text in FAKES.items():
        f = bindir / name
        f.write_text(text)
        f.chmod(f.stat().st_mode | stat.S_IEXEC)
    root = tmp_path / "root"
    root.mkdir(exist_ok=True)
    dirs = " ".join(str(root / d) for d in DIRS)
    script = f". {REPO}/scripts/lib-dist.sh\n_decl_dirs_ready {dirs}; echo RC=$?\n"
    full = {"PATH": f"{bindir}:/usr/bin:/bin", "HOME": str(tmp_path), "FAKE_LOG": str(tmp_path / "chmod.log")}
    full.update(env)
    return subprocess.run(["bash", "-c", script], env=full, capture_output=True, text=True, timeout=60)


def _chmods(tmp_path: Path) -> list[str]:
    p = tmp_path / "chmod.log"
    return p.read_text().splitlines() if p.exists() else []


def test_dirs_already_right_are_not_chmodded_even_if_another_user_owns_them(tmp_path):
    root = tmp_path / "root"
    for d in DIRS:
        (root / d).mkdir(parents=True)
    env = {f"FAKE_OWNER_{d.replace('.', '_').replace('-', '_')}": "root" for d in DIRS}
    env["FAKE_CHMOD_DENY"] = " ".join(DIRS)  # chmod by a non-owner would fail
    r = _run(tmp_path, **env)
    assert "RC=0" in r.stdout, r.stderr
    assert _chmods(tmp_path) == [], "a dir already 0755 was chmodded"
    assert "REFUSING" not in r.stderr


def test_a_wrong_mode_is_fixed_when_this_user_may_fix_it(tmp_path):
    root = tmp_path / "root"
    for d in DIRS:
        (root / d).mkdir(parents=True)
    r = _run(tmp_path, FAKE_MODE__noo_addon_routes="700")
    assert "RC=0" in r.stdout, r.stderr
    assert any(".noo-addon-routes" in c for c in _chmods(tmp_path))


def test_a_wrong_mode_this_user_cannot_fix_refuses_with_the_truth(tmp_path):
    root = tmp_path / "root"
    for d in DIRS:
        (root / d).mkdir(parents=True)
    r = _run(tmp_path, FAKE_MODE__noo_addon_systems="700", FAKE_OWNER__noo_addon_systems="root",
             FAKE_CHMOD_DENY=".noo-addon-systems")
    assert "RC=1" in r.stdout
    assert "exists, owned by root with mode 700" in r.stderr, r.stderr
    assert "fix: sudo chown -R" in r.stderr and ".noo-addon-systems" in r.stderr
    assert "could not create" not in r.stderr


def test_an_unwritable_dir_refuses_naming_owner_user_and_the_one_command(tmp_path):
    root = tmp_path / "root"
    for d in DIRS:
        (root / d).mkdir(parents=True)
    r = _run(tmp_path, FAKE_OWNER__noo_addon_workloads="root", FAKE_TOUCH_DENY=".noo-addon-workloads")
    assert "RC=1" in r.stdout
    assert "exists, owned by root (mode 755), and is not writable as" in r.stderr, r.stderr
    assert "sudo noo stack start" in r.stderr
    assert r.stderr.count("fix: sudo chown -R") == 1, "one command, naming every dir to fix"
    assert "could not create" not in r.stderr


def test_missing_dirs_are_made(tmp_path):
    r = _run(tmp_path)
    assert "RC=0" in r.stdout, r.stderr
    for d in DIRS:
        assert (tmp_path / "root" / d).is_dir()


def test_the_launcher_uses_it_and_never_chmods_unconditionally(tmp_path):
    src = (REPO / "scripts" / "lib-dist.sh").read_text()
    body = src.split("addon_decls_materialise() {", 1)[1].split("\n}\n", 1)[0]
    assert '_decl_dirs_ready "$_sys" "$_wl" "$_rt" || return 1' in body
    assert 'chmod 0755 "$_sys" "$_wl" "$_rt"' not in body
    assert "could not create the add-on declaration directories" not in src
