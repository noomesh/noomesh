# SPDX-License-Identifier: AGPL-3.0-only
# Copyright 2026 PersonifAI LLC

"""The launcher hands redis/grafana data to uid 65532 recursively, verified.

0.6.3 -> 0.6.4 (2026-10-16): redis moved to uid 65532 and the launcher's
re-own ran minutes before `up`, while the old root container was still
rewriting its files. ``appendonlydir/appendonly.aof.manifest`` came back
root-owned and the new redis crash-looped for three hours. The re-own now
runs right before `up`, stops the service first, chowns recursively and
re-probes; anything still not 65532 refuses the start.

Tests cannot chown to 65532, so the alpine runner is replaced through
``NOO_REOWN_CMD`` with a fake whose ``find``/``chown`` act on a ledger of
"root-owned" paths: the probe prints the ledger, chown -R empties it (or,
for the stuck case, does not).
"""

from __future__ import annotations

import os
import subprocess
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
LIB = ROOT / "scripts" / "lib-reown.sh"
START = ROOT / "scripts" / "noomesh-start.sh"

# The fake runner: `<runner> <host dir> <snippet>`. $D is the host dir; the
# fake `find` prints the ledger for that dir, the fake `chown` records its
# args and clears the ledger unless REOWN_STUCK is set.
FAKE_RUNNER = r"""#!/bin/bash
dir="$1"; snippet="$2"
ledger="$dir/.ledger"
bin="$(mktemp -d)"
cat > "$bin/find" <<FIND
#!/bin/bash
echo "find \$*" >> "$LOG"
[ -f "$ledger" ] && cat "$ledger"
exit 0
FIND
cat > "$bin/chown" <<CHOWN
#!/bin/bash
echo "chown \$*" >> "$LOG"
[ -n "\${REOWN_STUCK:-}" ] || : > "$ledger"
CHOWN
chmod +x "$bin/find" "$bin/chown"
D="$dir" PATH="$bin:$PATH" sh -c "$snippet"
"""


def _setup(tmp: Path) -> tuple[Path, Path, Path]:
    root = tmp / "data"
    runner = tmp / "runner.sh"
    runner.write_text(FAKE_RUNNER)
    runner.chmod(0o755)
    log = tmp / "log"
    log.write_text("")
    return root, runner, log


def _run(tmp: Path, runner: Path, log: Path, args: str, extra: dict[str, str] | None = None) -> subprocess.CompletedProcess:
    env = dict(os.environ, NOO_REOWN_CMD=str(runner), LOG=str(log))
    env.update(extra or {})
    script = (
        f'set -e; source "{LIB}"; '
        f'reown_stop_service() {{ echo "stop $1" >> "{log}"; }}; '
        f"reown_nonroot_dirs {args}"
    )
    return subprocess.run(["bash", "-c", script], env=env, capture_output=True, text=True, check=False, cwd=tmp)


def _seed(root: Path, svc: str, paths: list[str]) -> Path:
    d = root / svc
    (d / "appendonlydir").mkdir(parents=True, exist_ok=True)
    (d / ".ledger").write_text("".join(f"{d}/{p}\n" for p in paths))
    return d


def test_nested_root_owned_file_is_reowned_recursively_and_verified(tmp_path: Path) -> None:
    root, runner, log = _setup(tmp_path)
    d = _seed(root, "redis", ["appendonlydir/appendonly.aof.manifest", "dump.rdb"])
    r = _run(tmp_path, runner, log, f'"{root}" redis')
    assert r.returncode == 0, r.stderr
    assert f"re-owned 2 path(s) under {d} to 65532" in r.stdout, r.stdout
    calls = log.read_text().splitlines()
    chowns = [c for c in calls if c.startswith("chown")]
    assert chowns == [f"chown -R 65532:65532 {d}"], calls
    # stop BEFORE chown, and a verify probe AFTER it
    assert calls.index("stop redis") < calls.index(chowns[0]), calls
    finds = [i for i, c in enumerate(calls) if c.startswith("find")]
    assert len(finds) == 2 and finds[-1] > calls.index(chowns[0]), calls
    assert all("-user 65532" in calls[i] and "-group 65532" in calls[i] for i in finds), calls


def test_already_65532_is_a_silent_noop(tmp_path: Path) -> None:
    root, runner, log = _setup(tmp_path)
    _seed(root, "redis", [])
    _seed(root, "grafana", [])
    r = _run(tmp_path, runner, log, f'"{root}" redis grafana')
    assert r.returncode == 0 and r.stdout == "" and r.stderr == "", r
    calls = log.read_text().splitlines()
    assert not any(c.startswith(("chown", "stop")) for c in calls), calls
    assert sum(c.startswith("find") for c in calls) == 2, calls


def test_paths_left_after_chown_refuse_the_start_naming_them(tmp_path: Path) -> None:
    root, runner, log = _setup(tmp_path)
    d = _seed(root, "redis", ["appendonlydir/appendonly.aof.manifest"])
    r = _run(tmp_path, runner, log, f'"{root}" redis', {"REOWN_STUCK": "1"})
    assert r.returncode == 1, r
    assert f"{d}/appendonlydir/appendonly.aof.manifest" in r.stderr, r.stderr
    assert f"sudo chown -R 65532:65532 {d}" in r.stderr, r.stderr
    assert "re-owned" not in r.stdout


def test_grafana_too_and_a_missing_dir_is_skipped(tmp_path: Path) -> None:
    root, runner, log = _setup(tmp_path)
    d = _seed(root, "grafana", ["grafana.db"])
    r = _run(tmp_path, runner, log, f'"{root}" redis grafana')
    assert r.returncode == 0, r.stderr
    assert r.stdout.strip() == f"re-owned 1 path(s) under {d} to 65532", r.stdout
    assert "stop grafana" in log.read_text()


def test_the_launcher_reowns_right_before_both_ups() -> None:
    src = START.read_text()
    assert 'source "$SCRIPT_DIR/lib-reown.sh"' in src
    # the old top-of-script probe+chown is gone
    assert "-print -quit)\" ]; then chown" not in src
    full_check = src.index("check_bind_sources --no-deps $_bind_skip $ACTIVE_SVCS || exit 1")
    full_up = src.index("up -d --force-recreate $BUILD_FLAG")
    call = src.index("reown_nonroot_dirs", full_check)
    assert full_check < call < full_up
    sub_check = src.index('check_bind_sources "${SERVICES[@]}" || exit 1')
    sub_up = src.index('up -d "${SERVICES[@]}"')
    call2 = src.index("reown_nonroot_dirs", sub_check)
    assert sub_check < call2 < sub_up
    assert src.count("reown_nonroot_dirs \"$_data_root\"") == 2
    assert src.count("|| exit 1", call, full_up) >= 1


def test_the_lib_is_embedded_in_the_cli() -> None:
    assert '"scripts/lib-reown.sh"' in (ROOT / "noo-cli" / "build.rs").read_text()
