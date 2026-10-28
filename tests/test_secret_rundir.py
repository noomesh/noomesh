# SPDX-License-Identifier: AGPL-3.0-only
# Copyright 2026 PersonifAI LLC

"""Secrets reach the containers as files on a tmpfs, written by the launcher.

The gateway, worker(s) and trellion run `read_only: true`, and compose refuses
an `environment:`-sourced secret on a read-only service, so every top-level
compose secret is `file: ${NOO_SECRET_RUNDIR}/<name>` and
`scripts/lib-secrets.sh::write_secret_files` (called by `load_secrets`, which
every launcher, noo-hostd and the wizard's compose wrapper run first) writes
them. What this holds:

  * one file per declared secret, mode 0400, handed to the uid its consumers
    run as (the `x-noo-uid:` on the service entries is the one declaration);
  * the directory is 0700, ours, and on tmpfs: anything else is REFUSED with
    the reason and the remedy, and nothing is written;
  * an unset secret is an EMPTY file (the bind source must exist);
  * a failure anywhere (chown, owner conflict, no source) aborts `load_secrets`
    and leaves no temp file behind: no launcher reaches `compose up`;
  * `noo stack stop` removes them; a renamed secret's old file is pruned;
  * an older compose (environment: sources only) writes nothing;
  * no secret value lands in any file outside the rundir.

The chown to another uid needs root or a container; here
`NOO_SECRET_CHOWN_CMD` records the manifest the launcher hands it (uid + file
name, no value) instead, and the real path is exercised by the live check in
the PR.
"""

from __future__ import annotations

import os
import re
import shutil
import stat
import subprocess
import uuid
from pathlib import Path

import pytest

from tests._compose_projection import ROOT, full_projection

LIB = ROOT / "scripts" / "lib-secrets.sh"
SHM = Path("/dev/shm")

needs_shm = pytest.mark.skipif(
    not SHM.is_dir() or subprocess.run(["stat", "-f", "-c", "%T", str(SHM)], capture_output=True, text=True).stdout.strip() != "tmpfs",
    reason="/dev/shm is not a tmpfs here",
)

SECRET_MARK = "s3cr3t-marker-"


def _fake_bin(tmp: Path, store: str) -> Path:
    b = tmp / "bin"
    b.mkdir(exist_ok=True)
    sops = b / "sops"
    sops.write_text(f"#!/bin/sh\ncat <<'EOF'\n{store}\nEOF\n")
    sops.chmod(sops.stat().st_mode | stat.S_IEXEC)
    chown = b / "fake-chown"
    # Records the manifest ("<uid> <name>") and succeeds; FAKE_CHOWN_FAIL=1 fails.
    chown.write_text(
        "#!/bin/sh\n"
        '[ "$FAKE_CHOWN_FAIL" = 1 ] && exit 1\n'
        'cat "$1/$2" >> "$FAKE_CHOWN_LOG"\n'
    )
    chown.chmod(chown.stat().st_mode | stat.S_IEXEC)
    return b


STORE = "\n".join(
    [
        f"NOO_JWT_SECRET={SECRET_MARK}jwt",
        f"POSTGRES_PASSWORD={SECRET_MARK}pg",
        f"NOO_APP_DB_PASSWORD={SECRET_MARK}app",
        f"NOO_BROWSER_KEY={SECRET_MARK}browser",
        f"NOO_NODE_AGENT_TOKEN={SECRET_MARK}na",
        f"NOO_CLUSTER_SECRET={SECRET_MARK}cluster",
        f"NATS_NODE_PASSWORD={SECRET_MARK}natsnode",
    ]
)


class Box:
    def __init__(self, tmp: Path, compose_files: tuple[str, ...] = ("docker-compose.cluster.yml", "docker-compose.trellion.yml")):
        self.tmp = tmp
        (tmp / "secrets").mkdir()
        (tmp / "secrets" / "env.sops").write_text("x")
        (tmp / ".env").write_text("NOO_SECRETS_BACKEND=sops\n")
        for f in compose_files:
            shutil.copy(ROOT / f, tmp / f)
        self.bin = _fake_bin(tmp, STORE)
        self.rundir = SHM / f"noo-test-{uuid.uuid4().hex[:12]}"
        self.log = tmp / "chown.log"

    def run(self, body: str, rundir: Path | None = None, extra: dict[str, str] | None = None) -> subprocess.CompletedProcess:
        env = {
            "PATH": f"{self.bin}:/usr/local/bin:/usr/bin:/bin",
            "HOME": str(self.tmp),
            "NOO_SECRET_RUNDIR": str(rundir or self.rundir),
            "NOO_SECRET_CHOWN_CMD": str(self.bin / "fake-chown"),
            "FAKE_CHOWN_LOG": str(self.log),
        }
        env.update(extra or {})
        return subprocess.run(["bash", "-c", f'cd {self.tmp} && . {LIB} && {body}'], env=env, capture_output=True, text=True, timeout=60)

    def cleanup(self) -> None:
        shutil.rmtree(self.rundir, ignore_errors=True)


@pytest.fixture
def box(tmp_path: Path):
    b = Box(tmp_path)
    yield b
    b.cleanup()


def _expected_owners() -> dict[str, str]:
    """Secret name -> owner uid, from the COMPOSED projection (not the awk the
    launcher uses): the single non-zero uid among the services that take it,
    else 0."""
    p = full_projection()
    uids: dict[str, set[str]] = {}
    for svc in p["services"].values():
        for s in svc.get("secrets") or []:
            if isinstance(s, dict):
                uids.setdefault(s["source"], set()).add(str(s["x-noo-uid"]))
    out = {}
    for name in p["secrets"]:
        nz = uids.get(name, set()) - {"0"}
        assert len(nz) <= 1, f"{name} is taken by different non-root uids {nz}: one file has one owner"
        out[name] = next(iter(nz)) if nz else "0"
    return out


@needs_shm
def test_every_declared_secret_is_a_0400_file_handed_to_its_consumers_uid(box: Box) -> None:
    r = box.run("load_secrets >/dev/null")
    assert r.returncode == 0, r.stderr
    want = _expected_owners()
    assert len(want) >= 40, want
    assert {p.name for p in box.rundir.iterdir()} == set(want), "one file per declared secret, no others, no temp files"
    for name in want:
        mode = stat.S_IMODE((box.rundir / name).stat().st_mode)
        assert mode == 0o400, f"{name}: {oct(mode)}"
    # The owner each file is handed to is what the services' own `x-noo-uid:` says.
    handed = {}
    for line in box.log.read_text().splitlines():
        uid, tmpname = line.split()
        handed[re.sub(r"^\.\d+\.", "", tmpname)] = uid
    assert handed == want
    # Spot-check the cases that need a rule: a postgres-only secret, a root-only
    # one, and one shared by root (browser, node-agent) and non-root consumers.
    assert handed["postgres_password"] == "70"
    assert handed["nats_node_password"] == "0"
    assert handed["noo_browser_key"] == handed["noo_node_agent_token"] == handed["noo_cluster_secret"] == "65532"


@needs_shm
def test_the_file_holds_the_value_the_store_decrypts_to(box: Box) -> None:
    r = box.run("load_secrets >/dev/null")
    assert r.returncode == 0, r.stderr
    assert (box.rundir / "noo_jwt_secret").read_text() == f"{SECRET_MARK}jwt"
    assert (box.rundir / "postgres_password").read_text() == f"{SECRET_MARK}pg"
    # the derived pgpass body, not a store key
    assert (box.rundir / "pgpass_worker").read_text() == f"postgres:5432:noomesh:noo_app:{SECRET_MARK}app"


@needs_shm
def test_an_unset_secret_is_an_empty_file_so_compose_can_bind_it(box: Box) -> None:
    r = box.run("load_secrets >/dev/null")
    assert r.returncode == 0, r.stderr
    f = box.rundir / "tavily_api_key"
    assert f.is_file() and f.stat().st_size == 0, "the store has no TAVILY_API_KEY: an empty file, not an absent one"


@needs_shm
def test_the_directory_is_0700_ours_and_exported_for_compose(box: Box) -> None:
    r = box.run('load_secrets >/dev/null && printf "%s" "$NOO_SECRET_RUNDIR"')
    assert r.returncode == 0, r.stderr
    assert r.stdout == str(box.rundir)
    st = box.rundir.stat()
    assert stat.S_IMODE(st.st_mode) == 0o700 and st.st_uid == os.getuid()


def test_a_rundir_on_disk_is_refused_and_nothing_is_written(tmp_path: Path) -> None:
    fs = subprocess.run(["stat", "-f", "-c", "%T", str(tmp_path)], capture_output=True, text=True).stdout.strip()
    if fs in ("tmpfs", "ramfs"):
        pytest.skip(f"{tmp_path} is itself RAM-backed here")
    b = Box(tmp_path)
    disk = tmp_path / "on-disk"
    r = b.run("load_secrets >/dev/null", rundir=disk)
    assert r.returncode == 1, (r.returncode, r.stderr)
    assert "not RAM" in r.stderr and "tmpfs" in r.stderr and "NOO_SECRET_RUNDIR" in r.stderr, r.stderr
    leaked = [p for p in disk.rglob("*") if p.is_file()] if disk.exists() else []
    assert not leaked, f"files written before the refusal: {leaked}"
    assert not b.log.exists(), "the chown step must not run for a refused directory"


@needs_shm
def test_a_rundir_owned_by_someone_else_is_refused(box: Box) -> None:
    # /dev/shm itself is root-owned: pointing the rundir AT it is "not ours".
    r = box.run("load_secrets >/dev/null", rundir=SHM)
    assert r.returncode == 1 and "owned by uid" in r.stderr, r.stderr


@needs_shm
def test_a_rundir_that_is_a_symlink_is_refused(box: Box) -> None:
    target = SHM / f"noo-test-target-{uuid.uuid4().hex[:8]}"
    target.mkdir()
    box.rundir.symlink_to(target)
    try:
        r = box.run("load_secrets >/dev/null")
        assert r.returncode == 1 and "symlink" in r.stderr, r.stderr
        assert not list(target.iterdir())
    finally:
        box.rundir.unlink()
        shutil.rmtree(target, ignore_errors=True)


@needs_shm
def test_a_failed_chown_aborts_the_load_and_leaves_nothing_behind(box: Box) -> None:
    r = box.run("load_secrets >/dev/null", extra={"FAKE_CHOWN_FAIL": "1"})
    assert r.returncode == 1, r.stderr
    assert "could not hand the secret files" in r.stderr and "docker pull" in r.stderr, r.stderr
    assert list(box.rundir.iterdir()) == [], "temp files and the manifest must be removed on failure"


@needs_shm
def test_stop_removes_the_files_and_the_directory_and_is_safe_twice(box: Box) -> None:
    assert box.run("load_secrets >/dev/null").returncode == 0
    assert any(box.rundir.iterdir())
    r = box.run("remove_secret_files && remove_secret_files")
    assert r.returncode == 0, r.stderr
    assert not box.rundir.exists()


@needs_shm
def test_a_secret_the_compose_no_longer_names_is_pruned(box: Box) -> None:
    assert box.run("load_secrets >/dev/null").returncode == 0
    stale = box.rundir / "renamed_away_secret"
    stale.write_text("old plaintext")
    assert box.run("load_secrets >/dev/null").returncode == 0
    assert not stale.exists()


@needs_shm
def test_an_older_compose_with_only_environment_sources_writes_nothing(tmp_path: Path) -> None:
    b = Box(tmp_path, compose_files=())
    old = (ROOT / "docker-compose.cluster.yml").read_text()
    old = re.sub(
        r"^  ([a-z0-9_]+):\n    file: [^\n]*\n    x-noo-source: ([A-Z0-9_]+)\n",
        r"  \1:\n    environment: \2\n",
        old,
        flags=re.M,
    )
    assert "NOO_SECRET_RUNDIR" not in old.split("\nsecrets:\n", 1)[1].split("\nconfigs:\n", 1)[0]
    (tmp_path / "docker-compose.cluster.yml").write_text(old)
    try:
        r = b.run("load_secrets >/dev/null")
        assert r.returncode == 0, r.stderr
        assert not b.rundir.exists(), "an environment:-form compose needs no rundir"
        # ... and still gets its sources exported, exactly as before
        r = b.run('load_secrets >/dev/null && printf "%s" "$NOO_JWT_SECRET"')
        assert r.stdout == f"{SECRET_MARK}jwt"
    finally:
        b.cleanup()


@needs_shm
def test_two_different_nonroot_owners_for_one_secret_is_refused(tmp_path: Path) -> None:
    b = Box(tmp_path, compose_files=())
    (tmp_path / "docker-compose.cluster.yml").write_text(
        "services:\n"
        "  a:\n    secrets:\n      - { source: x, target: x, x-noo-uid: \"65532\" }\n"
        "  b:\n    secrets:\n      - { source: x, target: x, x-noo-uid: \"70\" }\n"
        "secrets:\n  x:\n    file: ${NOO_SECRET_RUNDIR:-/nonexistent/u}/x\n    x-noo-source: X_SECRET\n"
    )
    try:
        r = b.run("load_secrets >/dev/null")
        assert r.returncode == 1 and "x (CONFLICT)" in r.stderr, r.stderr
        assert not b.rundir.exists()
    finally:
        b.cleanup()


@needs_shm
def test_a_file_secret_with_no_source_variable_is_refused(tmp_path: Path) -> None:
    b = Box(tmp_path, compose_files=())
    (tmp_path / "docker-compose.cluster.yml").write_text(
        "services: {}\nsecrets:\n  x:\n    file: ${NOO_SECRET_RUNDIR:-/nonexistent/u}/x\n"
    )
    try:
        r = b.run("load_secrets >/dev/null")
        assert r.returncode == 1 and "x (NOSOURCE)" in r.stderr, r.stderr
    finally:
        b.cleanup()


@needs_shm
def test_no_secret_value_lands_in_any_file_outside_the_rundir(box: Box) -> None:
    assert box.run("load_secrets >/dev/null").returncode == 0
    hits = []
    for p in box.tmp.rglob("*"):
        if p.is_file() and not p.is_symlink():
            try:
                if SECRET_MARK.encode() in p.read_bytes():
                    hits.append(str(p))
            except OSError:
                pass
    # the fake `sops` script itself carries the store; nothing the LAUNCHER wrote does
    assert hits == [str(box.bin / "sops")], hits


def test_root_consumers_of_a_shared_secret_keep_dac_override() -> None:
    """A secret read by root AND a non-root service is owned by the non-root
    uid and root reads it through CAP_DAC_OVERRIDE: such a root service must
    not drop it (cap_drop ALL would turn the file into EACCES)."""
    p = full_projection()["services"]
    by_secret: dict[str, dict[str, set[str]]] = {}
    for name, svc in p.items():
        for s in svc.get("secrets") or []:
            if isinstance(s, dict):
                by_secret.setdefault(s["source"], {}).setdefault(str(s["x-noo-uid"]), set()).add(name)
    checked = 0
    for secret, per_uid in by_secret.items():
        if "0" in per_uid and set(per_uid) - {"0"}:
            for svc in per_uid["0"]:
                drops = {str(c).upper() for c in p[svc].get("cap_drop") or []}
                adds = {str(c).upper() for c in p[svc].get("cap_add") or []}
                checked += 1
                assert not (drops & {"ALL", "DAC_OVERRIDE"}) or "DAC_OVERRIDE" in adds, (
                    f"{svc} (root) reads {secret} owned by a non-root uid but drops DAC_OVERRIDE"
                )
    assert checked >= 2, "expected the browser and node-agent to share secrets with the gateway/worker"


def test_the_only_secret_writes_in_the_library_go_into_the_rundir() -> None:
    redirect = re.compile(r'(?<![0-9&<])>>?\s*"?([^\s"|;&)<]+)')
    bad = []
    seen = 0
    for i, line in enumerate((LIB).read_text().splitlines(), 1):
        if line.lstrip().startswith(("#", "echo", "printf '    %s")):
            continue
        for tgt in redirect.findall(line.replace(">&2", "")):
            if tgt.startswith(("/dev/null", "&")) or tgt == "2":
                continue
            seen += 1
            if not tgt.startswith("$d/"):
                bad.append(f"{i}: {line.strip()}")
    assert seen >= 3, f"the pattern saw {seen} redirections: it is reading the wrong thing"
    assert not bad, f"lib-secrets.sh redirects somewhere other than the tmpfs rundir: {bad}"


def test_stop_removes_the_files_and_the_wizard_runs_the_loader_for_every_install() -> None:
    stop = (ROOT / "scripts/noomesh-stop.sh").read_text()
    assert "remove_secret_files" in stop and "lib-secrets.sh" in stop
    sh = (ROOT / "noo-cli/src/onboard/sh.rs").read_text()
    m = re.search(r"fn compose_command\(.*?\n}\n", sh, re.S)
    assert m, "compose_command not found"
    assert "sops_active" not in m.group(0), (
        "the wizard's compose wrapper must run the loader on every install: the secret FILES are written by load_secrets"
    )
    assert "load_secrets" in m.group(0)


def test_hostd_keeps_the_loaders_stderr() -> None:
    go = (ROOT / "node-agent-go/internal/hostd/exec.go").read_text()
    assert "load_secrets >/dev/null 2>&1" not in go, "the refusal reason (not tmpfs, chown failed) would be discarded"


def _boot_script() -> str:
    go = (ROOT / "node-agent-go/internal/hostd/boot.go").read_text()
    m = re.search(r"const bootRestoreScript = `(.*?)`\n", go, re.S)
    assert m, "bootRestoreScript not found"
    return m.group(1).replace("%s", f"'{LIB}'")


def _boot_run(box: Box, populated: bool) -> tuple[subprocess.CompletedProcess, list[str]]:
    """Run the hostd boot-restore script for real, with a fake docker that has
    two stopped containers: one binding a secret file, one not."""
    log = box.tmp / "docker.log"
    docker = box.bin / "docker"
    docker.write_text(
        "#!/bin/sh\n"
        'echo "$@" >> "$DOCKER_LOG"\n'
        'case "$1" in\n'
        "  ps) printf 'aaa\\nbbb\\n' ;;\n"
        '  inspect) case "$4" in aaa) echo "$NOO_SECRET_RUNDIR/noo_jwt_secret" ;; *) echo /srv/other ;; esac ;;\n'
        "esac\n"
    )
    docker.chmod(docker.stat().st_mode | stat.S_IEXEC)
    if populated:
        box.rundir.mkdir(mode=0o700)
        (box.rundir / "x").write_text("1")
    r = box.run(f"bash -c {__import__('shlex').quote(_boot_script())}", extra={"DOCKER_LOG": str(log)})
    return r, (log.read_text().splitlines() if log.exists() else [])


@needs_shm
def test_boot_restore_rewrites_the_files_then_starts_only_the_containers_that_bind_them(box: Box) -> None:
    r, calls = _boot_run(box, populated=False)
    assert r.returncode == 0, r.stderr
    assert (box.rundir / "noo_jwt_secret").is_file(), "files must exist before any container is started"
    starts = [c for c in calls if c.startswith("start")]
    assert starts == ["start aaa"], calls
    assert "started 1 container" in r.stdout


@needs_shm
def test_boot_restore_leaves_a_populated_directory_and_stopped_services_alone(box: Box) -> None:
    r, calls = _boot_run(box, populated=True)
    assert r.returncode == 0 and "nothing to do" in r.stdout, (r.stdout, r.stderr)
    assert calls == [], "a hostd restart (files present) must not start anything"


@needs_shm
def test_boot_restore_failure_to_write_starts_nothing(box: Box) -> None:
    box.log.write_text("")
    r = box.run(
        f"bash -c {__import__('shlex').quote(_boot_script())}",
        extra={"FAKE_CHOWN_FAIL": "1", "DOCKER_LOG": str(box.tmp / "d.log")},
    )
    assert r.returncode == 1 and "could not write the secret files" in r.stderr
    assert not (box.tmp / "d.log").exists()


@needs_shm
def test_an_addon_overlay_that_extends_a_read_only_service_with_environment_secrets_is_refused(tmp_path: Path) -> None:
    b = Box(tmp_path)
    (tmp_path / "docker-compose.trellion-intel.yml").write_text(
        "services:\n  trellion-intel:\n    extends:\n      file: docker-compose.trellion.yml\n      service: trellion\n"
        "secrets:\n  noo_svc_key_trellion_intel:\n    environment: NOO_SVC_KEY_TRELLION_INTEL\n"
    )
    try:
        r = b.run("load_secrets >/dev/null")
        assert r.returncode == 1, r.stderr
        assert "noo_svc_key_trellion_intel" in r.stderr and "noo addons upgrade" in r.stderr and "Nothing was started" in r.stderr
        assert not b.rundir.exists(), "refused before anything is written"
    finally:
        b.cleanup()


@needs_shm
def test_an_independent_addon_with_environment_secrets_is_not_refused(tmp_path: Path) -> None:
    """noo-evolve does not extend trellion and is not read-only: its overlay's
    environment: secrets still work and are still exported."""
    b = Box(tmp_path)
    (tmp_path / "docker-compose.evolve.yml").write_text(
        "services:\n  noo-evolve:\n    image: x\nsecrets:\n  evolve_key:\n    environment: NOO_EVOLVE_KEY\n"
    )
    try:
        r = b.run("load_secrets >/dev/null")
        assert r.returncode == 0, r.stderr
    finally:
        b.cleanup()


def test_the_intel_overlay_in_its_repo_uses_file_secrets() -> None:
    p = Path.home() / "personifAI/trellion-intel/.worktrees/ro-rootfs/bundle/docker-compose.yml"
    if not p.is_file():
        pytest.skip("the trellion-intel checkout is not beside this one")
    plan = subprocess.run(["bash", "-c", f". {LIB}; _secret_form_conflicts {p}"], capture_output=True, text=True).stdout
    assert plan == "", plan


def _plan(compose: Path) -> dict[str, str]:
    out = subprocess.run(
        ["bash", "-c", f". {LIB} >/dev/null 2>&1; _secret_file_plan {compose}"],
        capture_output=True, text=True, check=True,
    ).stdout
    rows = {line.split()[0]: line.split()[2] for line in out.splitlines() if line.strip()}
    assert rows, f"the plan read no secret from {compose}: {out!r}"
    return rows


def test_a_signed_addon_bundles_swarm_uid_still_owns_its_file(tmp_path: Path) -> None:
    # trellion-intel v0.1.4 (signed for 0.6.13-rc.2) still writes the
    # Swarm-era `uid:` on its gateway key; reading only x-noo-uid (#387) left
    # that file root-owned 0400 and intel crash-looped on every start.
    c = tmp_path / "docker-compose.addon.yml"
    c.write_text(
        "services:\n"
        "  addon:\n    secrets:\n"
        '      - { source: k, target: noo_gateway_key, uid: "65532", gid: "65532", mode: 0400 }\n'
        "  both:\n    secrets:\n"
        '      - { source: y, target: y, x-noo-uid: "70", uid: "65532" }\n'
        "secrets:\n"
        "  k:\n    file: ${NOO_SECRET_RUNDIR:-/nonexistent/u}/k\n    x-noo-source: K\n"
        "  y:\n    file: ${NOO_SECRET_RUNDIR:-/nonexistent/u}/y\n    x-noo-source: Y\n"
    )
    plan = _plan(c)
    assert plan["k"] == "65532", plan
    assert plan["y"] == "70", "x-noo-uid wins over a Swarm uid on the same entry"
