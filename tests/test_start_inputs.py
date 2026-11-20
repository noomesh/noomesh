# SPDX-License-Identifier: AGPL-3.0-only
# Copyright 2026 PersonifAI LLC

"""A plain `noo stack start` recreates only what changed, decided from facts.

The launcher used to run every full start with `--force-recreate`: right after
`noo onboard` had started the stack, `noo stack start` recreated all 13
containers (every install-matrix cell, config-less containers included) and
dropped the node agent's NATS link and tunnel. The force was there because
compose's config hash does not cover the CONTENTS of a bind-mounted file or a
`secrets: file:` source, so a rotated secret or an edited config would never
reach its container.

Now every service carries `noo.inputs`, a keyed digest of exactly those
contents (scripts/noo-start-inputs.py, wired by scripts/lib-start-inputs.sh),
and compose's own hash does the rest. What this holds:

  * the fingerprint: same content, same label; changed content, a different
    label for exactly the services that read it; a data dir never counts; an
    oversized config dir is skipped and said; the order never matters;
  * secrecy: the label is ONE keyed value per service, never equal to (or
    containing) any input's sha256; two installs with different keys differ;
    the key is a 0600 file read by the helper itself, never an argument; an
    unreadable key refuses; the state file holds no raw digest;
  * the launcher: no literal --force-recreate on the full-start `up`; the
    force comes only from `--recreate` or a failed
    fingerprint; the secret digests are taken before the files are chowned;
  * the message: "N running, 0 recreated", or which files changed.
"""

from __future__ import annotations

import hashlib
import hmac
import importlib.util
import json
import os
import re
import stat
import subprocess
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
HELPER = ROOT / "scripts" / "noo-start-inputs.py"
LIB = ROOT / "scripts" / "lib-start-inputs.sh"
START = ROOT / "scripts" / "noomesh-start.sh"

_spec = importlib.util.spec_from_file_location("noo_start_inputs", HELPER)
SI = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(SI)


# ── a small install ────────────────────────────────────────────────────────

class Install:
    def __init__(self, tmp: Path, key_name: str = "key"):
        self.tmp = tmp
        self.root = tmp / "install"
        self.root.mkdir(exist_ok=True)
        self.key = tmp / ".config" / "noo" / key_name
        self.rundir = tmp / "run"
        self.rundir.mkdir(exist_ok=True)
        self.data = tmp / "data"
        (self.data / "models").mkdir(parents=True, exist_ok=True)
        (self.data / "models" / "weights.bin").write_bytes(b"w" * 64)
        (self.root / "monitoring").mkdir(exist_ok=True)
        (self.root / "monitoring" / "prometheus.yml").write_text("scrape: 15s\n")
        (self.root / "configs" / "dash").mkdir(parents=True, exist_ok=True)
        (self.root / "configs" / "dash" / "a.json").write_text("{}")
        (self.root / "prompts").mkdir(exist_ok=True)
        (self.root / "prompts" / "p.md").write_text("hello")
        (self.rundir / "noo_jwt_secret").write_text("short")
        (self.rundir / "postgres_password").write_text("pg-pass")

    def config(self, reverse: bool = False) -> dict:
        r, d = str(self.root), str(self.data)
        gw_vols = [
            {"type": "bind", "source": f"{r}/monitoring/prometheus.yml", "target": "/etc/p.yml", "read_only": True},
            {"type": "bind", "source": f"{r}/configs/dash", "target": "/dash", "read_only": True},
            {"type": "bind", "source": f"{r}/prompts", "target": "/app/prompts"},
            {"type": "bind", "source": f"{d}/models", "target": "/models", "read_only": True},
            {"type": "volume", "source": "pgdata", "target": "/var/lib/pg"},
            {"type": "bind", "source": "/", "target": "/rootfs", "read_only": True},
        ]
        gw_secrets = [{"source": "noo_jwt_secret", "target": "noo_jwt_secret"}]
        if reverse:
            gw_vols.reverse()
        return {
            "services": {
                "gateway": {"volumes": gw_vols, "secrets": gw_secrets},
                "postgres": {"secrets": [{"source": "postgres_password"}]},
                "redis": {},
            },
            "secrets": {
                "noo_jwt_secret": {"file": f"{self.rundir}/noo_jwt_secret"},
                "postgres_password": {"file": f"{self.rundir}/postgres_password"},
            },
        }

    def fingerprint(self, cfg: dict | None = None, cap: int | None = None, cache: Path | None = None,
                    old_state: Path | None = None, tag: str = "") -> tuple[subprocess.CompletedProcess, dict, dict]:
        ov, st = self.tmp / f"override{tag}.yml", self.tmp / f"state{tag}.json"
        args = ["python3", str(HELPER), "fingerprint", "--key-file", str(self.key), "--root", str(self.root),
                "--data-dir", str(self.data), "--override-out", str(ov), "--state-out", str(st)]
        if cap is not None:
            args += ["--cap", str(cap)]
        if cache is not None:
            args += ["--secret-digests", str(cache)]
        if old_state is not None:
            args += ["--old-state", str(old_state)]
        r = subprocess.run(args, input=json.dumps(cfg or self.config()), capture_output=True, text=True, timeout=60)
        labels = {}
        if r.returncode == 0:
            cur = None
            for line in ov.read_text().splitlines():
                m = re.match(r'^  "(.+)":$', line)
                if m:
                    cur = m.group(1)
                m = re.match(r'^      noo\.inputs: "([0-9a-z:]+)"$', line)
                if m:
                    labels[cur] = m.group(1)
        state = json.loads(st.read_text()) if r.returncode == 0 else {}
        return r, labels, state


def _sha(p: Path) -> str:
    return hashlib.sha256(p.read_bytes()).hexdigest()


# ── the fingerprint ────────────────────────────────────────────────────────

def test_same_content_same_labels_and_every_service_has_one(tmp_path: Path) -> None:
    i = Install(tmp_path)
    r1, a, _ = i.fingerprint()
    r2, b, _ = i.fingerprint()
    assert r1.returncode == 0 and r2.returncode == 0, r1.stderr + r2.stderr
    assert set(a) == {"gateway", "postgres", "redis"}, "a service with no file input still gets a (stable) label"
    assert a == b


def test_a_changed_secret_changes_only_its_services_label(tmp_path: Path) -> None:
    i = Install(tmp_path)
    _, a, _ = i.fingerprint()
    (i.rundir / "postgres_password").write_text("pg-pass-rotated")
    _, b, _ = i.fingerprint()
    assert a["postgres"] != b["postgres"]
    assert a["gateway"] == b["gateway"] and a["redis"] == b["redis"]


def test_a_changed_config_file_and_a_changed_ro_config_dir_change_the_label(tmp_path: Path) -> None:
    i = Install(tmp_path)
    _, a, _ = i.fingerprint()
    (i.root / "monitoring" / "prometheus.yml").write_text("scrape: 30s\n")
    _, b, _ = i.fingerprint()
    assert a["gateway"] != b["gateway"] and a["postgres"] == b["postgres"]
    (i.root / "configs" / "dash" / "b.json").write_text("{}")
    _, c, _ = i.fingerprint()
    assert b["gateway"] != c["gateway"], "a new file in a read-only config dir is a change"


def test_content_not_mtime(tmp_path: Path) -> None:
    i = Install(tmp_path)
    _, a, _ = i.fingerprint()
    p = i.root / "monitoring" / "prometheus.yml"
    os.utime(p, (1, 1))
    p.write_text(p.read_text())
    _, b, _ = i.fingerprint()
    assert a == b


def test_data_dirs_rw_dirs_volumes_and_system_paths_are_not_inputs(tmp_path: Path) -> None:
    i = Install(tmp_path)
    _, a, s = i.fingerprint()
    (i.data / "models" / "weights.bin").write_bytes(b"x" * 64)       # ro, under a data root
    (i.root / "prompts" / "p.md").write_text("edited")                 # rw dir
    _, b, _ = i.fingerprint()
    assert a == b
    paths = set(s["services"]["gateway"]["inputs"])
    assert not any(p.startswith(str(i.data)) for p in paths)
    assert str(i.root / "prompts") not in paths and "/" not in paths
    # A data root that sits UNDER the install root still never counts.
    inner = i.root / "data" / "models"
    inner.mkdir(parents=True)
    vol = {"type": "bind", "source": str(inner), "read_only": True}
    assert SI.classify_mount(vol, str(i.root), "", [str(i.root / "data")]) == "skip:data root"
    assert SI.classify_mount(vol, str(i.root), "", []) == "dir"
    assert SI.classify_mount({"type": "bind", "source": "/proc", "read_only": True}, str(i.root), "", []) == "skip:system path"
    assert SI.classify_mount({"type": "volume", "source": "pgdata"}, str(i.root), "", []) == "skip:not a bind mount"


def test_an_oversized_config_dir_is_skipped_and_said(tmp_path: Path) -> None:
    i = Install(tmp_path)
    (i.root / "configs" / "dash" / "big.bin").write_bytes(b"0" * 4096)
    r1, a, _ = i.fingerprint(cap=1024)
    assert r1.returncode == 0
    assert "not fingerprinted" in r1.stderr and str(i.root / "configs" / "dash") in r1.stderr and "--recreate" in r1.stderr
    (i.root / "configs" / "dash" / "big.bin").write_bytes(b"1" * 4096)
    _, b, _ = i.fingerprint(cap=1024)
    assert a == b, "a skipped dir does not move the label"


def test_order_is_stable(tmp_path: Path) -> None:
    i = Install(tmp_path)
    _, a, _ = i.fingerprint(i.config())
    _, b, _ = i.fingerprint(i.config(reverse=True))
    assert a == b


def test_an_unreadable_input_recreates_that_service_every_time_and_says_it(tmp_path: Path) -> None:
    i = Install(tmp_path)
    cfg = i.config()
    cfg["secrets"]["postgres_password"]["file"] = str(tmp_path / "nope" / "postgres_password")
    r1, a, _ = i.fingerprint(cfg)
    _, b, _ = i.fingerprint(cfg)
    assert a["postgres"] != b["postgres"] and a["gateway"] == b["gateway"]
    assert "postgres is recreated on every start" in r1.stderr


def test_the_launcher_cache_stands_in_for_a_secret_it_can_no_longer_read(tmp_path: Path) -> None:
    """After the chown the operator cannot read the secret files back: the
    keyed digests the launcher took from its own temp copies are used."""
    i = Install(tmp_path)
    d = i.rundir
    (d / ".1.postgres_password").write_text("pg-pass")
    cache = d / ".noo-inputs"
    r = subprocess.run(["python3", str(HELPER), "secret-digests", "--key-file", str(i.key), "--dir", str(d),
                        "--out", str(cache), "postgres_password=.1.postgres_password"], capture_output=True, text=True)
    assert r.returncode == 0, r.stderr
    assert stat.S_IMODE(cache.stat().st_mode) == 0o600
    _, direct, _ = i.fingerprint()
    cfg = i.config()
    (d / "postgres_password").unlink()  # stands for "not readable by us"
    _, via_cache, _ = i.fingerprint(cfg, cache=cache)
    assert via_cache["postgres"] == direct["postgres"]


# ── secrecy ────────────────────────────────────────────────────────────────

def test_the_label_is_never_a_plain_digest_of_an_input(tmp_path: Path) -> None:
    i = Install(tmp_path)
    _, labels, _ = i.fingerprint()
    digests = {_sha(i.rundir / "noo_jwt_secret"), _sha(i.rundir / "postgres_password"),
               _sha(i.root / "monitoring" / "prometheus.yml"), _sha(i.root / "configs" / "dash" / "a.json")}
    for svc, v in labels.items():
        assert v not in digests, svc
        assert not any(dg in v for dg in digests), svc
        assert re.fullmatch(r"[0-9a-f]{64}", v), v


def test_two_installs_with_different_keys_and_the_same_files_differ(tmp_path: Path) -> None:
    i = Install(tmp_path, key_name="key-a")
    _, a, _ = i.fingerprint()
    i.key = tmp_path / ".config" / "noo" / "key-b"
    _, b, _ = i.fingerprint()
    assert all(a[s] != b[s] for s in a)


def test_the_label_is_the_hmac_of_the_keyed_per_file_values(tmp_path: Path) -> None:
    i = Install(tmp_path)
    _, labels, state = i.fingerprint()
    key = i.key.read_bytes()
    pg = str(i.rundir / "postgres_password")
    v = hmac.new(key, f"file\0{pg}\0{_sha(i.rundir / 'postgres_password')}".encode(), hashlib.sha256).hexdigest()
    assert state["services"]["postgres"]["inputs"] == {pg: v}
    want = hmac.new(key, f"service\0{pg}\t{v}".encode(), hashlib.sha256).hexdigest()
    assert labels["postgres"] == want


def test_the_key_is_made_0600_in_a_0700_dir_and_reused(tmp_path: Path) -> None:
    i = Install(tmp_path)
    assert not i.key.exists()
    i.fingerprint()
    assert stat.S_IMODE(i.key.stat().st_mode) == 0o600
    assert stat.S_IMODE(i.key.parent.stat().st_mode) == 0o700
    assert len(i.key.read_bytes()) == 32
    k = i.key.read_bytes()
    i.fingerprint()
    assert i.key.read_bytes() == k


def test_a_key_open_to_others_is_closed(tmp_path: Path) -> None:
    i = Install(tmp_path)
    i.fingerprint()
    i.key.chmod(0o644)
    r, _, _ = i.fingerprint()
    assert r.returncode == 0 and stat.S_IMODE(i.key.stat().st_mode) == 0o600


def test_an_unreadable_key_refuses_and_never_falls_back(tmp_path: Path) -> None:
    i = Install(tmp_path)
    i.key.parent.mkdir(parents=True)
    i.key.mkdir()  # not a regular file: unreadable as a key
    r, _, _ = i.fingerprint()
    assert r.returncode == 3 and "start-inputs key" in r.stderr
    assert not (tmp_path / "override.yml").exists(), "no label is written without the key"
    i.key.rmdir()
    i.key.write_bytes(b"short")
    r, _, _ = i.fingerprint()
    assert r.returncode == 3


def test_the_key_is_never_on_a_command_line(tmp_path: Path) -> None:
    """The helper takes a key FILE (it reads the key itself); no `--key`
    option exists, and the shell lib passes only the path."""
    r = subprocess.run(["python3", str(HELPER), "fingerprint", "--key", "k", "--root", "/", "--override-out", "/dev/null",
                        "--state-out", "/dev/null"], input="{}", capture_output=True, text=True, cwd=tmp_path)
    assert r.returncode == 2 and "--key-file" in r.stderr, "an argument carrying the key itself must not exist"
    assert not (tmp_path / "k").exists(), "not even as an abbreviation of --key-file"
    lib = LIB.read_text()
    for m in re.finditer(r"--key-file\s+(\S+)", lib):
        assert m.group(1) == '"$(start_inputs_key_file)"', m.group(0)
    assert not re.search(r"(cat|<)\s*\"?\$\(start_inputs_key_file\)", lib), "the lib never reads the key"
    assert "start-inputs.key" not in START.read_text(), "the launcher names no key, it calls the lib"


def test_the_state_file_holds_no_raw_digest_and_is_0600(tmp_path: Path) -> None:
    i = Install(tmp_path)
    _, _, _ = i.fingerprint()
    text = (tmp_path / "state.json").read_text()
    assert stat.S_IMODE((tmp_path / "state.json").stat().st_mode) == 0o600
    assert stat.S_IMODE((tmp_path / "override.yml").stat().st_mode) == 0o600
    for p in [i.rundir / "noo_jwt_secret", i.rundir / "postgres_password", i.root / "monitoring" / "prometheus.yml",
              i.root / "configs" / "dash" / "a.json"]:
        assert _sha(p) not in text, p
    assert "short" not in text and "pg-pass" not in text


# ── the message ────────────────────────────────────────────────────────────

def _snap(p: Path, rows: dict[str, tuple[str, str]]) -> Path:
    p.write_text("".join(f"{s} {cid} {st}\n" for s, (cid, st) in rows.items()))
    return p


def test_the_report_says_nothing_moved(tmp_path: Path) -> None:
    rows = {"gateway": ("a1", "running"), "postgres": ("b1", "running"), "init": ("c1", "exited")}
    out = SI.report_lines(SI._read_snapshot(str(_snap(tmp_path / "b", rows))),
                          SI._read_snapshot(str(_snap(tmp_path / "a", rows))), {}, {})
    assert out == ["2 running, 0 recreated"]


def test_the_report_names_the_changed_files_not_their_hashes(tmp_path: Path) -> None:
    i = Install(tmp_path)
    _, _, s1 = i.fingerprint()
    (tmp_path / "state.json").rename(tmp_path / "old.json")
    (i.rundir / "noo_jwt_secret").write_text("rotated")
    (i.root / "monitoring" / "prometheus.yml").write_text("scrape: 1s\n")
    _, _, s2 = i.fingerprint()
    before = {"gateway": ("a1", "running"), "postgres": ("b1", "running")}
    after = {"gateway": ("a2", "running"), "postgres": ("b1", "running")}
    out = SI.report_lines(before, after, s1, s2, str(i.root), str(i.rundir))
    assert out[0] == "2 running, 1 recreated"
    assert out[1] == "recreated gateway: its inputs changed (config monitoring/prometheus.yml, secret noo_jwt_secret)"
    assert not re.search(r"[0-9a-f]{32}", "\n".join(out))
    # No earlier state: just the names.
    assert SI.report_lines(before, after, {}, s2)[1:] == ["recreated: gateway"]
    # A forced start says it was forced, not that inputs changed.
    assert SI.report_lines(before, after, s1, s2, forced=True)[1] == "recreated: gateway (forced: every container)"
    # A recreate with no input change is compose's own (config or image).
    assert SI.report_lines(before, after, s2, s2)[1] == "recreated gateway: its compose config or image changed"


def test_a_targeted_start_keeps_the_other_services_state(tmp_path: Path) -> None:
    i = Install(tmp_path)
    i.fingerprint()
    (tmp_path / "state.json").rename(tmp_path / "old.json")
    cfg = i.config()
    cfg["services"] = {"redis": {}}
    _, _, s = i.fingerprint(cfg, old_state=tmp_path / "old.json")
    assert set(s["services"]) == {"gateway", "postgres", "redis"}


# ── the launcher ───────────────────────────────────────────────────────────

def _full_start_up(src: str) -> str:
    lines = [ln for ln in src.splitlines() if re.match(r"^\s*noo_compose_up_isolating_stuck compose ", ln)]
    assert len(lines) == 1, lines
    return lines[0]


def test_the_full_start_up_forces_only_through_the_flag() -> None:
    src = START.read_text()
    lib = LIB.read_text()
    # start calls the lib's wrapper, the one CI drives against a real compose.
    assert re.search(r"^    start_inputs_full_up \$BUILD_FLAG \$GPU_SCALE \$AGENT_SCALE \$ADDON_HOLD_SCALE \|\| _up_rc=\$\?$", src, re.M)
    assert re.search(r'^    start_inputs_named_up "\$\{SERVICES\[@\]\}"$', src, re.M)
    assert "noo_compose_up_isolating_stuck compose" not in "\n".join(
        ln for ln in src.splitlines() if not ln.lstrip().startswith("#")), "start has no `up` of its own any more"
    up = _full_start_up(lib)
    assert "--force-recreate" not in up, "a plain full start must not force every container"
    assert " up -d $START_UP_FORCE " in up
    full = lib[lib.index("start_inputs_full_up() {"):]
    assert full.index("start_inputs_prepare || return 1") < full.index(up.strip())
    named = lib[lib.index("start_inputs_named_up() {"):]
    assert 'up -d $START_UP_FORCE "$@"' in named and named.index("start_inputs_prepare || return 1") < named.index("up -d")
    # The only place the force is spelled is the lib, and only for --recreate or a failed fingerprint.
    assert "--force-recreate" not in "\n".join(ln for ln in src.splitlines() if not ln.lstrip().startswith("#"))
    assert lib.count('START_UP_FORCE="--force-recreate"') == 4  # --recreate, no python3, no config, helper failed


def _parse(*args: str, env: dict[str, str] | None = None) -> str:
    """Run the launcher's own first argument loop in isolation."""
    src = START.read_text()
    a = src.index("START_RECREATE=false\n")
    b = src.index('set -- "${_argv[@]+"${_argv[@]}"}"', a)
    body = src[a:b] + 'set -- "${_argv[@]+"${_argv[@]}"}"\necho "recreate=$START_RECREATE rest=$*"\n'
    r = subprocess.run(["bash", "-c", body, "x", *args], capture_output=True, text=True,
                       env={"PATH": os.environ["PATH"], **(env or {})})
    assert r.returncode == 0, r.stderr
    return r.stdout.strip()


def test_recreate_is_parsed_with_the_other_launcher_flags() -> None:
    assert _parse() == "recreate=false rest="
    assert _parse("--dist", "--recreate", "gateway") == "recreate=true rest=gateway"
    # No environment switch: the flag on argv is the only way in.
    assert _parse(env={"NOO_START_RECREATE": "1"}) == "recreate=false rest="
    assert "NOO_START_RECREATE" not in START.read_text() and "NOO_START_RECREATE" not in LIB.read_text()


def _prepare(tmp_path: Path, recreate: bool, config_rc: int = 0) -> str:
    i = Install(tmp_path)
    bin_ = tmp_path / "bin"
    bin_.mkdir()
    (bin_ / "docker").write_text(f"#!/bin/sh\ncat {tmp_path}/cfg.json\nexit {config_rc}\n")
    (bin_ / "docker").chmod(0o755)
    (tmp_path / "cfg.json").write_text(json.dumps(i.config()))
    body = (
        f'ui_note() {{ echo "NOTE: $*"; }}; cd {i.root}; . {LIB}; COMPOSE_FILES="-f a.yml"; PROFILE_ARGS=""; '
        f'START_RECREATE={"true" if recreate else "false"}; start_inputs_prepare; echo "rc=$? force=[$START_UP_FORCE] files=[$COMPOSE_FILES]"'
    )
    r = subprocess.run(["bash", "-c", body], capture_output=True, text=True, timeout=60,
                       env={"PATH": f"{bin_}:{os.environ['PATH']}", "HOME": str(tmp_path)})
    return r.stdout + r.stderr


def test_prepare_labels_without_forcing_by_default(tmp_path: Path) -> None:
    out = _prepare(tmp_path, recreate=False)
    assert "rc=0 force=[] files=[-f a.yml -f ./.noo-start-inputs.yml]" in out, out
    assert (tmp_path / "install" / ".noo-start-inputs.yml").is_file()
    assert stat.S_IMODE((tmp_path / ".config" / "noo" / "start-inputs.key").stat().st_mode) == 0o600


def test_prepare_forces_under_recreate(tmp_path: Path) -> None:
    out = _prepare(tmp_path, recreate=True)
    assert "rc=0 force=[--force-recreate] files=[-f a.yml -f ./.noo-start-inputs.yml]" in out, out


def test_prepare_forces_when_the_config_cannot_render(tmp_path: Path) -> None:
    out = _prepare(tmp_path, recreate=False, config_rc=1)
    assert "rc=0 force=[--force-recreate] files=[-f a.yml]" in out, out


def test_the_secret_digests_are_taken_before_the_chown() -> None:
    sec = (ROOT / "scripts" / "lib-secrets.sh").read_text()
    body = sec[sec.index("write_secret_files() {"):]
    assert body.index("start_inputs_secret_digests") < body.index('if ! _secret_chown_files "$d" "$manifest"')
    start = START.read_text()
    assert start.index("lib-start-inputs.sh") < start.index("load_secrets ||")


def test_the_lib_and_helper_ship_with_a_standalone_install() -> None:
    build = (ROOT / "noo-cli" / "build.rs").read_text()
    assert '"scripts/lib-start-inputs.sh"' in build and '"scripts/noo-start-inputs.py"' in build
    ignore = (ROOT / ".gitignore").read_text().splitlines()
    assert ".noo-start-inputs.yml" in ignore and ".noo-start-inputs.json*" in ignore


def test_write_secret_files_leaves_keyed_digests_for_every_secret(tmp_path: Path) -> None:
    """The real writer (lib-secrets.sh, with the chown recorded instead of
    done): the cache beside the secret files has one KEYED value per secret
    file, and no raw content digest."""
    from tests.test_secret_rundir import SHM, Box, needs_shm  # noqa: F401
    if needs_shm.args and needs_shm.args[0]:
        pytest.skip("/dev/shm is not a tmpfs here")
    box = Box(tmp_path)
    try:
        r = box.run(f". {LIB} && load_secrets >/dev/null")
        assert r.returncode == 0, r.stderr
        cache = box.rundir / ".noo-inputs"
        assert stat.S_IMODE(cache.stat().st_mode) == 0o600
        rows = dict(line.split("\t") for line in cache.read_text().splitlines())
        names = {p.name for p in box.rundir.iterdir() if not p.name.startswith(".")}
        assert {Path(p).name for p in rows} == names
        key = (tmp_path / ".config" / "noo" / "start-inputs.key").read_bytes()
        jwt = str(box.rundir / "noo_jwt_secret")
        raw = hashlib.sha256((box.rundir / "noo_jwt_secret").read_bytes()).hexdigest()
        assert rows[jwt] == hmac.new(key, f"file\0{jwt}\0{raw}".encode(), hashlib.sha256).hexdigest()
        assert raw not in cache.read_text()
    finally:
        box.cleanup()


def test_a_new_key_recreates_everything_once_and_says_so(tmp_path: Path) -> None:
    i = Install(tmp_path)
    r1, a, s1 = i.fingerprint()
    assert "made a new start-inputs key" in r1.stderr
    (tmp_path / "state.json").rename(tmp_path / "old.json")
    r2, b, _ = i.fingerprint(old_state=tmp_path / "old.json")
    assert "made a new start-inputs key" not in r2.stderr and a == b
    i.key.unlink()
    r3, c, s3 = i.fingerprint(old_state=tmp_path / "old.json")
    assert "made a new start-inputs key" in r3.stderr
    assert all(a[s] != c[s] for s in a), "every label moves with the key"
    assert s1["key_id"] != s3["key_id"] and re.fullmatch(r"[0-9a-f]{16}", s3["key_id"])
    before = {s: (f"{s}1", "running") for s in a}
    after = {s: (f"{s}2", "running") for s in a}
    out = SI.report_lines(before, after, s1, s3)
    assert out[0] == "3 running, 3 recreated"
    assert out[1] == "recreated: gateway, postgres, redis (the start-inputs key is new, so every label changed once)"
