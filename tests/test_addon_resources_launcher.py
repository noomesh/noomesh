# SPDX-License-Identifier: AGPL-3.0-only
# Copyright 2026 PersonifAI LLC

"""An add-on's declared runtime inputs (resources.json, noomesh-internal i239
section 10) reach its services through the launcher, and nothing else does.

scripts/lib-dist.sh::addon_resources_materialise runs for real, after
require_addon_pins, against a fake `noo` that speaks both protocols
(`launch-pins`, `launch-resources`; the fake writes a generation the way
noo-cli/src/addons/resources.rs does, with a marker value in each file) and
the fixture add-on `rhaddon` (tests/fixtures/addons/rhaddon), in a tmp
install root. The chown helper is the secret-file seam
(NOO_SECRET_CHOWN_CMD), which records the manifest it is handed.

The Rust half (parse, refusals, values, modes, the URL, holds) is pinned by
the unit tests in noo-cli/src/addons/resources.rs over the same fixture.

Old code: there is no addon_resources_materialise, no launch-resources
protocol, no hold and no add-on-key resolution to the services an overlay
owns; every test below fails."""

from __future__ import annotations

import json
import os
import re
import shutil
import stat
import subprocess
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parents[1]
FIXTURE = REPO / "tests" / "fixtures" / "addons" / "rhaddon"
REF = "ghcr.io/example/rhaddon@sha256:" + "1" * 64
SECRET = "SECRET-MARKER-VALUE-4f1e"
GEN = "g-0123456789abcdef"

PINS = (
    "verified rhaddon 1.0.0 v0.6.0\\n"
    f"pin rhaddon NOO_ADDON_IMAGE_RHADDON {REF}\\n"
    "decl rhaddon system.json\\n"
)

# The CLI's lines for the fixture (paths under @GEN@, the generation dir).
RES_OK = (
    "hold rhaddon noo-rhaddon-gpu asks for a GPU\\n"
    "env rhaddon RHADDON_GATEWAY_URL https://gateway:8080\\n"
    "env rhaddon RHADDON_PUBLIC_ORIGINS https://ctl.example https://ctl.example:8080\\n"
    "env rhaddon RHADDON_DB_NETWORK noomesh_noo-db\\n"
    "env rhaddon RHADDON_GATEWAY_NETWORK noo-cluster\\n"
    "mount rhaddon RHADDON_COORD_DIR @GEN@/coord\\n"
    "mount rhaddon RHADDON_WORK_DIR @GEN@/work\\n"
    "own rhaddon 4242 @GEN@/coord\\n"
    "own rhaddon 4242 @GEN@/work\\n"
    "gen rhaddon @GEN@\\n"
    "stale rhaddon @BASE@/rhaddon/g-ffffffffffffffff\\n"
)

FAKE_DOCKER = """#!/bin/sh
case "$1 $2" in
  "image inspect") [ "$3" = "$FAKE_LOCAL" ] && exit 0; exit 1 ;;
esac
exit 0
"""

FAKE_NOO = """#!/bin/sh
case "$1 $2" in
  "addons launch-pins") printf '%b' "$FAKE_PINS" ;;
  "addons launch-resources")
    shift 2
    printf '%s\\n' "$*" > "$HOME/launch-resources.args"
    [ -n "${FAKE_RES_FAIL:-}" ] && { echo "unknown command: addons launch-resources" >&2; exit 2; }
    g="$NOO_ADDON_RUNDIR/rhaddon/""" + GEN + """"
    mkdir -p "$g/work" "$g/coord/db" && chmod 700 "$NOO_ADDON_RUNDIR/rhaddon" "$g" "$g/work" "$g/coord" "$g/coord/db"
    for f in work/peer-key coord/peer-key work/leaf.key coord/db/pgpass; do
      printf '%s' \"""" + SECRET + """\" > "$g/$f" && chmod 400 "$g/$f"
    done
    printf '%b' "$FAKE_RES" | sed "s#@GEN@#$g#g; s#@BASE@#$NOO_ADDON_RUNDIR#g" ;;
  *) exit 2 ;;
esac
"""

FAKE_CHOWN = """#!/bin/sh
# $1 = directory, $2 = manifest inside it: record, chown nothing.
cat "$1/$2" >> "$HOME/chown.manifest"
"""


def _root(tmp_path: Path) -> Path:
    root = tmp_path / "root"
    if not root.exists():
        (root / "scripts").mkdir(parents=True)
        for lib in ("lib-addons.sh", "lib-dist.sh", "lib-secrets.sh", "lib-restart.sh"):
            shutil.copy(REPO / "scripts" / lib, root / "scripts" / lib)
        d = root / "addons" / "rhaddon"
        d.mkdir(parents=True)
        for f in ("docker-compose.yml", "resources.json", "system.json"):
            shutil.copy(FIXTURE / f, d / f)
        # A core file, so the services an overlay OWNS can be told from core's.
        (root / "docker-compose.cluster.yml").write_text("services:\n  gateway:\n    image: x\n  postgres:\n    image: x\n")
    return root


def _bin(tmp_path: Path, name: str, text: str) -> Path:
    d = tmp_path / "bin"
    d.mkdir(exist_ok=True)
    f = d / name
    f.write_text(text)
    f.chmod(0o755)
    return f


def _run(tmp_path: Path, body: str = "", **env: str) -> subprocess.CompletedProcess:
    _bin(tmp_path, "docker", FAKE_DOCKER)
    _bin(tmp_path, "noo", FAKE_NOO)
    chown = _bin(tmp_path, "fake-chown", FAKE_CHOWN)
    root = _root(tmp_path)
    rundir = tmp_path / "rundir"
    rundir.mkdir(exist_ok=True)
    (rundir / "rhaddon" / "g-ffffffffffffffff" / "work").mkdir(parents=True, exist_ok=True)
    script = f"""
set -u
cd {tmp_path}
. {root}/scripts/lib-secrets.sh
. {root}/scripts/lib-addons.sh
. {root}/scripts/lib-dist.sh
require_addon_pins || exit 9
addon_resources_materialise || exit 7
addon_decls_materialise || exit 8
{body}
"""
    full_env = {
        "PATH": f"{tmp_path / 'bin'}:{os.environ['PATH']}",
        "HOME": str(tmp_path),
        "NOO_ADDON_MAP_OVERRIDE": "1",
        "NOO_ADDON_MAP": "rhaddon=1\nvoice=0\ntrellion=0\n",
        "DIST_MODE": "1",
        "DIST_TAG": "v0.6.0",
        "NOO_IMAGE_TAG": "v0.6.0",
        "FAKE_LOCAL": REF,
        "FAKE_PINS": PINS,
        "FAKE_RES": RES_OK,
        "NOO_ADDON_RUNDIR": str(rundir),
        "NOO_SECRET_CHOWN_CMD": str(chown),
    }
    full_env.update(env)
    return subprocess.run(["bash", "-c", script], env=full_env, capture_output=True, text=True, timeout=60)


def _vars(out: str) -> dict[str, str]:
    return dict(line.split("=", 1) for line in out.splitlines() if "=" in line)


def test_declared_inputs_are_handed_over_and_exported(tmp_path: Path) -> None:
    r = _run(tmp_path, body='env | grep -E "^(RHADDON_|NOO_ADDONS_)" | sort; echo "HOLD=$ADDON_HOLD_SCALE"')
    assert r.returncode == 0, r.stderr
    v = _vars(r.stdout)
    gen = tmp_path / "rundir" / "rhaddon" / GEN
    assert v["RHADDON_WORK_DIR"] == str(gen / "work")
    assert v["RHADDON_COORD_DIR"] == str(gen / "coord")
    assert v["RHADDON_GATEWAY_URL"] == "https://gateway:8080"
    assert v["RHADDON_PUBLIC_ORIGINS"] == "https://ctl.example https://ctl.example:8080", "a value with spaces survives"
    assert v["RHADDON_DB_NETWORK"] == "noomesh_noo-db"
    assert v["NOO_ADDONS_VERIFIED"] == "rhaddon=1.0.0@v0.6.0"
    # The CLI was asked for exactly this add-on, with the install's facts.
    args = (tmp_path / "launch-resources.args").read_text().split()
    assert args[args.index("--tag") + 1] == "v0.6.0"
    assert args[args.index("--project") + 1] == "noomesh"
    assert args[args.index("--network") + 1] == "noo-cluster"
    assert args[-1] == "rhaddon"
    # Every mount directory and file went to the declared uid, nothing else.
    manifest = (tmp_path / "chown.manifest").read_text().splitlines()
    assert manifest, "the helper was not asked to chown anything"
    assert all(line.startswith("4242 ") for line in manifest), manifest
    paths = {line.split(" ", 1)[1] for line in manifest}
    assert {"work", "work/peer-key", "work/leaf.key", "coord", "coord/db", "coord/db/pgpass"} <= paths
    assert (gen / ".complete").is_file(), "the generation is marked complete after the handover"
    assert not (tmp_path / "rundir" / "rhaddon" / "g-ffffffffffffffff").exists(), "an older generation is removed"
    # The 0400/0700 shape the CLI writes is left alone.
    assert stat.S_IMODE((gen / "work" / "leaf.key").stat().st_mode) == 0o400
    assert stat.S_IMODE((gen / "work").stat().st_mode) == 0o700
    # The add-on still declares its database to the gateway.
    assert (tmp_path / "root" / ".noo-addon-systems" / "rhaddon" / "system.json").is_file()


def test_no_value_reaches_any_output(tmp_path: Path) -> None:
    r = _run(tmp_path, body="env")
    assert r.returncode == 0, r.stderr
    assert SECRET not in r.stdout and SECRET not in r.stderr
    for line in (tmp_path / "chown.manifest").read_text().splitlines():
        assert SECRET not in line


def test_gpu_services_are_held_and_refused_by_name(tmp_path: Path) -> None:
    body = """
echo "HOLD=$ADDON_HOLD_SCALE"
echo "KEPT=$(addon_drop_held "$(printf 'gateway\\nnoo-rhaddon\\nnoo-rhaddon-gpu\\n')" | tr '\\n' ' ')"
addon_refuse_held noo-rhaddon && echo CPU-OK
addon_refuse_held noo-rhaddon-gpu || echo GPU-REFUSED
addon_refuse_held rhaddon-gpu || echo SHORT-REFUSED
"""
    r = _run(tmp_path, body=body)
    assert r.returncode == 0, r.stderr
    assert "HOLD=--scale noo-rhaddon-gpu=0" in r.stdout
    assert "KEPT=gateway noo-rhaddon " in r.stdout
    assert "CPU-OK" in r.stdout and "GPU-REFUSED" in r.stdout and "SHORT-REFUSED" in r.stdout
    assert "HELD: add-on rhaddon service noo-rhaddon-gpu is not started" in r.stderr


def test_an_input_that_cannot_be_produced_refuses_only_that_addon(tmp_path: Path) -> None:
    res = "refuse rhaddon resource peer-key (shared_secret): NOO_ADDON_SECRET_RHADDON__PEER_KEY is not in the encrypted store\\n"
    r = _run(tmp_path, FAKE_RES=res, body='env | grep -E "^(RHADDON_|NOO_ADDONS_)" | sort; addon_on rhaddon 0 || echo RHADDON-OFF')
    assert r.returncode == 0, r.stderr
    assert "REFUSED add-on rhaddon: resource peer-key (shared_secret)" in r.stderr
    v = _vars(r.stdout)
    assert v["NOO_ADDONS_VERIFIED"] == "none", "the gateway's registry no longer names it"
    assert v["NOO_ADDONS_REFUSED"] == "rhaddon"
    assert not any(k.startswith("RHADDON_") for k in v)
    assert "RHADDON-OFF" in r.stdout, "its overlay is no longer composed"
    assert not (tmp_path / "root" / ".noo-addon-systems" / "rhaddon").exists(), "a refused add-on declares nothing"


def test_a_variable_that_is_not_the_addons_own_refuses_it(tmp_path: Path) -> None:
    for var in ("NOO_JWT_SECRET", "POSTGRES_PASSWORD", "OTHER_URL"):
        r = _run(tmp_path, FAKE_RES=f"env rhaddon {var} x\\n", body=f'echo "SEEN=${{{var}:-unset}}"')
        assert r.returncode == 0, r.stderr
        assert f"named variable '{var}'" in r.stderr
        assert "SEEN=unset" in r.stdout


def test_an_optional_input_is_skipped_with_a_note(tmp_path: Path) -> None:
    res = RES_OK + "notice rhaddon resource addon-key (addon_key): NOO_SVC_KEY_RHADDON is not in the encrypted store (optional: skipped, nothing delivered)\\n"
    r = _run(tmp_path, FAKE_RES=res, body='echo "V=$NOO_ADDONS_VERIFIED"')
    assert r.returncode == 0, r.stderr
    assert "NOTE: add-on rhaddon: resource addon-key (addon_key)" in r.stderr
    assert "V=rhaddon=1.0.0@v0.6.0" in r.stdout
    assert "REFUSED" not in r.stderr


def test_a_cli_without_the_reader_refuses_an_addon_that_declares_inputs(tmp_path: Path) -> None:
    r = _run(tmp_path, FAKE_RES_FAIL="1", body='echo "R=${NOO_ADDONS_REFUSED:-}"')
    assert r.returncode == 0, r.stderr
    assert "REFUSED add-on rhaddon: its overlay's secrets and runtime inputs could not be checked" in r.stderr
    assert "R=rhaddon" in r.stdout
    assert "no add-on was checked and none was started" in r.stderr


def test_a_failed_check_refuses_an_addon_that_declares_no_inputs_too(tmp_path: Path) -> None:
    """launch-resources is where every add-on's overlay is checked against its
    own secrets (noo-cli addons/guards.rs). When it fails, an add-on with no
    resources.json was not checked either, so it does not start. Before
    0.6.13 only an add-on that declared inputs was refused here."""
    root = _root(tmp_path)
    (root / "addons" / "rhaddon" / "resources.json").unlink()
    assert not (root / "addons" / "rhaddon" / "resources.json").exists()
    r = _run(tmp_path, FAKE_RES_FAIL="1", body='echo "R=${NOO_ADDONS_REFUSED:-}"; echo "V=$NOO_ADDONS_VERIFIED"; addon_on rhaddon 0 || echo RHADDON-OFF')
    assert r.returncode == 0, r.stderr
    assert "REFUSED add-on rhaddon: its overlay's secrets and runtime inputs could not be checked" in r.stderr
    assert "R=rhaddon" in r.stdout and "V=none" in r.stdout, r.stdout
    assert "RHADDON-OFF" in r.stdout, "its overlay is no longer composed"


def test_a_dev_start_names_the_overlay_it_composes(tmp_path: Path) -> None:
    r = _run(tmp_path, DIST_MODE="0", DIST_TAG="", NOO_IMAGE_TAG="")
    assert r.returncode == 0, r.stderr
    args = (tmp_path / "launch-resources.args").read_text().split()
    assert "--tag" not in args
    assert args[-1] == f"rhaddon={tmp_path / 'root' / 'addons' / 'rhaddon' / 'docker-compose.yml'}"


def test_the_addon_key_restarts_the_services_its_overlay_owns(tmp_path: Path) -> None:
    body = f"""
COMPOSE_FILES="-f {tmp_path}/root/docker-compose.cluster.yml -f {tmp_path}/root/addons/rhaddon/docker-compose.yml"
ui_failed() {{ echo "$*" >&2; }}; ui_note() {{ :; }}
. {tmp_path}/root/scripts/lib-restart.sh
VALID="$(printf 'gateway\\npostgres\\nnoo-rhaddon\\nnoo-rhaddon-gpu\\n')"
restart_resolve_all "$VALID" $COMPOSE_FILES -- rhaddon
echo "RESOLVED=${{RESOLVED_SERVICES[*]}}"
echo "STARTS=$(addon_drop_held "$(printf '%s\\n' "${{RESOLVED_SERVICES[@]}}")" | tr '\\n' ' ')"
"""
    r = _run(tmp_path, body=body)
    assert r.returncode == 0, r.stderr
    assert "RESOLVED=noo-rhaddon noo-rhaddon-gpu" in r.stdout, "every service the overlay owns, no core service"
    assert "STARTS=noo-rhaddon " in r.stdout, "the held GPU service is left out"


def test_the_launchers_call_it_between_the_pins_and_the_declarations() -> None:
    for name in ("noomesh-start.sh", "noomesh-restart.sh", "noomesh-rebuild.sh"):
        text = (REPO / "scripts" / name).read_text()
        pins = text.index("require_addon_pins || exit 1")
        res = text.index("addon_resources_materialise || exit 1")
        decls = text.index("addon_decls_materialise || exit 1")
        assert pins < res < decls, name
        assert "$ADDON_HOLD_SCALE" in text, f"{name}: the blanket up must hold GPU add-on services"
        assert "addon_refuse_held" in text, f"{name}: a named held service must be refused"


@pytest.mark.skipif(shutil.which("docker") is None, reason="docker compose is not installed")
def test_the_fixture_overlay_composes_with_the_exported_inputs(tmp_path: Path) -> None:
    """`docker compose config` only renders; it changes nothing."""
    probe = subprocess.run(["docker", "compose", "version"], capture_output=True, text=True)
    if probe.returncode != 0:
        pytest.skip("docker compose is not available")
    env = {
        **os.environ,
        "NOO_ADDON_IMAGE_RHADDON": REF,
        "RHADDON_WORK_DIR": "/run/noo-test/work",
        "RHADDON_COORD_DIR": "/run/noo-test/coord",
        "RHADDON_GATEWAY_URL": "https://gateway:8080",
        "RHADDON_PUBLIC_ORIGINS": "https://ctl.example",
        "RHADDON_DB_NETWORK": "noomesh_noo-db",
        "RHADDON_GATEWAY_NETWORK": "noo-cluster",
    }
    r = subprocess.run(
        ["docker", "compose", "-p", "noo-fixture-config", "-f", str(FIXTURE / "docker-compose.yml"), "config", "--format", "json"],
        env=env, capture_output=True, text=True, timeout=60,
    )
    assert r.returncode == 0, r.stderr
    cfg = json.loads(r.stdout)
    svc = cfg["services"]["noo-rhaddon"]
    assert svc["image"] == REF
    binds = {(v["source"], v["target"], v.get("read_only", False)) for v in svc["volumes"]}
    assert ("/run/noo-test/work", "/run/rhaddon", True) in binds
    assert ("/run/noo-test/coord", "/run/rhaddon-coord", True) in binds
    assert cfg["networks"]["rhaddon-db"]["name"] == "noomesh_noo-db"


def test_the_schema_and_the_cli_agree_and_the_fixture_passes_it() -> None:
    schema = json.loads((REPO / "docs" / "reference" / "addon-resources.schema.json").read_text())
    src = (REPO / "noo-cli" / "src" / "addons" / "resources.rs").read_text()
    fmt = re.search(r'pub const FORMAT: &str = "([^"]+)";', src).group(1)
    assert schema["properties"]["format"]["const"] == fmt
    fixture = json.loads((FIXTURE / "resources.json").read_text())
    assert fixture["format"] == fmt
    kinds = set(schema["properties"]["resources"]["items"]["properties"]["kind"]["enum"])
    body = src[src.index("pub fn kind(&self)"):src.index("pub fn part(&self)")]
    rust_kinds = set(re.findall(r'=> "(\w+)",', body))
    assert kinds == rust_kinds == {"gateway", "tls_leaf", "addon_key", "shared_secret", "db", "network"}
    assert {r["kind"] for r in fixture["resources"]} == kinds, "the fixture declares every kind"
    try:
        import jsonschema
    except ImportError:
        return
    jsonschema.validate(fixture, schema, cls=jsonschema.Draft7Validator)
