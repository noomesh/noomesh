# SPDX-License-Identifier: AGPL-3.0-only
# Copyright 2026 PersonifAI LLC

"""An add-on's signed bundle declares its database system (system.json) and
its managed workloads (workloads.json); the launcher hands them to the gateway
ONLY for add-ons switched on whose signed lock it verified this start
(noomesh-internal i163 E/B).

scripts/lib-dist.sh::addon_decls_materialise runs for real after
require_addon_pins, against a fake `noo` that prints the launch-pins protocol
(`verified`, `pin`, `decl` lines) and a fake `docker`, in a tmp install root
with synthetic bundles for made-up add-ons (`example_addon`, `other_addon`).
Then lib-secrets.sh::_declared_systems is checked to contribute exactly the
materialised systems, with derived password variables, and to let a
noomesh.yaml entry of the same name win.

Old code: there is no addon_decls_materialise and _declared_systems reads
noomesh.yaml only; every test below fails."""

from __future__ import annotations

import os
import shutil
import stat
import subprocess
from pathlib import Path

REPO = Path(__file__).resolve().parents[1]

EXAMPLE_REF = "ghcr.io/example/example-addon@sha256:" + "1" * 64
OTHER_REF = "ghcr.io/example/other-addon@sha256:" + "2" * 64

EXAMPLE_OVERLAY = """services:
  example-addon:
    image: ${NOO_ADDON_IMAGE_EXAMPLE_ADDON:-noo-addon-unpinned.invalid/example-addon:x}
"""
OTHER_OVERLAY = """services:
  other-addon:
    image: ${NOO_ADDON_IMAGE_OTHER_ADDON:-noo-addon-unpinned.invalid/other-addon:x}
"""
SYSTEM = '{"schema":"%s","role":"noo_%s","ddl_role":"noo_%s_ddl"}'
WORKLOADS = '{"workloads":[{"name":"worker","container":"noo-%s-worker","gpu":true,"need_mb":1024,"drain":{"route":"drain","timeout_secs":60}}]}'

FAKE_DOCKER = """#!/bin/sh
case "$1 $2" in
  "image inspect") for r in $FAKE_LOCAL; do [ "$r" = "$3" ] && exit 0; done; exit 1 ;;
esac
exit 0
"""

FAKE_NOO = """#!/bin/sh
[ "$1 $2" = "addons launch-pins" ] || exit 2
printf '%b' "$FAKE_PINS"
"""

BOTH_VERIFIED = (
    "verified example_addon 1.0.0 v0.6.0\\n"
    f"pin example_addon NOO_ADDON_IMAGE_EXAMPLE_ADDON {EXAMPLE_REF}\\n"
    "decl example_addon system.json\\n"
    "decl example_addon workloads.json\\n"
    "verified other_addon 2.0.0 v0.6.0\\n"
    f"pin other_addon NOO_ADDON_IMAGE_OTHER_ADDON {OTHER_REF}\\n"
)


def _root(tmp_path: Path) -> Path:
    root = tmp_path / "root"
    if not root.exists():
        (root / "scripts").mkdir(parents=True)
        for lib in ("lib-addons.sh", "lib-dist.sh"):
            shutil.copy(REPO / "scripts" / lib, root / "scripts" / lib)
        for name, overlay in (("example_addon", EXAMPLE_OVERLAY), ("other_addon", OTHER_OVERLAY)):
            d = root / "addons" / name
            d.mkdir(parents=True)
            (d / "docker-compose.yml").write_text(overlay)
            (d / "system.json").write_text(SYSTEM % (name, name, name))
            (d / "workloads.json").write_text(WORKLOADS % name.replace("_", "-"))
    return root


def _bin(tmp_path: Path, name: str, text: str) -> None:
    d = tmp_path / "bin"
    d.mkdir(exist_ok=True)
    f = d / name
    f.write_text(text)
    f.chmod(f.stat().st_mode | stat.S_IEXEC)


def _run(tmp_path: Path, body: str = "", **env: str) -> subprocess.CompletedProcess:
    _bin(tmp_path, "docker", FAKE_DOCKER)
    _bin(tmp_path, "noo", FAKE_NOO)
    root = _root(tmp_path)
    script = f"""
set -u
cd {tmp_path}
. {root}/scripts/lib-addons.sh
. {root}/scripts/lib-dist.sh
require_addon_pins || exit 9
addon_decls_materialise || exit 8
{body}
"""
    full_env = {
        "PATH": f"{tmp_path / 'bin'}:{os.environ['PATH']}",
        "HOME": str(tmp_path),
        "NOO_ADDON_MAP_OVERRIDE": "1",
        "NOO_ADDON_MAP": env.pop("MAP", "example_addon=1\nother_addon=1\nvoice=0\n"),
        "DIST_MODE": "1",
        "DIST_TAG": "v0.6.0",
        "NOO_IMAGE_TAG": "v0.6.0",
        "FAKE_LOCAL": f"{EXAMPLE_REF} {OTHER_REF}",
        "FAKE_PINS": BOTH_VERIFIED,
    }
    full_env.update(env)
    return subprocess.run(["bash", "-c", script], env=full_env, capture_output=True, text=True, timeout=60)


def _tree(root: Path) -> list[str]:
    out = []
    for top in (".noo-addon-systems", ".noo-addon-workloads"):
        base = root / top
        for p in sorted(base.rglob("*")):
            if p.is_file():
                out.append(str(p.relative_to(root)))
    return out


def test_only_files_a_verified_lock_lists_reach_the_gateway(tmp_path: Path) -> None:
    r = _run(tmp_path)
    assert r.returncode == 0, r.stderr
    root = tmp_path / "root"
    # other_addon is verified too, but launch-pins named no `decl` file for
    # it: its system.json is not in its signed lock, so it is never copied.
    assert _tree(root) == [
        ".noo-addon-systems/example_addon/system.json",
        ".noo-addon-workloads/example_addon/workloads.json",
    ]
    copied = root / ".noo-addon-systems" / "example_addon" / "system.json"
    assert copied.read_text() == (root / "addons" / "example_addon" / "system.json").read_text()
    assert stat.S_IMODE(copied.stat().st_mode) == 0o644, "the gateway (another uid) reads it"


def test_a_decl_line_for_an_addon_the_verdict_does_not_name_is_ignored(tmp_path: Path) -> None:
    pins = (
        "verified example_addon 1.0.0 v0.6.0\\n"
        f"pin example_addon NOO_ADDON_IMAGE_EXAMPLE_ADDON {EXAMPLE_REF}\\n"
        f"pin other_addon NOO_ADDON_IMAGE_OTHER_ADDON {OTHER_REF}\\n"
        "decl other_addon system.json\\n"
        "decl example_addon evil.sh\\n"
    )
    r = _run(tmp_path, FAKE_PINS=pins)
    assert r.returncode == 0, r.stderr
    assert _tree(tmp_path / "root") == [], "neither an unverified add-on nor an unknown file name is copied"


def test_a_switched_off_addon_stops_declaring_on_the_next_start(tmp_path: Path) -> None:
    assert _run(tmp_path).returncode == 0
    root = tmp_path / "root"
    assert (root / ".noo-addon-systems" / "example_addon").is_dir()
    inode = (root / ".noo-addon-systems").stat().st_ino
    r = _run(tmp_path, MAP="example_addon=0\nother_addon=1\n",
             FAKE_PINS="verified other_addon 2.0.0 v0.6.0\\n" f"pin other_addon NOO_ADDON_IMAGE_OTHER_ADDON {OTHER_REF}\\n")
    assert r.returncode == 0, r.stderr
    assert _tree(root) == []
    assert (root / ".noo-addon-systems").stat().st_ino == inode, "the mounted directory keeps its inode"


def test_an_older_noo_without_decl_lines_hands_over_nothing(tmp_path: Path) -> None:
    pins = (
        "verified example_addon 1.0.0 v0.6.0\\n"
        f"pin example_addon NOO_ADDON_IMAGE_EXAMPLE_ADDON {EXAMPLE_REF}\\n"
        "verified other_addon 2.0.0 v0.6.0\\n"
        f"pin other_addon NOO_ADDON_IMAGE_OTHER_ADDON {OTHER_REF}\\n"
    )
    r = _run(tmp_path, FAKE_PINS=pins)
    assert r.returncode == 0, r.stderr
    assert _tree(tmp_path / "root") == []
    assert (tmp_path / "root" / ".noo-addon-systems").is_dir(), "the bind sources exist even when empty"


def test_a_dev_start_copies_the_files_beside_each_composed_overlay(tmp_path: Path) -> None:
    r = _run(tmp_path, DIST_MODE="0", MAP="example_addon=1\nother_addon=0\n")
    assert r.returncode == 0, r.stderr
    assert _tree(tmp_path / "root") == [
        ".noo-addon-systems/example_addon/system.json",
        ".noo-addon-workloads/example_addon/workloads.json",
    ]


def test_a_changed_system_set_rewrites_the_systems_secrets_file(tmp_path: Path) -> None:
    # load_secrets ran before the verdict existed; the set changed here, so
    # the launcher derives and writes the secret files again.
    stubs = 'derive_file_secrets() { echo DERIVED >> "$HOME/calls"; }; write_secret_files() { echo WROTE >> "$HOME/calls"; }'
    script_env = {"BASH_ENV": str(tmp_path / "stubs.sh")}
    (tmp_path / "stubs.sh").write_text(stubs + "\n")
    r = _run(tmp_path, **script_env)
    assert r.returncode == 0, r.stderr
    assert (tmp_path / "calls").read_text().split() == ["DERIVED", "WROTE"]
    (tmp_path / "calls").unlink()
    r = _run(tmp_path, **script_env)
    assert r.returncode == 0, r.stderr
    assert not (tmp_path / "calls").exists(), "an unchanged set rewrites nothing"


# ── _declared_systems: the second source ─────────────────────────────────

LIB_SECRETS = REPO / "scripts" / "lib-secrets.sh"


def _declared(tmp_path: Path, rendered: str | None) -> subprocess.CompletedProcess:
    env = {"PATH": "/usr/bin:/bin", "HOME": str(tmp_path)}
    if rendered is not None:
        fake = tmp_path / "fake-noo"
        fake.write_text("#!/bin/sh\ncat <<'OUT'\n" + rendered + "OUT\n")
        fake.chmod(0o755)
        env["NOO_CLI_BIN"] = str(fake)
        (tmp_path / "noomesh.yaml").write_text("systems: {}\n")
    return subprocess.run(["bash", "-c", f"cd {tmp_path} && . {LIB_SECRETS} && _declared_systems"],
                          env=env, capture_output=True, text=True, timeout=30)


def _plant(tmp_path: Path, addon: str) -> None:
    d = tmp_path / ".noo-addon-systems" / addon
    d.mkdir(parents=True)
    id_ = addon.replace("-", "_")
    (d / "system.json").write_text(SYSTEM % (id_, id_, id_))


def test_a_materialised_bundle_system_is_declared_with_derived_variables(tmp_path: Path) -> None:
    _plant(tmp_path, "example-addon")
    (tmp_path / ".noo-addon-systems" / "not-a-system").mkdir()  # no system.json: nothing
    (tmp_path / ".noo-addon-systems" / "Bad$name").mkdir()
    (tmp_path / ".noo-addon-systems" / "Bad$name" / "system.json").write_text("{}")
    r = _declared(tmp_path, None)
    assert r.returncode == 0, r.stderr
    assert r.stdout == "example_addon - NOO_EXAMPLE_ADDON_DB_PASSWORD NOO_EXAMPLE_ADDON_DDL_PASSWORD on\n"


def test_noomesh_yaml_wins_a_name_both_sources_declare(tmp_path: Path) -> None:
    _plant(tmp_path, "example-addon")
    _plant(tmp_path, "other-addon")
    r = _declared(tmp_path, "example_addon - NOO_HAND_PW NOO_HAND_DDL\n")
    assert r.returncode == 0, r.stderr
    assert r.stdout.splitlines() == [
        "example_addon - NOO_HAND_PW NOO_HAND_DDL",
        "other_addon - NOO_OTHER_ADDON_DB_PASSWORD NOO_OTHER_ADDON_DDL_PASSWORD on",
    ]


def test_nothing_materialised_declares_nothing_extra(tmp_path: Path) -> None:
    r = _declared(tmp_path, None)
    assert r.returncode == 0 and r.stdout == "", r.stderr


# ── the gateway's mounts ──────────────────────────────────────────────────

def test_the_gateway_mounts_both_directories_read_only() -> None:
    compose = (REPO / "docker-compose.cluster.yml").read_text()
    assert "      - ./.noo-addon-systems:/opt/noo/addon-systems:ro\n" in compose
    assert "      - ./.noo-addon-workloads:/opt/noo/addon-workloads:ro\n" in compose
    gw = compose.split("\n  gateway:\n", 1)[1].split("\n  worker:\n", 1)[0]
    assert "/opt/noo/addon-systems:ro" in gw and "/opt/noo/addon-workloads:ro" in gw, "the gateway alone reads them"
    rust = (REPO / "gateway-rust" / "src" / "addon_decls.rs").read_text()
    assert 'pub const SYSTEMS_DIR: &str = "/opt/noo/addon-systems";' in rust
    assert 'pub const WORKLOADS_DIR: &str = "/opt/noo/addon-workloads";' in rust


def test_each_launcher_materialises_right_after_the_verdict() -> None:
    for name in ("noomesh-start.sh", "noomesh-restart.sh", "noomesh-rebuild.sh"):
        text = (REPO / "scripts" / name).read_text()
        pins = text.rindex("require_addon_pins || exit 1")
        decls = text.index("addon_decls_materialise || exit 1")
        assert pins < decls, f"{name}: materialise needs the verdict require_addon_pins computes"


def test_the_cli_and_gateway_rule_constants_agree() -> None:
    """noo-cli does not link the gateway crate: the two copies of the
    system.json rules are held equal here. (workloads.json has one gateway
    parser, addon_workloads; the CLI's check at enable is a stricter subset.)"""
    import re
    cli = (REPO / "noo-cli" / "src" / "addons" / "decls.rs").read_text()
    gw = (REPO / "gateway-rust" / "src" / "addon_decls.rs").read_text()

    def const(src: str, name: str) -> str:
        m = re.search(rf"pub const {name}: [^=]+= (.*?);\n", src, re.S)
        assert m, name
        return re.sub(r"\s+", "", m.group(1))

    for name in ("ALLOWED_EXTENSIONS", "RESERVED_IDS", "MAX_FILE_BYTES"):
        assert const(cli, name) == const(gw, name), name
