# SPDX-License-Identifier: AGPL-3.0-only
# Copyright 2026 PersonifAI LLC
"""`noo addons enable <name> --provision-only`: the database, none of the services.

The promise has two halves. The CLI half (the broker call, the receipt, the
refusals) is covered by the unit tests in noo-cli/src/commands/addon_provision.rs.
This file holds the half that lives in shell and in constants the Rust code
cannot see:

* the LAUNCHER's compose selection. An add-on is composed only when
  `addons.<name>` is on in the map `noo config launch-render addons` prints.
  A provisioned add-on keeps that switch off (or unstated), so a later
  `noo stack restart --force` composes nothing of it; and a plain
  `noo addons enable` (switch on) composes it. Tested on the real
  `addon_compose_overlay_args`, with the add-on's bundle overlay present, so a
  regression in the selection is what fails, not a missing file.
* the constants the receipt states (database, host, port, container, binary
  path, network) equal what the compose files, the launcher's pgpass bodies and
  the gateway image actually use.
"""
from __future__ import annotations

import os
import re
import shutil
import subprocess
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
RS = (ROOT / "noo-cli/src/commands/addon_provision.rs").read_text()


def _overlay_args(tmp_path: Path, addon_map: str, bundle: bool = True) -> str:
    """`addon_compose_overlay_args` for a controller whose bundle for
    `pai-voice` is materialised under addons/pai-voice/, with `addon_map` as
    the output of `noo config launch-render addons`."""
    (tmp_path / "scripts").mkdir()
    shutil.copy(ROOT / "scripts/lib-addons.sh", tmp_path / "scripts/lib-addons.sh")
    if bundle:
        (tmp_path / "addons/pai-voice").mkdir(parents=True)
        (tmp_path / "addons/pai-voice/docker-compose.yml").write_text("services: {}\n")
    r = subprocess.run(
        [
            "bash",
            "-c",
            "source scripts/lib-addons.sh && addon_compose_overlay_args",
        ],
        cwd=tmp_path,
        env={
            "PATH": os.environ["PATH"],
            "NOO_ADDON_MAP_OVERRIDE": "1",
            "NOO_ADDON_MAP": addon_map,
        },
        capture_output=True,
        text=True,
        check=False,
    )
    assert r.returncode == 0, r.stderr
    return r.stdout


def test_a_provisioned_addon_is_not_composed_when_the_map_is_silent(tmp_path: Path) -> None:
    # provision-only never writes the switch: the map has no line for it
    out = _overlay_args(tmp_path, "trellion=1\n")
    assert "pai-voice" not in out, out


def test_a_provisioned_addon_is_not_composed_when_the_switch_is_off(tmp_path: Path) -> None:
    out = _overlay_args(tmp_path, "trellion=1\npai-voice=0\n")
    assert "pai-voice" not in out, out


def test_a_plain_enable_turns_it_fully_on(tmp_path: Path) -> None:
    out = _overlay_args(tmp_path, "trellion=1\npai-voice=1\n")
    assert f"-f {tmp_path}/addons/pai-voice/docker-compose.yml" in out, out


def test_the_launcher_composes_nothing_it_was_not_told_to() -> None:
    # The selection is keyed on the map only. Nothing in lib-addons.sh reads
    # the provisioned marker, so the state cannot leak into composition.
    src = (ROOT / "scripts/lib-addons.sh").read_text()
    assert "addon-provisioned" not in src and "provisioned.json" not in src


def test_the_command_never_declares_the_addon_on() -> None:
    body = RS[: RS.index("#[cfg(test)]")]
    for forbidden in ("write_addon_at(", "write_addon(", "set_addon("):
        assert forbidden not in body, forbidden


def test_the_receipt_names_the_database_the_stack_uses() -> None:
    consts = {k: v for k, v in re.findall(r'pub\(crate\) const (DB_\w+): [^=]+ = "?([^";]+)"?;', RS)}
    assert consts["DB_NAME"] == "noomesh" and consts["DB_HOST"] == "postgres" and consts["DB_PORT"] == "5432", consts
    secrets_sh = (ROOT / "scripts/lib-secrets.sh").read_text()
    assert f'body="${{body}}{consts["DB_HOST"]}:{consts["DB_PORT"]}:{consts["DB_NAME"]}:' in secrets_sh
    compose = (ROOT / "docker-compose.cluster.yml").read_text()
    assert f"@{consts['DB_HOST']}:{consts['DB_PORT']}/{consts['DB_NAME']}" in compose


def test_the_broker_binary_and_containers_are_the_images() -> None:
    gw_bin = re.search(r'GATEWAY_BIN: &str = "([^"]+)"', RS).group(1)
    dockerfile = (ROOT / "docker/Dockerfile.gateway-rust").read_text()
    assert f'ENTRYPOINT ["{gw_bin}"]' in dockerfile, "the broker is exec'd at the image's own entrypoint"
    compose = (ROOT / "docker-compose.cluster.yml").read_text()
    assert "container_name: ${NOO_CONTAINER_PREFIX:-noo}-postgres" in compose
    assert "container_name: ${NOO_CONTAINER_PREFIX:-noo}-gateway" in compose
    assert 'crate::envfile::container("gateway")' in RS and 'crate::envfile::container("postgres")' in RS
    # the gateway answers the subcommand the CLI sends
    main = (ROOT / "gateway-rust/src/main.rs").read_text()
    assert 'Some("provision-system")' in main
    assert '"provision-system"' in RS


def test_the_database_network_is_the_internal_one_clients_share() -> None:
    suffix = re.search(r'DB_NETWORK_SUFFIX: &str = "([^"]+)"', RS).group(1)
    compose = (ROOT / "docker-compose.cluster.yml").read_text()
    block = re.search(rf"^  {re.escape(suffix)}:\n((?:    .*\n|\s*#.*\n)+)", compose, re.M)
    assert block and "internal: true" in block.group(1), "noo-db is the internal database network"


def test_the_broker_has_one_implementation() -> None:
    gw = ROOT / "gateway-rust/src"
    broker = (gw / "system_provision.rs").read_text()
    cli = (gw / "system_provision_cli.rs").read_text()
    body = broker[: broker.index("#[cfg(test)]")]
    reconcile = body[body.index("pub async fn reconcile(") :]
    assert "provision_system(db, name, spec, &delivered)" in reconcile
    assert "ensure_schema(" not in reconcile and "ensure_role(" not in reconcile
    assert "provision_system(&db, &p.name, &p.spec, &p.delivered)" in cli[: cli.index("#[cfg(test)]")]
