# SPDX-License-Identifier: AGPL-3.0-only
# Copyright 2026 PersonifAI LLC

"""An add-on publishes its HTTP routes through core, not through the gateway
service (0.6.13).

#474 refuses a third-party overlay that extends a core service, mounts a core
volume or binds a host path (noo-cli/src/addons/guards.rs). The gateway used
to receive a route manifest ONLY through the add-on's own overlay (a volume
or bind on the `gateway` service), so a third-party add-on could not publish
routes at all. Now `routes.json` is a bundle declaration like `system.json`
and `workloads.json`: launch-pins names it (`decl <addon> routes.json`) only
when the verified signed lock lists it, the launcher copies it to
`<install root>/.noo-addon-routes/<addon>/routes.json`, and the gateway
mounts that directory read-only and reads it before the older per-add-on
volume path.

scripts/lib-dist.sh runs for real (require_addon_pins,
addon_resources_materialise, addon_decls_materialise) through the harness of
tests/test_addon_resources_launcher.py, with the fixture add-on `rhaddon`
(tests/fixtures/addons/rhaddon, routes.json included). The Rust halves are
unit tests: launch-pins names routes.json only when the lock lists it
(noo-cli/src/commands/addon_pins.rs), and the registry registers an add-on
from the bundle-delivered manifest, which wins over an overlay's copy
(gateway-rust/src/addon_registry.rs, addon_proxy.rs).

Old code: addon_decls_materialise drops a `routes.json` decl line, there is
no .noo-addon-routes and no gateway mount of it; every launcher test below
fails."""

from __future__ import annotations

import json
import re
import shutil
import stat
from pathlib import Path

import yaml

from tests.test_addon_resources_launcher import FIXTURE, PINS, _root, _run

REPO = Path(__file__).resolve().parents[1]
ROUTES = ".noo-addon-routes"
SIGNED = PINS + "decl rhaddon routes.json\\n"


def _with_routes(tmp_path: Path) -> Path:
    """The install root with the fixture bundle, routes.json beside it."""
    root = _root(tmp_path)
    shutil.copy(FIXTURE / "routes.json", root / "addons" / "rhaddon" / "routes.json")
    return root


def _copied(root: Path) -> Path:
    return root / ROUTES / "rhaddon" / "routes.json"


def test_a_routes_json_the_signed_lock_lists_reaches_the_gateways_directory(tmp_path: Path) -> None:
    root = _with_routes(tmp_path)
    r = _run(tmp_path, FAKE_PINS=SIGNED)
    assert r.returncode == 0, r.stderr
    copied = _copied(root)
    assert copied.is_file(), f"not handed over; tree: {sorted(str(p.relative_to(root)) for p in (root / ROUTES).rglob('*'))}"
    assert copied.read_bytes() == (FIXTURE / "routes.json").read_bytes()
    manifest = json.loads(copied.read_text())
    assert manifest["addon"] == "rhaddon"
    assert [x["name"] for x in manifest["routes"]] == ["status", "drain"], "the parse found the fixture's routes"
    assert stat.S_IMODE(copied.stat().st_mode) == 0o644, "the gateway (another uid) reads it"
    # Its other declaration still arrives beside it.
    assert (root / ".noo-addon-systems" / "rhaddon" / "system.json").is_file()


def test_an_unsigned_routes_json_left_beside_the_bundle_is_not_copied(tmp_path: Path) -> None:
    root = _with_routes(tmp_path)
    # Verified, but launch-pins named no `decl rhaddon routes.json`: the
    # signed lock does not list the file.
    r = _run(tmp_path, FAKE_PINS=PINS)
    assert r.returncode == 0, r.stderr
    assert (root / "addons" / "rhaddon" / "routes.json").is_file(), "the unsigned file is there to be (not) copied"
    assert (root / ROUTES).is_dir(), "the bind source exists even when empty"
    assert list((root / ROUTES).iterdir()) == []
    assert (root / ".noo-addon-systems" / "rhaddon" / "system.json").is_file(), "the run did hand over what was signed"


def test_an_addon_refused_or_switched_off_loses_its_routes_and_the_mount_keeps_its_inode(tmp_path: Path) -> None:
    root = _with_routes(tmp_path)
    assert _run(tmp_path, FAKE_PINS=SIGNED).returncode == 0
    assert _copied(root).is_file()
    inode = (root / ROUTES).stat().st_ino
    # Refused at the runtime-input step: unverified for the gateway, no routes.
    res = "refuse rhaddon resource peer-key (shared_secret): NOO_ADDON_SECRET_RHADDON__PEER_KEY is not in the encrypted store\\n"
    r = _run(tmp_path, FAKE_PINS=SIGNED, FAKE_RES=res)
    assert r.returncode == 0, r.stderr
    assert "REFUSED add-on rhaddon" in r.stderr
    assert not (root / ROUTES / "rhaddon").exists(), "a refused add-on publishes no routes"
    assert (root / ROUTES).stat().st_ino == inode, "the mounted directory keeps its inode"
    # Back on, then switched off.
    assert _run(tmp_path, FAKE_PINS=SIGNED).returncode == 0 and _copied(root).is_file()
    r = _run(tmp_path, FAKE_PINS=SIGNED, NOO_ADDON_MAP="rhaddon=0\nvoice=0\ntrellion=0\n")
    assert r.returncode == 0, r.stderr
    assert not (root / ROUTES / "rhaddon").exists(), "a switched-off add-on publishes no routes"
    assert (root / ROUTES).stat().st_ino == inode


def test_a_routes_decl_for_an_addon_the_verdict_does_not_name_is_ignored(tmp_path: Path) -> None:
    root = _with_routes(tmp_path)
    pins = "decl rhaddon routes.json\\n"  # no `verified` line, no pin
    r = _run(tmp_path, FAKE_PINS=pins)
    assert r.returncode == 0, r.stderr
    assert not (root / ROUTES / "rhaddon").exists()


# ── the gateway's side of the handover ────────────────────────────────────

def _const(src: str, name: str) -> str:
    m = re.search(rf'pub const {name}: &str = "([^"]+)";', src)
    assert m, f"{name} not found"
    return m.group(1)


def test_the_gateway_mounts_the_directory_read_only_where_it_reads_first() -> None:
    doc = yaml.safe_load((REPO / "docker-compose.cluster.yml").read_text())
    vols = doc["services"]["gateway"]["volumes"]
    mounts = [v for v in vols if isinstance(v, str) and v.startswith(f"./{ROUTES}:")]
    assert len(mounts) == 1, vols
    _, target, mode = mounts[0].split(":")
    assert mode == "ro"
    proxy = (REPO / "gateway-rust" / "src" / "addon_proxy.rs").read_text()
    assert _const(proxy, "BUNDLE_ROUTES_DIR") == target
    legacy = _const(proxy, "ROUTES_DIR")
    assert legacy != target and not target.startswith(legacy + "/"), "never nested under a path an overlay may mount over"
    for name, svc in doc["services"].items():
        if name != "gateway":
            assert not any(isinstance(v, str) and v.startswith(f"./{ROUTES}") for v in svc.get("volumes") or []), name
    reg = (REPO / "gateway-rust" / "src" / "addon_registry.rs").read_text()
    assert "read_manifest_in(&[inp.bundle_dir, inp.dir]" in reg, "the bundle's copy is read first"
    assert "bundle_dir: FsPath::new(crate::addon_proxy::BUNDLE_ROUTES_DIR)" in reg


def test_the_launcher_owns_the_bind_source() -> None:
    bind = (REPO / "noo-cli" / "src" / "commands" / "bind_sources.rs").read_text()
    m = re.search(r"pub const LAUNCHER_DIRS: &\[&str\] = &\[([^\]]*)\];", bind)
    assert m and f'"{ROUTES}"' in m.group(1), "created as the operator, never Docker's root"
    decls = (REPO / "noo-cli" / "src" / "addons" / "decls.rs").read_text()
    m = re.search(r"pub const DECL_FILES: &\[&str\] = &\[([^\]]*)\];", decls)
    assert m and "ROUTES_FILE" in m.group(1), "launch-pins names routes.json"
    assert f"/{ROUTES}/" in (REPO / ".gitignore").read_text()
