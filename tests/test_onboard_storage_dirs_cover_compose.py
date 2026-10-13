# SPDX-License-Identifier: AGPL-3.0-only
# Copyright 2026 PersonifAI LLC

"""Onboard step 6 must create every directory the stack bind-mounts under the data root.

The wizard's hand list (`STORAGE_SUBDIRS`, noo-cli/src/onboard/mod.rs) predated
the model-cache `images` and `bin` mounts, so every fresh dist install passed
step 6 and was REFUSED at step 7 by the bind-mount preflight
(`bind_sources.rs`), whose printed remedy (`noo onboard --only storage`)
recreated the same nine directories and fixed nothing.

Step 6 now derives its list from the composed config with the preflight's own
function (`bind_sources::directory_sources_under`) and keeps STORAGE_SUBDIRS as
the floor for when compose cannot be rendered. This test holds the floor to the
projection: it renders the widest stack (base + every add-on overlay, every
profile) under a sentinel data root and fails when a directory source under it
is not in the floor. (The filter below restates the Rust one on purpose: it is
the independent reader; the rule is "bind, under the root, a directory, not
pki/".)
"""

from __future__ import annotations

import json
import os
import re
import subprocess

from tests._compose_projection import ADDON_OVERLAYS, BASE, ROOT, _profiles_in, _require_compose_floor

SENTINEL = "/sentinel-data-root"
MOD_RS = ROOT / "noo-cli/src/onboard/mod.rs"
FILE_EXTS = {
    "pub", "crt", "key", "pem", "csr", "conf", "cnf", "cfg", "yml", "yaml", "json", "ini", "sh", "toml",
    "txt", "env", "html", "js", "py", "lua", "sql",
}


def _floor() -> set[str]:
    text = MOD_RS.read_text()
    m = re.search(r"STORAGE_SUBDIRS: &\[&str\] = &\[(.*?)\];", text, re.S)
    assert m, "STORAGE_SUBDIRS not found in onboard/mod.rs"
    names = set(re.findall(r'"([^"]+)"', m.group(1)))
    assert len(names) >= 9, f"parsed too few names ({names}) — the pattern drifted"
    return names


def _looks_like_file(p: str) -> bool:
    b = p.rstrip("/").rsplit("/", 1)[-1]
    i = b.rfind(".")
    return i > 0 and b[i + 1:].lower() in FILE_EXTS


def _render() -> dict:
    _require_compose_floor()
    files = [BASE, *(ROOT / o for o in ADDON_OVERLAYS)]
    cmd = ["docker", "compose"]
    for f in files:
        cmd += ["-f", str(f)]
    for p in sorted(_profiles_in(*files)):
        cmd += ["--profile", p]
    cmd += ["config", "--format", "json"]
    # The data root is the sentinel; NOO_IMAGE_PREFIX is the one `:?` variable
    # (the launcher sets it). Path overrides are dropped so defaults render.
    env = {**os.environ, "NOO_DATA_ROOT": SENTINEL, "NOO_IMAGE_PREFIX": "example.invalid/noo"}
    for k in ("HF_CACHE_DIR", "IMAGES_DIR", "NOO_PG_DATA", "OLLAMA_MODELS_DIR"):
        env.pop(k, None)
    out = subprocess.run(cmd, cwd=ROOT, capture_output=True, text=True, timeout=120, env=env)
    assert out.returncode == 0, f"{' '.join(cmd)}\n{out.stderr}"
    cfg = json.loads(out.stdout)
    assert cfg.get("services"), "zero services rendered — the assertion would be vacuous"
    return cfg


def _directory_sources(cfg: dict) -> dict[str, str]:
    """source -> 'service:target' for every directory bind under the sentinel root."""
    found: dict[str, str] = {}
    for name, svc in cfg["services"].items():
        for v in svc.get("volumes") or []:
            if v.get("type") != "bind":
                continue
            src, tgt = v.get("source", "").rstrip("/"), v.get("target", "")
            if not src.startswith(SENTINEL + "/"):
                continue
            if _looks_like_file(src) or _looks_like_file(tgt) or "/pki" in src:
                continue
            found[src] = f"{name}:{tgt}"
    # Device-bound NAMED volumes (`driver_opts: {type: none, o: bind, device}`):
    # compose creates no such directory and the daemon refuses the mount when it
    # is absent. postgres-data is one; it is the 12th directory a clean install
    # needs (v0.2.92-rc.1: step 7 died on "failed to mount local volume").
    for vname, vol in (cfg.get("volumes") or {}).items():
        opts = (vol or {}).get("driver_opts") or {}
        dev = str(opts.get("device", "")).rstrip("/")
        if opts.get("type") == "none" and "bind" in str(opts.get("o", "")).split(",") and dev.startswith(SENTINEL + "/"):
            found[dev] = f"volume:{vname}"
    return found


def test_the_floor_covers_every_directory_the_stack_mounts_under_the_data_root():
    found = _directory_sources(_render())
    assert found, "no bind source under the sentinel root — the render did not honour NOO_DATA_ROOT"
    missing = {src: who for src, who in found.items() if src[len(SENTINEL) + 1:] not in _floor()}
    assert not missing, (
        "compose bind-mounts directories under NOO_DATA_ROOT that onboard step 6's floor "
        f"(STORAGE_SUBDIRS in noo-cli/src/onboard/mod.rs) does not name: {missing}. "
        "Add them there — otherwise a derivation failure leaves them to be refused at step 7."
    )


def test_the_directories_that_were_missed_are_named():
    found = _directory_sources(_render())
    rel = {s[len(SENTINEL) + 1:] for s in found}
    # images: a bind mount missed in v0.2.90; postgres: a device-bound volume
    # missed in v0.2.92-rc.1. (bin was the other v0.2.90 miss; its mount went
    # with the agent swap, and must not come back.)
    assert {"images", "postgres"} <= rel, f"mounts moved: {sorted(rel)}"
    assert {"images", "postgres"} <= _floor()
    assert "bin" not in rel and "bin" not in _floor(), "the retired agent-binary store is back"


def test_every_device_bound_volume_is_in_the_derived_set():
    """The 11 a clean install needs (12 until the agent-binary store was retired,
    an earlier change A3): the floor must name every one."""
    found = _directory_sources(_render())
    volumes = {who for who in found.values() if who.startswith("volume:")}
    assert "volume:postgres-data" in volumes, volumes
    assert len(found) >= 11, sorted(found)
