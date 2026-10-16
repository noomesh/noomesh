# SPDX-License-Identifier: AGPL-3.0-only
# Copyright 2026 PersonifAI LLC

"""A bundle kind must be registered in THREE allowlists or it fails
differently in each place.

  scripts/sign-bundle.sh      KNOWN        — refuses to SIGN the kind (65)
  scripts/noo-apply.sh        KNOWN_KINDS  — the Linux applier refuses the
                                             ENTIRE bundle (76), not just
                                             that file
  noo-cli/src/commands/node_fetch.rs KNOWN_KINDS — the macOS poller, same

The Rust test `kind_allowlists_agree` pins these too, but it reads
`scripts/` from beside the crate — and the crate-only lane
(`CARGO_DOCKER_CRATE=$PWD/noo-cli scripts/cargo-docker.sh test`) mounts the
crate WITHOUT scripts/, so it skips there and verifies nothing. That is
exactly the gap through which a kind gets added in two places out of three,
so the shell strings are pinned here as well, in a job that always has the
whole tree (the same reasoning as test_entitlement_pubkey_parity.py).
"""

from __future__ import annotations

import re
from pathlib import Path

REPO = Path(__file__).resolve().parents[1]


def _shell_list(path: str, var: str) -> list[str]:
    text = (REPO / path).read_text()
    m = re.search(rf'^{var}="([^"]*)"$', text, re.M)
    assert m, f"{path}: no {var}=\"...\" assignment"
    return m.group(1).split()


def _rust_list() -> list[str]:
    text = (REPO / "noo-cli/src/commands/node_fetch.rs").read_text()
    m = re.search(r"const KNOWN_KINDS: &\[&str\] = &\[(.*?)\];", text, re.S)
    assert m, "node_fetch.rs: no KNOWN_KINDS array"
    return re.findall(r'"([^"]+)"', m.group(1))


def test_shell_allowlists_agree() -> None:
    assert _shell_list("scripts/noo-apply.sh", "KNOWN_KINDS") == _shell_list(
        "scripts/sign-bundle.sh", "KNOWN"
    )


def test_rust_applier_knows_every_linux_kind() -> None:
    rust = _rust_list()
    for kind in _shell_list("scripts/noo-apply.sh", "KNOWN_KINDS"):
        assert kind in rust, f"node_fetch.rs KNOWN_KINDS lacks {kind}"


def test_nats_creds_kind_is_registered_in_all_three() -> None:
    assert "nats-creds" in _shell_list("scripts/noo-apply.sh", "KNOWN_KINDS")
    assert "nats-creds" in _shell_list("scripts/sign-bundle.sh", "KNOWN")
    assert "nats-creds" in _rust_list()


def test_noo_apply_still_gates_on_the_string() -> None:
    """A stale literal nothing consults would pass every check above."""
    text = (REPO / "scripts/noo-apply.sh").read_text()
    assert 'case " $KNOWN_KINDS " in' in text


# The backend door leaves (the design A): ten kinds, one pair per door
# service. Pinned by name in all three lists for the same reason as
# nats-creds above — a pair added to two lists out of three is a bundle the
# third refuses whole.
DOOR_LEAF_KINDS = [
    f"svc-{svc}.{ext}"
    for svc in ("vllm", "llamacpp", "ollama", "tei", "reranker")
    for ext in ("crt", "key")
]


def test_door_leaf_kinds_are_registered_in_all_three() -> None:
    apply = _shell_list("scripts/noo-apply.sh", "KNOWN_KINDS")
    sign = _shell_list("scripts/sign-bundle.sh", "KNOWN")
    rust = _rust_list()
    for kind in DOOR_LEAF_KINDS:
        assert kind in apply, f"noo-apply.sh KNOWN_KINDS lacks {kind}"
        assert kind in sign, f"sign-bundle.sh KNOWN lacks {kind}"
        assert kind in rust, f"node_fetch.rs KNOWN_KINDS lacks {kind}"


def test_host_telemetry_kind_is_registered_in_all_three() -> None:
    """`noo cluster host-telemetry apply` delivers this kind; one list
    missing it makes the whole bundle refuse (76) on that side."""
    assert "host-telemetry" in _shell_list("scripts/noo-apply.sh", "KNOWN_KINDS")
    assert "host-telemetry" in _shell_list("scripts/sign-bundle.sh", "KNOWN")
    assert "host-telemetry" in _rust_list()


VENDOR_KINDS = ["vendor-cli", "vendor-cli-manifest", "vendor-runtime", "vendor-runtime-manifest"]


def test_vendor_kinds_are_registered_in_all_three() -> None:
    """i83 E1e: the controller stages a harness kind's vendor CLI (and its
    runtime) and the bundle carries it with a manifest each; a list missing
    one makes the whole bundle refuse on that side."""
    apply = _shell_list("scripts/noo-apply.sh", "KNOWN_KINDS")
    sign = _shell_list("scripts/sign-bundle.sh", "KNOWN")
    rust = _rust_list()
    for kind in VENDOR_KINDS:
        assert kind in apply, f"noo-apply.sh KNOWN_KINDS lacks {kind}"
        assert kind in sign, f"sign-bundle.sh KNOWN lacks {kind}"
        assert kind in rust, f"node_fetch.rs KNOWN_KINDS lacks {kind}"


def test_vendor_manifests_are_text_kinds_in_both_appliers() -> None:
    """The manifests are parsed line by line; a CR or NUL must be refused."""
    shell = _shell_list("scripts/noo-apply.sh", "TEXT_KINDS")
    text = (REPO / "noo-cli/src/commands/node_fetch.rs").read_text()
    m = re.search(r"const TEXT_KINDS: &\[&str\] = &\[(.*?)\];", text, re.S)
    assert m
    rust = re.findall(r'"([^"]+)"', m.group(1))
    for kind in ("vendor-cli-manifest", "vendor-runtime-manifest"):
        assert kind in shell and kind in rust, kind
