# SPDX-License-Identifier: AGPL-3.0-only
# Copyright 2026 PersonifAI LLC

"""The stunnel doors and the NVIDIA exporter run as an unprivileged uid (i132).

They were the last first-party images that ran as root, because their service
leaf keys were `0600` owned by the operator (`KeyReader::ContainerRoot`: root
in the container reads through CAP_DAC_OVERRIDE). The key table now hands each
of those keys to uid 65532 like every other non-root service, and the three
places that name the uid must agree or a door starts and cannot read its key:

* the Dockerfile's last `USER` (`nonroot`, created with uid 65532),
* compose's `user:` (the NAME `nonroot`: Docker 27 resolves a numeric
  string by name and fails, tests/test_compose_named_users.py),
* `SERVICE_KEY_READERS` in noo-cli/src/pki.rs (`ContainerUid(65532)`).

The doors a NODE's agent starts keep root on purpose (a root-owned 0600 leaf);
node-agent-go pins `User: "0"` in `TestSidecarRunsAsRootWhateverTheImageUserSays`.
"""

from __future__ import annotations

import re
from pathlib import Path

import pytest
import yaml

ROOT = Path(__file__).resolve().parents[1]
UID = 65532
# compose service -> the leaf (services/<leaf>) its key is read from
DOORS = {
    "stunnel-ollama": "ollama",
    "stunnel-ollama-embed": "ollama-embed",
    "stunnel-ollama-embed-cpu": "ollama-embed-cpu",
    "stunnel-llamacpp": "llamacpp",
    "stunnel-tei": "tei",
    "stunnel-tei-gpu": "tei",
    "stunnel-reranker": "reranker",
    "stunnel-vllm": "vllm",
    "stunnel-vllm-secondary": "vllm",
    "nvidia-exporter": "nvidia-exporter",
}
DOCKERFILES = {
    "stunnel": "docker/Dockerfile.stunnel",
    "nvidia-exporter": "docker/Dockerfile.nvidia-exporter",
}


def _readers() -> dict[str, str]:
    src = (ROOT / "noo-cli/src/pki.rs").read_text()
    table = src.split("pub const SERVICE_KEY_READERS", 1)[1].split("];", 1)[0]
    return dict(re.findall(r'\("([a-z0-9-]+)",\s*(KeyReader::[A-Za-z]+(?:\(\d+\))?)\)', table))


def _last_user(path: str) -> str | None:
    last = None
    for raw in (ROOT / path).read_text().splitlines():
        line = raw.strip()
        if line.upper().startswith("USER "):
            last = line.split(None, 1)[1].strip()
    return last


@pytest.mark.parametrize("name", sorted(DOCKERFILES))
def test_the_image_ends_with_the_nonroot_user_at_the_uid_the_key_is_handed_to(name):
    path = DOCKERFILES[name]
    user = _last_user(path)
    assert user is not None, f"{path} has no USER line: it runs as root"
    assert user.split(":")[0] == "nonroot", f"{path} ends USER {user}, want nonroot"
    text = (ROOT / path).read_text()
    # The name must resolve to the uid the key table hands the keys to.
    made = re.search(r"(?:addgroup|groupadd)[^\n]*?(?:-g|--gid)[ =]65532[^\n]*?nonroot", text.replace("\\\n", " "))
    assert made, f"{path} does not create `nonroot` at gid {UID}"
    assert re.search(r"(?:adduser|useradd)[^\n]*?(?:-u|--uid)[ =]65532", text.replace("\\\n", " ")), f"{path} does not create `nonroot` at uid {UID}"


@pytest.mark.parametrize("service,leaf", sorted(DOORS.items()))
def test_compose_pins_the_user_by_name(service, leaf):
    svc = yaml.safe_load((ROOT / "docker-compose.cluster.yml").read_text())["services"][service]
    assert svc.get("user") == "nonroot", f"{service}: user is {svc.get('user')!r}"


@pytest.mark.parametrize("leaf", sorted(set(DOORS.values())))
def test_the_key_table_hands_the_key_to_that_uid(leaf):
    row = _readers().get(leaf)
    assert row == f"KeyReader::ContainerUid({UID})", (
        f"services/{leaf}/service.key is {row} in SERVICE_KEY_READERS; the container runs as {UID}, "
        "so a root-only 0600 key would stop it starting"
    )


def test_no_first_party_image_in_the_table_still_reads_its_key_as_root_here():
    """The root rows left are third-party images (nats, nginx); vllm's
    key is read by its door now, not the engine;
    none of the doors or exporters this repo builds may be one. evolve runs
    as nonroot (65532) since evolve v0.1.4, so its key reader is that uid."""
    roots = {k for k, v in _readers().items() if v == "KeyReader::ContainerRoot"}
    assert not (roots & set(DOORS.values())), sorted(roots & set(DOORS.values()))
    assert roots == {"nats", "model-cache"}, sorted(roots)
    assert _readers().get("evolve") == "KeyReader::ContainerUid(65532)", _readers().get("evolve")


def test_the_node_agent_still_starts_its_doors_as_root():
    src = (ROOT / "node-agent-go/internal/docker/sidecar.go").read_text()
    assert re.search(r'const sidecarUser = "0"', src)
    assert re.search(r"User:\s+sidecarUser", src), "startSidecar must set User: sidecarUser (the image's USER is 65532)"
