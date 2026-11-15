# SPDX-License-Identifier: AGPL-3.0-only
# Copyright 2026 PersonifAI LLC

"""The controller's own box, by name (gateway chat_context.rs
`STACK_BACKEND_CONTAINERS`, noomesh#1235): every name the gateway accepts as
one of the stack's own containers is a `container_name` the compose it runs
declares. A name the compose does not declare could be another machine, and
the gateway would stamp the controller's decided context on it."""

from __future__ import annotations

import re
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
CHAT_CONTEXT = ROOT / "gateway-rust" / "src" / "chat_context.rs"
COMPOSE = ROOT / "docker-compose.cluster.yml"


def stack_backend_containers(src: str) -> list[str]:
    m = re.search(r"pub const STACK_BACKEND_CONTAINERS: &\[&str\] = &\[(.*?)\];", src, re.S)
    assert m, "STACK_BACKEND_CONTAINERS is not in chat_context.rs"
    names = re.findall(r'"([a-z0-9-]+)"', m.group(1))
    assert names, "STACK_BACKEND_CONTAINERS is empty"
    return names


def declared_containers(compose: str) -> set[str]:
    return set(re.findall(r"^\s*container_name: \$\{NOO_CONTAINER_PREFIX:-noo\}-([a-z0-9-]+)\s*$", compose, re.M))


def test_the_local_names_are_the_composes_own_containers():
    names = stack_backend_containers(CHAT_CONTEXT.read_text(encoding="utf-8"))
    declared = declared_containers(COMPOSE.read_text(encoding="utf-8"))
    missing = [n for n in names if n not in declared]
    assert not missing, f"accepted as the controller's own but not a container in docker-compose.cluster.yml: {missing}"
    assert len(names) == len(set(names)), names
