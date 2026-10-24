# SPDX-License-Identifier: AGPL-3.0-only
# Copyright 2026 PersonifAI LLC

"""Task #23 legacy sweep pins — the dead modules stay dead.

Each of these had ZERO live importers when moved (verified 2026-08-12);
a rebase resurrecting one of them silently reintroduces a second
implementation of something the Rust gateway owns."""

import pathlib

GONE = [
    "src/noomesh/channels/manager.py",
    "src/noomesh/channels/google_chat.py",
    "src/noomesh/channels/telegram.py",
    "src/noomesh/channels/registry.py",
    "src/noomesh/mcp/hub.py",
    "src/noomesh/cluster/backend_manager.py",
    "src/noomesh/cluster/router.py",
    "src/noomesh/cluster/placement.py",
    "src/noomesh/tools/device_sensors.py",
]

KEPT = [
    # Live survivors the sweep must never take: the outbound client, the
    # dispatcher protocol, and the manager-global module.
    "src/noomesh/channels/gateway_client.py",
    "src/noomesh/channels/base.py",
    "src/noomesh/channels/manager_ref.py",
    "src/noomesh/mcp/client.py",
]


def test_swept_modules_are_gone():
    for p in GONE:
        assert not pathlib.Path(p).exists(), f"{p} was resurrected"


def test_survivors_still_exist():
    for p in KEPT:
        assert pathlib.Path(p).exists(), f"{p} went missing — the sweep only covers GONE"


def test_packages_import_without_the_dead_modules():
    import noomesh.channels as ch
    import noomesh.cluster as cl
    import noomesh.mcp as m
    import noomesh.tools as t

    for pkg, name in [(ch, "build_channel_manager"), (cl, "TaskRouter"),
                      (m, "MCPHub"), (t, "DEVICE_SENSOR_TOOLS")]:
        assert not hasattr(pkg, name), f"{pkg.__name__}.{name} resurrected"
