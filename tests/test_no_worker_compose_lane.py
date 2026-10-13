# SPDX-License-Identifier: AGPL-3.0-only
# Copyright 2026 PersonifAI LLC

"""There is no `worker` compose profile — and nothing may quietly bring one back.

Fleet logging phase 4 (2026-09-28), from the frozen Grafana/TLS plan (ii).
Three services carried `profiles: [..., "worker"]`: docker-socket-proxy,
promtail and node-exporter. Their comments said "all nodes" and told a
worker to point `LOKI_PUSH_URL` at a port Loki never published. No worker
ever ran compose: nodes are native agents delivered by the bootstrap-token
+ provision rail (`provision.rs` and `enroll.rs` never run compose), and the
only launcher that passed `--profile worker` was the retired
`cluster-init.sh`. The profile was a lane with a sign and no road — and had
a worker followed the sign, its promtail would have pushed to Loki with no
client certificate (the node bundle carries no service leaf), and its node-exporter would never have been scraped.

promtail and the proxy are deleted; node-exporter is controller-only. A
`worker` profile re-appearing on any service is that lane coming back
without the design it needs (a published mTLS Loki port, a service leaf
delivered to nodes, a compose lane on the node). `worker-core` is a
different thing — the slim controller-side worker set — and is excluded by
exact name, not by prefix, so `worker-anything` else is caught.

Planted: `"worker"` added back to node-exporter's profiles → the first test
fails naming it.
"""

from __future__ import annotations

import pytest

from tests._compose_projection import full_projection, raw_services_union

DEAD_PROFILE = "worker"
# Legitimate profiles whose name contains the dead one. Exact matches only.
NOT_THE_DEAD_LANE = {"worker-core"}


def _carriers(services: dict) -> dict[str, list[str]]:
    out = {}
    for name, svc in sorted(services.items()):
        profiles = [str(p) for p in ((svc or {}).get("profiles") or [])]
        if DEAD_PROFILE in profiles:
            out[name] = profiles
    return out


def test_no_service_carries_the_worker_profile():
    services = raw_services_union()
    assert len(services) > 20, "the compose parse found almost nothing — vacuous"
    carriers = _carriers(services)
    assert not carriers, (
        f"the `worker` compose profile is back on {sorted(carriers)} — that lane was "
        "retired with promtail (fleet logging phase 4); nodes ship logs through "
        "their native agent (#526), and a worker never runs compose"
    )


def test_the_composed_projection_has_no_worker_profile_either():
    # Overlays (add-ons) are files too; the projection is what a launcher runs.
    services = full_projection()["services"]
    assert not _carriers(services)


def test_worker_core_is_still_a_profile_and_still_excluded_by_name():
    # The exclusion is exact: if `worker-core` ever goes, this row goes with
    # it rather than silently excluding nothing.
    services = raw_services_union()
    with_core = {n for n, s in services.items() if "worker-core" in ((s or {}).get("profiles") or [])}
    assert with_core, "no service carries `worker-core` any more — drop NOT_THE_DEAD_LANE with it"
    assert "worker-core" in NOT_THE_DEAD_LANE
    assert not any(p == DEAD_PROFILE for p in NOT_THE_DEAD_LANE)


def test_the_checker_catches_the_plant():
    bad = {
        "node-exporter": {"profiles": ["monitoring", "worker", "controller"]},
        "postgres": {"profiles": ["controller", "worker-core", "standalone"]},
    }
    assert _carriers(bad) == {"node-exporter": ["monitoring", "worker", "controller"]}


def test_no_launcher_passes_profile_worker():
    """The lane had one driver, and it is archived. A live script that says
    `--profile worker` would start nothing today and mislead tomorrow."""
    from pathlib import Path

    root = Path(__file__).resolve().parents[1]
    hits = []
    for path in list(root.glob("scripts/*.sh")) + list((root / "noo-cli" / "src").rglob("*.rs")):
        text = path.read_text(errors="replace")
        if "--profile worker " in text or text.rstrip().endswith("--profile worker") or '"--profile", "worker"' in text:
            hits.append(str(path.relative_to(root)))
    assert not hits, hits


@pytest.mark.parametrize("profile", sorted(NOT_THE_DEAD_LANE))
def test_the_exclusion_names_only_real_profiles(profile):
    services = raw_services_union()
    assert any(profile in ((s or {}).get("profiles") or []) for s in services.values()), profile
