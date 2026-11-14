# SPDX-License-Identifier: AGPL-3.0-only
# Copyright 2026 PersonifAI LLC
"""Every place that can remove a Docker volume, with the reason it is safe (i677 #20).

The rule (general, 2026-11-12): nothing in onboard, start, restart, clean,
reset or offboard may remove a volume that holds data unless the user asked
for that removal in this command and saw the volume by name first. An
automatic fix may only remove a bind RECORD whose data lives on the host,
and must say so before it does.

It came from onboard's volume reaper, which removed every "mismatched"
volume. A legacy (0.6.10+) noo-data has no bind and its data lives inside
docker, so a re-onboard with the stack down deleted the gateway's data. A
new removal site fails this test until it is added here with its reason.
"""
import re
from pathlib import Path

from tests._rust_src import own_code

ROOT = Path(__file__).resolve().parent.parent

REMOVAL = re.compile(
    r'volume rm|"volume",\s*"rm"|"volume"\.into\(\),\s*"rm"\.into\(\)|volume prune|down -v\b'
    r'|network rm|"network",\s*"rm"|"network"\.into\(\),\s*"rm"\.into\(\)|network prune'
)

# (file, a substring of the line) -> why it is safe
SITES = {
    ("noo-cli/src/commands/offboard.rs", 'run("docker", &["volume".into(), "rm".into(), "-f".into(), v.clone()]);'):
        "offboard: the user ran it and confirmed (or -y) 'STOP + DELETE the stack (containers, volumes = ALL DATA)'; "
        "the volumes are this project's, by exact label or the exact legacy noo-data name",
    ("noo-cli/src/commands/offboard.rs", 'run("docker", &["network".into(), "rm".into(), n.clone()]);'):
        "offboard: inside the same confirmed 'STOP + DELETE the stack' consent, after the containers; this "
        "project's networks by exact label plus the launcher's cluster network by exact name (networks hold no data)",
    ("noo-cli/src/onboard/steps.rs", '.args(["volume", "rm", "-f", vol])'):
        "onboard's reaper: ONLY a stale bind record (a different non-empty path; the data stays on the host), "
        "announced before it runs; an unbound volume or a failed inspect is kept",
    ("noo-cli/src/commands/at_rest_migrate.rs", 'run(&ctx.docker, &["volume".into(), "rm".into(), v.clone()], &ctx.root)?;'):
        "at-rest wipe: lists every volume by name, then needs a typed confirm phrase",
    ("scripts/noomesh-clean.sh", 'docker volume rm "$vol" >/dev/null 2>&1 && echo "  Removed $vol"'):
        "stack clean: the bulk set is printed by name before one confirm; stateful volumes "
        "(postgres, redis, noo-data) are never in it",
    ("scripts/noomesh-clean.sh", 'docker volume rm "$vol" >/dev/null 2>&1 && ui_done "Removed $vol"'):
        "stack clean --deep: a stateful volume, asked by name (under -y the plan says 'by -y: ALL of its data' first)",
    ("scripts/noomesh-clean.sh", 'ui_close_failed "volume(s) still present after removal:$STILL" "docker volume rm$STILL"'):
        "a hint printed to the user, not run",
    ("scripts/noomesh-stop.sh", "down -v --remove-orphans"):
        "stack stop --volumes: the CLI names every volume of the project before its confirm (or -y)",
    ("scripts/noomesh-rebuild.sh", "docker volume prune -f 2>/dev/null || true"):
        "anonymous volumes only, and only on a daemon whose prune is anonymous-only by default (has --all)",
    ("scripts/noomesh-rebuild.sh", "if docker volume prune --help 2>/dev/null | grep -q -- '--all'; then"):
        "a capability probe (--help), not a removal",
    ("scripts/bootstrap-standby.sh", 'docker volume rm "$VOLUME" > /dev/null 2>&1 || true'):
        "standby bootstrap: refuses when the volume already exists (a standby starts from a fresh base backup), "
        "creates it itself, and removes only that volume it just half-filled when the base backup fails",
    ("scripts/bootstrap-standby.sh", 'echo "  docker compose ${COMPOSE_FILES[*]} down postgres && docker volume rm $VOLUME"'):
        "a hint printed to the user, not run",
    ("noo-cli/src/commands/at_rest_migrate.rs", 'return Err(format!("docker volume rm {v} failed: {}", o.tail()));'):
        "an error message, not a removal",
}

# Dev and CI tools that manage their own throwaway volumes and networks, never a user's stack.
OUT_OF_SCOPE = {"scripts/noomesh-sandbox.sh", "scripts/cargo-docker.sh", "scripts/lib-baseline-db.sh"}


def _lines():
    for p in sorted((ROOT / "scripts").glob("*.sh")):
        rel = str(p.relative_to(ROOT))
        if rel in OUT_OF_SCOPE:
            continue
        for line in p.read_text().splitlines():
            if not line.lstrip().startswith("#"):
                yield rel, line
    for p in sorted((ROOT / "noo-cli" / "src").rglob("*.rs")):
        rel = str(p.relative_to(ROOT))
        for line in own_code(p.read_text()).splitlines():
            yield rel, line


def test_every_volume_removal_site_is_listed_with_its_reason():
    unlisted = []
    for rel, line in _lines():
        if REMOVAL.search(line) and not any(f == rel and sub in line for (f, sub) in SITES):
            unlisted.append(f"{rel}: {line.strip()}")
    assert not unlisted, (
        "a volume removal not in SITES: add it with the reason it cannot remove a user's data "
        "unseen (i677 #20), or remove it:\n  " + "\n  ".join(unlisted)
    )


def test_every_listed_site_still_exists():
    present = {(rel, sub) for rel, line in _lines() for (f, sub) in SITES if f == rel and sub in line}
    missing = [f"{f}: {sub}" for (f, sub) in SITES if (f, sub) not in present]
    assert not missing, "SITES names a removal that is gone: update the list\n  " + "\n  ".join(missing)
