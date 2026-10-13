# SPDX-License-Identifier: AGPL-3.0-only
# Copyright 2026 PersonifAI LLC

"""The shipped harness unit must pass the checks the applier makes at
install time (scripts/noo-apply.sh, the harness-unit block), and keep the
properties an earlier change decided on — read as unit-file LINES, not as a
substring search over the whole file (an earlier change: a guard that greps
prose passes on its own comment).

  - runs as the dedicated user, in group noo-agent and nothing more
  - never the docker group (an earlier change: that is root on the host)
  - no privilege escalation, read-only PKI, the caps the container had
  - NOT enabled by the applier: the agent starts it per placement, so the
    unit must not start itself at boot through anything but [Install],
    which the applier does not act on
"""
from __future__ import annotations

import re
from pathlib import Path

REPO = Path(__file__).resolve().parents[1]
UNIT = REPO / "node-agent-go/deploy/noo-harness.service"
ROOT = REPO
APPLY = REPO / "scripts/noo-apply.sh"


def _directives(section: str) -> dict[str, list[str]]:
    """Key=Value lines of one [section], comments stripped."""
    out: dict[str, list[str]] = {}
    current = None
    for raw in UNIT.read_text().splitlines():
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        m = re.match(r"^\[(\w+)\]$", line)
        if m:
            current = m.group(1)
            continue
        if current == section and "=" in line:
            k, v = line.split("=", 1)
            out.setdefault(k.strip(), []).append(v.strip())
    return out


def test_service_section_is_what_the_applier_demands() -> None:
    svc = _directives("Service")
    assert svc, "no [Service] section — the applier refuses this unit (exit 65)"
    assert svc.get("User") == ["noo-harness"], svc.get("User")
    assert svc.get("Group") == ["noo-agent"], svc.get("Group")
    groups = " ".join(svc.get("SupplementaryGroups", []))
    assert "docker" not in groups, "the applier refuses a unit that grants docker; so does this test"
    assert svc.get("NoNewPrivileges") == ["true"]
    assert svc.get("ProtectSystem") == ["strict"]
    assert "/etc/noo/pki" in " ".join(svc.get("ReadOnlyPaths", []))
    assert svc.get("EnvironmentFile") == ["-/etc/noo-harness.env"]
    assert svc.get("ExecStart") == ["/usr/local/bin/noo-gateway harness"]
    assert svc.get("MemoryMax") and svc.get("CPUQuota"), "the container's caps must carry over"


def test_applier_refusals_match_the_unit() -> None:
    """The applier's harness-unit greps and the unit agree on the exact
    lines, so a rename on either side fails here, not on a node."""
    text = APPLY.read_text()
    block = text[text.index('if [ -f "$WORK/files/harness-unit" ]'):]
    block = block[: block.index("applied=\"$applied harness-unit\"")]
    assert "grep -qE '^User=noo-harness$'" in block
    assert "SupplementaryGroups=.*docker" in block
    assert "useradd --system" in block and "--gid noo-agent noo-harness" in block
    # The sudoers grant is REMOVED, not installed — and the applier must
    # delete an existing one, so a node upgrading from a release that wrote
    # it does not keep a standing NOPASSWD root rule nothing takes.
    #
    # It could never work: noo-node-agent.service runs with
    # NoNewPrivileges=true, which makes setuid binaries inert, so sudo
    # cannot elevate whatever the drop-in says (host3, 2026-09-19). The
    # lifecycle is now noo-hostd's `harness-start` / `harness-stop` ops.
    assert "rm -f /etc/sudoers.d/noo-harness-lifecycle" in block, (
        "the applier must DELETE the unusable grant, not merely stop writing it"
    )
    # Comments explain why the grant is gone and legitimately name it, so
    # judge the CODE, not the prose around it.
    code = "\n".join(ln for ln in block.splitlines() if not ln.strip().startswith("#"))
    assert "visudo" not in code, "no sudoers drop-in is written for the harness any more"
    assert "NOPASSWD" not in code, "the harness lifecycle grants no sudo"
    for verb in ("start", "stop", "restart"):
        assert f"/usr/bin/systemctl {verb} noo-harness" not in block, (
            f"a sudo rule for `systemctl {verb} noo-harness` is back; the agent cannot use one"
        )
    assert "systemctl enable" not in block, "the applier must not enable the harness; the agent starts it per placement"


def test_the_agent_asks_hostd_for_the_lifecycle_and_hostd_serves_it() -> None:
    """Both ends of the replacement, pinned together.

    The op names are a contract across two files in two languages: the
    consumer matches them against the op list hostd ADVERTISES in its
    heartbeat, so a rename on one side reads as "this daemon is too old"
    rather than as a mismatch. That is a silent degradation, which is
    exactly the shape this repo keeps finding, so pin it here.
    """
    svc = (ROOT / "node-agent-go/internal/hostsvc/hostsvc.go").read_text()
    ops = (ROOT / "node-agent-go/internal/hostd/worker_ops.go").read_text()
    for op in ("harness-start", "harness-stop"):
        assert f'"{op}"' in svc, f"the consumer no longer asks for {op}"
        # gofmt aligns the registry, so the gap between key and value is
        # not fixed — match the pair, not the whitespace.
        assert re.search(rf'"{op}":\s*{{Name: "{op}"', ops), f"hostd no longer serves {op}"
    # Judge the code, not the comments that explain why sudo is gone. What
    # would be wrong is INVOKING it — a quoted "sudo" argv entry.
    svc_code = "\n".join(ln for ln in svc.splitlines() if not ln.strip().startswith("//"))
    assert '"sudo"' not in svc_code, (
        "the host service is invoking sudo again; under NoNewPrivileges it cannot work"
    )


# ── the bundle carries the BINARY's copies, not the controller's tree ────
# `noo upgrade --nodes` stages the harness unit and env template from a
# controller whose checkout is any revision at all. On 2026-09-19 a 0.5.42
# binary ran on a controller whose tree predated both files and four of five
# nodes failed to stage. They are compiled in now (build.rs → ASSET_HARNESS_*).
#
# The consts are empty in a crate-only build, which is how the existing
# enroll assets degrade — so the Rust drift test SKIPS there, and a wrong
# path in build.rs would make every bundle quietly say "no harness". This
# runs where the tree exists and checks the source of that value.
BUILD_RS = REPO / "noo-cli/build.rs"

HARNESS_ASSETS = {
    "ASSET_HARNESS_UNIT": "node-agent-go/deploy/noo-harness.service",
    "ASSET_HARNESS_ENV_TMPL": "node-agent-go/deploy/noo-harness.env.tmpl",
}


def test_build_rs_embeds_the_harness_assets_and_the_paths_resolve() -> None:
    text = BUILD_RS.read_text()
    m = re.search(r"const ENROLL_ASSETS: &\[\(&str, &str\)\] = &\[(.*?)\];", text, re.S)
    assert m, "build.rs: no ENROLL_ASSETS table"
    table = dict(re.findall(r'\("(\w+)",\s*"([^"]+)"\)', m.group(1)))
    for name, rel in HARNESS_ASSETS.items():
        assert table.get(name) == rel, (
            f"build.rs must embed {name} from {rel}, got {table.get(name)!r} — "
            "a wrong path compiles to an empty const and every bundle then "
            "silently carries no harness"
        )
        assert (REPO / rel).is_file(), f"{rel} does not exist, so {name} would embed nothing"
        assert (REPO / rel).stat().st_size > 0, f"{rel} is empty"


def test_provision_stages_the_embedded_copies_not_the_checkout() -> None:
    """The staging path must not read these two files from disk again."""
    src = (REPO / "noo-cli/src/commands/provision.rs").read_text()
    for rel in HARNESS_ASSETS.values():
        leaf = rel.rsplit("/", 1)[1]
        for line in src.splitlines():
            if leaf in line and "fs::read" in line:
                raise AssertionError(
                    f"provision.rs reads {leaf} from the controller's checkout: {line.strip()}"
                )
    assert "asset_harness_env_tmpl()" in src and "asset_harness_unit()" in src


# ── the harness binary must not impose a glibc floor on nodes ────────────
# 2026-09-19: the gateway asset was built for *-linux-gnu on the release
# runner, so it required GLIBC_2.38/2.39 and could not exec on host3
# (Ubuntu 22.04, glibc 2.35). systemd restarted it 300+ times. The CLI
# asset beside it has always been static musl. A node binary that links
# the build host's libc makes the RUNNER's distro a floor for the whole
# fleet, and the only symptom is a service that cannot start on the
# oldest box you own.
RELEASE_WF = REPO / ".github/workflows/noo-cli-release.yml"


def _gateway_targets() -> list[str]:
    text = RELEASE_WF.read_text()
    start = text.index("\n  gateway:")
    block = text[start : text.index("\n  release:", start)]
    return re.findall(r"- target: (\S+)", block)


def test_linux_gateway_assets_are_static_musl() -> None:
    targets = _gateway_targets()
    assert targets, "no gateway build targets found"
    linux = [t for t in targets if "linux" in t]
    assert linux, f"the gateway must build for Linux nodes, got {targets}"
    for t in linux:
        assert t.endswith("-musl"), (
            f"gateway target {t} links the build host's glibc — a node older than "
            "the release runner cannot exec it (host3, 2026-09-19)"
        )


def test_the_release_asserts_static_linkage() -> None:
    """Choosing a musl target is not the same as producing a static binary;
    the workflow must check the artifact, not the target name."""
    text = RELEASE_WF.read_text()
    start = text.index("\n  gateway:")
    block = text[start : text.index("\n  release:", start)]
    assert "static" in block and "not statically linked" in block, (
        "the gateway job must assert the artifact is statically linked"
    )


def test_provision_requests_the_static_asset() -> None:
    src = (REPO / "noo-cli/src/commands/provision.rs").read_text()
    m = re.search(r"fn gateway_asset_for.*?\n\}", src, re.S)
    assert m, "gateway_asset_for not found"
    for line in m.group(0).splitlines():
        if "noo-gateway-" in line and "linux" in line:
            assert "musl" in line, f"provision asks a node for a glibc-linked harness: {line.strip()}"


# ── one value, one home ──────────────────────────────────────────────────
# The harness env file is delivered once, at provision time. Anything in it
# that the DATABASE also owns is a second home for the same value, and the
# file is the one that cannot be changed without re-provisioning the node.
# `NOO_HARNESS_KIND` was exactly that: the placement carries it
# (`--kind`, validated by the gateway, enforced by the agent), the harness
# binary never reads it, and the template asserted `noo` anyway — harmless
# today only because a non-`noo` kind is refused before the harness starts,
# and a trap for whoever ships the foreign runners.
HARNESS_ENV_TMPL = REPO / "node-agent-go/deploy/noo-harness.env.tmpl"

# Keys the DATABASE owns, via the placement or noo_node_config.
DB_OWNED_KEYS = ("NOO_HARNESS_KIND",)


def _env_template_keys() -> set[str]:
    text = re.sub(r"\{#.*?#\}", "", HARNESS_ENV_TMPL.read_text(), flags=re.S)
    return {m.group(1) for m in re.finditer(r"^([A-Z_][A-Z0-9_]*)=", text, re.M)}


def test_the_env_file_does_not_restate_what_the_database_owns() -> None:
    keys = _env_template_keys()
    assert keys, "no keys parsed from the harness env template — is this the right file?"
    for k in DB_OWNED_KEYS:
        assert k not in keys, (
            f"{k} is owned by the placement in the database; setting it here makes a "
            "second home that only a re-provision can change"
        )


def test_the_env_file_still_carries_the_bootstrap_floor() -> None:
    """The counterpart: it must keep what is needed BEFORE the database is
    reachable (an earlier change's floor). Removing a DB-owned key must not turn
    into removing identity or transport."""
    keys = _env_template_keys()
    for k in ("NODE_ID", "NOO_GATEWAY_URL", "NATS_URL", "NOO_TLS_CA", "NOO_TLS_CERT", "NOO_TLS_KEY"):
        assert k in keys, f"{k} must stay in the env file — the harness needs it to reach anything"
