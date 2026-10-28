# SPDX-License-Identifier: AGPL-3.0-only
# Copyright 2026 PersonifAI LLC

"""Every var the agent-env template references must be supplied by `noo
cluster provision`.

The template (node-agent-go/deploy/noo-node-agent.env.tmpl) is the SINGLE source of
truth for the agent env — the native CLI renders it with a fail-loud
Jinja-subset renderer that never evaluates defaults (the ansible lane is gone).
That renderer errors at runtime on an unknown var, and provision.rs carries a
Rust test asserting the real template renders with exactly its vars map — but
the noo-cli CI job builds CRATE-ONLY (no repo around it), so that Rust test
self-skips in CI. This test is the same guard run where the full checkout
exists: the python `test` job.

Failure mode guarded (the fu52 bug class): someone adds `{{ new_cred }}` to the
template for the ansible lane, the CLI's vars map doesn't know it, and — without
this test — the first sign is a live provision failing (best case) or, had the
renderer used defaults, an agent shipped with an empty credential (worst case).
"""

from __future__ import annotations

import re
from pathlib import Path

REPO = Path(__file__).resolve().parents[1]
TEMPLATE = REPO / "node-agent-go/deploy/noo-node-agent.env.tmpl"
PROVISION = REPO / "noo-cli/src/commands/provision.rs"


def _template_vars() -> set[str]:
    text = TEMPLATE.read_text()
    # Strip {# … #} comments first — vars mentioned in prose don't count.
    text = re.sub(r"\{#.*?#\}", "", text, flags=re.S)
    out = set()
    for expr in re.findall(r"\{\{(.*?)\}\}", text, flags=re.S):
        # First identifier token = the variable (same rule as the Rust renderer).
        m = re.match(r"\s*([A-Za-z_][A-Za-z0-9_]*)", expr)
        if m:
            out.add(m.group(1))
    return out


def _provision_maps() -> dict[str, set[str]]:
    """Every var map in provision.rs, keyed by the function that builds it.

    Two functions render the template — the pull rail (`build_env_vars`, the
    map phase of `cluster_provision`) and the self-agent lane
    (`provision_local`) — each with its own map, and
    the renderer's guard checks the one in use. A var supplied by only one
    of them passed a union-based test and refused every node on a live
    `noo upgrade --nodes` (2026-09-11), so each map is held to the template
    on its own.
    """
    text = PROVISION.read_text()
    maps: dict[str, set[str]] = {}
    current = "<module>"
    for line in text.splitlines():
        m = re.match(r"^(?:pub(?:\(crate\))? )?fn ([a-z0-9_]+)", line)
        if m:
            current = m.group(1)
        for var in re.findall(r'vars\.insert\("([a-z0-9_]+)"', line):
            maps.setdefault(current, set()).add(var)
    return maps


def _provision_supplied() -> set[str]:
    return set().union(*_provision_maps().values())


def test_every_renderer_map_supplies_every_template_var() -> None:
    all_maps = _provision_maps()
    # The renderers of the AGENT template. (`attach_harness` only adds the
    # harness extras on top of `build_env_vars`; it is held to the harness
    # template below.)
    maps = {fn: v for fn, v in all_maps.items() if fn in ("build_env_vars", "provision_local_in")}
    assert len(maps) >= 2, f"expected the pull-rail and local maps, found {sorted(all_maps)}"
    template = _template_vars()
    for fn, supplied in maps.items():
        missing = template - supplied
        assert not missing, (
            f"provision.rs::{fn} renders the template without {sorted(missing)} — "
            "the renderer's guard refuses the whole provision for a var it does not supply"
        )


def test_provision_supplies_every_template_var() -> None:
    missing = _template_vars() - _provision_supplied()
    assert not missing, (
        f"noo-node-agent.env.j2 references {sorted(missing)} but "
        "`noo cluster provision` (noo-cli/src/commands/provision.rs) does not "
        "supply them. The native renderer never evaluates Jinja defaults, so "
        "each of these fails a live provision — add vars.insert lines with the "
        "gate-lane values (see provision-agent-via-gate.yml for what ansible "
        "would have passed)."
    )


def test_template_and_renderer_use_only_the_supported_subset() -> None:
    """The Rust renderer supports {{ var }}, {# #}, and ONE {% if %} shape."""
    text = re.sub(r"\{#.*?#\}", "", TEMPLATE.read_text(), flags=re.S)
    tags = [t.strip() for t in re.findall(r"\{%(.*?)%\}", text, flags=re.S)]
    unsupported = [
        t for t in tags
        if not (t.startswith("endif") or ("if" in t and "noo_pki_dir" in t))
    ]
    assert not unsupported, (
        f"noo-node-agent.env.j2 grew template tags {unsupported} the native "
        "renderer (provision.rs::render_env_template) does not support — "
        "extend the renderer and its tests in the same change."
    )


# ── the harness env ────────────────────────────────────────
# A second template, rendered by the pull rail only (the controller's own
# node gets no harness: its gateway runs turns in process). Same renderer,
# same rule: no defaults, every var supplied — and the map that supplies it
# is `hvars`, built inside `attach_harness` (a phase of cluster_provision) from
# the pull rail's `vars` (`build_env_vars`) plus the harness extras, which the
# `vars.insert(` scan above already picks up.
HARNESS_TEMPLATE = REPO / "node-agent-go/deploy/noo-harness.env.tmpl"


def _harness_template_vars() -> set[str]:
    text = re.sub(r"\{#.*?#\}", "", HARNESS_TEMPLATE.read_text(), flags=re.S)
    out = set()
    for expr in re.findall(r"\{\{(.*?)\}\}", text, flags=re.S):
        m = re.match(r"\s*([A-Za-z_][A-Za-z0-9_]*)", expr)
        if m:
            out.add(m.group(1))
    assert out, "harness template names no vars — is it the right file?"
    return out


def test_harness_template_has_no_defaults() -> None:
    """The renderer never evaluates `| default(...)`; a default in the
    template is a var that will be EMPTY on the node, silently."""
    text = re.sub(r"\{#.*?#\}", "", HARNESS_TEMPLATE.read_text(), flags=re.S)
    assert "default(" not in text, "the harness template carries a default the renderer will ignore"


def test_pull_rail_supplies_every_harness_template_var() -> None:
    maps = _provision_maps()
    assert "build_env_vars" in maps and "attach_harness" in maps, sorted(maps)
    # hvars = the pull rail's vars + the harness extras.
    supplied = maps["build_env_vars"] | maps["attach_harness"]
    missing = _harness_template_vars() - supplied
    assert not missing, (
        f"provision.rs::attach_harness renders the harness template without {sorted(missing)}"
    )


def test_harness_template_carries_the_agent_token_its_model_url_needs() -> None:
    """Phase D points NOO_HARNESS_MODEL_URL at the node agent's :8081 proxy,
    which is auth-gated. The first turn ever dispatched to a node (host3,
    2026-09-22) reached that proxy and was refused: 401 "Missing node agent
    auth token". The binary attaches the bearer whenever the variable is
    set; the template is the only place it can come from."""
    text = HARNESS_TEMPLATE.read_text()
    assert "NOO_NODE_AGENT_TOKEN={{ noo_node_agent_token }}" in text, (
        "the harness env names a :8081 model URL but no agent token — every model call will 401"
    )
    # A fleet on the shared mechanism has an EMPTY per-node token; the
    # bearer then falls back to the cluster credential, which must be here
    # too or the call still 401s (host3, 2026-09-22, on a build with the
    # token line present).
    assert "NOO_CLUSTER_SECRET={{ noo_cluster_secret }}" in text, (
        "the harness env carries the per-node token but not the fleet credential it falls back to"
    )
