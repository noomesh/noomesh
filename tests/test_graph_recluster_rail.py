# SPDX-License-Identifier: AGPL-3.0-only
# Copyright 2026 PersonifAI LLC

"""The graph rails span three languages; nothing else compares them.

`entity_clusters` and `entity_cluster_members` had no writer at all until
`worker.graph.recluster` existed. The reader — `/api/v1/graph/clusters/
overview` — was mounted, contracted, tested and green the whole time, and
answered with an empty graph on every install created after the Rust port
. Every one of those checks described the SHAPE. Nothing
asserted a row could exist.

So the checks here are about the seam rather than the behaviour: the subject
is a string in two repositories, the verb is a row in two Rust tables, and
the container that runs the handler is chosen by a module name that does not
have to match the subject prefix — and here deliberately does not.

Textual, because the crates share no library and `cargo-docker.sh` mounts
only the crate being built, exactly as `test_job_type_declarations.py` and
`test_node_tier_ladder_parity.py` do.
"""

from __future__ import annotations

import pathlib
import re

REPO = pathlib.Path(__file__).resolve().parent.parent
PROVIDER = REPO / "gateway-rust/src/memory/provider.rs"
# The subject STRINGS live in one place since i195 refactor 6 (TrellionClient);
# the provider names them by constant. The parity below resolves the name.
SUBJECTS_RS = REPO / "gateway-rust/src/trellion_client.rs"


def _subject_consts() -> dict[str, str]:
    text = SUBJECTS_RS.read_text(encoding="utf-8")
    out = dict(re.findall(r'pub const ([A-Z_0-9]+): &str = "([^"]+)";', text))
    assert "GRAPH_RECLUSTER" in out, "subject constants not found in trellion_client.rs"
    return out
KNOWLEDGE = REPO / "gateway-rust/src/routes/knowledge.rs"
CLI_MAIN = REPO / "noo-cli/src/main.rs"
CLI_USAGE = REPO / "noo-cli/src/usage.rs"
WORKERS = REPO / "src/noomesh/workers"

SUBJECT = "worker.graph.recluster"


def test_the_gateway_and_the_worker_name_the_same_subject():
    """Rename either end and the other still compiles, still passes, still
    ships — and the route answers "worker timeout" forever."""
    rust = PROVIDER.read_text(encoding="utf-8")
    assert "const SUBJECT_GRAPH_RECLUSTER: &str = subjects::GRAPH_RECLUSTER;" in rust
    assert _subject_consts()["GRAPH_RECLUSTER"] == SUBJECT

    handlers = "\n".join(
        p.read_text(encoding="utf-8") for p in sorted(WORKERS.glob("*.py"))
    )
    assert f'@worker_handler("{SUBJECT}")' in handlers


def test_the_handler_lives_where_the_clusterer_can_be_imported():
    """The container that runs a handler is chosen by MODULE, and the module
    has to be the one whose image ships `trellion_intel`.

    `graph_clusterer` is one of the modules the Intelligent tier provides
    rather than the open tree.
    On Basic it is imported through `_intel.import_intel`, which raises, so
    `RAGIntegration._GRAPH_CLUSTERER_AVAILABLE` is False and `rag.clusterer`
    is None. Registering this subject on the base `ml` surface would put the
    handler on the one container that can never satisfy it — and the symptom
    would be a permanent "clusterer unavailable" on LICENSED installs too,
    because the intel package is not in the base noo-trellion image.
    """
    init = (WORKERS / "__init__.py").read_text(encoding="utf-8")
    intel = re.search(r"_ML_INTEL_MODULES = \(([^)]*)\)", init).group(1)
    intel_modules = {m.strip().strip('"') for m in intel.split(",") if m.strip()}

    owner = [
        p.stem
        for p in sorted(WORKERS.glob("*.py"))
        if f'@worker_handler("{SUBJECT}")' in p.read_text(encoding="utf-8")
    ]
    assert len(owner) == 1, f"expected one owner for {SUBJECT}, got {owner}"
    assert owner[0] in intel_modules, (
        f"{SUBJECT} is registered in {owner[0]}.py, which is not in "
        f"_ML_INTEL_MODULES {sorted(intel_modules)} — the clusterer it calls "
        "is not importable outside the trellion-intel image"
    )


def test_the_gateway_refuses_before_dispatch_rather_than_timing_out():
    """No subscriber on Basic means a 900s wait ending in "worker timeout" —
    a transport word for a licensing fact. The route has to say the real
    thing, and the add-on table is where that sentence lives."""
    src = KNOWLEDGE.read_text(encoding="utf-8")
    # The route is operation-backed: it starts the `graph.recluster` op, and the
    # work is `recluster_core`, which gates BEFORE it delegates. The op type
    # also refuses at start (routes/ops.rs precheck), so a Basic install is
    # told the licensing fact at once instead of being handed a doomed op.
    route = src[src.index("async fn graph_recluster("):]
    route = route[: route.index("\n}\n")]
    assert 'route_start(&state, &ctx, "graph.recluster"' in route
    fn = src[src.index("async fn recluster_core("):]
    fn = fn[: fn.index("\n}\n")]
    assert "intel_refusal(" in fn, "recluster_core no longer gates"
    # ...and before the delegation, not after it.
    assert fn.index("intel_refusal(") < fn.index("graph_recluster(&body)")
    ops = (REPO / "gateway-rust/src/routes/ops.rs").read_text(encoding="utf-8")
    pre = ops[ops.index("fn pre_recluster("):]
    pre = pre[: pre.index("\n}\n")]
    assert "intel_refusal(knowledge::RECLUSTER_WHAT)" in pre

    # The shared gate is what actually reads the add-on state, so it is the
    # thing that has to name it.
    gate = src[src.index("fn intel_refusal("):]
    gate = gate[: gate.index("\n}\n")]
    assert "addons::trellion_intel_enabled()" in gate
    assert "intel_refusal_msg()" in gate


def test_the_subject_gets_a_timeout_that_fits_the_work():
    """Re-clustering with labelling is minutes of work. The default worker
    timeout is 120s, so on the default this route could only ever fail."""
    rust = PROVIDER.read_text(encoding="utf-8")
    m = re.search(r"const RECLUSTER_TIMEOUT: std::time::Duration = "
                  r"std::time::Duration::from_secs\((\d+)\);", rust)
    assert m, "RECLUSTER_TIMEOUT is gone — the subject is back on the 120s default"
    assert int(m.group(1)) >= 600, "shorter than the work it is waiting for"
    assert "request_slow(SUBJECT_GRAPH_RECLUSTER" in rust


def test_the_route_and_the_verb_both_exist():
    assert '.route("/api/v1/graph/recluster", post(graph_recluster))' \
        in KNOWLEDGE.read_text(encoding="utf-8")
    assert '(&["graph", "recluster"], commands::graph_recluster),' \
        in CLI_MAIN.read_text(encoding="utf-8")
    assert '(&["graph", "recluster"],' in CLI_USAGE.read_text(encoding="utf-8")


def test_an_empty_cluster_overview_says_why_it_is_empty():
    """The bug was never a 404. It was HTTP 200 and two empty arrays, which
    is indistinguishable from a small graph — so the endpoint has to
    separate "nothing to cluster" from "never clustered"."""
    src = KNOWLEDGE.read_text(encoding="utf-8")
    # The core, not the route: `graph_clusters_overview` is a thin wrapper
    # since `routes/kiosk.rs` began projecting this route's own answer, and
    # slicing the wrapper found none of the reasons. Caught by this test.
    empty = src[src.index("pub(super) async fn graph_clusters_overview_for("):]
    empty = empty[: empty.index("\n}\n")]
    for reason in ('"no_clusters"', '"empty_graph"', '"requires_intelligent_tier"'):
        assert reason in empty, (
            f"the empty branch no longer reports {reason} — three different "
            "situations produce two empty arrays and only the reason tells "
            "them apart: nothing ingested, nothing clustered, or clustering "
            "not part of this tier"
        )
    # Counted through `entity_count_for`, which scopes the count to the caller's
    # audience and is the `SELECT COUNT(*) FROM entities` the
    # unrestricted path runs.
    assert "entity_count_for(" in empty, (
        "the two cases are told apart by whether entities exist; without that "
        "count the reason is a guess"
    )


# ── The Intelligent tier's graph surface ────────────────────

INTEL_ROUTES = {
    "/api/v1/graph/navigate": "navigate",
    "/api/v1/graph/traverse": "traverse",
    "/api/v1/graph/explain-path": "explain_path",
    "/api/v1/graph/semantic-search": "semantic_search",
    "/api/v1/graph/search-clusters": "search_clusters",
    "/api/v1/graph/classify-intent": "classify_intent",
    "/api/v1/graph/extract-relations": "extract_relations",
    "/api/v1/graph/recall-traversals": "recall_traversals",
}


def test_every_intel_graph_route_is_mounted_and_has_a_subject():
    """Route, capability key and worker handler are three strings in three
    languages. The tools these serve spent their whole existence 404ing
    because two of those three were never compared."""
    rust = KNOWLEDGE.read_text(encoding="utf-8")
    provider = PROVIDER.read_text(encoding="utf-8")
    consts = _subject_consts()
    handlers = "\n".join(
        p.read_text(encoding="utf-8") for p in sorted(WORKERS.glob("*.py"))
    )
    for path, op in INTEL_ROUTES.items():
        assert f'.route("{path}"' in rust, f"{path} is not mounted"
        m = re.search(rf'\("{op}", subjects::([A-Z_0-9]+)\)', provider)
        assert m, f"capability `{op}` has no subject in SUBJECT_GRAPH_INTEL"
        assert consts.get(m.group(1)) == f"worker.graph.{op}", (
            f"capability `{op}` names {m.group(1)}, which is not worker.graph.{op}"
        )
        assert f'@worker_handler("worker.graph.{op}")' in handlers, (
            f"worker.graph.{op} has no handler — the route would time out"
        )


def test_no_intel_graph_route_can_skip_the_gate():
    """The gate is the one thing that must not vary between these eight.

    A route that forgot it would look like a worker timeout, and only on
    unlicensed installs — the configuration least likely to be the one
    anybody is testing on. So they all go through `intel_graph`, which gates
    before it delegates, and none of them may call the provider directly.
    """
    rust = KNOWLEDGE.read_text(encoding="utf-8")
    # navigate, traverse and extract_relations are operation-backed (gateway
    # ops.rs): their route handler starts the op and the SHARED body is
    # `<op>_core`, which is what goes through the gated helper. Every other
    # route still calls the helper from its own handler.
    core_ops = {"navigate", "traverse", "extract_relations"}
    for op in INTEL_ROUTES.values():
        if op in core_ops:
            fn = rust[rust.index(f"async fn {op}_core("):]
            fn = fn[: fn.index("\n}\n")]
            assert f'intel_graph(state, ctx, "{op}"' in fn, (
                f"{op}_core does not go through the gated helper"
            )
            handler = rust[rust.index(f"async fn graph_{op}("):]
            handler = handler[: handler.index("\n}\n")]
            assert "route_start(" in handler and "graph_intel(" not in handler
            continue
        fn = rust[rust.index(f"async fn graph_{op}("):]
        fn = fn[: fn.index("\n}\n")]
        assert f'intel_graph(&state, ctx, "{op}"' in fn, (
            f"graph_{op} does not go through the gated helper"
        )
        assert "graph_intel(" not in fn, (
            f"graph_{op} reaches the provider directly, bypassing the gate"
        )
    # ...and the helper itself gates before delegating.
    helper = rust[rust.index("async fn intel_graph("):]
    helper = helper[: helper.index("\n}\n")]
    assert helper.index("intel_refusal") < helper.index("graph_intel(")


def test_the_whole_worker_graph_family_is_intel_tier():
    """A prefix, not a list. The next graph capability is Intelligent by
    default — the safe direction — and one that earns an open baseline has
    to be taken out deliberately rather than by omission."""
    addons = (REPO / "gateway-rust/src/addons.rs").read_text(encoding="utf-8")
    fn = addons[addons.index("pub fn is_trellion_intel_subject"):]
    fn = fn[: fn.index("\n}\n")]
    assert 'subject.starts_with("worker.graph.")' in fn


# ── The single-flight guard (the race the first version shipped) ──────────

async def test_two_concurrent_recluster_requests_run_the_clusterer_once():
    """The first version checked `lock.locked()` and then did `async with`.

    `worker_pool._handle_concurrent` dispatches every message as its own
    task, so two requests arriving before either acquired both saw "not
    locked", both fell through, and the second BLOCKED on the lock and then
    ran a complete second clustering pass — two generations writing the same
    two tables, which is what the guard exists to prevent and what its own
    docstring claimed was impossible.

    This is the shape that matters in practice: the gateway gives up at 900s
    while the worker keeps going, so a caller that times out mid-run retries.
    """
    import asyncio
    import noomesh.workers.graph as g

    runs = 0

    class _Clusterer:
        async def run_clustering(self, **_):
            nonlocal runs
            runs += 1
            await asyncio.sleep(0.05)          # long enough for the second call
            return {"clusters": 3, "nodes": 10, "edges": 20}

    class _Rag:
        clusterer = _Clusterer()

    g._recluster_running = False
    g._recluster_started_at = None
    real = g._get_rag
    g._get_rag = lambda: _Rag()
    try:
        first, second = await asyncio.gather(
            g._graph_recluster({}), g._graph_recluster({})
        )
    finally:
        g._get_rag = real
        g._recluster_running = False
        g._recluster_started_at = None

    assert runs == 1, f"the clusterer ran {runs} times; the guard is not single-flight"
    statuses = sorted(r.get("status") for r in (first, second))
    assert statuses == ["already_running", "ok"], statuses

    refused = first if first.get("status") == "already_running" else second
    # And it reports a real elapsed time, not 0.0 — the timestamp used to be
    # cleared before the lock was released, so a concurrent caller saw
    # "in flight" with `started_at: null` and printed "0s elapsed" for a
    # fourteen-minute run.
    assert refused["started_at"] is not None
    assert refused["elapsed_secs"] is not None


async def test_the_flag_is_released_when_the_clusterer_raises():
    """A failed run must not wedge the subject permanently."""
    import noomesh.workers.graph as g

    class _Boom:
        async def run_clustering(self, **_):
            raise RuntimeError("leiden exploded")

    class _Rag:
        clusterer = _Boom()

    g._recluster_running = False
    real = g._get_rag
    g._get_rag = lambda: _Rag()
    try:
        out = await g._graph_recluster({})
    finally:
        g._get_rag = real
    assert "error" in out
    assert g._recluster_running is False, "a failed run left the subject locked out"
    assert g._recluster_started_at is None
