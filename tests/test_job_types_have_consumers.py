# SPDX-License-Identifier: AGPL-3.0-only
# Copyright 2026 PersonifAI LLC

"""Every job type the code can enqueue has a consumer that runs it.

`test_job_type_declarations.py` keeps the three DECLARATIONS of the job-type
table in agreement (Rust table, Go executor, Python enum). This module checks
the other direction: the PRODUCERS. A producer that enqueues a type nobody
consumes leaves a job queued forever: on 2026-10-10 the live controller held
`background_embed` jobs from a heartbeat action going back days.

Producers scanned, textually (the sources span three languages):

  * gateway-rust: every `submit_job_to_redis(<redis>, "<type>", ...)` call
    with a literal type (internal producers: heartbeat actions, autonomy
    evaluators, the inference route);
  * noo-cli: every `json!({...})` job body (`"type"` + `"payload"`) in a
    file that posts to `/api/jobs/submit`;
  * Python: `submit_job("<type>"` literals, and `Action(type="submit_job",
    config={"type": ...})` in the default-locations spec.

Routes that take the type from a caller are not producers here: the route
rejects an unexecutable type with a 400 (`job_types::unknown_type_error`).
"""
from __future__ import annotations

import re
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parents[1]
RUST_TABLE = REPO / "gateway-rust" / "src" / "job_types.rs"
GO_EXECUTOR = REPO / "node-agent-go" / "internal" / "jobs" / "executor.go"
DEFAULT_LOCATIONS = REPO / "src" / "noomesh" / "cluster" / "default_locations.py"

# Known gaps, each with the place it is tracked. A producer listed here is
# NOT live; the test below asserts that stays true.
KNOWN_UNCONSUMED = {
    # default_locations.py `gnn_reclustering`: a spec entry with no Rust
    # location (the Python autonomy loop does not run), disabled by default.
    "gnn_recluster",
}


def _node_types() -> set[str]:
    body = RUST_TABLE.read_text().split("pub const JOB_TYPES", 1)[1].split("];", 1)[0]
    found = set(re.findall(r'\("([a-z_]+)",\s*Executor::Node\)', body))
    assert found, "could not parse JOB_TYPES"
    return found


def _retired_types() -> set[str]:
    src = RUST_TABLE.read_text()
    body = src.split("pub const RETIRED_JOB_TYPES", 1)[1].split("];", 1)[0]
    return set(re.findall(r'\(\s*"([a-z_]+)",', body))


def _go_cases() -> set[str]:
    src = GO_EXECUTOR.read_text()
    body = src.split("switch job.Type {", 1)[1].split("\n\tdefault:", 1)[0]
    return set(re.findall(r'case "([a-z_]+)":', body))


def _json_blocks(src: str):
    """Yield the text of every `json!({ ... })` block, braces matched."""
    for m in re.finditer(r"json!\(\{", src):
        depth, i = 0, m.end() - 1
        while i < len(src):
            c = src[i]
            if c == "{":
                depth += 1
            elif c == "}":
                depth -= 1
                if depth == 0:
                    yield src[m.start() : i + 1]
                    break
            i += 1


def _rust_gateway_producers() -> dict[str, list[str]]:
    out: dict[str, list[str]] = {}
    pat = re.compile(r'submit_job_to_redis\(\s*[^,()]+,\s*"([a-z_]+)"')
    for path in (REPO / "gateway-rust" / "src").rglob("*.rs"):
        for t in pat.findall(path.read_text()):
            out.setdefault(t, []).append(str(path.relative_to(REPO)))
    return out


def _cli_producers() -> dict[str, list[str]]:
    out: dict[str, list[str]] = {}
    for path in (REPO / "noo-cli" / "src").rglob("*.rs"):
        src = path.read_text()
        if "/api/jobs/submit" not in src:
            continue
        for block in _json_blocks(src):
            if '"payload"' not in block:
                continue
            m = re.search(r'"type":\s*"([a-z_]+)"', block)
            if m:
                out.setdefault(m.group(1), []).append(str(path.relative_to(REPO)))
    return out


def _python_producers() -> dict[str, list[str]]:
    out: dict[str, list[str]] = {}
    for path in (REPO / "src").rglob("*.py"):
        src = path.read_text()
        for t in re.findall(r'submit_job\(\s*"([a-z_]+)"', src):
            out.setdefault(t, []).append(str(path.relative_to(REPO)))
    spec = DEFAULT_LOCATIONS.read_text()
    for t in re.findall(r'Action\(type="submit_job",\s*config=\{\s*"type":\s*"([a-z_]+)"', spec):
        out.setdefault(t, []).append(str(DEFAULT_LOCATIONS.relative_to(REPO)))
    return out


def test_the_scans_find_the_producers_they_claim_to_scan():
    # A regex that silently matches nothing would pass every check below.
    gw, cli, py = _rust_gateway_producers(), _cli_producers(), _python_producers()
    assert {"inference", "background_graph"} <= set(gw), gw
    assert {"inference", "model_file", "fetch_bundle"} <= set(cli), cli
    assert "background_graph" in py, py


@pytest.mark.parametrize(
    "source,scan",
    [("gateway-rust", _rust_gateway_producers), ("noo-cli", _cli_producers), ("python", _python_producers)],
)
def test_every_enqueued_type_has_a_node_consumer(source, scan):
    node, go = _node_types(), _go_cases()
    bad = {
        t: where
        for t, where in scan().items()
        if t not in KNOWN_UNCONSUMED and not (t in node and t in go)
    }
    assert not bad, (
        f"{source} enqueues job types no node-agent executes (not a Node row in "
        f"job_types.rs AND a case in executor.go): {bad}"
    )


def test_retired_types_are_gone_everywhere():
    retired = _retired_types()
    assert "background_embed" in retired
    from noomesh.cluster.scheduler import JobType

    assert not (retired & _node_types())
    assert not (retired & _go_cases())
    assert not (retired & {t.value for t in JobType})
    producers = {**_rust_gateway_producers(), **_cli_producers(), **_python_producers()}
    assert not (retired & set(producers)), {t: producers[t] for t in retired & set(producers)}


def test_known_unconsumed_producers_stay_inert():
    # gnn_recluster's only producer is a disabled spec entry in a loop that
    # does not run. If either changes, it stops being a known gap and becomes
    # a live producer of jobs nobody consumes.
    spec = DEFAULT_LOCATIONS.read_text()
    block = spec.split('name="gnn_reclustering"', 1)[1].split("MonitorLocation(", 1)[0]
    assert "enabled=False" in block
    for t in KNOWN_UNCONSUMED:
        assert t not in _rust_gateway_producers() and t not in _cli_producers()
