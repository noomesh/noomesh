# SPDX-License-Identifier: AGPL-3.0-only
# Copyright 2026 PersonifAI LLC

"""CLI entrypoint: ``python -m noo_eval <cmd>``.

Commands:
  topology [--out PATH]                     REAL topology report from `noo cluster status`
  demo     [--out PATH]                     render the SYNTHETIC seeded demo report
  run      SCENARIO --gateway URL [opts]    drive a live run and render a report

Reports are written under eval/reports/ by default (kept local, git-ignored).

Live run options:
  --gateway URL     gateway base URL (e.g. https://host3.ts.net:8080)
  --prom URL        Prometheus base URL for the security panel (optional)
  --token TOKEN     service bearer (or set NOO_EVAL_TOKEN)
  NOO_EVAL_IDENTITY_KEY   identity-scoped service key for the window / isolation probes (env only)
  --out PATH        report output path (default: eval/out/<scenario>.html)
  --body-only       emit Artifact-ready body (no <html>/<head>) instead of a full doc
  --json PATH       also dump the raw RunResult JSON
  --fixture         harness-compare only: run against the built-in FAKE gateway
                    (no cluster, no writes; every number is synthetic)

A scenario with a ``harness_compare:`` block runs one task set under each
harness kind on one node (see noo_eval.harness_compare). It CHANGES that
node's harness placement while it runs and puts it back at the end. Its
report gets a JSON twin next to the HTML (same path, ``.json``).
"""
from __future__ import annotations

import argparse
import asyncio
import os

import httpx
import sys
import time
from pathlib import Path

from . import collector, driver, harness_compare, harness_matrix, identity, report
from .demo import build_demo
from .harness_fake import FakeClock, FakeHarnessGateway, fixture_facts
from .faults import NodeKillInjector, schedule_faults
from .scenario import Scenario
from .schema import HarnessMatrix, RunResult, SecurityPosture


def _slug(s: str) -> str:
    return "".join(c if c.isalnum() else "-" for c in s.lower()).strip("-")[:60]


def _resolve_verify(ca: str):
    """TLS verification for httpx: a CA-bundle path (chain-verified) when we can
    find the cluster CA, else True (system trust). We never disable verification
    — the gateway cert chains to the cluster CA and its SAN covers localhost, so
    a CA path gives full chain+hostname verification (the CRIT-3-safe pattern).
    """
    candidates = [
        ca,
        os.getenv("NOO_EVAL_CA", ""),
        os.getenv("NOO_TLS_CA", ""),
        "/etc/noo/pki/ca.crt",                       # where `noo` installs the cluster CA
        os.path.expanduser("~/pai-assistant/pki/ca.crt"),
        os.path.join(os.getenv("NOO_PKI_DIR", ""), "ca.crt") if os.getenv("NOO_PKI_DIR") else "",
    ]
    for c in candidates:
        if c and os.path.isfile(c):
            return c
    return True


async def _compare_run(args, scn: Scenario) -> RunResult:
    """A harness-compare scenario: live against ``--gateway``, or against the
    fake gateway with ``--fixture``."""
    spec = scn.harness_compare
    if args.fixture:
        clock = FakeClock()
        fake = FakeHarnessGateway(node=spec.node, clock=clock)
        async with fake.client() as c:
            hc = await harness_compare.run_compare(spec, c, clock=clock, sleep=clock.sleep)
        return RunResult(scenario=f"SYNTHETIC fixture — {scn.name}", axes=["harness_kind"],
                         started_at=args.started_at or "", gateway="fake gateway (--fixture)",
                         harness_compare=hc,
                         notes=["--fixture: canned answers from noo_eval/harness_fake.py; nothing was placed."])
    token = args.token or os.getenv("NOO_EVAL_TOKEN", "")
    verify = _resolve_verify(getattr(args, "ca", ""))
    task_token = os.getenv(spec.task_token_env, "") if spec.task_token_env else ""
    notes = []
    if spec.task_token_env and not task_token:
        notes.append(f"{spec.task_token_env} is unset: tasks and usage ran under the --token credential")

    def client(tok: str) -> httpx.AsyncClient:
        auth = {"Authorization": f"Bearer {tok}"} if tok else {}
        return httpx.AsyncClient(base_url=args.gateway, headers=auth, timeout=30.0, verify=verify)

    print(f"[noo-eval] {scn.name}: harness-compare on {spec.node} → {args.gateway} "
          f"(this CHANGES {spec.node}'s harness placement while it runs, and restores it)")
    async with client(token) as ops:
        if task_token:
            async with client(task_token) as tc:
                hc = await harness_compare.run_compare(spec, ops, tc)
        else:
            hc = await harness_compare.run_compare(spec, ops)
    return RunResult(scenario=scn.name, axes=["harness_kind"], started_at=args.started_at or "",
                     gateway=args.gateway, harness_compare=hc, notes=notes)


async def _matrix_run(args, scn: Scenario) -> RunResult:
    """A harness-matrix scenario: every (node, model variant) in turn, live
    against ``--gateway`` or against one fake gateway per node (``--fixture``).
    Rows are appended to ``--history`` (unless it is ``-``) and the report's
    trend reads it back."""
    spec = scn.harness_matrix
    started = args.started_at or time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
    if args.fixture:
        hm = HarnessMatrix(kinds=list(spec.kinds))
        clock = FakeClock()
        for cell in spec.cells:
            one = spec.model_copy(update={"cells": [cell]})
            fake = FakeHarnessGateway(node=cell.node, clock=clock, facts=fixture_facts(cell.node))
            async with fake.client() as c:
                part = await harness_matrix.run_matrix(one, c, clock=clock, sleep=clock.sleep)
            hm.cells.extend(part.cells)
        name, gateway = f"SYNTHETIC fixture — {scn.name}", "fake gateway (--fixture)"
        notes = ["--fixture: canned nodes and answers from noo_eval/harness_fake.py; nothing was placed."]
    else:
        why = harness_matrix.preflight(spec, allow_placement_changes=args.allow_placement_changes)
        if why:
            print(f"[noo-eval] not started: {why}")
            return RunResult(scenario=scn.name, axes=["harness_kind", "node", "model"], started_at=started,
                             gateway=args.gateway, harness_matrix=HarnessMatrix(kinds=list(spec.kinds), refused=why))
        token = args.token or os.getenv("NOO_EVAL_TOKEN", "")
        verify = _resolve_verify(getattr(args, "ca", ""))
        task_token = os.getenv(spec.task_token_env, "") if spec.task_token_env else ""
        notes = []
        if spec.task_token_env and not task_token:
            notes.append(f"{spec.task_token_env} is unset: tasks and usage ran under the --token credential")

        def client(tok: str) -> httpx.AsyncClient:
            auth = {"Authorization": f"Bearer {tok}"} if tok else {}
            return httpx.AsyncClient(base_url=args.gateway, headers=auth, timeout=30.0, verify=verify)

        print(f"[noo-eval] {scn.name}: harness matrix on {', '.join(c.node for c in spec.cells)} → {args.gateway} "
              "(this CHANGES each node's harness placement, and a variant's model, while it runs, and restores them)")
        async with client(token) as ops:
            if task_token:
                async with client(task_token) as tc:
                    hm = await harness_matrix.run_matrix(spec, ops, tc)
            else:
                hm = await harness_matrix.run_matrix(spec, ops)
        name, gateway = scn.name, args.gateway
    if args.history != "-":
        harness_matrix.append_history(args.history, harness_matrix.rows(hm, run_id=started, scenario=name))
        hm.history = harness_matrix.read_history(args.history)
        notes.append(f"history: {args.history}")
    return RunResult(scenario=name, axes=["harness_kind", "node", "model"], started_at=started,
                     gateway=gateway, harness_matrix=hm, notes=notes)


async def _live_run(args) -> RunResult:
    scn = Scenario.load(args.scenario)
    if scn.harness_matrix is not None:
        if not args.fixture and not args.gateway:
            raise SystemExit("noo_eval run: --gateway URL is required (or --fixture for a dry run)")
        return await _matrix_run(args, scn)
    if scn.harness_compare is not None:
        if not args.fixture and not args.gateway:
            raise SystemExit("noo_eval run: --gateway URL is required (or --fixture for a dry run)")
        return await _compare_run(args, scn)
    if args.fixture:
        raise SystemExit("noo_eval run: --fixture applies to harness-compare and harness-matrix scenarios only")
    if not args.gateway:
        raise SystemExit("noo_eval run: --gateway URL is required")
    token = args.token or os.getenv("NOO_EVAL_TOKEN", "")
    print(f"[noo-eval] {scn.name}: {scn.duration_s:.0f}s @ concurrency {scn.concurrency} → {args.gateway}")

    topology = await collector.collect_topology(args.gateway, token)
    if not topology:
        # Gateway node list needs a bearer; fall back to the CLI (its own auth).
        topology = await collector.collect_topology_cli()
    print(f"[noo-eval] topology: {len(topology)} node(s), {sum(n.online for n in topology)} online")

    verify = _resolve_verify(getattr(args, "ca", ""))
    t0 = time.monotonic()
    injector = NodeKillInjector(args.gateway, token)  # dry-run unless stop/start wired
    if scn.workloads:
        load_task = asyncio.create_task(driver.run_load(scn, args.gateway, token, verify=verify))
        fault_task = asyncio.create_task(schedule_faults(injector, scn.faults, t0))
        records, faults = await asyncio.gather(load_task, fault_task)
    else:
        records, faults = [], []   # a probe-only scenario drives no load

    security = await collector.collect_security(args.prom) if args.prom else SecurityPosture()

    result = RunResult(
        scenario=scn.name, axes=scn.axes, started_at=args.started_at or "",
        duration_s=scn.duration_s, gateway=args.gateway,
        topology=topology, requests=records, faults=faults, security=security,
        notes=[f"{len(records)} requests over {scn.duration_s:.0f}s"],
    )
    # Identity-plane probes (windows, foreign account) and the cross-account
    # probes both mint through the identity exchange with ONE key from the
    # environment. Absent key → the probes are reported as not run, never as
    # isolated.
    key_env = scn.identity.key_env if scn.identity else "NOO_EVAL_IDENTITY_KEY"
    ikey = os.getenv(key_env, "")
    if scn.identity or scn.isolation_probes:
        if not ikey:
            result.notes.append(f"probes NOT RUN: set {key_env} to an identity-scoped service key")
        else:
            async with httpx.AsyncClient(base_url=args.gateway, timeout=30.0, verify=verify) as client:
                if scn.identity:
                    rep = await identity.run_identity(client, ikey, scn.identity.owner,
                                                      scn.identity.windows, scn.identity.foreign)
                    result.isolation_tests.extend(rep.tests)
                    result.notes.extend(rep.notes)
                if scn.isolation_probes:
                    rep = await identity.run_cross_account(client, ikey, [p.id for p in scn.personas])
                    result.isolation_tests.extend(rep.tests)
                    result.notes.extend(rep.notes)
    return result


async def _topology_run(args) -> RunResult:
    """Render a REAL report from live cluster topology — no synthetic data, no
    load driven. Node list comes from `noo cluster status`; security counters
    from Prometheus if --prom is given.
    """
    topology = await collector.collect_topology_cli()
    print(f"[noo-eval] real topology: {len(topology)} node(s), "
          f"{sum(n.online for n in topology)} online")
    security = await collector.collect_security(args.prom) if args.prom else SecurityPosture()
    online = [n.node_id for n in topology if n.online]
    return RunResult(
        scenario="Live cluster topology",
        axes=["node"],
        gateway="noo cluster status",
        topology=topology,
        security=security,
        notes=[
            "REAL data — node list from `noo cluster status --json`.",
            f"{len(online)} node(s) online: {', '.join(online) or 'none'}.",
            "No load driven and no faults injected in this snapshot; run "
            "`noo_eval run <scenario>` to add latency/throughput/failover metrics.",
            "Locations aren't tracked by the cluster yet — all nodes tagged 'tailnet'.",
        ],
    )


def main(argv=None) -> int:
    p = argparse.ArgumentParser(prog="noo_eval")
    sub = p.add_subparsers(dest="cmd", required=True)

    pt = sub.add_parser("topology", help="real topology report from `noo cluster status`")
    pt.add_argument("--out", default="eval/reports/topology.html")
    pt.add_argument("--prom", default="")
    pt.add_argument("--json", default="")

    pd = sub.add_parser("demo", help="render the SYNTHETIC seeded demo report")
    pd.add_argument("--out", default="eval/reports/demo-SYNTHETIC.html")
    pd.add_argument("--body-only", action="store_true")
    pd.add_argument("--json", default="")

    pr = sub.add_parser("run", help="drive a live evaluation run")
    pr.add_argument("scenario")
    pr.add_argument("--gateway", default="")
    pr.add_argument("--fixture", action="store_true",
                    help="harness-compare / harness-matrix: run against the built-in fake gateway (synthetic)")
    pr.add_argument("--allow-placement-changes", action="store_true",
                    help="harness-matrix: confirm this window is yours, so a scenario's model variants "
                         "may take a node's chat model from its live users for the run")
    pr.add_argument("--history", default="eval/reports/harness-matrix-history.jsonl",
                    help="harness-matrix: JSON-lines file each run appends its rows to, and the "
                         "report's trend reads ('-' keeps none)")
    pr.add_argument("--prom", default="")
    pr.add_argument("--token", default="")
    pr.add_argument("--started-at", default="")
    pr.add_argument("--ca", default="",
                    help="cluster CA bundle for TLS verification (default: auto-detect "
                         "NOO_TLS_CA / pki/ca.crt). Verification is never disabled.")
    pr.add_argument("--out", default="")
    pr.add_argument("--body-only", action="store_true")
    pr.add_argument("--json", default="")

    args = p.parse_args(argv)

    if args.cmd == "demo":
        result = build_demo()
    elif args.cmd == "topology":
        result = asyncio.run(_topology_run(args))
    else:
        result = asyncio.run(_live_run(args))
        if not args.out:
            args.out = f"eval/reports/{_slug(result.scenario)}.html"

    out = report.write_report(result, args.out, standalone=not getattr(args, "body_only", False))
    print(f"[noo-eval] report → {out}")
    if result.harness_compare is not None:
        twin = report.write_compare_json(result, Path(out).with_suffix(".json"))
        print(f"[noo-eval] report json → {twin}")
    if result.harness_matrix is not None:
        twin = Path(out).with_suffix(".json")
        twin.write_text(result.harness_matrix.model_dump_json(indent=2, exclude={"history"}), encoding="utf-8")
        print(f"[noo-eval] report json → {twin}")
    if getattr(args, "json", ""):
        Path(args.json).parent.mkdir(parents=True, exist_ok=True)
        Path(args.json).write_text(result.model_dump_json(indent=2))
        print(f"[noo-eval] raw json → {args.json}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
