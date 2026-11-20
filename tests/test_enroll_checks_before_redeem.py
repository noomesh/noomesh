# SPDX-License-Identifier: AGPL-3.0-only
# Copyright 2026 PersonifAI LLC

"""`noo enroll` checks before it spends the single-use token.

A run that cannot finish spends nothing: sudo (a terminal, root or
`--root-ok`), free disk, and a controller that answers are checked BEFORE the
token is redeemed. Before this, host prep's plain `sudo` failed with no
terminal AFTER the redeem ("the enrollment is registered, but the node has no
agent yet"), and the owner needed a fresh token.

This guard reads the enroll flow's own body (comments and `#[cfg(test)]`
removed, `fn_body` brace matching) and checks the order: the host checks,
then the controller check, then the one redeem call. The Rust tests in
enroll.rs prove the refusals with a fake redeemer that is never called.
"""

from __future__ import annotations

from pathlib import Path

from tests import _rust_src as rs

ROOT = Path(__file__).resolve().parents[1]
ENROLL = ROOT / "noo-cli" / "src" / "commands" / "enroll.rs"

HOST = "host_preflight(&needs, root_ok, probes)"
CONTROLLER = "controller_preflight(&noo_url, probes)"
REDEEM = 'redeem(&agent, &format!("{noo_url}/api/cluster/bootstrap"), &body)'


def _flow() -> str:
    return rs.fn_body(rs.own_code(ENROLL.read_text(encoding="utf-8")), "fn enroll_with(")


def order_problems(body: str) -> list[str]:
    """What is wrong with the order in an enroll flow body; [] when right."""
    out = []
    at = {k: body.find(k) for k in (HOST, CONTROLLER, REDEEM)}
    for k, i in at.items():
        if i < 0:
            out.append(f"missing: {k}")
        elif body.count(k) != 1:
            out.append(f"more than once: {k}")
    if out:
        return out
    if not at[HOST] < at[CONTROLLER] < at[REDEEM]:
        out.append(f"order: host {at[HOST]}, controller {at[CONTROLLER]}, redeem {at[REDEEM]}")
    return out


def test_the_checks_come_before_the_one_redeem():
    body = _flow()
    assert order_problems(body) == [], order_problems(body)
    # The token's only way out is the injected redeemer.
    assert ".post(format!(\"{noo_url}/api/cluster/bootstrap\"))" not in body
    # Each check's refusal returns before anything else runs.
    for call in (HOST, CONTROLLER):
        line = next(l for l in body.splitlines() if call in l)
        assert line.strip() == f"if let Err(refusal) = {call} {{", line


def test_the_live_enroll_wires_the_real_probes_and_the_real_post():
    code = rs.own_code(ENROLL.read_text(encoding="utf-8"))
    entry = rs.fn_body(code, "pub fn enroll(")
    assert "enroll_with(g, args, &Probes::live(), &mut redeem)" in entry, entry
    assert "agent.post(url).send_json(body)" in entry, entry


def test_the_order_check_is_not_vacuous():
    """A redeem moved before the checks, or a check removed, is caught."""
    good = f"fn enroll_with() {{\n    if let Err(refusal) = {HOST} {{ }}\n    if let Err(refusal) = {CONTROLLER} {{ }}\n    match {REDEEM} {{ }}\n}}"
    assert order_problems(good) == []
    moved = f"fn enroll_with() {{\n    match {REDEEM} {{ }}\n    if let Err(refusal) = {HOST} {{ }}\n    if let Err(refusal) = {CONTROLLER} {{ }}\n}}"
    assert order_problems(moved)
    removed = good.replace(f"if let Err(refusal) = {HOST} {{ }}", "")
    assert order_problems(removed) == [f"missing: {HOST}"]
