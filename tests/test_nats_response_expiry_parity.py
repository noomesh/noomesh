# SPDX-License-Identifier: AGPL-3.0-only
# Copyright 2026 PersonifAI LLC

"""The NATS reply window outlasts the longest request the gateway waits for.

`noo-cli/src/commands/nats_users.rs` grants workers, add-ons and nodes
`allow_responses: { max: 1, expires: RESPONSE_EXPIRES }`. A reply published
after that window is refused by nats-server as a permissions violation, so the
caller sees "unreachable" for work that finished. A bare `allow_responses: true`
means TWO minutes, and every graph recluster on host8 ran into it (2026-10-03
and 10-04).

The window must exceed every synchronous NATS request timeout the gateway uses
for those principals. The two long ones are `RECLUSTER_TIMEOUT` (memory
provider) and the harness turn default (`NOO_HARNESS_TURN_TIMEOUT_SECS`). The
crates share no library, so this reads both sources.
"""
import re
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
GRANTS = ROOT / "noo-cli/src/commands/nats_users.rs"
PROVIDER = ROOT / "gateway-rust/src/memory/provider.rs"
DISPATCH = ROOT / "gateway-rust/src/coordinator/dispatch.rs"


def _secs(duration: str) -> int:
    m = re.fullmatch(r"(\d+)([smh])", duration)
    assert m, f"unparseable NATS duration {duration!r}"
    return int(m.group(1)) * {"s": 1, "m": 60, "h": 3600}[m.group(2)]


def _window() -> int:
    m = re.search(r'pub\(crate\) const RESPONSE_EXPIRES: &str = "([^"]+)";', GRANTS.read_text())
    assert m, "RESPONSE_EXPIRES not found in nats_users.rs"
    return _secs(m.group(1))


def _recluster_timeout() -> int:
    m = re.search(r"const RECLUSTER_TIMEOUT: std::time::Duration = std::time::Duration::from_secs\((\d+)\)",
                  PROVIDER.read_text())
    assert m, "RECLUSTER_TIMEOUT not found in memory/provider.rs"
    return int(m.group(1))


def _harness_turn_default() -> int:
    m = re.search(r'"NOO_HARNESS_TURN_TIMEOUT_SECS"\)\.ok\(\)\.and_then\(\|v\| v\.parse\(\)\.ok\(\)\)\.unwrap_or\((\d+)\)',
                  DISPATCH.read_text())
    assert m, "the NOO_HARNESS_TURN_TIMEOUT_SECS default not found in coordinator/dispatch.rs"
    return int(m.group(1))


def test_every_grant_carries_an_explicit_reply_window():
    text = GRANTS.read_text()
    # The rendered grant lines are the `{ind}allow_responses: …` format strings.
    rendered = re.findall(r"\{ind\}allow_responses: ([^\n]*)", text)
    assert len(rendered) >= 2, "expected the worker and node grants"
    for line in rendered:
        assert "RESPONSE_EXPIRES" in line and not line.startswith("true"), (
            f"grant renders `allow_responses: {line}` — a bare `true` is nats-server's 2-minute window"
        )


def test_the_reply_window_outlasts_the_longest_request():
    window = _window()
    for name, secs in (("RECLUSTER_TIMEOUT", _recluster_timeout()),
                       ("NOO_HARNESS_TURN_TIMEOUT_SECS default", _harness_turn_default())):
        assert window > secs, (
            f"{name} is {secs}s but the NATS reply window is {window}s: a reply after the window "
            f"is refused and the gateway reports a finished job as unreachable. Raise RESPONSE_EXPIRES."
        )
