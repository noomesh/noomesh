# SPDX-License-Identifier: AGPL-3.0-only
# Copyright 2026 PersonifAI LLC

"""The gateway's Loki link and Loki's own contract, pinned across files.

Fleet logging phase 0 (2026-09-28). Four declarations, none of which can see
the others:

* `gateway-rust/src/**` reads `NOO_LOKI_URL` (`config::env_or_yaml`); compose
  handed the gateway `LOKI_URL` for a year, so `/api/logs/status` answered
  "not configured" while the container ran;
* `docker-compose.cluster.yml` — the gateway's env, the loki service's
  command (`-config.expand-env=true`, the mTLS config), its mounts (ONE
  config file), no `ports:`, and `NOO_LOKI_RETENTION`;
* `monitoring/loki/loki-config-tls.yml` — `client_auth_type`,
  `retention_period` and `reject_old_samples_max_age` as ONE expression over
  `NOO_LOKI_RETENTION` (a node that buffered logs offline must be able to
  replay them; the cap tracks retention);
* `docs/reference/env.md` names the knob.

Planted: `NOO_LOKI_URL` renamed in compose → the first test fails; the two
retention keys made to differ → the retention test fails.
"""

from __future__ import annotations

import re
from pathlib import Path

import pytest

from tests._compose_projection import BASE, env_of, full_projection, load_raw, untag
from tests.source_scan import executable_source

ROOT = Path(__file__).resolve().parents[1]
GATEWAY_SRC = ROOT / "gateway-rust" / "src"
LOKI_CFG = ROOT / "monitoring" / "loki" / "loki-config-tls.yml"
ENV_MD = ROOT / "docs" / "reference" / "env.md"


@pytest.fixture(scope="module")
def projection() -> dict:
    return full_projection()


def _gateway_loki_env_names() -> set[str]:
    """Every `NOO_LOKI*` name the gateway reads from its environment, found
    as a string literal handed to an env reader (env_or_yaml, std::env::var)."""
    names: set[str] = set()
    for rs in GATEWAY_SRC.rglob("*.rs"):
        src = executable_source(rs)
        for m in re.finditer(r'(?:env_or_yaml|env_or_yaml_u64|std::env::var|env::var)\(\s*"(NOO_LOKI[A-Z0-9_]*)"', src):
            names.add(m.group(1))
    assert names, "found no NOO_LOKI* reader in gateway-rust — the grep is stale, not the gateway"
    return names


def test_every_loki_env_the_gateway_reads_is_set_on_its_service(projection):
    env = env_of(projection["services"]["gateway"])
    missing = sorted(n for n in _gateway_loki_env_names() if n not in env)
    assert not missing, (
        f"the gateway reads {missing} but compose does not set them on the gateway service — "
        "`noo logs status` answers 'not configured' whatever runs"
    )
    assert env["NOO_LOKI_URL"].startswith("${NOO_LOKI_URL:-https://loki:3100}"), env["NOO_LOKI_URL"]
    assert "LOKI_URL" not in env, "the old, unread name is back on the gateway (the reader is NOO_LOKI_URL)"


# The modules allowed to read the name. Named, not counted: a reader added
# elsewhere is the fork this exists to catch (the model-cache rule), while
# these two are the query side (admin.rs) and the ingest side (#525).
LOKI_URL_READERS = [
    "gateway-rust/src/routes/admin.rs",        # status/query/errors/tail
    "gateway-rust/src/routes/grafana_ds.rs",   # Grafana's Loki data source
    "gateway-rust/src/routes/logs_ingest.rs",  # node → Loki push (#525)
    "gateway-rust/src/routes/logs_search.rs",  # search (#528)
]


def test_the_gateway_reads_the_loki_url_only_where_named():
    files = sorted(
        str(rs.relative_to(ROOT))
        for rs in GATEWAY_SRC.rglob("*.rs")
        if '"NOO_LOKI_URL"' in executable_source(rs)
    )
    assert files == LOKI_URL_READERS, files


def _loki_raw() -> dict:
    svc = (untag(load_raw(BASE)).get("services") or {}).get("loki")
    assert svc, "no loki service in docker-compose.cluster.yml"
    return svc


def test_loki_runs_the_mtls_config_only_with_env_expansion_and_no_port():
    svc = _loki_raw()
    cmd = svc.get("command") or []
    assert "-config.file=/etc/loki/tls-config.yaml" in cmd, cmd
    assert "-config.expand-env=true" in cmd, f"retention is ${{NOO_LOKI_RETENTION}} in the config; Loki must expand it: {cmd}"
    configs = [v for v in svc.get("volumes") or [] if isinstance(v, str) and "/etc/loki/" in v]
    assert configs == ["./monitoring/loki/loki-config-tls.yml:/etc/loki/tls-config.yaml:ro"], (
        f"exactly one Loki config may be mounted, the mTLS one: {configs}"
    )
    assert not (ROOT / "monitoring" / "loki" / "loki-config.yml").exists(), "the plaintext Loki config is back"
    assert "ports" not in svc, "Loki publishes a host port — it is compose-network only, mTLS, by design"
    env = {str(e).split("=", 1)[0]: str(e).split("=", 1)[1] for e in svc.get("environment") or []}
    assert env.get("NOO_LOKI_RETENTION") == "${NOO_LOKI_RETENTION:-720h}", env


def test_retention_and_reject_age_are_one_expression_over_the_knob():
    body = LOKI_CFG.read_text()
    code = "\n".join(l.split("#")[0] for l in body.splitlines())
    assert re.search(r"^\s*client_auth_type:\s*RequireAndVerifyClientCert\s*$", code, re.M), "Loki no longer requires client certificates"
    ret = re.search(r"^\s*retention_period:\s*(\S+)\s*$", code, re.M)
    age = re.search(r"^\s*reject_old_samples_max_age:\s*(\S+)\s*$", code, re.M)
    assert ret and age, "retention_period / reject_old_samples_max_age not found — the parse broke"
    assert ret.group(1) == "${NOO_LOKI_RETENTION:-720h}", ret.group(1)
    assert age.group(1) == ret.group(1), (
        f"reject_old_samples_max_age ({age.group(1)}) must equal retention_period ({ret.group(1)}): "
        "a node replaying a buffered window must not be refused"
    )
    assert re.search(r"^\s*reject_old_samples:\s*true\s*$", code, re.M)


def test_the_knob_is_documented():
    body = ENV_MD.read_text()
    assert "`NOO_LOKI_RETENTION`" in body, "docs/reference/env.md does not name NOO_LOKI_RETENTION"
    assert "720h" in body


def test_ingester_min_ready_duration_is_zero():
    """dskit's Lifecycler.CheckReady starts its 15s `min_ready_duration`
    clock on the first /ready CALL that finds the ring healthy, not when the
    ring became healthy. Nothing polls Loki's /ready, so the first
    `noo cluster verify` after a recreate always got 503 "waiting for 15s
    after being ready" (host8, 2026-10-03). A single-binary in-memory ring
    has no peer to wait for: the shipped config sets it to 0s."""
    import yaml

    cfg = yaml.safe_load(LOKI_CFG.read_text())
    lifecycler = ((cfg.get("ingester") or {}).get("lifecycler")) or {}
    assert "min_ready_duration" in lifecycler, (
        "monitoring/loki/loki-config-tls.yml no longer sets ingester.lifecycler.min_ready_duration — "
        "the 15s default makes the first /ready after a recreate a 503"
    )
    assert str(lifecycler["min_ready_duration"]) == "0s", lifecycler["min_ready_duration"]
    # The ring it relies on is the single-binary in-memory one; a real
    # multi-ingester ring would want the delay back.
    assert cfg["common"]["ring"]["kvstore"]["store"] == "inmemory", cfg["common"]["ring"]
    assert cfg["common"]["replication_factor"] == 1
