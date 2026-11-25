# SPDX-License-Identifier: AGPL-3.0-only
# Copyright 2026 PersonifAI LLC

"""A Mac's Ollama boot service: what enroll writes and what the agent requires.

The agent's `ollama_env` check lists the placement env a boot-service plist
must carry (`OllamaTuningKeys`) and records the wanted values in a file;
`noo enroll` (Rust) writes those keys into the plist it registers. They are
two languages, so this pins that the key lists and the file name are the same,
and that enroll writes what it reads and the agent's remedy stays true.
"""

from __future__ import annotations

import re
from pathlib import Path

from tests import _rust_src as rs

ROOT = Path(__file__).resolve().parents[1]
GO = (ROOT / "node-agent-go/internal/backendrt/ollama_telemetry.go").read_text()
RS_RAW = (ROOT / "noo-cli/src/commands/enroll.rs").read_text()
RS = rs.own_code((ROOT / "noo-cli/src/commands/enroll.rs").read_text())


def go_keys() -> list[str]:
    m = re.search(r"var OllamaTuningKeys = \[\]string\{(.*?)\}", GO, re.S)
    assert m, "this guard is stale: OllamaTuningKeys is gone"
    return re.findall(r'"([A-Z_]+)"', m.group(1))


def rust_keys() -> list[str]:
    m = re.search(r"OLLAMA_TUNING_KEYS: \[&str; (\d+)\] = \[(.*?)\];", RS, re.S)
    assert m, "this guard is stale: OLLAMA_TUNING_KEYS is gone"
    keys = re.findall(r'"([A-Z_]+)"', m.group(2))
    assert int(m.group(1)) == len(keys)
    return keys


def test_enroll_and_the_agent_list_the_same_ollama_keys_in_the_same_order():
    assert go_keys() == rust_keys()
    assert len(go_keys()) >= 6


def test_both_sides_name_the_same_wanted_env_file():
    go = re.search(r'const OllamaWantedEnvFile = "([^"]+)"', GO)
    rust = re.search(r'OLLAMA_WANTED_ENV_FILE: &str = "([^"]+)"', RS)
    assert go and rust and go.group(1) == rust.group(1)


def test_both_sides_use_the_same_path_for_the_wanted_env_file():
    go = re.search(r'WantedFile:\s*filepath\.Join\(home, "([^"]+)", OllamaWantedEnvFile\)', GO)
    assert go, "this guard is stale: NewOllamaGuard no longer sets WantedFile from home"
    caller = rs.fn_body(RS, "fn darwin_ollama_boot_service")
    rust = re.search(r'"\{\}/([^/{}"]+)/\{OLLAMA_WANTED_ENV_FILE\}"', caller)
    assert rust, "this guard is stale: enroll no longer reads {home}/<dir>/<file>"
    assert go.group(1) == rust.group(1)
    assert "home.trim_end_matches('/')" in caller


def test_enroll_writes_the_tuning_it_reads_into_the_boot_plist():
    plan = rs.fn_body(RS, "fn darwin_ollama_boot_plan")
    assert "for (k, v) in &w.set" in plan and "EnvironmentVariables.{k}" in plan
    assert "plutil -remove EnvironmentVariables.{k}" in plan and "for k in OLLAMA_TUNING_KEYS" in plan
    assert "fn ollama_tuning_value_ok" in RS
    caller = rs.fn_body(RS, "fn darwin_ollama_boot_service")
    assert "OLLAMA_WANTED_ENV_FILE" in caller and "ollama_wanted_env" in caller


def test_the_refusal_still_offers_resume_only_while_it_applies_the_recorded_env():
    drift = GO.split("func (g *OllamaGuard) reportSystemDrift", 1)[1].split("\nfunc ", 1)[0]
    assert "or run `noo enroll --resume`" in drift
    assert "g.recordWanted()" in drift
    assert "bootout system/" in drift and "2>/dev/null || true" in drift


def test_the_wanted_file_shape_is_the_same_on_both_sides():
    # Go writes {"known":true,"env":{...}}; Rust reads only that shape.
    assert 'json:"known"' in GO and 'json:"env"' in GO
    reader = rs.fn_body(RS, "fn ollama_wanted_env")
    assert '"known"' in reader and '"env"' in reader
    # the agent writes only once its desired state is known
    rec = GO.split("func (g *OllamaGuard) recordWanted", 1)[1].split("\nfunc ", 1)[0]
    assert "g.TuningKnown == nil || !g.TuningKnown()" in rec
    assert re.search(r"TuningKnown:\s+OllamaTuningKnown,", GO), "NewOllamaGuard must wire TuningKnown"


def test_every_value_the_agent_emits_is_in_the_list_the_rust_validator_is_tested_with():
    # Rust's validator test runs AGENT_EMITTED through it; this keeps that list
    # equal to what the Go side can format for each key.
    m = re.search(r"const AGENT_EMITTED: \[\(&str, &str\); \d+\] = \[(.*?)\];", RS_RAW, re.S)
    assert m, "this guard is stale: AGENT_EMITTED is gone"
    listed = set(re.findall(r'\("([A-Z_]+)", "([^"]*)"\)', m.group(1)))
    emitted: set[tuple[str, str]] = set()
    for f in ("reconcile/multirole.go", "reconcile/harness_profile.go"):
        src = (ROOT / "node-agent-go/internal" / f).read_text()
        emitted |= set(re.findall(r'env\["(OLLAMA_[A-Z_]+)"\] = "([^"]*)"', src))
    assert emitted, "this guard is stale: the agent's literal env values moved"
    assert emitted <= listed, f"the agent emits {emitted - listed} that the validator is not tested with"
    # decimal integers: the counts are formatted with strconv.Itoa on the Go side
    multi = (ROOT / "node-agent-go/internal/reconcile/multirole.go").read_text()
    assert 'env["OLLAMA_MAX_LOADED_MODELS"] = strconv.Itoa(' in multi
    prof = (ROOT / "node-agent-go/internal/reconcile/harness_profile.go").read_text()
    assert "strconv.Itoa(prof.Context)" in prof
    for k in ("OLLAMA_MAX_LOADED_MODELS", "OLLAMA_CONTEXT_LENGTH"):
        assert any(key == k and v.isdigit() for key, v in listed)
