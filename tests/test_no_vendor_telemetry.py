# SPDX-License-Identifier: AGPL-3.0-only
# Copyright 2026 PersonifAI LLC

"""No vendor phone-home: every service carries the switches its software reads.

noomesh says "no telemetry" (docs/security/telemetry.md). Some of what it runs
reports home unless told not to — vLLM posts a usage report to stats.vllm.ai at
engine start and every 10 minutes after; host3's noo-vllm had been doing it
since the stack began. This guard holds the list of switches each component
must carry and fails when one goes missing:

* every compose service (base + every add-on overlay, as `docker compose
  config` renders it) is CLASSIFIED — a new service fails until someone
  decides what its software phones home with — and carries its class's
  switches with the exact value;
* the node agent's backendSpecs (node-agent-go/internal/docker/backends.go),
  which launch the same vLLM / TEI / Ollama images on every node, carry the
  same switches in their Env literals, and telemetry.go's table agrees with
  this one (the parity check);
* our Python images bake the HF switches in, the headless and kiosk Chromium
  launches turn off Chromium's background traffic, Loki's usage reporting is
  off, and no known phone-home Python package is a dependency.

Grafana is deliberately absent here: its analytics are switched off on
branch fix/grafana-bookmark-and-no-phone-home, which owns grafana.ini.
"""

from __future__ import annotations

import json
import re
from pathlib import Path

import pytest
import yaml

from tests._compose_projection import env_of, full_projection

ROOT = Path(__file__).resolve().parents[1]
BACKENDS_GO = ROOT / "node-agent-go/internal/docker/backends.go"
TELEMETRY_GO = ROOT / "node-agent-go/internal/docker/telemetry.go"
DOC = ROOT / "docs/security/telemetry.md"

# The switches, by the software that reads them. Values are exact.
TELEMETRY_SWITCHES: dict[str, dict[str, str]] = {
    # vllm/usage/usage_lib.py is_usage_stats_enabled + huggingface_hub
    "vllm": {
        "VLLM_NO_USAGE_STATS": "1",
        "VLLM_DO_NOT_TRACK": "1",
        "DO_NOT_TRACK": "1",
        "HF_HUB_DISABLE_TELEMETRY": "1",
    },
    # huggingface_hub / transformers / faster-whisper / TEI's hf-hub fetch
    "hf": {
        "HF_HUB_DISABLE_TELEMETRY": "1",
        "DO_NOT_TRACK": "1",
    },
    # Ollama has no usage telemetry; this keeps prompts off ollama.com
    "ollama": {
        "OLLAMA_NO_CLOUD": "1",
    },
    # Software with no phone-home to switch off (verified per row in the doc).
    "none": {},
    # Off by config file, not env (checked below / on its own branch).
    "config": {},
}

# Every compose service, classified. A service missing from this map fails
# test_every_compose_service_is_classified.
SERVICE_CLASS: dict[str, str] = {
    # inference backends
    "vllm": "vllm",
    "vllm-secondary": "vllm",
    "tei": "hf",
    "tei-gpu": "hf",
    "reranker": "hf",  # the compose reranker is the TEI image
    "airllm": "hf",
    "ollama": "ollama",
    "ollama-embed": "ollama",
    "ollama-embed-cpu": "ollama",
    "llamacpp": "none",
    # our Python services
    "worker": "hf",
    "worker-extra": "hf",
    "trellion": "hf",
    "trellion-intel": "hf",
    "noo-evolve": "hf",
    # one-shot from the evolve image: copies a file, no network at all
    "noo-evolve-routes": "none",
    "whisper": "hf",
    "piper": "hf",
    "sandbox": "hf",
    "sandbox-extra": "hf",
    "browser": "hf",
    # Rust / Go binaries — no phone-home code (docs/security/telemetry.md)
    "gateway": "none",
    "node-agent": "none",
    "node-agent-sensors": "none",
    # shared services and exporters
    "postgres": "none",
    "redis": "none",
    "nats": "none",
    "prometheus": "none",
    "alertmanager": "none",
    "node-exporter": "none",
    "nvidia-exporter": "none",
    "model-cache": "none",
    "loki": "config",  # analytics.reporting_enabled: false
    "grafana": "config",  # branch fix/grafana-bookmark-and-no-phone-home
    # TLS sidecars
    "stunnel-llamacpp": "none",
    "stunnel-ollama": "none",
    "stunnel-ollama-embed": "none",
    "stunnel-ollama-embed-cpu": "none",
    "stunnel-tei": "none",
    "stunnel-tei-gpu": "none",
    "stunnel-reranker": "none",
    # build-only image targets — never run
    "deps-core": "none",
    "deps-base": "none",
    "sandbox-base": "none",
}

# Node-agent backend specs (backendSpecs keys, plus the reranker's two
# engine constructors) -> class.
GO_SPEC_CLASS: dict[str, str] = {
    "vllm": "vllm",
    "embedding": "hf",
    "airllm": "hf",
    "ollama": "ollama",
    "llamacpp": "none",
    "func rerankerSpecTEI": "hf",
    "func rerankerSpecLlamacpp": "none",
}

# Python packages known to phone home by default. None is a dependency
# today; adding one means adding its switch to the services that import it,
# a row to docs/security/telemetry.md, and an entry here.
PHONE_HOME_PACKAGES = (
    "chromadb",
    "posthog",
    "gradio",
    "litellm",
    "langsmith",
    "langchain",
    "sentry-sdk",
    "sentry_sdk",
    "wandb",
    "mlflow",
    "streamlit",
    "datasets",
    "dvc",
    "scarf",
)

CHROMIUM_QUIET_FLAGS = (
    "--disable-background-networking",
    "--disable-component-update",
    "--disable-domain-reliability",
    "--disable-breakpad",
    "--disable-sync",
    "--metrics-recording-only",
    "--no-pings",
)


# --- compose -----------------------------------------------------------------


def _services() -> dict:
    return full_projection()["services"]


def test_every_compose_service_is_classified():
    unclassified = sorted(set(_services()) - set(SERVICE_CLASS))
    assert not unclassified, (
        f"compose services with no telemetry classification: {unclassified}. Decide what each "
        "one's software phones home with, add it to SERVICE_CLASS (and its switches to the "
        "service), and add a row to docs/security/telemetry.md"
    )


def test_compose_services_carry_their_switches():
    services = _services()
    checked = 0
    problems = []
    for name, svc in sorted(services.items()):
        want = TELEMETRY_SWITCHES[SERVICE_CLASS.get(name, "none")]
        env = env_of(svc)
        for k, v in want.items():
            checked += 1
            if env.get(k) != v:
                problems.append(f"{name}: {k}={env.get(k)!r}, want {v!r}")
    assert checked >= 30, f"only {checked} switches checked — the projection or the table went empty"
    assert not problems, "vendor telemetry switches missing:\n  " + "\n  ".join(problems)


def test_the_vllm_services_turn_off_usage_stats():
    """The one confirmed phone-home, named outright so a table edit cannot
    quietly drop it."""
    services = _services()
    for name in ("vllm", "vllm-secondary"):
        env = env_of(services[name])
        assert env.get("VLLM_NO_USAGE_STATS") == "1", f"{name} would post to stats.vllm.ai"
        assert env.get("DO_NOT_TRACK") == "1", name


# --- node agent (Go) parity --------------------------------------------------


def _balanced_block(src: str, start: int) -> str:
    """The text of the `{...}` block whose `{` is the first one at/after start."""
    i = src.index("{", start)
    depth = 0
    for j in range(i, len(src)):
        if src[j] == "{":
            depth += 1
        elif src[j] == "}":
            depth -= 1
            if depth == 0:
                return src[i + 1 : j]
    raise AssertionError("unbalanced braces")


def _go_env_of_spec(src: str, marker: str) -> dict[str, str]:
    if marker.startswith("func "):
        at = src.index(marker + "()")
    else:
        table = src.index("var backendSpecs = map[string]BackendSpec{")
        at = src.index(f'\t"{marker}": {{', table)
    body = _balanced_block(src, at)
    env_at = body.index("Env: map[string]string{")
    env_block = _balanced_block(body, env_at + len("Env: map[string]string"))
    return dict(re.findall(r'^\s*"([A-Z0-9_]+)":\s*"([^"]*)"', env_block, re.M))


def test_go_backend_specs_carry_the_same_switches():
    src = BACKENDS_GO.read_text()
    checked = 0
    problems = []
    for marker, cls in GO_SPEC_CLASS.items():
        env = _go_env_of_spec(src, marker)
        assert env, f"parsed no Env for Go spec {marker!r} — the parser no longer matches backends.go"
        for k, v in TELEMETRY_SWITCHES[cls].items():
            checked += 1
            if env.get(k) != v:
                problems.append(f"{marker}: {k}={env.get(k)!r}, want {v!r}")
    assert checked >= 10, f"only {checked} Go switches checked"
    assert not problems, (
        "node-agent backendSpecs lack vendor telemetry switches (every node-launched "
        "backend would phone home):\n  " + "\n  ".join(problems)
    )


def test_go_backend_specs_are_all_classified():
    src = BACKENDS_GO.read_text()
    table = _balanced_block(src, src.index("var backendSpecs = map[string]BackendSpec{"))
    keys = set(re.findall(r'^\t"([a-z0-9-]+)":', table, re.M))
    assert keys, "parsed no backendSpecs keys"
    missing = sorted(keys - set(GO_SPEC_CLASS) - {"reranker"})
    assert not missing, f"backendSpecs entries with no telemetry classification: {missing}"


def test_go_telemetry_table_matches_this_one():
    src = TELEMETRY_GO.read_text()
    for go_var, cls in (
        ("telemetryOffVLLM", "vllm"),
        ("telemetryOffHF", "hf"),
        ("telemetryOffOllama", "ollama"),
    ):
        block = _balanced_block(src, src.index(f"{go_var} = map[string]string"))
        got = dict(re.findall(r'"([A-Z0-9_]+)":\s*"([^"]*)"', block))
        assert got == TELEMETRY_SWITCHES[cls], f"{go_var} = {got}, this guard says {TELEMETRY_SWITCHES[cls]}"


# --- images, browsers, config ------------------------------------------------


@pytest.mark.parametrize(
    "dockerfile",
    [
        "docker/Dockerfile.deps-core",  # worker, sandbox, deps-base -> trellion(-intel)
        "docker/Dockerfile.whisper",
        "docker/Dockerfile.piper",
        "docker/Dockerfile.airllm",
        "src/noomesh/tools/browser/Dockerfile",
    ],
)
def test_python_images_bake_the_hf_switches(dockerfile):
    text = (ROOT / dockerfile).read_text()
    env_lines = " ".join(
        m.group(0) for m in re.finditer(r"^ENV\s(?:[^\n]*\\\n)*[^\n]*", text, re.M)
    )
    for k, v in TELEMETRY_SWITCHES["hf"].items():
        assert re.search(rf"\b{k}={v}\b", env_lines), f"{dockerfile}: no ENV {k}={v}"


@pytest.mark.parametrize(
    "path",
    ["src/noomesh/tools/browser/server.py", "noo-cli/src/commands/kiosk_assets/noo-kiosk-launch"],
)
def test_chromium_launches_turn_off_background_traffic(path):
    text = (ROOT / path).read_text()
    missing = [f for f in CHROMIUM_QUIET_FLAGS if f not in text]
    assert not missing, f"{path} launches Chromium without {missing}"


def test_loki_usage_reporting_is_off():
    configs = sorted((ROOT / "monitoring/loki").glob("*.yml"))
    assert configs, "no Loki config found"
    for c in configs:
        doc = yaml.safe_load(c.read_text()) or {}
        assert doc.get("analytics", {}).get("reporting_enabled") is False, (
            f"{c.relative_to(ROOT)}: Loki reports usage to stats.grafana.org unless "
            "analytics.reporting_enabled is false"
        )


def test_no_phone_home_python_dependency():
    text = (ROOT / "pyproject.toml").read_text().lower()
    deps = set(re.findall(r'"\s*([a-z0-9_.-]+)', text))
    found = sorted(p for p in PHONE_HOME_PACKAGES if p in deps)
    assert not found, (
        f"pyproject.toml now depends on {found}, which phone home by default. Add its switch "
        "to every service that imports it, a row to docs/security/telemetry.md, and update "
        "this guard"
    )


def test_the_doc_names_every_switch():
    doc = DOC.read_text()
    for cls in ("vllm", "hf", "ollama"):
        for k in TELEMETRY_SWITCHES[cls]:
            assert k in doc, f"docs/security/telemetry.md does not mention {k}"
    for svc in ("vLLM", "Ollama", "text-embeddings-inference", "Loki", "Grafana", "NATS"):
        assert svc in doc, f"docs/security/telemetry.md has no row for {svc}"


def test_the_mac_plist_lane_carries_the_ollama_switch():
    # A Mac's ollama is a brew launchd job, not a container: the switch lives
    # in noo enroll's plist edit, the agent's convergence and the doc.
    enroll = (ROOT / "noo-cli/src/commands/enroll.rs").read_text()
    guard = (ROOT / "node-agent-go/internal/backendrt/ollama_telemetry.go").read_text()
    for k in TELEMETRY_SWITCHES["ollama"]:
        assert k in enroll, f"enroll.rs does not set {k} in the brew plist"
        assert k in guard, f"ollama_telemetry.go does not converge {k}"
    assert "homebrew.mxcl.ollama.plist" in DOC.read_text(), "the doc does not name the Mac plist"


# --- host software (docs/security/telemetry.md, "Host software") --------------

VENDOR_RS = ROOT / "noo-cli/src/vendor.rs"
HOSTTEL_GO = ROOT / "node-agent-go/internal/hostd/hosttelemetry.go"
VERIFY_RS = ROOT / "noo-cli/src/commands/cluster_verify.rs"


def _non_test_source(path: Path) -> str:
    """The file up to its `#[cfg(test)]` module, which is always last."""
    text = path.read_text()
    cut = re.search(r"^#\[cfg\(test\)\]\s*$", text, re.M)
    return text[: cut.start()] if cut else text


def test_tailscaled_log_upload_switch_is_set_where_noomesh_installs_it():
    # Tailscale uploads client logs to its log server unless told not to:
    # `--no-logs-no-support` / TS_NO_LOGS_NO_SUPPORT=true.
    vendor = _non_test_source(VENDOR_RS)
    assert 'TAILSCALE_NO_LOGS_ENV: &str = "TS_NO_LOGS_NO_SUPPORT"' in vendor
    assert "/etc/default/tailscaled" in vendor, "no Linux script writes the unit's EnvironmentFile"
    assert "homebrew.mxcl.tailscale.plist" in vendor and "launchctl bootstrap system" in vendor, "no Mac script"
    enroll = _non_test_source(ROOT / "noo-cli/src/commands/enroll.rs")
    assert enroll.count("tailscale_logs_off()") >= 2, "enroll defines but never calls the switch (fresh install and already-installed paths)"
    steps = _non_test_source(ROOT / "noo-cli/src/onboard/steps.rs")
    assert "tailscale_nologs_linux_script" in steps, "the controller's onboard installs Tailscale without the switch"


def test_every_brew_command_noomesh_runs_turns_analytics_off():
    assert "HOMEBREW_NO_ANALYTICS=1" in _non_test_source(VENDOR_RS)
    found = []
    problems = []
    for rs in sorted((ROOT / "noo-cli/src").rglob("*.rs")):
        for n, line in enumerate(_non_test_source(rs).splitlines(), 1):
            if line.lstrip().startswith("//"):
                continue
            if re.search(r"\bbrew (install|list|services|upgrade|update|analytics)\b", line):
                found.append(f"{rs.name}:{n}")
                if "{b}" not in line and "BREW_ENV" not in line and "HOMEBREW_NO_ANALYTICS=1" not in line:
                    problems.append(f"{rs.relative_to(ROOT)}:{n}: {line.strip()[:110]}")
    assert len(found) >= 4, f"only {found} brew commands found — the scan no longer matches enroll.rs"
    assert not problems, "brew runs without HOMEBREW_NO_ANALYTICS=1:\n  " + "\n  ".join(problems)
    assert "HOMEBREW_NO_ANALYTICS=1" in (ROOT / "scripts/setup-dev.sh").read_text()


def test_hostd_reports_the_host_telemetry_facts_and_verify_judges_them():
    go = HOSTTEL_GO.read_text()
    for needle in ("TS_NO_LOGS_NO_SUPPORT", "no-logs-no-support", "motd-news", "popularity-contest", "whoopsie", "/etc/default/tailscaled"):
        assert needle in go, f"hosttelemetry.go does not read {needle}"
    # report-only: hostd must never restart tailscaled or edit these files
    assert not re.search(r'"(restart|stop|start|enable|disable|mask)"', go), "hostd's telemetry collector must be read-only"
    verify = _non_test_source(VERIFY_RS)
    assert '"host telemetry"' in verify and "fn host_telemetry_check" in verify
    assert "host_telemetry_check(id, host)" in verify.replace("\n", " ")
    assert "TS_NO_LOGS_NO_SUPPORT=true" in verify, "the row prints no exact remedy"


def test_the_doc_has_a_host_software_section_naming_each_switch():
    doc = DOC.read_text()
    assert "## Host software" in doc
    for k in (
        "TS_NO_LOGS_NO_SUPPORT",
        "--no-logs-no-support",
        "technical support",
        "HOMEBREW_NO_ANALYTICS",
        "brew analytics",
        "motd-news",
        "popularity-contest",
        "whoopsie",
        "Docker Desktop",
        "Docker Engine",
        "nvidia-container-toolkit",
        "host telemetry",
        "controlplane.tailscale.com",
    ):
        assert k in doc, f"docs/security/telemetry.md does not mention {k}"


def test_tailscaled_logs_stay_local_and_reach_loki():
    # With upload off, tailscaled still logs locally; the operator reads it in
    # Loki as name=tailscaled. Linux: hostd's journal allowlist. Mac: the brew log file.
    jf = (ROOT / "node-agent-go/internal/hostd/journal_follow.go").read_text()
    assert re.search(r'map\[string\]bool\{[^}]*"tailscaled": true', jf), "tailscaled's journal is not in the follow allowlist"
    agent = (ROOT / "node-agent-go/internal/agent/agent.go").read_text()
    assert re.search(r'NewFileSource\("[^"]*/var/log/tailscaled\.log", "tailscaled"', agent), "the Mac agent does not ship the brew tailscaled log"
    doc = DOC.read_text()
    for k in ("tailscale bugreport", "journalctl -u tailscaled", 'name="tailscaled"', "allow-tailscale-log-upload"):
        assert k in doc, f"docs/security/telemetry.md does not mention {k}"


def test_the_operator_opt_in_marker_is_the_same_path_in_rust_and_go():
    rs = re.search(r'TAILSCALE_UPLOAD_MARKER: &str = "([^"]+)"', VENDOR_RS.read_text())
    go = re.search(r'TailscaleUploadMarker = "([^"]+)"', HOSTTEL_GO.read_text())
    assert rs and go, "marker constant not found in vendor.rs / hosttelemetry.go"
    assert rs.group(1) == go.group(1) == "/etc/noo/allow-tailscale-log-upload"


KIOSK_RS = ROOT / "noo-cli/src/commands/kiosk.rs"


def _kiosk_code() -> str:
    # Everything before the first test module: the shipped code, not its tests.
    return KIOSK_RS.read_text().split("\n#[cfg(test)]\nmod tests", 1)[0]


def test_kiosk_setup_switches_off_the_displays_tailscaled_log_upload():
    # A kiosk is a viewer, not an enrolled node: no noo-hostd reports its
    # tailscaled, so the seat must set the switch itself, with the same
    # opt-in marker rule enroll follows.
    code = _kiosk_code()
    assert "sh(&tailscale_logs_off_cmd())" in code, "kiosk_setup no longer runs the tailscaled switch step"
    m = re.search(r"fn tailscale_logs_off_cmd\(\) -> String \{(.*?)\n\}", code, re.S)
    assert m, "tailscale_logs_off_cmd not found"
    assert "tailscale_nologs_linux_script()" in m.group(1), "the seat must reuse enroll's script, marker rule included"
    assert "command -v tailscaled" in m.group(1), "a display without tailscale must be a no-op"
    vendor = VENDOR_RS.read_text()
    script = re.search(r"pub fn tailscale_nologs_linux_script\(\) -> String \{(.*?)\n\}", vendor, re.S).group(1)
    assert "TAILSCALE_UPLOAD_MARKER" in script and "TS_NO_LOGS_NO_SUPPORT" in vendor


def test_kiosk_status_shows_the_hosts_own_reporters_without_privilege():
    code = _kiosk_code()
    for row in ('"tailscale logs"', '"os reporters"'):
        assert row in code, f"noo kiosk status has no {row} row"
    status = code.split("pub fn kiosk_status", 1)[1].split("// ── teardown", 1)[0]
    live = "\n".join(l for l in status.splitlines() if not l.lstrip().startswith("//"))
    assert "sudo" not in live, "status must stay readable without privilege"


def test_the_doc_covers_kiosk_hosts_and_phones():
    doc = DOC.read_text()
    for k in (
        "### Kiosk displays",
        "not an enrolled node",
        "tag:kiosk",
        "rpi-connect",
        "### Phones and other client devices",
        "no phone app",
        "no\n  opt-out for the iOS or Android apps",
        "companion node's node agent",
        "noo cluster host-telemetry apply",
    ):
        assert k in doc, f"docs/security/telemetry.md does not mention {k!r}"


def test_the_web_console_phones_nothing_home_and_runs_nothing_in_the_background():
    # What a phone loads from noomesh: ui/apps/web. No service worker, no
    # manifest, no external script/style/font, no analytics package.
    web = ROOT / "ui/apps/web"
    for page in ("index.html", "kiosk.html"):
        html = (web / page).read_text()
        external = re.findall(r'(?:src|href)\s*=\s*["\']((?:https?:)?//[^"\']+)', html)
        assert not external, f"{page} loads {external} from outside the gateway"
    pkg = (web / "package.json").read_text().lower()
    for name in sorted(set(PHONE_HOME_PACKAGES) | {"workbox-window", "vite-plugin-pwa", "react-ga", "@sentry/react", "@vercel/analytics"}):
        assert f'"{name}"' not in pkg, f"ui/apps/web depends on {name}"
    for f in list((web / "src").rglob("*.ts")) + list((web / "src").rglob("*.tsx")):
        if ".test." in f.name:
            continue
        t = f.read_text()
        assert "serviceWorker" not in t, f"{f.relative_to(ROOT)} registers a service worker"
        assert "sendBeacon" not in t, f"{f.relative_to(ROOT)} sends a beacon"
    assert not list(web.rglob("manifest.webmanifest")) and not list(web.rglob("manifest.json")), "the console ships a web-app manifest"
    assert not list(web.rglob("sw.js")), "the console ships a service worker"


def test_the_verify_remedy_names_the_apply_verb_and_the_verb_exists():
    verify = (ROOT / "noo-cli/src/commands/cluster_verify.rs").read_text()
    assert "noo cluster host-telemetry apply {id}" in verify, "the host telemetry remedy no longer points at the apply verb"
    usage = (ROOT / "noo-cli/src/usage.rs").read_text()
    main = (ROOT / "noo-cli/src/main.rs").read_text()
    assert '&["cluster", "host-telemetry", "apply"]' in usage and '&["cluster", "host-telemetry", "apply"]' in main


# --- agent harnesses (docs/security/telemetry.md, "Agent harnesses") ---------

HARNESS_KINDS_JSON = ROOT / "config/harness-kinds.json"

# The switches each third-party harness CLI must be launched with, with the
# vendor's own documentation as the source (code.claude.com/docs/en/env-vars,
# github.blog/changelog/2026-04-07-copilot-cli-now-supports-byok-and-local-models).
# "noo" is our own binary: no phone-home code, so no switches. "codex" has no
# switches declared yet (the doc says so) and no runner ships for it. A new
# kind must be added in config/harness-kinds.json (which both the gateway and
# the node agent embed), HERE, and in the doc.
HARNESS_SWITCHES: dict[str, dict[str, str]] = {
    "noo": {},
    "claude-code": {
        "CLAUDE_CODE_DISABLE_NONESSENTIAL_TRAFFIC": "1",
        "DISABLE_TELEMETRY": "1",
        "DISABLE_ERROR_REPORTING": "1",
        "DISABLE_FEEDBACK_COMMAND": "1",
        "CLAUDE_CODE_DISABLE_FEEDBACK_SURVEY": "1",
        "DISABLE_UPDATES": "1",
        "DO_NOT_TRACK": "1",
        # NOT covered by CLAUDE_CODE_DISABLE_NONESSENTIAL_TRAFFIC (Anthropic says
        # so in that variable's row); it has its own switch.
        "CLAUDE_CODE_DISABLE_OFFICIAL_MARKETPLACE_AUTOINSTALL": "1",
    },
    "copilot": {"COPILOT_OFFLINE": "true"},
    "codex": {},
}


def _harness_kinds() -> list[dict]:
    kinds = json.loads(HARNESS_KINDS_JSON.read_text())["kinds"]
    assert kinds, "config/harness-kinds.json declares no kinds"
    return kinds


def test_every_harness_kind_has_its_switches_declared_once():
    rows = _harness_kinds()
    kinds = [r["kind"] for r in rows]
    assert len(kinds) == len(set(kinds)), f"a harness kind is declared twice: {kinds}"
    for r in rows:
        assert isinstance(r.get("telemetry_off"), dict), (
            f"harness kind {r['kind']!r} has no telemetry_off entry in config/harness-kinds.json: a new "
            "harness kind must declare its vendor telemetry switches there (even an empty map), "
            "HARNESS_SWITCHES here and a row in docs/security/telemetry.md"
        )
    declared = {r["kind"]: r["telemetry_off"] for r in rows}
    assert set(HARNESS_SWITCHES) == set(declared), f"HARNESS_SWITCHES {sorted(HARNESS_SWITCHES)} != {sorted(declared)}"
    for kind in sorted(declared):
        assert declared[kind] == HARNESS_SWITCHES[kind], (
            f"{kind}: config/harness-kinds.json declares {declared[kind]}, this guard says {HARNESS_SWITCHES[kind]}"
        )
    assert declared["claude-code"] and declared["copilot"], "a third-party harness with no switches phones home"
    # A foreign kind with no switches declared must not be launchable: every
    # runner is now `noo-gateway`, so the runner no longer says whether a
    # kind can launch anything. What makes a kind launchable is a vendor
    # `cli` PLUS a backend that can serve its wire (`wires` non-empty; an
    # empty `wires` is refused by data). A kind that is launchable would run
    # a CLI nobody has switched off.
    for r in rows:
        if r["kind"] != "noo" and not r["telemetry_off"]:
            assert r.get("cli") is None or not r["wires"], (
                f"harness kind {r['kind']!r} names a vendor CLI and a serving backend with no telemetry switches declared"
            )


def test_the_doc_has_a_row_and_a_switch_for_every_harness_kind():
    doc = DOC.read_text()
    assert "### Agent harnesses" in doc
    for kind, switches in HARNESS_SWITCHES.items():
        assert f"kind `{kind}`" in doc, f"docs/security/telemetry.md has no Components row for harness kind {kind}"
        for k in switches:
            assert k in doc, f"docs/security/telemetry.md does not mention {k}"
    for needle in ("skipWebFetchPreflight", "not shipped", "code.claude.com/docs/en/env-vars", "COPILOT_OFFLINE", "cloud model"):
        assert needle in doc, f"docs/security/telemetry.md does not mention {needle!r}"
    assert "### Paid add-ons" in doc


def test_the_doc_has_a_row_for_the_addon_registry_and_its_switch():
    """Add-on pulls through the vendor's add-on registry (i91) are outbound
    traffic to the vendor: the doc names the host, what the vendor keeps, and
    the switch that keeps a controller off it (NOO_ADDON_REGISTRY_TOKEN)."""
    doc = (ROOT / "docs/security/telemetry.md").read_text()
    rows = [l for l in doc.splitlines() if l.startswith("| Add-on pulls |")]
    assert len(rows) == 1, "telemetry.md needs exactly one 'Add-on pulls' row"
    row = rows[0]
    for needle in ("addons.noomesh.ai", "NOO_ADDON_REGISTRY_TOKEN", "30 days", "never an IP address"):
        assert needle in row, f"the Add-on pulls row must name {needle!r}"
    selector = (ROOT / "noo-cli/src/addons/lock_fetch.rs").read_text()
    assert "vendor_token || anchor.pull.is_none()" in selector, (
        "the route selector must keep NOO_ADDON_REGISTRY_TOKEN as the switch off the proxy"
    )

