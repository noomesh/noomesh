# SPDX-License-Identifier: AGPL-3.0-only
# Copyright 2026 PersonifAI LLC

"""The per-backend TLS switches are retired and must not ship in any template.

`NOO_VLLM_TLS`, `NOO_LLAMACPP_TLS`, `NOO_OLLAMA_TLS` (and `NOO_TEI_TLS`,
`NOO_RERANKER_TLS`) select nothing: every backend door is mTLS
unconditionally, and the node agent REFUSES to start when one of them is
left at a false value (node-agent-go/internal/config). A shipped template
that still carries one is a trap for a new install, so none may. An existing
.env that carries one is covered by scripts/retired-env-keys, which the
launcher WARNs on and `noo onboard --only env` offers to remove.

Declared in more than one place: the Go refusal table (`BackendTLSFlags`),
the retired-key list, and every template. This is the guard that keeps them
agreeing.
"""

import re
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent

SWITCHES = ("NOO_VLLM_TLS", "NOO_LLAMACPP_TLS", "NOO_OLLAMA_TLS", "NOO_TEI_TLS", "NOO_RERANKER_TLS")
NAMES = "|".join(SWITCHES)
# A line that SETS (or passes through, or comments out a setting of) a switch:
#   NOO_X_TLS=...   - NOO_X_TLS=${NOO_X_TLS:-}   # NOO_X_TLS=true   NOO_X_TLS: "..."
# Prose that merely names a retired switch does not match.
SETS = re.compile(rf"^\s*(?:#\s*)?(?:-\s*)?(?:export\s+)?(?:{NAMES})\s*[=:]", re.M)
JINJA = re.compile(r"\bnoo_(?:vllm|llamacpp|ollama|tei|reranker)_tls\b")


def _shipped_templates() -> list[Path]:
    out = [ROOT / ".env.example", ROOT / "noomesh.yaml.example"]
    out += sorted(ROOT.glob("docker-compose*.yml"))
    out += sorted((ROOT / "node-agent-go" / "deploy").glob("*"))
    out += sorted((ROOT / "deploy").rglob("*")) if (ROOT / "deploy").is_dir() else []
    out += sorted((ROOT / "ansible").rglob("*.j2")) if (ROOT / "ansible").is_dir() else []
    return [p for p in out if p.is_file()]


def test_no_shipped_template_carries_a_retired_tls_switch() -> None:
    files = _shipped_templates()
    assert len(files) > 5, "scanned suspiciously few templates"
    hits = []
    for f in files:
        text = f.read_text(errors="replace")
        for m in SETS.finditer(text):
            hits.append(f"{f.relative_to(ROOT)}: {m.group(0).strip()}")
        if f.suffix in (".tmpl", ".j2") and JINJA.search(text):
            hits.append(f"{f.relative_to(ROOT)}: renders a noo_*_tls variable")
    assert not hits, "a retired TLS switch is still shipped (the agent refuses a false value):\n" + "\n".join(hits)


def test_no_rust_writer_or_renderer_emits_a_retired_tls_switch() -> None:
    """The CLI writes .env (onboard) and the node env (provision): neither may name a switch."""
    pat = re.compile(rf'"(?:{NAMES})"|vars\.insert\("noo_(?:vllm|llamacpp|ollama|tei|reranker)_tls"')
    hits = []
    for sub in ("noo-cli/src/onboard", "noo-cli/src/commands/provision.rs", "src/noomesh/cluster"):
        base = ROOT / sub
        for f in ([base] if base.is_file() else sorted(base.rglob("*.rs")) + sorted(base.rglob("*.py"))):
            for i, line in enumerate(f.read_text(errors="replace").splitlines(), 1):
                if pat.search(line):
                    hits.append(f"{f.relative_to(ROOT)}:{i}: {line.strip()}")
    # steps.rs/cli.py history lives in comments only; a quoted name outside a comment is a writer.
    hits = [h for h in hits if not h.split(": ", 1)[1].startswith(("//", "#"))]
    assert not hits, "a writer still emits a retired TLS switch:\n" + "\n".join(hits)


def test_every_switch_the_agent_refuses_is_in_the_retired_key_list() -> None:
    go = (ROOT / "node-agent-go" / "internal" / "config" / "config.go").read_text()
    refused = set(re.findall(r'"(NOO_[A-Z]+_TLS)"', go.split("var BackendTLSFlags")[1].split("}")[0]))
    assert refused == set(SWITCHES), f"the Go refusal table and this guard disagree: {refused ^ set(SWITCHES)}"
    keys = {
        line.split("|", 1)[0].strip()
        for line in (ROOT / "scripts" / "retired-env-keys").read_text().splitlines()
        if line.strip() and not line.startswith("#")
    }
    missing = refused - keys
    assert not missing, f"scripts/retired-env-keys must list {sorted(missing)}: an upgraded .env keeps them otherwise"
