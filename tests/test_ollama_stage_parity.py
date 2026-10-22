# SPDX-License-Identifier: AGPL-3.0-only
# Copyright 2026 PersonifAI LLC

"""The controller writes staged ollama models; the node reads them. The two
halves are different languages and must agree on four things, or a staged
model is silently never found (or, worse, found and run as something else):

* the store NAME of a registry tag (`gemma4:12b` -> `ollama+library+gemma4+12b`),
* the Modelfile header the node requires (`# noo-ollama-stage: v1`,
  `# model-sha256: <hex>`),
* the directives a staged Modelfile may use,
* the sweep exclusion: `sync-model-files` must not push a staged weight to
  every node.

Each side carries the same vectors in its own tests; this pins that they are
the same list, and that the allow-lists and header strings match.
"""

from __future__ import annotations

import re
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
GO = (ROOT / "node-agent-go/internal/docker/ollama_stage.go").read_text()
GO_TEST = (ROOT / "node-agent-go/internal/docker/ollama_stage_test.go").read_text()
RS = (ROOT / "noo-cli/src/commands/ollama_stage.rs").read_text()
CLUSTER = (ROOT / "noo-cli/src/commands/cluster.rs").read_text()


def go_vectors() -> list[tuple[str, str]]:
    block = GO_TEST.split("var ollamaStemVectors", 1)[1].split("\n}\n", 1)[0]
    return re.findall(r'\{"([^"]+)", "([^"]+)"\}', block)


def rust_vectors() -> list[tuple[str, str]]:
    block = RS.split("const STEM_VECTORS", 1)[1].split("];", 1)[0]
    return re.findall(r'\("([^"]+)", "([^"]+)"\)', block)


def test_both_sides_carry_the_same_name_vectors() -> None:
    go, rs = go_vectors(), rust_vectors()
    assert len(go) >= 6, f"parse found only {len(go)} Go vectors"
    assert go == rs, "the CLI and the node disagree about which store name a registry tag gets"
    for ref, stem in go:
        assert stem.startswith("ollama+") and " " not in stem, (ref, stem)


def test_the_header_the_node_requires_is_the_one_the_cli_writes() -> None:
    for line in ("# noo-ollama-stage: v1", "# model-sha256: "):
        assert line in RS, f"the CLI no longer writes {line!r}"
    assert "# noo-ollama-stage: v1$" in GO.replace("\\", "") or "noo-ollama-stage: v1$" in GO
    assert "# model-sha256: ([0-9a-f]{64})$" in GO


def test_the_directive_allow_lists_match() -> None:
    go_block = GO.split("var stagedModelfileDirectives", 1)[1].split("}\n", 1)[0]
    go = set(re.findall(r'"([A-Z]+)": true', go_block))
    # The directives render_modelfile emits.
    rs = set(re.findall(r'"(FROM|TEMPLATE|SYSTEM|PARAMETER|LICENSE|MESSAGE|RENDERER|PARSER) ', RS))
    rs |= set(re.findall(r'(?:out\.push_str\(&format!\(|push_str\(&format!\()"(TEMPLATE|SYSTEM|PARAMETER|LICENSE|MESSAGE|RENDERER|PARSER|FROM) ', RS))
    assert go == {"FROM", "TEMPLATE", "SYSTEM", "PARAMETER", "LICENSE", "MESSAGE", "RENDERER", "PARSER"}, go
    assert rs <= go, f"the CLI writes directives the node refuses: {sorted(rs - go)}"
    assert "ADAPTER" not in go


def test_staged_weights_stay_out_of_the_default_sweep() -> None:
    assert "is_staged_name" in CLUSTER and 'starts_with("ollama+")' in RS


def test_the_node_never_dials_the_ollama_registry_for_a_staged_tag() -> None:
    """The import path is the existing store path (`ollama create` over two
    store files); the only registry pull is `ollama pull`, behind the
    placed-node refusal, and it is not called from the import."""
    code = re.sub(r"//.*", "", (ROOT / "node-agent-go/internal/docker/ollama_model.go").read_text())
    assert '"pull"' not in code and "OllamaPull(" not in code and "/api/pull" not in code
    assert '"create"' in code or "create" in code
    assert "https://registry.ollama.ai" not in code and "http.Get" not in code
