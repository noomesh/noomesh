# SPDX-License-Identifier: AGPL-3.0-only
# Copyright 2026 PersonifAI LLC

"""The controller writes staged ollama models; the node reads them. The two
halves are different languages and must agree on what is in the store, or a
staged model is silently never found (or, worse, found and run as something
else):

* the store NAME of a registry tag (`gemma4:12b` -> `ollama+library+gemma4+12b`),
* the mirror's store files (`sha256-<hex>.ollama-blob`,
  `<stem>.ollama-manifest`) and the manifest limits both sides enforce,
* the Modelfile header and directives of the OLD pair, which nodes still
  import but the CLI no longer writes,
* the sweep exclusion: `sync-model-files` must not push staged files to every
  node.

Each side carries the same vectors in its own tests; this pins that they are
the same list, and that the constants, allow-lists and header strings match.
"""

from __future__ import annotations

import re
from pathlib import Path

from tests import _rust_src as rs

ROOT = Path(__file__).resolve().parents[1]
GO = (ROOT / "node-agent-go/internal/docker/ollama_stage.go").read_text()
GO_TEST = (ROOT / "node-agent-go/internal/docker/ollama_stage_test.go").read_text()
RS = (ROOT / "noo-cli/src/commands/ollama_stage.rs").read_text()
CLUSTER = (ROOT / "noo-cli/src/commands/cluster.rs").read_text()
GO_MIRROR = (ROOT / "node-agent-go/internal/docker/ollama_mirror.go").read_text()


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


def test_the_cli_no_longer_writes_a_modelfile() -> None:
    """The mirror replaced the GGUF + Modelfile rebuild. The node still reads
    an OLD pair (and keeps its header and directive checks, pinned below), but
    nothing in the CLI may write one for a registry tag."""
    code = rs.own_code(RS)
    for gone in ("# noo-ollama-stage", "# model-sha256", "render_modelfile", "plan_layers", "install_weight"):
        assert gone not in code, f"the CLI still has the Modelfile rebuild: {gone!r}"
    assert not re.search(r'format!\("(FROM|TEMPLATE|SYSTEM|PARAMETER|LICENSE|MESSAGE|RENDERER|PARSER) ', code)


def test_the_node_still_reads_the_old_pair_it_always_did() -> None:
    assert "noo-ollama-stage: v1$" in GO.replace("\\", "")
    assert "# model-sha256: ([0-9a-f]{64})$" in GO
    go_block = GO.split("var stagedModelfileDirectives", 1)[1].split("}\n", 1)[0]
    go = set(re.findall(r'"([A-Z]+)": true', go_block))
    assert go == {"FROM", "TEMPLATE", "SYSTEM", "PARAMETER", "LICENSE", "MESSAGE", "RENDERER", "PARSER"}, go
    assert "ADAPTER" not in go


def _rust_const(name: str) -> str:
    m = re.search(rf"const {name}: [^=]+= ([^;]+);", RS)
    assert m, f"{name} missing from ollama_stage.rs"
    return m.group(1).strip()


def _go_const(name: str) -> str:
    m = re.search(rf"^\s*{name}\s*=\s*([^\n/]+)", GO_MIRROR, re.M)
    assert m, f"{name} missing from ollama_mirror.go"
    return m.group(1).strip()


def test_the_manifest_limits_match_the_nodes() -> None:
    pairs = {
        "MIRROR_MAX_LAYERS": "mirrorMaxLayers",
        "MIRROR_MAX_MANIFEST_BYTES": "mirrorMaxManifestBytes",
        "MIRROR_MAX_BLOB_BYTES": "mirrorMaxBlobBytes",
    }
    for rust_name, go in pairs.items():
        assert _rust_const(rust_name) == _go_const(go), (rust_name, go)
    assert _rust_const("MIRROR_MAX_LAYERS") == "64"
    assert _rust_const("MIRROR_MAX_MANIFEST_BYTES") == "1 << 20"
    assert _rust_const("MIRROR_MAX_BLOB_BYTES") == "1 << 40"
    # Digest and media-type shapes: the same rules in both languages.
    assert "[A-Za-z0-9.+/_-]{1,128}" in GO_MIRROR
    assert "^sha256:[0-9a-f]{64}$" in GO_MIRROR
    assert "b'.' | b'+' | b'/' | b'_' | b'-'" in RS and "(1..=128).contains" in RS
    assert "len() == 64" in RS and "strip_prefix(\"sha256:\")" in RS
    assert "schemaVersion" in RS and "Some(2)" in RS


def test_the_mirror_store_names_match_the_nodes() -> None:
    assert _rust_const("MIRROR_BLOB_SUFFIX") == _go_const("mirrorBlobSuffix") == '".ollama-blob"'
    assert _rust_const("MIRROR_MANIFEST_SUFFIX") == _go_const("mirrorManifestSuffix") == '".ollama-manifest"'
    assert _rust_const("MIRROR_BLOB_PREFIX") == '"sha256-"'
    assert '"sha256-" + b.Hex + mirrorBlobSuffix' in GO_MIRROR


def test_staged_files_stay_out_of_the_default_sweep() -> None:
    assert "is_staged_name" in CLUSTER
    fn = rs.fn_body(rs.own_code(RS), "pub(crate) fn is_staged_name")
    assert 'starts_with("ollama+")' in fn
    assert "MIRROR_BLOB_SUFFIX" in fn and "MIRROR_MANIFEST_SUFFIX" in fn
    # The sweep lists only .gguf files; a mirror file never has that extension.
    assert 'Some("gguf")' in CLUSTER


def test_the_node_never_dials_the_ollama_registry_for_a_staged_tag() -> None:
    """The import path is the existing store path (`ollama create` over two
    store files); the only registry pull is `ollama pull`, behind the
    placed-node refusal, and it is not called from the import."""
    code = re.sub(r"//.*", "", (ROOT / "node-agent-go/internal/docker/ollama_model.go").read_text())
    assert '"pull"' not in code and "OllamaPull(" not in code and "/api/pull" not in code
    assert '"create"' in code or "create" in code
    assert "https://registry.ollama.ai" not in code and "http.Get" not in code
