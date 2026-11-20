# SPDX-License-Identifier: AGPL-3.0-only
# Copyright 2026 PersonifAI LLC

"""Every model onboard can pick has a KV row, and every derived row is recomputed.

The 0.6.29-rc.1 rehearsal refused a reranker placement on a small CPU box with
"qwen2.5:0.5b [chat] 20.3 GB (estimated)": the model had no row and no node
reported its architecture, so placement_fit charged the 144 KiB/token chat floor
(a 0.5B model's real KV is 12 KiB/token). The fix is a row, never a guess:

- `config/model-capabilities.json` carries `kv_bytes_per_token` for each model
  the wizard (`noo-cli/src/onboard/steps.rs`, `noo-cli/src/catalog.rs`) can offer
  and for the rehearsal's tiny model (`scripts/install-cell/run.sh`);
- each row says where it came from (`kv_source`): the GGUF header of the Ollama
  model, whose attention fields are copied, and only those, to
  `tests/fixtures/model_kv/ollama_gguf_metadata.json`;
- this test recomputes every derived row from that copy, so a hand-edited
  number, or a fixture that no longer says what the row says, is red.

Margin kept (the same text is in each row's `kv_source.margin`): a derived figure
is the FULL-attention one. Sliding windows are not credited (a gemma layer is
charged for the whole context), layers that share KV are charged anyway, K and V
are both counted, and the dtype is f16 even when OLLAMA_KV_CACHE_TYPE is q8_0 or
q4_0 (placement_fit scales the figure down per row; the row never does). DeepSeek
MLA is charged as the expanded per-head K/V, not the compressed latent. The one
measured row (gemma4:e2b, 16 KiB) stays measured and must stay under its own
full-attention figure.
"""

from __future__ import annotations

import json
import re
from pathlib import Path

from tests import _rust_src as rs

REPO = Path(__file__).resolve().parents[1]
TABLE = REPO / "config" / "model-capabilities.json"
FIXTURE = REPO / "tests" / "fixtures" / "model_kv" / "ollama_gguf_metadata.json"
STEPS = REPO / "noo-cli" / "src" / "onboard" / "steps.rs"
CATALOG = REPO / "noo-cli" / "src" / "catalog.rs"
RUN_SH = REPO / "scripts" / "install-cell" / "run.sh"

ROWS = json.loads(TABLE.read_text())["models"]
FX = json.loads(FIXTURE.read_text())


def derive(model: str) -> int:
    """f16 KV bytes per token, every layer full attention: sum over layers of
    kv_heads x (key_length + value_length) x 2 bytes."""
    g = FX["models"][model]["gguf"]
    arch = g["general.architecture"]
    p = arch + "."
    n = g[p + "block_count"]
    heads = g[p + "attention.head_count"]
    kv = g[p + "attention.head_count_kv"]
    kv = kv if isinstance(kv, list) else [kv] * n
    assert len(kv) == n, f"{model}: head_count_kv has {len(kv)} entries for {n} layers"
    k = g.get(p + "attention.key_length", g[p + "embedding_length"] // heads)
    v = g.get(p + "attention.value_length", k)
    ks = g.get(p + "attention.key_length_swa", k)
    vs = g.get(p + "attention.value_length_swa", v)
    sliding = g.get(p + "attention.sliding_window_pattern", [False] * n)
    assert len(sliding) == n
    return sum(kv[i] * ((ks + vs) if sliding[i] else (k + v)) * 2 for i in range(n))


def _norm(model: str) -> str:
    m = model.strip()
    return m.rsplit("/", 1)[-1].lower()


def _glob(pattern: str, s: str) -> bool:
    return re.fullmatch(".*".join(re.escape(x) for x in pattern.split("*")), s, re.S) is not None


def lookup(model: str):
    """model_capabilities.rs `lookup`: the first row whose globs match."""
    m = _norm(model)
    if not m:
        return None
    return next((r for r in ROWS if any(_glob(p, m) for p in r["match"])), None)


def onboard_pickable() -> dict[str, str]:
    """name -> where onboard's source names it."""
    out: dict[str, str] = {}
    steps = rs.own_code(STEPS.read_text())
    body = rs.fn_body(steps, "fn starter_models")
    for m in re.finditer(r'\(\s*"([a-z0-9.\-]+:[a-z0-9.\-]+)"\s*,\s*"', body):
        out[m.group(1)] = "noo-cli/src/onboard/steps.rs starter_models (offline curated list)"
    m = re.search(r'const PRODUCT_DEFAULT_MODEL: &str = "([^"]+)";', steps)
    assert m, "this guard is stale: PRODUCT_DEFAULT_MODEL moved"
    out[m.group(1)] = "noo-cli/src/onboard/steps.rs PRODUCT_DEFAULT_MODEL"
    cat = rs.fn_body(rs.own_code(CATALOG.read_text()), "pub fn ollama_live_starters")
    fams = re.findall(r'\(\s*"([a-z0-9.\-]+)"\s*,\s*"[A-Za-z ]+"\s*,\s*"[A-Z]+"\s*\)', cat)
    assert fams, "this guard is stale: ollama_live_starters FAMILIES moved"
    for fam in fams:
        tags = FX["registry_plain_tags"].get(fam)
        assert tags, f"onboard's live picker can offer the {fam} family and the fixture lists none of its tags: fetch them (see the fixture's _comment)"
        for t in tags:
            out[f"{fam}:{t}"] = f"noo-cli/src/catalog.rs ollama_live_starters FAMILIES ({fam}, plain size tag {t})"
    run = RUN_SH.read_text()
    m = re.search(r'TINY_MODEL="\$\{TINY_MODEL:-([^}]+)\}"', run)
    assert m, "this guard is stale: TINY_MODEL moved"
    out[m.group(1)] = "scripts/install-cell/run.sh TINY_MODEL (the rehearsal's chat model)"
    return out


def test_the_onboard_pick_list_is_read_from_source():
    names = onboard_pickable()
    for must in ("gemma4:e2b", "qwen3:8b", "llama3.2:3b", "qwen3:4b", "llama3.2:1b", "qwen2.5:0.5b"):
        assert must in names, f"{must} is no longer found in onboard's source: {sorted(names)}"


def test_every_onboard_pickable_model_has_a_kv_row():
    missing = []
    for name, where in sorted(onboard_pickable().items()):
        row = lookup(name)
        if row is None or not row.get("kv_bytes_per_token"):
            missing.append(f"{name} ({where})")
    assert not missing, "no kv_bytes_per_token row for: " + "; ".join(missing)


def test_every_derived_row_is_recomputed_from_the_checked_in_metadata():
    seen = 0
    for row in ROWS:
        src = row.get("kv_source")
        if not row.get("kv_bytes_per_token"):
            continue
        assert src, f"{row['family']}: a kv_bytes_per_token with no kv_source (where was it read?)"
        assert src["fixture"] == "tests/fixtures/model_kv/ollama_gguf_metadata.json"
        assert src["model"] in FX["models"], f"{row['family']}: {src['model']} is not in the fixture"
        assert src["margin"].strip(), f"{row['family']}: the margin kept is not stated"
        full = derive(src["model"])
        if src["basis"] == "derived":
            assert row["kv_bytes_per_token"] == full, f"{row['family']}: row {row['kv_bytes_per_token']} != recomputed {full}"
            seen += 1
        else:
            assert src["basis"] == "measured"
            assert src["full_attention_bytes_per_token"] == full, f"{row['family']}: recorded full-attention figure is stale"
            assert 0 < row["kv_bytes_per_token"] <= full, f"{row['family']}: a measured figure above its own full-attention bound"
        # The row serves the model it was derived for and no other tag of the family.
        assert lookup(src["model"]) is row, f"{src['model']} resolves to another row first"
    assert seen >= 20, seen


def test_the_figures_that_motivated_the_rows():
    # qwen2.5:0.5b: 24 layers x 2 kv heads x 64 head dim x K+V x 2 B = 12 KiB; the
    # floor charged 144 KiB (12x) and refused a reranker placement on a small box.
    assert derive("qwen2.5:0.5b") == 24 * 2 * 64 * 2 * 2 == 12288
    # qwen3:4b: the floor's own origin, 36 x 8 x 128 x 2 x 2 B = 144 KiB.
    assert derive("qwen3:4b") == 144 * 1024


def test_the_fixture_keeps_only_attention_fields_and_a_digest():
    for name, m in FX["models"].items():
        assert re.fullmatch(r"sha256:[0-9a-f]{64}", m["digest"]), name
        arch = m["gguf"]["general.architecture"]
        for k in m["gguf"]:
            assert k == "general.architecture" or k.startswith(arch + "."), (name, k)
