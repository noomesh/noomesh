# SPDX-License-Identifier: AGPL-3.0-only
# Copyright 2026 PersonifAI LLC

"""model_cache.json write safety (WP-C hazard 2).

The cache file is shared between the Python ModelCatalog and the Rust CLI
(noo-cli/src/catalog.rs). Both used to do unlocked whole-file
read-modify-write: concurrent refreshes lost each other's backend entries
and a mid-write crash left truncated JSON. `_write_cache` now takes an
flock on `model_cache.json.lock`, re-reads the file FRESH under the lock,
and lands the result via tmp+rename.

Byte-shape stays pinned: top-level keys are exactly
catalogs / fetched_at / ttl_hours (the Rust round-trip tests in
noo-cli/tests/gateway_integration.rs read this file back).
"""
import json
import threading

from noomesh.cluster.model_catalog import ModelCatalog


def _catalog(tmp_path):
    return ModelCatalog(cache_file=tmp_path / "model_cache.json")


def test_out_of_band_entry_survives_write(tmp_path):
    cat = _catalog(tmp_path)
    cat._write_cache("ollama", [{"id": "m1"}])

    # Another process (e.g. the Rust CLI) writes a different backend.
    on_disk = json.loads(cat.cache_file.read_text(encoding="utf-8"))
    on_disk["catalogs"]["vllm"] = [{"id": "other-proc"}]
    cat.cache_file.write_text(json.dumps(on_disk), encoding="utf-8")

    # This instance's in-memory copy is stale; the write must still keep
    # the out-of-band vllm entry (fresh read under the lock).
    cat._write_cache("llamacpp", [{"id": "m2"}])

    final = json.loads(cat.cache_file.read_text(encoding="utf-8"))
    assert final["catalogs"]["ollama"] == [{"id": "m1"}]
    assert final["catalogs"]["vllm"] == [{"id": "other-proc"}]
    assert final["catalogs"]["llamacpp"] == [{"id": "m2"}]


def test_shape_and_no_tmp_leftovers(tmp_path):
    cat = _catalog(tmp_path)
    cat._write_cache("ollama", [{"id": "m1"}])

    leftovers = [p.name for p in tmp_path.iterdir() if ".tmp" in p.name]
    assert leftovers == [], f"tmp files left behind: {leftovers}"

    doc = json.loads(cat.cache_file.read_text(encoding="utf-8"))
    assert sorted(doc.keys()) == ["catalogs", "fetched_at", "ttl_hours"]
    assert doc["ttl_hours"] == cat.ttl_hours
    assert "ollama" in doc["fetched_at"]


def test_corrupt_cache_is_recovered_not_crashed(tmp_path):
    cat = _catalog(tmp_path)
    cat.cache_file.parent.mkdir(parents=True, exist_ok=True)
    cat.cache_file.write_text("{truncated", encoding="utf-8")

    cat._write_cache("ollama", [{"id": "m1"}])

    doc = json.loads(cat.cache_file.read_text(encoding="utf-8"))
    assert doc["catalogs"]["ollama"] == [{"id": "m1"}]


def test_concurrent_writers_keep_every_backend(tmp_path):
    path = tmp_path / "model_cache.json"

    def write(i):
        cat = ModelCatalog(cache_file=path)
        cat._write_cache(f"backend{i}", [{"id": i}])

    threads = [threading.Thread(target=write, args=(i,)) for i in range(6)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()

    doc = json.loads(path.read_text(encoding="utf-8"))
    for i in range(6):
        assert doc["catalogs"][f"backend{i}"] == [{"id": i}], (
            f"backend{i} entry lost under concurrency: {doc}"
        )


def test_read_cache_roundtrip_unchanged(tmp_path):
    # The reader still sees exactly what the writer wrote (TTL fresh).
    cat = _catalog(tmp_path)
    models = [{"id": "m1", "params_b": 3, "quant": "GGUF"}]
    cat._write_cache("ollama", models)
    # New instance → cold read from disk.
    cat2 = ModelCatalog(cache_file=cat.cache_file)
    assert cat2._read_cache("ollama") == models
