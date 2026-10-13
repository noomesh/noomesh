# SPDX-License-Identifier: AGPL-3.0-only
# Copyright 2026 PersonifAI LLC

"""US-vendor + approved-task model governance (strict allow-list)."""
import os

os.environ.pop("NOO_MODEL_VENDORS", None)
os.environ.pop("NOO_MODEL_TASKS", None)
os.environ["NOO_MODEL_FILTER_MODE"] = "strict"
os.environ.pop("NOO_MODEL_PUBLISHERS", None)
os.environ.pop("NOO_MODEL_PUBLISHER_MODE", None)

from noomesh.cluster.model_catalog import (  # noqa: E402
    BACKEND_SEARCHES, FALLBACK_MODELS, TRUST_FIRST_PARTY, TRUST_OTHER, TRUST_TRUSTED,
    ModelCatalog, _task_fits_backend, filter_approved, is_approved, model_vendor,
    publisher_trust, trust_label,
)


def test_approved_families_pass():
    for mid, vendor in [
        ("google/gemma-4-12B-it", "Google"),
        ("google/gemma-4-E4B-it", "Google"),
        ("unsloth/gemma4-e2b-GGUF", "Google"),
        ("microsoft/Phi-4", "Microsoft"),
        ("microsoft/harrier-oss-v1-0.6b", "Microsoft"),
        ("nvidia/NVIDIA-Nemotron-3-Nano-30B-A3B-NVFP4", "Nvidia"),
        ("nvidia/NV-EmbedCode-7b-v1", "Nvidia"),
        ("meta-llama/Llama-3.1-8B-Instruct", "Meta"),
        ("thinkingmachines/Inkling-Small", "Thinking Machines"),
        ("unsloth/Inkling-Small-GGUF", "Thinking Machines"),
    ]:
        assert is_approved({"id": mid}, "vllm"), mid
        assert model_vendor(mid) == vendor


def test_nonus_and_gemma3_rejected():
    for mid in ["Qwen/Qwen3-8B-AWQ", "ModelCloud/DeepSeek-R1-Distill-Qwen-7B",
                "mistralai/Mistral-Large-Instruct-2411", "01-ai/Yi-34B",
                "google/gemma-3-12b-it",              # gemma-4 series ONLY now
                "bartowski/gemma-3-12b-it-GGUF",      # gemma-3 quant also rejected
                "google/flan-t5-large",               # non-gemma-4 Google rejected
                "philbert440/Qwen3.8-27B-W4A16-AWQ",  # "phi" in a user name is not a vendor
                "dbourget/philai-embeddings-v1.1",    # nor a prefix of a longer word
                "phi010402/finetune-law-embedding"]:
        assert not is_approved({"id": mid}, "vllm"), mid
    for mid in ["phi4", "bartowski/Phi-3.5-mini-instruct-GGUF", "llama3.1:8b", "nemotron-mini"]:
        assert is_approved({"id": mid}, "ollama"), mid


def test_task_axis():
    # ASR + Omni (any-to-any) Nemotron tasks now approved
    assert is_approved({"id": "nvidia/nemotron-3.5-asr-streaming-0.6b",
                        "pipeline_tag": "automatic-speech-recognition"}, "vllm")
    assert is_approved({"id": "nvidia/Nemotron-3-Nano-Omni-30B-A3B-Reasoning-NVFP4",
                        "pipeline_tag": "any-to-any"}, "vllm")
    # vision-capable chat models (Gemma 4 31B/26B, Inkling) are approved
    assert is_approved({"id": "google/gemma-4-31B-it",
                        "pipeline_tag": "image-text-to-text"}, "vllm")
    assert is_approved({"id": "unsloth/Inkling-Small-GGUF",
                        "pipeline_tag": "image-text-to-text"}, "llamacpp")
    # a disallowed task is still rejected
    assert not is_approved({"id": "nvidia/some-image-model",
                            "pipeline_tag": "image-classification"}, None)


def test_search_queries_do_not_require_instruct_token():
    # HF ANDs every search token against the repo id; Google spells it `-it`
    # and Phi-4 / Nemotron-3 / Inkling have no suffix, so an "instruct" token
    # hid every non-Llama family.
    for backend, queries in BACKEND_SEARCHES.items():
        for q in queries:
            assert "instruct" not in q.lower(), f"{backend}: {q}"
    assert "gemma-4 GGUF" in BACKEND_SEARCHES["llamacpp"]
    assert "inkling AWQ" in BACKEND_SEARCHES["vllm"]
    assert "nvidia embed" in BACKEND_SEARCHES["embedding"]


def test_task_axis_is_per_backend():
    assert _task_fits_backend("image-text-to-text", "llamacpp")
    assert _task_fits_backend("any-to-any", "vllm")
    assert _task_fits_backend(None, "vllm")
    assert not _task_fits_backend("feature-extraction", "vllm")
    assert _task_fits_backend("sentence-similarity", "embedding")
    assert not _task_fits_backend("text-generation", "embedding")


def test_strict_filters_and_off_passes():
    mixed = [{"id": "google/gemma-4-E4B-it"}, {"id": "Qwen/Qwen3-8B-AWQ"}]
    assert [m["id"] for m in filter_approved(list(mixed), "vllm")] == ["google/gemma-4-E4B-it"]
    os.environ["NOO_MODEL_FILTER_MODE"] = "off"
    assert len(filter_approved(list(mixed), "vllm")) == 2
    os.environ["NOO_MODEL_FILTER_MODE"] = "strict"


def test_publisher_tiers():
    assert publisher_trust("google/gemma-4-12B-it-qat-q4_0-gguf") == ("google", TRUST_FIRST_PARTY)
    assert publisher_trust("nvidia/Gemma-4-31B-IT-NVFP4") == ("nvidia", TRUST_FIRST_PARTY)
    assert publisher_trust("thinkingmachines/Inkling") == ("thinkingmachines", TRUST_FIRST_PARTY)
    assert publisher_trust("unsloth/gemma-4-12B-it-qat-GGUF") == ("unsloth", TRUST_TRUSTED)
    assert publisher_trust("cyankiwi/gemma-4-26B-A4B-it-AWQ-4bit") == ("cyankiwi", TRUST_OTHER)
    assert publisher_trust("phi4") == ("library", TRUST_FIRST_PARTY)   # Ollama-library fallback id
    assert trust_label(TRUST_OTHER) == "other"


def test_first_party_outranks_downloads():
    models = [
        {"id": "cyankiwi/gemma-4-26B-A4B-it-AWQ-4bit", "downloads": 2_374_050},
        {"id": "unsloth/gemma-4-12B-it-qat-GGUF", "downloads": 1_249_309},
        {"id": "google/gemma-4-12B-it-qat-q4_0-gguf", "downloads": 711_630},
        {"id": "HauhauCS/Gemma-4-E4B-Uncensored", "downloads": 2_562_002},
    ]
    out = filter_approved(models, "llamacpp")
    assert [m["id"] for m in out] == [
        "google/gemma-4-12B-it-qat-q4_0-gguf",
        "unsloth/gemma-4-12B-it-qat-GGUF",
        "HauhauCS/Gemma-4-E4B-Uncensored",     # tier 3, but more downloads than cyankiwi
        "cyankiwi/gemma-4-26B-A4B-it-AWQ-4bit",
    ]
    assert out[0]["publisher"] == "google" and out[0]["trust"] == TRUST_FIRST_PARTY
    os.environ["NOO_MODEL_PUBLISHER_MODE"] = "strict"
    try:
        assert [m["trust"] for m in filter_approved(list(models), "llamacpp")] == [1, 2]
    finally:
        os.environ.pop("NOO_MODEL_PUBLISHER_MODE", None)


def test_enrich_stamps_publisher():
    m = ModelCatalog().enrich_model({"id": "unsloth/Inkling-Small-GGUF"})
    assert (m["publisher"], m["trust"]) == ("unsloth", TRUST_TRUSTED)


def test_fallback_catalog_is_all_approved():
    for backend, models in FALLBACK_MODELS.items():
        for m in models:
            assert is_approved(m, backend), f"{backend}: {m['id']} not approved"


if __name__ == "__main__":
    for fn in [test_approved_families_pass, test_nonus_and_gemma3_rejected, test_task_axis,
               test_search_queries_do_not_require_instruct_token, test_task_axis_is_per_backend,
               test_publisher_tiers, test_first_party_outranks_downloads, test_enrich_stamps_publisher,
               test_strict_filters_and_off_passes, test_fallback_catalog_is_all_approved]:
        fn()
    print("all model-vendor governance tests passed")
