# SPDX-License-Identifier: AGPL-3.0-only
# Copyright 2026 PersonifAI LLC

"""
Mesh - Adaptive Model Catalog

Live-fetching model catalog that queries HuggingFace for current models,
classifies them by tier/backend, caches results locally, and falls back
to a minimal offline list when the API is unreachable.
"""

from __future__ import annotations

import os

from .. import json_fast as json
import re
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import httpx

# ---------------------------------------------------------------------------
# Cache location
# ---------------------------------------------------------------------------
CACHE_DIR = Path.home() / ".config" / "mesh"
CACHE_FILE = CACHE_DIR / "model_cache.json"
CACHE_TTL_HOURS = 24

# ---------------------------------------------------------------------------
# ---------------------------------------------------------------------------
# Approved-vendor / approved-task model governance (US-vendor focus)
# ---------------------------------------------------------------------------
# A model is ALLOWED only when its family is an approved vendor AND its task is
# approved. Strict by default — non-approved models are hidden from listing,
# search, and (therefore) auto-placement. Configurable via env:
#   NOO_MODEL_VENDORS      comma families (default below)
#   NOO_MODEL_TASKS        comma HF pipeline tags (default below)
#   NOO_MODEL_FILTER_MODE  strict (default) | prefer | off
# This is model-supply-chain governance: only
# US-vendor open models (Google/Microsoft/Nvidia/Meta) are considered.
_DEFAULT_VENDORS: dict[str, str] = {
    "gemma-4": "Google",      # gemma-4 series ONLY (not gemma-3/gemma-2)
    "gemma4": "Google",       # unhyphenated spelling (Ollama tags, some re-uploads)
    "phi": "Microsoft",
    "harrier": "Microsoft",   # microsoft/harrier-oss-v1-* (HF→GGUF→Ollama; see MODEL_CONVERSION.md)
    "nemotron": "Nvidia",
    "minitron": "Nvidia",
    "llama": "Meta",
    "inkling": "Thinking Machines",
}
_DEFAULT_TASKS = {
    "text-generation",
    "image-text-to-text",             # Gemma 4 31B/26B, Inkling — vision-capable chat models
    "feature-extraction", "sentence-similarity",
    "automatic-speech-recognition",   # Nemotron ASR
    "any-to-any",                     # Nemotron Omni, Gemma 4 E2B/E4B/12B (multimodal)
}
# HF orgs owned by each vendor — any model under one of these orgs is approved
# (catches vendor models that don't carry the family name, e.g. nvidia/NV-Embed).
# Google is intentionally OMITTED: approve only the `gemma-4` family, not every
# google/ model (so gemma-3 and other Google models are excluded).
_VENDOR_ORGS: dict[str, list[str]] = {
    "Microsoft": ["microsoft"],
    "Nvidia": ["nvidia"],
    "Meta": ["meta-llama", "meta"],
    "Thinking Machines": ["thinkingmachines"],
}

# ---------------------------------------------------------------------------
# Publisher trust — WHO uploaded the repo, independent of WHOSE model it is
# ---------------------------------------------------------------------------
# Download count alone ranks a prolific third-party quantizer above the
# vendor's own upload. Three tiers, primary sort key ahead of downloads:
#   1  first-party  — the vendor's own org (google/, nvidia/, microsoft/ …)
#   2  trusted      — well-known quantizer accounts (curated, overridable)
#   3  other        — everyone else (unknown accounts, abliterated forks)
# Ranking, not filtering, is the default (NOO_MODEL_PUBLISHER_MODE=prefer):
# a first-party repo is often the unquantized bf16 release, and for some
# model/backend pairs a third-party quant is the only option.
TRUST_FIRST_PARTY, TRUST_TRUSTED, TRUST_OTHER = 1, 2, 3
# Google is a first-party PUBLISHER even though it is deliberately not an
# approved ORG (the vendor axis admits only the gemma-4 family).
_EXTRA_FIRST_PARTY_ORGS = {"google"}
_DEFAULT_TRUSTED_PUBLISHERS = [
    "unsloth", "bartowski", "lmstudio-community", "hugging-quants", "ggml-org",
    "redhatai", "maziyarpanahi", "ista-daslab", "mlx-community",
]


def trusted_publishers() -> set[str]:
    raw = os.getenv("NOO_MODEL_PUBLISHERS", "").strip()
    if raw:
        return {p.strip().lower() for p in raw.split(",") if p.strip()}
    return set(_DEFAULT_TRUSTED_PUBLISHERS)


def _is_first_party_org(org: str) -> bool:
    return org in _EXTRA_FIRST_PARTY_ORGS or any(org in orgs for orgs in _VENDOR_ORGS.values())


def publisher_trust(model_id: str) -> tuple[str, int]:
    """(publisher, trust tier). Ollama-library ids with no org (phi4,
    llama3.1:8b) are the curated fallback entries — first-party."""
    mid = (model_id or "").lower()
    if "/" not in mid:
        return "library", TRUST_FIRST_PARTY
    org = mid.split("/", 1)[0]
    if _is_first_party_org(org):
        return org, TRUST_FIRST_PARTY
    if org in trusted_publishers():
        return org, TRUST_TRUSTED
    return org, TRUST_OTHER


def trust_label(tier: int) -> str:
    return {TRUST_FIRST_PARTY: "first-party", TRUST_TRUSTED: "trusted"}.get(tier, "other")


def _rank_by_publisher(models: list[dict]) -> list[dict]:
    """Annotate publisher/trust and order by trust tier, then downloads.
    strict also drops tier-3 repos; off leaves the download order alone."""
    mode = os.getenv("NOO_MODEL_PUBLISHER_MODE", "prefer").strip().lower()
    for m in models:
        m["publisher"], m["trust"] = publisher_trust(m.get("id", ""))
    if mode == "off":
        return models
    if mode == "strict":
        models = [m for m in models if m["trust"] < TRUST_OTHER]
    return sorted(models, key=lambda m: (m["trust"], -(m.get("downloads") or 0)))


def approved_vendors() -> dict[str, str]:
    raw = os.getenv("NOO_MODEL_VENDORS", "").strip()
    if not raw:
        return dict(_DEFAULT_VENDORS)
    return {f.strip().lower(): _DEFAULT_VENDORS.get(f.strip().lower(), f.strip())
            for f in raw.split(",") if f.strip()}


def approved_tasks() -> set[str]:
    raw = os.getenv("NOO_MODEL_TASKS", "").strip()
    return {t.strip() for t in raw.split(",") if t.strip()} if raw else set(_DEFAULT_TASKS)


def _approved_orgs() -> dict[str, str]:
    """HF org -> vendor label, derived from the currently-approved vendors."""
    out: dict[str, str] = {}
    for label in set(approved_vendors().values()):
        # No default org — a vendor without an explicit entry (e.g. Google) is
        # matched by family name only, so 'gemma-4' doesn't approve all google/.
        for org in _VENDOR_ORGS.get(label, []):
            out[org] = label
    return out


def _family_in(name: str, fam: str) -> bool:
    """`fam` occurs in `name` as a family token: followed by the end of the
    name or a non-letter (phi-4, phi4, Phi-3.5), never as a prefix of a
    longer word (philai, philbert)."""
    start = 0
    while (i := name.find(fam, start)) != -1:
        nxt = name[i + len(fam):i + len(fam) + 1]
        if not nxt or not nxt.isalpha():
            return True
        start = i + 1
    return False


def model_vendor(model_id: str) -> str | None:
    """Vendor label for a model id via its HF org (nvidia/…) or an approved
    family name in the repo-name part of the id (so third-party quant
    re-uploads like unsloth/gemma-4-…-GGUF still resolve to their vendor).
    The org part is only consulted against _VENDOR_ORGS — a family substring
    in a user name (philbert440/Qwen…) is not a vendor signal."""
    mid = (model_id or "").lower()
    if "/" in mid:
        org = mid.split("/", 1)[0]
        if org in _approved_orgs():
            return _approved_orgs()[org]
    name = mid.rsplit("/", 1)[-1]
    vendors = approved_vendors()
    for fam in vendors:
        if _family_in(name, fam):
            return vendors[fam]
    return None


def model_family(model_id: str) -> str | None:
    return model_vendor(model_id)


def _backend_task(backend: str | None) -> str:
    return "feature-extraction" if backend == "embedding" else "text-generation"


def is_approved(model: dict, backend: str | None = None) -> bool:
    if model_family(model.get("id", "")) is None:
        return False
    task = model.get("pipeline_tag") or _backend_task(backend)
    tasks = approved_tasks()
    return not (task and tasks and task not in tasks)


def filter_approved(models: list[dict], backend: str | None = None) -> list[dict]:
    """Apply the vendor+task allow-list. strict → approved only; prefer →
    approved first with the rest tagged unapproved; off → passthrough."""
    mode = os.getenv("NOO_MODEL_FILTER_MODE", "strict").strip().lower()
    if mode == "off":
        return _rank_by_publisher(models)
    approved, rest = [], []
    for m in models:
        if is_approved(m, backend):
            m["vendor"] = model_vendor(m.get("id", ""))
            approved.append(m)
        else:
            rest.append(m)
    approved = _rank_by_publisher(approved)
    if mode == "prefer":
        rest = _rank_by_publisher(rest)
        for m in rest:
            m["unapproved"] = True
        return approved + rest
    return approved  # strict


# Backend-specific HF search strategies — vendor-targeted so the live HF fetch
# surfaces approved families first (built from approved_vendors()).
#
# Family + format only. HF `search` ANDs every token against the repo id, and
# most approved families do not spell "instruct" in the id (Google uses `-it`,
# Phi-4 / Nemotron-3 / Inkling carry no suffix at all) — an "instruct" token
# silently reduced the catalog to Llama plus a couple of Phi minis.
def _vendor_searches(suffix: str) -> list[str]:
    return [f"{fam} {suffix}" for fam in approved_vendors()]


BACKEND_SEARCHES: dict[str, list[str]] = {
    "vllm": _vendor_searches("AWQ") + _vendor_searches("GPTQ"),
    "llamacpp": _vendor_searches("GGUF"),
    "ollama": _vendor_searches("GGUF"),
    "airllm": _vendor_searches("safetensors"),
    # "embed" rather than "embedding": first-party embedders are NV-Embed-v2,
    # Nemotron-3-Embed-1B, llama-nemotron-embed-…; org-scoped queries catch the
    # ones that carry no family name.
    "embedding": _vendor_searches("embed") + [f"{org} embed" for org in _approved_orgs()],
}

_EMBED_TASKS = {"feature-extraction", "sentence-similarity"}


def _task_fits_backend(pipeline_tag: str | None, backend: str) -> bool:
    """HF `filter=` is an AND over tags, so the task axis is applied
    client-side: a single `filter=text-generation` on the request dropped
    every vision-capable chat model (Gemma 4 is `image-text-to-text` /
    `any-to-any`) and, for the embedding backend, every actual embedding
    model. Untagged repos pass — the backend default applies in is_approved."""
    if not pipeline_tag:
        return True
    return (pipeline_tag in _EMBED_TASKS) == (backend == "embedding")

# ---------------------------------------------------------------------------
# Quantization patterns
# ---------------------------------------------------------------------------
_QUANT_RE = re.compile(
    r"(AWQ|GPTQ|EXL2|GGUF|Q[2-8]_[KSM0-9_]+|[Qq]uant)", re.IGNORECASE
)
_HEAVY_QUANT_RE = re.compile(r"Q[23]_[KSM]", re.IGNORECASE)
_LIGHT_QUANT_RE = re.compile(r"Q[45678]_[KSM]", re.IGNORECASE)

# ---------------------------------------------------------------------------
# Common VRAM-estimation helpers
# ---------------------------------------------------------------------------
_PARAM_RE = re.compile(r"(\d+(?:\.\d+)?)\s*[Bb]", re.IGNORECASE)


def _extract_param_count(model_id: str, tags: list[str] | None = None) -> float | None:
    """Try to extract parameter count (in billions) from model name or tags."""
    for source in [model_id] + (tags or []):
        m = _PARAM_RE.search(source)
        if m:
            return float(m.group(1))
    return None


# ---------------------------------------------------------------------------
# Fallback catalog (offline, updated Feb 2026)
# ---------------------------------------------------------------------------
FALLBACK_MODELS: dict[str, list[dict[str, Any]]] = {
    # US-vendor only: Google (gemma-4 series), Microsoft (Phi/Harrier),
    # Nvidia (Nemotron-3 / NV-Embed), Meta (Llama). Live HF results are filtered
    # by the same allow-list; this mirrors it offline.
    "vllm": [
        {"id": "google/gemma-4-12B-it", "params_b": 12, "quant": "none", "gated": "Open", "downloads": 400_000, "tool_parser": "gemma4", "reasoning_parser": "gemma4", "desc": "Gemma 4 12B — primary, native tool calling, multimodal"},
        {"id": "google/gemma-4-E4B-it", "params_b": 4, "quant": "none", "gated": "Open", "downloads": 500_000, "tool_parser": "gemma4", "reasoning_parser": "gemma4", "desc": "Gemma 4 E4B — native tool calling, ~8 GB"},
        {"id": "google/gemma-4-E2B-it", "params_b": 2, "quant": "none", "gated": "Open", "downloads": 300_000, "tool_parser": "gemma4", "reasoning_parser": "gemma4", "desc": "Gemma 4 E2B — edge, ~4 GB"},
        {"id": "microsoft/harrier-oss-v1-0.6b", "params_b": 0.6, "quant": "none", "gated": "Open", "downloads": 100_000, "tool_parser": "hermes", "desc": "Microsoft Harrier OSS v1 0.6B — edge (HF→GGUF→Ollama, see MODEL_CONVERSION.md)"},
        {"id": "microsoft/Phi-4", "params_b": 14, "quant": "none", "gated": "Open", "downloads": 500_000, "tool_parser": "hermes", "desc": "Phi-4 14B — strong reasoning, dense"},
        {"id": "nvidia/NVIDIA-Nemotron-3-Nano-30B-A3B-NVFP4", "params_b": 30, "quant": "NVFP4", "gated": "Open", "downloads": 1_580_000, "tool_parser": "hermes", "desc": "Nemotron-3 Nano 30B-A3B (NVFP4) — MoE, ~3B active, fits mid GPU"},
        {"id": "nvidia/NVIDIA-Nemotron-3-Super-120B-A12B-NVFP4", "params_b": 120, "quant": "NVFP4", "gated": "Open", "downloads": 385_000, "tool_parser": "hermes", "desc": "Nemotron-3 Super 120B-A12B (NVFP4) — MoE flagship"},
        {"id": "nvidia/Nemotron-3-Nano-Omni-30B-A3B-Reasoning-NVFP4", "params_b": 30, "quant": "NVFP4", "gated": "Open", "downloads": 2_160_000, "pipeline_tag": "any-to-any", "desc": "Nemotron-3 Nano Omni 30B-A3B (NVFP4) — multimodal any-to-any, reasoning"},
        {"id": "nvidia/nemotron-3.5-asr-streaming-0.6b", "params_b": 0.6, "quant": "none", "gated": "Open", "downloads": 276_000, "pipeline_tag": "automatic-speech-recognition", "desc": "Nemotron 3.5 ASR streaming 0.6B — speech recognition"},
        {"id": "meta-llama/Llama-3.1-8B-Instruct", "params_b": 8, "quant": "none", "gated": "Gated", "downloads": 3_000_000, "tool_parser": "llama3_json", "desc": "Llama 3.1 8B — proven, tool calling"},
    ],
    "llamacpp": [
        {"id": "unsloth/NVIDIA-Nemotron-3-Nano-30B-A3B-NVFP4", "params_b": 30, "quant": "GGUF", "gated": "Open", "downloads": 20_000, "desc": "Nemotron-3 Nano 30B-A3B GGUF/NVFP4 (unsloth) — MoE"},
        {"id": "unsloth/NVIDIA-Nemotron-3-Super-120B-A12B-GGUF", "params_b": 120, "quant": "GGUF", "gated": "Open", "downloads": 11_300, "desc": "Nemotron-3 Super 120B-A12B GGUF (unsloth)"},
        {"id": "bartowski/microsoft_Phi-4-GGUF", "params_b": 14, "quant": "GGUF", "gated": "Open", "downloads": 300_000, "desc": "Phi-4 14B GGUF"},
        {"id": "harrier-oss-v1-0.6b", "params_b": 0.6, "quant": "GGUF", "gated": "Open", "downloads": 0, "desc": "Microsoft Harrier 0.6B — locally converted GGUF (see MODEL_CONVERSION.md)"},
        {"id": "bartowski/Meta-Llama-3.1-8B-Instruct-GGUF", "params_b": 8, "quant": "GGUF", "gated": "Open", "downloads": 700_000, "desc": "Llama 3.1 8B GGUF"},
        {"id": "bartowski/Llama-3.2-3B-Instruct-GGUF", "params_b": 3, "quant": "GGUF", "gated": "Open", "downloads": 500_000, "desc": "Llama 3.2 3B GGUF — 4-6 GB"},
        {"id": "bartowski/Llama-3.2-1B-Instruct-GGUF", "params_b": 1, "quant": "GGUF", "gated": "Open", "downloads": 400_000, "desc": "Llama 3.2 1B GGUF — RPi / 2 GB"},
    ],
    "ollama": [
        {"id": "phi4", "params_b": 14, "quant": "GGUF", "gated": "Open", "downloads": 700_000, "desc": "Microsoft Phi-4 14B"},
        {"id": "harrier-oss-v1-0.6b", "params_b": 0.6, "quant": "GGUF", "gated": "Open", "downloads": 0, "desc": "Microsoft Harrier 0.6B — locally converted (ollama create)"},
        {"id": "llama3.1:8b", "params_b": 8, "quant": "GGUF", "gated": "Open", "downloads": 5_000_000, "desc": "Meta Llama 3.1 8B — proven, tool calling"},
        {"id": "llama3.2:3b", "params_b": 3, "quant": "GGUF", "gated": "Open", "downloads": 3_000_000, "desc": "Meta Llama 3.2 3B — lightweight"},
        {"id": "llama3.2:1b", "params_b": 1, "quant": "GGUF", "gated": "Open", "downloads": 2_000_000, "desc": "Meta Llama 3.2 1B — RPi / 2 GB"},
        {"id": "nemotron-mini", "params_b": 4, "quant": "GGUF", "gated": "Open", "downloads": 150_000, "desc": "Nvidia Nemotron-Mini 4B — edge, tool calling"},
    ],
    "airllm": [
        {"id": "nvidia/NVIDIA-Nemotron-3-Ultra-550B-A55B-BF16", "params_b": 561, "quant": None, "gated": "Open", "downloads": 115_000, "desc": "Nemotron-3 Ultra 550B-A55B — flagship MoE, layer-by-layer"},
        {"id": "nvidia/NVIDIA-Nemotron-3-Super-120B-A12B-BF16", "params_b": 124, "quant": None, "gated": "Open", "downloads": 1_180_000, "desc": "Nemotron-3 Super 120B-A12B — layer-by-layer"},
        {"id": "meta-llama/Llama-3.1-405B-Instruct", "params_b": 405, "quant": None, "gated": "Gated", "downloads": 300_000, "desc": "Llama 3.1 405B — flagship, layer-by-layer"},
    ],
    "embedding": [
        {"id": "nvidia/NV-EmbedCode-7b-v1", "params_b": 7, "quant": "none", "gated": "Open", "downloads": 150_000, "pipeline_tag": "feature-extraction", "desc": "Nvidia NV-EmbedCode 7B v1 — code retrieval embeddings"},
        {"id": "nvidia/NV-Embed-v2", "params_b": 7, "quant": "none", "gated": "Open", "downloads": 300_000, "pipeline_tag": "feature-extraction", "desc": "Nvidia NV-Embed v2 — top MTEB retrieval"},
        {"id": "nvidia/llama-3.2-nv-embedqa-1b-v2", "params_b": 1, "quant": "none", "gated": "Open", "downloads": 100_000, "pipeline_tag": "feature-extraction", "desc": "Nvidia Llama-3.2 NV-EmbedQA 1B — light QA retrieval"},
    ],
}


class ModelCatalog:
    """Live-fetching model catalog with caching and classification."""

    def __init__(self, cache_file: Path = CACHE_FILE, ttl_hours: int = CACHE_TTL_HOURS):
        self.cache_file = cache_file
        self.ttl_hours = ttl_hours
        self._cache: dict[str, Any] | None = None

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def fetch_models(
        self,
        backend: str,
        tier: int | None = None,
        limit: int = 20,
        refresh: bool = False,
    ) -> list[dict[str, Any]]:
        """Fetch models for a backend, using cache or HF API.

        Returns a list of dicts with keys:
            id, params_b, quant, gated, downloads, likes, desc, backends, tier, size_estimate
        """
        if not refresh:
            cached = self._read_cache(backend)
            if cached is not None:
                return self._filter_tier(filter_approved(cached, backend), tier)[:limit]

        try:
            models = self._fetch_from_hf(backend, limit=limit * 3)
            self._write_cache(backend, models)
        except Exception:
            # HF unreachable — try stale cache, then fallback
            cached = self._read_cache(backend, ignore_ttl=True)
            if cached is not None:
                return self._filter_tier(filter_approved(cached, backend), tier)[:limit]
            models = FALLBACK_MODELS.get(backend, [])

        return self._filter_tier(filter_approved(models, backend), tier)[:limit]

    def search_models(self, query: str, backend: str | None = None, limit: int = 15) -> list[dict[str, Any]]:
        """Live search HF API with a user query. Falls back to cached catalog."""
        try:
            raw = self._hf_search(query, limit=limit)
            return filter_approved([self._normalize(m) for m in raw], backend)[:limit]
        except Exception:
            # Fall back to searching cached/fallback data
            results = []
            backends = [backend] if backend else list(BACKEND_SEARCHES.keys())
            query_lower = query.lower()
            for b in backends:
                cached = self._read_cache(b, ignore_ttl=True)
                source = cached if cached is not None else FALLBACK_MODELS.get(b, [])
                for m in source:
                    if query_lower in m.get("id", "").lower() or query_lower in m.get("desc", "").lower():
                        results.append(m)
            return filter_approved(results, backend)[:limit]

    def model_info(self, model_id: str) -> dict[str, Any] | None:
        """Fetch detailed info for a single model from HF."""
        try:
            with httpx.Client(timeout=10) as client:
                resp = client.get(f"https://huggingface.co/api/models/{model_id}")
                resp.raise_for_status()
                data = resp.json()
            return self._normalize_detail(data)
        except Exception:
            return None

    def cache_age_text(self, backend: str) -> str:
        """Human-readable cache freshness string."""
        cache = self._load_cache_file()
        if not cache:
            return "No cache"
        entry = cache.get("catalogs", {}).get(backend)
        if not entry:
            return "No cache"
        fetched_at = cache.get("fetched_at", {}).get(backend)
        if not fetched_at:
            return "No cache"
        try:
            dt = datetime.fromisoformat(fetched_at)
            age = datetime.now(timezone.utc) - dt
            hours = int(age.total_seconds() / 3600)
            if hours < 1:
                mins = int(age.total_seconds() / 60)
                return f"{mins} minute{'s' if mins != 1 else ''} ago"
            if hours < 24:
                return f"{hours} hour{'s' if hours != 1 else ''} ago"
            days = hours // 24
            return f"{days} day{'s' if days != 1 else ''} ago"
        except Exception:
            return "Unknown"

    # ------------------------------------------------------------------
    # Classification helpers (public for reuse)
    # ------------------------------------------------------------------

    @staticmethod
    def classify_tier(params_b: float | None, quant: str | None) -> int:
        """Assign a hardware tier (1/2/3) based on parameter count and quantization."""
        if params_b is None:
            return 1  # default to tier 1 if unknown

        is_quantized = quant is not None and quant.upper() not in ("", "NONE")
        is_heavy_quant = bool(_HEAVY_QUANT_RE.search(quant)) if quant else False

        if params_b <= 3:
            return 3
        if params_b <= 7:
            if is_heavy_quant:
                return 3
            if is_quantized:
                return 2
            return 2
        if params_b <= 14:
            if is_quantized:
                return 1
            return 1
        # 14B+
        return 1

    @staticmethod
    def is_arm(arch: str | None) -> bool:
        """True for arm/aarch64 CPU architectures (edge boards, Apple silicon)."""
        a = (arch or "").lower()
        return "arm" in a or "aarch" in a

    @staticmethod
    def backends_for(tier: int, arch: str | None = None) -> list[str]:
        """Inference backends compatible with a node's hardware *tier* and CPU
        *arch*. Bigger tier = weaker hardware (1 GPU worker … 4 edge, 5
        companion). arm/aarch64 nodes drop GPU/x86-only backends (vllm, airllm)
        and rely on GGUF (llama.cpp / ollama) — this is why an arm edge box like
        host9 must never be offered a vLLM model."""
        if tier <= 1:
            base = ["vllm", "llamacpp", "ollama", "airllm"]
        elif tier == 2:
            base = ["vllm", "llamacpp", "ollama"]
        elif tier == 3:
            base = ["llamacpp", "ollama"]
        else:  # 4 edge, 5 companion — GGUF only
            base = ["llamacpp", "ollama"]
        if ModelCatalog.is_arm(arch):
            base = [b for b in base if b not in ("vllm", "airllm")]
        return base

    @staticmethod
    def model_class_for(tier: int) -> int | None:
        """Which model size-class (classify_tier value) to recommend for a
        hardware tier. None = no cap (tier 1 runs anything). Tiers 3/4/5 map to
        the smallest class (3), so edge/companion nodes only see models that
        actually fit."""
        if tier <= 1:
            return None
        if tier == 2:
            return 2
        return 3

    @staticmethod
    def detect_backend_compat(tags: list[str], siblings: list[dict] | None = None) -> list[str]:
        """Determine which backends can run this model from HF tags/files."""
        tags_lower = {t.lower() for t in tags}
        backends = []
        file_names = []
        if siblings:
            file_names = [s.get("rfilename", "").lower() for s in siblings]

        has_gguf = "gguf" in tags_lower or any(f.endswith(".gguf") for f in file_names)
        has_awq = "awq" in tags_lower or any("awq" in t for t in tags_lower)
        has_gptq = "gptq" in tags_lower or any("gptq" in t for t in tags_lower)
        has_safetensors = "safetensors" in tags_lower or any(f.endswith(".safetensors") for f in file_names)

        if has_awq or has_gptq:
            backends.append("vllm")
        if has_gguf:
            backends.append("llamacpp")
            backends.append("ollama")
        if has_safetensors and not (has_awq or has_gptq or has_gguf):
            backends.append("airllm")
            backends.append("vllm")

        return backends if backends else ["unknown"]

    @staticmethod
    def parse_gated(gated_field: Any) -> str:
        """Translate HF gated field to human label."""
        if gated_field is False or gated_field == "false":
            return "Open"
        if gated_field == "auto":
            return "Login"
        if gated_field == "manual" or gated_field is True or gated_field == "true":
            return "Gated"
        return "Open"

    @staticmethod
    def estimate_size(model_data: dict[str, Any]) -> str:
        """Estimate download size as a human string."""
        # Try safetensors.total (bytes)
        st = model_data.get("safetensors", {})
        if isinstance(st, dict) and st.get("total"):
            return _fmt_bytes(st["total"])

        # Try usedStorage
        used = model_data.get("usedStorage")
        if used:
            return _fmt_bytes(used)

        # Infer from param count
        params_b = model_data.get("params_b")
        if params_b:
            quant = model_data.get("quant")
            if quant and quant.upper() in ("AWQ", "GPTQ"):
                return _fmt_bytes(int(params_b * 0.5e9))  # ~0.5 bytes/param for 4-bit
            if quant and "GGUF" in quant.upper():
                return _fmt_bytes(int(params_b * 0.6e9))  # ~Q4-Q5 average
            return _fmt_bytes(int(params_b * 2e9))  # fp16

        return "?"

    # ------------------------------------------------------------------
    # HF API internals
    # ------------------------------------------------------------------

    def _fetch_from_hf(self, backend: str, limit: int = 60) -> list[dict[str, Any]]:
        """Query HF API with backend-specific search terms, deduplicate, normalize."""
        searches = BACKEND_SEARCHES.get(backend, [])
        seen_ids: set[str] = set()
        results: list[dict[str, Any]] = []

        for query in searches:
            raw = self._hf_search(query, limit=limit)
            for m in raw:
                mid = m.get("modelId", m.get("id", ""))
                if mid in seen_ids:
                    continue
                seen_ids.add(mid)
                if not _task_fits_backend(m.get("pipeline_tag"), backend):
                    continue
                normed = self._normalize(m)
                results.append(normed)

        # Sort by downloads descending
        results.sort(key=lambda x: x.get("downloads", 0), reverse=True)
        return results

    def _hf_search(self, query: str, limit: int = 30) -> list[dict]:
        """Raw HF /api/models search."""
        with httpx.Client(timeout=15) as client:
            resp = client.get(
                "https://huggingface.co/api/models",
                params={
                    "search": query,
                    "limit": limit,
                    "sort": "downloads",
                    "direction": "-1",
                    "full": "true",
                },
            )
            resp.raise_for_status()
            return resp.json()

    def _normalize(self, m: dict) -> dict[str, Any]:
        """Normalize an HF API model result into our standard schema."""
        model_id = m.get("modelId", m.get("id", ""))
        tags = m.get("tags", [])
        siblings = m.get("siblings")
        params_b = _extract_param_count(model_id, tags)

        # Try to get param count from safetensors info
        if params_b is None:
            st = m.get("safetensors", {})
            if isinstance(st, dict) and st.get("parameters"):
                params_data = st["parameters"]
                if isinstance(params_data, dict):
                    total = sum(params_data.values())
                elif isinstance(params_data, (int, float)):
                    total = params_data
                else:
                    total = 0
                if total > 0:
                    params_b = round(total / 1e9, 1)

        quant = self._detect_quant(model_id, tags)
        backends = self.detect_backend_compat(tags, siblings)
        tier = self.classify_tier(params_b, quant)
        gated = self.parse_gated(m.get("gated", False))
        desc = (m.get("cardData", {}) or {}).get("description", "")
        if not desc:
            # Build a short desc from id
            desc = model_id.split("/")[-1].replace("-", " ")

        result = {
            "id": model_id,
            "params_b": params_b,
            "quant": quant,
            "gated": gated,
            "downloads": m.get("downloads", 0),
            "likes": m.get("likes", 0),
            "desc": desc[:80],
            "backends": backends,
            "tier": tier,
            "size_estimate": self.estimate_size({"safetensors": m.get("safetensors"), "usedStorage": m.get("usedStorage"), "params_b": params_b, "quant": quant}),
        }
        if m.get("pipeline_tag"):
            result["pipeline_tag"] = m["pipeline_tag"]
        # Auto-enrich with tool parser and VRAM estimate
        return self.enrich_model(result)

    def _normalize_detail(self, m: dict) -> dict[str, Any]:
        """Normalize a full HF model detail response."""
        base = self._normalize(m)
        base["license"] = (m.get("cardData", {}) or {}).get("license", "unknown")
        base["author"] = m.get("author", "")
        base["last_modified"] = m.get("lastModified", "")
        base["pipeline_tag"] = m.get("pipeline_tag", "")

        # Gather file info
        siblings = m.get("siblings", [])
        formats = set()
        for s in siblings:
            fname = s.get("rfilename", "")
            if fname.endswith(".gguf"):
                formats.add("GGUF")
            elif fname.endswith(".safetensors"):
                formats.add("safetensors")
            elif fname.endswith(".bin"):
                formats.add("pytorch")
        base["formats"] = sorted(formats)
        return base

    @staticmethod
    def _detect_quant(model_id: str, tags: list[str]) -> str | None:
        """Detect quantization type from model id / tags."""
        combined = model_id + " " + " ".join(tags)
        combined_lower = combined.lower()
        if "awq" in combined_lower:
            return "AWQ"
        if "gptq" in combined_lower:
            return "GPTQ"
        if "exl2" in combined_lower:
            return "EXL2"
        if "gguf" in combined_lower:
            return "GGUF"
        m = _QUANT_RE.search(combined)
        if m:
            return m.group(1).upper()
        return None

    # ------------------------------------------------------------------
    # Tool/reasoning parser detection
    # ------------------------------------------------------------------

    @staticmethod
    def detect_tool_parser(model_id: str) -> str:
        """Auto-detect the vLLM tool call parser for a model."""
        mid = model_id.lower()
        if "gemma-4" in mid or "gemma4" in mid:
            return "gemma4"
        if "gemma-3" in mid or "gemma3" in mid:
            return "pythonic"
        if "llama" in mid:
            return "llama3_json"
        if "mistral" in mid or "mixtral" in mid:
            return "mistral"
        if "jamba" in mid:
            return "jamba"
        # Qwen, DeepSeek, and most others use Hermes format
        return "hermes"

    @staticmethod
    def detect_reasoning_parser(model_id: str) -> str | None:
        """Auto-detect the vLLM reasoning parser (if model supports thinking)."""
        mid = model_id.lower()
        if "gemma-4" in mid or "gemma4" in mid:
            return "gemma4"
        if "deepseek-r1" in mid or "deepseek_r1" in mid:
            return "deepseek_r1"
        return None

    @staticmethod
    def estimate_vram_gb(params_b: float | None, quant: str | None) -> float | None:
        """Estimate VRAM usage in GB from param count and quantization."""
        if params_b is None:
            return None
        q = (quant or "").upper()
        if q in ("AWQ", "GPTQ", "INT4"):
            return round(params_b * 0.6 + 1.5, 1)  # 4-bit + overhead
        if q in ("GGUF",):
            return round(params_b * 0.65 + 1.0, 1)  # Q4-Q5 avg
        if q in ("INT8", "W8A8"):
            return round(params_b * 1.1 + 1.5, 1)
        # fp16 / no quant
        return round(params_b * 2.1 + 2.0, 1)

    def enrich_model(self, model: dict[str, Any]) -> dict[str, Any]:
        """Add tool_parser, reasoning_parser, vram_gb to a model entry."""
        mid = model.get("id", "")
        if "tool_parser" not in model:
            model["tool_parser"] = self.detect_tool_parser(mid)
        if "reasoning_parser" not in model:
            rp = self.detect_reasoning_parser(mid)
            if rp:
                model["reasoning_parser"] = rp
        if "vram_gb" not in model:
            vram = self.estimate_vram_gb(model.get("params_b"), model.get("quant"))
            if vram:
                model["vram_gb"] = vram
        if "publisher" not in model:
            model["publisher"], model["trust"] = publisher_trust(mid)
        return model

    async def refresh_catalog(
        self,
        backends: list[str] | None = None,
        use_llm: bool = False,
        gateway_url: str = "https://127.0.0.1:8080",
    ) -> dict[str, Any]:
        """Refresh the model catalog from HuggingFace, enrich with metadata.

        Args:
            backends: Which backends to refresh (default: all)
            use_llm: If True, use the coordinator LLM to analyze model cards
            gateway_url: Gateway URL for LLM calls (if use_llm=True)

        Returns:
            Summary dict with counts per backend
        """
        target_backends = backends or list(BACKEND_SEARCHES.keys())
        summary: dict[str, Any] = {}

        for backend in target_backends:
            try:
                models = self._fetch_from_hf(backend, limit=40)
                # Enrich with tool parsers and VRAM estimates
                for m in models:
                    self.enrich_model(m)

                if use_llm and models:
                    models = await self._llm_enrich_batch(models, gateway_url)

                self._write_cache(backend, models)
                summary[backend] = {"count": len(models), "status": "refreshed"}
            except Exception as e:
                summary[backend] = {"count": 0, "status": f"error: {e}"}

        # Also enrich the fallback catalog
        for backend, fallback_models in FALLBACK_MODELS.items():
            for m in fallback_models:
                self.enrich_model(m)

        return summary

    async def _llm_enrich_batch(
        self, models: list[dict], gateway_url: str,
    ) -> list[dict]:
        """Use the coordinator LLM to analyze top models and refine metadata."""
        import httpx

        # Only analyze top 10 by downloads (LLM calls are expensive)
        top = sorted(models, key=lambda m: m.get("downloads", 0), reverse=True)[:10]
        model_summaries = "\n".join(
            f"- {m['id']} ({m.get('params_b','?')}B, {m.get('quant','none')}, "
            f"downloads={m.get('downloads',0)}, parser={m.get('tool_parser','?')})"
            for m in top
        )

        prompt = f"""Analyze these AI models for our local inference cluster. For each model, confirm or correct:
1. tool_parser (hermes/gemma4/pythonic/llama3_json/mistral/jamba)
2. Does it support tool/function calling? (yes/no)
3. Does it support reasoning/thinking mode? (yes/no)
4. Quality assessment for agentic use (good/fair/poor)

Models:
{model_summaries}

Respond as JSON array: [{{"id": "...", "tool_parser": "...", "tool_calling": true/false, "reasoning": true/false, "agentic_quality": "good/fair/poor"}}]
Only return the JSON array, no other text."""

        try:
            from .cluster_auth import internal_gateway_headers
            from ..gateway.deps import ssl_verify

            # Verify the cluster CA chain (ssl_verify checks the CA but skips
            # hostname matching for LAN-IP / Docker-name SANs). NEVER verify=False:
            # this request carries an internal gateway credential and was
            # previously MITM-able.
            async with httpx.AsyncClient(timeout=30, verify=ssl_verify()) as client:
                resp = await client.post(
                    f"{gateway_url}/api/inference",
                    json={"prompt": prompt, "max_iterations": 1},
                    headers=internal_gateway_headers("model_catalog"),
                )
                if resp.status_code == 200:
                    data = resp.json()
                    response_text = data.get("response", "")
                    # Try to parse JSON from the response
                    import re as _re
                    json_match = _re.search(r'\[.*\]', response_text, _re.DOTALL)
                    if json_match:
                        enrichments = json.loads(json_match.group())
                        enrich_map = {e["id"]: e for e in enrichments if "id" in e}
                        for m in models:
                            if m["id"] in enrich_map:
                                e = enrich_map[m["id"]]
                                if "tool_parser" in e:
                                    m["tool_parser"] = e["tool_parser"]
                                m["tool_calling"] = e.get("tool_calling", True)
                                m["reasoning"] = e.get("reasoning", False)
                                m["agentic_quality"] = e.get("agentic_quality", "fair")
        except Exception:
            pass  # LLM enrichment is best-effort

        return models

    # ------------------------------------------------------------------
    # Cache management
    # ------------------------------------------------------------------

    def _load_cache_file(self) -> dict[str, Any] | None:
        if self._cache is not None:
            return self._cache
        if not self.cache_file.exists():
            return None
        try:
            data = json.loads(self.cache_file.read_text(encoding="utf-8"))
            self._cache = data
            return data
        except Exception:
            return None

    def _read_cache(self, backend: str, ignore_ttl: bool = False) -> list[dict[str, Any]] | None:
        cache = self._load_cache_file()
        if not cache:
            return None
        catalogs = cache.get("catalogs", {})
        if backend not in catalogs:
            return None
        if not ignore_ttl:
            fetched_at = cache.get("fetched_at", {}).get(backend)
            if not fetched_at:
                return None
            try:
                dt = datetime.fromisoformat(fetched_at)
                age_hours = (datetime.now(timezone.utc) - dt).total_seconds() / 3600
                if age_hours > self.ttl_hours:
                    return None
            except Exception:
                return None
        return catalogs[backend]

    def _write_cache(self, backend: str, models: list[dict[str, Any]]) -> None:
        """Write one backend's catalog under an flock, re-reading the file
        FRESH first and landing it via tmp+rename.

        The cache file is shared with the Rust CLI (noo-cli/src/catalog.rs
        uses the same ``model_cache.json.lock`` sidecar), and both sides used
        to do unlocked whole-file read-modify-write: concurrent refreshes
        lost each other's backend entries and a mid-write crash left
        truncated JSON. Byte shape of the payload is unchanged
        (``json.dumps(cache, default=str)``).
        """
        import fcntl
        import os
        import tempfile

        self.cache_file.parent.mkdir(parents=True, exist_ok=True)
        lock_path = self.cache_file.parent / f"{self.cache_file.name}.lock"
        with open(lock_path, "w", encoding="utf-8") as lock_fh:
            fcntl.flock(lock_fh, fcntl.LOCK_EX)
            try:
                # Fresh read under the lock — never trust self._cache here.
                try:
                    cache = json.loads(self.cache_file.read_text(encoding="utf-8"))
                    if not isinstance(cache, dict):
                        raise ValueError("cache root is not an object")
                    cache.setdefault("catalogs", {})
                    cache.setdefault("fetched_at", {})
                except (OSError, ValueError):
                    cache = {"catalogs": {}, "fetched_at": {}, "ttl_hours": self.ttl_hours}
                cache["catalogs"][backend] = models
                cache["fetched_at"][backend] = datetime.now(timezone.utc).isoformat()
                cache["ttl_hours"] = self.ttl_hours

                # Atomic write: tmp file in the SAME dir, then rename.
                fd, tmp_path = tempfile.mkstemp(
                    prefix=f".{self.cache_file.name}.", suffix=".tmp",
                    dir=str(self.cache_file.parent),
                )
                try:
                    with os.fdopen(fd, "w", encoding="utf-8") as fh:
                        fh.write(json.dumps(cache, default=str))
                    os.replace(tmp_path, self.cache_file)
                except BaseException:
                    try:
                        os.unlink(tmp_path)
                    except OSError:
                        pass
                    raise
            finally:
                fcntl.flock(lock_fh, fcntl.LOCK_UN)
        self._cache = cache

    @staticmethod
    def _filter_tier(models: list[dict[str, Any]], tier: int | None) -> list[dict[str, Any]]:
        if tier is None:
            return models
        return [m for m in models if m.get("tier") == tier]


# ---------------------------------------------------------------------------
# Utility
# ---------------------------------------------------------------------------

def _fmt_bytes(b: int | float) -> str:
    """Format bytes to human-readable."""
    b = float(b)
    if b >= 1e9:
        return f"{b / 1e9:.1f}GB"
    if b >= 1e6:
        return f"{b / 1e6:.0f}MB"
    return f"{b / 1e3:.0f}KB"
