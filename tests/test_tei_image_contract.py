# SPDX-License-Identifier: AGPL-3.0-only
# Copyright 2026 PersonifAI LLC

"""What we send a Text Embeddings Inference (TEI) container is what the pinned TEI reads.

TEI is the opt-in embedder (compose `tei` / `tei-gpu`, profile `tei-compose`)
and the opt-in reranker (compose `reranker`). The node agent no longer runs it
(the `embedding` backend and the TEI reranker were removed in 0.6.30, i1182a), so
only the compose services and the gateway's bodies are checked here, until they
go too. Its CLI is clap with `long, env`
on every argument, and its HTTP request types do NOT deny unknown fields, so a
renamed flag fails at start but a renamed env var or body field is silently
ignored: `{"truncation": true}` would fall back to the server default.

TEI ships two flavours, and each is pinned to its own reviewed release:
CPU (compose `tei`) and CUDA (compose `tei-gpu` and `reranker`). PINNED names the release of each, RELEASES
holds what each release reads (from its source). This test checks:

- every TEI image is spelled for its flavour (`cpu-<v>` / `<v>`) at that
  flavour's PINNED release, and compose pins that release's digest, so moving
  an image without a RELEASES row (a review) fails here;
- the GPU flavour is HELD (see HELD) and says so where it is pinned, so
  moving it is a deliberate edit of this file;
- every `--flag` we pass is accepted by EVERY pinned release, and every start
  passes --model-id (no default since 1.9.0);
- the env vars that carry our behaviour are read by every pinned release:
  MODEL_ID and HOSTNAME (the loopback-only listener behind the stunnel door);
- the bodies the gateway sends to /embed and /rerank use only fields every
  pinned release reads.

Review of 1.6.1 -> 1.9.4 (release notes v1.7.0..v1.9.4 and the router source
at both tags): no CLI argument or env var was removed or renamed (added:
--served-model-name, --dense-path, --prometheus-port); /embed, /rerank,
/embed_sparse, /info, /health, /v1/embeddings keep their routes and request
fields (added: optional `dimensions`). Defaults that moved: `--auto-truncate`
(true since 1.9.0) and `--model-id` (no default since 1.9.0). The /embed
bodies set `truncate: true` explicitly, so they do not depend on the first.
"""
from __future__ import annotations

import re
from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parents[1]
COMPOSE = ROOT / "docker-compose.cluster.yml"
EMBEDDING_CLIENT_RS = ROOT / "gateway-rust/src/embedding_client.rs"
EXTERNAL_RS = ROOT / "gateway-rust/src/routes/external.rs"

REPO = "ghcr.io/huggingface/text-embeddings-inference"

# The `Args` fields of router/src/main.rs at v1.6.1 (every one is `long, env`:
# flag --a-b, env A_B); v1.9.4 adds three and removes none.
_ARGS_1_6_1 = (
    "model_id revision tokenization_workers dtype pooling "
    "max_concurrent_requests max_batch_tokens max_batch_requests max_client_batch_size "
    "auto_truncate default_prompt_name default_prompt hf_api_token hf_token "
    "hostname port uds_path huggingface_hub_cache payload_limit api_key json_output "
    "disable_spans otlp_endpoint otlp_service_name cors_allow_origin"
).split()
_ARGS_1_9_4 = _ARGS_1_6_1 + ["served_model_name", "dense_path", "prometheus_port"]

# router/src/http/types.rs EmbedRequest / RerankRequest at v1.6.1; v1.9.4 adds
# EmbedRequest.dimensions.
_EMBED_1_6_1 = {"inputs", "truncate", "truncation_direction", "prompt_name", "normalize"}
_RERANK_1_6_1 = {"query", "texts", "truncate", "truncation_direction", "raw_scores", "return_text"}


def _release(args: list[str], embed: set[str], **digests: str) -> dict:
    return {
        "flags": {"--" + a.replace("_", "-") for a in args},
        "env": {a.upper() for a in args},
        # Image config Env: PORT=80 on the CPU and CUDA images of both releases.
        "port": 80,
        "embed_fields": embed,
        "rerank_fields": _RERANK_1_6_1,
        **digests,
    }


# Image tag -> the reviewed release. Digests: ghcr.io index digests
# (linux/amd64 + attestation manifest; no arm64 in either release).
RELEASES = {
    "1.6": _release(  # = 1.6.1 (image label org.opencontainers.image.version)
        _ARGS_1_6_1, _EMBED_1_6_1,
        gpu_digest="sha256:25e35b0b266241a543c5ee305083eced4b6ac0772eb969c3fdaae2d4c2ef7266",
    ),
    "1.9.4": _release(  # resolved 2026-11-20
        _ARGS_1_9_4, _EMBED_1_6_1 | {"dimensions"},
        cpu_digest="sha256:2538ea1c9640d3763b15af668039d24172d063b42337b0c27796fc2be180c78d",
    ),
}

# The release each flavour runs.
PINNED = {"cpu": "1.9.4", "gpu": "1.6"}

# Flavours held back from the newest reviewed release, and why. Moving the GPU
# flavour means editing PINNED and deleting its entry here, after a GPU node
# whose driver reports CUDA >= 12.9 has run TEI 1.9.4 (#1444).
HELD = {
    "gpu": "held at 1.6: TEI 1.9.4's CUDA image requires cuda>=12.9 with no GeForce exemption "
           "(driver >= ~575, inferred from the image config); move after a GPU node proves it (#1444)",
}
HELD_MARK = "held at 1.6: TEI 1.9.4's CUDA image requires cuda>=12.9"

TEI_SERVICES = ("tei", "tei-gpu", "reranker")
CPU_SERVICES = ("tei",)
# The env vars whose meaning we rely on TEI reading.
RELIED_ON_ENV = ("MODEL_ID", "HOSTNAME")


def _pinned_releases() -> list[dict]:
    return [RELEASES[v] for v in sorted(set(PINNED.values()))]


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


def _compose_services() -> dict:
    services = yaml.safe_load(COMPOSE.read_text())["services"]
    missing = [s for s in TEI_SERVICES if s not in services]
    assert not missing, f"docker-compose.cluster.yml lost TEI services {missing}"
    return {s: services[s] for s in TEI_SERVICES}


def _image_refs() -> list[tuple[str, str, str]]:
    """(where, flavour, image text) for every TEI image the stack names."""
    refs = [
        (f"compose {n}", "cpu" if n in CPU_SERVICES else "gpu", str(svc["image"]))
        for n, svc in _compose_services().items()
    ]
    return refs


def test_every_tei_image_is_its_flavours_reviewed_release():
    for flavour, v in PINNED.items():
        assert v in RELEASES, (
            f"TEI {v} ({flavour}) has no RELEASES row: read its release notes and router source "
            f"(flags, env, request fields, defaults) and record it before moving the pin"
        )
    refs = _image_refs()
    assert {f for _, f, _ in refs} == {"cpu", "gpu"}, refs
    for where, flavour, img in refs:
        want = f"{REPO}:{'cpu-' if flavour == 'cpu' else ''}{PINNED[flavour]}"
        assert re.search(re.escape(want) + r"(?![0-9A-Za-z.-])", img), f"{where} ({flavour}): want {want}, got {img!r}"


def test_compose_pins_each_flavours_reviewed_digest():
    for name, svc in _compose_services().items():
        flavour = "cpu" if name in CPU_SERVICES else "gpu"
        digest = RELEASES[PINNED[flavour]].get(f"{flavour}_digest")
        assert digest, f"RELEASES[{PINNED[flavour]!r}] records no {flavour} digest"
        var = "NOO_IMAGE_DIGEST_TEI_CPU" if flavour == "cpu" else "NOO_IMAGE_DIGEST_TEI"
        img = str(svc["image"])
        assert f"${{{var}:-@{digest}}}" in img, (
            f"compose {name}: the default digest is not the reviewed {flavour} {PINNED[flavour]} digest {digest}: {img!r}"
        )


def test_the_gpu_flavour_is_held_on_purpose():
    newest = max(RELEASES, key=lambda v: tuple(int(x) for x in v.split(".")))
    behind = {f for f, v in PINNED.items() if v != newest}
    assert behind == set(HELD), (
        f"flavours behind the newest reviewed release {newest}: {sorted(behind)}; HELD names {sorted(HELD)}. "
        "A flavour held back needs a HELD reason; one that moved drops its HELD entry"
    )
    assert PINNED["gpu"] == "1.6" and "cuda>=12.9" in HELD["gpu"], (PINNED, HELD)
    # The reason sits at every GPU pin, so whoever edits the pin reads it.
    compose = COMPOSE.read_text()
    for name in TEI_SERVICES:
        if name in CPU_SERVICES:
            continue
        block = compose[compose.index(f"\n  {name}:\n"):]
        block = block[: block.index("\n    image:")]
        assert HELD_MARK in block, f"compose {name}: no hold comment above its image"


def _flags(args: list[str]) -> list[str]:
    return [a.split("=", 1)[0] for a in args if a.startswith("--")]


def test_every_flag_we_pass_tei_is_accepted_by_every_pinned_release():
    seen = []
    for name, svc in _compose_services().items():
        seen += [(f"compose {name}", f) for f in _flags([str(x) for x in svc.get("command") or []])]
    assert len(seen) >= 3, f"parsed only {seen}: the parser no longer matches the sources"
    for v in sorted(set(PINNED.values())):
        bad = [f"{w}: {f}" for w, f in seen if f not in RELEASES[v]["flags"]]
        assert not bad, f"TEI flags {v} does not accept (it would refuse to start):\n  " + "\n  ".join(bad)
    # Since 1.9.0 --model-id has no default: every start must pass it.
    starts = {w for w, _ in seen}
    without = sorted(w for w in starts if (w, "--model-id") not in seen)
    assert not without, f"TEI starts without --model-id (no default since 1.9.0): {without}"


def test_the_env_we_rely_on_is_read_by_every_pinned_release():
    for r in _pinned_releases():
        missing = [k for k in RELIED_ON_ENV if k not in r["env"]]
        assert not missing, f"a pinned TEI reads none of {missing}"
    for name, svc in _compose_services().items():
        env = {e.split("=", 1)[0] for e in svc.get("environment") or []}
        for k in ("MODEL_ID", "HOSTNAME"):
            assert k in env, f"compose {name}: no {k} (TEI reads it as --{k.lower().replace('_', '-')})"


def test_the_bodies_we_send_tei_use_fields_every_pinned_release_reads():
    embed_ok = set.intersection(*(r["embed_fields"] for r in _pinned_releases()))
    rerank_ok = set.intersection(*(r["rerank_fields"] for r in _pinned_releases()))
    gw = re.search(r'format!\("\{\}/embed", self\.url\),\s*json!\(\{([^}]*)\}\)', EMBEDDING_CLIENT_RS.read_text())
    assert gw, "embedding_client.rs: no tei /embed body"
    gw_keys = set(re.findall(r'"(\w+)":', gw.group(1)))
    for where, keys in (("gateway /embed", gw_keys),):
        assert keys >= {"inputs", "truncate"}, f"{where}: {sorted(keys)}"
        assert keys <= embed_ok, f"{where}: fields a pinned TEI ignores: {sorted(keys - embed_ok)}"
    rr = re.search(r'json!\(\{("query": query, "texts"[^}]*)\}\)', EXTERNAL_RS.read_text())
    assert rr, "external.rs: no rerank body"
    rr_keys = set(re.findall(r'"(\w+)":', rr.group(1)))
    assert rr_keys >= {"query", "texts"} and rr_keys <= rerank_ok, (
        f"gateway /rerank: {sorted(rr_keys)} vs {sorted(rerank_ok)}"
    )
