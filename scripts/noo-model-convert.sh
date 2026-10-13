#!/bin/bash
# SPDX-License-Identifier: AGPL-3.0-only
# Copyright 2026 PersonifAI LLC

# Convert an HF model → GGUF → Ollama, one command, fully containerized.
# No local llama.cpp build needed — conversion + quantization run inside the
# official llama.cpp container. Wraps the MODEL_CONVERSION.md runbook for models
# that don't ship an Ollama/GGUF build (Microsoft Harrier, Nemotron Omni/ASR…).
#
# Usage:
#   scripts/noo-model-convert.sh <hf-repo-id> [ollama-name] [quant]
# Examples:
#   scripts/noo-model-convert.sh microsoft/harrier-oss-v1-0.6b harrier
#   scripts/noo-model-convert.sh microsoft/harrier-oss-v1-0.6b harrier Q5_K_M
#
# Env:
#   LLAMACPP_IMAGE  llama.cpp container with convert+quantize tools
#                   (default: ghcr.io/ggml-org/llama.cpp:full)
#   WORKDIR         scratch dir for downloads/gguf (default: ./.model-convert)
#   OLLAMA_CTX      context length for the Modelfile (default: 8192)
#   HF_TOKEN        forwarded for gated models
set -euo pipefail

HF_ID="${1:?usage: noo-model-convert.sh <hf-repo-id> [ollama-name] [quant]}"
OLLAMA_NAME="${2:-$(basename "$HF_ID" | tr '[:upper:]' '[:lower:]')}"
QUANT="${3:-Q4_K_M}"
LLAMACPP_IMAGE="${LLAMACPP_IMAGE:-ghcr.io/ggml-org/llama.cpp:full}"
WORKDIR="${WORKDIR:-./.model-convert}"
OLLAMA_CTX="${OLLAMA_CTX:-8192}"

say() { echo -e "\033[0;36m==>\033[0m $*"; }
die() { echo -e "\033[0;31mERROR:\033[0m $*" >&2; exit 1; }

command -v docker >/dev/null 2>&1 || die "docker not found"
# Ollama may be a host binary OR the noo-ollama container. If neither is
# available we still produce the GGUF + Modelfile and print the create command.
OLLAMA_MODE="none"
if [ -n "${NOO_CONVERT_GGUF_ONLY:-}" ]; then
    :  # forced GGUF-only (e.g. ship-model converts on the controller, creates on the node)
elif command -v ollama >/dev/null 2>&1; then
    OLLAMA_MODE="host"
elif docker ps --format '{{.Names}}' 2>/dev/null | grep -qx noo-ollama; then
    OLLAMA_MODE="container"
fi

mkdir -p "$WORKDIR"
ABS_WORK="$(cd "$WORKDIR" && pwd)"
HF_SUB="$(echo "$HF_ID" | tr '/' '_')-hf"
F16="${OLLAMA_NAME}-f16.gguf"
OUT="${OLLAMA_NAME}-${QUANT}.gguf"

# --- 1. Download (containerized — no host huggingface-cli needed) -------------
if [ ! -d "$ABS_WORK/$HF_SUB" ]; then
    say "downloading $HF_ID"
    docker run --rm -v "$ABS_WORK":/w -w /w -e HF_TOKEN="${HF_TOKEN:-}" \
        -e HF_HUB_DISABLE_TELEMETRY=1 -e DO_NOT_TRACK=1 python:3.12-slim \
        bash -c "pip install -q huggingface_hub && hf download '$HF_ID' --local-dir '/w/$HF_SUB'"
fi

# --- 2. Convert + quantize (in the llama.cpp container) ----------------------
if [ ! -f "$ABS_WORK/$F16" ]; then
    say "converting HF → GGUF (f16) via $LLAMACPP_IMAGE"
    docker run --rm -v "$ABS_WORK":/w "$LLAMACPP_IMAGE" \
        --convert "/w/$HF_SUB" --outfile "/w/$F16" --outtype f16
fi
say "quantizing → $QUANT"
docker run --rm -v "$ABS_WORK":/w "$LLAMACPP_IMAGE" \
    --quantize "/w/$F16" "/w/$OUT" "$QUANT"

# --- 3. Ollama Modelfile -----------------------------------------------------
if [ -f "$ABS_WORK/$HF_SUB/tokenizer_config.json" ] \
   && grep -q chat_template "$ABS_WORK/$HF_SUB/tokenizer_config.json"; then
    say "NOTE: this model ships a chat_template — verify the Modelfile TEMPLATE matches it (tool calling breaks otherwise)."
fi
MODELFILE="$ABS_WORK/${OLLAMA_NAME}.Modelfile"
cat > "$MODELFILE" <<EOF
FROM ./$OUT
TEMPLATE """{{ .System }}\n{{ .Prompt }}"""
PARAMETER num_ctx $OLLAMA_CTX
EOF

case "$OLLAMA_MODE" in
    host)
        say "ollama create $OLLAMA_NAME (host)"
        ( cd "$ABS_WORK" && ollama create "$OLLAMA_NAME" -f "$(basename "$MODELFILE")" )
        ;;
    container)
        say "ollama create $OLLAMA_NAME (in the noo-ollama container)"
        docker exec noo-ollama sh -c 'mkdir -p /convert'
        docker cp "$ABS_WORK/$OUT" "noo-ollama:/convert/$OUT"
        docker cp "$MODELFILE" "noo-ollama:/convert/Modelfile"
        docker exec -w /convert noo-ollama ollama create "$OLLAMA_NAME" -f Modelfile
        ;;
    none)
        say "no Ollama (host binary or noo-ollama container) found — GGUF is ready."
        say "when Ollama is up, run:  (cd $ABS_WORK && ollama create $OLLAMA_NAME -f $(basename "$MODELFILE"))"
        say "GGUF: $ABS_WORK/$OUT"
        exit 0
        ;;
esac

say "done. smoke test:  ollama run $OLLAMA_NAME 'hello'"
say "register on a node: noo cluster up ollama $OLLAMA_NAME --node <node>"
