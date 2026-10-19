// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 PersonifAI LLC

package docker

import (
	"context"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"log/slog"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"time"

	"github.com/moby/moby/api/types/container"
	"github.com/moby/moby/api/types/mount"
	"github.com/moby/moby/api/types/network"
	"github.com/moby/moby/client"

	"github.com/noomesh/noomesh/node-agent-go/internal/auth"
	nodeconfig "github.com/noomesh/noomesh/node-agent-go/internal/config"
	"github.com/noomesh/noomesh/node-agent-go/internal/dataroots"
	"github.com/noomesh/noomesh/node-agent-go/internal/preseed"
	"github.com/noomesh/noomesh/node-agent-go/internal/refusals"
)

// vllmEntrypointScript is the shared vLLM auto-detection entrypoint.
// Mirrors the logic in docker-compose.cluster.yml so controller and worker
// nodes launch vLLM identically — auto-detecting tool parser, reasoning
// parser, quantization, and max-num-seqs from the model name.
const vllmEntrypointScript = `
# Auto-detect tool call parser from model name
if [ -z "$VLLM_TOOL_PARSER" ]; then
  case "$VLLM_MODEL" in
    *gemma-4*|*gemma4*|*E4B*|*E2B*)
      # gemma-4 emits its own call syntax (<|tool_call>call:name{...}<tool_call|>).
      # "pythonic" misses it and the call arrives as plain text: a research
      # gather ended on one on host3, 2026-09-29, and the run failed. The
      # controller's compose services already use "gemma4"; asked of the image
      # here because older vLLM builds do not register it.
      if python3 -c "import sys
try:
    from vllm.tool_parsers import ToolParserManager as M
except ImportError:
    from vllm.entrypoints.openai.tool_parsers import ToolParserManager as M
sys.exit(0 if 'gemma4' in M.list_registered() else 1)" >/dev/null 2>&1; then
        VLLM_TOOL_PARSER="gemma4"
      else
        VLLM_TOOL_PARSER="pythonic"
      fi ;;
    *gemma-3*|*gemma3*)               VLLM_TOOL_PARSER="pythonic" ;;
    *Llama*|*llama*)                  VLLM_TOOL_PARSER="llama3_json" ;;
    *mistral*|*Mistral*)              VLLM_TOOL_PARSER="mistral" ;;
    *)                                VLLM_TOOL_PARSER="hermes" ;;
  esac
  echo "Auto-detected tool parser: $VLLM_TOOL_PARSER for model $VLLM_MODEL"
fi

# Auto-detect reasoning parser
#
# gemma-4 wraps its reasoning in special tokens (<|channel>thought ... <channel|>).
# vLLM drops special tokens when it detokenizes, so WITHOUT the gemma4 parser the
# gateway receives a bare "thought" line with reasoning and answer run together
# and no end marker — heartbeat reports, the research gather step and chat all
# carried the reasoning as the answer. The parser moves it into the response's
# "reasoning" field, which the gateway already reads.
#
# Asked of the image, not assumed: vLLM 0.18 shipped without a gemma4 parser,
# and an unknown --reasoning-parser name stops the server from booting. On an
# image that lacks it we run without one, as before.
if [ -z "$VLLM_REASONING_PARSER" ]; then
  case "$VLLM_MODEL" in
    *gemma-4*|*gemma4*|*E4B*|*E2B*)
      if python3 -c "import sys; from vllm.reasoning import ReasoningParserManager as M; sys.exit(0 if 'gemma4' in M.list_registered() else 1)" >/dev/null 2>&1; then
        VLLM_REASONING_PARSER="gemma4"
      else
        VLLM_REASONING_PARSER=""
        echo "This vLLM image has no gemma4 reasoning parser; gemma reasoning will arrive inline"
      fi ;;
    *DeepSeek-R1*|*deepseek*)           VLLM_REASONING_PARSER="deepseek_r1" ;;
    *)                                  VLLM_REASONING_PARSER="" ;;
  esac
  echo "Auto-detected reasoning parser: ${VLLM_REASONING_PARSER:-none} for model $VLLM_MODEL"
fi

# Auto-detect quantization
QUANT_ARG=""
case "$VLLM_MODEL" in
  *AWQ*|*awq*)   QUANT_ARG="--quantization awq" ;;
  *GPTQ*|*gptq*) QUANT_ARG="--quantization gptq" ;;
  *NVFP4*)       QUANT_ARG="--quantization fp8" ;;
  *)             QUANT_ARG="" ;;
esac

# Auto-detect max-num-seqs for hybrid/Mamba architectures
MAX_SEQS_ARG=""
case "$VLLM_MODEL" in
  *Qwen3.5*|*qwen3.5*|*mamba*|*Mamba*|*jamba*|*Jamba*) MAX_SEQS_ARG="--max-num-seqs 64" ;;
esac

# Build args
ARGS="--model $VLLM_MODEL $QUANT_ARG --gpu-memory-utilization $GPU_MEMORY_UTILIZATION --max-model-len $VLLM_MAX_MODEL_LEN --tensor-parallel-size $TENSOR_PARALLEL_SIZE $MAX_SEQS_ARG --enable-auto-tool-choice --tool-call-parser $VLLM_TOOL_PARSER --host 0.0.0.0 --port 8000"
if [ -n "$VLLM_REASONING_PARSER" ]; then
  ARGS="$ARGS --reasoning-parser $VLLM_REASONING_PARSER"
fi
# TLS is not a switch. The listener presents the vllm service leaf, verifies
# every caller against the cluster CA and REQUIRES a client certificate
# (--ssl-cert-reqs 2 = ssl.CERT_REQUIRED): the agent's inference proxy, job
# executor and GPU probe present the node leaf. Until 2026-09-29 this ran only
# under NOO_VLLM_TLS and even then asked for no client cert, so any container
# on the bridge could read every prompt. No leaf = no listener: refuse to
# start rather than serve plaintext (exit 78 = EX_CONFIG). The agent checks
# the leaf BEFORE creating this container (backendDoorCheck), so this arm is
# the second line, not the first.
if [ ! -f /app/pki/services/vllm/service.crt ] || [ ! -f /app/pki/services/vllm/service.key ]; then
  echo "vllm: no services/vllm leaf under NOO_PKI_DIR — refusing to serve plaintext" >&2
  exit 78
fi
ARGS="$ARGS --ssl-certfile /app/pki/services/vllm/service.crt --ssl-keyfile /app/pki/services/vllm/service.key --ssl-ca-certs /app/pki/ca.crt --ssl-cert-reqs 2"

# Resilient launch: retry with lower max-num-seqs on failure
echo "Starting vLLM: $ARGS"
python3 -m vllm.entrypoints.openai.api_server $ARGS 2>&1
EXIT_CODE=$?

if [ $EXIT_CODE -ne 0 ] && [ -z "$MAX_SEQS_ARG" ]; then
  echo ""
  echo "vLLM failed (exit $EXIT_CODE) — retrying with --max-num-seqs 64..."
  ARGS="$ARGS --max-num-seqs 64"
  exec python3 -m vllm.entrypoints.openai.api_server $ARGS
else
  exit $EXIT_CODE
fi
`

// BackendSpec defines how to create a backend container.
// This replaces the docker-compose profile logic — each backend's config
// from docker-compose.cluster.yml is encoded here.
type BackendSpec struct {
	Image string
	// CPUImage, when set, is used instead of Image on nodes WITHOUT an
	// NVIDIA GPU. Lets a single backend type (e.g. embedding/reranker, which
	// ship distinct CUDA `:1.6` and `:cpu-1.6` TEI images) auto-select the
	// right image per node — GPU where available, CPU otherwise. The GPU
	// device reservation is independently guarded by hasNvidiaGPU(), so the
	// two stay in sync. Empty → Image is used on every node (LLM backends).
	CPUImage      string
	ContainerName string
	Env           map[string]string // key -> env expression (supports ${VAR:-default})
	Volumes       []VolumeMount
	GPUCount      string // "all", "1", or "" for no GPU
	Network       string
	Command       []string
	Entrypoint    []string
	MemoryLimit   int64   // bytes, 0 = unlimited
	CPULimit      float64 // cores, 0 = unlimited

	// DisableHealthcheck turns the image's baked-in HEALTHCHECK off. The
	// harness runs from the gateway image, whose probe hits
	// the gateway's own port — a port the harness never opens.
	DisableHealthcheck bool
	// HealthcheckURL overrides the image's baked-in HEALTHCHECK.
	//
	// Needed because an upstream image's healthcheck hardcodes the port IT
	// defaults to, while we run the backend on the port the CLUSTER expects.
	// llama.cpp is the live example: its image probes :8080, we set
	// LLAMA_ARG_PORT=8085, and the container therefore reported "unhealthy"
	// continuously — 31,841 consecutive failures over 11 days on host9 —
	// while serving inference perfectly on 8085.
	//
	// A permanently-false health status is worse than none: it trains
	// operators to ignore the field, and any automation that gates on
	// container health sees a healthy backend as dead.
	//
	// Supports ${VAR:-default} like the other fields; resolved at create
	// time so it always matches the port actually configured.
	HealthcheckURL string
	// HealthcheckCmd is a CMD-SHELL healthcheck for a listener that curl
	// cannot probe bare: vLLM requires a client certificate, so the probe
	// presents the container's OWN leaf to itself (the compose vllm service
	// does the same). Takes precedence over HealthcheckURL.
	HealthcheckCmd string
}

// VolumeMount describes a bind mount.
type VolumeMount struct {
	Source   string // host path (supports env var substitution)
	Target   string
	ReadOnly bool
	// Optional: skip the mount (and say so in the log) when the resolved
	// host source does not exist, instead of handing Docker a strict bind
	// that fails the whole container start. Used for the PKI files, which a
	// node holds only partially: `/etc/noo/pki` on a provisioned node carries
	// ca.crt + its own nodes/<id>/ leaf (build_signed_cert_bundle) and no
	// services/ tree at all, while the controller's $NOO_PKI_DIR carries
	// every service leaf.
	Optional bool
}

// PKI mount sources. `${NOO_PKI_DIR:-./.pki-placeholder}` keeps the shape
// the compose files use: an unset NOO_PKI_DIR resolves to a relative path
// that exists nowhere, and buildMounts skips it as an Optional miss.
//
// What is deliberately NOT here: the PKI root itself, and nodes/. Until
// 2026-09-28 every backend spec bind-mounted the whole directory, so on a
// worker the vllm/llamacpp/reranker containers (root inside, DAC_OVERRIDE
// kept) held that node's `nodes/<id>/node.key` — the node's gateway-facing
// identity — which none of them ever reads. The gateway never dials a
// backend on a node directly: it dials the agent (`https://<ip>:8081`,
// coordinator/backend.rs) and the agent's inference proxy dials the
// backend by SchemeFor(). A backend's PKI is therefore only what it SERVES
// with, and only vllm can serve TLS at all.
const (
	pkiCACertSource = "${NOO_PKI_DIR:-./.pki-placeholder}/ca.crt"
	pkiCACertTarget = "/app/pki/ca.crt"
)

// pkiServiceLeafSource is the host path of a service leaf directory.
func pkiServiceLeafSource(service string) string {
	return "${NOO_PKI_DIR:-./.pki-placeholder}/services/" + service
}

// pkiServiceLeafTarget is where a backend container reads its own leaf.
func pkiServiceLeafTarget(service string) string {
	return "/app/pki/services/" + service
}

// backendSpecs defines container configurations matching docker-compose.cluster.yml.
// These are the same configs the compose file defines, expressed as Go structs.
var backendSpecs = map[string]BackendSpec{
	"vllm": {
		Image:         "${VLLM_IMAGE:-vllm/vllm-openai:v0.25.0}",
		ContainerName: "noo-vllm",
		Env: map[string]string{
			"VLLM_MODEL":             "${VLLM_MODEL:-google/gemma-4-E4B-it}",
			"MODEL_NAME":             "${VLLM_MODEL:-google/gemma-4-E4B-it}",
			"GPU_MEMORY_UTILIZATION": "${GPU_MEM_UTIL:-0.9}",
			"HF_TOKEN":               "${HF_TOKEN:-}",
			"HUGGING_FACE_HUB_TOKEN": "${HF_TOKEN:-}",
			"VLLM_MAX_MODEL_LEN":     "${VLLM_MAX_MODEL_LEN:-16384}",
			"TENSOR_PARALLEL_SIZE":   "${TENSOR_PARALLEL_SIZE:-1}",
			"VLLM_TOOL_PARSER":       "${VLLM_TOOL_PARSER:-}",
			"VLLM_REASONING_PARSER":  "${VLLM_REASONING_PARSER:-}",
			// vLLM ≥0.25 disables pinned memory (UVA) on WSL2 by default and
			// the engine dies at boot ("UVA is not available", surfaced as a
			// misleading circular-import traceback). Harmless elsewhere.
			// Mirrors the same fix in docker-compose.cluster.yml.
			"VLLM_WSL2_ENABLE_PIN_MEMORY": "${VLLM_WSL2_ENABLE_PIN_MEMORY:-1}",
			// vLLM ≥0.25's V2 model runner wedges the engine on WSL2 under a
			// thinking model: the container stays "Up (healthy)" while GPU util
			// sits at 0% and every request times out. Default it off here rather
			// than on the placement — placement env is REPLACED wholesale on
			// upsert (routes/cluster.rs `env = COALESCE($7, existing.env)`), so a
			// later `noo cluster place` that forgets to re-pass -e would silently
			// drop the fix and the wedge would come back looking brand new.
			"VLLM_USE_V2_MODEL_RUNNER": "${VLLM_USE_V2_MODEL_RUNNER:-0}",
			// Vendor telemetry off (docs/security/telemetry.md). vLLM posts
			// a usage report to stats.vllm.ai at engine start and every 10
			// minutes after, unless one of these is set; host3's container
			// had been writing /root/.config/vllm/usage_stats.json. Literal
			// values, not ${VAR:-1}: no node .env or placement may turn
			// them back on (buildEnvList re-asserts them after overrides).
			"VLLM_NO_USAGE_STATS":      "1",
			"VLLM_DO_NOT_TRACK":        "1",
			"DO_NOT_TRACK":             "1",
			"HF_HUB_DISABLE_TELEMETRY": "1",
		},
		Volumes: []VolumeMount{
			{Source: hfCacheSource, Target: "/root/.cache/huggingface"},
			// Exactly what the entrypoint serves with: --ssl-ca-certs
			// /app/pki/ca.crt and the vllm leaf. Optional so that a missing
			// source is reported by buildMounts rather than failing the
			// bind inside Docker — and then REFUSED by backendDoorCheck
			// before the running container is touched: a provisioned node
			// holds ca.crt + node.{crt,key} only (its bundle carries no
			// services/ tree), and without the leaf vllm is never started,
			// plain or otherwise.
			{Source: pkiCACertSource, Target: pkiCACertTarget, ReadOnly: true, Optional: true},
			{Source: pkiServiceLeafSource("vllm"), Target: pkiServiceLeafTarget("vllm"), ReadOnly: true, Optional: true},
		},
		GPUCount:   "${GPU_COUNT:-1}",
		Network:    "noo-cluster",
		Entrypoint: []string{"sh", "-c"},
		Command:    []string{vllmEntrypointScript},
		// Self-check with the container's OWN leaf: the listener requires
		// a client certificate and this image carries python3, not curl.
		// Presenting the service's cert to itself proves the mTLS listener
		// is up; it grants nothing (the container already holds that key).
		// `localhost` is in every service leaf's SANs. Same probe as the
		// compose vllm service.
		HealthcheckCmd: vllmHealthcheckCmd,
	},
	"llamacpp": {
		// Image is overridable via LLAMACPP_IMAGE env var. Default chosen
		// dynamically by initBackends() at startup so ARM nodes (which
		// don't have a local pai-assistant/llamacpp build) automatically
		// pull the multi-arch upstream image.
		Image:         envOr("LLAMACPP_IMAGE", llamacppDefaultImage()),
		ContainerName: "noo-llamacpp",
		Env: map[string]string{
			"MODEL_PATH": "${LLAMACPP_MODEL:-/models/llama-7b-Q5_K_M.gguf}",
			// "auto" sentinel — buildEnvList resolves it to "999" (offload
			// all layers to GPU) when hasNvidiaGPU() is true, else "0"
			// (CPU-only). User can still set N_GPU_LAYERS=N explicitly to
			// override (e.g., partial offload, or force CPU on a GPU node).
			"N_GPU_LAYERS": "${N_GPU_LAYERS:-auto}",
			"N_CTX":        "${N_CTX:-4096}",
			"N_THREADS":    "${N_THREADS:-4}",
			// No NOO_TLS_CA and no PKI mount: llama-server (hardened x86
			// image and upstream ghcr :server alike) has no TLS listener
			// and never sources docker/inject-ca.sh. Its door is the
			// noo-stunnel-llamacpp sidecar the agent runs beside it
			// (sidecarSpec: the llamacpp leaf, `verify = 2`); the container
			// itself listens plain on the bridge, reachable only by peers
			// on that bridge (a private network per backend is followup
			// 1234 F-ii). TLS to the gateway is the agent's inference proxy
			// (:8081, the node leaf).
			// Pin the cluster contract port explicitly. BackendPorts (and
			// every consumer: jobs executor, inference proxy) expects
			// llamacpp on 8085; a stale image whose baked-in ENV PORT
			// differs (host8 shipped one listening on 8080) otherwise
			// silently breaks all routed inference on the node.
			"HOST": "0.0.0.0",
			"PORT": "${LLAMACPP_PORT:-8085}",
			// Native tool calls on /v1/chat/completions need llama-server's
			// `--jinja`. The hardened x86 image passes the flag in its CMD;
			// the upstream multi-arch image (ARM) reads llama-server's
			// LLAMA_ARG_* environment instead, so say it both ways. The
			// gateway dials llama.cpp as OpenAI on the strength of this
			// (coordinator/backend.rs wire_format) and only falls back to
			// the prompt-flattening /completion path if a server refuses.
			"LLAMA_ARG_JINJA": "1",
		},
		Volumes: []VolumeMount{
			{Source: modelsSource, Target: "/models", ReadOnly: true},
			// No PKI mount — see the NOO_TLS_CA note above.
		},
		GPUCount:    "all",
		Network:     "noo-cluster",
		MemoryLimit: 8 * 1024 * 1024 * 1024, // 8GB
		CPULimit:    4,
		// The llama.cpp image's own HEALTHCHECK hardcodes :8080 while we run
		// on LLAMACPP_PORT (8085 by default), so without this override the
		// container is permanently "unhealthy" while serving fine.
		HealthcheckURL: "http://127.0.0.1:${LLAMACPP_PORT:-8085}/health",
	},
	// GPUCount is env-expressed (like vllm's) rather than the literal "all",
	// so a node can run ollama on CPU. The case that needs it: a fallback
	// embedder co-located with the gateway on a box whose GPU is already
	// committed to vLLM. "all" would have ollama demand every GPU and
	// collide with the chat backend — and GPUCount is NOT placement-
	// overridable (only model/image/port/tls/env are), so without this the
	// only route to a CPU ollama was inventing a second backend type.
	//
	// Set NOO_OLLAMA_GPU_COUNT=0 on that node's node-agent to pin it to CPU.
	// Embedding is a single forward pass with no autoregressive decode, so a
	// small embedder (harrier is 0.6B at Q4, ~397MB) is entirely viable on
	// CPU — unlike a chat model, where CPU-only would be painful.
	"ollama": {
		Image:         "${OLLAMA_IMAGE:-ollama/ollama:0.40.5}",
		ContainerName: "noo-ollama",
		Env: map[string]string{
			"OLLAMA_HOST":  "0.0.0.0",
			"OLLAMA_MODEL": "${OLLAMA_MODEL:-qwen3:8b}",
			// Ollama sends no usage telemetry, but it can hand a prompt to
			// ollama.com: a `*-cloud` model is inferred remotely, and the
			// server offers a web-search tool. Off — every model a
			// noomesh backend serves is local (docs/security/telemetry.md).
			"OLLAMA_NO_CLOUD": "1",
		},
		Volumes: []VolumeMount{
			{Source: ollamaSource, Target: "/root/.ollama"},
		},
		GPUCount: "${NOO_OLLAMA_GPU_COUNT:-all}",
		Network:  "noo-cluster",
	},
	"airllm": {
		Image:         "pai-assistant/airllm:latest",
		ContainerName: "noo-airllm",
		Env: map[string]string{
			"MODEL_PATH":  "${AIRLLM_MODEL:-meta-llama/Llama-2-70b-hf}",
			"MAX_VRAM_GB": "${MAX_VRAM_GB:-8.0}",
			"COMPRESSION": "${COMPRESSION:-4bit}",
			// transformers/huggingface_hub (docs/security/telemetry.md).
			"HF_HUB_DISABLE_TELEMETRY": "1",
			"DO_NOT_TRACK":             "1",
		},
		Volumes: []VolumeMount{
			{Source: modelsSource, Target: "/models"},
		},
		GPUCount:    "1",
		Network:     "noo-cluster",
		MemoryLimit: 16 * 1024 * 1024 * 1024, // 16GB
	},
	// Embedding — TEI serving a sentence embedder (POST /embed). GPU where
	// available (CUDA :1.6), CPU otherwise (:cpu-1.6) — auto-selected per
	// node via CPUImage + hasNvidiaGPU(). GPUCount "1" is a no-op on CPU
	// nodes (the reservation is GPU-guarded). Start with:
	//   noo cluster up embedding BAAI/bge-base-en-v1.5 --node <node>
	"embedding": {
		Image:         "${TEI_GPU_IMAGE:-ghcr.io/huggingface/text-embeddings-inference:1.6}",
		CPUImage:      "${TEI_CPU_IMAGE:-ghcr.io/huggingface/text-embeddings-inference:cpu-1.6}",
		ContainerName: "noo-tei",
		Env: map[string]string{
			"HUGGING_FACE_HUB_TOKEN": "${HF_TOKEN:-}",
			"MODEL_ID":               "${TEI_MODEL:-BAAI/bge-base-en-v1.5}",
			// TEI sends no usage report (its only exporter is OTLP, and only
			// to an endpoint we never configure); these keep its hf-hub
			// model fetch from reporting (docs/security/telemetry.md).
			"HF_HUB_DISABLE_TELEMETRY": "1",
			"DO_NOT_TRACK":             "1",
		},
		// Persist + share the TEI model cache at /data — same host dir the
		// compose `hf-cache` named volume binds to, so the node-agent backend
		// reuses models the compose tei/tei-gpu already downloaded.
		Volumes: []VolumeMount{
			{Source: hfCacheSource, Target: "/data"},
		},
		GPUCount: "1",
		Network:  "noo-cluster",
		Command:  []string{"--model-id", "${TEI_MODEL:-BAAI/bge-base-en-v1.5}"},
	},
	// Reranker — engine-selectable via RERANK_ENGINE, spec built by
	// rerankerSpec() below. Default: hardened llama.cpp (llama-server
	// --reranking on a gguf cross-encoder); RERANK_ENGINE=tei restores the
	// TEI cross-encoder image. Either way ContainerName stays noo-reranker —
	// the "rerank" in the name is what makes the capability detector
	// advertise `rerank` to the gateway, and the node-agent /rerank proxy
	// translates the wire shape so gateway callers never see the engine.
	"reranker": rerankerSpec(),
}

// rerankEntrypointScript translates the hardened llamacpp image's stable env
// interface (MODEL_PATH/N_GPU_LAYERS/N_CTX/N_THREADS/HOST/PORT) into
// llama-server flags with reranking enabled. Uses $VAR (NOT ${VAR}) so
// substitution happens in the CONTAINER shell — resolveEnvSlice expands
// ${...} from the node-agent's own env at create time, which would clobber
// these. `command -v` covers the hardened image (llama-server on PATH);
// /app/llama-server covers the upstream ghcr multi-arch image (ARM nodes).
const rerankEntrypointScript = `
BIN="$(command -v llama-server 2>/dev/null || echo /app/llama-server)"
exec "$BIN" --model "$MODEL_PATH" --reranking \
  --n-gpu-layers "$N_GPU_LAYERS" --ctx-size "$N_CTX" --threads "$N_THREADS" \
  --host "$HOST" --port "$PORT"
`

// rerankerSpec picks the reranker backend spec by RERANK_ENGINE
// ("llamacpp" default, "tei" fallback). Evaluated once at package init,
// like LLAMACPP_IMAGE. Note the spec only takes effect when the container
// is (re)created by the reconciler / `noo cluster up reranker` — a live
// TEI noo-reranker keeps running (and keeps working: the /rerank proxy
// autodetects the engine) until then.
func rerankerSpec() BackendSpec {
	if strings.EqualFold(strings.TrimSpace(os.Getenv("RERANK_ENGINE")), "tei") {
		return rerankerSpecTEI()
	}
	return rerankerSpecLlamacpp()
}

// rerankerSpecTEI is the legacy TEI cross-encoder spec (POST /rerank on :80).
// Same image family + CPU/GPU auto-select as the embedding backend. Start:
//
//	RERANK_ENGINE=tei; noo cluster up reranker BAAI/bge-reranker-base --node <node>
func rerankerSpecTEI() BackendSpec {
	return BackendSpec{
		Image:         "${TEI_GPU_IMAGE:-ghcr.io/huggingface/text-embeddings-inference:1.6}",
		CPUImage:      "${TEI_CPU_IMAGE:-ghcr.io/huggingface/text-embeddings-inference:cpu-1.6}",
		ContainerName: "noo-reranker",
		Env: map[string]string{
			"HUGGING_FACE_HUB_TOKEN": "${HF_TOKEN:-}",
			"MODEL_ID":               "${RERANK_MODEL:-BAAI/bge-reranker-base}",
			// Same as the embedding backend (docs/security/telemetry.md).
			"HF_HUB_DISABLE_TELEMETRY": "1",
			"DO_NOT_TRACK":             "1",
		},
		// Shared TEI model cache — see embedding backend.
		Volumes: []VolumeMount{
			{Source: hfCacheSource, Target: "/data"},
		},
		GPUCount: "1",
		Network:  "noo-cluster",
		Command:  []string{"--model-id", "${RERANK_MODEL:-BAAI/bge-reranker-base}"},
	}
}

// rerankerSpecLlamacpp runs llama-server --reranking from the hardened
// llamacpp image (same image/default-resolution story as the llamacpp LLM
// backend: pai-assistant/llamacpp on x86, upstream ghcr multi-arch on ARM;
// RERANK_IMAGE overrides). Serves Jina-style POST /v1/rerank on :8085; the
// node-agent /rerank proxy translates to/from the TEI wire contract.
//
// RERANK_MODEL is a bare GGUF FILENAME under /models (default
// bge-reranker-v2-m3-Q8_0.gguf) — unlike TEI it is NOT auto-downloaded
// from HF; the gguf must be shipped to the node first:
//
//  1. On the controller, place the file in the model store:
//     huggingface-cli download gpustack/bge-reranker-v2-m3-GGUF \
//     bge-reranker-v2-m3-Q8_0.gguf --local-dir "$MODELS_DIR"
//     (MODELS_DIR defaults to $NOO_DATA_ROOT/models)
//  2. Ship it to the target node:
//     noo cluster sync-model-files <node> -m bge-reranker-v2-m3-Q8_0.gguf
//     (or let preseedGGUF pull it from NOO_MODEL_CACHE_URL at start)
//  3. Recreate the container:
//     noo cluster up reranker bge-reranker-v2-m3-Q8_0.gguf --node <node>
func rerankerSpecLlamacpp() BackendSpec {
	return BackendSpec{
		Image:         envOr("RERANK_IMAGE", llamacppDefaultImage()),
		ContainerName: "noo-reranker",
		Env: map[string]string{
			"MODEL_PATH": "/models/${RERANK_MODEL:-bge-reranker-v2-m3-Q8_0.gguf}",
			// Both default images (hardened x86 + upstream ghcr :server) are
			// CPU builds; the cross-encoder is small enough that CPU is fine.
			"N_GPU_LAYERS": "0",
			"N_CTX":        "${RERANK_N_CTX:-8192}",
			"N_THREADS":    "${RERANK_THREADS:-4}",
			"HOST":         "0.0.0.0",
			"PORT":         "${RERANK_PORT:-8085}",
		},
		Volumes: []VolumeMount{
			{Source: modelsSource, Target: "/models", ReadOnly: true},
			// No PKI mount: rerankEntrypointScript passes no TLS flag to
			// llama-server and reads nothing under /app/pki. Its door is
			// the noo-stunnel-reranker sidecar (the reranker leaf); the
			// agent's /rerank proxy dials the sidecar with the node leaf.
		},
		Network:     "noo-cluster",
		Entrypoint:  []string{"sh", "-c"},
		Command:     []string{rerankEntrypointScript},
		MemoryLimit: 4 * 1024 * 1024 * 1024, // 4GB — bge-reranker-v2-m3 Q8 is ~600MB
		CPULimit:    4,
	}
}

// StartOverrides carries controller-supplied values that take precedence
// over the worker's local .env / spec defaults. This is the canonical
// source of truth for backend image + parser config — the
// controller's BackendManager builds these from `noomesh.yaml` and the
// gateway's own env, so all workers run the same image regardless of
// what their local .env says. Empty/zero fields fall through to env-based
// resolution (backwards compat for hand-started backends).
type StartOverrides struct {
	Image           string // overrides spec.Image (e.g. "vllm/vllm-openai:gemma4")
	ToolParser      string // VLLM_TOOL_PARSER (vLLM only)
	ReasoningParser string // VLLM_REASONING_PARSER (vLLM only)
	MaxModelLen     int    // VLLM_MAX_MODEL_LEN (vLLM only)
	Quantization    string // VLLM_QUANTIZATION (vLLM only)
	GpuMemUtil      string // GPU_MEMORY_UTILIZATION (vLLM/llamacpp)

	// Desired-state reconcile (DESIRED_STATE_CONFIG.md): the DB-backed
	// placement dictates where models live and any extra env — instead
	// of the node's local .env, which is exactly the drift source the
	// 2026-07-03 incidents traced back to.
	ModelsDir string            // overrides the /models bind-mount source
	ExtraEnv  map[string]string // merged last into the env list

	// SpecHash is a stable fingerprint of the desired placement spec
	// (model + image + port + tls + non-volatile env), computed by the
	// reconciler. When non-empty it is stamped on the container as the
	// SpecHashLabel so a later reconcile pass can detect spec drift
	// (env/image/port/tls edits) and recreate the container — the model
	// name alone doesn't change when only env/image/port change.
	SpecHash string

	// Target is the placement's hardware target: "cpu" | "gpu" | "" (not
	// declared). "cpu" means the container gets NO GPU device request and
	// CUDA_VISIBLE_DEVICES is emptied, and llama.cpp offloads no layers —
	// whatever N_GPU_LAYERS says, since there is no device to offload to.
	// Anything else leaves the existing GPU logic alone.
	Target string

	// MemoryLimit (bytes) replaces a llama.cpp container's fixed spec limit
	// when > 0: the controller derives it from the model's fit estimate and
	// caps it by the node's usage profile. Ignored for other backends.
	MemoryLimit int64
}

// cpuTargetEnv is what the agent stamps on a container placed with target
// cpu, after every other env source: no CUDA device is visible, and llama.cpp
// (both the noo image's N_GPU_LAYERS and upstream's LLAMA_ARG_N_GPU_LAYERS)
// offloads nothing. Agent-side, so the placement env allow-list (which
// refuses NVIDIA_* / CUDA device visibility from a placement) is untouched.
func cpuTargetEnv(backend string) map[string]string {
	env := map[string]string{"CUDA_VISIBLE_DEVICES": ""}
	if backend == "llamacpp" || backend == "reranker" {
		env["N_GPU_LAYERS"] = "0"
		env["LLAMA_ARG_N_GPU_LAYERS"] = "0"
	}
	return env
}

// llamaArgMirror maps the noo llama.cpp image's tuning env onto llama-server's
// own LLAMA_ARG_* environment. The upstream multi-arch image (ARM nodes) reads
// only LLAMA_ARG_*, so a placement's N_THREADS / N_CTX / N_BATCH / N_PARALLEL
// would otherwise be ignored there. A LLAMA_ARG_* the placement set itself
// wins; llama-server gives command-line flags precedence over this env, so an
// image that passes --threads "$N_THREADS" sees the same value either way.
var llamaArgMirror = [][2]string{
	{"N_THREADS", "LLAMA_ARG_THREADS"},
	{"N_CTX", "LLAMA_ARG_CTX_SIZE"},
	{"N_BATCH", "LLAMA_ARG_BATCH"},
	{"N_PARALLEL", "LLAMA_ARG_N_PARALLEL"},
	{"N_GPU_LAYERS", "LLAMA_ARG_N_GPU_LAYERS"},
}

// llamacppMemoryLimit is the llama.cpp container's memory limit: the
// placement's derived one when the controller sent it, else the spec's.
func llamacppMemoryLimit(specLimit, placed int64) int64 {
	if placed > 0 {
		return placed
	}
	return specLimit
}

func mirrorLlamaArgs(env map[string]string) {
	for _, m := range llamaArgMirror {
		v, ok := env[m[0]]
		// "auto" is the agent's own N_GPU_LAYERS sentinel, resolved later in
		// buildEnvList; it is not a llama-server value.
		if !ok || v == "" || v == "auto" {
			continue
		}
		if _, set := env[m[1]]; !set {
			env[m[1]] = v
		}
	}
}

// llamacppCPULimit is the llama.cpp container's CPU quota for a placement
// asking for `threads`: the spec's quota, raised to the thread count when
// the placement tuned more threads than that (a quota below the thread count
// just time-slices them), and never above the cores this node has.
func llamacppCPULimit(specLimit float64, threads string, cores int) float64 {
	n, err := strconv.Atoi(strings.TrimSpace(threads))
	if err != nil || n <= 0 || float64(n) <= specLimit {
		return specLimit
	}
	if cores > 0 && n > cores {
		n = cores
	}
	if float64(n) < specLimit {
		return specLimit
	}
	return float64(n)
}

// SpecHashLabel names the container label that carries the desired-spec
// fingerprint (StartOverrides.SpecHash). Read back by the reconciler to
// detect spec drift. Absent on containers created before this feature.
const SpecHashLabel = "noo.spec.hash"

// StartBackendSDK creates and starts a backend container using the Docker API directly.
// This replaces the `docker compose up` shell-out, eliminating the Docker CLI dependency.
//
// `overrides` lets the controller dictate image + parser
// config; empty fields fall through to env-based resolution.
func (c *Client) StartBackendSDK(backend, model string, gpuCount int, overrides StartOverrides) error {
	spec, ok := backendSpecs[backend]
	if !ok {
		return fmt.Errorf("unknown backend: %s", backend)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Minute)
	defer cancel()

	// ONE image choice (image_choice.go, shared with BackendImageRef):
	// CPU/GPU auto-select (an embedding/reranker CPUImage on a node without an
	// NVIDIA GPU; the GPU device reservation is independently gated by
	// hasNvidiaGPU() below), then the controller's override, else
	// ${VLLM_IMAGE:-default} env substitution - and the policy that refuses a
	// floating or digest-less third-party ref.
	choice, err := chooseBackendImage(backend, spec, overrides.Image)
	if err != nil {
		return err
	}
	spec.Image = choice.Ref

	// Reranker engine correction: a placement/RERANK_IMAGE override can point
	// at the other engine's image than RERANK_ENGINE selected (e.g. desired
	// state pins the TEI image while the node defaults to llamacpp). When the
	// resolved image clearly identifies an engine that contradicts the chosen
	// spec, re-derive the spec so env/entrypoint match what actually runs.
	// Ambiguous custom images keep the RERANK_ENGINE-selected spec.
	if backend == "reranker" {
		img := spec.Image
		teiSpec := spec.Env["MODEL_ID"] != ""
		teiImage := strings.Contains(img, "text-embeddings-inference")
		llamaImage := strings.Contains(img, "llamacpp") || strings.Contains(img, "llama.cpp")
		if teiImage && !teiSpec {
			spec = rerankerSpecTEI()
			spec.Image = img
		} else if llamaImage && teiSpec {
			spec = rerankerSpecLlamacpp()
			spec.Image = img
		}
	}

	// Override model in env
	envOverrides := map[string]string{}
	switch backend {
	case "vllm":
		if model != "" {
			envOverrides["VLLM_MODEL"] = model
			envOverrides["MODEL_NAME"] = model
		}
		// Controller-driven vLLM tuning — overrides whatever's in the
		// worker's .env. Empty strings mean "leave env / spec default".
		if overrides.ToolParser != "" {
			envOverrides["VLLM_TOOL_PARSER"] = overrides.ToolParser
		}
		if overrides.ReasoningParser != "" {
			envOverrides["VLLM_REASONING_PARSER"] = overrides.ReasoningParser
		}
		if overrides.MaxModelLen > 0 {
			envOverrides["VLLM_MAX_MODEL_LEN"] = fmt.Sprintf("%d", overrides.MaxModelLen)
		}
		if overrides.Quantization != "" {
			envOverrides["VLLM_QUANTIZATION"] = overrides.Quantization
		}
		if overrides.GpuMemUtil != "" {
			envOverrides["GPU_MEMORY_UTILIZATION"] = overrides.GpuMemUtil
		}
	case "llamacpp":
		if model != "" {
			// The model volume mounts at /models; a bare filename makes
			// llama-server look in its cwd and crash-loop ("failed to
			// load model" — observed on host8 2026-07-03).
			mp := model
			if !strings.HasPrefix(mp, "/") {
				mp = "/models/" + mp
			}
			envOverrides["MODEL_PATH"] = mp
			// Upstream ghcr.io/ggml-org/llama.cpp images (ARM nodes)
			// ignore the noo image's MODEL_PATH/PORT/HOST wrapper envs
			// and read LLAMA_ARG_* instead — without these host9's
			// container came up in model-less router mode on :8080.
			envOverrides["LLAMA_ARG_MODEL"] = mp
		}
		envOverrides["LLAMA_ARG_HOST"] = "0.0.0.0"
		envOverrides["LLAMA_ARG_PORT"] = resolveEnv("${LLAMACPP_PORT:-8085}")
		// llamacpp doesn't use GPU_MEMORY_UTILIZATION — its sizing is
		// driven by N_GPU_LAYERS / N_CTX, both kept worker-local in env.
	case "ollama":
		if model != "" {
			envOverrides["OLLAMA_MODEL"] = model
		}
	case "airllm":
		if model != "" {
			envOverrides["MODEL_PATH"] = model
		}
	case "embedding":
		if model != "" {
			envOverrides["MODEL_ID"] = model
		}
	case "reranker":
		if model != "" {
			if spec.Env["MODEL_ID"] != "" {
				// TEI engine: HF repo id.
				envOverrides["MODEL_ID"] = model
			} else {
				// llama.cpp engine: gguf filename under the /models mount
				// (same bare-filename handling as the llamacpp backend).
				mp := model
				if !strings.HasPrefix(mp, "/") {
					mp = "/models/" + mp
				}
				envOverrides["MODEL_PATH"] = mp
			}
		}
	}

	// GPU count override
	gpuReserve := resolveEnv(spec.GPUCount)
	if gpuCount > 1 {
		gpuReserve = fmt.Sprintf("%d", gpuCount)
		envOverrides["TENSOR_PARALLEL_SIZE"] = fmt.Sprintf("%d", gpuCount)
		envOverrides["GPU_COUNT"] = fmt.Sprintf("%d", gpuCount)
	}

	// Prefer a locally-present hardened llamacpp build over the upstream
	// multi-arch image. Candidates, in order:
	//   1. pai-assistant/llamacpp:<GOARCH>  — an explicitly arch-tagged
	//      build shipped to this node (the cross-arch story; lets an arm64
	//      edge node get a genuine arm64 image, not a mislabeled one).
	//   2. pai-assistant/llamacpp:latest    — the controller's compose-built
	//      image, and what `sync-images` ships same-arch (x86→x86). This is
	//      what makes the feature fire TODAY on same-arch nodes.
	// First that exists wins; otherwise fall back to upstream. Explicit
	// LLAMACPP_IMAGE / placement overrides are respected — spec.Image only
	// equals the ghcr default when nothing overrode it.
	if backend == "llamacpp" && spec.Image == "ghcr.io/ggml-org/llama.cpp:server" {
		for _, hardened := range []string{
			fmt.Sprintf("pai-assistant/llamacpp:%s", runtime.GOARCH),
			"pai-assistant/llamacpp:latest",
		} {
			info, err := c.docker.ImageInspect(ctx, hardened)
			if err != nil {
				continue
			}
			// Verify the image's real arch matches this node — guards
			// against a wrong-arch :latest that would exec-format-error at
			// start (an x86 image manually loaded on an arm64 box).
			if info.Architecture != "" && info.Architecture != runtime.GOARCH {
				slog.Warn("skipping arch-mismatched llamacpp image",
					"image", hardened, "image_arch", info.Architecture,
					"node_arch", runtime.GOARCH)
				continue
			}
			slog.Info("using hardened llamacpp build", "image", hardened)
			spec.Image = hardened
			break
		}
	}

	// The image: local if the controller vouches for it, else over the
	// artifact rail; never a registry pull for our own images (image_source.go).
	ctx = withRailOnly(ctx, choice.RailOnly)
	if err := ensureImageFn(ctx, c, spec.Image); err != nil {
		return fmt.Errorf("backend %s image: %w", backend, err)
	}

	// Model-weight store (delivery layer): copy the placed model's weights
	// from the controller's store into this node's HF cache before the
	// backend starts, then run offline.
	//
	// On a PLACED node (NOO_MODEL_CACHE_URL set: it takes its weights from the
	// controller) the run is ALWAYS offline and holds no Hugging Face token: a
	// store miss is an explained refusal, never a WAN download from
	// huggingface.co. The weights a node runs are the ones the controller
	// holds, and a mis-staged cache shows up as a refusal `noo cluster
	// verify` names instead of a multi-GB download that hides it. A node with
	// no store configured (the controller's own agent, a dev box) keeps the
	// old behaviour: online on a miss, the token passed through.
	if hfBackend(backend) && placedNode() && !isGGUFModel(model) {
		hit := c.preseedModel(ctx, backend, model)
		if !hit && model != "" && !hfRepoCachedLocally(model) {
			return &ModelNotStagedError{Backend: backend, Model: model}
		}
		envOverrides["HF_HUB_OFFLINE"] = "1"
		envOverrides["HF_TOKEN"] = ""
		envOverrides["HUGGING_FACE_HUB_TOKEN"] = ""
	} else if c.preseedModel(ctx, backend, model) {
		envOverrides["HF_HUB_OFFLINE"] = "1"
	}
	// GGUF weights (llama.cpp) are a flat file; copy from the store if present.
	c.preseedGGUF(ctx, backend, model)

	// Placement-driven extras win over everything env-derived.
	for k, v := range overrides.ExtraEnv {
		envOverrides[k] = v
	}
	// A cpu target overrides even the placement's own GPU sizing: there is
	// no device to size for.
	if overrides.Target == "cpu" {
		for k, v := range cpuTargetEnv(backend) {
			envOverrides[k] = v
		}
		gpuReserve = "0"
	}
	if backend == "llamacpp" {
		mirrorLlamaArgs(envOverrides)
		spec.CPULimit = llamacppCPULimit(spec.CPULimit, envOverrides["N_THREADS"], runtime.NumCPU())
		spec.MemoryLimit = llamacppMemoryLimit(spec.MemoryLimit, overrides.MemoryLimit)
	}

	// Build environment list
	env := buildEnvList(spec.Env, envOverrides)

	// Placement models_dir replaces the env-resolved /models source — but
	// only after the node agrees the path is one of its own.
	//
	// This used to swap the bind source with no check whatsoever. The
	// reconciler validates before it gets here, and this is the second
	// check at the only function that creates the container: the day a
	// second caller appears, the validation must not be somewhere else.
	// A refusal fails the START; it does not quietly fall back to the
	// node's default, because a backend running against a different
	// models dir than the placement describes is a wrong answer wearing a
	// success.
	if overrides.ModelsDir != "" {
		clean, err := ValidateHostPathUnderRoots(overrides.ModelsDir)
		if err != nil {
			return fmt.Errorf("models_dir for backend %s: %w", backend, err)
		}
		for i := range spec.Volumes {
			if spec.Volumes[i].Target == "/models" {
				spec.Volumes[i].Source = clean
			}
		}
	}

	// Build mounts and check the DOOR before touching the running
	// container. A backend the agent dials with a client certificate must
	// have the leaf its door serves with — vLLM's own, or its sidecar's —
	// and the leaf must name the host the agent dials; otherwise refuse
	// here, while whatever runs today keeps running. Until 2026-09-29 this
	// check sat AFTER the stop/remove below, so a refusal left the node
	// with no backend at all instead of the one it had.
	mounts, _ := buildMounts(spec.Volumes)
	if err := backendDoorCheck(backend, mounts); err != nil {
		return err
	}
	// Enforcing nodes refuse to mount anything until their data root passes
	// the policy (dataroots/policy.go); warn mode only reports.
	if err := dataroots.Refusal(dataroots.Current()); err != nil {
		return fmt.Errorf("backend %s: %w", backend, err)
	}
	if err := requireMountSources(backend, mounts); err != nil {
		return err
	}
	// The sidecar image, for the same reason: a pull that fails must not
	// have cost the running backend first.
	var sidecarImage string
	if SidecarFor(backend) != "" {
		img, err := c.ensureSidecarImage(ctx)
		if err != nil {
			return fmt.Errorf("sidecar image for %s: %w", backend, err)
		}
		sidecarImage = img
	}

	// Build command
	cmd := resolveEnvSlice(spec.Command)
	entrypoint := spec.Entrypoint

	// Container config
	containerCfg := &container.Config{
		Image: spec.Image,
		Env:   env,
		Labels: map[string]string{
			"com.docker.compose.project": "pai-assistant",
			"noo.backend":                backend,
			"noo.managed-by":             "node-agent-go",
		},
	}
	// Stamp the desired-spec fingerprint so the reconciler can detect
	// spec drift (env/image/port/tls edits) on a later pass and recreate.
	if overrides.SpecHash != "" {
		containerCfg.Labels[SpecHashLabel] = overrides.SpecHash
	}
	if len(cmd) > 0 {
		containerCfg.Cmd = cmd
	}
	if len(entrypoint) > 0 {
		containerCfg.Entrypoint = entrypoint
	}
	// Override the image's healthcheck when the spec pins one, so the probe
	// targets the port we actually configured rather than the image default.
	// CMD-SHELL (not CMD) so ${VAR} inside the URL is expanded by the
	// container's shell at probe time, matching how Command/Env are handled.
	if spec.DisableHealthcheck {
		containerCfg.Healthcheck = &container.HealthConfig{Test: []string{"NONE"}}
	} else if spec.HealthcheckCmd != "" {
		containerCfg.Healthcheck = &container.HealthConfig{
			Test:        []string{"CMD-SHELL", spec.HealthcheckCmd},
			Interval:    30 * time.Second,
			Timeout:     10 * time.Second,
			Retries:     3,
			StartPeriod: 900 * time.Second, // a cold vLLM model load
		}
	} else if url := resolveEnv(spec.HealthcheckURL); url != "" {
		containerCfg.Healthcheck = &container.HealthConfig{
			Test:        []string{"CMD-SHELL", fmt.Sprintf("curl -fsS %s >/dev/null 2>&1 || exit 1", url)},
			Interval:    30 * time.Second,
			Timeout:     5 * time.Second,
			Retries:     3,
			StartPeriod: 120 * time.Second, // model load can take minutes on edge nodes
		}
	}

	// Host config.
	//
	// The two security lines are the floor for EVERY backend container,
	// whatever the controller asked for — the same floor skills.go applies
	// to a skill sandbox, and for the same reason: the image and the
	// environment are controller-chosen, so the container's privileges must
	// not be.
	//
	//   no-new-privileges  a setuid binary inside the image cannot buy back
	//                      what CapDrop took away.
	//   CapDrop ALL + CapAdd backendCaps  an inference server needs no
	//                      kernel capability of its own. What it does need
	//                      is the entrypoint pattern these images share:
	//                      start as root, chown the cache/model directory,
	//                      drop to a service user. That is CHOWN,
	//                      DAC_OVERRIDE, FOWNER, SETGID, SETUID and nothing
	//                      else. Gone: SYS_ADMIN, SYS_PTRACE, SYS_MODULE,
	//                      NET_RAW, NET_ADMIN, MKNOD, SYS_CHROOT — the set
	//                      that turns a container escape into a host.
	//
	// GPU access does NOT need a capability. The NVIDIA container runtime
	// works through device cgroups and bind-mounted driver libraries
	// (hostCfg.Resources.DeviceRequests below), not through the ambient
	// capability set — which is why the compose services that run these
	// same images are not privileged either.
	hostCfg := &container.HostConfig{
		Mounts:        mounts,
		RestartPolicy: container.RestartPolicy{Name: container.RestartPolicyUnlessStopped},
		SecurityOpt:   []string{"no-new-privileges"},
		CapDrop:       []string{"ALL"},
		CapAdd:        backendCaps(),
	}

	// Resource limits
	if spec.MemoryLimit > 0 {
		hostCfg.Resources.Memory = spec.MemoryLimit
	}
	if spec.CPULimit > 0 {
		hostCfg.Resources.NanoCPUs = int64(spec.CPULimit * 1e9)
	}

	// GPU reservation — only request the NVIDIA device driver if this
	// node actually has NVIDIA GPUs. ARM SBCs (Pi, Jetson Nano with
	// integrated GPU) and CPU-only x86 boxes don't, and Docker fails
	// the start with `could not select device driver "nvidia"` when we
	// ask for one anyway.
	//
	// A GPU the kernel shows is not a GPU Docker can hand out: the device
	// request only works when the NVIDIA container runtime is registered
	// with the daemon. On WSL2 the /dev/dxg probe says "GPU" on every box
	// (the host's, inherited by any container), and a tier-3 worker with no
	// toolkit then failed every placed backend with "could not select
	// device driver nvidia", reconciling into the same wall every five
	// minutes (2026-09-28 newcomer rehearsal). Ask the daemon; without the
	// runtime, start on CPU and say so once per start.
	if gpuReserve != "" && gpuReserve != "0" && hasNvidiaGPU() {
		if c.nvidiaRuntimeRegistered(ctx) {
			hostCfg.Resources.DeviceRequests = []container.DeviceRequest{
				{
					Driver:       "nvidia",
					Capabilities: [][]string{{"gpu"}},
					Count:        parseGPUCount(gpuReserve),
				},
			}
		} else {
			slog.Warn("GPU detected but the NVIDIA container runtime is not registered with Docker — starting on CPU",
				"backend", backend, "fix", "install the NVIDIA container toolkit (nvidia-ctk runtime configure) and restart docker, or set NOO_NO_GPU=1")
		}
	}

	// vLLM is its own door (--ssl-cert-reqs 2): on macOS publish that
	// listener on host loopback so the host-mode dialer can reach it
	// (LoopbackDoorPublish). A sidecar-fronted backend's raw port is never
	// published — its door is the sidecar's (startSidecar).
	if door, ok := backendDoors[backend]; ok && door.Sidecar == "" && LoopbackDoorPublish() {
		applyLoopbackDoor(containerCfg, hostCfg, door.Port)
	}

	// Network config — ensure network exists on this node
	networkCfg := &network.NetworkingConfig{}
	if spec.Network != "" {
		if err := c.ensureNetwork(ctx, spec.Network); err != nil {
			slog.Warn("could not create network, using default", "network", spec.Network, "error", err)
		} else {
			networkCfg.EndpointsConfig = map[string]*network.EndpointSettings{
				spec.Network: {},
			}
		}
	}

	// Remove the existing container only now, after every check above has
	// passed. It used to go first, so a start that was always going to fail
	// (a bind source that no longer exists, a refused models_dir) took down
	// a backend that was serving: host3's vLLM, 2026-09-29, when a
	// placement edit recreated it against a cache path the node's env no
	// longer named. A refusal now leaves the old container running.
	_, _ = c.docker.ContainerStop(ctx, spec.ContainerName, client.ContainerStopOptions{})
	_, _ = c.docker.ContainerRemove(ctx, spec.ContainerName, client.ContainerRemoveOptions{Force: true})
	c.removeSidecar(ctx, backend)

	// Create and start
	resp, err := c.docker.ContainerCreate(ctx, client.ContainerCreateOptions{
		Config:           containerCfg,
		HostConfig:       hostCfg,
		NetworkingConfig: networkCfg,
		Name:             spec.ContainerName,
	})
	if err != nil {
		return fmt.Errorf("create container %s: %w", spec.ContainerName, err)
	}

	if _, err := c.docker.ContainerStart(ctx, resp.ID, client.ContainerStartOptions{}); err != nil {
		return fmt.Errorf("start container %s: %w", spec.ContainerName, err)
	}

	// The door. A backend that cannot terminate TLS itself gets its stunnel
	// sidecar now; if the sidecar cannot start, the backend does not stay
	// up plain behind a missing door — it is torn down and the start fails
	// loudly (the reconciler records it; `cluster verify` shows the row).
	if sidecarImage != "" {
		port := sidecarConnectPort(backend, spec, envOverrides)
		if err := c.startSidecar(ctx, backend, sidecarImage, spec.Network, spec.ContainerName, port); err != nil {
			_, _ = c.docker.ContainerStop(ctx, spec.ContainerName, client.ContainerStopOptions{})
			_, _ = c.docker.ContainerRemove(ctx, spec.ContainerName, client.ContainerRemoveOptions{Force: true})
			return fmt.Errorf("start %s door (%s): %w — %s torn down rather than left serving plaintext",
				backend, SidecarContainerFor(backend), err, spec.ContainerName)
		}
	}

	slog.Info("backend started via SDK", "backend", backend, "model", model, "container", spec.ContainerName,
		"door", backendDialURL(backend, nil))
	return nil
}

// StopBackendSDK stops and removes a backend container using the Docker API.
func (c *Client) StopBackendSDK(backend string) error {
	spec, ok := backendSpecs[backend]
	if !ok {
		return fmt.Errorf("unknown backend: %s", backend)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	timeout := 10
	if _, err := c.docker.ContainerStop(ctx, spec.ContainerName, client.ContainerStopOptions{Timeout: &timeout}); err != nil {
		slog.Warn("stop container warning", "container", spec.ContainerName, "error", err)
	}

	if _, err := c.docker.ContainerRemove(ctx, spec.ContainerName, client.ContainerRemoveOptions{}); err != nil {
		slog.Debug("remove container note", "container", spec.ContainerName, "error", err)
	}
	c.removeSidecar(ctx, backend)

	slog.Info("backend stopped via SDK", "backend", backend, "container", spec.ContainerName)
	return nil
}

// preseedModel copies a placed HF model from the controller's model-weight
// store into this node's HF cache, so the backend can start with
// HF_HUB_OFFLINE=1. Best-effort: a store miss or any error returns false and
// the backend downloads from HuggingFace as usual. Only HF-repo backends
// (vllm/embedding/reranker); GGUF + Ollama use other delivery paths.
// Requires NOO_MODEL_CACHE_URL on the node.
//
// In-process since 2026-09-12. This used to run inside a disposable helper
// container from the agent's OWN image (`noo-node-agent -preseed` with the
// HF cache bind-mounted) — written when the agent was itself a container and
// the host cache was easiest to reach from inside one. The agent has been a
// host process since the fleet hardening, and no rail delivers its image to
// a node (`upgrade --nodes` ships the binary, `sync-images` declines
// node-agent refs, `upgrade-agents` needs a checkout), so on every node the
// helper was "No such image" and the preseed silently fell back to a
// multi-GB WAN download that then died mid-stream (host3, vllm gemma4-12B).
// The binary already carries the preseed code — the Ollama import uses it
// directly — so the HF snapshot now goes the same way: this process, the
// host path, the same model-cache rail (mTLS :8443 C-i).
func (c *Client) preseedModel(ctx context.Context, backend, model string) bool {
	cacheURL := preseed.CacheURL()
	if cacheURL == "" || model == "" {
		return false
	}
	switch backend {
	case "vllm", "embedding", "reranker":
	default:
		return false
	}
	// A gguf reranker (llamacpp engine) is a flat file, not an HF repo —
	// preseedGGUF handles it.
	if strings.HasSuffix(strings.ToLower(model), ".gguf") {
		return false
	}
	repo := preseed.RepoCacheDir(model)
	src := fmt.Sprintf("%s/hf/%s/", cacheURL, repo)
	hfHost := resolveEnv(hfCacheSource)
	dest := filepath.Join(hfHost, "hub", repo)
	// Model weights are multi-GB; give the copy a generous window (bounded by
	// the caller's ctx). The old fixed 60s killed it mid-download.
	mctx, cancel := context.WithTimeout(ctx, 15*time.Minute)
	defer cancel()
	n, err := preseed.New().MirrorHFRepo(mctx, src, dest)
	if err != nil {
		if isPermissionErr(err) {
			// Not a miss: the store has the model and this process cannot
			// write where the backend will read. Say so, once, with the
			// path — the fallback still runs so the placement is not lost.
			slog.Error("model preseed cannot write the node's HF cache — falling back to HF",
				"model", model, "dest", dest, "error", err,
				"fix", "make "+hfHost+" writable by the agent's user (it is a declared host root; prep-host owns it)")
		} else {
			slog.Info("model-cache preseed miss; downloading from HF",
				"model", model, "src", src, "err", err)
		}
		return false
	}
	slog.Info("model preseeded from controller store", "model", model, "files", n, "dest", dest)
	return true
}

// preseedGGUF copies a placed GGUF weight from the controller's model-weight
// store (/gguf/<file>) into this node's models dir before a llamacpp backend
// starts, so an edge node that lacks the file pulls it over the LAN instead of
// requiring manual placement. Unlike HF weights, a GGUF is one flat file and
// llama.cpp loads it by path — no offline env flag needed, just presence.
// Best-effort: on a miss, StartBackendSDK proceeds and llama.cpp fails exactly
// as it would today if the file were absent. Requires NOO_MODEL_CACHE_URL.
// In-process for the same reason as preseedModel (see there).
func (c *Client) preseedGGUF(ctx context.Context, backend, model string) bool {
	cacheURL := preseed.CacheURL()
	// llamacpp LLMs and gguf rerankers (llamacpp-engine reranker backend)
	// both load flat gguf files from /models.
	if cacheURL == "" || model == "" || (backend != "llamacpp" && backend != "reranker") {
		return false
	}
	if !strings.HasSuffix(strings.ToLower(model), ".gguf") || strings.Contains(model, "/") {
		return false // only bare GGUF filenames; guard path traversal
	}
	src := fmt.Sprintf("%s/gguf/%s", cacheURL, url.PathEscape(model))
	modelsHost := resolveEnv(modelsSource)
	dest := filepath.Join(modelsHost, model)
	// Ask the controller's artifact manifest what these bytes should hash to
	// NO MANIFEST, NO PRESEED.
	//
	// This used to fall through and copy the bytes unverified when the
	// manifest route answered 404, "to keep the rollout order free". That
	// turned an integrity control into a suggestion: anything that could
	// answer NOO_MODEL_CACHE_URL — or sit on the path to it — chose the
	// weights this node then loads and serves.
	//
	// Refusing costs nothing real. The manifest route hashes the SAME
	// directory the cache serves (docker-compose.cluster.yml: MODELS_DIR is
	// bound read-only at /artifacts/models, served as /gguf/ by the model cache), so a
	// 404 manifest means the cache does not hold the file either. And the
	// preseed was always best-effort: a refusal leaves the backend to load a
	// locally-present file exactly as before, or to fail with the same
	// "model not found" it would have had.
	//
	// Version floor: the manifest route (GET /api/artifacts/manifest/{kind}/
	// {name}) landed in gateway stack-v0.2.25. A node agent carrying this
	// change against an OLDER gateway never preseeds GGUFs — ship the file
	// with `noo cluster sync-model-files` instead, or roll the gateway first.
	sha := fetchArtifactDigest(ctx, "gguf", model)
	if sha == "" {
		slog.Warn("gguf preseed refused: no artifact manifest for these bytes",
			"model", model,
			"detail", "the controller could not state a sha256 for this file, so the "+
				"copy would be unverified; refusing rather than loading bytes nothing vouched for",
			"fix", "roll a gateway >= stack-v0.2.25 (which serves /api/artifacts/manifest), "+
				"confirm the file is in the controller's model store, or place it on the node "+
				"with `noo cluster sync-model-files`")
		return false
	}
	slog.Info("gguf preseed will verify against controller manifest",
		"model", model, "sha256", sha[:12]+"…")
	fctx, cancel := context.WithTimeout(ctx, 15*time.Minute)
	defer cancel()
	wrote, err := preseed.New().FetchOneVerified(fctx, src, dest, sha)
	if err != nil {
		if isPermissionErr(err) {
			slog.Error("gguf preseed cannot write the node's models dir — expecting local file or manual placement",
				"model", model, "dest", dest, "error", err,
				"fix", "make "+modelsHost+" writable by the agent's user (it is a declared host root; prep-host owns it)")
		} else {
			slog.Info("gguf preseed miss; expecting local file or manual placement",
				"model", model, "src", src, "err", err)
		}
		return false
	}
	slog.Info("gguf preseeded from controller store", "model", model, "wrote", wrote, "dest", dest)
	return true
}

// isPermissionErr tells "this process may not write here" from every other
// preseed failure, so the log names the fix instead of calling it a miss.
func isPermissionErr(err error) bool {
	return errors.Is(err, os.ErrPermission) || errors.Is(err, fs.ErrPermission)
}

// fetchArtifactDigest asks the gateway's artifact control plane for the
// sha256 of a named artifact. Empty string means "no digest available" —
// route missing (older gateway), artifact unknown, or any transport error.
// The caller treats that as "pull unverified", never as a failure: the
// manifest is an integrity UPGRADE, not a new hard dependency.
//
// Auth is the same cluster-HMAC bearer the heartbeat uses, and TLS is the
// same CA-verified transport (config.HTTPTransport loads NOO_TLS_CA into
// RootCAs). Verification is NOT skippable here on purpose: this endpoint is
// the integrity root for the bytes about to be executed as a model — a
// manifest accepted from an unverified peer would let an on-path attacker
// bless arbitrary bytes with a matching digest. No CA configured → no
// digest → the pull proceeds unverified, which is honest about what it is.
func fetchArtifactDigest(ctx context.Context, kind, name string) string {
	m := fetchArtifactManifest(ctx, kind, name)
	if m == nil {
		return ""
	}
	return m.SHA256
}

// artifactManifest is the gateway's manifest response, including the step-7
// signature fields when the gateway signs (jws + signer_cert_pem). Callers
// that only need integrity-over-TLS read SHA256; the swap path carries the
// signed pair through to the hostd verifier.
//
// ImageID and LockDigest are set for kind=image only, by a gateway that
// reads the controller's staging records (the `<tar>.imageid` sidecar and
// staged-images.json): the local image ID the tar loads as, and the
// release-lock digest it was staged from. An older gateway omits both, and
// every caller treats "absent" as "cannot compare", never as a match.
type artifactManifest struct {
	SHA256        string `json:"sha256"`
	JWS           string `json:"jws"`
	SignerCertPEM string `json:"signer_cert_pem"`
	ImageID       string `json:"image_id"`
	LockDigest    string `json:"lock_digest"`
}

// fetchArtifactManifest asks the gateway's artifact control plane for the
// full manifest. Nil means "no manifest available" — same contract as
// fetchArtifactDigest's empty string, for the same reasons (see above).
func fetchArtifactManifest(ctx context.Context, kind, name string) *artifactManifest {
	controller := strings.TrimRight(os.Getenv("CONTROLLER_URL"), "/")
	if controller == "" {
		return nil
	}
	reqURL := fmt.Sprintf("%s/api/artifacts/manifest/%s/%s", controller, kind, url.PathEscape(name))
	ctx, cancel := context.WithTimeout(ctx, 15*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, reqURL, nil)
	if err != nil {
		return nil
	}
	if secret := nodeconfig.Load().ClusterSecret; secret != "" {
		nodeID := os.Getenv("NODE_ID")
		auth.SetClusterAuth(req, nodeID, secret)
	}
	transport, err := nodeconfig.Load().HTTPTransport()
	if err != nil {
		return nil
	}
	httpClient := &http.Client{Timeout: 15 * time.Second, Transport: transport}
	resp, err := httpClient.Do(req)
	if err != nil {
		return nil
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return nil
	}
	var m artifactManifest
	if json.Unmarshal(body, &m) != nil || len(m.SHA256) != 64 {
		return nil
	}
	m.SHA256 = strings.ToLower(m.SHA256)
	return &m
}

// --- helpers ---

// resolveEnv performs ${VAR:-default} substitution from os.Environ.
// Supports nested expressions like ${OUTER:-${INNER}/cache}.
func resolveEnv(s string) string {
	if !strings.Contains(s, "${") {
		return s
	}

	result := s
	for {
		start := strings.Index(result, "${")
		if start < 0 {
			break
		}

		// Find matching closing brace, accounting for nesting
		end := findMatchingBrace(result, start+2)
		if end < 0 {
			break
		}

		expr := result[start+2 : end]
		var name, fallback string
		if idx := strings.Index(expr, ":-"); idx >= 0 {
			name = expr[:idx]
			fallback = expr[idx+2:]
		} else {
			name = expr
			fallback = ""
		}

		val := os.Getenv(name)
		if val == "" {
			val = resolveEnv(fallback) // recursive for nested ${...}
		}

		result = result[:start] + val + result[end+1:]
	}
	return result
}

// findMatchingBrace finds the closing } for an expression starting at pos,
// handling nested ${...} braces.
func findMatchingBrace(s string, pos int) int {
	depth := 1
	for i := pos; i < len(s); i++ {
		if i+1 < len(s) && s[i] == '$' && s[i+1] == '{' {
			depth++
			i++ // skip '{'
		} else if s[i] == '}' {
			depth--
			if depth == 0 {
				return i
			}
		}
	}
	return -1
}

func resolveEnvSlice(ss []string) []string {
	out := make([]string, len(ss))
	for i, s := range ss {
		out[i] = resolveEnv(s)
	}
	return out
}

func buildEnvList(specEnv map[string]string, overrides map[string]string) []string {
	merged := make(map[string]string, len(specEnv)+len(overrides))
	for k, v := range specEnv {
		merged[k] = resolveEnv(v)
	}
	for k, v := range overrides {
		merged[k] = v
	}
	// A telemetry switch the spec carries is not overridable: a placement's
	// env or a node-local value cannot turn vendor phone-home back on.
	for k, v := range specEnv {
		if IsTelemetrySwitch(k) {
			merged[k] = resolveEnv(v)
		}
	}

	// Resolve "auto" sentinels for GPU-aware defaults. Only applied AFTER
	// user overrides so explicit values always win.
	if merged["N_GPU_LAYERS"] == "auto" {
		if hasNvidiaGPU() {
			merged["N_GPU_LAYERS"] = "999" // llama.cpp convention: offload all
		} else {
			merged["N_GPU_LAYERS"] = "0" // CPU-only
		}
	}

	env := make([]string, 0, len(merged))
	for k, v := range merged {
		env = append(env, k+"="+v)
	}
	return env
}

// skippedMount is a VolumeMount buildMounts left out, with why.
type skippedMount struct {
	Source string // resolved host path
	Target string
	Reason string
}

// buildMounts resolves each VolumeMount's host source and returns the bind
// mounts to hand Docker, plus every mount it left out. Nothing is skipped
// silently: a container running without a bind it was specified with is a
// wrong answer wearing a success, so each skip is logged here and the list
// is returned for the caller to judge (backendDoorCheck fails a start
// whose TLS leaf is among them).
func buildMounts(vols []VolumeMount) ([]mount.Mount, []skippedMount) {
	mounts := make([]mount.Mount, 0, len(vols))
	var skipped []skippedMount
	skip := func(v VolumeMount, source, reason string) {
		skipped = append(skipped, skippedMount{Source: source, Target: v.Target, Reason: reason})
		slog.Info("backend.mount_skipped", "target", v.Target, "source", source, "reason", reason)
	}
	for _, v := range vols {
		source := resolveEnv(v.Source)
		if source == "" || strings.HasPrefix(source, "./.pki-placeholder") {
			skip(v, source, "placeholder source (NOO_PKI_DIR unset)")
			continue
		}
		if v.Optional {
			if _, err := os.Stat(source); err != nil {
				skip(v, source, "optional source missing: "+err.Error())
				continue
			}
		}
		mounts = append(mounts, mount.Mount{
			Type:     mount.TypeBind,
			Source:   source,
			Target:   v.Target,
			ReadOnly: v.ReadOnly,
		})
	}
	return mounts, skipped
}

// requireMountSources refuses a start whose bind sources do not exist.
//
// Docker would refuse the create anyway ("bind source path does not exist"),
// but only after StartBackend had removed the running container. Checking
// here keeps the old one serving. Only a definite not-exist refuses: a
// source this agent cannot stat (a root-only path the daemon can still
// bind) is left to Docker, so the check never blocks a start that works.
func requireMountSources(backend string, mounts []mount.Mount) error {
	for _, m := range mounts {
		if m.Type != mount.TypeBind {
			continue
		}
		if _, err := os.Stat(m.Source); err != nil && os.IsNotExist(err) {
			return fmt.Errorf("backend %s: bind source %s (for %s) does not exist on this node; "+
				"not replacing the running container — check HF_CACHE_DIR / NOO_DATA_ROOT / MODELS_DIR in the agent env%s",
				backend, m.Source, m.Target, dataRootHint(m.Source))
		}
	}
	return nil
}

// backendDoorCheck refuses to start a backend whose door cannot be built
// from what this node holds: the service leaf the door serves with (vLLM's
// own listener reads services/vllm; a sidecar reads services/<sidecar>),
// the cluster CA, and — because the agent verifies the door's hostname
// when it dials — a leaf that actually NAMES the host the agent dials
// (`noo-vllm`, `noo-stunnel-<x>`; the controller's own service leaves
// carry these SANs, onboard steps.rs svc_extra_hostnames).
//
// Both halves used to fail quietly: vllmEntrypointScript tested `-f
// service.crt` and served plain HTTP when the leaf was absent, and a
// mis-issued leaf failed at the first request's handshake while the
// container sat "Up (healthy)". The refusal rides the heartbeat
// (reconcile_refusals) and shows as a `cluster verify` row on the node.
// Called BEFORE the running container is touched, so a refusal costs
// nothing that runs today.
func backendDoorCheck(backend string, mounts []mount.Mount) error {
	door, ok := backendDoors[backend]
	if !ok {
		// Plain by named exception (airllm) — nothing to check.
		refusals.Clear("backend_tls", backend)
		return nil
	}
	svc := doorLeafService(backend)
	dialHost := "noo-" + backend
	if door.Sidecar != "" {
		dialHost = StunnelContainerPrefix + door.Sidecar
	}
	fix := "re-run `noo cluster provision <this node>` on the controller (or `noo upgrade --nodes`): " +
		"the provision bundle carries this node's backend door leaves (svc-" + svc + ".crt/.key, SAN " +
		dialHost + ") and noo-apply installs them under $NOO_PKI_DIR/services/" + svc + "/"
	refuse := func(reason string) error {
		refusals.Record("backend_tls", backend, reason)
		return fmt.Errorf("refusing to start %s: %s", backend, reason)
	}

	pkiDir := resolveEnv("${NOO_PKI_DIR:-}")
	if pkiDir == "" {
		return refuse("NOO_PKI_DIR is not set, so this node cannot hand " + svc + "'s door its leaf " +
			"(services/" + svc + "/service.{crt,key}) or the cluster CA; set it in /etc/noo-node-agent.env " +
			"(provision renders /etc/noo/pki)")
	}
	caPath := resolveEnv(pkiCACertSource)
	if _, err := os.Stat(caPath); err != nil {
		return refuse("no cluster CA at " + caPath + " (" + err.Error() + "); the door verifies every " +
			"caller against it — re-run `noo cluster provision <node>`")
	}
	leafDir := resolveEnv(pkiServiceLeafSource(svc))
	crt := filepath.Join(leafDir, "service.crt")
	key := filepath.Join(leafDir, "service.key")
	for _, f := range []string{crt, key} {
		if _, err := os.Stat(f); err != nil {
			return refuse("this node's PKI dir has no services/" + svc + " leaf (" + f + ": " + err.Error() +
				"); a provisioned node holds ca.crt + its node cert only, and " + backend +
				"'s door (" + dialHost + ") serves with that leaf. Fix: " + fix)
		}
	}
	if door.Sidecar == "" {
		// vLLM reads the leaf from its own mounts; the mount must be there.
		seen := 0
		for _, m := range mounts {
			if m.Target == pkiServiceLeafTarget(svc) || m.Target == pkiCACertTarget {
				seen++
			}
		}
		if seen != 2 {
			return refuse("the vllm leaf or the cluster CA is not among the container's mounts " +
				"(buildMounts skipped it — see backend.mount_skipped above); the listener would " +
				"refuse to start (exit 78). Fix: " + fix)
		}
	}
	names, err := leafDNSNames(crt)
	if err != nil {
		return refuse("services/" + svc + "/service.crt is not a readable certificate (" + err.Error() +
			"). Fix: " + fix)
	}
	for _, n := range names {
		if n == dialHost {
			refusals.Clear("backend_tls", backend)
			return nil
		}
	}
	return refuse("services/" + svc + "/service.crt does not name " + dialHost + " (SANs: " +
		strings.Join(names, ", ") + "); the agent dials the door by that name and verifies it, so " +
		"every request would fail the handshake. Fix: " + fix)
}

// leafDNSNames returns the DNS SANs of a PEM certificate file.
func leafDNSNames(path string) ([]string, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	block, _ := pem.Decode(raw)
	if block == nil {
		return nil, errors.New("no PEM block")
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return nil, err
	}
	return cert.DNSNames, nil
}

// vllmHealthcheckCmd probes vLLM's mTLS listener with the container's own
// leaf (CMD-SHELL; python3 because the vllm image carries no curl). Mirrors
// the compose vllm service's healthcheck byte for byte in intent.
const vllmHealthcheckCmd = `python3 -c "import ssl,urllib.request; ctx=ssl.create_default_context(cafile='/app/pki/ca.crt'); ctx.load_cert_chain('/app/pki/services/vllm/service.crt','/app/pki/services/vllm/service.key'); urllib.request.urlopen('https://localhost:8000/health',context=ctx,timeout=5)" || exit 1`

// ensureNetwork creates a Docker bridge network if it doesn't already exist.
// Worker nodes don't have docker-compose creating networks, so the agent does it.
func (c *Client) ensureNetwork(ctx context.Context, name string) error {
	_, err := c.docker.NetworkInspect(ctx, name, client.NetworkInspectOptions{})
	if err == nil {
		return nil // already exists
	}
	_, err = c.docker.NetworkCreate(ctx, name, client.NetworkCreateOptions{
		Driver: "bridge",
		Labels: map[string]string{
			"noo.managed-by": "node-agent-go",
		},
	})
	if err != nil {
		return fmt.Errorf("create network %s: %w", name, err)
	}
	slog.Info("docker network created", "network", name)
	return nil
}

func parseGPUCount(s string) int {
	if s == "all" {
		return -1 // Docker API: -1 means all GPUs
	}
	n := 1
	fmt.Sscanf(s, "%d", &n)
	return n
}

// backendCapsDefault is the capability set every backend container keeps
// after CapDrop ALL. See the HostConfig comment in StartBackendSDK.
var backendCapsDefault = []string{"CHOWN", "DAC_OVERRIDE", "FOWNER", "SETGID", "SETUID"}

// BackendCapsEnv lets an operator widen the set for an image that genuinely
// needs more, node-locally. Comma-separated capability names without the
// CAP_ prefix; the empty string means "keep nothing but the default", and
// the literal "none" means "add nothing at all".
//
// Read from THIS process's environment on purpose: which capabilities a
// node hands a container is a node-local decision, not something a
// controller row may choose. That is the same trust split as the host
// roots and the skill bind roots.
const BackendCapsEnv = "NOO_BACKEND_CAP_ADD"

func backendCaps() []string {
	v := strings.TrimSpace(os.Getenv(BackendCapsEnv))
	if v == "" {
		return backendCapsDefault
	}
	if strings.EqualFold(v, "none") {
		return nil
	}
	out := make([]string, 0, 8)
	for _, c := range strings.Split(v, ",") {
		c = strings.ToUpper(strings.TrimSpace(strings.TrimPrefix(strings.ToUpper(strings.TrimSpace(c)), "CAP_")))
		if c != "" {
			out = append(out, c)
		}
	}
	slog.Info("backend containers: capability set widened by the node's own environment",
		"env", BackendCapsEnv, "cap_add", out)
	return out
}

// envOr returns the value of env var `name`, or `fallback` if unset/empty.
func envOr(name, fallback string) string {
	v := os.Getenv(name)
	if v == "" {
		return fallback
	}
	return v
}

// hasNvidiaGPU reports whether the host has an NVIDIA GPU detectable by
// docker. Cheap heuristics first; cached after first call so we don't
// fork on every backend start.
//
// Detection order (any positive answer wins):
//  1. NODE_TIER >= 4 → edge node, no NVIDIA → false
//  2. ARM arch + no obvious indicator → false (Pi, generic ARM SBCs)
//  3. /dev/nvidia0 exists OR /proc/driver/nvidia exists → true
//  4. Default → false (assume no GPU; user can override with NOO_FORCE_GPU=1
//     if their setup requires it for some reason)
var nvidiaGPUDetected = func() bool {
	// User override
	if os.Getenv("NOO_FORCE_GPU") == "1" {
		return true
	}
	if os.Getenv("NOO_NO_GPU") == "1" {
		return false
	}
	// Edge nodes never have NVIDIA
	if runtime.GOARCH == "arm" || runtime.GOARCH == "arm64" {
		// Jetson exception: NVIDIA Tegra has integrated GPU. Detect by /dev/nvgpu*
		if _, err := os.Stat("/dev/nvgpu"); err == nil {
			return true
		}
		return false
	}
	// x86: probe filesystem for NVIDIA driver
	if _, err := os.Stat("/dev/nvidia0"); err == nil {
		return true
	}
	if _, err := os.Stat("/proc/driver/nvidia"); err == nil {
		return true
	}
	// WSL2 exposes the GPU as a paravirtual /dev/dxg device — /dev/nvidia0
	// never exists there, so without this probe every WSL2 controller node
	// silently creates CPU-only backend containers (vllm then dies with
	// "Failed to infer device type"). The device must be visible in the
	// node-agent's namespace (mount it, or set NOO_FORCE_GPU=1).
	if _, err := os.Stat("/dev/dxg"); err == nil {
		return true
	}
	return false
}()

func hasNvidiaGPU() bool {
	return nvidiaGPUDetected
}

// nvidiaRuntimeRegistered reports whether the daemon lists an "nvidia"
// runtime (what the NVIDIA container toolkit registers). Unknown (the info
// call failed) keeps the previous behaviour and requests the device.
func (c *Client) nvidiaRuntimeRegistered(ctx context.Context) bool {
	res, err := c.docker.Info(ctx, client.InfoOptions{})
	if err != nil {
		return true
	}
	return runtimesIncludeNvidia(res.Info.Runtimes)
}

// runtimesIncludeNvidia is the pure half of the check, for tests.
func runtimesIncludeNvidia[V any](runtimes map[string]V) bool {
	_, ok := runtimes["nvidia"]
	return ok
}

// llamacppDefaultImage picks the right llama.cpp image based on host
// architecture. ARM nodes (Pi/Jetson/RK) use the upstream multi-arch
// ggml-org image since we don't ship our own ARM build. x86 nodes
// default to the locally-built pai-assistant variant (DHI hardened,
// nonroot, TLS-aware) when present.
// ContainerNameFor is the container a managed backend runs as, "" for a
// backend the agent does not know.
func ContainerNameFor(backend string) string {
	return backendSpecs[backend].ContainerName
}

func llamacppDefaultImage() string {
	// runtime.GOARCH is the architecture the binary is built for, which
	// matches the host since node-agent runs natively (not under emulation).
	if runtime.GOARCH == "arm64" || runtime.GOARCH == "arm" {
		return "ghcr.io/ggml-org/llama.cpp:server"
	}
	// x86: the hardened llama-server. `pai-assistant/llamacpp:latest` is a
	// LOCAL build name — it exists only on a machine that ran
	// `scripts/build-hardened-llamacpp.sh`, or `noo stack
	// rebuild` (compose builds the same Dockerfile). On a --dist install nothing builds it and
	// nothing published it, so the pull failed with "pull access denied"
	// and llamacpp could never start on an x86 node.
	// The image is now in the release matrix, so prefer the published one
	// whenever the deployment tells us which release it is running.
	prefix := os.Getenv("NOO_IMAGE_PREFIX")
	tag := os.Getenv("NOO_IMAGE_TAG")
	if prefix != "" && tag != "" {
		return prefix + "/llamacpp:" + tag
	}
	// No release pin and no local hardened build (the hardened build is
	// published in the release, but a box with no release pin has not pulled
	// it — see docker/README-llamacpp.md): a box with neither used to fall back
	// to "pai-assistant/llamacpp:latest", a name that exists only on a
	// machine that built it, and the pull failed with "pull access
	// denied". Upstream is the same CPU/OpenBLAS capability class, so it
	// is the working default here instead.
	return "ghcr.io/ggml-org/llama.cpp:server"
}

// ExpectsGGUFModel reports whether a backend loads a model FILE from the
// node's models dir, as opposed to a HuggingFace repo id it resolves itself.
//
// The distinction matters because the two are not interchangeable and the
// failure is silent-ish: give a gguf-only engine an HF repo id and
// llama-server exits immediately with
//
//	gguf_init_from_file: failed to open GGUF file '/models/BAAI/bge-reranker-base'
//
// on every start, forever. That is exactly how host8's reranker sat in a
// restart loop — the placement carried `BAAI/bge-reranker-base` while the
// llamacpp engine wanted a bare filename like bge-reranker-v2-m3-Q8_0.gguf.
//
// `reranker` is engine-dependent: RERANK_ENGINE=tei restores the TEI
// cross-encoder, which DOES take a repo id.
func ExpectsGGUFModel(backend string) bool {
	switch backend {
	case "llamacpp":
		return true
	case "reranker":
		return !strings.EqualFold(strings.TrimSpace(os.Getenv("RERANK_ENGINE")), "tei")
	default:
		return false
	}
}

// hfBackend: backends that load an HF repo id (vs a flat GGUF / ollama tag).
func hfBackend(backend string) bool {
	switch backend {
	case "vllm", "embedding", "reranker":
		return true
	}
	return false
}

func isGGUFModel(model string) bool { return strings.HasSuffix(strings.ToLower(model), ".gguf") }

func placedNode() bool { return preseed.Placed() }

// hfRepoCachedLocally: the node's HF cache already holds a snapshot of the
// repo (preseeded earlier, the controller briefly unreachable now).
func hfRepoCachedLocally(model string) bool {
	snaps := filepath.Join(resolveEnv(hfCacheSource), "hub", preseed.RepoCacheDir(model), "snapshots")
	entries, err := os.ReadDir(snaps)
	return err == nil && len(entries) > 0
}

// ModelNotStagedError: a placed node could not get the model from the
// controller's store and will not download it from the internet.
type ModelNotStagedError struct{ Backend, Model string }

func (e *ModelNotStagedError) Error() string {
	return fmt.Sprintf("model_cache_miss: %s needs %s, which is not in the controller's model store, and a placed node never downloads weights "+
		"from huggingface.co. Stage it on the controller (run the model once there, or `HF_HOME=$HF_CACHE_DIR huggingface-cli download %s` on the controller), "+
		"then check `noo cluster verify` (model cache row) and that this node's NOO_MODEL_CACHE_URL is https://<controller>:8443",
		e.Backend, e.Model, e.Model)
}
