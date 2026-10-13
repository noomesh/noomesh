// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 PersonifAI LLC

package hardware

import (
	"runtime"

	"github.com/noomesh/noomesh/node-agent-go/internal/config"
	"github.com/noomesh/noomesh/node-agent-go/internal/embedtarget"
	"os"
	"os/exec"
	"strconv"
	"strings"
)

// Capabilities describes what a node can do.
type Capabilities struct {
	CPUCores int      `json:"cpu_cores"`
	RAMGB    float64  `json:"ram_gb"`
	GPUModel string   `json:"gpu_model,omitempty"`
	VRAMGB   float64  `json:"vram_gb"`
	GPUCount int      `json:"gpu_count"`
	IsARM    bool     `json:"is_arm"`
	Backends []string `json:"backends"`
	Tools    []string `json:"tools"`
	Tier     int      `json:"tier"`

	// Capability-placement manifest fields (docs/NODE_CAPABILITY_PLACEMENT.md).
	// The node reports these so the controller uses REPORTED truth instead of
	// inferring the GPU API from the model string — which it can't do for a
	// Mac (Metal isn't visible in a model name).
	OS                string `json:"os"`                  // runtime.GOOS: linux|darwin|windows
	Arch              string `json:"arch"`                // runtime.GOARCH: amd64|arm64|arm
	GPUAPI            string `json:"gpu_api"`             // cuda|metal|rocm|none
	UnifiedMemory     bool   `json:"unified_memory"`      // Apple Silicon shares CPU/GPU RAM
	CanGPUPassthrough bool   `json:"can_gpu_passthrough"` // false for Docker-for-Mac (Metal blocked)

	// Raw /proc/device-tree/model string ("" on non-SBC / non-Linux). The
	// FIRST branch of the tier ladder (device-tree SBC → Tier 4,
	// checked BEFORE the VRAM rules because a Jetson reports VRAM > 0 yet is
	// edge-class) — and until recently the one input the agent didn't report,
	// which is what kept the controller from re-deriving tier from
	// heartbeats. Raw on purpose: the model→family mapping stays in its one
	// canonical home (noo-cli `sbc_family_from_model`), never copied here.
	DeviceTreeModel string `json:"device_tree_model,omitempty"`
}

// detectGPUAPI reports which GPU compute API this node exposes. Today the
// only detectable one is CUDA (a non-empty nvidia-smi GPU model). On macOS an
// Apple GPU is Metal (reported blindly for now — a native Metal probe is a
// hardware-gated follow-up). Everything else is "none" (CPU-only).
func detectGPUAPI(gpuModel string) string {
	if runtime.GOOS == "darwin" {
		return "metal" // Apple Silicon / Intel-Mac AMD both go through Metal
	}
	if gpuModel != "" {
		return "cuda" // gpuModel here comes from nvidia-smi
	}
	return "none"
}

// GPUProbe is the GPU-detection surface Detect depends on.
//
// An interface rather than the concrete *GPUDetector so detection can be
// faked in tests. Without it, Detect's behaviour is a function of the HOST
// running the test: `TestDetect_ClearsStaleGPUEnvWhenNoHardware` asserts a
// stale GPU_MODEL is cleared when no hardware is present, which is only true
// on a GPU-less machine. On any developer box with an NVIDIA card the real
// nvidia-smi answered and the test failed ("expected 0 VRAM, got 16") — a red
// suite that says nothing about the code.
//
// *GPUDetector satisfies this already; no call site changes.
type GPUProbe interface {
	DetectVRAM() float64
	DetectCount() int
	DetectModel() string
}

// Detect gathers hardware capabilities for this node.
func Detect(cfg *config.Config, gpu GPUProbe) Capabilities {
	vram := cfg.VRAMGB
	if vram == 0 {
		vram = gpu.DetectVRAM()
	}
	gpuCount := gpu.DetectCount()

	gpuModel := cfg.GPUModel
	if gpuModel == "" {
		gpuModel = gpu.DetectModel()
	}
	// Don't advertise a GPU the hardware can't back up. A stale GPU_MODEL
	// env (e.g. copied from another host when this node was provisioned)
	// would otherwise make a GPU-less box — a Raspberry Pi — report a
	// discrete GPU. If the env declared a model but neither VRAM nor a GPU
	// count is detectable, treat the env as wrong and clear it.
	if gpuModel != "" && vram <= 0 && gpuCount == 0 {
		gpuModel = ""
	}

	hasGPU := gpuModel != ""

	// Available backends
	backends := []string{"ollama"} // Ollama works everywhere
	if hasGPU {
		backends = append(backends, "vllm", "airllm")
	}
	backends = append(backends, "llamacpp") // works on CPU and GPU

	// Available tools
	tools := []string{"web_search", "python_tool", "local_files"}
	if hasGPU {
		tools = append(tools, "image_generation", "video_processing")
	}
	if TotalMemoryGB() > 16.0 {
		tools = append(tools, "data_analysis")
	}

	gpuAPI := detectGPUAPI(gpuModel)
	isDarwin := runtime.GOOS == "darwin"

	// Unified memory (Apple Silicon, NVIDIA Tegra/Jetson, DGX Spark GB10,
	// AMD/Intel APUs): the GPU draws on system RAM, so "VRAM 0, GPU count
	// 0" is wrong — an 8 GB Mac mini landed in tier 4.
	// Report the GPU as present with the usable share of RAM as its memory.
	unified, usable := detectUnifiedMemory(gpuAPI, vram, TotalMemoryGB())
	if unified {
		if vram <= 0 {
			vram = usable
		}
		if gpuCount == 0 {
			gpuCount = 1
		}
		if gpuModel == "" {
			gpuModel = unifiedGPUModel()
		}
		if gpuAPI == "none" || gpuAPI == "" {
			gpuAPI = unifiedGPUAPI()
		}
		hasGPU = true
		// Backends by API, not by tier: Metal boxes get ollama + llamacpp;
		// vLLM/airllm stay CUDA-only.
		backends = []string{"ollama", "llamacpp"}
		if gpuAPI == "cuda" {
			backends = []string{"ollama", "vllm", "airllm", "llamacpp"}
		}
	}

	// What this node can actually SERVE, which is not the same as what its
	// hardware could in principle run.
	//
	// llama.cpp runs excellently on Apple Silicon — Metal support is
	// first-class, and it is arguably the platform's best runtime. But this
	// agent starts `llamacpp` only as a Docker CONTAINER, and Docker on macOS
	// is a Linux VM that cannot reach Metal. So the capability is real and the
	// delivery is not: host6 has been advertising `ollama,llamacpp` while
	// able to serve neither.
	//
	// Ollama is different only because its server is already running natively
	// and this agent adopts it (internal/backendrt) — and ollama embeds
	// llama.cpp, so nothing is given up by routing through it.
	//
	// Derived from the RUNTIME rather than hardcoded per platform, so
	// `llamacpp` reappears on its own the day a native llama-server lifecycle
	// lands, instead of waiting for someone to remember this slice.
	backends = servableBackends(backends)

	return Capabilities{
		CPUCores: CPUCores(),
		RAMGB:    TotalMemoryGB(),
		GPUModel: gpuModel,
		VRAMGB:   vram,
		GPUCount: gpuCount,
		IsARM:    IsARM(),
		Backends: backends,
		Tools:    tools,
		Tier:     cfg.Tier,

		OS:              runtime.GOOS,
		Arch:            runtime.GOARCH,
		GPUAPI:          gpuAPI,
		DeviceTreeModel: DeviceTreeModel(),
		UnifiedMemory:   unified,
		// Docker-for-Mac can't pass the GPU into a container, so on macOS a
		// GPU is only usable by a native backend. Everywhere else, yes.
		CanGPUPassthrough: !isDarwin,
	}
}

// RuntimeCapabilities returns a list of capability strings based on
// currently running services, used for gossip announcements.
type RuntimeCapabilityDetector struct {
	GetRunningBackends func() map[string]string
	ListContainers     func() []string
}

func (d *RuntimeCapabilityDetector) Detect() []string {
	caps := []string{"inference"}

	backends := d.GetRunningBackends()
	backendStr := ""
	for k, v := range backends {
		backendStr += k + "=" + v + " "
	}

	containerNames := ""
	for _, name := range d.ListContainers() {
		containerNames += name + " "
	}

	lower := func(s string) string {
		return s // already lowercase from Docker
	}

	combined := lower(backendStr) + lower(containerNames)
	if containsAny(combined, "tei", "embed") {
		caps = append(caps, "embedding")
	}
	if containsAny(combined, "whisper", "stt") {
		caps = append(caps, "whisper")
	}
	if containsAny(combined, "faiss") {
		caps = append(caps, "faiss")
	}
	// A reranker container (TEI cross-encoder, e.g. noo-reranker) makes this
	// node a rerank target. The gateway resolves rerank-capable nodes via
	// this capability and proxies /api/external/rerank through the node-agent
	// (it never connects to the reranker container directly). The container
	// name carries "rerank" but not "tei"/"embed", so this stays distinct
	// from the embedding capability above.
	if containsAny(combined, "rerank") {
		caps = append(caps, "rerank")
	}

	// `embed` marks this node as a mesh embedding target: the gateway
	// resolves embed-capable nodes via this capability and proxies
	// OpenAI-shaped embeddings through the node-agent's /embed proxy.
	//
	// This used to key on a container named "tei", because /embed could
	// only reach TEI. It now speaks every engine in the dialect registry,
	// so the honest signal is DESIRED STATE: the reconciler publishes the
	// role=embed placement's target, and a node advertises `embed` exactly
	// when it has one.
	//
	// Keying on container names was actively wrong in both directions. A
	// node serving harrier-on-ollama advertised nothing (the model name
	// matches none of "nomic/embed/bge/minilm" either), so the mesh could
	// not find the only real embedder in the fleet. And a node with a
	// leftover, undeclared noo-tei container advertised `embed` and drew
	// traffic to a backend nobody had placed — which is exactly how a
	// stray TEI kept answering with 768-dim vectors after the fleet had
	// moved to 1024.
	if embedtarget.Get().BaseURL != "" {
		caps = append(caps, "embed")
	}

	// Looser "embedding" capability for ollama serving a recognisable
	// embedding model. Name-matching is a heuristic and misses models whose
	// names say nothing about their purpose (harrier, for one), so it is a
	// supplement to the role-derived `embed` above, never the basis for
	// mesh routing.
	if _, ok := backends["ollama"]; ok {
		if containsAny(backendStr, "nomic", "embed", "bge", "minilm") {
			caps = append(caps, "embedding")
		}
	}
	// A declared embedder is an embedding node regardless of what its model
	// happens to be called.
	if embedtarget.Get().BaseURL != "" {
		caps = append(caps, "embedding")
	}

	return dedupe(caps)
}

func containsAny(haystack string, needles ...string) bool {
	for _, n := range needles {
		if len(n) > 0 && len(haystack) > 0 {
			for i := 0; i <= len(haystack)-len(n); i++ {
				if haystack[i:i+len(n)] == n {
					return true
				}
			}
		}
	}
	return false
}

func dedupe(ss []string) []string {
	seen := make(map[string]struct{}, len(ss))
	out := make([]string, 0, len(ss))
	for _, s := range ss {
		if _, ok := seen[s]; !ok {
			seen[s] = struct{}{}
			out = append(out, s)
		}
	}
	return out
}

// servableBackends filters an advertised list to those this node can actually
// start or reach with the runtimes it has.
//
// Off darwin every backend is container-served and the list is unchanged.
// On darwin only backends with a native runtime survive, because the
// container lane cannot reach the GPU there.
func servableBackends(advertised []string) []string {
	return servableBackendsFor(runtime.GOOS, advertised)
}

// servableBackendsFor is the decision with the platform passed in, so the
// darwin rule is testable on the Linux machine that actually runs CI. A
// darwin-only test that skips everywhere else asserts nothing where it runs.
func servableBackendsFor(goos string, advertised []string) []string {
	if goos != "darwin" {
		return advertised
	}
	out := make([]string, 0, len(advertised))
	for _, b := range advertised {
		if nativeServable[b] {
			out = append(out, b)
		}
	}
	return out
}

// nativeServable lists the backends with a native (non-Docker) runtime in
// this agent. Adding native llama-server means adding "llamacpp" here, and the
// advertisement follows automatically.
var nativeServable = map[string]bool{
	"ollama": true,
}

// detectUnifiedMemory says whether the GPU shares system RAM and how much of
// it is usable for models. Signals, platform-neutral: Apple Silicon (always);
// a Tegra/Jetson/GB10 device tree or nvidia-smi reporting a pool the size of
// RAM (≥ 90%); AMD/Intel APUs (no dedicated pool but a GPU API). Usable is
// three quarters of RAM — Metal's default wired limit (iogpu.wired_limit_mb
// when set) and a safe share elsewhere.
func detectUnifiedMemory(gpuAPI string, vram, ramGB float64) (bool, float64) {
	usable := ramGB * 0.75
	if runtime.GOOS == "darwin" && runtime.GOARCH == "arm64" {
		if out, err := exec.Command("sysctl", "-n", "iogpu.wired_limit_mb").Output(); err == nil {
			if mb, perr := strconv.ParseFloat(strings.TrimSpace(string(out)), 64); perr == nil && mb > 0 {
				usable = mb / 1024.0
			}
		}
		return true, usable
	}
	if runtime.GOOS == "linux" {
		if b, err := os.ReadFile("/proc/device-tree/compatible"); err == nil {
			c := strings.ToLower(string(b))
			if strings.Contains(c, "nvidia,tegra") || strings.Contains(c, "nvidia,p3") || strings.Contains(c, "gb10") {
				return true, usable
			}
		}
		if gpuAPI == "cuda" && vram > 0 && ramGB > 0 && vram >= ramGB*0.9 {
			return true, usable // DGX Spark-class: the CUDA pool IS the RAM
		}
	}
	return false, 0
}

func unifiedGPUModel() string {
	if runtime.GOOS == "darwin" {
		if out, err := exec.Command("sysctl", "-n", "machdep.cpu.brand_string").Output(); err == nil {
			if s := strings.TrimSpace(string(out)); s != "" {
				return s + " (Metal, unified memory)"
			}
		}
		return "Apple Silicon (Metal, unified memory)"
	}
	if m := DeviceTreeModel(); m != "" {
		return m + " (unified memory)"
	}
	return "unified-memory GPU"
}

func unifiedGPUAPI() string {
	if runtime.GOOS == "darwin" {
		return "metal"
	}
	return "cuda"
}
