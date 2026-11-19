// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 PersonifAI LLC

package docker

import (
	"context"
	"log/slog"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
)

// Did a GPU llamacpp start reach the GPU? A CUDA llama.cpp whose CUDA init
// fails (a driver too old for the CUDA 12.9 build, or no device in the
// container) does not stop: it loads the model on the CPU while the
// container keeps the GPU reserved, and nothing says so. After every
// llamacpp start on the GPU (llamacppOnGPU) the agent reads llama-server's
// own startup lines from the container's log and reports what it found as
// the heartbeat's `llamacpp_offload`; a start that offloaded nothing is a
// slog.Warn naming the likely cause, and a WARN row in `noo cluster verify`
// (noo-cli cluster_verify.rs llamacpp_offload_check).
//
// The lines, as llama.cpp prints them at the pinned ref (b9628):
//
//	ggml/src/ggml-cuda/ggml-cuda.cu:209  "%s: failed to initialize CUDA: %s\n"            (ggml_cuda_init)
//	ggml/src/ggml-cuda/ggml-cuda.cu:221  "%s: found %d CUDA devices (Total VRAM: %zu MiB):\n"
//	ggml/src/ggml-cuda/ggml-cuda.cu:292  "  Device %d: %s, compute capability %d.%d, VMM: %s, VRAM: %zu MiB\n"
//	ggml/src/ggml-cuda/ggml-cuda.cu:99   "CUDA error: %s\n"                                (a CUDA call that failed later)
//	src/llama.cpp:269                    "%s: using device %s (%s) (%s) - %zu MiB free\n"  (llama_prepare_model_devices)
//	src/llama-model.cpp:1592             "%s: offloaded %d/%d layers to GPU\n"           (load_tensors)
//	tools/server/server.cpp:317          "model loaded"                                    (SRV_INF, after the warmup)
//
// When CUDA init fails there is no CUDA device, llama_supports_gpu_offload()
// is false and the offload line is NOT printed at all; when the CUDA backend
// module does not load (the image's backends are GGML_BACKEND_DL modules and
// a release build loads them silently) there is not even a ggml_cuda_init
// line. So "model loaded" with no offload line is as much a CPU run as
// "offloaded 0/N".

// The causes a WARN names.
const (
	LlamacppCauseDriver   = "the NVIDIA driver is too old for the CUDA 12.9 build (needs a 12.9-capable driver; a GPU that runs the PTX fallback needs driver 575 or newer)"
	LlamacppCauseNoDevice = "no CUDA device was visible in the container"
	LlamacppCauseNoLayers = "llama.cpp was started with no GPU layers (N_GPU_LAYERS resolved to 0)"
	LlamacppCauseNoLine   = "llama-server printed no offload line before the check gave up (still loading, or it exited)"
)

// Offload states.
const (
	offloadLoading = "loading" // watching; nothing conclusive yet
	offloadGPU     = "gpu"     // layers offloaded
	offloadCPU     = "cpu"     // it runs on the CPU: a failure, or 0 offloaded
	offloadUnknown = "unknown" // the watch timed out without an answer
)

// LlamacppOffload is one backend's report: `llamacpp_offload` in the beat.
type LlamacppOffload struct {
	Backend     string `json:"backend"`
	Model       string `json:"model"`
	Target      string `json:"target"`
	State       string `json:"state"`
	Offloaded   *int   `json:"offloaded,omitempty"`
	Total       *int   `json:"total,omitempty"`
	CUDADevices *int   `json:"cuda_devices,omitempty"`
	Device      string `json:"device,omitempty"`
	ComputeCap  string `json:"compute_cap,omitempty"`
	Failure     string `json:"failure,omitempty"`
	Cause       string `json:"cause,omitempty"`
	CheckedAt   string `json:"checked_at"`
}

// offloadLog is what llama-server's startup lines said.
type offloadLog struct {
	offloadSeen bool
	offloaded   int
	total       int
	initSeen    bool // a ggml_cuda_init line (found N, or failed)
	devices     int
	device      string
	computeCap  string
	failure     string
	modelLoaded bool
}

var (
	reOffloaded   = regexp.MustCompile(`offloaded (\d+)/(\d+) layers to GPU`)
	reCUDAFound   = regexp.MustCompile(`ggml_cuda_init: found (\d+) CUDA devices`)
	reCUDAFailed  = regexp.MustCompile(`ggml_cuda_init: failed to initialize CUDA: (.*)$`)
	reCUDADevice  = regexp.MustCompile(`Device (\d+): (.+), compute capability (\d+\.\d+),`)
	reUsingDevice = regexp.MustCompile(`using device (\S+) \((.+?)\) \(`)
	reCUDAError   = regexp.MustCompile(`\bCUDA error: (.*)$`)
	reModelLoaded = regexp.MustCompile(`: model loaded\s*$`)
)

// parseLlamacppStartLog reads llama-server's startup lines (each may carry
// the docker timestamp prefix ContainerLogs adds).
func parseLlamacppStartLog(lines []string) offloadLog {
	var o offloadLog
	usingDevice := ""
	for _, raw := range lines {
		l := strings.TrimRight(raw, "\r")
		if m := reOffloaded.FindStringSubmatch(l); m != nil {
			o.offloadSeen = true
			o.offloaded, _ = strconv.Atoi(m[1])
			o.total, _ = strconv.Atoi(m[2])
			continue
		}
		if m := reCUDAFailed.FindStringSubmatch(l); m != nil {
			o.initSeen = true
			o.failure = strings.TrimSpace(m[1])
			continue
		}
		if m := reCUDAFound.FindStringSubmatch(l); m != nil {
			o.initSeen = true
			o.devices, _ = strconv.Atoi(m[1])
			continue
		}
		if m := reCUDADevice.FindStringSubmatch(l); m != nil {
			if o.device == "" {
				o.device, o.computeCap = strings.TrimSpace(m[2]), m[3]
			}
			continue
		}
		if m := reUsingDevice.FindStringSubmatch(l); m != nil {
			if usingDevice == "" && strings.HasPrefix(m[1], "CUDA") {
				usingDevice = m[2]
			}
			continue
		}
		if m := reCUDAError.FindStringSubmatch(l); m != nil {
			if o.failure == "" {
				o.failure = strings.TrimSpace(m[1])
			}
			continue
		}
		if reModelLoaded.MatchString(l) {
			o.modelLoaded = true
		}
	}
	if usingDevice != "" {
		o.device = usingDevice
	}
	return o
}

// offloadCause names the likely cause of a start that did not reach the GPU.
func offloadCause(o offloadLog) string {
	switch {
	case strings.Contains(o.failure, "no CUDA-capable device"):
		return LlamacppCauseNoDevice
	case o.failure != "":
		return LlamacppCauseDriver
	case o.devices == 0:
		return LlamacppCauseNoDevice
	default:
		return LlamacppCauseNoLayers
	}
}

// llamacppOffloadVerdict turns what the log said into the report and whether
// the watch is done. timedOut: the bound passed, so whatever is known is the
// answer.
func llamacppOffloadVerdict(backend, model string, o offloadLog, timedOut bool, now time.Time) (LlamacppOffload, bool) {
	r := LlamacppOffload{Backend: backend, Model: model, Target: "gpu", State: offloadLoading,
		Device: o.device, ComputeCap: o.computeCap, Failure: o.failure, CheckedAt: now.UTC().Format(time.RFC3339)}
	if o.initSeen {
		d := o.devices
		r.CUDADevices = &d
	}
	if o.offloadSeen {
		n, m := o.offloaded, o.total
		r.Offloaded, r.Total = &n, &m
	}
	done := o.modelLoaded || o.failure != "" || timedOut
	switch {
	case o.failure != "":
		r.State, r.Cause = offloadCPU, offloadCause(o)
	case o.offloadSeen && o.offloaded > 0:
		// Layers are on the GPU; the watch goes on to "model loaded" so a
		// CUDA error in the warmup (a PTX the driver cannot JIT) is caught.
		r.State = offloadGPU
	case o.offloadSeen || o.modelLoaded:
		r.State, r.Cause = offloadCPU, offloadCause(o)
	case timedOut:
		r.State, r.Cause = offloadUnknown, LlamacppCauseNoLine
	}
	return r, done
}

// LlamacppOffloadWarns: the report is a GPU start that is not on the GPU.
func LlamacppOffloadWarns(r LlamacppOffload) bool {
	return r.Target == "gpu" && (r.State == offloadCPU || r.State == offloadUnknown)
}

// The reports, per backend, and a generation per backend so a newer start
// (or a stop) retires an older watch.
var (
	offloadMu      sync.Mutex
	offloadReports = map[string]LlamacppOffload{}
	offloadGen     = map[string]int{}
)

// beginLlamacppOffload starts a new generation for backend and records the
// loading report (target gpu) or clears it (any other start, or a stop).
func beginLlamacppOffload(backend, model string, gpu bool, now time.Time) int {
	offloadMu.Lock()
	defer offloadMu.Unlock()
	offloadGen[backend]++
	if gpu {
		offloadReports[backend] = LlamacppOffload{Backend: backend, Model: model, Target: "gpu", State: offloadLoading,
			CheckedAt: now.UTC().Format(time.RFC3339)}
	} else {
		delete(offloadReports, backend)
	}
	return offloadGen[backend]
}

// storeLlamacppOffload records r if gen is still the current watch.
func storeLlamacppOffload(gen int, r LlamacppOffload) bool {
	offloadMu.Lock()
	defer offloadMu.Unlock()
	if offloadGen[r.Backend] != gen {
		return false
	}
	offloadReports[r.Backend] = r
	return true
}

// LlamacppOffloadReport is the heartbeat's `llamacpp_offload`: one entry per
// backend started on the GPU, nil (omitted) when there is none.
func LlamacppOffloadReport() any {
	offloadMu.Lock()
	defer offloadMu.Unlock()
	if len(offloadReports) == 0 {
		return nil
	}
	out := make([]LlamacppOffload, 0, len(offloadReports))
	for _, r := range offloadReports {
		out = append(out, r)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Backend < out[j].Backend })
	return out
}

// The watch's bounds: model load can take minutes (a large GGUF, a first
// PTX JIT), and the log is read every interval until it is conclusive.
var (
	offloadWatchTimeout  = 15 * time.Minute
	offloadWatchInterval = 5 * time.Second
)

// watchLlamacppOffload reads the container's log (fetch) every interval until
// it is conclusive or the bound passes, storing each answer, and logs a WARN
// when the GPU start runs on the CPU. Runs on its own goroutine: the reconcile
// loop never waits on a model load.
func watchLlamacppOffload(ctx context.Context, gen int, backend, model string, fetch func(context.Context) ([]string, error)) {
	deadline := time.Now().Add(offloadWatchTimeout)
	t := time.NewTicker(offloadWatchInterval)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
		lines, err := fetch(ctx)
		if err != nil {
			slog.Debug("llamacpp offload: log read failed", "backend", backend, "error", err)
		}
		timedOut := !time.Now().Before(deadline)
		r, done := llamacppOffloadVerdict(backend, model, parseLlamacppStartLog(lines), timedOut, time.Now())
		if !storeLlamacppOffload(gen, r) {
			return // a newer start or a stop owns the report
		}
		if done {
			logLlamacppOffload(r)
			return
		}
	}
}

// logLlamacppOffload is the agent log line for a finished watch.
func logLlamacppOffload(r LlamacppOffload) {
	if LlamacppOffloadWarns(r) {
		slog.Warn("llamacpp placed on the GPU is running on the CPU: no layer was offloaded",
			"backend", r.Backend, "model", r.Model, "failure", r.Failure, "likely_cause", r.Cause,
			"remedy", "update the NVIDIA driver, or place it on cpu (noo cluster place <node> llamacpp <model> --on cpu)")
		return
	}
	if r.Offloaded != nil && r.Total != nil {
		slog.Info("llamacpp offload", "backend", r.Backend, "model", r.Model, "device", r.Device,
			"offloaded", *r.Offloaded, "total", *r.Total)
	}
}

// startLlamacppOffloadWatch is the start's hook: a GPU llamacpp start gets a
// watch over its container's log; any other llamacpp start clears the report.
// The watch outlives the start's ctx (a reconcile tick ends long before a
// model loads) but keeps its values, and is bounded by offloadWatchTimeout.
func (c *Client) startLlamacppOffloadWatch(ctx context.Context, backend, model, containerName string, gpu bool) {
	if backend != "llamacpp" {
		return
	}
	gen := beginLlamacppOffload(backend, model, gpu, time.Now())
	if !gpu || c == nil || c.docker == nil {
		return
	}
	fetch := func(ctx context.Context) ([]string, error) {
		return c.ContainerLogs(ctx, containerName, 2000, "")
	}
	wctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), offloadWatchTimeout+time.Minute)
	go func() {
		defer cancel()
		watchLlamacppOffload(wctx, gen, backend, model, fetch)
	}()
}
