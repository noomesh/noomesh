// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 PersonifAI LLC

package docker

import (
	"context"
	"strings"
	"testing"
	"time"
)

// The fixtures are llama-server's startup lines as llama.cpp b9628 prints
// them (format strings quoted in llamacpp_offload.go), with the timestamp
// prefix ContainerLogs adds. Values are realistic for an 8B model (32
// repeating layers + output = 33) on a compute 6.1 card.
func logLines(s string) []string {
	var out []string
	for i, l := range strings.Split(strings.Trim(s, "\n"), "\n") {
		out = append(out, "2026-11-18T10:00:"+twoDigits(i)+".000000000Z "+l)
	}
	return out
}

func twoDigits(i int) string { return string(rune('0'+i/10%10)) + string(rune('0'+i%10)) }

const fullOffloadLog = `
ggml_cuda_init: found 1 CUDA devices (Total VRAM: 8192 MiB):
  Device 0: NVIDIA GeForce GTX 1080, compute capability 6.1, VMM: yes, VRAM: 8192 MiB
load_backend: loaded CUDA backend from /app/libggml-cuda.so
load_backend: loaded CPU backend from /app/libggml-cpu-haswell.so
llama_prepare_model_devices: using device CUDA0 (NVIDIA GeForce GTX 1080) (0000:01:00.0) - 7944 MiB free
load_tensors: loading model tensors, this can take a while... (mmap = true, direct_io = false)
load_tensors: offloading output layer to GPU
load_tensors: offloading 31 repeating layers to GPU
load_tensors: offloaded 33/33 layers to GPU
load_tensors:        CUDA0 model buffer size =  4403.49 MiB
load_tensors:   CPU_Mapped model buffer size =   281.81 MiB
srv          main: model loaded
`

const partialOffloadLog = `
ggml_cuda_init: found 1 CUDA devices (Total VRAM: 6144 MiB):
  Device 0: NVIDIA GeForce GTX 1060 6GB, compute capability 6.1, VMM: yes, VRAM: 6144 MiB
load_backend: loaded CUDA backend from /app/libggml-cuda.so
llama_prepare_model_devices: using device CUDA0 (NVIDIA GeForce GTX 1060 6GB) (0000:01:00.0) - 5980 MiB free
load_tensors: offloading output layer to GPU
load_tensors: offloading 19 repeating layers to GPU
load_tensors: offloaded 20/63 layers to GPU
srv          main: model loaded
`

const zeroOffloadLog = `
ggml_cuda_init: found 1 CUDA devices (Total VRAM: 8192 MiB):
  Device 0: NVIDIA GeForce GTX 1080, compute capability 6.1, VMM: yes, VRAM: 8192 MiB
load_backend: loaded CUDA backend from /app/libggml-cuda.so
load_tensors: offloading 0 repeating layers to GPU
load_tensors: offloaded 0/33 layers to GPU
srv          main: model loaded
`

// A driver older than the CUDA 12.9 runtime: cudaGetDeviceCount fails, no
// CUDA device registers, and so no offload line is printed at all.
const driverTooOldLog = `
ggml_cuda_init: failed to initialize CUDA: CUDA driver version is insufficient for CUDA runtime version
load_backend: loaded CUDA backend from /app/libggml-cuda.so
load_backend: loaded CPU backend from /app/libggml-cpu-haswell.so
load_tensors: loading model tensors, this can take a while... (mmap = true, direct_io = false)
load_tensors:   CPU_Mapped model buffer size =  4685.30 MiB
srv          main: model loaded
`

const noDeviceLog = `
ggml_cuda_init: failed to initialize CUDA: no CUDA-capable device is detected
load_backend: loaded CUDA backend from /app/libggml-cuda.so
load_backend: loaded CPU backend from /app/libggml-cpu-haswell.so
srv          main: model loaded
`

// The CUDA backend module did not load (a release build loads it silently):
// not even a ggml_cuda_init line.
const noCUDABackendLog = `
load_backend: loaded CPU backend from /app/libggml-cpu-haswell.so
load_tensors:   CPU_Mapped model buffer size =  4685.30 MiB
srv          main: model loaded
`

// A GPU without a cubin runs the PTX fallback; a driver that cannot JIT it
// fails at the warmup, after the offload line.
const ptxFailLog = `
ggml_cuda_init: found 1 CUDA devices (Total VRAM: 16384 MiB):
  Device 0: Tesla V100-PCIE-16GB, compute capability 7.0, VMM: yes, VRAM: 16384 MiB
load_tensors: offloaded 33/33 layers to GPU
CUDA error: the provided PTX was compiled with an unsupported toolchain.
`

var t0 = time.Date(2026, 11, 18, 10, 5, 0, 0, time.UTC)

func verdict(t *testing.T, log string, timedOut bool) (LlamacppOffload, bool) {
	t.Helper()
	return llamacppOffloadVerdict("llamacpp", "llama-3.1-8b-Q4_K_M.gguf", parseLlamacppStartLog(logLines(log)), timedOut, t0)
}

func TestLlamacppOffloadParsesFullOffload(t *testing.T) {
	r, done := verdict(t, fullOffloadLog, false)
	if !done || r.State != "gpu" || r.Offloaded == nil || *r.Offloaded != 33 || *r.Total != 33 {
		t.Fatalf("full offload: done=%v %+v", done, r)
	}
	if r.CUDADevices == nil || *r.CUDADevices != 1 || r.Device != "NVIDIA GeForce GTX 1080" || r.ComputeCap != "6.1" {
		t.Fatalf("device: %+v", r)
	}
	if LlamacppOffloadWarns(r) || r.Cause != "" {
		t.Fatalf("a full offload warned: %+v", r)
	}
}

func TestLlamacppOffloadParsesPartialOffload(t *testing.T) {
	r, _ := verdict(t, partialOffloadLog, false)
	if r.State != "gpu" || *r.Offloaded != 20 || *r.Total != 63 || r.Device != "NVIDIA GeForce GTX 1060 6GB" {
		t.Fatalf("partial offload: %+v", r)
	}
	if LlamacppOffloadWarns(r) {
		t.Fatalf("a partial offload is on the GPU, not a WARN: %+v", r)
	}
}

func TestLlamacppOffloadZeroOffloadedWarns(t *testing.T) {
	r, done := verdict(t, zeroOffloadLog, false)
	if !done || r.State != "cpu" || *r.Offloaded != 0 || !LlamacppOffloadWarns(r) {
		t.Fatalf("0 offloaded on a GPU start: done=%v %+v", done, r)
	}
	if r.Cause != LlamacppCauseNoLayers {
		t.Fatalf("a device was found, so the cause is the layer count: %q", r.Cause)
	}
}

func TestLlamacppOffloadCUDAInitFailureNamesTheDriver(t *testing.T) {
	r, done := verdict(t, driverTooOldLog, false)
	if !done || r.State != "cpu" || !LlamacppOffloadWarns(r) {
		t.Fatalf("CUDA init failure: done=%v %+v", done, r)
	}
	if r.Failure != "CUDA driver version is insufficient for CUDA runtime version" || r.Offloaded != nil {
		t.Fatalf("failure text: %+v", r)
	}
	if r.Cause != LlamacppCauseDriver || !strings.Contains(r.Cause, "575") {
		t.Fatalf("cause: %q", r.Cause)
	}
}

func TestLlamacppOffloadNoCUDADeviceNamesNoDevice(t *testing.T) {
	for name, log := range map[string]string{"init failed": noDeviceLog, "no cuda backend": noCUDABackendLog} {
		r, done := verdict(t, log, false)
		if !done || r.State != "cpu" || !LlamacppOffloadWarns(r) || r.Cause != LlamacppCauseNoDevice {
			t.Fatalf("%s: done=%v %+v", name, done, r)
		}
	}
}

func TestLlamacppOffloadCUDAErrorAfterOffloadWarns(t *testing.T) {
	r, done := verdict(t, ptxFailLog, false)
	if !done || r.State != "cpu" || !LlamacppOffloadWarns(r) || !strings.Contains(r.Failure, "PTX") {
		t.Fatalf("PTX failure: done=%v %+v", done, r)
	}
}

func TestLlamacppOffloadNoLineByTheBoundWarns(t *testing.T) {
	loading := `
ggml_cuda_init: found 1 CUDA devices (Total VRAM: 8192 MiB):
load_tensors: loading model tensors, this can take a while... (mmap = true, direct_io = false)
`
	r, done := verdict(t, loading, false)
	if done || r.State != "loading" || LlamacppOffloadWarns(r) {
		t.Fatalf("still loading is not an answer: done=%v %+v", done, r)
	}
	r, done = verdict(t, loading, true)
	if !done || r.State != "unknown" || !LlamacppOffloadWarns(r) || r.Cause != LlamacppCauseNoLine {
		t.Fatalf("timed out: done=%v %+v", done, r)
	}
}

// The WARN decision: only a GPU start reports; a cpu start (or a stop)
// clears the report, and a newer start retires an older watch.
func TestLlamacppOffloadReportsOnlyGPUStarts(t *testing.T) {
	t.Cleanup(func() { beginLlamacppOffload("llamacpp", "", false, t0) })
	gen := beginLlamacppOffload("llamacpp", "m.gguf", true, t0)
	rep, _ := LlamacppOffloadReport().([]LlamacppOffload)
	if len(rep) != 1 || rep[0].State != "loading" || rep[0].Target != "gpu" {
		t.Fatalf("a GPU start reports loading: %v", LlamacppOffloadReport())
	}
	r, _ := verdict(t, driverTooOldLog, false)
	if !storeLlamacppOffload(gen, r) {
		t.Fatal("the current watch could not store")
	}
	beginLlamacppOffload("llamacpp", "m.gguf", false, t0)
	if got := LlamacppOffloadReport(); got != nil {
		t.Fatalf("a cpu start reports nothing: %v", got)
	}
	if storeLlamacppOffload(gen, r) {
		t.Fatal("a retired watch stored over a newer start")
	}
}

func TestLlamacppOffloadWatchStopsWhenConclusive(t *testing.T) {
	t.Cleanup(func() {
		beginLlamacppOffload("llamacpp", "", false, t0)
		offloadWatchInterval, offloadWatchTimeout = 5*time.Second, 15*time.Minute
	})
	offloadWatchInterval = time.Millisecond
	gen := beginLlamacppOffload("llamacpp", "m.gguf", true, t0)
	calls := 0
	fetch := func(context.Context) ([]string, error) {
		calls++
		if calls < 3 {
			return logLines("ggml_cuda_init: found 1 CUDA devices (Total VRAM: 8192 MiB):"), nil
		}
		return logLines(fullOffloadLog), nil
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	watchLlamacppOffload(ctx, gen, "llamacpp", "m.gguf", fetch)
	rep, _ := LlamacppOffloadReport().([]LlamacppOffload)
	if calls != 3 || len(rep) != 1 || rep[0].State != "gpu" || *rep[0].Offloaded != 33 {
		t.Fatalf("calls=%d report=%+v", calls, rep)
	}
}
