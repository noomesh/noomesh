// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 PersonifAI LLC

package heartbeat

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"sort"
	"strings"
	"testing"

	"github.com/noomesh/noomesh/node-agent-go/internal/config"
	"github.com/noomesh/noomesh/node-agent-go/internal/hardware"
	"github.com/noomesh/noomesh/node-agent-go/internal/imagesource"
	"github.com/noomesh/noomesh/node-agent-go/internal/lanes"
	"github.com/noomesh/noomesh/node-agent-go/internal/modelpresence"
)

// i675 F11: how many bytes one heartbeat puts on the wire, per section, for
// realistic node shapes, and per beat BEFORE (plain JSON) and AFTER gzip
// (beatgzip.go, as sent once the gateway advertises it). A measurement, not
// a contract: it asserts only the encoding of each beat. Run with -v.
//
// The shapes copy live fleet records (2026-11-14, stack-v0.6.23) with the
// names and addresses made generic: a CPU node (ollama + one chat model +
// the harrier embedder) and a GPU node (ollama, vllm, llamacpp, reranker,
// several models and lanes, a long hostd package list).

// sizeShape installs one node shape on a reporter and the process-global
// registries a beat reads. Every global it touches is reset on cleanup.
type sizeShape struct {
	name       string
	caps       hardware.Capabilities
	running    map[string]string
	placed     []lanes.Placed
	presence   map[string]modelpresence.Entry
	stats      []ModelStat
	adopted    []string
	containers map[string]any
	images     [][3]string
	leaves     []string
	gpuJSON    string
	hostdJSON  string
	facts      map[string]any
	modelSets  any
}

func hostdFixture(held []string, extraBoot string) string {
	platform := make([]string, 0, len(held))
	for _, h := range held {
		platform = append(platform, fmt.Sprintf("%q:%q", h, "580.173.02-1pop1~1783343684~24.04~397d671"))
	}
	heldJSON, _ := json.Marshal(held)
	return `{"age_secs":6,"alive":true,"host":{"boot_loader":"grub","boot_partition":{` + extraBoot +
		`"initrd_bytes":{"6.18.7-76061807-generic":139229542,"7.1.5-76070105-generic":143537297}},` +
		`"booted_at":"2026-11-05T01:04:18Z","collected_at":"2026-11-14T13:50:26Z","default_kernel":"7.1.5-76070105-generic",` +
		`"fallback_kernel":"6.18.7-76061807-generic","held":` + string(heldJSON) + `,"ip_nonlocal_bind":false,"os":"linux",` +
		`"platform":{` + strings.Join(platform, ",") + `},"running_kernel":"7.1.5-76070105-generic","tailscale_online":true,` +
		`"tailscale_state":"Running","telemetry":{"os_reporters":[],"tailscale_logs":"off","tailscale_logs_configured":true,` +
		`"tailscale_logs_operator_choice":false}},"ops":["disk-reclaim","fetch-bundle","harness-start","harness-stop",` +
		`"journal-follow","restart-agent","swap-agent","unit-logs"],"pid":2349296,"ts":"2026-11-14T13:54:26Z",` +
		`"version":"noo-cli-v0.6.23+465e066"}`
}

func cpuNodeShape() sizeShape {
	return sizeShape{
		name: "cpu: ollama, 1 chat + harrier",
		caps: hardware.Capabilities{CPUCores: 8, RAMGB: 31.2, Backends: []string{"ollama", "llamacpp"},
			Tools: []string{"web_search", "python_tool", "local_files"}, Tier: 3, OS: "linux", Arch: "amd64",
			GPUAPI: "none", CanGPUPassthrough: true},
		running: map[string]string{"ollama": "gemma4:e2b-it-qat"},
		placed: []lanes.Placed{
			{Backend: "ollama", Model: "gemma4:e2b-it-qat", Role: "chat"},
			{Backend: "ollama", Model: "harrier", Role: "embed"},
		},
		presence: map[string]modelpresence.Entry{
			"ollama":       {Model: "gemma4:e2b-it-qat", Role: "chat", Present: true},
			"ollama#embed": {Model: "harrier", Role: "embed", Present: true},
		},
		stats: []ModelStat{
			{Name: "gemma4:e2b-it-qat", SizeBytes: 4336358185, ResidentBytes: 5100000000, Loaded: true, ContextLength: 131072},
			{Name: "harrier:latest", SizeBytes: 396705831, ResidentBytes: 569659883, Loaded: true, ContextLength: 32768},
		},
		adopted: []string{"gemma4:e2b-it-qat", "harrier:latest"},
		containers: map[string]any{"ollama": map[string]any{"container": "noo-ollama", "image": "ghcr.io/noomesh/ollama:v0.6.23",
			"image_floating": false, "in_flight": 0, "queued": 0, "running": true, "slots": 0, "started_at": 1794368182,
			"telemetry_missing": []string{}}},
		images: [][3]string{
			{"ghcr.io/noomesh/ollama:v0.6.23", "rail", "sha256:499c5e50d2a74bcf3249e94acbb66f29a740f854c1a0178e829b614c50b42cfd"},
			{"ghcr.io/noomesh/stunnel:v0.6.23", "rail", "sha256:b684f375f92ef4a3a34707e55668cf4e5d5a3319b15cd182a39fbb0308443431"},
		},
		leaves:  []string{"vllm", "llamacpp", "ollama", "tei", "reranker"},
		gpuJSON: `{"foreign_mb":0,"free_mb":0,"generation":0,"gpu_backends":[],"method":"not-measured","need_mb":0,"noomesh_mb":0,"paused_backends":[],"policy":"auto","since":"2026-11-11T03:28:29Z","state":"free","total_mb":0,"unknown_mb":0,"unmeasured":"no-nvidia","unmeasured_for_s":296760}`,
		hostdJSON: hostdFixture([]string{"containerd.io", "docker-buildx-plugin", "docker-ce", "docker-ce-cli",
			"docker-compose-plugin", "tailscale"}, ""),
		facts: map[string]any{"nvidia_runtime": false, "addon_workloads_policy": "approve",
			"addon_workloads_approvals": []any{}, "node_workloads": []any{}, "harness_policy": "auto"},
		modelSets: []any{},
	}
}

func gpuNodeShape() sizeShape {
	return sizeShape{
		name: "gpu: ollama+vllm+llamacpp+reranker",
		caps: hardware.Capabilities{CPUCores: 16, RAMGB: 62.6, GPUModel: "NVIDIA GeForce RTX 3080 Laptop GPU", VRAMGB: 16,
			GPUCount: 1, Backends: []string{"ollama", "vllm", "airllm", "llamacpp"},
			Tools: []string{"web_search", "python_tool", "local_files", "image_generation", "video_processing", "data_analysis"},
			Tier:  2, OS: "linux", Arch: "amd64", GPUAPI: "cuda", CanGPUPassthrough: true},
		running: map[string]string{"ollama": "harrier", "vllm": "google/gemma-4-12b-it-qat", "llamacpp": "gemma-4-26B_q4_0-it",
			"reranker": "bge-reranker-v2-m3-Q4_K_M"},
		placed: []lanes.Placed{
			{Backend: "vllm", Model: "google/gemma-4-12b-it-qat", Role: "chat"},
			{Backend: "llamacpp", Model: "gemma-4-26B_q4_0-it", Role: "chat"},
			{Backend: "ollama", Model: "harrier", Role: "embed"},
			{Backend: "ollama", Model: "llama3.2:3b", Role: "chat"},
			{Backend: "reranker", Model: "bge-reranker-v2-m3-Q4_K_M", Role: "rerank"},
		},
		presence: map[string]modelpresence.Entry{
			"vllm":         {Model: "google/gemma-4-12b-it-qat", Role: "chat", Present: true},
			"llamacpp":     {Model: "gemma-4-26B_q4_0-it", Role: "chat", Present: true},
			"ollama#embed": {Model: "harrier", Role: "embed", Present: true},
			"ollama":       {Model: "llama3.2:3b", Role: "chat", Present: true},
			"reranker":     {Model: "bge-reranker-v2-m3-Q4_K_M", Role: "rerank", Present: true},
		},
		stats: []ModelStat{
			{Name: "gemma4:e2b-it-qat", SizeBytes: 4336358185, ContextLength: 131072},
			{Name: "harrier:latest", SizeBytes: 396705831, ResidentBytes: 569659883, Loaded: true, ContextLength: 32768},
			{Name: "llama3.2:3b", SizeBytes: 2019393189, ContextLength: 131072},
			{Name: "google/gemma-4-12b-it-qat", SizeBytes: 8400000000, ResidentBytes: 9100000000, VRAMBytes: 9100000000, Loaded: true, ContextLength: 32768},
		},
		adopted: []string{"gemma4:e2b-it-qat", "llama3.2:3b", "harrier:latest", "Llama-3.2-3B-Instruct-Q4_K_M",
			"gemma-4-26B_q4_0-it", "harrier-Q4_K_M", "bge-reranker-v2-m3-Q4_K_M"},
		containers: map[string]any{
			"ollama": map[string]any{"container": "noo-ollama", "image": "ghcr.io/noomesh/ollama:v0.6.23", "image_floating": false,
				"in_flight": 0, "queued": 0, "running": true, "slots": 0, "started_at": 1794367749, "telemetry_missing": []string{}},
			"vllm": map[string]any{"container": "noo-vllm", "image": "ghcr.io/noomesh/vllm:v0.6.23", "image_floating": false,
				"in_flight": 1, "queued": 0, "running": true, "health": "healthy", "slots": 4, "started_at": 1794367751, "telemetry_missing": []string{}},
			"llamacpp": map[string]any{"container": "noo-llamacpp", "image": "ghcr.io/noomesh/llamacpp:v0.6.23", "image_floating": false,
				"in_flight": 0, "queued": 0, "running": true, "health": "healthy", "slots": 2, "started_at": 1794367760, "telemetry_missing": []string{}},
			"reranker": map[string]any{"container": "noo-reranker", "image": "ghcr.io/noomesh/llamacpp:v0.6.23", "image_floating": false,
				"in_flight": 0, "queued": 0, "running": true, "health": "healthy", "slots": 1, "started_at": 1794367770, "telemetry_missing": []string{}},
		},
		images: [][3]string{
			{"ghcr.io/noomesh/ollama:v0.6.23", "rail", "sha256:499c5e50d2a74bcf3249e94acbb66f29a740f854c1a0178e829b614c50b42cfd"},
			{"ghcr.io/noomesh/vllm:v0.6.23", "rail", "sha256:1f0e3dad99908345f7439f8ffabdffc4dd3c1cfb8d0f8a0b6c1a1d5e7b3e9a10"},
			{"ghcr.io/noomesh/llamacpp:v0.6.23", "rail", "sha256:9e107d9d372bb6826bd81d3542a419d6c8b2e1f5a4d3c2b1a0f9e8d7c6b5a493"},
			{"ghcr.io/noomesh/stunnel:v0.6.23", "rail", "sha256:b684f375f92ef4a3a34707e55668cf4e5d5a3319b15cd182a39fbb0308443431"},
		},
		leaves:  []string{"vllm", "llamacpp", "ollama", "tei", "reranker"},
		gpuJSON: `{"foreign_mb":0,"free_mb":4139,"generation":0,"gpu_backends":["ollama","vllm","llamacpp","reranker"],"method":"nvidia-smi","need_mb":0,"noomesh_mb":12005,"paused_backends":[],"policy":"auto","since":"2026-11-11T03:27:32Z","state":"free","total_mb":16384,"unknown_mb":0}`,
		hostdJSON: hostdFixture([]string{"containerd.io", "docker-buildx-plugin", "docker-ce", "docker-ce-cli",
			"docker-compose-plugin", "libnvidia-container-tools", "libnvidia-container1", "linux-generic",
			"linux-headers-generic", "linux-image-generic", "nvidia-container-toolkit", "nvidia-container-toolkit-base",
			"nvidia-dkms-580", "nvidia-driver-580", "nvidia-kernel-common-580", "nvidia-kernel-source-580",
			"nvidia-utils-580", "tailscale"},
			`"default_entry":"current.conf","default_entry_source":"efi-var","dkms_compressed":{"6.18.7-76061807-generic":true,"7.1.5-76070105-generic":true},`+
				`"entries":[{"esp_initrd_bytes":143537297,"intact":true,"kernel":"7.1.5-76070105-generic","name":"current.conf"},`+
				`{"esp_initrd_bytes":139229542,"intact":true,"kernel":"6.18.7-76061807-generic","name":"oldkern.conf"}],`+
				`"free_bytes":4331028480,"mount":"/boot/efi","total_bytes":4822401024,"used_bytes":491372544,`),
		facts: map[string]any{"nvidia_runtime": true, "gpu_compute_cap": "8.6", "addon_workloads_policy": "approve",
			"addon_workloads_approvals": []any{map[string]any{"addon": "example-addon", "workload": "worker", "approved_at": "2026-11-01T10:00:00Z", "approved_by": "operator"}},
			"node_workloads":            []any{map[string]any{"addon": "example-addon", "workload": "worker", "state": "running", "reason": ""}},
			"harness_policy":            "auto"},
		modelSets: []any{map[string]any{"id": "gemma-4-26b", "revision": "r3", "state": "held"}},
	}
}

// installShape wires one shape onto a fresh reporter pointed at srvURL.
func installShape(t *testing.T, srvURL string, s sizeShape) *Reporter {
	t.Helper()
	pki := t.TempDir()
	t.Setenv("NOO_PKI_DIR", pki)
	t.Setenv("NOO_BIND_ADDR", "")
	t.Setenv("NODE_LOCATION", "")
	t.Setenv("MODELS_DIR", "")
	t.Setenv("NOO_DATA_ROOT", "/data/noo")
	for _, svc := range s.leaves {
		writeTestLeaf(t, pki, svc, []string{svc, "localhost", "noo-" + svc, "stunnel-" + svc, "noo-stunnel-" + svc})
	}
	modelpresence.Reset()
	imagesource.Reset()
	t.Cleanup(func() { modelpresence.Reset(); imagesource.Reset(); lanes.SetPlaced(nil) })
	for k, e := range s.presence {
		modelpresence.Set(k, e)
	}
	for _, im := range s.images {
		imagesource.Record(im[0], im[1], im[2])
	}
	lanes.SetPlaced(s.placed)

	r := newTestReporter(t, srvURL, &config.Config{NodeID: "size-node", Tier: s.caps.Tier, NodeIP: "100.64.0.10"})
	r.getBackends = func() (map[string]string, error) { return s.running, nil }
	r.SetAdoptedModels(func() []string { return s.adopted })
	r.SetModelStats(func() []ModelStat { return s.stats })
	r.SetBackendContainers(func() map[string]any { return s.containers })
	runtimes := map[string]string{}
	mounts := map[string][]string{}
	for b := range s.running {
		runtimes[b] = "docker"
		mounts[b] = []string{"/data/noo/" + b}
	}
	r.SetBackendRuntimes(func() map[string]string { return runtimes })
	r.SetDataMounts(func() (map[string][]string, error) { return mounts, nil })
	r.SetLoadedModels(func() map[string]string { return map[string]string{"ollama": "harrier:latest"} })
	r.SetHostState(func() map[string]any {
		return map[string]any{"harness": map[string]any{"runtime": "systemd", "state": "stopped"}}
	})
	r.SetHostdState(func() map[string]any { return mustObj(t, s.hostdJSON) })
	r.SetLogShipState(func() map[string]any {
		return map[string]any{"dropped_total": 0, "enabled": true, "journal": "running", "last_accepted_unix": 1794664469,
			"last_error": "", "queued": 1, "redacted_total": 18, "route_ready": true, "shipped_total": 1094263, "spill_pending": false}
	})
	r.SetBusStatus(func() any {
		return map[string]any{"connected": true, "connects": 2, "detail": "connected; tasks.dispatch durable is bound",
			"disconnected_for_sec": nil, "job_dispatch_bound": true, "last_connected_at": "2026-11-12T22:13:29Z",
			"last_disconnected_at": "2026-11-12T22:10:36Z", "role": "node", "state": "connected",
			"url": "tls://controller.example.ts.net:4222", "user": "node-size-node"}
	})
	r.SetNatsRPC(func() bool { return true })
	r.SetTunnel(func() bool { return true })
	r.SetGPUContention(func() any { return mustObj(t, s.gpuJSON) })
	r.SetModelSets(func() any { return s.modelSets })
	r.SetModelSetsFreeBytes(func() (int64, bool) { return 391100000000, true })
	r.SetNodeFacts(func() map[string]any { return s.facts })
	r.caps = &s.caps
	return r
}

func mustObj(t *testing.T, s string) map[string]any {
	t.Helper()
	var m map[string]any
	if err := json.Unmarshal([]byte(s), &m); err != nil {
		t.Fatalf("fixture JSON: %v", err)
	}
	return m
}

// sectionOfKey names the section that put each top-level key in a beat, by
// replaying heartbeatSections on an empty map. Keys no section adds come
// from the beat's base (metrics, address, sensors, companion telemetry).
func sectionOfKey(r *Reporter, running map[string]string) map[string]string {
	p := map[string]any{"running_backends": running}
	owner := map[string]string{}
	for _, sec := range heartbeatSections {
		before := map[string]bool{}
		for k := range p {
			before[k] = true
		}
		sec.add(r, p)
		for k := range p {
			if !before[k] {
				owner[k] = sec.name
			}
		}
	}
	return owner
}

func TestHeartbeatPayloadSize(t *testing.T) {
	const beatsPerDay = 24 * 60 * 60 / 30
	for _, shape := range []sizeShape{cpuNodeShape(), gpuNodeShape()} {
		t.Run(strings.SplitN(shape.name, ":", 2)[0], func(t *testing.T) {
			var wire []byte
			var encoding string
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
				wire, _ = io.ReadAll(req.Body)
				encoding = req.Header.Get("Content-Encoding")
				w.WriteHeader(200)
				// A gateway that takes gzip beats (beatgzip.go).
				_, _ = w.Write([]byte(`{"status":"ok","accept_encoding":["gzip"]}`))
			}))
			defer srv.Close()
			r := installShape(t, srv.URL, shape)
			// BEFORE: the first beat is plain, as every gateway gets it today.
			r.SendHeartbeat()
			body := wire
			if len(body) == 0 || encoding != "" {
				t.Fatalf("first beat: %d bytes, Content-Encoding %q; want a plain beat", len(body), encoding)
			}
			// AFTER: the beat once the gateway advertised gzip, as sent.
			r.SendHeartbeat()
			gzWire := wire
			if encoding != "gzip" || len(gzWire) == 0 {
				t.Fatalf("second beat: Content-Encoding %q; want gzip", encoding)
			}

			var keys map[string]json.RawMessage
			if err := json.Unmarshal(body, &keys); err != nil {
				t.Fatalf("beat is not a JSON object: %v", err)
			}
			owner := sectionOfKey(r, shape.running)
			perSection := map[string]int{}
			perKey := map[string][]string{}
			for k, v := range keys {
				sec := owner[k]
				if sec == "" {
					sec = "(base)"
				}
				// "key":value, — the bytes this key costs in the object.
				n := len(k) + 3 + len(v) + 1
				perSection[sec] += n
				perKey[sec] = append(perKey[sec], fmt.Sprintf("%s=%d", k, n))
			}
			names := make([]string, 0, len(perSection))
			for s := range perSection {
				names = append(names, s)
			}
			sort.Slice(names, func(i, j int) bool { return perSection[names[i]] > perSection[names[j]] })

			var out strings.Builder
			fmt.Fprintf(&out, "\n%s\n%-20s %7s %6s  keys\n", shape.name, "section", "bytes", "share")
			for _, s := range names {
				sort.Strings(perKey[s])
				fmt.Fprintf(&out, "%-20s %7d %5.1f%%  %s\n", s, perSection[s],
					100*float64(perSection[s])/float64(len(body)), strings.Join(perKey[s], " "))
			}
			fmt.Fprintf(&out, "per beat: BEFORE %d B plain, AFTER %d B gzip on the wire (%.0f%% of plain)\n",
				len(body), len(gzWire), 100*float64(len(gzWire))/float64(len(body)))
			fmt.Fprintf(&out, "per day @30s (%d beats): BEFORE %.1f MB, AFTER %.1f MB\n", beatsPerDay,
				float64(len(body)*beatsPerDay)/1e6, float64(len(gzWire)*beatsPerDay)/1e6)
			t.Log(out.String())
		})
	}
}
