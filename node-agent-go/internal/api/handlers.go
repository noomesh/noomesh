// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 PersonifAI LLC

package api

import (
	"encoding/json"
	"errors"
	"fmt"
	"github.com/noomesh/noomesh/node-agent-go/internal/logring"
	"io"
	"log/slog"
	"net/http"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/noomesh/noomesh/node-agent-go/internal/auth"
	"github.com/noomesh/noomesh/node-agent-go/internal/ctrlrpc"
	dockerpkg "github.com/noomesh/noomesh/node-agent-go/internal/docker"
	"github.com/noomesh/noomesh/node-agent-go/internal/gpuyield"
	"github.com/noomesh/noomesh/node-agent-go/internal/hardware"
	"github.com/noomesh/noomesh/node-agent-go/internal/version"
)

// --- Request / Response types ---

// backendStartReq carries the controller's start request for a backend.
//
// Backend + Model + GPUCount are the original minimal fields; the rest
// are the design additions that let the controller act as the
// canonical source of truth for backend image + parser config.
// Workers' local .env values are used only when the request omits the
// field (backwards compat for hand-started backends).
type backendStartReq struct {
	Backend         string `json:"backend"`
	Model           string `json:"model"`
	GPUCount        *int   `json:"gpu_count,omitempty"`
	Image           string `json:"image,omitempty"`            // overrides spec/env image
	ToolParser      string `json:"tool_parser,omitempty"`      // vLLM only
	ReasoningParser string `json:"reasoning_parser,omitempty"` // vLLM only
	MaxModelLen     int    `json:"max_model_len,omitempty"`    // vLLM only
	Quantization    string `json:"quantization,omitempty"`     // vLLM only
	GpuMemUtil      string `json:"gpu_mem_util,omitempty"`     // string so "" means "fall back to env"
}

type backendStopReq struct {
	Backend string `json:"backend"`
}

type cleanReq struct {
	RemoveFolder bool `json:"remove_folder"`
	// Deep also removes this deployment's IMAGES. Off by default because
	// images are the expensive half to get back — a multi-GB pull or a
	// rebuild — while containers are recreated by the next backend start.
	//
	// An agent that predates this field removed images unconditionally, so
	// the response echoes `deep` and the caller can say what actually
	// happened rather than what it asked for.
	Deep bool `json:"deep"`
}

// --- Handlers ---

// handleHealth reports the control API's health and, separately, the NATS
// bus state.
//
// `status` deliberately still describes the HTTP control API only: the
// Docker healthcheck and the gateway's reachability probes hang off it, and
// flapping it during a bus outage would restart a container that is
// otherwise working (killing its running jobs). The bus is reported
// alongside as its own fact — a node can be HTTP-healthy and bus-deaf, and
// a reader must be able to see both.
//
// TWO SHAPES, by whether the caller authenticated.
//
// This route is the one unauthenticated endpoint on :8081, and it used to
// answer every caller with the node id, the NATS URL and the username the
// node authenticates to the bus as, and the host's disk layout and free
// space. That is a free inventory of the mesh to anything that can open a
// socket to the port — and on a node where NOO_BIND_ADDR is unset the port
// is on 0.0.0.0.
//
// Liveness genuinely must stay open: the Docker healthcheck, a load
// balancer, and the gateway's own reachability probe all need to know the
// listener is up without being anybody. So the anonymous answer is exactly
// that — is it up, and which build — and every FACT about the node moves
// behind the bearer — or the controller's leaf alone. The
// gateway's readers (node_reachability.rs and the disk-watermark evaluator
// in autonomy_evaluators.rs) attach node_agent_auth::header_for(), which
// sends the bearer to an agent that has not reported controller_leaf_only
// and nothing to one that has, so nothing in the fleet loses a field.
func (s *Server) handleHealth(w http.ResponseWriter, r *http.Request) {
	body := map[string]any{
		"status":        "healthy",
		"status_detail": "control API is serving",
		"version":       version.String(),
	}
	// The controller's leaf alone earns the detail too: the
	// gateway stops sending the bearer to an agent that reports
	// controller_leaf_only, and its readers still need the facts.
	// This node's own harness (its leaf, over loopback, no bearer) learns
	// here that the chat route admits it without the token.
	// Only that caller is told: it is the only one the answer is about.
	if auth.IsOwnHarnessLeafWithoutBearer(s.cfg, r) {
		body[auth.OwnHarnessLeafOnlyField] = true
	}
	if !auth.IsBusController(r) && !auth.IsTunnelController(r) && !auth.HasValidToken(s.cfg, r) && !auth.IsControllerLeafWithoutBearer(s.cfg, r) {
		writeJSON(w, http.StatusOK, body)
		return
	}
	body["status_detail"] = "control API is serving; see `nats` for bus state"
	body["node_id"] = s.cfg.NodeID
	body["nats"] = s.BusStatusOrUnavailable()
	// Per-node disk visibility for the controller's disk_watermark
	// evaluator: as a host process these are the REAL host filesystems.
	// The list covers the two disks the docker split can put layers on;
	// DiskUsages dedups by fsid so single-disk hosts report one entry.
	body["disk"] = hardware.DiskUsages([]string{"/", "/var/lib/containerd", "/var/lib/docker"})
	// What this node's own reclaim ladder last decided and did — the
	// controller's node disk alert reports it instead of guessing.
	if s.diskReclaim != nil {
		body["disk_reclaim"] = s.diskReclaim()
	}
	writeJSON(w, http.StatusOK, body)
}

func (s *Server) handleStartBackend(w http.ResponseWriter, r *http.Request) {
	var req backendStartReq
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"detail": "invalid request body"})
		return
	}

	// The native check comes BEFORE any Docker check, deliberately. On a Mac
	// there may be no Docker client at all, and answering "Docker not
	// available" about a backend that is running natively and serving
	// requests would be a false statement about the node — the true answer is
	// that this backend exists and is not managed here.
	//
	// A backend served NATIVELY here is not ours to start. Reporting it and
	// managing it are different claims, and this agent only makes the first.
	if model, isNative := s.nativeBackends()[req.Backend]; isNative {
		writeJSON(w, http.StatusNotImplemented, map[string]string{
			"error":   "backend_runtime_unmanaged",
			"backend": req.Backend,
			"runtime": s.native.Runtime(),
			"detail": fmt.Sprintf(
				"%s is served by the %s runtime on this host (currently: %s) and this agent does not manage "+
					"its lifecycle — start, stop and model changes are the operator's, not the "+
					"controller's. The backend IS reported and routable.",
				req.Backend, s.native.Runtime(), nativeModelLabel(model)),
		})
		return
	}

	// Paused for other work on the GPU (internal/gpuyield): an imperative
	// start (`noo cluster up`, the autonomy engine) must not take the GPU
	// back from it. 409 names why; `noo cluster gpu release` or the GPU
	// freeing ends it.
	if gpuyield.HoldsStart(req.Backend) {
		writeJSON(w, http.StatusConflict, map[string]string{
			"error":   "gpu_in_use_by_other",
			"backend": req.Backend,
			"detail":  req.Backend + " is paused: this node's GPU is in use by other work (gpu_contention); it resumes when the GPU frees or the hold is released",
		})
		return
	}

	if s.docker == nil {
		writeJSON(w, http.StatusServiceUnavailable, map[string]string{"detail": "Docker not available"})
		return
	}

	// The daemon must actually answer. `s.docker != nil` never meant "Docker
	// works" on a HOST: NewClient only warns there, deliberately, because the
	// agent runs on macOS with no Docker at all and on Linux may start before
	// dockerd. So the nil check above could not catch an absent daemon, and
	// every start returned 200 "starting" and then failed in a goroutine
	// nobody reads — on host6, for every start ever attempted.
	if !s.docker.Reachable() {
		writeJSON(w, http.StatusServiceUnavailable, map[string]string{
			"error":   "docker_unreachable",
			"backend": req.Backend,
			"detail": "the Docker daemon is not answering on this node, so no container-backed " +
				"backend can start. This is a report of the node's state, not a queued action: " +
				"nothing has been scheduled and retrying will not help until Docker is up.",
		})
		return
	}

	gpuCount := 0
	if req.GPUCount != nil {
		gpuCount = *req.GPUCount
	}

	// Build the override config from the request. Empty string fields
	// signal "use env / spec default" — node-agent doesn't second-guess
	// what the controller sent, just substitutes provided values.
	overrides := dockerpkg.StartOverrides{
		Image:           req.Image,
		ToolParser:      req.ToolParser,
		ReasoningParser: req.ReasoningParser,
		MaxModelLen:     req.MaxModelLen,
		Quantization:    req.Quantization,
		GpuMemUtil:      req.GpuMemUtil,
	}

	// Return immediately — pull + start runs in background.
	// The BackendManager polls the health endpoint to know when it's ready.
	// Over the control bus the outcome is also published on the op's event
	// stream (node.<id>.evt.<op_id>); over HTTPS the reporter is a no-op and
	// the outcome is only logged, as before.
	rep := ctrlrpc.ReporterFrom(r.Context())
	go func() {
		if err := s.docker.StartBackend(req.Backend, req.Model, gpuCount, overrides); err != nil {
			slog.Error("backend start failed", "backend", req.Backend, "error", err)
			rep.Done(http.StatusInternalServerError, map[string]string{"status": "failed", "backend": req.Backend, "detail": err.Error()})
		} else {
			slog.Info("backend started", "backend", req.Backend, "model", req.Model, "image_override", overrides.Image)
			rep.Done(http.StatusOK, map[string]string{"status": "started", "backend": req.Backend, "model": req.Model})
		}
	}()

	writeJSON(w, http.StatusOK, map[string]string{
		"status":  "starting",
		"backend": req.Backend,
		"model":   req.Model,
	})
}

// nativeModelLabel renders the loaded model for an operator-facing message.
// A native backend that is up with nothing loaded is a real and common state
// (a fresh ollama), and "no model loaded" says so rather than printing an
// empty string that reads like a bug.
func nativeModelLabel(model string) string {
	if strings.TrimSpace(model) == "" {
		return "no model loaded"
	}
	return model
}

func (s *Server) handleStopBackend(w http.ResponseWriter, r *http.Request) {
	var req backendStopReq
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"detail": "invalid request body"})
		return
	}

	// Refuse to stop a process this agent did not start. Without this the
	// call reaches Docker, fails to find a container, and answers 500 with a
	// daemon error — which reads as a broken node rather than the true
	// answer, which is that the backend is not this agent's to stop.
	if _, isNative := s.nativeBackends()[req.Backend]; isNative {
		writeJSON(w, http.StatusNotImplemented, map[string]string{
			"error":   "backend_runtime_unmanaged",
			"backend": req.Backend,
			"runtime": s.native.Runtime(),
			"detail": fmt.Sprintf(
				"%s is served by the %s runtime on this host and was not started by this agent, so it "+
					"will not be stopped by it either.", req.Backend, s.native.Runtime()),
		})
		return
	}

	if s.docker == nil {
		writeJSON(w, http.StatusServiceUnavailable, map[string]string{"detail": "Docker not available"})
		return
	}

	if err := s.docker.StopBackend(req.Backend); err != nil {
		slog.Error("failed to stop backend", "backend", req.Backend, "error", err)
		writeJSON(w, http.StatusInternalServerError, map[string]string{"detail": err.Error()})
		return
	}

	slog.Info("backend stopped", "backend", req.Backend)
	writeJSON(w, http.StatusOK, map[string]string{
		"status":  "stopped",
		"backend": req.Backend,
	})
}

func (s *Server) handleRestart(w http.ResponseWriter, r *http.Request) {
	slog.Info("restart requested")
	writeJSON(w, http.StatusOK, map[string]string{"status": "restarting"})

	// Exit after response flushes — Docker restart policy brings us back
	go func() {
		<-r.Context().Done()
		os.Exit(0)
	}()
}

func (s *Server) handleClean(w http.ResponseWriter, r *http.Request) {
	if s.docker == nil {
		writeJSON(w, http.StatusServiceUnavailable, map[string]string{"detail": "Docker not available"})
		return
	}

	var req cleanReq
	json.NewDecoder(r.Body).Decode(&req) // ignore errors, defaults are fine

	slog.Info("clean requested", "remove_folder", req.RemoveFolder, "deep", req.Deep)

	containersStopped, err := s.docker.StopAllPAIContainers()
	if err != nil {
		slog.Error("clean: stop containers failed", "error", err)
	}

	imagesRemoved := 0
	if req.Deep {
		imagesRemoved, err = s.docker.RemoveStackImages()
		if err != nil {
			slog.Error("clean: remove images failed", "error", err)
		}
	}

	folderRemoved := false
	if req.RemoveFolder {
		slog.Warn("folder removal skipped", "reason", "agent running from folder")
	}

	writeJSON(w, http.StatusOK, map[string]any{
		"containers_stopped": containersStopped,
		"images_removed":     imagesRemoved,
		"folder_removed":     folderRemoved,
		// Echoed so the caller reports what this agent DID, not what it was
		// asked for: an agent older than the field removes images either way,
		// and its response has no `deep` key at all.
		"deep": req.Deep,
	})
}

func (s *Server) handleGPUMetrics(w http.ResponseWriter, r *http.Request) {
	metrics := s.gpu.Metrics()
	if metrics == nil {
		resp := map[string]any{
			"available": false,
			"message":   "GPU metrics not available",
		}
		// A probe deadline miss is busyness, not absence: nvidia-smi can
		// blow the 5s window while the GPU is saturated (the 2026-08-28
		// HOST3 false wedge — 84% util, vLLM mid-research-run). Report
		// non-boolean so the controller's gpu_health evaluator, which
		// alerts only on an explicit `available: false`, reads it as
		// unknown and stays quiet.
		if s.gpu.ProbeTimedOut() {
			resp["available"] = "unknown"
			resp["message"] = "gpu probe timed out — GPU busy or driver slow; not evidence of a wedge"
		}
		if s.gpuWatch != nil {
			resp["watchdog"] = s.gpuWatch()
		}
		writeJSON(w, http.StatusOK, resp)
		return
	}

	resp := map[string]any{
		"available":                  true,
		"node_id":                    s.cfg.NodeID,
		"gpu_model":                  s.gpu.DetectModel(),
		"gpu_utilization_percent":    metrics.GPUUtilizationPct,
		"memory_utilization_percent": metrics.MemoryUtilizationPct,
		"memory_used_mb":             metrics.MemoryUsedMB,
		"memory_total_mb":            metrics.MemoryTotalMB,
		"temperature_c":              metrics.TemperatureC,
	}
	if metrics.PowerDrawW != nil {
		resp["power_draw_w"] = *metrics.PowerDrawW
	}
	// Telemetry only: empty is normal (on-demand backends unload when
	// idle), so nothing may alert on its absence.
	resp["compute_apps"] = s.gpu.ComputeApps()
	if s.gpuWatch != nil {
		resp["watchdog"] = s.gpuWatch()
	}
	writeJSON(w, http.StatusOK, resp)
}

func (s *Server) handleListLogContainers(w http.ResponseWriter, r *http.Request) {
	if s.docker == nil {
		writeJSON(w, http.StatusOK, []any{})
		return
	}
	containers, err := s.docker.ListContainers()
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"detail": err.Error()})
		return
	}
	writeJSON(w, http.StatusOK, containers)
}

// OwnLog holds the agent's own recent log lines (filled by main's slog
// tee). Served under the agent's unit name, so `noo cluster logs <node>`
// — which asks for "noo-node-agent" — reads the process's log whether the
// agent is a container (never, since the fleet hardening), a systemd unit
// or a launchd job (2026-09-11: it was a 500 "No such container" on every
// node, and a placement that did not converge left nothing to read).
var OwnLog = logring.New(2000)

// OwnLogName is the container name the CLI uses for the agent itself.
const OwnLogName = "noo-node-agent"

func (s *Server) handleContainerLogs(w http.ResponseWriter, r *http.Request) {
	containerName := r.PathValue("container")
	if containerName == "" {
		writeJSON(w, http.StatusBadRequest, map[string]string{"detail": "container name required"})
		return
	}

	tail := 200
	if t := r.URL.Query().Get("tail"); t != "" {
		if v, err := strconv.Atoi(t); err == nil {
			tail = v
		}
	}
	if containerName == OwnLogName {
		lines := OwnLog.Tail(tail)
		// The ring lives in THIS process, so a crash-looping agent presents
		// an empty one every time — the case you most want the log for is
		// the case that erases it. Fall through to the platform's own
		// capture, which outlived the crash.
		if len(lines) > 0 {
			writeJSON(w, http.StatusOK, map[string]any{
				"container": containerName,
				"source":    "agent process (in-memory ring, same lines as the host journal)",
				"logs":      lines,
			})
			return
		}
	}
	// Host services are not containers. Asking
	// Docker for them returns "No such container", which reads as "nothing
	// to see" rather than "wrong question" — the 2026-09-11 failure, one
	// service later.
	if _, ok := HostServiceUnits[containerName]; ok {
		lines, source, err := HostServiceLogs(r.Context(), containerName, tail)
		if err != nil {
			// A helper that is down or too old is a NAMED failure, not an
			// empty list: "no logs" and "could not read logs" are
			// different facts and only one means the service was quiet.
			writeJSON(w, http.StatusServiceUnavailable, map[string]string{"detail": err.Error()})
			return
		}
		writeJSON(w, http.StatusOK, map[string]any{
			"container": containerName,
			"source":    source,
			"logs":      lines,
		})
		return
	}
	if s.docker == nil {
		writeJSON(w, http.StatusServiceUnavailable, map[string]string{"detail": "Docker not available"})
		return
	}
	since := r.URL.Query().Get("since")

	lines, err := s.docker.ContainerLogs(containerName, tail, since)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"detail": err.Error()})
		return
	}

	writeJSON(w, http.StatusOK, map[string]any{
		"container": containerName,
		"logs":      lines,
	})
}

func (s *Server) handleContainerStats(w http.ResponseWriter, r *http.Request) {
	if s.docker == nil {
		writeJSON(w, http.StatusOK, []any{})
		return
	}
	stats := s.docker.AllContainerStats()
	writeJSON(w, http.StatusOK, stats)
}

// --- Skill execution ---

func (s *Server) handleSkillRun(w http.ResponseWriter, r *http.Request) {
	if s.docker == nil {
		writeJSON(w, http.StatusServiceUnavailable, map[string]string{"detail": "Docker not available"})
		return
	}

	var req dockerpkg.SkillRunRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"detail": "invalid request body"})
		return
	}

	// Admission for the WHOLE spec, not just the image. This endpoint is
	// reachable by any peer holding the fleet cluster secret and it returns
	// the container's stdout, so an unvalidated spec was a one-request read
	// of this node's secrets at rest:
	//   {"image":"busybox","command":["sh","-c","cat /h/etc/noo-node-agent.env"],
	//    "volumes":{"/":"/h"}}
	// ValidateSkillRunRequest bounds bind sources to the configured skill
	// roots, refuses network_mode "host", and keeps the inline-files checks.
	// Everything fails here, as a 400, before any container work happens.
	if err := dockerpkg.ValidateSkillRunRequest(&req); err != nil {
		slog.Warn("skill run refused", "image", req.Image, "container", req.ContainerName, "error", err)
		writeJSON(w, http.StatusBadRequest, map[string]string{"detail": err.Error()})
		return
	}

	slog.Info("skill run requested",
		"image", req.Image,
		"container", req.ContainerName,
		"timeout", req.Timeout,
		"files", len(req.Files),
	)

	result, err := s.docker.RunSkillContainer(req)
	if err != nil {
		slog.Error("skill run failed", "container", req.ContainerName, "error", err)
		writeJSON(w, http.StatusInternalServerError, map[string]string{
			"detail": err.Error(),
		})
		return
	}

	writeJSON(w, http.StatusOK, result)
}

// --- Helpers ---

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(v)
}

// handleGPUHold pauses the node's GPU backends for the caller's operation
// and keeps them paused until a release (operator hold, internal/gpuyield;
// an owned lease that drains first, lease.go). Body:
// {reason, owner, operation_id, mode: drain|immediate, timeout_secs, force}.
// A body with no operation_id is a legacy hold: immediate and a force.
// 409 held_by_other names the current lease; 409 transition_in_progress
// while another hold/release runs; 409 drain_timeout (status
// needs_attention) when the backends did not go idle: nothing was stopped.
func (s *Server) handleGPUHold(w http.ResponseWriter, r *http.Request) {
	if s.gpuHold == nil {
		writeJSON(w, http.StatusServiceUnavailable, map[string]any{"error": "gpu yield not running on this agent"})
		return
	}
	var body struct {
		Reason      string `json:"reason"`
		Owner       string `json:"owner"`
		OperationID string `json:"operation_id"`
		Workload    string `json:"workload"`
		Mode        string `json:"mode"`
		TimeoutSecs int    `json:"timeout_secs"`
		Force       bool   `json:"force"`
	}
	_ = json.NewDecoder(io.LimitReader(r.Body, 4096)).Decode(&body)
	req := gpuyield.HoldRequest{
		Reason:      clipField(body.Reason, 200),
		Owner:       clipField(body.Owner, 200),
		OperationID: clipField(body.OperationID, 64),
		Workload:    clipField(body.Workload, 120),
		Mode:        strings.TrimSpace(body.Mode),
		Timeout:     time.Duration(body.TimeoutSecs) * time.Second,
		Force:       body.Force,
	}
	gc, err := s.gpuHold(r.Context(), req)
	if err != nil {
		writeGPUHoldError(w, "hold", err, gc)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"status": "held", "gpu_contention": gc})
}

// handleGPURelease ends the hold the body names: {operation_id, generation,
// force, resume: "now"}. The ids must match the lease (compare-and-set) or
// the release is 409 held_by_other with the current lease; force ends any
// hold (a body with neither ids nor force is a legacy release = force).
func (s *Server) handleGPURelease(w http.ResponseWriter, r *http.Request) {
	if s.gpuRelease == nil {
		writeJSON(w, http.StatusServiceUnavailable, map[string]any{"error": "gpu yield not running on this agent"})
		return
	}
	var body struct {
		OperationID string `json:"operation_id"`
		Generation  uint64 `json:"generation"`
		Force       bool   `json:"force"`
		Resume      string `json:"resume"`
	}
	_ = json.NewDecoder(io.LimitReader(r.Body, 4096)).Decode(&body)
	req := gpuyield.ReleaseRequest{
		OperationID: clipField(body.OperationID, 64),
		Generation:  body.Generation,
		Force:       body.Force || strings.TrimSpace(body.OperationID) == "",
		ResumeNow:   strings.EqualFold(strings.TrimSpace(body.Resume), "now"),
	}
	gc, err := s.gpuRelease(r.Context(), req)
	if err != nil {
		writeGPUHoldError(w, "release", err, gc)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"status": "released", "gpu_contention": gc})
}

func clipField(s string, n int) string {
	s = strings.TrimSpace(s)
	if len(s) > n {
		s = s[:n]
	}
	return s
}

// writeGPUHoldError maps a lease error to its status and a machine-readable
// code, with the node's gpu_contention beside it so the caller sees the
// current lease.
func writeGPUHoldError(w http.ResponseWriter, op string, err error, gc gpuyield.Contention) {
	var held *gpuyield.ErrHeld
	var drain *gpuyield.ErrDrainTimeout
	out := map[string]any{"status": "refused", "op": op, "detail": err.Error(), "gpu_contention": gc}
	switch {
	case errors.As(err, &held):
		out["error"] = "held_by_other"
		out["current"] = held.Current
		writeJSON(w, http.StatusConflict, out)
	case errors.As(err, &drain):
		out["status"] = "needs_attention"
		out["error"] = "drain_timeout"
		out["in_flight"] = drain.Remaining
		writeJSON(w, http.StatusConflict, out)
	case errors.Is(err, gpuyield.ErrTransition):
		out["error"] = "transition_in_progress"
		writeJSON(w, http.StatusConflict, out)
	case errors.Is(err, gpuyield.ErrNotHeld):
		out["error"] = "not_held"
		writeJSON(w, http.StatusConflict, out)
	default:
		out["error"] = "bad_request"
		writeJSON(w, http.StatusBadRequest, out)
	}
}
