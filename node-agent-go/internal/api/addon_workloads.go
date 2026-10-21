// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 PersonifAI LLC

package api

// The add-on workload actuator (noomesh-internal i163 part B): ONE
// controller-only API that starts or stops a container an add-on declared
// in its verified bundle. The declaration reaches this node in desired-config
// (internal/addonwl); the container must exist already (the add-on's own
// compose created it) and carry the labels noo.addon=<addon> and
// noo.workload=<workload>. The caller names nothing but the two names: no
// image, command or mount ever comes over this door, so the add-on's own
// controller needs no Docker socket, and the node agent never starts a
// container it was not told about by a verified bundle.
//
// A GPU workload starts only while the node's GPU is HELD (gpuyield): the
// pool's backends are paused for it, never stopped under it. The gateway's
// reservation takes the hold (drain, then pause) before it asks for the
// start.

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"time"

	"github.com/noomesh/noomesh/node-agent-go/internal/addonwl"
	dockerpkg "github.com/noomesh/noomesh/node-agent-go/internal/docker"
	"github.com/noomesh/noomesh/node-agent-go/internal/gpuyield"
)

// workloadOps is the docker surface the actuator needs (the client, or a
// fake in tests).
type workloadOps interface {
	FindWorkloadContainer(ctx context.Context, addon, workload, name string) (*dockerpkg.WorkloadState, error)
	StartContainer(ctx context.Context, id string) error
	StopContainerGraceful(ctx context.Context, id string, timeoutS int) error
}

// workloadStopGrace is the SIGTERM grace a workload stop gives by default;
// the body's timeout_secs overrides it (the add-on drained its sessions
// before the gateway asked, so this is for the process to exit).
const workloadStopGrace = 30

func (s *Server) workloads() workloadOps {
	if s.workloadOps != nil {
		return s.workloadOps
	}
	if s.docker == nil {
		return nil
	}
	return s.docker
}

// gpuHeldNow reports whether the node's GPU is under an operator hold (the
// only state a GPU workload may start in). An agent with no GPU yield wired
// has no held state, so the answer is no.
func gpuHeldNow() bool {
	c := gpuyield.Default()
	return c != nil && c.Report().State == gpuyield.StateHeld
}

// resolveWorkload answers the names' declaration and container, or writes
// the refusal and returns nil.
func (s *Server) resolveWorkload(w http.ResponseWriter, r *http.Request) (*addonwl.Decl, *dockerpkg.WorkloadState, workloadOps) {
	addon, name := r.PathValue("addon"), r.PathValue("workload")
	if !addonwl.NameOK(addon) || !addonwl.NameOK(name) {
		writeJSON(w, http.StatusBadRequest, map[string]any{"error": "bad_name",
			"detail": "add-on and workload names are lowercase letters, digits, - and _, starting with a letter, at most 32 characters"})
		return nil, nil, nil
	}
	decl, ok := addonwl.Lookup(addon, name)
	if !ok {
		writeJSON(w, http.StatusNotFound, map[string]any{"error": "not_declared", "addon": addon, "workload": name,
			"detail": "no verified add-on bundle declares this workload for this node (desired-config addon_workloads)"})
		return nil, nil, nil
	}
	ops := s.workloads()
	if ops == nil {
		writeJSON(w, http.StatusServiceUnavailable, map[string]any{"error": "no_docker", "detail": "Docker not available"})
		return nil, nil, nil
	}
	ctx, cancel := context.WithTimeout(r.Context(), 20*time.Second)
	defer cancel()
	st, err := ops.FindWorkloadContainer(ctx, addon, name, decl.Container)
	if err != nil {
		writeJSON(w, http.StatusNotFound, map[string]any{"error": "no_container", "addon": addon, "workload": name,
			"container": decl.Container, "detail": err.Error()})
		return nil, nil, nil
	}
	return &decl, st, ops
}

func workloadReply(status string, decl *addonwl.Decl, st *dockerpkg.WorkloadState) map[string]any {
	return map[string]any{
		"status": status, "addon": decl.Addon, "workload": decl.Name, "container": st.Name,
		"running": st.Running, "health": st.Health, "gpu": decl.GPU, "need_mb": decl.NeedMB,
		"gpu_held": gpuHeldNow(),
	}
}

// handleWorkloadStatus serves GET /api/addon-workloads/{addon}/{workload}:
// the declared container's running state and health (the gateway's
// ready wait polls it).
func (s *Server) handleWorkloadStatus(w http.ResponseWriter, r *http.Request) {
	decl, st, _ := s.resolveWorkload(w, r)
	if decl == nil {
		return
	}
	writeJSON(w, http.StatusOK, workloadReply("ok", decl, st))
}

// handleWorkloadStart serves POST /api/addon-workloads/{addon}/{workload}/start.
// A GPU workload is refused (409 gpu_not_held) unless the node's GPU is
// held: the reservation holds first. Starting a running container is a
// no-op that answers its state.
func (s *Server) handleWorkloadStart(w http.ResponseWriter, r *http.Request) {
	decl, st, ops := s.resolveWorkload(w, r)
	if decl == nil {
		return
	}
	if decl.GPU && !gpuHeldNow() {
		out := workloadReply("refused", decl, st)
		out["error"] = "gpu_not_held"
		out["detail"] = "a GPU workload starts only under a GPU hold (noo cluster reserve takes one first); the pool's backends still own the GPU"
		writeJSON(w, http.StatusConflict, out)
		return
	}
	if !st.Running {
		ctx, cancel := context.WithTimeout(r.Context(), 60*time.Second)
		defer cancel()
		if err := ops.StartContainer(ctx, st.ID); err != nil {
			out := workloadReply("error", decl, st)
			out["error"] = "start_failed"
			out["detail"] = err.Error()
			writeJSON(w, http.StatusBadGateway, out)
			return
		}
		if again, err := ops.FindWorkloadContainer(ctx, decl.Addon, decl.Name, decl.Container); err == nil {
			st = again
		} else {
			st.Running = true
		}
	}
	writeJSON(w, http.StatusOK, workloadReply("started", decl, st))
}

// handleWorkloadStop serves POST /api/addon-workloads/{addon}/{workload}/stop
// with an optional body {timeout_secs}: a graceful stop (SIGTERM, then
// kill at the grace); the container keeps its spec for the next start.
func (s *Server) handleWorkloadStop(w http.ResponseWriter, r *http.Request) {
	decl, st, ops := s.resolveWorkload(w, r)
	if decl == nil {
		return
	}
	var body struct {
		TimeoutSecs int `json:"timeout_secs"`
	}
	_ = json.NewDecoder(io.LimitReader(r.Body, 4096)).Decode(&body)
	grace := workloadStopGrace
	if body.TimeoutSecs > 0 && body.TimeoutSecs <= 600 {
		grace = body.TimeoutSecs
	}
	if st.Running {
		ctx, cancel := context.WithTimeout(r.Context(), time.Duration(grace+30)*time.Second)
		defer cancel()
		if err := ops.StopContainerGraceful(ctx, st.ID, grace); err != nil {
			out := workloadReply("error", decl, st)
			out["error"] = "stop_failed"
			out["detail"] = err.Error()
			writeJSON(w, http.StatusBadGateway, out)
			return
		}
		st.Running = false
		st.Health = ""
	}
	writeJSON(w, http.StatusOK, workloadReply("stopped", decl, st))
}
