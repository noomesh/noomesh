// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 PersonifAI LLC

package api

import (
	"context"
	"errors"
	"net/http"
	"time"

	"github.com/noomesh/noomesh/node-agent-go/internal/addonwl"
	dockerpkg "github.com/noomesh/noomesh/node-agent-go/internal/docker"
	"github.com/noomesh/noomesh/node-agent-go/internal/mutant"
)

// Agent-managed node workloads on the actuator (i300 F5b). The same three
// routes serve both kinds of workload. A workload whose worker container
// carries noo.managed-by=agent was provisioned by this agent from
// desired-config's node_workloads, and its start and stop go through the node
// workload lifecycle (internal/docker, NodeWorkloads): start provisions if
// needed, starts the door and then the worker; stop drains the worker through
// the door and only then stops it. Every other workload (an i163 container the
// add-on's own compose created) keeps the path in addon_workloads.go,
// untouched.

// workloadSyncTimeout bounds a managed start (provisioning may load an image)
// and a managed stop beyond the drain's own timeout, which is the decl's
// (up to an hour) and is applied inside the lifecycle.
const (
	managedStartTimeout = 10 * time.Minute
	managedStopTimeout  = time.Hour + 5*time.Minute
)

// serveManaged answers the request and returns true when addon/workload is an
// agent-managed node workload. status is the reply word of the route: "started"
// (start), "stopped" (stop), anything else is the status route.
func (s *Server) serveManaged(w http.ResponseWriter, r *http.Request, status string) bool {
	if s.managed == nil {
		if mutant.On("am_nil") {
			writeJSON(w, http.StatusInternalServerError, map[string]any{"error": "no lifecycle"})
			return true
		}
		return false
	}
	addon, name := r.PathValue("addon"), r.PathValue("workload")
	if (!addonwl.NameOK(addon) && !mutant.On("am_name_addon")) || (!addonwl.NameOK(name) && !mutant.On("am_name_workload")) {
		return false // the container path answers the bad name
	}
	ok, err := s.managed.Managed(r.Context(), addon, name)
	if (err != nil && !mutant.On("am_err")) || (!ok && !mutant.On("am_notours")) {
		// Unknown (the daemon failed) or not ours: the container path decides,
		// as it did before this existed.
		return false
	}
	var st dockerpkg.ManagedState
	switch status {
	case "started":
		ctx, cancel := context.WithTimeout(r.Context(), mutant.Pick("am_start_timeout", time.Nanosecond, managedStartTimeout))
		defer cancel()
		st, err = s.managed.Start(ctx, addon, name)
	case "stopped":
		ctx, cancel := context.WithTimeout(r.Context(), mutant.Pick("am_stop_timeout", time.Nanosecond, managedStopTimeout))
		defer cancel()
		st, err = s.managed.Stop(ctx, addon, name)
	default:
		ctx, cancel := context.WithTimeout(r.Context(), mutant.Pick("am_status_timeout", time.Nanosecond, 20*time.Second))
		defer cancel()
		st, err = s.managed.Status(ctx, addon, name)
	}
	out := map[string]any{"addon": addon, "workload": name, "managed": true, "container": dockerpkg.WorkloadContainerName(addon, name)}
	if err != nil {
		var me *dockerpkg.ManagedError
		code, detail, httpStatus := "workload_error", err.Error(), http.StatusBadGateway
		if errors.As(err, &me) {
			code = mutant.Pick("am_err_code", code, me.Code)
			detail = mutant.Pick("am_err_detail", detail, me.Detail)
			httpStatus = mutant.Pick("am_err_status", httpStatus, me.HTTP)
		}
		out["status"], out["error"], out["detail"] = "refused", code, detail
		writeJSON(w, httpStatus, out)
		return true
	}
	out["status"], out["state"], out["running"], out["ready"] = status, st.State, st.Running && !mutant.On("am_out_running"), st.Ready && !mutant.On("am_out_ready")
	if mutant.On("am_out_state") {
		out["state"] = ""
	}
	out["health"] = managedHealth(st)
	if st.Reason != "" && !mutant.On("am_reason") {
		out["reason"] = st.Reason
	}
	writeJSON(w, http.StatusOK, out)
	return true
}

// managedHealth is docker's health word for the gateway's ready wait, from the
// workload's own readiness (health.ready through the door): "healthy" once
// ready, "starting" while the worker runs and is not yet ready, "" when it is
// not running.
func managedHealth(st dockerpkg.ManagedState) string {
	switch {
	case st.Ready && !mutant.On("am_h_ready"):
		return "healthy"
	case st.Running && !mutant.On("am_h_running"):
		return "starting"
	}
	return ""
}
