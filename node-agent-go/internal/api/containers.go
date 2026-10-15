// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 PersonifAI LLC

// Handlers for generic container lifecycle + disk cleanup routes.
//
// These four routes existed only as gateway call sites until 2026-08:
// heartbeat disk_cleanup POSTs /cleanup/images + /cleanup/logs and the
// browser tool POSTs /api/containers/start + /api/containers/stop, but no
// node-agent implementation (Python or Go) ever served them. Implemented
// here so those callers stop 404ing.
package api

import (
	"encoding/json"
	"log/slog"
	"net/http"
	"net/http/httputil"
	"net/url"

	dockerpkg "github.com/noomesh/noomesh/node-agent-go/internal/docker"
)

type cleanupImagesReq struct {
	DryRun bool `json:"dry_run"`
}

type cleanupLogsReq struct {
	DryRun    bool `json:"dry_run"`
	MaxSizeMB int  `json:"max_size_mb"`
}

type containerStopReq struct {
	ContainerName string `json:"container_name"`
}

// handleCleanupImages serves POST /cleanup/images.
// Response: {"removed": N, "dry_run": bool} — the gateway's
// detect_docker_images reads `removed`.
func (s *Server) handleCleanupImages(w http.ResponseWriter, r *http.Request) {
	if s.docker == nil {
		writeJSON(w, http.StatusServiceUnavailable, map[string]string{"detail": "Docker not available"})
		return
	}
	var req cleanupImagesReq
	_ = json.NewDecoder(r.Body).Decode(&req) // empty body → full run

	removed, err := s.docker.CleanupImages(req.DryRun)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"detail": err.Error()})
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"removed": removed,
		"dry_run": req.DryRun,
	})
}

// handleCleanupLogs serves POST /cleanup/logs.
// Response: {"truncated": N, "dry_run": bool} — the gateway's
// detect_container_logs reads `truncated`.
func (s *Server) handleCleanupLogs(w http.ResponseWriter, r *http.Request) {
	if s.docker == nil {
		writeJSON(w, http.StatusServiceUnavailable, map[string]string{"detail": "Docker not available"})
		return
	}
	var req cleanupLogsReq
	_ = json.NewDecoder(r.Body).Decode(&req)

	truncated, err := s.docker.CleanupLogs(req.DryRun, req.MaxSizeMB)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"detail": err.Error()})
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"truncated": truncated,
		"dry_run":   req.DryRun,
	})
}

// handleContainerStart serves POST /api/containers/start.
// Response includes `host_port` — the gateway's browser_start reads it to
// build the container URL.
func (s *Server) handleContainerStart(w http.ResponseWriter, r *http.Request) {
	if s.docker == nil {
		writeJSON(w, http.StatusServiceUnavailable, map[string]string{"detail": "Docker not available"})
		return
	}
	var req dockerpkg.ContainerStartRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"detail": "invalid request body"})
		return
	}

	// Admission for the WHOLE spec before any container work — the same
	// shape as /api/skills/run. The controller chooses the image, command
	// and environment here, so the node bounds the image to its own
	// allow-list and refuses host networking outright.
	if err := dockerpkg.ValidateContainerStartRequest(&req); err != nil {
		slog.Warn("managed container start refused",
			"image", req.Image, "container", req.ContainerName,
			"network_mode", req.NetworkMode, "error", err)
		writeJSON(w, http.StatusBadRequest, map[string]string{"detail": err.Error()})
		return
	}

	result, err := s.docker.StartManagedContainer(req)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"detail": err.Error()})
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"status":         "started",
		"container_name": result.ContainerName,
		"host_port":      result.HostPort,
		"host_ports":     result.HostPorts,
	})
}

// handleContainerStop serves POST /api/containers/stop.
func (s *Server) handleContainerStop(w http.ResponseWriter, r *http.Request) {
	if s.docker == nil {
		writeJSON(w, http.StatusServiceUnavailable, map[string]string{"detail": "Docker not available"})
		return
	}
	var req containerStopReq
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"detail": "invalid request body"})
		return
	}
	if err := dockerpkg.ValidateManagedContainerName(req.ContainerName); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"detail": err.Error()})
		return
	}

	if err := s.docker.StopManagedContainer(req.ContainerName); err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"detail": err.Error()})
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"status":         "stopped",
		"container_name": req.ContainerName,
	})
}

// UpstreamAuthHeader carries the credential for the CONTAINER on a proxied
// request. Authorization is spent on this agent's own auth (the cluster
// bearer, or none for the controller's leaf), so the container's bearer
// rides here and is moved into Authorization on the way in.
const UpstreamAuthHeader = "X-Noo-Upstream-Authorization"

// handleContainerProxy serves ANY method on
// /api/containers/{name}/proxy/{path...}: it forwards to the managed
// container's loopback-published port, path and query intact. The route is
// controller-only (ctrlMW), same as start/stop.
func (s *Server) handleContainerProxy(w http.ResponseWriter, r *http.Request) {
	resolve := s.proxyTarget
	if resolve == nil {
		if s.docker == nil {
			writeJSON(w, http.StatusServiceUnavailable, map[string]string{"detail": "Docker not available"})
			return
		}
		resolve = s.docker.ProxyTarget
	}
	name := r.PathValue("name")
	if err := dockerpkg.ValidateManagedContainerName(name); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"detail": err.Error()})
		return
	}
	hostPort, err := resolve(name)
	if err != nil {
		writeJSON(w, http.StatusNotFound, map[string]string{"detail": err.Error()})
		return
	}
	target := &url.URL{Scheme: "http", Host: hostPort}
	path := "/" + r.PathValue("path")
	rp := &httputil.ReverseProxy{
		Rewrite: func(pr *httputil.ProxyRequest) {
			pr.Out.URL.Scheme = target.Scheme
			pr.Out.URL.Host = target.Host
			pr.Out.URL.Path = path
			pr.Out.URL.RawPath = ""
			pr.Out.Host = target.Host
			// Never forward this agent's own credential to a container.
			pr.Out.Header.Del("Authorization")
			if v := pr.In.Header.Get(UpstreamAuthHeader); v != "" {
				pr.Out.Header.Set("Authorization", v)
			}
			pr.Out.Header.Del(UpstreamAuthHeader)
		},
		ErrorHandler: func(w http.ResponseWriter, _ *http.Request, err error) {
			slog.Warn("container proxy failed", "container", name, "error", err)
			writeJSON(w, http.StatusBadGateway, map[string]string{"detail": "container unreachable"})
		},
	}
	rp.ServeHTTP(w, r)
}
