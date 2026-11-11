// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 PersonifAI LLC

package api

import (
	"context"
	"io"
	"net/http"
	"strings"
	"time"
)

// metricsBackends are the backends whose /metrics this route hands back:
// vLLM's exposition, which the gateway's backend_metrics collector reads and
// allow-lists. Any other name is refused, so the route is never a way to GET
// an arbitrary path on an arbitrary container.
var metricsBackends = map[string]bool{"vllm": true, "vllm-secondary": true}

const (
	backendMetricsTimeout  = 5 * time.Second
	backendMetricsMaxBytes = 2 << 20
)

// handleBackendMetrics is GET /backend-metrics/{backend}: the running
// backend's /metrics, fetched through its door with this agent's own leaf
// (the same client the inference proxy uses), bounded in time and size.
// Controller-only (ctrlMW). It adds no trust path: the gateway already
// reaches this agent, and this agent already reaches its doors.
func (s *Server) handleBackendMetrics(w http.ResponseWriter, r *http.Request) {
	b := r.PathValue("backend")
	if !metricsBackends[b] {
		jsonError(w, http.StatusBadRequest, "unknown_backend", "metrics are served for vllm and vllm-secondary only")
		return
	}
	if s.docker == nil {
		jsonError(w, http.StatusServiceUnavailable, "docker_unavailable", "no docker client on this agent")
		return
	}
	running, err := s.docker.RunningBackendsCached(r.Context())
	if err != nil {
		jsonError(w, http.StatusServiceUnavailable, "docker_unavailable", err.Error())
		return
	}
	if _, ok := running[b]; !ok {
		jsonError(w, http.StatusNotFound, "backend_not_running", b+" is not running on this node")
		return
	}
	base := strings.TrimRight(s.docker.BackendDialURL(r.Context(), b), "/")
	body, status, err := fetchBounded(r.Context(), s.backendClient(base, backendMetricsTimeout), base+"/metrics")
	if err != nil {
		jsonError(w, http.StatusBadGateway, "backend_unreachable", err.Error())
		return
	}
	if status != http.StatusOK {
		jsonError(w, http.StatusBadGateway, "backend_metrics_status", http.StatusText(status))
		return
	}
	w.Header().Set("Content-Type", "text/plain; version=0.0.4")
	_, _ = w.Write(body)
}

// fetchBounded GETs url with the client, refusing a body over
// backendMetricsMaxBytes rather than truncating it (a cut exposition parses
// as a different one).
func fetchBounded(ctx context.Context, c *http.Client, url string) ([]byte, int, error) {
	ctx, cancel := context.WithTimeout(ctx, backendMetricsTimeout)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, 0, err
	}
	resp, err := c.Do(req)
	if err != nil {
		return nil, 0, err
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(io.LimitReader(resp.Body, backendMetricsMaxBytes+1))
	if err != nil {
		return nil, resp.StatusCode, err
	}
	if len(body) > backendMetricsMaxBytes {
		return nil, resp.StatusCode, errTooLarge
	}
	return body, resp.StatusCode, nil
}

var errTooLarge = metricsError("backend metrics body over the 2 MiB bound")

type metricsError string

func (e metricsError) Error() string { return string(e) }
