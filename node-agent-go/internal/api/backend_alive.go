// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 PersonifAI LLC

package api

import (
	"context"
	"io"
	"net/http"
	"strings"
	"time"

	dockerpkg "github.com/noomesh/noomesh/node-agent-go/internal/docker"
)

// aliveReads is the READ this route sends to each backend it serves: a GET
// that answers whether the server is there and cannot load a model. Only
// ollama is listed. An ollama loads the model a chat or generate request
// names, empty messages included (that is its documented load request), so
// the gateway's dispatch-health chat probe kept the node's chat model
// resident on an idle box, refreshed every 300 s. The engines (vLLM,
// llama.cpp) load at start and are probed by the gateway's deliberately
// invalid chat, which this route does not replace. backend_serving.go
// excludes ollama from the agent's own serving probe for the same reason.
var aliveReads = map[string]string{"ollama": "/api/tags"}

// backendAliveTimeout bounds one read. /api/tags reads manifests on disk,
// never weights.
const backendAliveTimeout = 5 * time.Second

// handleBackendAlive is GET /backend-alive/{backend}: can this agent reach
// the running backend, asked with a read that loads nothing. Controller-only
// (ctrlMW). The backend is dialled exactly as the inference proxy dials it
// (inferenceTarget: the adopted lane's endpoint, else the container's door),
// so "reachable here" means the proxy can reach it too.
//
// Answers, in the proxy's error shape (jsonError):
//
//	200 {"backend","reachable":true,"status"}  the backend answered (any status)
//	502 backend_unreachable                    the dial or the read failed
//	404 backend_not_running                    not running on this node
//	400 unknown_backend                        not a backend this route reads
//	503 docker_unavailable                     running backends unknown
func (s *Server) handleBackendAlive(w http.ResponseWriter, r *http.Request) {
	b := r.PathValue("backend")
	path, ok := aliveReads[b]
	if !ok {
		jsonError(w, http.StatusBadRequest, "unknown_backend", "liveness reads are served for ollama only")
		return
	}
	running, native, err := s.runningAndNative(r.Context())
	if err != nil {
		jsonError(w, http.StatusServiceUnavailable, "docker_unavailable", err.Error())
		return
	}
	if _, up := running[b]; !up {
		jsonError(w, http.StatusNotFound, "backend_not_running", b+" is not running on this node")
		return
	}
	base, _ := s.inferenceTarget(r.Context(), b, dockerpkg.BackendPorts[b], native)
	base = strings.TrimRight(base, "/")
	writeBackendAlive(r.Context(), w, b, s.backendClient(base, backendAliveTimeout), base+path)
}

// writeBackendAlive sends the one GET and answers for it. Any HTTP answer
// proves the dial (the backend is there, whatever it said); only a failed
// dial or read is backend_unreachable, the code the inference proxy gives a
// dead backend, so the gateway reads both routes the same way.
func writeBackendAlive(ctx context.Context, w http.ResponseWriter, backend string, c *http.Client, url string) {
	ctx, cancel := context.WithTimeout(ctx, backendAliveTimeout)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		jsonError(w, http.StatusInternalServerError, "bad_backend_url", err.Error())
		return
	}
	resp, err := c.Do(req)
	if err != nil {
		jsonError(w, http.StatusBadGateway, "backend_unreachable", backend+": "+err.Error())
		return
	}
	_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 1<<20))
	_ = resp.Body.Close()
	writeJSON(w, http.StatusOK, map[string]any{"backend": backend, "reachable": true, "status": resp.StatusCode})
}
