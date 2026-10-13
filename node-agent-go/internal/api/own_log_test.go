// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 PersonifAI LLC

package api

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/noomesh/noomesh/node-agent-go/internal/config"
)

func TestOwnLogIsServedWithoutDocker(t *testing.T) {
	OwnLog.Add(`{"msg":"reconcile.start_failed","backend":"ollama"}`)
	OwnLog.Add(`{"msg":"reconcile.ollama_pull_start","model":"gemma4:12b"}`)
	s := &Server{cfg: &config.Config{}, mux: http.NewServeMux()}
	req := httptest.NewRequest(http.MethodGet, "/logs/"+OwnLogName+"?tail=1", nil)
	req.SetPathValue("container", OwnLogName)
	w := httptest.NewRecorder()
	s.handleContainerLogs(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("status %d: %s", w.Code, w.Body.String())
	}
	var body struct {
		Logs []string `json:"logs"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &body); err != nil {
		t.Fatal(err)
	}
	if len(body.Logs) != 1 || !strings.Contains(body.Logs[0], "ollama_pull_start") {
		t.Fatalf("logs = %v", body.Logs)
	}
}

func TestOtherContainersStillNeedDocker(t *testing.T) {
	s := &Server{cfg: &config.Config{}, mux: http.NewServeMux()}
	req := httptest.NewRequest(http.MethodGet, "/logs/noo-ollama", nil)
	req.SetPathValue("container", "noo-ollama")
	w := httptest.NewRecorder()
	s.handleContainerLogs(w, req)
	if w.Code != http.StatusServiceUnavailable {
		t.Fatalf("expected 503 without docker, got %d", w.Code)
	}
}
