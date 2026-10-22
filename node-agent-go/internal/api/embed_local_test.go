// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 PersonifAI LLC

package api

import (
	"context"
	"net/http"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/noomesh/noomesh/node-agent-go/internal/config"
	"github.com/noomesh/noomesh/node-agent-go/internal/embedtarget"
)

// EmbedLocal (the pull worker's door) must be handleEmbedProxy, not a copy of
// it: same target resolution, same native lane, same status and body.
func TestEmbedLocalRunsTheSameProxyInProcess(t *testing.T) {
	var calls int32
	withEmbedTarget(t, embedtarget.Target{Backend: "ollama", Model: "harrier"})
	s := &Server{cfg: &config.Config{}, mux: http.NewServeMux(), native: nativeEmbedder(t, &calls)}

	status, body, err := s.EmbedLocal(context.Background(), []byte(`{"input":["hello"]}`))
	if err != nil || status != http.StatusOK {
		t.Fatalf("status=%d err=%v body=%s", status, err, body)
	}
	if atomic.LoadInt32(&calls) == 0 || !strings.Contains(string(body), "0.25") {
		t.Errorf("the embedder was not reached through the shared path: calls=%d body=%s", calls, body)
	}

	// The proxy's own refusals come back as a status, not an error.
	withEmbedTarget(t, embedtarget.Target{Backend: "embedding", Model: "harrier"})
	status, body, err = s.EmbedLocal(context.Background(), []byte(`{"input":["hello"]}`))
	if err != nil || status != http.StatusServiceUnavailable || !strings.Contains(string(body), "no_local_embedder") {
		t.Errorf("status=%d err=%v body=%s", status, err, body)
	}
}
