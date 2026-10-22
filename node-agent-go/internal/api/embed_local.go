// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 PersonifAI LLC

package api

import (
	"bytes"
	"context"
	"net/http"
)

// EmbedLocal runs one OpenAI-shaped embeddings request against this node's
// local embedder IN PROCESS and returns the status and body the /embed route
// would have written.
//
// It is handleEmbedProxy itself, not a copy: the pulled-embedding worker
// (internal/jobs/embedpull.go, proposal i179) must resolve the target, speak
// the engine's dialect and strip the knobs the engine rejects exactly as a
// query-time /embed does, and a second implementation would drift. The only
// thing this adds is a buffering ResponseWriter.
func (s *Server) EmbedLocal(ctx context.Context, body []byte) (int, []byte, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, "/embed", bytes.NewReader(body))
	if err != nil {
		return 0, nil, err
	}
	req.Header.Set("Content-Type", "application/json")
	rec := &bufferedResponse{header: http.Header{}, status: http.StatusOK}
	s.handleEmbedProxy(rec, req)
	return rec.status, rec.body.Bytes(), nil
}

// bufferedResponse is the smallest http.ResponseWriter that keeps what was
// written.
type bufferedResponse struct {
	header http.Header
	status int
	body   bytes.Buffer
}

func (b *bufferedResponse) Header() http.Header         { return b.header }
func (b *bufferedResponse) WriteHeader(code int)        { b.status = code }
func (b *bufferedResponse) Write(p []byte) (int, error) { return b.body.Write(p) }
