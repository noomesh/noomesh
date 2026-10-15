// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 PersonifAI LLC

package api

import (
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestContainerProxyRoundTrip(t *testing.T) {
	var gotAuth, gotPath, gotQuery, gotBody, gotUp string
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		gotAuth, gotPath, gotQuery, gotBody = r.Header.Get("Authorization"), r.URL.Path, r.URL.RawQuery, string(b)
		gotUp = r.Header.Get(UpstreamAuthHeader)
		w.WriteHeader(201)
		_, _ = w.Write([]byte(`{"ok":true}`))
	}))
	defer backend.Close()

	s := &Server{proxyTarget: func(name string) (string, error) {
		return strings.TrimPrefix(backend.URL, "http://"), nil
	}}
	mux := http.NewServeMux()
	mux.HandleFunc("/api/containers/{name}/proxy/{path...}", s.handleContainerProxy)

	req := httptest.NewRequest("POST", "/api/containers/noo-browser-ab12/proxy/navigate?x=1", strings.NewReader(`{"url":"u"}`))
	req.Header.Set("Authorization", "Bearer AGENT")
	req.Header.Set(UpstreamAuthHeader, "Bearer BROWSER")
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)

	if rec.Code != 201 || rec.Body.String() != `{"ok":true}` {
		t.Fatalf("got %d %q", rec.Code, rec.Body.String())
	}
	if gotAuth != "Bearer BROWSER" {
		t.Errorf("container saw Authorization %q; want the upstream bearer, never the agent's", gotAuth)
	}
	if gotUp != "" {
		t.Errorf("upstream header leaked to container: %q", gotUp)
	}
	if gotPath != "/navigate" || gotQuery != "x=1" || gotBody != `{"url":"u"}` {
		t.Errorf("path=%q query=%q body=%q", gotPath, gotQuery, gotBody)
	}
}

func TestContainerProxyRefusals(t *testing.T) {
	s := &Server{proxyTarget: func(string) (string, error) { return "", io.EOF }}
	mux := http.NewServeMux()
	mux.HandleFunc("/api/containers/{name}/proxy/{path...}", s.handleContainerProxy)
	for name, want := range map[string]int{"redis": 400, "noo-node-agent": 400, "noo-browser-x": 404} {
		rec := httptest.NewRecorder()
		mux.ServeHTTP(rec, httptest.NewRequest("GET", "/api/containers/"+name+"/proxy/status", nil))
		if rec.Code != want {
			t.Errorf("%s: got %d want %d", name, rec.Code, want)
		}
	}
}
