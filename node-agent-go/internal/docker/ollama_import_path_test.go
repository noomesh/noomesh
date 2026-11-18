// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 PersonifAI LLC

package docker

import (
	"context"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// inspectDaemon answers only the inspect of noo-ollama, with the given status
// (200 = the managed container exists, 404 = no such container, 500 = Docker
// cannot say).
func inspectDaemon(t *testing.T, status int) *Client {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		p := r.URL.Path
		switch {
		case strings.HasSuffix(p, "/_ping"):
			w.Header().Set("API-Version", "1.45")
			_, _ = w.Write([]byte("OK"))
		case r.Method == http.MethodGet && strings.HasSuffix(p, "/containers/"+OllamaContainer+"/json"):
			w.WriteHeader(status)
			switch status {
			case http.StatusOK:
				_, _ = w.Write([]byte(`{"Id":"c1","Name":"/` + OllamaContainer + `","State":{"Status":"running","Running":true}}`))
			case http.StatusNotFound:
				_, _ = w.Write([]byte(`{"message":"No such container: ` + OllamaContainer + `"}`))
			default:
				_, _ = w.Write([]byte(`{"message":"daemon busy"}`))
			}
		default:
			w.WriteHeader(http.StatusInternalServerError)
			_, _ = w.Write([]byte(`{"message":"not faked: ` + r.Method + " " + p + `"}`))
		}
	}))
	t.Cleanup(srv.Close)
	t.Setenv("DOCKER_HOST", "tcp://"+strings.TrimPrefix(srv.URL, "http://"))
	c, err := NewClient(http.DefaultClient, "http", "test", false)
	if err != nil {
		t.Fatal(err)
	}
	return c
}

// withHostOllama puts an executable `ollama` on PATH (a stray host install)
// and clears the fixed install paths, so only this one can be found.
func withHostOllama(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	bin := filepath.Join(dir, "ollama")
	if err := os.WriteFile(bin, []byte("#!/bin/sh\nexit 0\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", dir)
	old := ollamaHostPaths
	ollamaHostPaths = nil
	t.Cleanup(func() { ollamaHostPaths = old })
	return bin
}

// A Linux node whose Ollama is the managed container, with a stray host
// binary beside it: the import goes to the container, never the host.
func TestImportGoesToTheManagedContainerEvenWithAHostBinary(t *testing.T) {
	withHostOllama(t)
	c := inspectDaemon(t, http.StatusOK)
	bin, host, err := c.ollamaImportHost(context.Background())
	if err != nil || host || bin != "" {
		t.Fatalf("managed container + host binary: got bin=%q host=%v err=%v, want the container", bin, host, err)
	}
	if v := c.ollamaImportVia(context.Background()); v != "the "+OllamaContainer+" container" {
		t.Fatalf("via = %q", v)
	}
}

// A Linux node that runs Ollama natively (no managed container): the host
// binary, the case "host binary first" was written for.
func TestImportUsesTheHostBinaryWhereNoManagedContainerExists(t *testing.T) {
	want := withHostOllama(t)
	c := inspectDaemon(t, http.StatusNotFound)
	bin, host, err := c.ollamaImportHost(context.Background())
	if err != nil || !host || bin != want {
		t.Fatalf("no container + host binary: got bin=%q host=%v err=%v, want the host binary %s", bin, host, err, want)
	}
	if v := c.ollamaImportVia(context.Background()); v != "the host binary "+want {
		t.Fatalf("via = %q", v)
	}
}

// A Mac: no Docker client at all, Ollama native: the host binary.
func TestImportUsesTheHostBinaryWithoutDocker(t *testing.T) {
	want := withHostOllama(t)
	var c *Client
	bin, host, err := c.ollamaImportHost(context.Background())
	if err != nil || !host || bin != want {
		t.Fatalf("no Docker + host binary: got bin=%q host=%v err=%v", bin, host, err)
	}
}

// Docker cannot say (a timeout on a loaded node): an error, never a fall
// through to the host binary.
func TestImportRefusesToGuessWhenDockerCannotSay(t *testing.T) {
	withHostOllama(t)
	c := inspectDaemon(t, http.StatusInternalServerError)
	_, host, err := c.ollamaImportHost(context.Background())
	if err == nil || host {
		t.Fatalf("inspect error: got host=%v err=%v, want an error and no host path", host, err)
	}
	if !strings.Contains(err.Error(), "cannot tell whether "+OllamaContainer+" exists") {
		t.Fatalf("err = %v", err)
	}
}

// The repair's failure names the path the rebuild took, so a 0.6.27 agent's
// refusal says whether the container or a host binary failed.
func TestARepairFailureNamesThePathItTook(t *testing.T) {
	withHostOllama(t)
	t.Setenv("NOO_MODEL_CACHE_URL", "")
	c := inspectDaemon(t, http.StatusOK)
	err := c.repairOllamaModel(context.Background(), "qwen3:4b", nil)
	if err == nil || !strings.Contains(err.Error(), "the rebuild through the "+OllamaContainer+" container") {
		t.Fatalf("err = %v, want it to name the container path", err)
	}
}
