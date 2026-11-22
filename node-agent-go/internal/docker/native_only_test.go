// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 PersonifAI LLC

package docker

import (
	"context"
	"errors"
	"net/http"
	"strings"
	"testing"

	"github.com/noomesh/noomesh/node-agent-go/internal/backendrt"
)

// Followup i1156: on a Mac, Ollama runs natively or not at all.

func asDarwin(t *testing.T) {
	t.Helper()
	prev := goos
	goos = "darwin"
	t.Cleanup(func() { goos = prev })
}

func nativeServing(t *testing.T, up bool) {
	t.Helper()
	prev := nativeOllamaServing
	nativeOllamaServing = func(context.Context) bool { return up }
	t.Cleanup(func() { nativeOllamaServing = prev })
}

func withoutHostOllama(t *testing.T) {
	t.Helper()
	t.Setenv("PATH", t.TempDir())
	old := ollamaHostPaths
	ollamaHostPaths = nil
	t.Cleanup(func() { ollamaHostPaths = old })
}

// The backstop: StartBackendSDK refuses ollama on a Mac before any image is
// resolved (ensureImageFn is never asked).
func TestStartBackendSDKRefusesOllamaOnAMac(t *testing.T) {
	asDarwin(t)
	withoutHostOllama(t)
	asked := recordEnsure(t)
	err := (&Client{}).StartBackendSDK(context.Background(), "ollama", "", 0, StartOverrides{Image: "ollama/ollama:0.40.5@sha256:" + strings.Repeat("a", 64)})
	var down *backendrt.NativeDownError
	if !errors.As(err, &down) {
		t.Fatalf("err = %v, want a NativeDownError", err)
	}
	if len(*asked) != 0 {
		t.Fatalf("the ollama image was asked for on a Mac: %v", *asked)
	}
	if down.BinaryPresent || !strings.Contains(err.Error(), "brew install ollama") {
		t.Fatalf("no binary: want the install remedy, got %v", err)
	}
	// Another backend on the same Mac is not native-only (Docker Desktop is
	// a real lane for it), and Linux is unchanged.
	if nativeOnlyBackend("llamacpp") {
		t.Fatal("llamacpp on a Mac is not native-only")
	}
	goos = "linux"
	if nativeOnlyBackend("ollama") {
		t.Fatal("ollama on Linux is not native-only")
	}
}

// The import path on a Mac never asks Docker: a daemon that would answer
// "cannot tell" (500) is never consulted; the host binary serves.
func TestImportOnAMacUsesTheNativeOllamaAndNeverAsksDocker(t *testing.T) {
	asDarwin(t)
	nativeServing(t, true)
	want := withHostOllama(t)
	c := inspectDaemon(t, http.StatusInternalServerError)
	bin, host, err := c.ollamaImportHost(context.Background())
	if err != nil || !host || bin != want {
		t.Fatalf("mac, binary + server up: got bin=%q host=%v err=%v, want the host binary %s", bin, host, err, want)
	}
}

// Binary present, server down: the native-down refusal with the start remedy,
// never the container lane's "cannot tell whether noo-ollama exists".
func TestImportOnAMacWithTheNativeOllamaStopped(t *testing.T) {
	asDarwin(t)
	nativeServing(t, false)
	withHostOllama(t)
	c := inspectDaemon(t, http.StatusInternalServerError)
	_, host, err := c.ollamaImportHost(context.Background())
	var down *backendrt.NativeDownError
	if host || !errors.As(err, &down) || !down.BinaryPresent {
		t.Fatalf("mac, server down: got host=%v err=%v, want a NativeDownError with the binary present", host, err)
	}
	if !strings.Contains(err.Error(), "isn't running on this Mac") || strings.Contains(err.Error(), OllamaContainer) {
		t.Fatalf("err = %v", err)
	}
}

// No binary at all: the install remedy, and still no container lane.
func TestImportOnAMacWithoutOllamaInstalled(t *testing.T) {
	asDarwin(t)
	nativeServing(t, true)
	withoutHostOllama(t)
	c := inspectDaemon(t, http.StatusNotFound)
	_, host, err := c.ollamaImportHost(context.Background())
	var down *backendrt.NativeDownError
	if host || !errors.As(err, &down) || down.BinaryPresent {
		t.Fatalf("mac, no binary: got host=%v err=%v, want a NativeDownError without the binary", host, err)
	}
	if !strings.Contains(err.Error(), "brew install ollama") {
		t.Fatalf("err = %v", err)
	}
}
