// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 PersonifAI LLC

package docker

// On a Mac, Ollama runs natively or not at all (followup i1156).
//
// Docker on a Mac is a Linux VM without the GPU, and a Mac node may have no
// Docker at all, so an ollama container there is never what the operator
// wants: the reconciler, the start API and the import path refuse it with
// backendrt.NativeDownError. This file holds the docker package's half: the
// backstop inside StartBackendSDK (any future caller that skips the
// reconciler's check still never pulls or creates an ollama container on a
// Mac) and the import path's native-only choice.
//
// Docker itself is NOT refused on a Mac: Docker Desktop is a real lane for
// container doors (LoopbackDoorPublish), so the refusal is per backend, never
// in the client constructor.

import (
	"context"
	"net/http"
	"runtime"
	"time"

	"github.com/noomesh/noomesh/node-agent-go/internal/backendrt"
)

// goos is the platform the native-only rules read. A package var so tests
// exercise the darwin paths on Linux CI.
var goos = runtime.GOOS

// nativeOnlyBackend reports whether backend may run on this node only as a
// native process: Ollama on a Mac.
func nativeOnlyBackend(backend string) bool {
	return goos == "darwin" && backend == "ollama"
}

// nativeOllamaServing asks the native Ollama whether it answers. A package
// var so tests decide.
var nativeOllamaServing = func(ctx context.Context) bool {
	ctx, cancel := context.WithTimeout(ctx, 2*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, nativeOllamaBase()+"/api/version", nil)
	if err != nil {
		return false
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return false
	}
	_ = resp.Body.Close()
	return resp.StatusCode < 500
}

// nativeDown is the refusal for a native-only backend.
func nativeDown(backend string, binaryPresent bool) *backendrt.NativeDownError {
	return backendrt.NewNativeDownError(backend, binaryPresent)
}
