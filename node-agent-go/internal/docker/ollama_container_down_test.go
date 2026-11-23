// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 PersonifAI LLC

package docker

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"testing"
)

// noHostOllama leaves no host `ollama` to find, so an absent container is a
// container-lane import with nothing running.
func noHostOllama(t *testing.T) {
	t.Helper()
	t.Setenv("PATH", t.TempDir())
	old := ollamaHostPaths
	ollamaHostPaths = nil
	t.Cleanup(func() { ollamaHostPaths = old })
}

// Both producers of "the container is not running" return an error that
// errors.Is matches (also through a wrap), and keep the operator's text.
func TestOllamaContainerDownErrorIsTypedOnBothProducers(t *testing.T) {
	noHostOllama(t)
	t.Setenv("NODE_ID", "n1")
	c := inspectDaemon(t, http.StatusNotFound)

	_, createErr := c.ollamaCreateInContainer(context.Background(), t.TempDir(), "m", "Modelfile", "w.gguf")
	_, _, _, baseErr := c.ollamaImportBase(context.Background())

	for name, err := range map[string]error{"ollamaCreateInContainer": createErr, "ollamaImportBase": baseErr} {
		if err == nil {
			t.Fatalf("%s: no error with the container down", name)
		}
		wrapped := fmt.Errorf("the rebuild through the container: %w", err)
		if !errors.Is(err, errOllamaContainerDown) || !errors.Is(wrapped, errOllamaContainerDown) {
			t.Errorf("%s: %v does not match errOllamaContainerDown (bare or wrapped)", name, err)
		}
		if !strings.Contains(err.Error(), "start it (`noo cluster start-backend n1 ollama`)") {
			t.Errorf("%s: the operator text is gone: %v", name, err)
		}
	}
}

// A repair that failed only because the container is down is deferred, not
// refused: the verdict about the bytes is left for after the start.
func TestOllamaVerifyRepairNeedingTheDownContainerIsDeferred(t *testing.T) {
	rg := newVerifyRig(t, false)
	model := rg.ggufSetup()
	rg.writeBlobAt(model, "tampered GGUF bytes")
	rg.repairFn = func() error {
		return fmt.Errorf("the rebuild through the container: %w", ollamaContainerDown())
	}
	res := rg.v.Verify(context.Background(), ggufModel)
	if len(rg.repairs) != 1 {
		t.Fatalf("repair not attempted: %+v", rg.repairs)
	}
	if res.State != OllamaDeferred {
		t.Fatalf("got %+v, want deferred", res)
	}
}

// Regression guard: a real repair failure still refuses, with its remedy.
func TestOllamaVerifyRealRepairFailureStillRefuses(t *testing.T) {
	t.Setenv("NOO_SELF_NODE", "1")
	rg := newVerifyRig(t, false)
	model := rg.ggufSetup()
	rg.writeBlobAt(model, "tampered GGUF bytes")
	rg.repairFn = func() error { return errors.New("ollama create failed") }
	res := rg.v.Verify(context.Background(), ggufModel)
	if res.State != OllamaRefused || !strings.Contains(res.Reason, "noo models pull "+ggufModel) {
		t.Fatalf("got %+v, want refused with its remedy", res)
	}
}
