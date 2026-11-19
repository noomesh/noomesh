// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 PersonifAI LLC

// Fixture for TestGuardFlagsADoorLiteral: under testdata, so never built.
// No BackendDialURL, no OLLAMA_URL — only door literals link it to a backend.
package doorliteral

import (
	"net/http"

	"github.com/noomesh/noomesh/node-agent-go/internal/containerdial"
)

// Builds a transport and dials a door by name with no host dial: must be reported.
func dialsDoorWithoutApplyDial() (*http.Response, error) {
	c := &http.Client{Transport: &http.Transport{}}
	return c.Get("https://noo-stunnel-x:1/v1/models")
}

// Same, through ApplyDial: covered, not reported.
func dialsDoorWithApplyDial() (*http.Response, error) {
	c := &http.Client{Transport: containerdial.ApplyDial(&http.Transport{})}
	return c.Get("https://noo-stunnel-x:1/v1/models")
}

// Names a door but builds no transport: not reported.
func namesDoorOnly() string { return "http://noo-reranker:8085" }
