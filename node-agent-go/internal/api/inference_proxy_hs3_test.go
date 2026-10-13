// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 PersonifAI LLC

package api

import (
	"testing"

	"github.com/noomesh/noomesh/node-agent-go/internal/config"
)

// H-S3: the inference proxy must never disable TLS verification. Previously it
// fell back to InsecureSkipVerify when the cluster CA couldn't be loaded, which
// makes backend traffic MITM-able on a shared docker host.
func TestHttpsTransportNeverSkipsVerify(t *testing.T) {
	tr := httpsTransport(&config.Config{})
	if tr.TLSClientConfig == nil {
		t.Fatal("httpsTransport must set a TLSClientConfig")
	}
	if tr.TLSClientConfig.InsecureSkipVerify {
		t.Fatal("httpsTransport must NOT set InsecureSkipVerify (fail-closed, H-S3)")
	}
}
