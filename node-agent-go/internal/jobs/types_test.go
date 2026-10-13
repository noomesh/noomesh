// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 PersonifAI LLC

package jobs

import "testing"

func TestCanExecuteKnownTypes(t *testing.T) {
	for _, jt := range []string{
		"inference", "tool_exec", "model_download",
		"background_graph", "background_cache", "fetch_bundle", "model_file",
	} {
		if !CanExecute(jt) {
			t.Errorf("CanExecute(%q) = false, want true", jt)
		}
	}
}

func TestCanExecuteRejectsGatewayLocalAndUnknown(t *testing.T) {
	// test_run is gateway-local (gateway-rust/src/job_types.rs). Dispatching
	// it here used to be silently ignored until the reaper; now it is a
	// fast, non-retryable failure.
	// background_embed is retired: an old gateway that still dispatches it
	// gets a fast refusal instead of a round trip that did nothing new.
	for _, jt := range []string{"test_run", "", "smoke", "warm_embeddings", "background_embed"} {
		if CanExecute(jt) {
			t.Errorf("CanExecute(%q) = true, want false", jt)
		}
	}
}
