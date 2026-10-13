// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 PersonifAI LLC

package jobs

import "testing"

func TestFetchBundleIsDispatchable(t *testing.T) {
	// The whole point of moving off the HTTP poke: this must ride the
	// ordinary dispatch rail, where JetStream holds it for an offline node
	// and the connection is outbound.
	if !CanExecute("fetch_bundle") {
		t.Fatal("fetch_bundle must be executable on a node")
	}
}

func TestFetchBundleIgnoresItsPayload(t *testing.T) {
	// Timing crosses the wire, never content. executeFetchBundle takes no
	// arguments at all — the signature is the guarantee, so this test exists
	// to fail loudly if someone widens it to accept a payload later.
	//
	// A compile error here is the intended failure mode.
	var f func(*Executor) (any, error) = (*Executor).executeFetchBundle
	_ = f
}
