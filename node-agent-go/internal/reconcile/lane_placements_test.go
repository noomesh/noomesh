// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 PersonifAI LLC

package reconcile

import (
	"reflect"
	"testing"

	"github.com/noomesh/noomesh/node-agent-go/internal/lanes"
)

func TestPublishLanePlacements_RunningNonHarnessRowsVerbatim(t *testing.T) {
	t.Cleanup(func() { lanes.SetPlaced(nil) })
	publishLanePlacements([]placement{
		{Backend: "ollama", Model: "gemma4:12b", Role: "", DesiredState: "running"},
		{Backend: "ollama", Model: "harrier", Role: "embed", DesiredState: "running"},
		{Backend: "vllm", Model: "org/m", DesiredState: "stopped"},
		{Backend: "harness", Model: "auto", DesiredState: "running"},
	})
	want := []lanes.Placed{
		{Backend: "ollama", Model: "gemma4:12b", Role: ""},
		{Backend: "ollama", Model: "harrier", Role: "embed"},
	}
	if got := lanes.PlacedNow(); !reflect.DeepEqual(got, want) {
		t.Errorf("got %#v want %#v", got, want)
	}
}
