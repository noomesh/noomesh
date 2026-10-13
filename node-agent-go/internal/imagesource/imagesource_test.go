// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 PersonifAI LLC

package imagesource

import "testing"

func TestLatestRecordWinsAndReportIsSorted(t *testing.T) {
	tr := &Tracker{}
	if tr.Report() != nil {
		t.Fatal("nothing started yet: the heartbeat key must be omitted")
	}
	tr.Record("ollama/ollama:latest", Registry, "sha256:aa")
	tr.Record("ghcr.io/noomesh/llamacpp:v1", Local, "sha256:bb")
	tr.Record("ghcr.io/noomesh/llamacpp:v1", Rail, "sha256:cc")
	tr.Record("", Rail, "x") // ignored
	got := tr.Report()
	if len(got) != 2 {
		t.Fatalf("want 2 entries, got %+v", got)
	}
	if got[0].Image != "ghcr.io/noomesh/llamacpp:v1" || got[0].Source != Rail || got[0].ImageID != "sha256:cc" {
		t.Errorf("latest record must win: %+v", got[0])
	}
	if got[1].Source != Registry {
		t.Errorf("registry provenance kept: %+v", got[1])
	}
}
