// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 PersonifAI LLC

package embedtarget

import "testing"

func TestSetAllGetAndFor(t *testing.T) {
	t.Cleanup(func() { Set(Target{}) })
	SetAll([]Target{
		{Backend: "ollama", Model: "harrier"},
		{Backend: "ollama", Model: "Nomic-Embed-Code"},
	})
	if got := Get(); got.Model != "harrier" {
		t.Errorf("Get() = %+v, want the primary (first)", got)
	}
	if len(All()) != 2 {
		t.Errorf("All() = %+v", All())
	}
	for _, m := range []string{"nomic-embed-code", "NOMIC-EMBED-CODE:latest", " harrier:latest "} {
		if _, ok := For(m); !ok {
			t.Errorf("For(%q) found nothing", m)
		}
	}
	if got, _ := For("nomic-embed-code"); got.Model != "Nomic-Embed-Code" {
		t.Errorf("For returned %+v", got)
	}
	for _, m := range []string{"", "bge-m3"} {
		if _, ok := For(m); ok {
			t.Errorf("For(%q) matched", m)
		}
	}
}

func TestSetKeepsSingleTargetShapeAndClears(t *testing.T) {
	t.Cleanup(func() { Set(Target{}) })
	Set(Target{Backend: "embedding", Model: "m"})
	if Get().Model != "m" || len(All()) != 1 {
		t.Errorf("Set did not record one target: %+v", All())
	}
	Set(Target{})
	if Get() != (Target{}) || len(All()) != 0 {
		t.Errorf("zero Set must clear: %+v", All())
	}
}
