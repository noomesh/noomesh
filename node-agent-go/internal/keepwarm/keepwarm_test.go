// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 PersonifAI LLC

package keepwarm

import "testing"

func TestLookupFindsOnlyTheDeclaredModel(t *testing.T) {
	t.Cleanup(func() { Set(nil) })
	Set([]Warm{{Model: "gemma4:12b", Target: "gpu"}})
	if _, ok := Lookup("gemma4:12b"); !ok {
		t.Fatal("the declared model must be found")
	}
	for _, other := range []string{"gemma4", "gemma4:e2b", "harrier", "", "auto"} {
		if _, ok := Lookup(other); ok {
			t.Errorf("%q is not the declared model", other)
		}
	}
	Set(nil)
	if _, ok := Lookup("gemma4:12b"); ok {
		t.Fatal("an emptied set declares nothing")
	}
}

func TestSameModelFollowsOllamasImplicitLatest(t *testing.T) {
	for _, c := range []struct {
		a, b string
		want bool
	}{
		{"gemma4", "gemma4:latest", true},
		{"Gemma4:12B", "gemma4:12b", true},
		{"gemma4:12b", "gemma4", false},
		{"host:5000/ns/m", "host:5000/ns/m:latest", true},
		{"", "", false},
	} {
		if got := SameModel(c.a, c.b); got != c.want {
			t.Errorf("SameModel(%q, %q) = %v, want %v", c.a, c.b, got, c.want)
		}
	}
}

func TestOnlyACPUTargetIsOffTheGPU(t *testing.T) {
	if (Warm{Target: "cpu"}).OnGPU() {
		t.Error("a cpu placement holds no GPU")
	}
	if !(Warm{}).OnGPU() || !(Warm{Target: "gpu"}).OnGPU() {
		t.Error("an undeclared or gpu target may hold the GPU")
	}
}
