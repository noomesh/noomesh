// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 PersonifAI LLC

package docker

import (
	"strings"
	"testing"
)

func TestOwnRegistryRootsExcludeLocalBuildNamespaces(t *testing.T) {
	t.Setenv("NOO_IMAGE_PREFIX", "registry.example.net/mine")
	roots := OwnRegistryRoots()
	joined := strings.Join(roots, ",")
	if !strings.Contains(joined, "registry.example.net/mine/") {
		t.Fatalf("NOO_IMAGE_PREFIX must be a root: %v", roots)
	}
	for _, r := range roots {
		if !strings.HasSuffix(r, "/") {
			t.Fatalf("root %q must end in /", r)
		}
		for _, l := range localBuildNamespaces {
			if strings.TrimRight(r, "/") == strings.TrimRight(l, "/") {
				t.Fatalf("local build namespace %q must never be a root", l)
			}
		}
	}
}
