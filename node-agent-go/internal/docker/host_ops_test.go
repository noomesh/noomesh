// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 PersonifAI LLC

package docker

import "testing"

func TestHostDirAllowed(t *testing.T) {
	ok := []string{
		"/media/user/extradrive1/noo-data/models",
		"/data/noo/models",
		"/mnt/d/noo/models",
		"/home/user/pai-assistant/models",
	}
	for _, d := range ok {
		if err := hostDirAllowed(d); err != nil {
			t.Errorf("expected allowed: %s → %v", d, err)
		}
	}
	bad := []string{
		"/etc", "/etc/passwd", "/root/.ssh", "/root", "/usr/bin",
		"/var/lib/docker/volumes", "/home/user/.ssh", "/data/../etc",
		"relative/path", "", "/run/secrets",
	}
	for _, d := range bad {
		if err := hostDirAllowed(d); err == nil {
			t.Errorf("expected refused: %s", d)
		}
	}
}

// The helper image is the agent's own release image, never the pre-rename
// local build name (2026-09-07: "No such image: pai-assistant/node-agent").
func TestHelperImageFollowsTheReleasePair(t *testing.T) {
	t.Setenv("NOO_HELPER_IMAGE", "")
	t.Setenv("NOO_IMAGE_PREFIX", "ghcr.io/noomesh/")
	t.Setenv("NOO_IMAGE_TAG", "v0.2.28")
	if got := helperImage(); got != "ghcr.io/noomesh/node-agent:v0.2.28" {
		t.Fatalf("release pair: got %q", got)
	}
	t.Setenv("NOO_IMAGE_PREFIX", "")
	t.Setenv("NOO_IMAGE_TAG", "")
	if got := helperImage(); got != "ghcr.io/noomesh/node-agent:latest" {
		t.Fatalf("default: got %q", got)
	}
	t.Setenv("NOO_HELPER_IMAGE", "example.test/pinned:1")
	if got := helperImage(); got != "example.test/pinned:1" {
		t.Fatalf("pin: got %q", got)
	}
}
