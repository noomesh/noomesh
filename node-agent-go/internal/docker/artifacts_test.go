// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 PersonifAI LLC

package docker

import "testing"

// The tar-name convention IS the protocol between the controller's export
// (`image_tar_name` in noo-cli) and this node's pull — these cases pin the
// Go half; noo-cli pins the Rust half with the same inputs and outputs.
func TestImageTarName(t *testing.T) {
	cases := []struct {
		ref, arch, want string
	}{
		{"pai-assistant/node-agent:latest", "amd64", "pai-assistant_node-agent_latest_amd64.tar"},
		{"noo-sandbox-base:latest", "arm64", "noo-sandbox-base_latest_arm64.tar"},
		{"ghcr.io/noomesh/llamacpp:v0.1.47", "amd64", "ghcr.io_noomesh_llamacpp_v0.1.47_amd64.tar"},
	}
	for _, c := range cases {
		if got := ImageTarName(c.ref, c.arch); got != c.want {
			t.Errorf("ImageTarName(%q, %q) = %q, want %q", c.ref, c.arch, got, c.want)
		}
	}
}

func TestImageTarGzNameIsTheTarNamePlusGz(t *testing.T) {
	if got := ImageTarGzName("ghcr.io/x/y:z", "arm64"); got != "ghcr.io_x_y_z_arm64.tar.gz" {
		t.Errorf("ImageTarGzName = %q", got)
	}
	for _, ref := range []string{"pai-assistant/node-agent:latest", "noo-sandbox-base:latest"} {
		if ImageTarGzName(ref, "amd64") != ImageTarName(ref, "amd64")+".gz" {
			t.Errorf("%s: gz name is not tar name + .gz", ref)
		}
	}
}
