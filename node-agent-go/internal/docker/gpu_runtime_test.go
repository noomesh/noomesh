// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 PersonifAI LLC

package docker

import "testing"

// The daemon's runtime table decides whether a GPU device request can be
// honoured; a kernel that shows a GPU (WSL2's /dev/dxg on every box) does not.
func TestGPUDeviceRequestNeedsTheNvidiaRuntime(t *testing.T) {
	if runtimesIncludeNvidia(map[string]struct{}{"io.containerd.runc.v2": {}, "runc": {}}) {
		t.Fatal("runc alone must not count as an NVIDIA runtime")
	}
	if !runtimesIncludeNvidia(map[string]struct{}{"runc": {}, "nvidia": {}}) {
		t.Fatal("a registered nvidia runtime must count")
	}
	if runtimesIncludeNvidia(map[string]struct{}{}) {
		t.Fatal("no runtimes at all must not count")
	}
}
