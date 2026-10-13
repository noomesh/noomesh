// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 PersonifAI LLC

package docker

import (
	"net/netip"
	"os"
	"runtime"
	"strings"
	"testing"

	"github.com/moby/moby/api/types/container"
	"github.com/moby/moby/api/types/network"
)

// The door is published on host loopback only, on the DOOR's port, with an
// ephemeral host port — and only on macOS (Docker Desktop cannot route to a
// bridge IP; a Linux host can, and publishes nothing).
func TestDoorPublishIsLoopbackOnly(t *testing.T) {
	for backend, door := range backendDoors {
		cfg, hc := &container.Config{}, &container.HostConfig{}
		applyLoopbackDoor(cfg, hc, door.Port)
		if len(hc.PortBindings) != 1 || len(cfg.ExposedPorts) != 1 {
			t.Fatalf("%s: want exactly the door published, got %v", backend, hc.PortBindings)
		}
		for p, bs := range hc.PortBindings {
			if int(p.Num()) != door.Port {
				t.Errorf("%s: published %v, want the door port %d", backend, p, door.Port)
			}
			if door.Sidecar != "" && int(p.Num()) == door.PlainPort && door.PlainPort != door.Port {
				t.Errorf("%s: published the RAW backend port %d", backend, door.PlainPort)
			}
			for _, b := range bs {
				if !b.HostIP.IsLoopback() {
					t.Errorf("%s: door bound on %v — loopback only", backend, b.HostIP)
				}
			}
		}
	}
	// Source guard: the one binding in this package's backend/sidecar path
	// is the loopback one above.
	for _, f := range []string{"backends.go", "sidecar.go", "client.go"} {
		src, err := os.ReadFile(f)
		if err != nil {
			t.Fatal(err)
		}
		if strings.Contains(string(src), "PortBindings") || strings.Contains(string(src), "PublishAllPorts") {
			t.Errorf("%s sets a port binding directly — go through applyLoopbackDoor", f)
		}
	}
	src, _ := os.ReadFile("doorpublish.go")
	if strings.Contains(string(src), "0.0.0.0") || strings.Count(string(src), `MustParseAddr("127.0.0.1")`) != 1 {
		t.Error("doorpublish.go must bind 127.0.0.1 and nothing else")
	}
	if LoopbackDoorPublish() != (runtime.GOOS == "darwin") {
		t.Error("LoopbackDoorPublish must be true on macOS only")
	}
}

func TestDialAddrPrefersLoopbackDoorThenBridge(t *testing.T) {
	p, _ := network.PortFrom(8000, network.TCP)
	bridge := map[string]*network.EndpointSettings{"noo-cluster": {IPAddress: netip.MustParseAddr("172.18.0.2")}}

	// Linux, nothing published: the bridge IP on the container port.
	ns := &container.NetworkSettings{Networks: bridge}
	if got, err := dialAddrFrom("noo-vllm", "8000", ns, "linux"); err != nil || got != "172.18.0.2:8000" {
		t.Fatalf("linux bridge: %q %v", got, err)
	}
	// macOS, nothing published: an error naming why, never a bridge IP.
	if got, err := dialAddrFrom("noo-vllm", "8000", ns, "darwin"); err == nil {
		t.Fatalf("darwin without a loopback door dialled %q", got)
	}
	// A loopback door wins on both.
	ns.Ports = network.PortMap{p: {{HostIP: netip.MustParseAddr("127.0.0.1"), HostPort: "49153"}}}
	for _, goos := range []string{"linux", "darwin"} {
		if got, err := dialAddrFrom("noo-vllm", "8000", ns, goos); err != nil || got != "127.0.0.1:49153" {
			t.Fatalf("%s loopback door: %q %v", goos, got, err)
		}
	}
	// A 0.0.0.0 publish is never the route.
	ns.Ports = network.PortMap{p: {{HostIP: netip.MustParseAddr("0.0.0.0"), HostPort: "8000"}}}
	if got, _ := dialAddrFrom("noo-vllm", "8000", ns, "linux"); got != "172.18.0.2:8000" {
		t.Fatalf("0.0.0.0 publish used as the dial address: %q", got)
	}
}
