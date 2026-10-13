// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 PersonifAI LLC

package docker

import (
	"net/netip"
	"runtime"

	"github.com/moby/moby/api/types/container"
	"github.com/moby/moby/api/types/network"
)

// LoopbackDoorPublish reports whether this agent publishes each backend's
// DOOR — vLLM's own client-certificate listener, or the stunnel sidecar in
// front of any other backend — on the host's loopback. True on macOS only.
//
// The agent is a host process and dials its doors by container name through
// the host-mode dialer (internal/containerdial), which swaps the name for an
// address the host can reach while the URL, SNI and hostname verification
// stay on the door's SAN. On Linux that address is the container's bridge IP
// and nothing is published. Docker Desktop runs containers in a VM whose
// bridge IPs the Mac cannot route to, so there the door alone is published
// on 127.0.0.1 (ephemeral host port, read back by ContainerDialAddr's
// inspect) and the dialer uses that. Never the raw port of a sidecar-fronted
// backend, never a non-loopback address.
func LoopbackDoorPublish() bool { return runtime.GOOS == "darwin" }

// applyLoopbackDoor publishes doorPort on 127.0.0.1 (ephemeral host port) —
// the one place in this package a backend or sidecar container gets a port
// binding (pinned by TestDoorPublishIsLoopbackOnly and
// tests/test_node_backends_require_client_certs.py).
func applyLoopbackDoor(cfg *container.Config, hostCfg *container.HostConfig, doorPort int) {
	p, ok := network.PortFrom(uint16(doorPort), network.TCP)
	if !ok {
		return
	}
	if cfg.ExposedPorts == nil {
		cfg.ExposedPorts = network.PortSet{}
	}
	cfg.ExposedPorts[p] = struct{}{}
	hostCfg.PortBindings = network.PortMap{
		p: {{HostIP: netip.MustParseAddr("127.0.0.1"), HostPort: ""}},
	}
}
