// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 PersonifAI LLC

package docker

import (
	"context"
	"fmt"
	"net"
	"runtime"

	"github.com/moby/moby/api/types/container"
	"github.com/moby/moby/api/types/network"
	"github.com/moby/moby/client"
)

// Why this exists: the agent addresses backends by
// their docker-DNS names ("https://noo-vllm:8000"), which resolve only on
// the compose network. Inside a container that is fine; as a host process
// every such dial dies with "no such host". The host-mode dialer
// (internal/containerdial) swaps the name for an address the host CAN reach
// at socket-dial time, leaving the URL — and with it TLS SNI and hostname
// verification against the door's SAN (noo-vllm, noo-stunnel-<x>) —
// untouched. On Linux that is the bridge IP (routable from the host); on
// macOS it is the door's loopback publish. The first network with an IP
// wins: backends sit on exactly one network (noo-cluster).
//
// ContainerDialAddr is the host:port the HOST dials to reach a container's
// port — containerdial's resolver (host-mode agents only). In order:
//
//  1. a LOOPBACK publish of that port (127.0.0.1 / ::1): the door a macOS
//     node publishes (LoopbackDoorPublish), and the only address a Docker
//     Desktop host can reach — its containers live in a VM whose bridge IPs
//     the Mac cannot route to;
//  2. on Linux, the bridge IP (ContainerBridgeIP's rule) on the container
//     port — no publish needed, nothing bound on the host;
//  3. on macOS with no loopback publish, an error that says so, never a
//     bridge IP that will time out.
//
// A publish on a non-loopback address is never dialled: the agent reaches a
// door on this host only, and a 0.0.0.0 publish is a bug to surface, not a
// route to use.
func (c *Client) ContainerDialAddr(ctx context.Context, name, port string) (string, error) {
	res, err := c.docker.ContainerInspect(ctx, name, client.ContainerInspectOptions{})
	if err != nil {
		return "", fmt.Errorf("inspect %s: %w", name, err)
	}
	return dialAddrFrom(name, port, res.Container.NetworkSettings, runtime.GOOS)
}

// dialAddrFrom is the pure decision behind ContainerDialAddr.
func dialAddrFrom(name, port string, ns *container.NetworkSettings, goos string) (string, error) {
	if ns == nil {
		return "", fmt.Errorf("%s has no network settings", name)
	}
	if p, err := network.ParsePort(port + "/tcp"); err == nil {
		for _, b := range ns.Ports[p] {
			if b.HostPort != "" && b.HostIP.IsValid() && b.HostIP.IsLoopback() {
				return net.JoinHostPort(b.HostIP.String(), b.HostPort), nil
			}
		}
	}
	if goos == "darwin" {
		return "", fmt.Errorf("%s publishes no loopback port for %s; a Docker Desktop host cannot route to "+
			"container bridge IPs (the agent publishes a door on 127.0.0.1 on macOS — a container created "+
			"by an older agent is recreated by the reconciler)", name, port)
	}
	for _, ep := range ns.Networks {
		if ep != nil && ep.IPAddress.IsValid() && !ep.IPAddress.IsUnspecified() {
			return net.JoinHostPort(ep.IPAddress.String(), port), nil
		}
	}
	return "", fmt.Errorf("%s has no attached network with an IP (Networks may be {})", name)
}
