// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 PersonifAI LLC

package docker

// Attached-stdio containers for node-local MCP servers.
//
// # Why this exists
//
// PR #96 took the choice of WHAT runs away from the controller: a node-local
// stdio MCP server is declared in root-owned /etc/noo/mcp-servers.json, and the
// controller cannot write it. What that did not fix is what the server runs AS.
// `exec.Command` from the agent gives the child the agent's own credentials,
// and the agent is in the `docker` group — so an MCP binary that is compromised
// upstream (the realistic case for anything pulled from a package registry)
// opens /var/run/docker.sock and is root on the host.
//
// Two walls stopped that being a tweak to `startStdio`:
//
//  1. dropping the `docker` supplementary group needs CAP_SETGID, and the
//     agent is deliberately not root, so it cannot setgroups();
//  2. Go offers no hook between fork and exec, and syscall.SysProcAttr on
//     Linux has no NoNewPrivs field, so prctl(PR_SET_NO_NEW_PRIVS) is out
//     without a shim binary.
//
// A container gets both for free. So the server runs in one, under the SAME
// floor the skills route already applies (SkillFloorHostConfig), with its
// JSON-RPC riding an attached stdio stream instead of a pipe pair.
//
// # The stream
//
// ContainerCreate with OpenStdin + AttachStdin/Stdout/Stderr and Tty false,
// then ContainerAttach for the hijacked duplex connection. With Tty false the
// daemon multiplexes stdout and stderr into one framed stream, so the frames
// are demultiplexed with stdcopy: stdout carries the JSON-RPC lines, stderr
// goes to a sink the supervisor already keeps so "why did the server die" is
// still answerable.

import (
	"context"
	"fmt"
	"io"
	"log/slog"
	"net"
	"sort"
	"strings"
	"time"

	"github.com/moby/moby/api/pkg/stdcopy"
	"github.com/moby/moby/api/types/container"
	"github.com/moby/moby/api/types/mount"
	"github.com/moby/moby/api/types/network"
	"github.com/moby/moby/client"
)

// MCPContainerSpec is one node-local MCP server, as the node's own file
// declares it. Everything here comes from a root-owned file the controller
// cannot write; nothing here is a request field.
type MCPContainerSpec struct {
	// Name is the managed container name (ValidateManagedContainerName).
	Name string
	// Image is the server's image, checked against this node's
	// managed-container allow-list.
	Image string
	// Command is argv inside the container. Command[0] is the absolute host
	// path the node's file declared — the binary the node validated (root
	// owned, optional sha256) and which BinaryMount bind-mounts read-only at
	// that same path.
	Command []string
	// Env is the already-resolved, already-scrubbed environment in KEY=VALUE
	// form (mcpsrv.ScrubbedEnv upstream). The agent's own environment is NOT
	// inherited: this process holds the fleet secret, the node-agent token and
	// the NATS password.
	Env []string
	// BinaryMount is the host path of Command[0], mounted read-only at the
	// same path inside the container. Empty means the image supplies the
	// binary and the node validated nothing — which the node-local loader
	// does not allow, so in practice it is always set.
	BinaryMount string
	// Volumes are extra read-only binds, host path -> container path. Every
	// source must already have been proven to live under this node's declared
	// host roots; ValidateHostPathUnderRoots is re-run here anyway, because
	// this function must not depend on its caller having done it.
	Volumes map[string]string
	// Network is "none" (the default) or a named docker network. "host" is
	// refused: a sandbox on this node's loopback is not a sandbox.
	Network string
	// MemoryLimit is a Docker-style size ("512m"); empty means unlimited.
	MemoryLimit string
}

// AttachedContainer is a running container with its stdio attached.
type AttachedContainer struct {
	ID   string
	Name string
	// Stdout yields the container's stdout with the daemon's stream framing
	// already removed.
	Stdout io.Reader
	// Stdin writes to the container's stdin.
	Stdin io.WriteCloser

	c      *Client
	closer func()
}

// Close kills and removes the container and tears the attachment down. Safe to
// call more than once.
func (a *AttachedContainer) Close() error {
	if a == nil {
		return nil
	}
	if a.closer != nil {
		a.closer()
		a.closer = nil
	}
	if a.c == nil || a.ID == "" {
		return nil
	}
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	_, _ = a.c.docker.ContainerRemove(ctx, a.ID, client.ContainerRemoveOptions{Force: true})
	a.ID = ""
	return nil
}

// BuildMCPContainerSpec is the whole admission decision plus the container
// configuration, as a PURE function.
//
// It is separate from StartMCPContainer on purpose: the floor this change
// exists to apply is a set of fields on a HostConfig, and a test that asserts
// those fields must not need a Docker daemon to do it. Everything that can
// refuse, refuses here.
func BuildMCPContainerSpec(spec MCPContainerSpec) (
	*container.Config, *container.HostConfig, *network.NetworkingConfig, error,
) {
	if err := ValidateManagedContainerName(spec.Name); err != nil {
		return nil, nil, nil, err
	}
	if err := validateManagedImage(spec.Image); err != nil {
		return nil, nil, nil, err
	}
	if len(spec.Command) == 0 || strings.TrimSpace(spec.Command[0]) == "" {
		return nil, nil, nil, fmt.Errorf("command is required")
	}
	net := strings.TrimSpace(spec.Network)
	if net == "" {
		net = "none"
	}
	if strings.EqualFold(net, "host") {
		return nil, nil, nil, fmt.Errorf(
			`network "host" is refused for an MCP server container: it would put the server on ` +
				`this node's loopback, in reach of every service that trusts 127.0.0.1 — ` +
				`use "none" (the default) or a named network`)
	}

	env := append([]string(nil), spec.Env...)
	sort.Strings(env)

	cfg := &container.Config{
		Image: spec.Image,
		Cmd:   spec.Command,
		Env:   env,
		// Non-root, from the same node-local decision the skills route makes.
		User: SkillRunUser(),
		// The whole point of the transport: a duplex stdio stream, no TTY (so
		// the daemon frames stdout and stderr separately and stdcopy can tell
		// JSON-RPC from log noise).
		OpenStdin:    true,
		StdinOnce:    false,
		AttachStdin:  true,
		AttachStdout: true,
		AttachStderr: true,
		Tty:          false,
		Labels: map[string]string{
			"noo.managed-by": "node-agent-go",
			"noo.mcp-server": "true",
		},
	}

	// THE floor — the same object the skills route builds, not a copy of it.
	hostCfg := SkillFloorHostConfig()
	hostCfg.NetworkMode = container.NetworkMode(net)
	if memBytes := parseMemoryLimit(spec.MemoryLimit); memBytes > 0 {
		hostCfg.Resources.Memory = memBytes
	}

	var mounts []mount.Mount
	// The declared binary, read-only at its own path. It is exempt from the
	// declared-host-roots rule that `volumes` obeys, and deliberately so: it
	// carries a STRICTER rule of its own that a data root cannot offer — the
	// node's loader proved it is an absolute, root-owned, non-group-writable
	// regular file, and optionally that its sha256 is exactly what the
	// operator recorded. A path under a data root satisfies none of that.
	if spec.BinaryMount != "" {
		src, err := canonicalHostPath(spec.BinaryMount)
		if err != nil {
			return nil, nil, nil, fmt.Errorf("refusing MCP binary %q: %w", spec.BinaryMount, err)
		}
		mounts = append(mounts, mount.Mount{
			Type: mount.TypeBind, Source: src, Target: spec.Command[0], ReadOnly: true,
		})
	}
	for hostPath, containerPath := range spec.Volumes {
		if strings.TrimSpace(containerPath) == "" || !strings.HasPrefix(containerPath, "/") {
			return nil, nil, nil, fmt.Errorf(
				"bind target %q must be an absolute path in the container", containerPath)
		}
		src, err := ValidateHostPathUnderRoots(hostPath)
		if err != nil {
			return nil, nil, nil, err
		}
		mounts = append(mounts, mount.Mount{
			Type: mount.TypeBind, Source: src, Target: containerPath, ReadOnly: true,
		})
	}
	// Deterministic order, so SpecHash-style comparisons and test assertions
	// do not ride on Go's map iteration.
	sort.Slice(mounts, func(i, j int) bool { return mounts[i].Target < mounts[j].Target })
	hostCfg.Mounts = mounts

	netCfg := &network.NetworkingConfig{}
	if net != "none" && net != "bridge" {
		netCfg.EndpointsConfig = map[string]*network.EndpointSettings{net: {}}
	}
	return cfg, hostCfg, netCfg, nil
}

// StartMCPContainer creates the container from BuildMCPContainerSpec, attaches
// its stdio, starts it, and hands back the demultiplexed streams.
//
// stderrSink receives the container's stderr as it arrives; the supervisor
// keeps the tail of it so a server that dies at startup is not a silent hole.
func (c *Client) StartMCPContainer(
	ctx context.Context, spec MCPContainerSpec, stderrSink io.Writer,
) (*AttachedContainer, error) {
	cfg, hostCfg, netCfg, err := BuildMCPContainerSpec(spec)
	if err != nil {
		return nil, err
	}
	// The image, over the artifact rail (image_source.go).
	if err := ensureImageFn(ctx, c, spec.Image); err != nil {
		return nil, fmt.Errorf("MCP server %s image: %w", spec.Name, err)
	}
	// A previous incarnation of this server, from before an agent restart.
	_, _ = c.docker.ContainerStop(ctx, spec.Name, client.ContainerStopOptions{})
	_, _ = c.docker.ContainerRemove(ctx, spec.Name, client.ContainerRemoveOptions{Force: true})

	created, err := c.docker.ContainerCreate(ctx, client.ContainerCreateOptions{
		Config: cfg, HostConfig: hostCfg, NetworkingConfig: netCfg, Name: spec.Name,
	})
	if err != nil {
		return nil, fmt.Errorf("create MCP container %s: %w", spec.Name, err)
	}
	id := created.ID

	// Attach BEFORE start, or the server's `initialize` reply can be produced
	// and dropped before anything is reading.
	att, err := c.docker.ContainerAttach(ctx, id, client.ContainerAttachOptions{
		Stream: true, Stdin: true, Stdout: true, Stderr: true,
	})
	if err != nil {
		_, _ = c.docker.ContainerRemove(ctx, id, client.ContainerRemoveOptions{Force: true})
		return nil, fmt.Errorf("attach to MCP container %s: %w", spec.Name, err)
	}
	if _, err := c.docker.ContainerStart(ctx, id, client.ContainerStartOptions{}); err != nil {
		att.Close()
		_, _ = c.docker.ContainerRemove(ctx, id, client.ContainerRemoveOptions{Force: true})
		return nil, fmt.Errorf("start MCP container %s: %w", spec.Name, err)
	}

	// Demultiplex: stdout into a pipe the JSON-RPC reader owns, stderr into
	// the supervisor's tail buffer.
	pr, pw := io.Pipe()
	hijack := att.HijackedResponse
	go func() {
		_, err := stdcopy.StdCopy(pw, stderrSink, hijack.Reader)
		_ = pw.CloseWithError(err)
	}()
	slog.Info("mcpsrv.container_started",
		"container", spec.Name, "id", id[:12], "image", spec.Image,
		"network", hostCfg.NetworkMode, "user", cfg.User, "env_keys", len(spec.Env))
	return &AttachedContainer{
		ID:     id,
		Name:   spec.Name,
		Stdout: pr,
		Stdin:  stdinWriter{hijack.Conn},
		c:      c,
		closer: func() { _ = pr.Close(); hijack.Close() },
	}, nil
}

// stdinWriter narrows the hijacked net.Conn to its write half. Closing the
// whole connection would also kill the read side the RPC loop is using, so
// "close stdin" must mean CloseWrite when the transport offers it — which for
// a unix-socket or TCP hijack it does.
type stdinWriter struct{ conn net.Conn }

func (w stdinWriter) Write(p []byte) (int, error) { return w.conn.Write(p) }

func (w stdinWriter) Close() error {
	if cw, ok := w.conn.(client.CloseWriter); ok {
		return cw.CloseWrite()
	}
	return w.conn.Close()
}
