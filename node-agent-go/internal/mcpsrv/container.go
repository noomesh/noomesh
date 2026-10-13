// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 PersonifAI LLC

package mcpsrv

// The container transport for node-local MCP servers.
//
// This is the whole of the sandbox floor's node-side seam. `startStdio` — the
// plain `exec.Command` lane — is GONE, not deprecated, and there is no
// fallback to it: a server that cannot be contained does not run. See
// local.go's `image` refusal for the operator-facing half of that.

import (
	"context"
	"encoding/json"
	"fmt"
	"io"

	"github.com/noomesh/noomesh/node-agent-go/internal/docker"
)

// containerSpec is the placement spec a node-local entry renders to. It is
// deliberately NOT the old `stdioSpec`: a spec that cannot name an image is a
// spec that cannot be contained, and keeping one type for both would let an
// uncontained one through by leaving a field empty.
type containerSpec struct {
	Image   string            `json:"image"`
	Command string            `json:"command"`
	Args    []string          `json:"args"`
	Env     map[string]string `json:"env"`
	Volumes map[string]string `json:"volumes,omitempty"`
	Network string            `json:"network,omitempty"`
	Memory  string            `json:"memory,omitempty"`
}

// ContainerRuntime is what the supervisor needs from Docker. An interface
// rather than *docker.Client so the supervisor's refusal paths are testable
// without a daemon — and so a node with no Docker at all gets a legible
// message instead of a nil dereference.
type ContainerRuntime interface {
	StartMCPContainer(ctx context.Context, spec docker.MCPContainerSpec, stderr io.Writer) (*docker.AttachedContainer, error)
}

// containerClient is the JSON-RPC core over a contained server's attached
// stdio. Same Client interface as before, so rpc.go and the supervisor's
// discover/call paths did not change.
type containerClient struct {
	*pipeClient
	att    *docker.AttachedContainer
	stderr *bufio_tail
}

func (c *containerClient) Close() error {
	_ = c.att.Stdin.Close()
	return c.att.Close()
}

// mcpContainerName is the managed container name for a server id. The
// `noo-` prefix is what ValidateManagedContainerName requires, and the
// `noo-mcp-` namespace keeps these distinguishable from backends and skills
// in `docker ps`.
func mcpContainerName(id string) string { return "noo-mcp-" + id }

// startContainer is the ONLY way a node-local MCP server starts.
func startContainer(
	ctx context.Context, rt ContainerRuntime, p Placement, lookup func(string) (string, bool),
) (*containerClient, error) {
	var spec containerSpec
	if err := json.Unmarshal(p.Spec, &spec); err != nil {
		return nil, fmt.Errorf("spec: %w", err)
	}
	if spec.Image == "" {
		// Unreachable from the node-local loader (validateLocalEntry refuses
		// first), and it must stay unreachable from anywhere else: this is
		// the point past which there is no un-contained lane to fall back to.
		return nil, fmt.Errorf(
			"MCP server %q has no `image`, so there is nothing to contain it in", p.ID)
	}
	env, err := ResolveRefs(spec.Env, lookup)
	if err != nil {
		return nil, err
	}
	// LAST, after everything about the entry itself has been checked: a
	// misconfigured entry on a node with no Docker should report the
	// misconfiguration, not the Docker gap.
	if rt == nil {
		return nil, fmt.Errorf(
			"this agent has no Docker runtime, and a node-local MCP server runs only in a "+
				"container (the skills sandbox floor: non-root, no capabilities, "+
				"no-new-privileges, a pid cap and no host network). Server %q cannot be "+
				"started here; run it as a `streamable_http` server the node dials instead",
			p.ID)
	}
	tail := &bufio_tail{}
	att, err := rt.StartMCPContainer(ctx, docker.MCPContainerSpec{
		Name:        mcpContainerName(p.ID),
		Image:       spec.Image,
		Command:     append([]string{spec.Command}, spec.Args...),
		Env:         ScrubbedEnv(env, true),
		BinaryMount: spec.Command,
		Volumes:     spec.Volumes,
		Network:     spec.Network,
		MemoryLimit: spec.Memory,
	}, tail)
	if err != nil {
		return nil, err
	}
	return &containerClient{
		pipeClient: newPipeClient(att.Stdout, att.Stdin),
		att:        att,
		stderr:     tail,
	}, nil
}
