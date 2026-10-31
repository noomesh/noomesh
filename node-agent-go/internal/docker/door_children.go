// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 PersonifAI LLC

package docker

import (
	"context"
	"log/slog"
	"strings"

	"github.com/moby/moby/api/types/container"
	"github.com/moby/moby/client"
)

// Every running container in a door's network namespace (`network_mode:
// container:<noo-stunnel-x>`) that the backend path in readDeclaredTLS does
// not judge: the controller's compose-only doors (noo-ollama-embed,
// noo-ollama-embed-cpu, noo-vllm-secondary), which have no backendDoors
// sidecar. A door restarted alone, by `docker restart` or by its own
// restart policy after a crash, leaves such a child in the old namespace,
// alive and unreachable (i317 e1, the 0.6.15 rc.2 and rc.4 rehearsals).
// Compose's `depends_on … restart: true` covers a compose-driven restart
// only, so the agent heals the rest the same way it heals its own engines.

// doorChildren returns the running doors (ID -> name) and the containers in
// a door's namespace that backendKeyFromName does not map to a fronted
// backend. Pure, so the selection is tested without a daemon.
func doorChildren(ctrs []container.Summary) (map[string]string, []container.Summary) {
	doors := map[string]string{}
	for _, ctr := range ctrs {
		if len(ctr.Names) == 0 {
			continue
		}
		if name := strings.TrimPrefix(ctr.Names[0], "/"); strings.HasPrefix(name, StunnelContainerPrefix) {
			doors[ctr.ID] = name
		}
	}
	var children []container.Summary
	for _, ctr := range ctrs {
		if len(ctr.Names) == 0 || doors[ctr.ID] != "" {
			continue
		}
		if !strings.HasPrefix(ctr.HostConfig.NetworkMode, "container:") {
			continue
		}
		if key := backendKeyFromName(strings.TrimPrefix(ctr.Names[0], "/")); key != "" && SidecarFor(key) != "" {
			continue // judged by readDeclaredTLS, healed with the engines
		}
		children = append(children, ctr)
	}
	return doors, children
}

// strandedDoorChildren is the restart list (child name -> ID): each child
// whose door started after it. A child whose namespace owner is not a
// running door is left alone; it is not this heal's to judge. started
// returns a container's State.StartedAt by ID or name, "" when unknown.
func strandedDoorChildren(ctrs []container.Summary, started func(string) string) map[string]string {
	doors, children := doorChildren(ctrs)
	out := map[string]string{}
	for _, ch := range children {
		ref := strings.TrimPrefix(ch.HostConfig.NetworkMode, "container:")
		shape, doorID := judgeEngineDoor(ch.HostConfig.NetworkMode, doors, started(ch.ID), started(ref))
		if shape == engineStranded && doorID != "" {
			out[strings.TrimPrefix(ch.Names[0], "/")] = ch.ID
		}
	}
	return out
}

// healStrandedDoorChildren restarts each child strandedDoorChildren names;
// a restart rejoins the door's current namespace. Returns the restarted
// container names.
func (c *Client) healStrandedDoorChildren(ctx context.Context) []string {
	ctrs, err := c.listContainers(ctx, client.ContainerListOptions{})
	if err != nil {
		return nil
	}
	started := func(id string) string {
		res, err := c.docker.ContainerInspect(ctx, id, client.ContainerInspectOptions{})
		if err != nil || res.Container.State == nil {
			return ""
		}
		return res.Container.State.StartedAt
	}
	var out []string
	for name, id := range strandedDoorChildren(ctrs, started) {
		timeout := 10
		if _, err := c.docker.ContainerRestart(ctx, id, client.ContainerRestartOptions{Timeout: &timeout}); err != nil {
			slog.Warn("door: could not restart a container stranded by its door's restart", "container", name, "error", err)
			continue
		}
		slog.Warn("door: restarted a container stranded by its door's restart", "container", name)
		out = append(out, name)
	}
	return out
}
