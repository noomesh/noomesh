// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 PersonifAI LLC

package docker

import (
	"context"
	"fmt"
	"strings"

	"github.com/moby/moby/api/types/container"
	"github.com/moby/moby/client"
)

// Labels an add-on's compose puts on a workload container so the node
// agent's actuator (internal/addonwl, api/addon_workloads.go) may act on it.
const (
	LabelAddon    = "noo.addon"
	LabelWorkload = "noo.workload"
)

// WorkloadState is what the actuator reports about a workload's container.
type WorkloadState struct {
	ID      string `json:"id"`
	Name    string `json:"name"`
	Running bool   `json:"running"`
	// Health: the container's healthcheck verdict (`healthy`, `unhealthy`,
	// `starting`), empty when it has none.
	Health string `json:"health,omitempty"`
}

// FindWorkloadContainer is the one container (running or stopped) that
// carries BOTH labels for addon/workload and has the declared name. Two
// matches, or a match under another name, is a refusal: the actuator acts
// on exactly what the bundle declared, never on a look-alike.
func (c *Client) FindWorkloadContainer(ctx context.Context, addon, workload, name string) (*WorkloadState, error) {
	opts := client.ContainerListOptions{
		All: true,
		Filters: make(client.Filters).
			Add("label", LabelAddon+"="+addon).
			Add("label", LabelWorkload+"="+workload),
	}
	ctrs, err := c.listContainers(ctx, opts)
	if err != nil {
		return nil, fmt.Errorf("list containers: %w", err)
	}
	var found *container.Summary
	for i := range ctrs {
		for _, n := range ctrs[i].Names {
			if strings.TrimPrefix(n, "/") == name {
				if found != nil {
					return nil, fmt.Errorf("more than one container is labelled %s=%s %s=%s and named %s", LabelAddon, addon, LabelWorkload, workload, name)
				}
				found = &ctrs[i]
			}
		}
	}
	if found == nil {
		if len(ctrs) > 0 {
			return nil, fmt.Errorf("a container is labelled %s=%s %s=%s but is not named %s (the declaration names the container)", LabelAddon, addon, LabelWorkload, workload, name)
		}
		return nil, fmt.Errorf("no container labelled %s=%s %s=%s named %s: the add-on's compose has not created it on this node", LabelAddon, addon, LabelWorkload, workload, name)
	}
	st := &WorkloadState{ID: found.ID, Name: name}
	ins, err := c.docker.ContainerInspect(ctx, found.ID, client.ContainerInspectOptions{})
	if err != nil {
		return nil, fmt.Errorf("inspect %s: %w", name, err)
	}
	if s := ins.Container.State; s != nil {
		st.Running = s.Running
		if s.Health != nil {
			if h := strings.TrimSpace(string(s.Health.Status)); h != "" && h != string(container.NoHealthcheck) {
				st.Health = h
			}
		}
	}
	return st, nil
}
