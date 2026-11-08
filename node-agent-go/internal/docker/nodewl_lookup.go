// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 PersonifAI LLC

package docker

import (
	"context"
	"fmt"
	"time"

	"github.com/moby/moby/client"
)

// NodeWorkloadOf reports whether the container called name is an
// agent-managed node workload's worker, and which one. The labels the agent
// itself wrote at provision time decide it (noo.managed-by=agent,
// noo.addon, noo.workload), and the name must be exactly the worker name
// those labels imply, so a sidecar, a pre-created i163 workload or any other
// container is never one. A container the daemon does not know is
// (managed=false, err=nil): the caller's ordinary path then answers it.
func (c *Client) NodeWorkloadOf(ctx context.Context, name string) (addon, workload string, managed bool, err error) {
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	ins, err := c.docker.ContainerInspect(ctx, name, client.ContainerInspectOptions{})
	if err != nil {
		if isGone(err) {
			return "", "", false, nil
		}
		return "", "", false, fmt.Errorf("inspect %s: %w", name, err)
	}
	if ins.Container.Config == nil {
		return "", "", false, nil
	}
	l := ins.Container.Config.Labels
	if l[LabelManagedBy] != ManagedByAgent || l[LabelAddon] == "" || l[LabelWorkload] == "" {
		return "", "", false, nil
	}
	if name != WorkloadContainerName(l[LabelAddon], l[LabelWorkload]) {
		return "", "", false, nil
	}
	return l[LabelAddon], l[LabelWorkload], true, nil
}

// NodeWorkloadDoorAddr is NodeWorkloads.DoorAddr over this client, read from
// the daemon on every call.
func (c *Client) NodeWorkloadDoorAddr(ctx context.Context, addon, workload string) (string, error) {
	return (&NodeWorkloads{api: dockerProvAPI{c}}).DoorAddr(ctx, addon, workload)
}
