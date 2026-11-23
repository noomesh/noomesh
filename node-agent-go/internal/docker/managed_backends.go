// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 PersonifAI LLC

package docker

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/moby/moby/client"
)

// ManagedContainer is one container as the unplace reaper and the orphan
// report judge it: its name, its labels and when Docker created it.
type ManagedContainer struct {
	Name   string
	Labels map[string]string
	// Created is Docker's creation time, in whole seconds.
	Created int64
	State   string
}

// ManagedByNodeAgent is the `noo.managed-by` value this agent stamps on the
// backend containers and doors it creates (a node workload's is
// ManagedByAgent, "agent", on purpose: no backend sweep claims it).
const ManagedByNodeAgent = managedByAgent

// BackendLabel names the backend a backend container serves (`noo.backend`,
// set by StartBackendSDK).
const BackendLabel = "noo.backend"

// ManagedByLabel is the ownership label key.
const ManagedByLabel = LabelManagedBy

// ComposeServiceLabel is set by compose on every service container; the
// agent never sets it.
const ComposeServiceLabel = composeServiceLabel

// ManagedContainers lists every container carrying this agent's
// `noo.managed-by` label, running or not (an exited one comes back with its
// restart policy). A list error is an error, never an empty list: the caller
// must not judge "nothing runs" from a failure.
func (c *Client) ManagedContainers(ctx context.Context) ([]ManagedContainer, error) {
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	list, err := c.listContainers(ctx, client.ContainerListOptions{All: true})
	if err != nil {
		return nil, fmt.Errorf("listing containers: %w", err)
	}
	var out []ManagedContainer
	for _, ctr := range list {
		if len(ctr.Names) == 0 || ctr.Labels[ManagedByLabel] != managedByAgent {
			continue
		}
		out = append(out, ManagedContainer{
			Name:    strings.TrimPrefix(ctr.Names[0], "/"),
			Labels:  ctr.Labels,
			Created: ctr.Created,
			State:   string(ctr.State),
		})
	}
	return out, nil
}
