// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 PersonifAI LLC

package docker

import (
	"context"
	"sort"
	"strings"
	"time"

	"github.com/moby/moby/api/types/container"
	"github.com/moby/moby/api/types/mount"
	"github.com/moby/moby/client"
)

// dataMountSources returns the host side of a container's DATA bind mounts,
// sorted and de-duplicated. Only bind mounts count (a named volume has no
// operator-chosen host path), and the PKI mounts under /app/pki are not
// data: they live under NOO_PKI_DIR, not a data root, and must not read as
// "this container mounts a path outside the data roots".
func dataMountSources(mps []container.MountPoint) []string {
	seen := map[string]bool{}
	out := []string{}
	for _, m := range mps {
		if m.Type != mount.TypeBind || m.Source == "" {
			continue
		}
		if m.Destination == "/app/pki" || strings.HasPrefix(m.Destination, "/app/pki/") {
			continue
		}
		if !seen[m.Source] {
			seen[m.Source] = true
			out = append(out, m.Source)
		}
	}
	sort.Strings(out)
	return out
}

// managedDataMounts maps backend key -> data mount sources over a container
// listing, for containers THIS agent manages only (label noo.managed-by =
// node-agent-go, and a name that is a backend). Sidecars and rename-orphans
// have no backend key (backendKeyFromName) and are skipped.
func managedDataMounts(containers []container.Summary) map[string][]string {
	out := map[string][]string{}
	for _, ctr := range containers {
		if ctr.Labels["noo.managed-by"] != "node-agent-go" || len(ctr.Names) == 0 {
			continue
		}
		key := backendKeyFromName(strings.TrimPrefix(ctr.Names[0], "/"))
		if key == "" {
			continue
		}
		out[key] = dataMountSources(ctr.Mounts)
	}
	return out
}

// ManagedDataMounts asks docker which host paths each running managed
// backend container mounts. An empty map is "none running";
// an error is "could not look".
func (c *Client) ManagedDataMounts() (map[string][]string, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	containers, err := c.listContainers(ctx, client.ContainerListOptions{})
	if err != nil {
		return nil, err
	}
	return managedDataMounts(containers), nil
}
