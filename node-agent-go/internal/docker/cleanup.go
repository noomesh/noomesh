// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 PersonifAI LLC

package docker

import (
	"context"
	"log/slog"
	"os"
	"time"

	"github.com/moby/moby/client"
)

// CleanupImages counts (and unless dryRun, removes) dangling Docker images.
//
// Serves POST /cleanup/images, called by the gateway's disk_cleanup
// heartbeat action (heartbeat_actions.rs detect_docker_images, always
// dry_run:true today). Scope is deliberately narrow: dangling images only —
// never tagged images, so a cleanup can't evict a model backend image the
// node would just re-pull.
//
// Returns the number of dangling images found (dry run) or removed.
func (c *Client) CleanupImages(dryRun bool) (int, error) {
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()

	images, err := c.listImages(ctx, client.ImageListOptions{
		Filters: make(client.Filters).Add("dangling", "true"),
	})
	if err != nil {
		return 0, err
	}

	if dryRun {
		return len(images), nil
	}

	removed := 0
	for _, img := range images {
		if _, err := c.docker.ImageRemove(ctx, img.ID, client.ImageRemoveOptions{}); err != nil {
			slog.Warn("cleanup: image remove failed", "image", img.ID, "error", err)
			continue
		}
		removed++
	}
	return removed, nil
}

// CleanupLogs counts (and unless dryRun, truncates) container json-log files
// larger than maxSizeMB.
//
// Serves POST /cleanup/logs, called by the gateway's disk_cleanup heartbeat
// action (detect_container_logs, dry_run:true + max_size_mb:50). Log paths
// come from container inspect; when the agent runs containerized without
// /var/lib/docker mounted the stat fails and the file is skipped — the
// count is then a lower bound, never an error.
//
// Returns the number of oversized log files found (dry run) or truncated.
func (c *Client) CleanupLogs(dryRun bool, maxSizeMB int) (int, error) {
	if maxSizeMB <= 0 {
		maxSizeMB = 50
	}
	maxBytes := int64(maxSizeMB) * 1024 * 1024

	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()

	containers, err := c.listContainers(ctx, client.ContainerListOptions{All: true})
	if err != nil {
		return 0, err
	}

	affected := 0
	for _, ctr := range containers {
		res, err := c.docker.ContainerInspect(ctx, ctr.ID, client.ContainerInspectOptions{})
		if err != nil {
			continue
		}
		logPath := res.Container.LogPath
		if logPath == "" {
			continue
		}
		info, err := os.Stat(logPath)
		if err != nil || info.Size() <= maxBytes {
			continue // unreachable from this mount namespace, or small enough
		}
		if dryRun {
			affected++
			continue
		}
		if err := os.Truncate(logPath, 0); err != nil {
			slog.Warn("cleanup: log truncate failed", "path", logPath, "error", err)
			continue
		}
		affected++
	}
	return affected, nil
}
