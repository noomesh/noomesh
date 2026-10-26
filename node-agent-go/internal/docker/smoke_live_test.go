// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 PersonifAI LLC

package docker

// Live integration smoke for the moby/v2 client migration (PR #86).
// Exercises every migrated Docker API call path against the REAL local
// daemon using a throwaway alpine container: image inspect/pull, network
// inspect/create/remove, container create/start/wait/logs/list/stats/
// stop/remove. Gated behind NOO_DOCKER_SMOKE=1 so CI and normal test
// runs skip it (runners may not expose a usable daemon socket).
//
// Run:
//
//	NOO_DOCKER_SMOKE=1 go test -v -run TestLiveDockerSmoke ./internal/docker/

import (
	"context"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/moby/moby/api/types/container"
	"github.com/moby/moby/client"
)

func TestLiveDockerSmoke(t *testing.T) {
	if os.Getenv("NOO_DOCKER_SMOKE") != "1" {
		t.Skip("set NOO_DOCKER_SMOKE=1 to run against the local Docker daemon")
	}

	c, err := NewClient(nil, "http", "", false)
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}
	defer c.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
	defer cancel()

	const img = "alpine:3.20"
	const name = "noo-smoke-moby-v2"
	const netName = "noo-smoke-net"

	// ImageInspect (was ImageInspectWithRaw) + ImagePull with drain, the
	// same ensure-image sequence StartBackendSDK runs.
	if _, err := c.docker.ImageInspect(ctx, img); err != nil {
		reader, pullErr := c.docker.ImagePull(ctx, img, client.ImagePullOptions{})
		if pullErr != nil {
			t.Fatalf("ImagePull: %v", pullErr)
		}
		buf := make([]byte, 32*1024)
		for {
			if _, err := reader.Read(buf); err != nil {
				break
			}
		}
		reader.Close()
	}

	// Pre-clean, exercising the (Result, error) stop/remove wrappers on a
	// likely-missing container — must not panic or hard-fail.
	_, _ = c.docker.ContainerStop(ctx, name, client.ContainerStopOptions{})
	_, _ = c.docker.ContainerRemove(ctx, name, client.ContainerRemoveOptions{Force: true})

	// NetworkInspect + NetworkCreate via the same helper backends use.
	if err := c.ensureNetwork(ctx, netName); err != nil {
		t.Fatalf("ensureNetwork: %v", err)
	}
	defer c.docker.NetworkRemove(context.Background(), netName, client.NetworkRemoveOptions{})

	// ContainerCreate through the new options struct.
	resp, err := c.docker.ContainerCreate(ctx, client.ContainerCreateOptions{
		Config: &container.Config{
			Image: img,
			Cmd:   []string{"sh", "-c", "echo smoke-ok"},
		},
		Name: name,
	})
	if err != nil {
		t.Fatalf("ContainerCreate: %v", err)
	}
	defer c.docker.ContainerRemove(context.Background(), resp.ID,
		client.ContainerRemoveOptions{Force: true})

	if _, err := c.docker.ContainerStart(ctx, resp.ID, client.ContainerStartOptions{}); err != nil {
		t.Fatalf("ContainerStart: %v", err)
	}

	// ContainerWait's channel-struct result.
	waitRes := c.docker.ContainerWait(ctx, resp.ID,
		client.ContainerWaitOptions{Condition: container.WaitConditionNotRunning})
	select {
	case w := <-waitRes.Result:
		if w.StatusCode != 0 {
			t.Fatalf("container exited %d, want 0", w.StatusCode)
		}
	case err := <-waitRes.Error:
		t.Fatalf("ContainerWait: %v", err)
	case <-time.After(60 * time.Second):
		t.Fatal("timed out waiting for container exit")
	}

	// Package-level logs helper — verifies the multiplex-header stripping
	// still lines up with what the new client returns.
	lines, err := c.ContainerLogs(context.Background(), name, 10, "")
	if err != nil {
		t.Fatalf("ContainerLogs: %v", err)
	}
	if !strings.Contains(strings.Join(lines, "\n"), "smoke-ok") {
		t.Fatalf("logs missing smoke marker, got: %q", lines)
	}

	// listContainers unwrap helper + typed Summary.State conversion.
	infos, err := c.ListContainers(context.Background())
	if err != nil {
		t.Fatalf("ListContainers: %v", err)
	}
	found := false
	for _, ci := range infos {
		if ci.Name == name {
			found = true
			if ci.Status == "" {
				t.Fatal("ListContainers returned empty Status for smoke container")
			}
		}
	}
	if !found {
		t.Fatal("smoke container missing from ListContainers")
	}

	// Stats path: listContainers + ContainerStats against whatever is
	// running on the host (must not error or panic; may be empty).
	_ = c.AllContainerStats(context.Background())
}
