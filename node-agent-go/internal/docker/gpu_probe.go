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

// GPUContainer is a running container whose config requests GPU access —
// either via HostConfig.DeviceRequests (the compose/SDK device-reservation
// path) or the nvidia runtime. This is DERIVED from the container's own
// config, never from a declared watch list: fu 57's watchdog died because
// its hardcoded list went stale the day its one entry was retired.
type GPUContainer struct {
	ID   string
	Name string
	// Managed: the cluster's own containers (the same hardcoded "noo-"
	// convention StartManagedContainer enforces). Only these are probed
	// and remediated — a GPU-requesting container the cluster does not
	// own (found live: CI's buildx builder requests GPUs automatically)
	// is reported for visibility but never exec'd into, restarted, or
	// alerted on.
	Managed bool
}

// GPUContainers lists RUNNING containers that request GPU access.
func (c *Client) GPUContainers(ctx context.Context) ([]GPUContainer, error) {
	containers, err := c.listContainers(ctx, client.ContainerListOptions{})
	if err != nil {
		return nil, err
	}

	var out []GPUContainer
	for _, ctr := range containers {
		res, err := c.docker.ContainerInspect(ctx, ctr.ID, client.ContainerInspectOptions{})
		if err != nil {
			continue
		}
		hc := res.Container.HostConfig
		if hc == nil {
			continue
		}
		// Explicit device reservation is a request. The nvidia RUNTIME alone
		// is not: on a host whose daemon defaults to it, EVERY container
		// carries Runtime=="nvidia" (found live on host8 — the buildx
		// builder showed up and would have been restarted-then-faulted).
		// The runtime's own activation contract is the NVIDIA_VISIBLE_DEVICES
		// env: without it the runtime injects nothing, so a container that
		// hasn't set it has not asked for a GPU.
		wantsGPU := false
		for _, dr := range hc.Resources.DeviceRequests {
			for _, caps := range dr.Capabilities {
				for _, cap := range caps {
					if cap == "gpu" {
						wantsGPU = true
					}
				}
			}
		}
		if !wantsGPU && hc.Runtime == "nvidia" && res.Container.Config != nil {
			for _, env := range res.Container.Config.Env {
				if v, ok := strings.CutPrefix(env, "NVIDIA_VISIBLE_DEVICES="); ok && v != "" && v != "void" && v != "none" {
					wantsGPU = true
					break
				}
			}
		}
		if !wantsGPU {
			continue
		}
		name := ctr.ID[:12]
		if len(ctr.Names) > 0 {
			name = strings.TrimPrefix(ctr.Names[0], "/")
		}
		out = append(out, GPUContainer{
			ID:      ctr.ID,
			Name:    name,
			Managed: strings.HasPrefix(name, "noo-"),
		})
	}
	return out, nil
}

// ExecProbe runs cmd inside a container and returns its exit code. It is a
// health probe, not a shell: no streams are attached, the exec is started
// detached and its exit code polled. A create/start error (image lacks the
// binary, container gone mid-probe) is returned as an error so callers can
// distinguish "probe impossible" from "probe failed".
func (c *Client) ExecProbe(ctx context.Context, containerID string, cmd []string) (int, error) {
	created, err := c.docker.ExecCreate(ctx, containerID, client.ExecCreateOptions{Cmd: cmd})
	if err != nil {
		return 0, fmt.Errorf("exec create: %w", err)
	}
	if _, err := c.docker.ExecStart(ctx, created.ID, client.ExecStartOptions{Detach: true}); err != nil {
		return 0, fmt.Errorf("exec start: %w", err)
	}
	for {
		ins, err := c.docker.ExecInspect(ctx, created.ID, client.ExecInspectOptions{})
		if err != nil {
			return 0, fmt.Errorf("exec inspect: %w", err)
		}
		if !ins.Running {
			// A 126/127 exit means the binary itself is absent or not
			// executable in this image — the probe is impossible there,
			// which is not the same finding as "the GPU is broken".
			if ins.ExitCode == 126 || ins.ExitCode == 127 {
				return ins.ExitCode, fmt.Errorf("probe binary unavailable in container (exit %d)", ins.ExitCode)
			}
			return ins.ExitCode, nil
		}
		select {
		case <-ctx.Done():
			return 0, ctx.Err()
		case <-time.After(500 * time.Millisecond):
		}
	}
}

// RestartContainer restarts a container by ID with the default stop timeout.
func (c *Client) RestartContainer(ctx context.Context, containerID string) error {
	_, err := c.docker.ContainerRestart(ctx, containerID, client.ContainerRestartOptions{})
	return err
}
