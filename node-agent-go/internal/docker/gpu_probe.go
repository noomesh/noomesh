// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 PersonifAI LLC

package docker

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/moby/moby/api/types/container"
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
		wantsGPU := requestsGPU(res.Container.HostConfig, res.Container.Config)
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

// requestsGPU reports whether a container's config asks for GPU access.
func requestsGPU(hc *container.HostConfig, cfg *container.Config) bool {
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
	if !wantsGPU && hc.Runtime == "nvidia" && cfg != nil {
		for _, env := range cfg.Env {
			if v, ok := strings.CutPrefix(env, "NVIDIA_VISIBLE_DEVICES="); ok && v != "" && v != "void" && v != "none" {
				wantsGPU = true
				break
			}
		}
	}
	return wantsGPU
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

// GPUBackend is one of this agent's backend containers that requests a GPU,
// running OR stopped — the shared-GPU yield (internal/gpuyield) pauses and
// resumes these and must still see them while they are stopped.
type GPUBackend struct {
	Backend string // "vllm", "llamacpp", ... (the noo-<backend> key)
	ID      string // full container id (cgroup attribution matches on it)
	Name    string
	Running bool
}

// GPUBackendContainers lists the agent's own backend containers that request
// a GPU, stopped ones included. Only containers the agent manages (the
// `noo-<backend>` name convention backendKeyFromName enforces) are returned:
// anything else on the host is foreign and is never touched.
func (c *Client) GPUBackendContainers(ctx context.Context) ([]GPUBackend, error) {
	if c == nil || c.docker == nil {
		return nil, fmt.Errorf("docker unavailable")
	}
	containers, err := c.listContainers(ctx, client.ContainerListOptions{All: true})
	if err != nil {
		return nil, err
	}
	var out []GPUBackend
	for _, ctr := range containers {
		if len(ctr.Names) == 0 {
			continue
		}
		name := strings.TrimPrefix(ctr.Names[0], "/")
		if !strings.HasPrefix(name, "noo-") || stunnelBackendKey(name) != "" {
			continue
		}
		key := backendKeyFromName(name)
		if key == "" {
			continue
		}
		res, err := c.docker.ContainerInspect(ctx, ctr.ID, client.ContainerInspectOptions{})
		if err != nil || res.Container.HostConfig == nil {
			continue
		}
		if !requestsGPU(res.Container.HostConfig, res.Container.Config) {
			continue
		}
		running := res.Container.State != nil && res.Container.State.Running
		out = append(out, GPUBackend{Backend: key, ID: ctr.ID, Name: name, Running: running})
	}
	return out, nil
}

// StopContainerGraceful stops (never removes) a container, giving the
// process timeoutS seconds to exit on SIGTERM. The container keeps its spec,
// so StartContainer brings back exactly what ran. Restart policy
// unless-stopped keeps an explicitly stopped container down across a
// daemon restart.
func (c *Client) StopContainerGraceful(ctx context.Context, id string, timeoutS int) error {
	_, err := c.docker.ContainerStop(ctx, id, client.ContainerStopOptions{Timeout: &timeoutS})
	return err
}

// StartContainer starts an existing (stopped) container.
func (c *Client) StartContainer(ctx context.Context, id string) error {
	_, err := c.docker.ContainerStart(ctx, id, client.ContainerStartOptions{})
	return err
}

// NoomeshContainer is ANY container on this host that is noomesh's — the
// agent's own backends, the compose-managed controller stack (noo-ollama-embed,
// noo-tei, noo-reranker, noo-whisper, noo-piper, ...), and leftovers from an
// older agent or image. The shared-GPU yield uses this set to tell "our
// process" from "someone else's"; it must be a superset of GPUBackend.
type NoomeshContainer struct {
	ID      string
	Name    string
	Running bool
	// GPU: the container's own config requests the GPU (running ones only).
	GPU bool
	// Orphan: recognised by NAME only. It carries neither the stack's compose
	// project label nor the agent's noo.managed-by label, so nothing this
	// agent or the stack currently owns made it — an older-image leftover
	// (found live on pop-os 2026-10-21: a noo-ollama from before the labels).
	// It is still noomesh's GPU use; it is flagged so it can be cleaned up.
	Orphan bool
}

// stackComposeProjects are the compose project labels that mark noomesh's
// own containers: "noomesh" is the controller stack (docker-compose.cluster.yml
// `name:`), "pai-assistant" the project the agent stamps on the backends it
// starts (and that older stacks used).
var stackComposeProjects = map[string]bool{"noomesh": true, "pai-assistant": true}

// ClassifyNoomesh decides whether a container is noomesh's. Labels are
// authoritative (compose project, noo.managed-by); the `noo-` name prefix is
// the fallback for containers that predate the labels, flagged orphan. The
// image is NOT consulted: attribution here only decides whether a GPU
// process counts as ours, and a mislabelled container can at worst make the
// node tolerate a lookalike's GPU use (fail-safe), never touch it.
func ClassifyNoomesh(name string, labels map[string]string, composeProject string) (owned, orphan bool) {
	if labels["noo.managed-by"] != "" || stackComposeProjects[labels["com.docker.compose.project"]] ||
		(composeProject != "" && labels["com.docker.compose.project"] == composeProject) {
		return true, false
	}
	if strings.HasPrefix(name, "noo-") {
		return true, true
	}
	return false, false
}

// NoomeshContainers lists every noomesh container on the host, stopped ones
// included (a stopped container's id can still sit in a cgroup path for a
// moment). Not limited to backends the agent knows a key for.
func (c *Client) NoomeshContainers(ctx context.Context) ([]NoomeshContainer, error) {
	if c == nil || c.docker == nil {
		return nil, fmt.Errorf("docker unavailable")
	}
	containers, err := c.listContainers(ctx, client.ContainerListOptions{All: true})
	if err != nil {
		return nil, err
	}
	var out []NoomeshContainer
	for _, ctr := range containers {
		name := ctr.ID
		if len(ctr.Names) > 0 {
			name = strings.TrimPrefix(ctr.Names[0], "/")
		}
		owned, orphan := ClassifyNoomesh(name, ctr.Labels, c.composeProject)
		if !owned {
			continue
		}
		nc := NoomeshContainer{ID: ctr.ID, Name: name, Orphan: orphan, Running: string(ctr.State) == "running"}
		if nc.Running {
			if res, err := c.docker.ContainerInspect(ctx, ctr.ID, client.ContainerInspectOptions{}); err == nil && res.Container.HostConfig != nil {
				nc.GPU = requestsGPU(res.Container.HostConfig, res.Container.Config)
			}
		}
		out = append(out, nc)
	}
	return out, nil
}
