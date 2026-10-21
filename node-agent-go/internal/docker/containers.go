// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 PersonifAI LLC

// Generic managed-container start/stop for the gateway's
// /api/containers/start and /api/containers/stop node-agent routes.
//
// These serve ad-hoc PAI service containers the gateway launches by name —
// today the Playwright browser sandbox (routes/ui.rs browser_start /
// browser_stop, container "noo-browser-<session>"). Unlike backends.go this
// path takes the full container spec from the controller instead of a local
// BackendSpec, and publishes requested ports on ephemeral host ports so the
// gateway can reach the container from outside the node.
//
// Safety rails match /clean and StopAllPAIContainers: only containers whose
// name starts with "noo-" can be created or stopped, and the node-agent's
// own container is untouchable.
package docker

import (
	"context"
	"fmt"
	"github.com/noomesh/noomesh/node-agent-go/internal/addonwl"
	"log/slog"
	"net/netip"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/moby/moby/api/types/container"
	"github.com/moby/moby/api/types/network"
	"github.com/moby/moby/client"
)

// ContainerStartRequest is the payload of POST /api/containers/start.
// Field set matches the gateway's browser_start payload (routes/ui.rs) and
// the legacy Python BrowserTool.start_session contract.
type ContainerStartRequest struct {
	Image         string            `json:"image"`
	Command       []string          `json:"command"`
	ContainerName string            `json:"container_name"`
	Env           map[string]string `json:"env"`
	MemoryLimit   string            `json:"memory_limit"`
	NetworkMode   string            `json:"network_mode"`
	GPU           bool              `json:"gpu"`
	// Ports maps container port ("9222" or "9222/tcp") to a desired host
	// port; null/0 requests an ephemeral host port. Every entry is
	// published on 127.0.0.1 ONLY (managedPublishIP): the gateway reaches
	// the container through this agent's authenticated
	// /api/containers/{name}/proxy/... route, never by dialing the port.
	Ports map[string]*int `json:"ports"`
}

// managedPublishIP is the host address every managed-container port is
// published on. Not request-controllable.
var managedPublishIP = netip.MustParseAddr("127.0.0.1")

// ContainerStartResult reports the started container and its first published
// host port (the gateway reads `host_port` to build the service URL).
type ContainerStartResult struct {
	ContainerName string         `json:"container_name"`
	HostPort      int            `json:"host_port,omitempty"`
	HostPorts     map[string]int `json:"host_ports,omitempty"`
}

// ValidateManagedContainerName enforces the naming rail for generic
// container operations: PAI-prefixed, not the node-agent itself, and a
// conservative charset (no path separators, no shell metacharacters).
func ValidateManagedContainerName(name string) error {
	if name == "" {
		return fmt.Errorf("container_name is required")
	}
	if !strings.HasPrefix(name, "noo-") {
		return fmt.Errorf("container_name must start with 'noo-'")
	}
	if name == "noo-node-agent" {
		return fmt.Errorf("refusing to manage the node-agent's own container")
	}
	if len(name) > 128 {
		return fmt.Errorf("container_name too long")
	}
	for _, r := range name {
		if (r < 'a' || r > 'z') && (r < 'A' || r > 'Z') && (r < '0' || r > '9') &&
			r != '-' && r != '_' && r != '.' {
			return fmt.Errorf("container_name contains invalid character %q", r)
		}
	}
	return nil
}

// ManagedImageAllowEnv extends the set of images this node will start on
// /api/containers/start. Comma-separated repository references (tag
// optional). Read from THIS process's environment: which images a node runs
// is a node-local decision, not a request field.
const ManagedImageAllowEnv = "NOO_CONTAINER_IMAGE_ALLOW"

// managedImageAllowDefault is what the shipped callers actually ask for.
// The only in-tree caller of /api/containers/start is the gateway's browser
// tool, which starts "noo-browser:latest" (gateway-rust routes/ui.rs).
var managedImageAllowDefault = append([]string{"noo-browser"}, managedRegistryRoots...)

// validateManagedImage bounds which image a controller-supplied spec may
// run. Without it this route was "start any image, with any command, with
// any environment, on any node" — strictly more than the skills route next
// door, which refuses all three.
//
// A bare name matches the image's repository exactly (tag ignored); an
// entry ending in "/" matches any repository under that prefix.
func validateManagedImage(image string) error {
	if err := validateSkillImage(image); err != nil {
		return err
	}
	repo := strings.TrimSpace(image)
	if i := strings.LastIndex(repo, "@"); i > 0 {
		repo = repo[:i]
	}
	// Strip the tag, but only when the colon is after the last "/" — a
	// registry host may carry a port ("localhost:5000/x").
	if i := strings.LastIndex(repo, ":"); i > strings.LastIndex(repo, "/") {
		repo = repo[:i]
	}
	allow := append([]string{}, managedImageAllowDefault...)
	for _, v := range strings.Split(os.Getenv(ManagedImageAllowEnv), ",") {
		if v = strings.TrimSpace(v); v != "" {
			allow = append(allow, v)
		}
	}
	for _, a := range allow {
		if strings.HasSuffix(a, "/") {
			if strings.HasPrefix(repo, a) {
				return nil
			}
			continue
		}
		if repo == a {
			return nil
		}
	}
	return fmt.Errorf(
		"image %q is not in this node's managed-container allow-list [%s] — "+
			"add it to %s in /etc/noo-node-agent.env and restart the agent if this node "+
			"is meant to run it", image, strings.Join(allow, ", "), ManagedImageAllowEnv)
}

// ValidateContainerStartRequest is the whole admission decision for
// /api/containers/start, so a bad spec is a 400 before any container work.
//
// The constraints match the skills sibling (skills.go
// ValidateSkillRunRequest), which is the point: both routes take a
// controller-supplied container spec, and there was no reason this one
// accepted `network_mode: host`, root, and an arbitrary image while the
// other refused all three. The gateway's only caller sends
// network_mode "bridge" and one known image, so nothing legitimate is lost.
func ValidateContainerStartRequest(req *ContainerStartRequest) error {
	if req == nil {
		return fmt.Errorf("empty request")
	}
	if err := ValidateManagedContainerName(req.ContainerName); err != nil {
		return err
	}
	if err := validateManagedImage(req.Image); err != nil {
		return err
	}
	// host networking puts the container on this node's loopback, in reach
	// of every service that trusts 127.0.0.1 — the agent's own control API
	// among them.
	if strings.EqualFold(strings.TrimSpace(req.NetworkMode), "host") {
		return fmt.Errorf(`network_mode "host" is refused for managed containers: ` +
			`it would put the container on this node's loopback, in reach of every ` +
			`service that trusts 127.0.0.1 — use "none", "bridge" or a named network`)
	}
	return nil
}

// StartManagedContainer creates and starts a generic PAI container from a
// controller-supplied spec, replacing any existing container with the same
// name. It returns the published host ports once the container is running.
func (c *Client) StartManagedContainer(req ContainerStartRequest) (*ContainerStartResult, error) {
	// Re-validate at the door of the function that creates the container.
	// The handler already did this; this path must not depend on that,
	// because the day a second caller appears the checks would be gone.
	if err := ValidateContainerStartRequest(&req); err != nil {
		return nil, err
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()

	// The image, over the artifact rail (image_source.go).
	if err := ensureImageFn(ctx, c, req.Image); err != nil {
		return nil, fmt.Errorf("container %s image: %w", req.ContainerName, err)
	}

	// Replace an existing container with the same name.
	_, _ = c.docker.ContainerStop(ctx, req.ContainerName, client.ContainerStopOptions{})
	_, _ = c.docker.ContainerRemove(ctx, req.ContainerName, client.ContainerRemoveOptions{Force: true})

	env := make([]string, 0, len(req.Env))
	for k, v := range req.Env {
		env = append(env, k+"="+v)
	}

	containerCfg := &container.Config{
		Image: req.Image,
		Cmd:   req.Command,
		Env:   env,
		Labels: map[string]string{
			"noo.managed-by": "node-agent-go",
			"noo.generic":    "true",
		},
	}

	// Same sandbox floor as a skill container, applied to EVERY managed
	// container whatever the spec asked for: non-root, no privilege
	// escalation past that user, no kernel capabilities, a process cap.
	// managedRunUser is overridable node-locally for an image that
	// genuinely needs its own uid — never by the request.
	pidsLimit := managedPidsLimit
	hostCfg := &container.HostConfig{
		SecurityOpt: []string{"no-new-privileges"},
		CapDrop:     []string{"ALL"},
		Resources:   container.Resources{PidsLimit: &pidsLimit},
	}
	if u := managedRunUser(); u != "" {
		containerCfg.User = u
	}
	if memBytes := parseMemoryLimit(req.MemoryLimit); memBytes > 0 {
		hostCfg.Resources.Memory = memBytes
	}
	if req.GPU && hasNvidiaGPU() {
		hostCfg.Resources.DeviceRequests = []container.DeviceRequest{{
			Driver:       "nvidia",
			Capabilities: [][]string{{"gpu"}},
			Count:        1,
		}}
	}

	// Port publishing: each requested container port is exposed and bound
	// on loopback only; empty HostPort lets Docker pick an ephemeral one.
	// A container that speaks plaintext HTTP behind a bearer must not be
	// reachable from the LAN/tailnet; see ProxyTarget / api proxy route.
	if len(req.Ports) > 0 {
		containerCfg.ExposedPorts = make(network.PortSet, len(req.Ports))
		hostCfg.PortBindings = make(network.PortMap, len(req.Ports))
		for portStr, hostPort := range req.Ports {
			port, err := network.ParsePort(portStr)
			if err != nil {
				return nil, fmt.Errorf("invalid port %q: %w", portStr, err)
			}
			binding := network.PortBinding{HostIP: managedPublishIP}
			if hostPort != nil && *hostPort > 0 {
				binding.HostPort = strconv.Itoa(*hostPort)
			}
			containerCfg.ExposedPorts[port] = struct{}{}
			hostCfg.PortBindings[port] = []network.PortBinding{binding}
		}
	}

	// Network mode: "none"/"host" go on HostConfig; a named network (or
	// "bridge") is attached via NetworkingConfig — same as skills.go.
	networkCfg := &network.NetworkingConfig{}
	switch req.NetworkMode {
	case "host":
		// Unreachable — ValidateContainerStartRequest refuses it up front.
		// Kept as a hard stop so a future edit to the validator cannot
		// quietly re-open it here.
		return nil, fmt.Errorf(`network_mode "host" is refused for managed containers`)
	case "none":
		hostCfg.NetworkMode = container.NetworkMode(req.NetworkMode)
	case "", "bridge", "default":
		// default bridge network; nothing to configure
	default:
		if err := c.ensureNetwork(ctx, req.NetworkMode); err == nil {
			networkCfg.EndpointsConfig = map[string]*network.EndpointSettings{
				req.NetworkMode: {},
			}
		} else {
			slog.Warn("containers: could not ensure network, using default",
				"network", req.NetworkMode, "error", err)
		}
	}

	resp, err := c.docker.ContainerCreate(ctx, client.ContainerCreateOptions{
		Config:           containerCfg,
		HostConfig:       hostCfg,
		NetworkingConfig: networkCfg,
		Name:             req.ContainerName,
	})
	if err != nil {
		return nil, fmt.Errorf("create container %s: %w", req.ContainerName, err)
	}
	if _, err := c.docker.ContainerStart(ctx, resp.ID, client.ContainerStartOptions{}); err != nil {
		_, _ = c.docker.ContainerRemove(ctx, resp.ID, client.ContainerRemoveOptions{Force: true})
		return nil, fmt.Errorf("start container %s: %w", req.ContainerName, err)
	}

	result := &ContainerStartResult{ContainerName: req.ContainerName}

	// Resolve ephemeral host ports from inspect.
	if len(req.Ports) > 0 {
		if ins, err := c.docker.ContainerInspect(ctx, resp.ID, client.ContainerInspectOptions{}); err == nil &&
			ins.Container.NetworkSettings != nil {
			result.HostPorts = make(map[string]int)
			for port, bindings := range ins.Container.NetworkSettings.Ports {
				for _, b := range bindings {
					if hp, err := strconv.Atoi(b.HostPort); err == nil && hp > 0 {
						result.HostPorts[port.String()] = hp
						if result.HostPort == 0 {
							result.HostPort = hp
						}
						break
					}
				}
			}
		}
	}

	slog.Info("generic container started",
		"container", req.ContainerName, "image", req.Image, "host_port", result.HostPort)
	return result, nil
}

// managedPidsLimit caps process creation: a fork bomb in a managed
// container must not take this node's backends down with it.
const managedPidsLimit int64 = 512

// ManagedRunUserEnv overrides the uid[:gid] a managed container runs as.
// Empty string restores the image's own default, which is a deliberate
// operator choice; unset means the shared non-root default.
const ManagedRunUserEnv = "NOO_CONTAINER_RUN_USER"

func managedRunUser() string {
	if v, ok := os.LookupEnv(ManagedRunUserEnv); ok {
		return strings.TrimSpace(v)
	}
	// The browser sandbox image (the one shipped caller) runs Playwright,
	// which works fine unprivileged. 65534 (nobody) exists in every base
	// image we ship — the same default the skills sandbox uses.
	return "65534:65534"
}

// StopManagedContainer stops and removes a PAI container by name.
func (c *Client) StopManagedContainer(name string) error {
	if err := ValidateManagedContainerName(name); err != nil {
		return err
	}

	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()

	timeout := 10
	if _, err := c.docker.ContainerStop(ctx, name, client.ContainerStopOptions{Timeout: &timeout}); err != nil {
		// Fall through to remove — the container may already be stopped.
		slog.Debug("containers: stop returned error", "container", name, "error", err)
	}
	if _, err := c.docker.ContainerRemove(ctx, name, client.ContainerRemoveOptions{Force: true}); err != nil {
		return fmt.Errorf("remove container %s: %w", name, err)
	}
	slog.Info("generic container stopped", "container", name)
	return nil
}

// ProxyTarget returns the loopback "127.0.0.1:<port>" a managed container's
// first published port is bound to. Only containers this agent started
// through StartManagedContainer (label noo.generic=true) qualify, so the
// proxy route cannot be pointed at a backend or any other container.
func (c *Client) ProxyTarget(name string) (string, error) {
	if err := ValidateManagedContainerName(name); err != nil {
		return "", err
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	ins, err := c.docker.ContainerInspect(ctx, name, client.ContainerInspectOptions{})
	if err != nil {
		return "", fmt.Errorf("inspect %s: %w", name, err)
	}
	if ins.Container.Config == nil {
		return "", fmt.Errorf("%s is not a managed container", name)
	}
	labels := ins.Container.Config.Labels
	// A managed container, or a workload an add-on's verified bundle
	// declared (labelled noo.addon/noo.workload, internal/addonwl): the
	// gateway's workload proxy reaches a reserved worker through here.
	if labels["noo.generic"] != "true" && !addonwl.DeclaredContainer(labels[LabelAddon], labels[LabelWorkload], name) {
		return "", fmt.Errorf("%s is not a managed container", name)
	}
	if ins.Container.NetworkSettings == nil {
		return "", fmt.Errorf("%s has no published port", name)
	}
	best := 0
	for _, bindings := range ins.Container.NetworkSettings.Ports {
		for _, b := range bindings {
			if hp, err := strconv.Atoi(b.HostPort); err == nil && hp > 0 && (best == 0 || hp < best) {
				best = hp
			}
		}
	}
	if best == 0 {
		return "", fmt.Errorf("%s has no published port", name)
	}
	return "127.0.0.1:" + strconv.Itoa(best), nil
}
