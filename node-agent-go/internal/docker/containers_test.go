// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 PersonifAI LLC

package docker

import (
	"os"
	"strings"
	"testing"
)

func TestValidateManagedContainerName(t *testing.T) {
	valid := []string{
		"noo-browser-abc12345",
		"noo-skill-x",
		"noo-thing_1.2",
	}
	for _, name := range valid {
		if err := ValidateManagedContainerName(name); err != nil {
			t.Errorf("expected %q valid, got %v", name, err)
		}
	}

	invalid := []string{
		"",                                 // empty
		"nginx",                            // no noo- prefix
		"browser-noo-1",                    // prefix not at start
		"noo-node-agent",                   // the agent itself
		"noo-x;rm -rf /",                   // shell metachars
		"noo-a/b",                          // path separator
		"noo-" + string(make([]byte, 200)), // too long / NUL bytes
	}
	for _, name := range invalid {
		if err := ValidateManagedContainerName(name); err == nil {
			t.Errorf("expected %q invalid", name)
		}
	}
}

// /api/containers/start took the full container spec from the controller
// and checked only the "noo-" name prefix — so `network_mode: "host"`, any
// image, any command and any environment were all accepted, on a route
// whose sibling (/api/skills/run) refuses all three.
func TestManagedContainerRefusesHostNetwork(t *testing.T) {
	for _, nm := range []string{"host", "HOST", " host "} {
		req := &ContainerStartRequest{
			Image:         "noo-browser:latest",
			ContainerName: "noo-browser-abc",
			NetworkMode:   nm,
		}
		err := ValidateContainerStartRequest(req)
		if err == nil {
			t.Errorf("network_mode %q must be refused", nm)
		} else if !strings.Contains(err.Error(), "loopback") {
			t.Errorf("the refusal must say why, got %q", err)
		}
	}
	// What the one shipped caller actually sends (gateway browser tool).
	ok := &ContainerStartRequest{
		Image:         "noo-browser:latest",
		ContainerName: "noo-browser-abc",
		NetworkMode:   "bridge",
	}
	if err := ValidateContainerStartRequest(ok); err != nil {
		t.Fatalf("the gateway's own browser spec must still be accepted: %v", err)
	}
}

func TestManagedContainerImageAllowList(t *testing.T) {
	t.Setenv(ManagedImageAllowEnv, "")

	for _, img := range []string{
		"alpine",
		"attacker/img:latest",
		"docker.io/library/busybox",
		"ghcr.io/someone-else/noomesh/thing:1",
	} {
		req := &ContainerStartRequest{Image: img, ContainerName: "noo-x", NetworkMode: "bridge"}
		if err := ValidateContainerStartRequest(req); err == nil {
			t.Errorf("image %q must be refused by the default allow-list", img)
		}
	}

	for _, img := range []string{
		"noo-browser",
		"noo-browser:latest",
		"ghcr.io/noomesh/node-agent:v1",
	} {
		req := &ContainerStartRequest{Image: img, ContainerName: "noo-x", NetworkMode: "bridge"}
		if err := ValidateContainerStartRequest(req); err != nil {
			t.Errorf("image %q should be accepted: %v", img, err)
		}
	}

	// Widening is node-local, from this process's environment.
	t.Setenv(ManagedImageAllowEnv, "alpine, registry.local:5000/team/img")
	for _, img := range []string{"alpine:3.20", "registry.local:5000/team/img:v2"} {
		req := &ContainerStartRequest{Image: img, ContainerName: "noo-x", NetworkMode: "bridge"}
		if err := ValidateContainerStartRequest(req); err != nil {
			t.Errorf("node-local widening must be honoured for %q: %v", img, err)
		}
	}
}

// The name reaches ContainerRemove(Force). Unvalidated it was a
// force-remove of anything on the host from a sandbox route.
func TestManagedContainerStartValidatesName(t *testing.T) {
	for _, name := range []string{
		"", "noo-node-agent", "noo-gateway/../x", "noo-x;id", "postgres", "noo-x y",
	} {
		req := &ContainerStartRequest{Image: "noo-browser", ContainerName: name, NetworkMode: "bridge"}
		if err := ValidateContainerStartRequest(req); err == nil {
			t.Errorf("container_name %q must be refused", name)
		}
	}
}

// The same rail on the skills route: a skill run used to force-remove
// whatever container name it was handed before doing any other work.
func TestSkillRunValidatesContainerName(t *testing.T) {
	skillRootFixture(t)
	for _, name := range []string{"", "noo-node-agent", "noo-gateway;id", "noo-vllm/../x"} {
		req := &SkillRunRequest{Image: "busybox", ContainerName: name, NetworkMode: "none"}
		if err := ValidateSkillRunRequest(req); err == nil {
			t.Errorf("skill container_name %q must be refused", name)
		}
	}
	ok := &SkillRunRequest{Image: "busybox", ContainerName: "noo-skill-run-1", NetworkMode: "none"}
	if err := ValidateSkillRunRequest(ok); err != nil {
		t.Fatalf("a well-formed skill request must still be accepted: %v", err)
	}
}

// A managed container's published ports are loopback-only: the browser
// door serves plaintext HTTP behind a bearer and must not be LAN-reachable.
func TestManagedPublishIsLoopbackOnly(t *testing.T) {
	if got := managedPublishIP.String(); got != "127.0.0.1" {
		t.Fatalf("managedPublishIP = %s, want 127.0.0.1", got)
	}
	src, err := os.ReadFile("containers.go")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(src), "network.PortBinding{HostIP: managedPublishIP}") {
		t.Fatal("StartManagedContainer must build every PortBinding with HostIP: managedPublishIP")
	}
}
