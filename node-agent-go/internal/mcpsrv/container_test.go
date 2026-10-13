// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 PersonifAI LLC

package mcpsrv

import (
	"context"
	"encoding/json"
	"io"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/noomesh/noomesh/node-agent-go/internal/docker"
	"github.com/noomesh/noomesh/node-agent-go/internal/refusals"
)

// testImage is an image inside the shipped managed-container allow-list
// (docker.managedImageAllowDefault), so the entries in these tests do not also
// have to set NOO_CONTAINER_IMAGE_ALLOW to get past admission.
const testImage = "ghcr.io/noomesh/mcp-git:v1"

// ── the floor ───────────────────────────────────────────────────────────

// THE finding this change closes. A node-local stdio MCP server ran as
// `noo-agent`, and `noo-agent` is in the `docker` group — so an operator-chosen
// binary that is compromised upstream opens /var/run/docker.sock and is root on
// the host. An entry that names no image cannot be contained, and there is no
// un-contained lane left to fall back to, so it must REFUSE — visibly, through
// the refusals channel, naming the field that fixes it.
func TestAnEntryWithNoImageIsRefused(t *testing.T) {
	refusals.Reset()
	t.Cleanup(refusals.Reset)
	bin := rootOwnedBinary(t)
	localFile(t, `[
      {"id":"contained","image":"`+testImage+`","command":"`+bin+`"},
      {"id":"bare","command":"`+bin+`"}
    ]`)

	entries, refs, err := loadLocalStdio(LocalStdioPath(), localOwnerOK)
	if err != nil {
		t.Fatalf("the file itself is fine: %v", err)
	}
	if len(entries) != 1 || entries[0].ID != "contained" {
		t.Fatalf("only the contained entry may load: %+v", entries)
	}
	why, ok := refs["bare"]
	if !ok {
		t.Fatalf("an entry with no image must be refused; refusals = %v", refs)
	}
	// The message has to name the field, or the operator's next move is a
	// guess. Assert the parse found a real refusal before asserting its text.
	if !strings.Contains(why, "`image`") {
		t.Errorf("the refusal must name the field that fixes it; got %q", why)
	}
	if !strings.Contains(why, LocalStdioPath()) {
		t.Errorf("the refusal must name the file to edit; got %q", why)
	}
	// And it must reach the OPERATOR, not just the loader's return value:
	// resolveWanted is what records to the heartbeat channel.
	New(nil, nil, nil).resolveWanted(nil)
	var found bool
	for _, r := range refusals.List() {
		if r.Scope == "mcp_local_server" && r.Target == "bare" && strings.Contains(r.Reason, "`image`") {
			found = true
		}
	}
	if !found {
		t.Errorf("the refusal must reach the heartbeat channel: %+v", refusals.List())
	}
}

// The node's own entry renders as a CONTAINER placement. "stdio" now means
// "an uncontained process" and this package no longer has one, so a renderer
// that still emitted it would be handing the supervisor a transport whose only
// remaining implementation is a refusal.
func TestALocalEntryRendersAContainerPlacement(t *testing.T) {
	bin := rootOwnedBinary(t)
	localFile(t, `[{"id":"git","image":"`+testImage+`","command":"`+bin+`",
	  "args":["--repo","/srv/x"],"env":{"A":"1"},"network":"none"}]`)

	s := New(nil, nil, nil)
	got, ok := s.resolveWanted(nil)["git"]
	if !ok {
		t.Fatal("the node's own server must be wanted")
	}
	if got.Transport != transportContainer {
		t.Fatalf("transport = %q, want %q", got.Transport, transportContainer)
	}
	var spec containerSpec
	if err := json.Unmarshal(got.Spec, &spec); err != nil {
		t.Fatal(err)
	}
	if spec.Image != testImage || spec.Command != bin || len(spec.Args) != 2 {
		t.Fatalf("spec = %+v", spec)
	}
}

// The container is created with the SKILLS host config — not a config that
// resembles it. This is the assertion the whole change exists to make true, so
// it reads the fields off the object the transport would hand the daemon.
func TestTheContainerIsCreatedWithTheSkillsFloor(t *testing.T) {
	bin := rootOwnedBinary(t)
	cfg, hostCfg, netCfg, err := docker.BuildMCPContainerSpec(docker.MCPContainerSpec{
		Name:        "noo-mcp-git",
		Image:       testImage,
		Command:     []string{bin, "--repo", "/srv/x"},
		Env:         []string{"A=1"},
		BinaryMount: bin,
	})
	if err != nil {
		t.Fatalf("BuildMCPContainerSpec: %v", err)
	}

	// The floor, field by field. `SkillFloorHostConfig` is the single
	// declaration; comparing against a literal here would only prove this test
	// agrees with itself, so compare against that declaration.
	floor := docker.SkillFloorHostConfig()
	if len(hostCfg.SecurityOpt) != 1 || hostCfg.SecurityOpt[0] != "no-new-privileges" {
		t.Errorf("SecurityOpt = %v, want no-new-privileges", hostCfg.SecurityOpt)
	}
	if len(hostCfg.CapDrop) != 1 || hostCfg.CapDrop[0] != "ALL" {
		t.Errorf("CapDrop = %v, want ALL", hostCfg.CapDrop)
	}
	if hostCfg.Resources.PidsLimit == nil || floor.Resources.PidsLimit == nil ||
		*hostCfg.Resources.PidsLimit != *floor.Resources.PidsLimit {
		t.Errorf("PidsLimit = %v, want the skills floor's", hostCfg.Resources.PidsLimit)
	}
	if cfg.User != docker.SkillRunUser() || cfg.User == "" {
		t.Errorf("User = %q, want the non-root skills user", cfg.User)
	}
	// No host network, by default and without being asked.
	if string(hostCfg.NetworkMode) != "none" {
		t.Errorf("NetworkMode = %q, want none", hostCfg.NetworkMode)
	}
	if len(netCfg.EndpointsConfig) != 0 {
		t.Errorf("EndpointsConfig = %v, want none", netCfg.EndpointsConfig)
	}
	// The stream the transport rides on.
	if !cfg.OpenStdin || !cfg.AttachStdin || !cfg.AttachStdout || !cfg.AttachStderr || cfg.Tty {
		t.Errorf("stdio attach flags wrong: %+v", cfg)
	}
	// The declared binary is mounted read-only at its own path.
	if len(hostCfg.Mounts) != 1 {
		t.Fatalf("mounts = %+v, want the binary bind", hostCfg.Mounts)
	}
	if m := hostCfg.Mounts[0]; m.Target != bin || !m.ReadOnly {
		t.Errorf("binary mount = %+v, want %s read-only", m, bin)
	}
}

// "host" would put the server on this node's loopback — in reach of the
// agent's own API and every other service that trusts 127.0.0.1. A sandbox
// that can dial localhost is not a sandbox.
func TestHostNetworkIsRefused(t *testing.T) {
	bin := rootOwnedBinary(t)
	_, _, _, err := docker.BuildMCPContainerSpec(docker.MCPContainerSpec{
		Name: "noo-mcp-git", Image: testImage, Command: []string{bin}, Network: "host",
	})
	if err == nil {
		t.Fatal(`network "host" must be refused`)
	}
	if !strings.Contains(err.Error(), "loopback") {
		t.Errorf("the refusal must say why; got %q", err)
	}
}

// An extra bind must live under a root the NODE declared. Otherwise the
// operator's file — or anything that got write access to it — picks the
// container's view of the host filesystem.
func TestExtraVolumesMustSitUnderDeclaredRoots(t *testing.T) {
	bin := rootOwnedBinary(t)
	t.Setenv(docker.HostRootsEnv, "")
	_, _, _, err := docker.BuildMCPContainerSpec(docker.MCPContainerSpec{
		Name: "noo-mcp-git", Image: testImage, Command: []string{bin},
		Volumes: map[string]string{"/etc": "/etc"},
	})
	if err == nil {
		t.Fatal("a bind outside the declared roots must be refused")
	}

	root := t.TempDir()
	t.Setenv(docker.HostRootsEnv, root)
	_, hostCfg, _, err := docker.BuildMCPContainerSpec(docker.MCPContainerSpec{
		Name: "noo-mcp-git", Image: testImage, Command: []string{bin},
		BinaryMount: bin, Volumes: map[string]string{root + "/repos": "/srv/repos"},
	})
	if err != nil {
		t.Fatalf("a bind under a declared root must be accepted: %v", err)
	}
	if len(hostCfg.Mounts) != 2 {
		t.Fatalf("mounts = %+v, want the binary plus the declared bind", hostCfg.Mounts)
	}
}

// ── the transport ───────────────────────────────────────────────────────

// A full JSON-RPC round trip over the attached stream, with the DAEMON
// replaced by a stub rather than the server: the code under test is the
// framing and lifecycle, and a real container would make this an integration
// test (see TestLiveMCPContainerRoundTrip).
func TestContainerTransportRoundTrip(t *testing.T) {
	bin := rootOwnedBinary(t)
	rt := &stubRuntime{}
	spec, _ := json.Marshal(containerSpec{Image: testImage, Command: bin})
	p := Placement{ID: "git", Transport: transportContainer, Spec: spec}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	c, err := startContainer(ctx, rt, p, func(string) (string, bool) { return "", false })
	if err != nil {
		t.Fatalf("startContainer: %v", err)
	}
	t.Cleanup(func() { _ = c.Close() })

	go stubMCPServer(t, rt.in, rt.out)
	tools, err := c.ListTools(ctx)
	if err != nil {
		t.Fatalf("ListTools: %v", err)
	}
	if len(tools) != 1 || tools[0].Name != "git_log" {
		t.Fatalf("tools = %+v", tools)
	}
	if !rt.started {
		t.Error("the transport must have gone through the container runtime")
	}
	if rt.spec.Name != "noo-mcp-git" {
		t.Errorf("container name = %q", rt.spec.Name)
	}
}

// A node with no Docker must say so, by name, rather than quietly running the
// server uncontained — which is the exact failure this change removes.
func TestNoDockerMeansNoNodeLocalServer(t *testing.T) {
	spec, _ := json.Marshal(containerSpec{Image: testImage, Command: "/bin/cat"})
	_, err := startContainer(context.Background(), nil,
		Placement{ID: "git", Transport: transportContainer, Spec: spec},
		func(string) (string, bool) { return "", false })
	if err == nil {
		t.Fatal("with no container runtime the server must not start")
	}
	if !strings.Contains(err.Error(), "no Docker runtime") {
		t.Errorf("the refusal must name the reason; got %q", err)
	}
}

// ── helpers ─────────────────────────────────────────────────────────────

// stubRuntime stands in for the Docker daemon: it hands back a pair of pipes
// in place of the hijacked connection, so the transport's framing, lifecycle
// and spec-building are exercised without a container.
type stubRuntime struct {
	spec    docker.MCPContainerSpec
	started bool
	in      io.Reader      // what the client wrote to the container's stdin
	out     io.WriteCloser // what the container writes to its stdout
}

func (s *stubRuntime) StartMCPContainer(
	_ context.Context, spec docker.MCPContainerSpec, _ io.Writer,
) (*docker.AttachedContainer, error) {
	// Build the real spec so a refusal in BuildMCPContainerSpec is still a
	// refusal here — the stub must not be a way past admission.
	if _, _, _, err := docker.BuildMCPContainerSpec(spec); err != nil {
		return nil, err
	}
	s.spec = spec
	s.started = true
	inR, inW := io.Pipe()
	outR, outW := io.Pipe()
	s.in, s.out = inR, outW
	return &docker.AttachedContainer{
		ID: "stub", Name: spec.Name, Stdout: outR, Stdin: inW,
	}, nil
}

// stubMCPServer answers the four calls the node makes, over the stub's pipes.
func stubMCPServer(t *testing.T, in io.Reader, out io.WriteCloser) {
	t.Helper()
	dec := json.NewDecoder(in)
	for {
		var req struct {
			ID     *int64 `json:"id"`
			Method string `json:"method"`
		}
		if err := dec.Decode(&req); err != nil {
			return
		}
		if req.ID == nil {
			continue // a notification
		}
		var result string
		switch req.Method {
		case "initialize":
			result = `{"protocolVersion":"2024-11-05","capabilities":{}}`
		case "tools/list":
			result = `{"tools":[{"name":"git_log","description":"log","inputSchema":{"type":"object"}}]}`
		default:
			result = `{}`
		}
		if _, err := out.Write([]byte(
			`{"jsonrpc":"2.0","id":` + strconv.FormatInt(*req.ID, 10) + `,"result":` + result + "}\n")); err != nil {
			return
		}
	}
}
