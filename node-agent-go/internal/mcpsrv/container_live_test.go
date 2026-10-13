// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 PersonifAI LLC

package mcpsrv

// The stdio round trip against a REAL container.
//
// Gated behind NOO_DOCKER_SMOKE=1, the same gate
// `docker.TestLiveDockerSmoke` uses and for the same reason: a CI runner or a
// developer box may expose no usable daemon socket, and a test that needs one
// must not be the thing that decides whether `go test ./...` passes. The unit
// tests next door cover the spec builder, the refusals and the framing; this
// one covers what only a daemon can answer — that ContainerCreate with
// OpenStdin + ContainerAttach really produces a duplex stream, and that
// stdcopy really separates the JSON-RPC frames from the server's stderr.
//
// Run:
//
//	NOO_DOCKER_SMOKE=1 go test -v -run TestLiveMCPContainerRoundTrip ./internal/mcpsrv/

import (
	"context"

	"os"
	"strings"
	"testing"
	"time"

	"github.com/noomesh/noomesh/node-agent-go/internal/docker"
)

// liveSmokeImage is a plain busybox/alpine, used as a stand-in MCP server: the
// container's job here is to speak enough JSON-RPC to answer `initialize` and
// `tools/list`, which `sh` can do from a here-doc. A purpose-built stub image
// would prove less, not more — the point is that an ORDINARY image works.
const liveSmokeImage = "alpine:latest"

func TestLiveMCPContainerRoundTrip(t *testing.T) {
	if os.Getenv("NOO_DOCKER_SMOKE") != "1" {
		t.Skip("set NOO_DOCKER_SMOKE=1 to run against the local Docker daemon")
	}
	// The image is not in the shipped allow-list, and it should not be: this
	// is the node-local widening an operator would make for a real server.
	t.Setenv(docker.ManagedImageAllowEnv, "alpine")

	c, err := docker.NewClient(nil, "http", "", false)
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}
	defer c.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()

	// Reads one request per line, answers it, and writes a line to STDERR on
	// the way in — so the demultiplexing is exercised, not assumed: if stderr
	// leaked into the stdout stream the JSON-RPC reader would see it.
	const server = `
while IFS= read -r line; do
  echo "stderr: saw a request" >&2
  case "$line" in
    *'"tools/list"'*) echo "$line" | sed 's/.*"id":\([0-9]*\).*/{"jsonrpc":"2.0","id":\1,"result":{"tools":[{"name":"echo","description":"d","inputSchema":{"type":"object"}}]}}/' ;;
    *'"id"'*)         echo "$line" | sed 's/.*"id":\([0-9]*\).*/{"jsonrpc":"2.0","id":\1,"result":{}}/' ;;
  esac
done
`

	// BinaryMount would bind /bin/sh from the HOST over the image's own, which
	// is right for an operator-declared binary and wrong for this test, whose
	// "server" is a shell script the image already has. startContainer always
	// sets it, so drive the runtime directly here.
	cfgSpec := docker.MCPContainerSpec{
		Name:    "noo-mcp-smoke",
		Image:   liveSmokeImage,
		Command: []string{"/bin/sh", "-c", server},
	}
	tail := &bufio_tail{}
	att, err := c.StartMCPContainer(ctx, cfgSpec, tail)
	if err != nil {
		t.Fatalf("StartMCPContainer: %v", err)
	}
	defer att.Close()

	client := &containerClient{
		pipeClient: newPipeClient(att.Stdout, att.Stdin), att: att, stderr: tail,
	}
	tools, err := client.ListTools(ctx)
	if err != nil {
		t.Fatalf("ListTools over the attached stream: %v (stderr: %s)", err, tail.String())
	}
	if len(tools) != 1 || tools[0].Name != "echo" {
		t.Fatalf("tools = %+v", tools)
	}
	// stderr must have gone to the sink, NOT into the JSON-RPC stream.
	if !strings.Contains(tail.String(), "saw a request") {
		t.Errorf("the container's stderr must reach the tail buffer; got %q", tail.String())
	}
}
