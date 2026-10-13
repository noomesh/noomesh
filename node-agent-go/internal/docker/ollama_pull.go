// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 PersonifAI LLC

package docker

import (
	"bytes"
	"context"
	"fmt"
	"regexp"
	"strings"
	"time"

	"github.com/moby/moby/api/pkg/stdcopy"
	"github.com/moby/moby/client"
)

// An ollama placement names a REGISTRY tag (`gemma4:12b`), and until
// 2026-09-11 nothing on the node fetched it: StartBackend set OLLAMA_MODEL
// on the container, RunningBackends read that env back, the placement
// reported converged — and the first request 404'd because the model was
// never pulled. `import-model` covers GGUFs published through the
// controller store; this is the other, far more common shape: a tag ollama
// itself can pull. The reconciler calls these once the container is up.

// ollamaTagPattern bounds what reaches `ollama pull` as an argument: a
// registry ref (optional host/namespace, name, optional tag). No shell is
// involved — exec takes an argv — but a name that is not a ref is a
// misconfiguration worth refusing with a clear message.
var ollamaTagPattern = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]*(/[A-Za-z0-9][A-Za-z0-9._-]*)*(:[A-Za-z0-9][A-Za-z0-9._-]*)?$`)

// OllamaHasModel reports whether the ollama container already holds `name`.
func (c *Client) OllamaHasModel(ctx context.Context, name string) (bool, error) {
	if c == nil || c.docker == nil {
		return false, fmt.Errorf("Docker not available")
	}
	if !ollamaTagPattern.MatchString(name) {
		return false, fmt.Errorf("model %q is not an ollama registry ref", name)
	}
	if !c.isRunning(ctx, OllamaContainer) {
		return false, fmt.Errorf("%s is not running", OllamaContainer)
	}
	out, err := c.execCapture(ctx, OllamaContainer, []string{"ollama", "list"}, 30*time.Second)
	if err != nil {
		return false, err
	}
	return ollamaListHas(out, name), nil
}

// OllamaPull fetches `name` into the ollama container from its registry.
// Blocking: a multi-GB pull can take many minutes, so the caller runs it
// off the reconcile tick.
func (c *Client) OllamaPull(ctx context.Context, name string) (string, error) {
	if c == nil || c.docker == nil {
		return "", fmt.Errorf("Docker not available")
	}
	if !ollamaTagPattern.MatchString(name) {
		return "", fmt.Errorf("model %q is not an ollama registry ref", name)
	}
	if !c.isRunning(ctx, OllamaContainer) {
		return "", fmt.Errorf("%s is not running", OllamaContainer)
	}
	return c.execCapture(ctx, OllamaContainer, []string{"ollama", "pull", name}, 2*time.Hour)
}

// ollamaListHas matches a placement's model against `ollama list` output.
// The list prints every model with an explicit tag, so a bare name
// (`harrier`, how `import-model` places it) matches its `:latest`.
func ollamaListHas(listOutput, name string) bool {
	want := name
	if !strings.Contains(want, ":") {
		want += ":latest"
	}
	for i, line := range strings.Split(listOutput, "\n") {
		fields := strings.Fields(line)
		if len(fields) == 0 || (i == 0 && fields[0] == "NAME") {
			continue
		}
		if fields[0] == want {
			return true
		}
	}
	return false
}

// execCapture runs argv in a container and returns its combined output,
// failing on a non-zero exit. The same exec/attach/inspect sequence
// ollamaCreateInContainer uses, without the copy step.
func (c *Client) execCapture(ctx context.Context, container string, cmd []string, timeout time.Duration) (string, error) {
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	// No TTY: `ollama pull`/`ollama list` print plain progress lines when
	// stdout isn't a terminal, whereas a TTY makes ollama's CLI (it decides
	// this per exec, not per docker) emit cursor-control and terminal-query
	// escape sequences that otherwise land verbatim in the journal via
	// reconcile.ollama_pull_done. Without a TTY the stream is Docker's
	// multiplexed stdout/stderr framing, so it needs stdcopy to demux
	// instead of a raw read.
	created, err := c.docker.ExecCreate(ctx, container, client.ExecCreateOptions{
		Cmd:          cmd,
		AttachStdout: true,
		AttachStderr: true,
		TTY:          false,
	})
	if err != nil {
		return "", fmt.Errorf("exec create: %w", err)
	}
	att, err := c.docker.ExecAttach(ctx, created.ID, client.ExecAttachOptions{TTY: false})
	if err != nil {
		return "", fmt.Errorf("exec attach: %w", err)
	}
	var stdout, stderr bytes.Buffer
	_, _ = stdcopy.StdCopy(&stdout, &stderr, att.Reader)
	att.Close()
	raw := stdout.String()
	if stderr.Len() > 0 {
		if raw != "" {
			raw += "\n"
		}
		raw += stderr.String()
	}
	out := strings.TrimSpace(raw)
	ins, err := c.docker.ExecInspect(ctx, created.ID, client.ExecInspectOptions{})
	if err != nil {
		return out, fmt.Errorf("exec inspect: %w", err)
	}
	if ins.ExitCode != 0 {
		return out, fmt.Errorf("%s exited %d in %s: %s", strings.Join(cmd, " "), ins.ExitCode, container, lastLine(out))
	}
	return out, nil
}
