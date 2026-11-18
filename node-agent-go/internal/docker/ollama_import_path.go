// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 PersonifAI LLC

package docker

import (
	"context"
	"fmt"

	"github.com/moby/moby/client"
)

// ollamaImportHost decides where an Ollama import (a Modelfile model's
// `ollama create`, or a mirror install) goes on this node, and with it the
// rebuild #1291's verify-on-load runs after a mismatch.
//
// The rule is the heartbeat's own (agent.runningBackendsWithRuntime): where
// the managed noo-ollama container exists, that container IS this node's
// Ollama, so the import goes there and never to a host binary. A host
// `ollama` found on PATH beside it is a stray: importing through it writes
// the noo-agent user's ~/.ollama and the host daemon's store, neither of
// which the agent may write (proposal 61 phase 0b), and the model would land
// in an Ollama nothing serves from. The host binary is used only where no
// managed container exists, the case it was written for: a Mac, or a Linux
// node that runs Ollama natively.
//
// Only a definite "no such container" counts as absent. Any other answer
// from Docker (a timeout on a loaded node) is an error, never a guess that
// falls through to the host binary.
func (c *Client) ollamaImportHost(ctx context.Context) (bin string, host bool, err error) {
	if c != nil && c.docker != nil {
		_, ierr := c.docker.ContainerInspect(ctx, OllamaContainer, client.ContainerInspectOptions{})
		switch {
		case ierr == nil:
			return "", false, nil
		case !isGone(ierr):
			return "", false, fmt.Errorf(
				"cannot tell whether %s exists on this node (%v), so the import does not choose between it and a host ollama — retry when Docker answers",
				OllamaContainer, ierr)
		}
	}
	bin, host = ollamaBinary()
	return bin, host, nil
}

// ollamaImportVia names the path ollamaImportHost picks, for a refusal or a
// log line: the first heartbeat after a failed rebuild says which one failed.
func (c *Client) ollamaImportVia(ctx context.Context) string {
	bin, host, err := c.ollamaImportHost(ctx)
	switch {
	case err != nil:
		return "no path (" + err.Error() + ")"
	case host:
		return "the host binary " + bin
	default:
		return "the " + OllamaContainer + " container"
	}
}
