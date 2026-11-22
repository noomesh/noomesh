// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 PersonifAI LLC

package docker

import (
	"context"
	"fmt"
	"log/slog"
	"strings"
	"time"

	"github.com/moby/moby/client"
)

// The TEI (text-embeddings-inference) engine was removed from core in 0.6.30
// (i1182a). A node upgraded from an older release can still run what that
// agent created: noo-tei / noo-tei-gpu behind noo-stunnel-tei[-gpu], or a
// noo-reranker on the TEI image. With the specs gone the reconciler can no
// longer see them (backendKeyFromName maps no name to them), so nothing would
// stop them: a surviving noo-tei keeps answering /embed with vectors from a
// model nobody placed. RemoveRetiredTEI is the one place that does.

// managedByAgent is the label value this agent stamps on every container it
// creates (backends, doors, helpers). A container without it is not ours.
const managedByAgent = "node-agent-go"

// retiredTEINames are the container names the old agent gave the TEI backend
// and its door, matched EXACTLY (not by substring: a user's own container
// named like noo-tei-proxy is not ours to remove).
var retiredTEINames = map[string]bool{
	"noo-tei":             true,
	"noo-tei-gpu":         true,
	"noo-stunnel-tei":     true,
	"noo-stunnel-tei-gpu": true,
}

// teiImageMarker is in the image ref of every TEI image.
const teiImageMarker = "text-embeddings-inference"

// RetiredTEI is one container RemoveRetiredTEI removed.
type RetiredTEI struct {
	Name string
	// Reranker is true for the noo-reranker that ran the TEI image (its
	// replacement is a GGUF reranker, not an Ollama embedder).
	Reranker bool
}

// RemoveRetiredTEI stops and removes the TEI containers THIS agent created:
// the container is named exactly noo-tei, noo-tei-gpu, noo-stunnel-tei or
// noo-stunnel-tei-gpu, or is the noo-reranker running a TEI image, AND
// carries the agent's own label noo.managed-by=node-agent-go. A container of
// that name without the label (compose-run, or someone else's) is left alone.
// A noo-reranker on the llama.cpp image is never touched here (the reconciler
// owns it). The reranker's door (noo-stunnel-reranker) is shared with the
// llama.cpp engine and is left to the reconciler too.
//
// Stopped containers are included: an exited orphan would come back with its
// restart policy. Returns what it removed. A list error is an error (nothing
// is removed on a guess); one container failing to remove is logged and the
// rest still go.
func (c *Client) RemoveRetiredTEI(ctx context.Context) ([]RetiredTEI, error) {
	ctx, cancel := context.WithTimeout(ctx, time.Minute)
	defer cancel()

	containers, err := c.listContainers(ctx, client.ContainerListOptions{All: true})
	if err != nil {
		return nil, fmt.Errorf("listing containers: %w", err)
	}
	var removed []RetiredTEI
	for _, ctr := range containers {
		if len(ctr.Names) == 0 || ctr.Labels["noo.managed-by"] != managedByAgent {
			continue
		}
		name := strings.TrimPrefix(ctr.Names[0], "/")
		reranker := name == "noo-reranker" && strings.Contains(ctr.Image, teiImageMarker)
		if !retiredTEINames[name] && !reranker {
			continue
		}
		timeout := 10
		if _, err := c.docker.ContainerStop(ctx, ctr.ID, client.ContainerStopOptions{Timeout: &timeout}); err != nil {
			slog.Debug("retired TEI: stop note", "container", name, "error", err)
		}
		if _, err := c.docker.ContainerRemove(ctx, ctr.ID, client.ContainerRemoveOptions{Force: true}); err != nil {
			slog.Warn("retired TEI: remove failed", "container", name, "error", err)
			continue
		}
		removed = append(removed, RetiredTEI{Name: name, Reranker: reranker})
	}
	return removed, nil
}
