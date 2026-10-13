// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 PersonifAI LLC

package jobs

import (
	"context"
	"fmt"
)

// executeModelFile pulls one flat GGUF from the controller's model store.
//
// The job that replaced `noo cluster sync-model-files`, which scp'd weights
// over SSH. Weights are the one payload the bundle rail cannot carry — a
// CMS-encrypted spool blob is for small signed payloads, not 15 GB — so they
// ride the artifact data plane instead, with the gateway's manifest stating
// the digest the bytes must have.
//
// Unlike `model_download`, which pulls a docker PROFILE (an image), this
// fetches a FILE. The two were easy to confuse and are not the same thing.
//
// Idempotent: a file already present with the right digest returns
// `up_to_date` without transferring anything, so dispatching this to a whole
// fleet costs one hash per node that already has it.
func (e *Executor) executeModelFile(ctx context.Context, payload map[string]any) (any, error) {
	name, _ := payload["model"].(string)
	if name == "" {
		return nil, fmt.Errorf("model_file: no `model` in payload")
	}
	if e.docker == nil {
		return nil, fmt.Errorf("model_file: no docker client on this agent")
	}
	return e.docker.PullModelArtifact(ctx, name)
}
