// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 PersonifAI LLC

package reconcile

import (
	"fmt"

	dockerpkg "github.com/noomesh/noomesh/node-agent-go/internal/docker"
	"github.com/noomesh/noomesh/node-agent-go/internal/nodewl"
	"github.com/noomesh/noomesh/node-agent-go/internal/refusals"
)

// minComputeCap is the node's lowest GPU compute capability probe (the one
// the heartbeat's gpu_compute_cap reports), or nil when the reconciler was
// built without facts (tests).
func (r *Reconciler) minComputeCap() func() (string, error) {
	if r.facts == nil {
		return nil
	}
	return r.facts.MinComputeCap
}

// vllmComputeRefusal says why the pinned vLLM cannot start on this node's GPU
// (dockerpkg.VllmMinComputeCap), or "" when it can, or the backend is not
// vLLM. A refusal rests on a KNOWN fact: only a compute capability known to
// be below the floor refuses here. An unknown one (this agent's own probe
// failing, no nvidia-smi answer) starts as asked; the gateway warned at place
// time and the `vllm compute` verify row warns while it stays unknown.
func vllmComputeRefusal(backend string, minCap func() (string, error)) string {
	if (backend != "vllm" && backend != "vllm-secondary") || minCap == nil {
		return ""
	}
	have, err := minCap()
	if err != nil {
		return ""
	}
	ok, err := nodewl.ComputeCapAtLeast(have, dockerpkg.VllmMinComputeCap)
	if err != nil || ok {
		return ""
	}
	return fmt.Sprintf("vllm_compute_low: vLLM %s is built on CUDA %s, which needs GPU compute capability %s+; this node's GPU is compute %s. "+
		"Unplace it (noo cluster unplace <node> %s) and place the model on ollama or llamacpp",
		dockerpkg.VllmImageTag, dockerpkg.VllmImageCUDA, dockerpkg.VllmMinComputeCap, have, backend)
}

// clearUnplacedVllmRefusals drops the start refusal of each vLLM backend that
// no placement wants running any more: nothing is being refused once it is
// unplaced (or stopped).
func clearUnplacedVllmRefusals(ps []placement) {
	for _, b := range []string{"vllm", "vllm-secondary"} {
		wanted := false
		for _, p := range ps {
			if p.Backend == b && p.DesiredState == "running" {
				wanted = true
			}
		}
		if !wanted {
			refusals.Clear("backend_start", b)
		}
	}
}
