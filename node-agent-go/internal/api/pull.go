// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 PersonifAI LLC

// POST /pull — the artifact-pull verb.
//
// The controller (via the gateway proxy at /api/cluster/nodes/{id}/pull)
// asks this node to fetch an artifact from the controller's store and stage
// it: `image` fetches the digest-verified `docker save` tar for THIS node's
// architecture and `docker load`s it, `sandbox-base` builds the capability sandbox base
// locally, `ollama-model` fetches a converted weight with its Modelfile and
// runs `ollama create`. Synchronous on purpose — the caller is an operator
// command that wants the real outcome, not a fire-and-forget "starting".
//
// `binary` (stage an agent binary for the worker hostd to swap) is RETIRED by
// the design and refused below: its manifest was signed by the gateway's
// TLS key, so a compromised gateway could put code on every node as root.
// Agent binaries now arrive only in a signed bundle over the pull rail.
//
// Every kind names WHAT, never HOW: `sandbox-base` builds a Dockerfile embedded in this binary, `ollama-model`
// fetches its recipe from the controller's store rather than accepting one in
// the body. No kind takes content from the caller, which is what keeps this a
// pull verb and not a remote-execution endpoint.
package api

import (
	"encoding/json"
	"log/slog"
	"net/http"
)

// BinaryPullRetired is the refusal for the retired kind=binary.
const BinaryPullRetired = "kind=binary retired: agent binaries arrive only in a signed bundle " +
	"over the pull rail — `noo cluster provision <node> --wait`"

type pullReq struct {
	Kind  string `json:"kind"`
	Image string `json:"image"`
	// Binary name for the retired kind=binary — read only so the refusal
	// can name what was asked for.
	Binary string `json:"binary"`
	// The controller's local image ID — when set and it matches this
	// node's, the transfer is skipped ("up_to_date").
	ImageID string `json:"image_id"`
	// Force-remove this container after a successful load, so the next
	// backend start recreates it on the new image. The agent does NOT
	// bring it back itself — BackendManager/desired-state owns that.
	RemoveContainer string `json:"remove_container"`
	// Model name for kind=ollama-model. Names an artifact PAIR in the
	// controller's GGUF store (`<name>.Modelfile` and the weight its FROM
	// line points at) — never content, and never a path.
	Name string `json:"name"`
}

func (s *Server) handlePull(w http.ResponseWriter, r *http.Request) {
	var req pullReq
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"detail": "invalid request body"})
		return
	}
	if req.Kind == "binary" {
		// Retired. Refused loudly — a 410, logged — so an
		// old CLI's `noo cluster upgrade-agents` fails with the reason rather
		// than appearing to succeed or hanging on a swap that never comes.
		slog.Warn("pull refused: kind=binary is retired", "binary", req.Binary)
		writeJSON(w, http.StatusGone, map[string]string{"detail": BinaryPullRetired})
		return
	}
	if s.docker == nil {
		writeJSON(w, http.StatusServiceUnavailable, map[string]string{"detail": "Docker not available"})
		return
	}
	switch req.Kind {
	case "image":
		if req.Image == "" {
			writeJSON(w, http.StatusBadRequest, map[string]string{"detail": "image ref required"})
			return
		}
		res, err := s.docker.PullImageArtifact(r.Context(), req.Image, req.ImageID, req.RemoveContainer)
		if err != nil {
			writeJSON(w, http.StatusBadGateway, map[string]string{"detail": err.Error()})
			return
		}
		writeJSON(w, http.StatusOK, res)
	case "sandbox-base":
		// Takes NO caller-supplied content: the Dockerfile is embedded in
		// this binary. An arm64 node builds the capability sandbox base
		// itself because the upstream base is multi-arch — a build here is
		// cheaper and more honest than a cross-build on the controller.
		res, err := s.docker.BuildSandboxBase(r.Context())
		if err != nil {
			writeJSON(w, http.StatusBadGateway, map[string]string{"detail": err.Error()})
			return
		}
		writeJSON(w, http.StatusOK, res)
	case "ollama-model":
		// Name only. The Modelfile is a recipe the ollama daemon executes, so
		// accepting one in this body would make /pull a remote-execution
		// endpoint; the agent fetches it from the controller's store instead
		// and verifies its digest before ollama is told anything.
		if req.Name == "" {
			writeJSON(w, http.StatusBadRequest, map[string]string{"detail": "model name required"})
			return
		}
		res, err := s.docker.PullOllamaModel(r.Context(), req.Name)
		if err != nil {
			writeJSON(w, http.StatusBadGateway, map[string]string{"detail": err.Error()})
			return
		}
		writeJSON(w, http.StatusOK, res)
	default:
		writeJSON(w, http.StatusBadRequest, map[string]string{
			"detail": "unsupported pull kind '" + req.Kind + "' (kinds: image, sandbox-base, ollama-model; models preseed via placement)",
		})
	}
}
