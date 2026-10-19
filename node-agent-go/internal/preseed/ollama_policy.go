// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 PersonifAI LLC

package preseed

import (
	"fmt"
	"os"
)

// OllamaRegistryPullEnv is the explicit, per-node opt-in to pull an ollama
// tag straight from registry.ollama.ai on a placed node.
const OllamaRegistryPullEnv = "NOO_ALLOW_OLLAMA_REGISTRY_PULL"

// OllamaRegistryPullAllowed: a PLACED node (NOO_MODEL_CACHE_URL set) takes its
// weights from the controller's store, never from the internet. The controller
// stages an ollama registry tag into that store (`noo models fetch ollama:<tag>`:
// it pulls the manifest and blobs, checks each against the digest the manifest
// carries, and the node imports the staged pair like any other store model), so
// a tag reaches a placed node that way. A tag the controller has not staged
// cannot be delivered, and is refused with the remedy instead of quietly
// reaching registry.ollama.ai. The operator can accept the exception per node
// with NOO_ALLOW_OLLAMA_REGISTRY_PULL=1.
func OllamaRegistryPullAllowed(name string) error {
	if !Placed() || os.Getenv(OllamaRegistryPullEnv) == "1" {
		return nil
	}
	return fmt.Errorf("ollama_registry_pull_refused: %s is an ollama registry tag the controller's store does not hold (or could not be asked about), and a placed node takes models only from the controller's store, "+
		"never from registry.ollama.ai. Stage it on the controller (`noo models fetch ollama:%s`; this node imports it from the store on its next reconcile), "+
		"or put a GGUF there (`noo models fetch <hf_repo> <file.gguf>`) and place the file name; or accept the exception on this node with %s=1 in its node-agent environment", name, name, OllamaRegistryPullEnv)
}
