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
// store carries GGUF files (`noo models fetch`), which the node imports with
// `import-model` from the rail; it does not carry ollama registry blobs, so a
// bare registry tag cannot be delivered that way and is refused with the
// remedy instead of quietly reaching registry.ollama.ai. The operator can
// accept the exception per node with NOO_ALLOW_OLLAMA_REGISTRY_PULL=1.
func OllamaRegistryPullAllowed(name string) error {
	if !Placed() || os.Getenv(OllamaRegistryPullEnv) == "1" {
		return nil
	}
	return fmt.Errorf("ollama_registry_pull_refused: %s is an ollama registry tag, and a placed node takes models only from the controller's store, "+
		"never from registry.ollama.ai. Put the model on the controller as a GGUF (`noo models fetch <hf_repo> <file.gguf>`) and place the file name "+
		"(the node imports it from the store); or accept the exception on this node with %s=1 in its node-agent environment", name, OllamaRegistryPullEnv)
}
