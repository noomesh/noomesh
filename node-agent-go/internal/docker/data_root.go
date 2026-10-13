// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 PersonifAI LLC

package docker

import (
	"os"
	"strings"

	"github.com/noomesh/noomesh/node-agent-go/internal/dataroots"
)

// The bind sources every backend spec derives from the data root. An explicit
// child (HF_CACHE_DIR, MODELS_DIR, OLLAMA_DATA_DIR) wins; otherwise it is a
// child of NOO_DATA_ROOT, falling back to dataroots.DefaultDataRoot — one
// definition, not a literal per spec.
var (
	dataRootSource = "${NOO_DATA_ROOT:-" + dataroots.DefaultDataRoot + "}"
	hfCacheSource  = "${HF_CACHE_DIR:-" + dataRootSource + "/hf-cache}"
	modelsSource   = "${MODELS_DIR:-" + dataRootSource + "/models}"
	ollamaSource   = "${OLLAMA_DATA_DIR:-" + dataRootSource + "/ollama}"
)

// dataRootHint explains a missing bind source that came from the default
// root rather than one the operator chose: the fix is to choose one.
func dataRootHint(source string) string {
	if strings.TrimSpace(os.Getenv("NOO_DATA_ROOT")) != "" ||
		!strings.HasPrefix(source, dataroots.DefaultDataRoot+"/") {
		return ""
	}
	return "; NOO_DATA_ROOT is unset on this node, so the default " + dataroots.DefaultDataRoot +
		" was used — set the node's data root with `noo cluster set-config <node> --data-root <path>`"
}
