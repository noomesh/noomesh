// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 PersonifAI LLC

package docker

// THE declared home of the image registry namespace for node-agent-go. The
// shell twin is scripts/lib-dist.sh::release_image_namespace and the Rust twin
// is noo-cli/src/registry.rs::IMAGE_NAMESPACE; tests/test_image_namespace_*.py
// fail if the three disagree or a literal appears anywhere else.
//
// THE FLIP to the public org has happened: DefaultImagePrefix is
// `ghcr.io/noomesh`, and it is the only root the allow-list accepts: the move
// is a full replacement, the pre-move org is not recognised.

// DefaultImagePrefix is where release images are pulled from when
// NOO_IMAGE_PREFIX is unset. An operator-set prefix always wins. ABSENT env
// means this default; a set-but-blank env is treated as absent.
const DefaultImagePrefix = "ghcr.io/noomesh"

// managedRegistryRoots are the registry roots a controller-supplied image may
// live under (an entry ending in "/" matches any repository below it).
var managedRegistryRoots = []string{
	"ghcr.io/noomesh/",
}
