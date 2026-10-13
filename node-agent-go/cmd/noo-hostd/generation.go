// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 PersonifAI LLC

package main

import "fmt"

// hostdGenerationMarker is read out of a hostd-binary payload by
// scripts/noo-apply.sh: the applier refuses to replace an
// installed hostd with one carrying a LOWER generation, so a signed bundle
// cannot downgrade the root helper to a build with a retired lane. Bump the
// two digits when a hostd change must not be undone by a downgrade.
// `noo-hostd generation` prints it, which also keeps it in the binary.
const hostdGenerationMarker = "noo-hostd-generation=01;"

func cmdGeneration() error {
	fmt.Println(hostdGenerationMarker)
	return nil
}
