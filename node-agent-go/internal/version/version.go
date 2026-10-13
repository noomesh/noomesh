// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 PersonifAI LLC

// Package version exposes the node-agent build version so the controller
// can see which binary each node is actually running.
//
// Values are injected at build time via -ldflags:
//
//	-X github.com/noomesh/noomesh/node-agent-go/internal/version.Version=<v>
//	-X github.com/noomesh/noomesh/node-agent-go/internal/version.Commit=<sha>
//	-X github.com/noomesh/noomesh/node-agent-go/internal/version.BuildDate=<iso8601>
//
// Un-stamped local builds report "dev", which is itself a useful signal
// (a node reporting "dev" was not built through build-cross.sh / the image).
package version

import "strings"

// Injected via -ldflags -X at build time; defaults mark an un-stamped build.
var (
	Version   = "dev"
	Commit    = "unknown"
	BuildDate = "unknown"
)

// String renders the version for the app_version heartbeat field. When the
// repo is untagged, `git describe --always` already yields the short SHA, so
// Version and Commit coincide — append the commit only when it adds info
// (i.e. a tagged Version like "v1.2.3" → "v1.2.3+abc1234").
func String() string {
	if Commit != "" && Commit != "unknown" && !strings.Contains(Version, Commit) {
		return Version + "+" + Commit
	}
	return Version
}
