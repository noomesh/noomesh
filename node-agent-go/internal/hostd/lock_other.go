// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 PersonifAI LLC

//go:build !unix

package hostd

import "context"

// acquireComposeLock is a no-op on platforms without flock.
//
// noo-hostd targets Linux and macOS — the two places a Mesh controller runs
// (Windows is supported through WSL2, which is Linux). This file exists so
// `go build ./...` on a Windows developer machine still compiles the package,
// not because unlocked compose operations are acceptable there.
func acquireComposeLock(_ context.Context) (func(), error) {
	return func() {}, nil
}
