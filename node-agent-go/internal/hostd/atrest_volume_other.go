// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 PersonifAI LLC

//go:build !linux

package hostd

import (
	"errors"
	"io"
)

// IsAtRestVolumeVerb mirrors the Linux build so main dispatches the same way.
func IsAtRestVolumeVerb(args []string) bool {
	return len(args) > 0 && (args[0] == "create-volume" || args[0] == "copy" || args[0] == "wipe")
}

// RunAtRestVolume is Linux-only: the encrypted state volume is LUKS2 with a
// systemd TPM enrollment (i10a — Linux controllers only; Mac, WSL2 and worker
// nodes report "not supported here").
func RunAtRestVolume(_ []string, _, _ io.Writer) error {
	return errors.New("at-rest: not supported here (the encrypted state volume needs a Linux controller with systemd and a TPM)")
}
