// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 PersonifAI LLC

//go:build !linux

package hostd

import "io"

// IsAtRestRecoveryVerb mirrors the Linux build so dispatch is the same.
func IsAtRestRecoveryVerb(args []string) bool {
	return len(args) > 0 && (args[0] == "recovery-key" || args[0] == "reenroll")
}

// RunAtRestRecovery is Linux-only (LUKS2 with a systemd TPM enrollment).
func RunAtRestRecovery(_ []string, _, _ io.Writer) error {
	return errNotSupportedHere
}
