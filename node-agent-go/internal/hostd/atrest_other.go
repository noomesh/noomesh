// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 PersonifAI LLC

//go:build !linux

package hostd

import (
	"errors"
	"io"
)

// RunAtRest is Linux-only: sealing to the TPM uses systemd-creds and a
// systemd unit (i10a — controllers on Linux only; Mac, WSL2 and worker
// nodes report "not supported here").
func RunAtRest(_ []string, _, _ io.Writer) error {
	return errors.New("at-rest: not supported here (TPM sealing needs a Linux controller with systemd)")
}
