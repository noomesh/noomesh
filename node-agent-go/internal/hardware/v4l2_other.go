// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 PersonifAI LLC

//go:build !linux

package hardware

// v4l2Info is the non-Linux stub. The node-agent only ever runs on Linux;
// this exists so `go build`/`go vet` stay clean on a developer's macOS box.
type v4l2Info struct {
	Driver  string
	Caps    uint32
	Queried bool
}

func (v v4l2Info) IsCaptureCapable() bool { return false }

func queryV4L2(string) v4l2Info { return v4l2Info{} }
