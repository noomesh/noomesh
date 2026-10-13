// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 PersonifAI LLC

// Package sidecarimage records which image this node's stunnel sidecars
// (the backend doors, internal/docker/sidecar.go) run on, so the controller
// can see a node that is on the alpine + `apk add` fallback.
//
// The fallback exists for nodes whose release predates the published
// multi-arch `stunnel` image (#552): with no built image reachable, the
// sidecar runs plain alpine and installs stunnel from the alpine mirror at
// EVERY start. That works, and it is also a door whose start depends on a
// third-party mirror being up. It is not a refusal (the backend starts), so
// it does not go through internal/refusals; it goes on the heartbeat as
//
//	"stunnel_image": "published" | "fallback-alpine"
//
// — the image the most recent sidecar start chose. Absent when this agent
// process has started no sidecar yet (nothing chosen, nothing to say), and
// from an agent too old to report. `noo cluster verify <node>` WARNs on
// "fallback-alpine". The fallback is removed once every node runs a
// release carrying the published image.
//
// Package-level singleton for the same reason refusals is: the producer
// (the docker client, at backend start) and the consumer (the heartbeat)
// are wired at different points in agent startup.
package sidecarimage

import (
	"log/slog"
	"strings"
	"sync"
)

// The two values of the heartbeat's `stunnel_image`.
const (
	Published      = "published"
	FallbackAlpine = "fallback-alpine"
)

// Tracker holds the last choice and warns once per process about the
// fallback.
type Tracker struct {
	mu     sync.Mutex
	state  string
	warned sync.Once
	// log is the logger the one-time WARN goes to; nil = slog.Default().
	log *slog.Logger
}

var defaultTracker = &Tracker{}

// Chose records the image a sidecar start chose. fallback is true when it
// is the alpine + apk image; missing names the published image(s) that
// were tried first and not reachable (with their errors).
func Chose(image string, fallback bool, missing []string) {
	defaultTracker.Chose(image, fallback, missing)
}

// Report is the heartbeat's `stunnel_image`: "" when no sidecar image has
// been chosen by this process (the key is then omitted).
func Report() string { return defaultTracker.Report() }

// Chose records a choice on t. The fallback WARN is logged at most once per
// Tracker (per agent process for the default one): every backend start on
// a fallback node takes this path, and the operator needs to hear it once,
// not per start — the heartbeat field is the standing record.
func (t *Tracker) Chose(image string, fallback bool, missing []string) {
	t.mu.Lock()
	if fallback {
		t.state = FallbackAlpine
	} else {
		t.state = Published
	}
	t.mu.Unlock()
	if !fallback {
		return
	}
	t.warned.Do(func() {
		log := t.log
		if log == nil {
			log = slog.Default()
		}
		missingText := strings.Join(missing, "; ")
		if missingText == "" {
			missingText = "none tried"
		}
		log.Warn("sidecar: the published stunnel image is missing on this node; backend doors run on "+image+
			" and install stunnel from the alpine mirror at EVERY sidecar start (a door start now depends on that mirror). "+
			"Upgrade the node to a release carrying the published stunnel image, or set STUNNEL_IMAGE",
			"image", image, "missing", missingText, "heartbeat", "stunnel_image="+FallbackAlpine)
	})
}

// Report returns t's current value ("" when nothing chosen yet).
func (t *Tracker) Report() string {
	t.mu.Lock()
	defer t.mu.Unlock()
	return t.state
}
