// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 PersonifAI LLC

// Package imagesource records WHERE each image this agent started a
// container from came from, so the controller can see a node that is not
// running on the rail.
//
// The design rule: the controller pulls every image with its
// own registry login and stages it as a digest-verified tar in its artifact
// store; a node pulls it from there over mTLS and never needs a registry
// credential. Every image start path goes through docker.EnsureImage, which
// reports here, and the heartbeat carries the result as
//
//	"image_sources": [{"image": "...", "source": "...", "image_id": "..."}]
//
// where source is one of:
//
//   - rail: loaded from the controller's store this start, or already
//     present at exactly the image ID the controller's manifest names;
//   - local: present locally, but nothing on the controller vouches for it
//     (not staged, an older gateway, or the controller unreachable);
//   - registry: pulled from a public registry under the third-party
//     fallback policy (NOO_IMAGE_REGISTRY_FALLBACK).
//
// `noo cluster verify` WARNs on any image that is not `rail`.
//
// A package-level singleton for the same reason sidecarimage is one: the
// producer (the docker client, at container start) and the consumer (the
// heartbeat) are wired at different points in agent startup.
package imagesource

import (
	"log/slog"
	"os"
	"sort"
	"strings"
	"sync"
)

// The values of an entry's `source`.
const (
	Rail     = "rail"
	Local    = "local"
	Registry = "registry"
)

// Entry is one image's provenance, as the heartbeat carries it.
type Entry struct {
	Image   string `json:"image"`
	Source  string `json:"source"`
	ImageID string `json:"image_id,omitempty"`
}

// Tracker holds the latest provenance per image ref.
type Tracker struct {
	mu   sync.Mutex
	byID map[string]Entry
}

var defaultTracker = &Tracker{}

// Record notes that a container was just started from image, obtained via
// source. The latest record for a ref wins: a ref that came from a registry
// once and from the rail since is reported as rail.
func Record(image, source, imageID string) { defaultTracker.Record(image, source, imageID) }

// Report is the heartbeat's `image_sources`: nil when this process has
// started nothing yet (the key is then omitted).
func Report() []Entry { return defaultTracker.Report() }

// Reset clears the default tracker. Tests only.
func Reset() {
	defaultTracker.mu.Lock()
	defaultTracker.byID = nil
	defaultTracker.mu.Unlock()
}

func (t *Tracker) Record(image, source, imageID string) {
	if image == "" || source == "" {
		return
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	if t.byID == nil {
		t.byID = map[string]Entry{}
	}
	t.byID[image] = Entry{Image: image, Source: source, ImageID: imageID}
}

func (t *Tracker) Report() []Entry {
	t.mu.Lock()
	defer t.mu.Unlock()
	if len(t.byID) == 0 {
		return nil
	}
	out := make([]Entry, 0, len(t.byID))
	for _, e := range t.byID {
		out = append(out, e)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Image < out[j].Image })
	return out
}

// ModeEnv is the per-node switch: NOO_IMAGE_SOURCE=legacy opts a node out
// of the rail (the default).
const ModeEnv = "NOO_IMAGE_SOURCE"

// The two modes.
const (
	ModeRail   = "rail"
	ModeLegacy = "legacy"
)

// Mode is the node's image-source mode: "legacy" (the pre-rail behaviour)
// only when ModeEnv says so, case-insensitively; "rail" otherwise. The rail
// is the default, and a typo fails closed toward it: the controller is the
// one place images come from, so an unrecognised value must not quietly
// turn the node into a registry puller.
func Mode() string {
	if strings.EqualFold(strings.TrimSpace(os.Getenv(ModeEnv)), ModeLegacy) {
		return ModeLegacy
	}
	return ModeRail
}

// The values of ModeSource.
const (
	ModeSourceEnv     = "env"
	ModeSourceDefault = "default"
)

// ModeSource says where Mode came from: "env" when ModeEnv holds a
// recognised value (rail or legacy), "default" when it is unset, empty or
// unrecognised. The controller needs it to tell a node that chose legacy
// (an escape hatch) from one that merely has not rolled yet.
func ModeSource() string {
	switch strings.ToLower(strings.TrimSpace(os.Getenv(ModeEnv))) {
	case ModeRail, ModeLegacy:
		return ModeSourceEnv
	}
	return ModeSourceDefault
}

// LogMode logs, once at startup, an explicit legacy choice (the escape
// hatch is worth seeing in the log) and an unrecognised value (which means
// rail).
func LogMode() {
	raw := strings.TrimSpace(os.Getenv(ModeEnv))
	switch {
	case raw == "":
	case strings.EqualFold(raw, ModeLegacy):
		slog.Warn("image source is legacy: images come from the node's own registry pulls, not the controller's rail",
			"switch", ModeEnv, "remedy", "remove "+ModeEnv+"=legacy from /etc/noo-node-agent.env and restart the agent")
	case strings.EqualFold(raw, ModeRail):
	default:
		slog.Warn("unrecognised image source value; using rail", "switch", ModeEnv, "value", raw)
	}
}
