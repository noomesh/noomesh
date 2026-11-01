// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 PersonifAI LLC

package docker

import (
	"archive/tar"
	"compress/gzip"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"github.com/distribution/reference"
)

// normalizeRef is the full reference Docker itself resolves a ref to:
// "ollama/ollama:latest" → "docker.io/ollama/ollama:latest", "alpine" →
// "docker.io/library/alpine:latest". A ref Docker cannot parse comes back
// unchanged.
func normalizeRef(ref string) string {
	n, err := reference.ParseNormalizedNamed(strings.TrimSpace(ref))
	if err != nil {
		return ref
	}
	return reference.TagNameOnly(n).String()
}

// normalizeName is normalizeRef without the tag or digest:
// "noo-sandbox-base:latest" → "docker.io/library/noo-sandbox-base".
func normalizeName(ref string) string {
	n, err := reference.ParseNormalizedNamed(strings.TrimSpace(ref))
	if err != nil {
		return strings.TrimSpace(ref)
	}
	return n.Name()
}

// localBuildNamespaces are images that exist in no registry — the
// controller builds them — written as the normalised names Docker gives
// them. The Rust twins (noo-cli image_stage.rs, gateway artifacts.rs) hold
// the same list, and all three read tests/fixtures/own_image_cases.json.
var localBuildNamespaces = []string{"docker.io/noomesh/", "docker.io/pai-assistant/", "docker.io/library/noo-"}

// isOwnImageWith is THE ownership rule, shared with Rust: after
// normalising, a ref is ours if its name sits under one of `roots`
// (registry namespaces, e.g. the managed roots and NOO_IMAGE_PREFIX) or
// under a local-build namespace. An unparsable ref counts as ours —
// fail closed to rail-only.
func isOwnImageWith(ref string, roots []string) bool {
	if _, err := reference.ParseNormalizedNamed(strings.TrimSpace(ref)); err != nil {
		return true
	}
	name := normalizeName(ref)
	for _, r := range roots {
		r = strings.TrimRight(strings.TrimSpace(r), "/")
		if r == "" {
			continue
		}
		if strings.HasPrefix(name, normalizeName(r)+"/") {
			return true
		}
	}
	for _, p := range localBuildNamespaces {
		if strings.HasPrefix(name, p) {
			return true
		}
	}
	return false
}

// checkTarManifest reads a `docker save` archive's manifest.json and/or
// index.json BEFORE it is loaded and refuses an archive that holds more than
// one image, or tags anything other than ref. An untagged archive (saved by
// ID) is fine — finishLoad tags it.
//
// A staged `.tar.gz` is read through compress/gzip. Whether the file is
// gzip is decided by BOTH its name and its magic bytes (1f 8b): a mismatch
// either way (a `.tar.gz` that is not gzip, a `.tar` that is) is a loud
// verification error naming the mismatch rather than a confusing tar error.
// The raw file, not the inflated stream, is what `docker load` is given.
func checkTarManifest(path, ref string) error {
	f, err := os.Open(path)
	if err != nil {
		return fmt.Errorf("open staged tar: %w", err)
	}
	defer f.Close()
	var magic [2]byte
	n, _ := io.ReadFull(f, magic[:])
	isGz := n == 2 && magic[0] == 0x1f && magic[1] == 0x8b
	namedGz := strings.HasSuffix(path, ".gz")
	if namedGz != isGz {
		if namedGz {
			return fmt.Errorf("%s is named .gz but is not gzip data (mislabeled export)", filepath.Base(path))
		}
		return fmt.Errorf("%s is gzip data but is not named .gz (mislabeled export)", filepath.Base(path))
	}
	if _, err := f.Seek(0, io.SeekStart); err != nil {
		return fmt.Errorf("read staged tar: %w", err)
	}
	if !isGz {
		return checkTarManifestReader(f, ref)
	}
	zr, err := gzip.NewReader(f)
	if err != nil {
		return fmt.Errorf("read staged gzip: %w", err)
	}
	defer zr.Close()
	return checkTarManifestReader(zr, ref)
}

func checkTarManifestReader(r io.Reader, ref string) error {
	var manifestJSON, indexJSON []byte
	tr := tar.NewReader(r)
	for {
		h, err := tr.Next()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return fmt.Errorf("read image archive: %w", err)
		}
		switch strings.TrimPrefix(h.Name, "./") {
		case "manifest.json":
			manifestJSON, err = io.ReadAll(io.LimitReader(tr, 1<<20))
		case "index.json":
			indexJSON, err = io.ReadAll(io.LimitReader(tr, 1<<20))
		}
		if err != nil {
			return fmt.Errorf("read image archive: %w", err)
		}
	}
	if manifestJSON == nil && indexJSON == nil {
		return errors.New("not an image archive: no manifest.json or index.json")
	}
	want := normalizeRef(ref)
	if manifestJSON != nil {
		var m []struct {
			RepoTags []string `json:"RepoTags"`
		}
		if err := json.Unmarshal(manifestJSON, &m); err != nil {
			return fmt.Errorf("unreadable manifest.json: %w", err)
		}
		if len(m) != 1 {
			return fmt.Errorf("the archive holds %d images; a staged tar must hold exactly one", len(m))
		}
		for _, t := range m[0].RepoTags {
			if normalizeRef(t) != want {
				return fmt.Errorf("the archive tags %q, not the requested %s — loading it would re-point that tag on this node", t, ref)
			}
		}
	}
	if indexJSON != nil {
		var idx struct {
			Manifests []ociIndexEntry `json:"manifests"`
		}
		if err := json.Unmarshal(indexJSON, &idx); err != nil {
			return fmt.Errorf("unreadable index.json: %w", err)
		}
		images := 0
		for _, m := range idx.Manifests {
			// Every entry, attestation or not: a name here is a tag
			// `docker load` would set, so it must be the requested ref.
			if name := m.Annotations["io.containerd.image.name"]; name != "" && normalizeRef(name) != want {
				return fmt.Errorf("the archive names %q, not the requested %s", name, ref)
			}
			if m.isAttestation() {
				if m.Annotations["io.containerd.image.name"] != "" {
					return errors.New("the archive's attestation entry carries an image name; loading it would tag it")
				}
				continue
			}
			images++
		}
		if images != 1 {
			return fmt.Errorf("the archive index lists %d images; a staged tar must hold exactly one", images)
		}
	}
	return nil
}

// ociIndexEntry is one row of an image archive's index.json.
type ociIndexEntry struct {
	ArtifactType string            `json:"artifactType"`
	Annotations  map[string]string `json:"annotations"`
}

// isAttestation: the buildx provenance/SBOM manifest that rides beside an
// image. `docker save --platform` on the containerd image store exports it
// with its subject (Docker 29: `artifactType`
// application/vnd.docker.attestation.manifest.v1+json and
// `io.containerd.manifest.subject`), so a single-platform tar of a buildx
// image lists two entries and holds ONE image. Counting it as an image
// refused every arm64 sidecar (robopi, 0.6.15 stunnel, 2026-11-01).
func (e ociIndexEntry) isAttestation() bool {
	return e.ArtifactType == "application/vnd.docker.attestation.manifest.v1+json" ||
		e.Annotations["vnd.docker.reference.type"] == "attestation-manifest" ||
		e.Annotations["io.containerd.manifest.subject"] != ""
}
