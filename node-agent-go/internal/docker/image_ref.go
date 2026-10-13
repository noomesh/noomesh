// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 PersonifAI LLC

package docker

import (
	"archive/tar"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
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
func checkTarManifest(path, ref string) error {
	f, err := os.Open(path)
	if err != nil {
		return fmt.Errorf("open staged tar: %w", err)
	}
	defer f.Close()
	return checkTarManifestReader(f, ref)
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
			Manifests []struct {
				Annotations map[string]string `json:"annotations"`
			} `json:"manifests"`
		}
		if err := json.Unmarshal(indexJSON, &idx); err != nil {
			return fmt.Errorf("unreadable index.json: %w", err)
		}
		if len(idx.Manifests) != 1 {
			return fmt.Errorf("the archive index lists %d images; a staged tar must hold exactly one", len(idx.Manifests))
		}
		if name := idx.Manifests[0].Annotations["io.containerd.image.name"]; name != "" && normalizeRef(name) != want {
			return fmt.Errorf("the archive names %q, not the requested %s", name, ref)
		}
	}
	return nil
}
