// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 PersonifAI LLC

package docker

import (
	_ "embed"
	"encoding/json"
	"fmt"
	"os"
	"regexp"
	"strings"

	"github.com/noomesh/noomesh/node-agent-go/internal/imagesource"
)

// A pinned door does not follow the node's release. Every other door runs
// NOO_IMAGE_PREFIX/stunnel:NOO_IMAGE_TAG, so a release roll recreates it and
// its engine (ReleaseSidecarImage, folded into the spec hash). For vLLM that
// is a model load per roll for a door that did not change: the stunnel
// image is rebuilt every release, so its digest moves even when nothing in
// it did. Its door is pinned instead (operator, 2026-10-28) and recreated
// only when the pin moves.
//
// door_images.json is a byte-equal copy of config/door-images.json, which
// the controller's CLI reads to stage each pin on the artifact rail
// (noo-cli image_stage.rs, source door-pin, kept across release retention).

//go:embed door_images.json
var doorImagesJSON []byte

// doorImagePin is one pinned door: a published release's stunnel image,
// by tag and the index digest that release's signed lock records.
type doorImagePin struct {
	Image  string `json:"image"`
	Tag    string `json:"tag"`
	Digest string `json:"digest"`
}

var pinDigestRe = regexp.MustCompile(`^sha256:[0-9a-f]{64}$`)

func parseDoorPins(raw []byte) (map[string]doorImagePin, error) {
	var f struct {
		Doors map[string]doorImagePin `json:"doors"`
	}
	if err := json.Unmarshal(raw, &f); err != nil {
		return nil, err
	}
	for backend, p := range f.Doors {
		if SidecarFor(backend) == "" {
			return nil, fmt.Errorf("%s has no door to pin", backend)
		}
		if p.Image == "" || strings.ContainsAny(p.Image, "/:@ ") || p.Tag == "" || strings.ContainsAny(p.Tag, "/:@ ") {
			return nil, fmt.Errorf("%s: image %q tag %q is not a plain <name>:<tag>", backend, p.Image, p.Tag)
		}
		if !pinDigestRe.MatchString(p.Digest) {
			return nil, fmt.Errorf("%s: digest %q is not sha256:<64 hex>", backend, p.Digest)
		}
	}
	return f.Doors, nil
}

// doorPins: backend -> its pinned door. Swapped in tests.
var doorPins = func() map[string]doorImagePin {
	p, err := parseDoorPins(doorImagesJSON)
	if err != nil {
		panic("docker: embedded door_images.json: " + err.Error())
	}
	return p
}()

// pinnedDoorRef is a pinned door's full ref, `<prefix>/<image>:<tag>@<digest>`
// (prefix NOO_IMAGE_PREFIX, else the published namespace), "" for a door
// that follows the release.
func pinnedDoorRef(backend string) string {
	p, ok := doorPins[backend]
	if !ok {
		return ""
	}
	prefix := strings.TrimRight(strings.TrimSpace(os.Getenv("NOO_IMAGE_PREFIX")), "/")
	if prefix == "" {
		prefix = DefaultImagePrefix
	}
	return prefix + "/" + p.Image + ":" + p.Tag + "@" + p.Digest
}

// pinnedDoorFetchRef is the ref a node fetches and runs a pinned door by: on
// a rail node the tag ref the controller staged it under (the rail's
// manifest verifies the tar, as for every rail image), elsewhere the digest
// ref, so a registry pull cannot land anything else.
func pinnedDoorFetchRef(backend string) string {
	ref := pinnedDoorRef(backend)
	if ref != "" && imageSourceMode() == imagesource.ModeRail {
		ref, _ = splitDigest(ref)
	}
	return ref
}
