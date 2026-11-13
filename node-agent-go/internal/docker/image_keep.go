// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 PersonifAI LLC

package docker

import (
	"context"
	"os"
	"strings"
)

// LocalImageID is the local image ID ref names on this node, "" when the
// daemon has no such image (or cannot be asked). Image retention's keep
// file records it, so hostd keeps a rail-loaded image by ID even when the
// tar left it with no digest.
func (c *Client) LocalImageID(ctx context.Context, ref string) string {
	if c == nil || c.docker == nil || strings.TrimSpace(ref) == "" {
		return ""
	}
	r, err := c.docker.ImageInspect(ctx, ref)
	if err != nil {
		return ""
	}
	return r.ID
}

// OwnRegistryRoots are the registry roots whose images are ours on this node
// (the managed roots plus NOO_IMAGE_PREFIX), as `<host>/<path>/`. Local-build
// namespaces are deliberately NOT included: image retention never treats a
// local build as ours.
func OwnRegistryRoots() []string {
	roots := append([]string{}, managedRegistryRoots...)
	if p := strings.TrimSpace(os.Getenv("NOO_IMAGE_PREFIX")); p != "" {
		roots = append(roots, p)
	}
	out := make([]string, 0, len(roots))
	for _, r := range roots {
		r = strings.TrimRight(strings.TrimSpace(r), "/")
		if r != "" {
			out = append(out, r+"/")
		}
	}
	return out
}
