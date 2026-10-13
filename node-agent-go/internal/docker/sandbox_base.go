// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 PersonifAI LLC

// noo-sandbox-base, built on the node that will run it.
//
// The base image for sandboxed capability containers is multi-arch upstream
// (python:3.12-slim) and the Dockerfile has no COPY steps, so an arm64 node
// building locally gets its own architecture for free — no cross-build on the
// controller, no qemu, no registry reachable from a worker. x86 nodes take
// the `docker save` tar over the artifact rail instead; only arm64 comes here.
//
// The Dockerfile is EMBEDDED, not received. That is the whole security shape
// of this file: `/pull kind=sandbox-base` takes no caller-supplied content, so
// there is no request that can make this node build something the controller's
// release did not ship. An endpoint that built whatever Dockerfile it was sent
// would be a remote-execution endpoint wearing a build's clothes — the same
// reason `kind=binary` allowlists exactly one name agent-side rather than
// fetching whatever it is told to.
package docker

import (
	"archive/tar"
	"bytes"
	"context"
	_ "embed"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"time"

	"github.com/moby/moby/client"
)

// SandboxBaseImage is the tag the skills executor looks for; a capability
// manifest that names no image gets this one.
const SandboxBaseImage = "noo-sandbox-base:latest"

//go:embed sandbox-base.Dockerfile
var sandboxBaseDockerfile []byte

// BuildSandboxBaseResult is what the controller's operator command prints.
type BuildSandboxBaseResult struct {
	Status  string `json:"status"`
	Image   string `json:"image"`
	ImageID string `json:"image_id,omitempty"`
}

// buildContextTar wraps the embedded Dockerfile as the one-entry tar the
// Engine API's /build expects. There is no build context beyond it — the
// image adds a user to an upstream base and nothing else.
func buildContextTar(dockerfile []byte) (*bytes.Buffer, error) {
	var buf bytes.Buffer
	tw := tar.NewWriter(&buf)
	hdr := &tar.Header{
		Name:    "Dockerfile",
		Mode:    0o644,
		Size:    int64(len(dockerfile)),
		ModTime: time.Unix(0, 0),
	}
	if err := tw.WriteHeader(hdr); err != nil {
		return nil, err
	}
	if _, err := tw.Write(dockerfile); err != nil {
		return nil, err
	}
	if err := tw.Close(); err != nil {
		return nil, err
	}
	return &buf, nil
}

// buildStreamError drains the daemon's build stream and returns the failure
// it reports, or "" when it reported none.
//
// The stream is newline-delimited JSON. A failure arrives as an object with
// an `error` (and usually `errorDetail`) field; everything else is progress.
// Anything unparseable is ignored rather than treated as a failure — the
// daemon interleaves aux/progress shapes and a strict reader would turn a
// successful build into a reported one.
func buildStreamError(r io.Reader) string {
	dec := json.NewDecoder(r)
	var last string
	for {
		var msg struct {
			Error       string `json:"error"`
			ErrorDetail struct {
				Message string `json:"message"`
			} `json:"errorDetail"`
		}
		if err := dec.Decode(&msg); err != nil {
			// io.EOF is the normal end; a decode error means the rest is
			// not JSON we understand, and we have already seen any error
			// object the daemon sent before it.
			break
		}
		if msg.ErrorDetail.Message != "" {
			last = msg.ErrorDetail.Message
		} else if msg.Error != "" {
			last = msg.Error
		}
	}
	return last
}

// BuildSandboxBase builds the embedded Dockerfile on this node.
//
// Synchronous, like the other /pull kinds: the caller is an operator command
// that wants the real outcome, not a fire-and-forget "starting". The build
// pulls python:3.12-slim, so a node with no route to a registry fails here —
// honestly, and with the daemon's own message.
func (c *Client) BuildSandboxBase(ctx context.Context) (*BuildSandboxBaseResult, error) {
	if c == nil || c.docker == nil {
		return nil, fmt.Errorf("Docker not available")
	}
	tarball, err := buildContextTar(sandboxBaseDockerfile)
	if err != nil {
		return nil, fmt.Errorf("assemble build context: %w", err)
	}
	slog.Info("building sandbox base", "image", SandboxBaseImage, "dockerfile_bytes", len(sandboxBaseDockerfile))
	buildCtx, cancel := context.WithTimeout(ctx, 20*time.Minute)
	defer cancel()
	res, err := c.docker.ImageBuild(buildCtx, tarball, client.ImageBuildOptions{
		Tags:       []string{SandboxBaseImage},
		Dockerfile: "Dockerfile",
		Remove:     true,
		// The daemon streams progress and reports a FAILED build in that
		// stream, not in the HTTP status — draining it is not optional.
		SuppressOutput: false,
	})
	if err != nil {
		return nil, fmt.Errorf("build %s: %w", SandboxBaseImage, err)
	}
	defer res.Body.Close()
	// A build that fails mid-stream returns HTTP 200 and reports the failure
	// as an {"error":…} object IN the stream. The stream is therefore the
	// only verdict there is.
	//
	// An earlier version of this used "does the tag exist afterwards?"
	// instead. That is wrong in the exact way this whole rail exists to
	// avoid: the tag survives a failed rebuild pointing at the PREVIOUS
	// image, so a broken build reported `built` and the node kept running
	// the old base. Caught by planting a `RUN exit 7` — which passed.
	if buildErr := buildStreamError(res.Body); buildErr != "" {
		return nil, fmt.Errorf("build %s failed: %s", SandboxBaseImage, buildErr)
	}
	inspect, err := c.docker.ImageInspect(buildCtx, SandboxBaseImage)
	if err != nil {
		return nil, fmt.Errorf("the build stream reported no error but %s does not exist afterwards: %w",
			SandboxBaseImage, err)
	}
	return &BuildSandboxBaseResult{
		Status:  "built",
		Image:   SandboxBaseImage,
		ImageID: inspect.ID,
	}, nil
}
