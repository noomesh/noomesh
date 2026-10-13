// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 PersonifAI LLC

package docker

import (
	"archive/tar"
	"bytes"
	"io"
	"os"
	"strings"
	"testing"
)

// The Dockerfile is compiled in, so "did it ship?" is answerable without a
// daemon — and it is worth answering: an empty embed builds an image with no
// instructions and the failure would surface as a capability container that
// runs as root.
func TestSandboxBaseDockerfileIsEmbedded(t *testing.T) {
	body := string(sandboxBaseDockerfile)
	if len(body) == 0 {
		t.Fatal("sandbox-base.Dockerfile embedded empty")
	}
	for _, want := range []string{
		"FROM python:3.12-slim",
		// The non-root user IS the isolation this image exists to provide.
		"useradd",
		"USER sandbox",
	} {
		if !strings.Contains(body, want) {
			t.Errorf("embedded Dockerfile lacks %q", want)
		}
	}
	// Nothing may be COPYed in: there is no build context to copy from, so a
	// COPY would fail on the node with a message about a path nobody sent.
	for _, line := range strings.Split(body, "\n") {
		u := strings.ToUpper(strings.TrimSpace(line))
		if strings.HasPrefix(u, "COPY ") || strings.HasPrefix(u, "ADD ") {
			t.Errorf("the sandbox base must stay context-free, found: %s", line)
		}
	}
}

// The Engine API's /build takes a tar, and the daemon looks for the name in
// ImageBuildOptions.Dockerfile. A mismatch is a build that fails on the node
// with "Cannot locate specified Dockerfile" — worth catching here.
func TestBuildContextTarHoldsExactlyTheDockerfile(t *testing.T) {
	buf, err := buildContextTar([]byte("FROM scratch\n"))
	if err != nil {
		t.Fatalf("buildContextTar: %v", err)
	}
	tr := tar.NewReader(bytes.NewReader(buf.Bytes()))
	var names []string
	for {
		h, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			t.Fatalf("read tar: %v", err)
		}
		names = append(names, h.Name)
		body, _ := io.ReadAll(tr)
		if h.Name == "Dockerfile" && string(body) != "FROM scratch\n" {
			t.Errorf("Dockerfile body round-tripped as %q", body)
		}
		if h.Size != int64(len(body)) {
			t.Errorf("%s: header size %d, body %d", h.Name, h.Size, len(body))
		}
	}
	if len(names) != 1 || names[0] != "Dockerfile" {
		t.Errorf("build context should hold exactly [Dockerfile], got %v", names)
	}
}

// A nil client must refuse rather than panic: /pull checks s.docker, but this
// is the function's own contract and the check is one line.
func TestBuildSandboxBaseRefusesWithoutADaemon(t *testing.T) {
	var c *Client
	if _, err := c.BuildSandboxBase(t.Context()); err == nil {
		t.Fatal("a nil client must refuse")
	}
}

// The whole path against a REAL daemon: embedded Dockerfile → tar → /build →
// an image that exists afterwards. Gated like the other live smoke, because
// a CI runner may have no usable socket.
//
//	NOO_DOCKER_SMOKE=1 go test -v -run TestLiveBuildSandboxBase ./internal/docker/
func TestLiveBuildSandboxBase(t *testing.T) {
	if os.Getenv("NOO_DOCKER_SMOKE") != "1" {
		t.Skip("set NOO_DOCKER_SMOKE=1 to run against the local daemon")
	}
	c, err := NewClient(nil, "http", "", false)
	if err != nil {
		t.Fatalf("docker client: %v", err)
	}
	res, err := c.BuildSandboxBase(t.Context())
	if err != nil {
		t.Fatalf("BuildSandboxBase: %v", err)
	}
	if res.Status != "built" || res.Image != SandboxBaseImage || res.ImageID == "" {
		t.Fatalf("unexpected result %+v", res)
	}
	// The user is the point of the image; assert it rather than the build's
	// exit status, which a mid-stream failure does not reflect.
	inspect, err := c.docker.ImageInspect(t.Context(), SandboxBaseImage)
	if err != nil {
		t.Fatalf("inspect: %v", err)
	}
	if inspect.Config == nil || inspect.Config.User != "sandbox" {
		t.Errorf("image must run as sandbox, got %+v", inspect.Config)
	}
}

// The stream is the verdict. This is the logic that replaced "does the tag
// exist afterwards?", which reported success for a failed rebuild because the
// tag still pointed at the previous image.
func TestBuildStreamErrorReadsTheDaemonsVerdict(t *testing.T) {
	cases := []struct {
		name   string
		stream string
		want   string
	}{
		{
			"a clean build reports nothing",
			`{"stream":"Step 1/5 : FROM python:3.12-slim"}
{"stream":"Successfully tagged noo-sandbox-base:latest\n"}`,
			"",
		},
		{
			"errorDetail is preferred over error",
			`{"stream":"Step 2/5 : RUN useradd"}
{"errorDetail":{"code":7,"message":"The command '/bin/sh -c useradd' returned a non-zero code: 7"},"error":"short"}`,
			"The command '/bin/sh -c useradd' returned a non-zero code: 7",
		},
		{
			"a bare error field still counts",
			`{"error":"pull access denied for python"}`,
			"pull access denied for python",
		},
		{
			// The daemon interleaves progress and aux shapes; a reader that
			// treated an unfamiliar object as a failure would report a
			// successful build as broken.
			"progress and aux objects are not failures",
			`{"status":"Pulling from library/python","progressDetail":{"current":1,"total":2}}
{"aux":{"ID":"sha256:abc"}}`,
			"",
		},
		{"an empty stream is not a failure", "", ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := buildStreamError(strings.NewReader(tc.stream)); got != tc.want {
				t.Errorf("got %q, want %q", got, tc.want)
			}
		})
	}
}
