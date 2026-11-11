// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 PersonifAI LLC

package docker

import (
	"archive/tar"
	"bytes"
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"net/url"
	"os"
	"path"
	"path/filepath"
	"strings"
	"time"

	"github.com/moby/moby/client"

	nodeconfig "github.com/noomesh/noomesh/node-agent-go/internal/config"
	"github.com/noomesh/noomesh/node-agent-go/internal/preseed"
)

// nativeOllamaModelsDir is where a native ollama keeps its models. The agent
// replaces it at start on a Mac (the brew plist's OLLAMA_MODELS, which the
// agent pins); elsewhere it is OLLAMA_MODELS from the agent's environment,
// else ollama's default under HOME. A wrong answer is caught: the daemon
// must list the tag with the staged digest after the write, or the write is
// taken back out (installMirror).
var nativeOllamaModelsDir = func() string {
	if d := strings.TrimSpace(os.Getenv("OLLAMA_MODELS")); d != "" {
		return d
	}
	home, _ := os.UserHomeDir()
	return filepath.Join(home, ".ollama", "models")
}

// SetNativeOllamaModelsDir installs the resolver for a native ollama's model
// store (agent start, darwin).
func SetNativeOllamaModelsDir(f func() string) {
	if f != nil {
		nativeOllamaModelsDir = f
	}
}

// nativeOllamaBase is the URL of the host's own ollama: OLLAMA_URL when the
// agent was given one, else ollama's loopback default.
func nativeOllamaBase() string {
	if u := strings.TrimRight(strings.TrimSpace(os.Getenv("OLLAMA_URL")), "/"); u != "" {
		return u
	}
	return "http://127.0.0.1:11434"
}

// ollamaTransport is how the agent dials base: the node leaf for an mTLS
// door, a bare transport (no proxy: the bytes go to this host's daemon and
// nowhere else) for plaintext loopback.
func ollamaTransport(base string) (*http.Transport, error) {
	if strings.HasPrefix(strings.ToLower(base), "https://") {
		return nodeconfig.Load().HTTPTransport()
	}
	return &http.Transport{Proxy: nil, MaxIdleConnsPerHost: 2, IdleConnTimeout: 30 * time.Second}, nil
}

// mirrorRef is a staged registry tag, resolved.
type mirrorRef struct {
	ns, name, tag string
	stem          string
}

// mirrorRefOf resolves name as a registry tag the mirror could have staged.
func mirrorRefOf(name string) (mirrorRef, bool) {
	ns, n, tag, err := parseOllamaRef(name)
	if err != nil {
		return mirrorRef{}, false
	}
	stem, err := OllamaStoreStem(name)
	if err != nil {
		return mirrorRef{}, false
	}
	return mirrorRef{ns: ns, name: n, tag: tag, stem: stem}, true
}

// importMirror installs a mirror-staged tag. gm is the gateway's manifest for
// the staged manifest FILE; work is this import's scratch directory.
func (c *Client) importMirror(ctx context.Context, name string, r mirrorRef, gm *artifactManifest, cacheURL, work string) (*PullOllamaModelResult, error) {
	mfName := r.stem + mirrorManifestSuffix
	dest := filepath.Join(work, mfName)
	if _, err := preseed.New().FetchOneVerified(ctx, cacheURL+"/gguf/"+url.PathEscape(mfName), dest, gm.SHA256); err != nil {
		return nil, fmt.Errorf("fetch %s: %w", mfName, err)
	}
	body, err := os.ReadFile(dest)
	if err != nil {
		return nil, fmt.Errorf("read %s: %w", mfName, err)
	}
	m, err := parseMirrorManifest(body)
	if err != nil {
		return nil, fmt.Errorf("%s: %w — restage it with `noo models fetch ollama:%s --force`", mfName, err, name)
	}

	var deps mirrorDeps
	var via, base string
	if _, ok := ollamaBinary(); ok {
		via, base = "host", nativeOllamaBase()
		modelsDir := nativeOllamaModelsDir()
		deps.writeManifest = func(_ context.Context, ns, n, tag string, b []byte) (*manifestWrite, error) {
			return writeManifestNative(modelsDir, ns, n, tag, b)
		}
		deps.checkSpace = func(missing []mirrorBlob) error { return requireFree(modelsDir, missing, "ollama's model store") }
	} else {
		if c == nil || c.docker == nil {
			return nil, fmt.Errorf("no `ollama` binary on this node and Docker is not available to run it in %s", OllamaContainer)
		}
		if !c.isRunning(ctx, OllamaContainer) {
			return nil, fmt.Errorf(
				"no `ollama` binary on this node and the %s container is not running — start it (`noo cluster start-backend %s ollama`) or install ollama, then re-run",
				OllamaContainer, os.Getenv("NODE_ID"))
		}
		if strings.TrimSpace(os.Getenv("OLLAMA_URL")) != "" {
			// The blobs would go to the daemon at OLLAMA_URL and the manifest
			// into the container's store: two ollamas, one half each.
			return nil, fmt.Errorf("OLLAMA_URL is set (%s) but this node has no host ollama, so the import would write into %s while pushing to that URL — unset OLLAMA_URL or install ollama on the host",
				os.Getenv("OLLAMA_URL"), OllamaContainer)
		}
		via, base = "container", c.BackendDialURL(ctx, "ollama")
		deps.writeManifest = c.writeManifestContainer
	}
	tr, err := ollamaTransport(base)
	if err != nil {
		return nil, fmt.Errorf("dialling ollama at %s: %w", base, err)
	}
	// One transport for this import; never leave its connections parked
	// (the i441 class).
	defer tr.CloseIdleConnections()
	deps.api = &ollamaHTTP{base: base, transport: tr}
	deps.fetchBlob = func(ctx context.Context, b mirrorBlob) (string, error) {
		return fetchMirrorBlob(ctx, name, b, cacheURL, work)
	}

	slog.Info("ollama mirror import", "model", name, "manifest_sha256", m.SHA256, "blobs", len(m.Blobs), "via", via, "ollama", base)
	if err := installMirror(ctx, r.ns, r.name, r.tag, m, deps); err != nil {
		return nil, err
	}
	slog.Info("ollama mirror imported", "model", name, "manifest_sha256", m.SHA256, "via", via)
	return &PullOllamaModelResult{Status: "created", Model: name, Via: via, ManifestSHA256: m.SHA256, Blobs: len(m.Blobs)}, nil
}

// fetchMirrorBlob fetches one blob from the store into work. The store's
// digest for the file must be the blob's own name: a file that hashes to
// anything else is not that blob, whatever the transfer says.
func fetchMirrorBlob(ctx context.Context, model string, b mirrorBlob, cacheURL, work string) (string, error) {
	n := b.blobName()
	am, err := awaitArtifactManifest(ctx, "ollamablob", n)
	if errors.Is(err, ErrArtifactAbsent) {
		return "", fmt.Errorf("the controller store's mirror of %s lacks blob %s (%s) — restage it with `noo models fetch ollama:%s --force`", model, b.short(), b.Media, model)
	}
	if err != nil {
		return "", fmt.Errorf("could not get the artifact manifest for blob %s from the controller: %w", b.short(), err)
	}
	if am.SHA256 != b.Hex {
		return "", fmt.Errorf("the controller store's %s hashes to %s — it is not the blob its name says; restage with `noo models fetch ollama:%s --force`", n, short(am.SHA256), model)
	}
	if err := requireFree(work, []mirrorBlob{b}, "the agent's staging area"); err != nil {
		return "", err
	}
	dest := filepath.Join(work, n)
	budget := 60*time.Minute + time.Duration(b.Size/(5<<20))*time.Second
	fctx, cancel := context.WithTimeout(ctx, budget)
	defer cancel()
	if _, err := preseed.New().FetchOneVerified(fctx, cacheURL+"/gguf/"+url.PathEscape(n), dest, b.Hex); err != nil {
		_ = os.Remove(dest)
		return "", fmt.Errorf("fetch blob %s: %w", b.short(), err)
	}
	return dest, nil
}

// requireFree refuses when dir lacks room for the blobs plus a margin.
func requireFree(dir string, blobs []mirrorBlob, what string) error {
	var need uint64 = 512 << 20
	for _, b := range blobs {
		need += uint64(b.Size)
	}
	free, err := freeBytes(dir)
	if err != nil {
		return fmt.Errorf("checking free space in %s (%s): %w", what, dir, err)
	}
	if free < need {
		return fmt.Errorf("%s (%s) has %d MiB free; this import needs %d MiB there — free space and re-run", what, dir, free>>20, need>>20)
	}
	return nil
}

// ollamaContainerStore is the store root inside noo-ollama, read from its
// mounts, and the uid that owns it: the hardened image's non-root store, or
// the upstream image's root one.
func (c *Client) ollamaContainerStore(ctx context.Context) (string, int, error) {
	res, err := c.docker.ContainerInspect(ctx, OllamaContainer, client.ContainerInspectOptions{})
	if err != nil {
		return "", 0, fmt.Errorf("inspect %s: %w", OllamaContainer, err)
	}
	for _, mnt := range res.Container.Mounts {
		switch mnt.Destination {
		case ollamaOursStore:
			return ollamaOursStore, ollamaStoreUID, nil
		case ollamaUpstreamStore:
			return ollamaUpstreamStore, 0, nil
		}
	}
	return "", 0, fmt.Errorf("%s mounts no ollama store at %s or %s — refusing to write a manifest into its image layer", OllamaContainer, ollamaOursStore, ollamaUpstreamStore)
}

// writeManifestContainer writes the manifest inside noo-ollama, as the
// container's own user: mkdir -p the tag's directory, copy the manifest in
// under a temp name, keep a copy of any manifest already there, then mv the
// temp over the tag. Docker resolves every path inside the container, so a
// link in its store cannot reach the host.
func (c *Client) writeManifestContainer(ctx context.Context, ns, name, tag string, body []byte) (*manifestWrite, error) {
	root, uid, err := c.ollamaContainerStore(ctx)
	if err != nil {
		return nil, err
	}
	dir := path.Join(root, "models", "manifests", "registry.ollama.ai", ns, name)
	final := path.Join(dir, tag)
	var rnd [8]byte
	if _, err := rand.Read(rnd[:]); err != nil {
		return nil, err
	}
	sfx := hex.EncodeToString(rnd[:])
	tmpName := ".noo-" + tag + "-" + sfx + ".tmp"
	tmp := path.Join(dir, tmpName)
	backup := path.Join(dir, ".noo-"+tag+"-"+sfx+".prev")
	run := func(cmd ...string) error {
		_, err := c.execCaptureIn(ctx, OllamaContainer, "/", cmd, time.Minute)
		return err
	}
	if err := run("mkdir", "-p", dir); err != nil {
		return nil, fmt.Errorf("create %s in %s: %w", dir, OllamaContainer, err)
	}
	var buf bytes.Buffer
	tw := tar.NewWriter(&buf)
	if err := tw.WriteHeader(&tar.Header{Name: tmpName, Mode: 0o644, Uid: uid, Gid: uid, Size: int64(len(body)), Typeflag: tar.TypeReg, ModTime: time.Unix(0, 0)}); err != nil {
		return nil, err
	}
	if _, err := tw.Write(body); err != nil {
		return nil, err
	}
	if err := tw.Close(); err != nil {
		return nil, err
	}
	if _, err := c.docker.CopyToContainer(ctx, OllamaContainer, client.CopyToContainerOptions{
		DestinationPath: dir, Content: &buf, CopyUIDGID: true,
	}); err != nil {
		return nil, fmt.Errorf("copy the manifest into %s: %w", OllamaContainer, err)
	}
	hadOld := run("test", "-f", final) == nil
	if hadOld {
		if err := run("cp", "-p", final, backup); err != nil {
			_ = run("rm", "-f", tmp)
			return nil, fmt.Errorf("keep the existing manifest before replacing it: %w", err)
		}
	}
	if err := run("mv", "-f", tmp, final); err != nil {
		_ = run("rm", "-f", tmp, backup)
		return nil, fmt.Errorf("move the manifest into place in %s: %w", OllamaContainer, err)
	}
	return &manifestWrite{
		undo: func() error {
			if hadOld {
				return run("mv", "-f", backup, final)
			}
			return run("rm", "-f", final)
		},
		commit: func() {
			if hadOld {
				_ = run("rm", "-f", backup)
			}
		},
	}, nil
}
