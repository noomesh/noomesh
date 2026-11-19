// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 PersonifAI LLC

package docker

import (
	"archive/tar"
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"path"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/moby/moby/api/types/container"
	"github.com/moby/moby/api/types/mount"
	"github.com/moby/moby/client"
)

// The agent's two copies into noo-ollama, against a REAL daemon
// (.github/workflows/ollama-pull-record.yml runs it on the runner's own
// dockerd and on a docker:27-dind one). Our ollama image sets
// `USER 65532:65532`. A CopyToContainer with CopyUIDGID makes the daemon
// resolve that user: Docker 27 and older look the WHOLE "65532:65532" up in
// the container's passwd and refuse the copy ("getent unable to find entry
// \"65532:65532\" in passwd database"); Docker 28 splits uid:gid. Every fake
// in this package accepts the option, so only a real old daemon shows it.
//
// What each subtest proves, through the product's own functions:
//   - manifest: writeManifestContainer (the mirror import) succeeds for a
//     model the store has never held, and the manifest AND every directory
//     the call created for it are owned 65532:65532;
//   - convert: ollamaCreateInContainer gets past its copy of the dirTar'd
//     pair (an error, if any, is `ollama create` refusing the dummy weight,
//     never "copy the model into"), and its cleanup, which runs as 65532,
//     removes the staging dir: a pair extracted as any other owner would
//     leave files 65532 cannot delete.
//
// Opt-in (house rule: tests never touch a real daemon by default):
// NOO_REAL_DAEMON_OWNER_TEST=1, against the daemon in DOCKER_HOST. With
// NOO_OWNER_TEST_IMAGE set, the test starts that image as noo-ollama on an
// anonymous volume at the store path (as the agent's backend spec mounts it)
// and removes both afterwards; it refuses to replace a noo-ollama that is
// already there. Without it, it uses the running noo-ollama as it finds it.
func TestRealDaemonCopiesIntoOllamaKeepTheStoreOwner(t *testing.T) {
	if os.Getenv("NOO_REAL_DAEMON_OWNER_TEST") != "1" {
		t.Skip("set NOO_REAL_DAEMON_OWNER_TEST=1 to copy into a real noo-ollama (house rule: tests never touch a daemon by default)")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Minute)
	defer cancel()
	c, err := NewClient(http.DefaultClient, "http", "", false)
	if err != nil {
		t.Fatalf("docker client: %v", err)
	}
	t.Cleanup(func() { _ = c.Close() })
	if !c.Reachable() {
		t.Fatalf("no daemon answers at DOCKER_HOST=%q", os.Getenv("DOCKER_HOST"))
	}
	v, err := c.docker.ServerVersion(ctx, client.ServerVersionOptions{})
	if err != nil {
		t.Fatalf("server version: %v", err)
	}
	t.Logf("daemon: Docker %s (API %s) at DOCKER_HOST=%q", v.Version, v.APIVersion, os.Getenv("DOCKER_HOST"))

	if img := os.Getenv("NOO_OWNER_TEST_IMAGE"); img != "" {
		startOwnerTestOllama(ctx, t, c, img)
	} else if !c.isRunning(ctx, OllamaContainer) {
		t.Fatalf("NOO_OWNER_TEST_IMAGE is unset and no %s is running to test against", OllamaContainer)
	}
	ins, err := c.docker.ContainerInspect(ctx, OllamaContainer, client.ContainerInspectOptions{})
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("%s runs as Config.User=%q", OllamaContainer, ins.Container.Config.User)

	root, uid, err := c.ollamaContainerStore(ctx)
	if err != nil {
		t.Fatalf("ollamaContainerStore: %v", err)
	}
	if root != ollamaOursStore || uid != ollamaStoreUID {
		t.Fatalf("store = %s (uid %d), want our image's %s (uid %d)", root, uid, ollamaOursStore, ollamaStoreUID)
	}
	want := fmt.Sprintf("%d:%d", ollamaStoreUID, ollamaStoreUID)

	t.Run("manifest", func(t *testing.T) {
		// A model name no store holds yet, so the call creates its manifest
		// directory: an implicitly created parent would take the daemon's
		// root owner, so every directory the call makes is checked too.
		name := fmt.Sprintf("fa-owner-probe-%d", time.Now().UnixNano())
		tag := "latest"
		manifests := path.Join(root, "models", "manifests")
		chain := []string{
			path.Join(root, "models"), manifests,
			path.Join(manifests, "registry.ollama.ai"),
			path.Join(manifests, "registry.ollama.ai", "library"),
			path.Join(manifests, "registry.ollama.ai", "library", name),
		}
		var fresh []string
		for _, d := range chain {
			if _, err := c.execCaptureIn(ctx, OllamaContainer, "/", []string{"test", "-e", d}, time.Minute); err != nil {
				fresh = append(fresh, d)
			}
		}
		if len(fresh) == 0 || fresh[len(fresh)-1] != chain[len(chain)-1] {
			t.Fatalf("the probe's manifest dir already exists in the store: %v", fresh)
		}
		body := []byte(`{"schemaVersion":2,"mediaType":"application/vnd.docker.distribution.manifest.v2+json",` +
			`"config":{"mediaType":"application/vnd.docker.container.image.v1+json",` +
			`"digest":"sha256:0000000000000000000000000000000000000000000000000000000000000000","size":2},"layers":[]}`)
		mw, err := c.writeManifestContainer(ctx, "library", name, tag, body)
		if err != nil {
			t.Fatalf("writeManifestContainer: %v", err)
		}
		mw.commit()
		final := path.Join(chain[len(chain)-1], tag)
		t.Cleanup(func() {
			_, _ = c.execCaptureIn(context.WithoutCancel(ctx), OllamaContainer, "/", []string{"rm", "-rf", chain[len(chain)-1]}, time.Minute)
		})
		bad := 0
		for _, p := range append(fresh, final) {
			hdr := ownerTestStat(ctx, t, c, p)
			got := fmt.Sprintf("%d:%d", hdr.Uid, hdr.Gid)
			t.Logf("%s: owner %s mode %#o", p, got, hdr.Mode&0o7777)
			if got != want {
				t.Errorf("%s is owned %s, want %s (the store's owner)", p, got, want)
				bad++
			}
		}
		if bad > 0 {
			t.FailNow()
		}
	})

	t.Run("convert", func(t *testing.T) {
		work := t.TempDir()
		const modelfile, weight = "Modelfile", "weight.gguf"
		if err := os.WriteFile(filepath.Join(work, modelfile), []byte("FROM ./"+weight+"\n"), 0o644); err != nil {
			t.Fatal(err)
		}
		// Not a GGUF: `ollama create` refuses it after the copy, which is
		// all this needs (the copy and the cleanup are what is under test).
		if err := os.WriteFile(filepath.Join(work, weight), []byte("not a gguf, owner test only\n"), 0o644); err != nil {
			t.Fatal(err)
		}
		out, err := c.ollamaCreateInContainer(ctx, work, fmt.Sprintf("noo-owner-test-%d", time.Now().UnixNano()), modelfile, weight)
		t.Logf("ollama create (a dummy weight, expected to be refused): err=%v out=%q", err, lastLine(out))
		if err != nil && strings.Contains(err.Error(), "copy the model into") {
			t.Fatalf("the convert path's copy into %s failed: %v", OllamaContainer, err)
		}
		// dirTar carries an explicit entry for convertDir itself and its
		// parent (the store) already exists, so no directory is created
		// implicitly: the dir and the pair are the archive's own entries.
		// The cleanup (rm -rf, as 65532) can only remove them if 65532 owns
		// the dir. It is not waited on by the product; give it a moment.
		var left error
		for i := 0; i < 20; i++ {
			if _, left = c.execCaptureIn(ctx, OllamaContainer, "/", []string{"test", "-e", convertDir}, time.Minute); left != nil {
				return // gone: 65532 could remove what the copy wrote
			}
			time.Sleep(500 * time.Millisecond)
		}
		ls, _ := c.execCaptureIn(ctx, OllamaContainer, "/", []string{"ls", "-lan", convertDir}, time.Minute)
		t.Fatalf("%s is still there after the cleanup ran as %s: the copied pair is not owned by the store's owner:\n%s", convertDir, want, ls)
	})
}

// startOwnerTestOllama runs img as noo-ollama the way ollamaContainerStore
// expects it: the image's own user, a volume at our store path.
func startOwnerTestOllama(ctx context.Context, t *testing.T, c *Client, img string) {
	t.Helper()
	if _, err := c.docker.ContainerInspect(ctx, OllamaContainer, client.ContainerInspectOptions{}); err == nil {
		t.Fatalf("a %s already exists on this daemon: refusing to replace it (unset NOO_OWNER_TEST_IMAGE to test the running one)", OllamaContainer)
	}
	resp, err := c.docker.ContainerCreate(ctx, client.ContainerCreateOptions{
		Name:   OllamaContainer,
		Config: &container.Config{Image: img, Labels: map[string]string{"noo.owner-test": "true"}},
		HostConfig: &container.HostConfig{
			// Anonymous: the daemon seeds it from the image's 65532-owned
			// /home/nonroot/.ollama, as prep-host owns a node's store.
			Mounts: []mount.Mount{{Type: mount.TypeVolume, Target: ollamaOursStore}},
		},
	})
	if err != nil {
		t.Fatalf("create %s from %s: %v", OllamaContainer, img, err)
	}
	t.Cleanup(func() {
		_, _ = c.docker.ContainerRemove(context.Background(), resp.ID, client.ContainerRemoveOptions{Force: true, RemoveVolumes: true})
	})
	if _, err := c.docker.ContainerStart(ctx, resp.ID, client.ContainerStartOptions{}); err != nil {
		t.Fatalf("start %s: %v", OllamaContainer, err)
	}
	var last error
	for i := 0; i < 60; i++ {
		if _, last = c.execCaptureIn(ctx, OllamaContainer, "/", []string{"ollama", "list"}, 30*time.Second); last == nil {
			return
		}
		time.Sleep(time.Second)
	}
	t.Fatalf("%s did not answer `ollama list`: %v", OllamaContainer, last)
}

// ownerTestStat reads one path's tar header out of noo-ollama: its numeric
// owner and mode, with no dependence on a stat binary in the image.
func ownerTestStat(ctx context.Context, t *testing.T, c *Client, p string) *tar.Header {
	t.Helper()
	res, err := c.docker.CopyFromContainer(ctx, OllamaContainer, client.CopyFromContainerOptions{SourcePath: p})
	if err != nil {
		t.Fatalf("read %s back from %s: %v", p, OllamaContainer, err)
	}
	defer res.Content.Close()
	// The archive's first entry is the path itself (a file or a directory).
	h, err := tar.NewReader(res.Content).Next()
	if errors.Is(err, io.EOF) {
		t.Fatalf("%s: no entry in the archive", p)
	}
	if err != nil {
		t.Fatal(err)
	}
	if h.Name != path.Base(p) && strings.TrimSuffix(h.Name, "/") != path.Base(p) {
		t.Fatalf("%s: the archive starts with %q, not the path", p, h.Name)
	}
	return h
}
