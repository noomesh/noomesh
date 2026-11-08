// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 PersonifAI LLC

package docker

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"testing"

	"github.com/noomesh/noomesh/node-agent-go/internal/preseed"
	"github.com/noomesh/noomesh/node-agent-go/internal/preseed/preseedtest"
)

// ---- dockerProvAPI over a daemon on a loopback port ----------------------

var (
	inspectImagePath = regexp.MustCompile(`/images/(.+)/json$`)
)

// provDaemon is the slice of the Docker Engine API dockerProvAPI uses for
// images: inspect (by whatever name the caller gives) and load.
type provDaemon struct {
	mu sync.Mutex
	// resolve maps the name inspect is asked for to the image ID the daemon
	// answers with. Docker resolves tags and ID prefixes, so a name can
	// answer with an ID that is not the name.
	resolve map[string]string
	// loadStatus and loadBody answer POST /images/load.
	loadStatus int
	loadBody   string
}

func newProvDaemon(t *testing.T, d *provDaemon) dockerProvAPI {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if strings.HasSuffix(r.URL.Path, "/_ping") {
			w.Header().Set("API-Version", "1.45")
			_, _ = w.Write([]byte("OK"))
			return
		}
		d.mu.Lock()
		defer d.mu.Unlock()
		if r.Method == http.MethodPost && strings.HasSuffix(r.URL.Path, "/images/load") {
			_, _ = io.Copy(io.Discard, r.Body)
			w.WriteHeader(d.loadStatus)
			_, _ = w.Write([]byte(d.loadBody))
			return
		}
		if m := inspectImagePath.FindStringSubmatch(r.URL.Path); m != nil && r.Method == http.MethodGet {
			if id, ok := d.resolve[m[1]]; ok {
				_, _ = w.Write([]byte(`{"Id":"` + id + `"}`))
				return
			}
			w.WriteHeader(http.StatusNotFound)
			_, _ = w.Write([]byte(`{"message":"No such image: ` + m[1] + `"}`))
			return
		}
		w.WriteHeader(http.StatusNotFound)
		_, _ = w.Write([]byte(`{"message":"unexpected ` + r.Method + " " + r.URL.Path + `"}`))
	}))
	t.Cleanup(srv.Close)
	t.Setenv("DOCKER_HOST", "tcp://"+strings.TrimPrefix(srv.URL, "http://"))
	c, err := NewClient(http.DefaultClient, "http", "test", false)
	if err != nil {
		t.Fatal(err)
	}
	return dockerProvAPI{c}
}

// Check 40: an image ID is exact. A name the daemon resolves to a different
// image, or a prefix of the ID that resolves to the full one, is not "the
// image is there".
func TestImageExistsIsExactOnTheID(t *testing.T) {
	const want = "sha256:cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc"
	const oneOff = "sha256:cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccd"
	for _, c := range []struct {
		name   string
		ask    string
		daemon map[string]string
		exists bool
	}{
		{"exact", want, map[string]string{want: want}, true},
		{"exact, bare hex", strings.TrimPrefix(want, "sha256:"), map[string]string{strings.TrimPrefix(want, "sha256:"): want}, true},
		{"daemon answers with an ID one hex char off", want, map[string]string{want: oneOff}, false},
		{"asked by prefix, daemon resolves the full ID", want[:19], map[string]string{want[:19]: want}, false},
		{"asked by prefix, daemon resolves another image", want[:19], map[string]string{want[:19]: oneOff}, false},
		{"absent", want, map[string]string{}, false},
		{"daemon answers an empty ID", want, map[string]string{want: ""}, false},
	} {
		t.Run(c.name, func(t *testing.T) {
			api := newProvDaemon(t, &provDaemon{resolve: c.daemon})
			got, err := api.ImageExists(context.Background(), c.ask)
			if err != nil {
				t.Fatalf("ImageExists: %v", err)
			}
			if got != c.exists {
				t.Errorf("ImageExists(%q) = %v, want %v", c.ask, got, c.exists)
			}
		})
	}
}

// Check 41: docker load streams its failures as JSON lines with a 200. A
// {"error": ...} line is a failed load, whatever the status.
func TestLoadImageSurfacesAnErrorInTheStream(t *testing.T) {
	const id = "sha256:cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc"
	tarPath := filepath.Join(t.TempDir(), "img.tar")
	if err := os.WriteFile(tarPath, tarOneImage(t, 1), 0o644); err != nil {
		t.Fatal(err)
	}

	for _, c := range []struct {
		name    string
		body    string
		wantIDs []string
		wantErr string // "" = success
	}{
		{"loaded", `{"stream":"Loaded image ID: ` + id + `\n"}` + "\n", []string{id}, ""},
		{"error line with a 200", `{"errorDetail":{"message":"unpacking failed"},"error":"unpacking failed"}` + "\n", nil, "docker load reported"},
		{"error after progress", `{"stream":"Loading layer"}` + "\n" + `{"error":"no space left on device"}` + "\n", nil, "no space left on device"},
		{"error beside a loaded line", `{"stream":"Loaded image ID: ` + id + `\n"}` + "\n" + `{"error":"late failure"}` + "\n", nil, "late failure"},
	} {
		t.Run(c.name, func(t *testing.T) {
			api := newProvDaemon(t, &provDaemon{loadStatus: 200, loadBody: c.body})
			f, oerr := os.Open(tarPath)
			if oerr != nil {
				t.Fatal(oerr)
			}
			defer f.Close()
			ids, err := api.LoadImage(context.Background(), f)
			switch {
			case c.wantErr == "" && err != nil:
				t.Errorf("LoadImage: %v", err)
			case c.wantErr != "" && (err == nil || !strings.Contains(err.Error(), c.wantErr)):
				t.Errorf("LoadImage = %v, %v; want an error containing %q", ids, err, c.wantErr)
			}
			if c.wantErr != "" && len(ids) != 0 {
				t.Errorf("a failed load returned IDs %v", ids)
			}
			if c.wantErr == "" && (len(ids) != 1 || ids[0] != id) {
				t.Errorf("ids = %v, want [%s]", ids, id)
			}
		})
	}
}

// ---- fetchRailTar --------------------------------------------------------

// railNode stands up the node's PKI, a staging dir, and a mesh store serving
// handler; NOO_MODEL_CACHE_URL is the production knob that points at it.
func railNode(t *testing.T, handler http.Handler) *httptest.Server {
	t.Helper()
	pki := preseedtest.New(t)
	pki.SetNodeEnv(t)
	srv := pki.Store(t, handler)
	t.Setenv("NOO_MODEL_CACHE_URL", srv.URL)
	t.Setenv("NOO_AGENT_STAGING_DIR", t.TempDir())
	return srv
}

func sumHex(b []byte) string { s := sha256.Sum256(b); return hex.EncodeToString(s[:]) }

func TestFetchRailTar(t *testing.T) {
	body := tarOneImage(t, 1)
	const artifact = "noo-addon-wl_a_b_ffff_amd64.tar"

	t.Run("a tar whose bytes match the manifest lands", func(t *testing.T) {
		railNode(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.URL.Path != "/images/"+artifact {
				w.WriteHeader(404)
				return
			}
			_, _ = w.Write(body)
		}))
		stubManifestFetch(t, func(string) (*artifactManifest, error) { return &artifactManifest{SHA256: sumHex(body)}, nil })
		path, cleanup, err := fetchRailTar(context.Background(), artifact)
		if err != nil {
			t.Fatalf("fetchRailTar: %v", err)
		}
		got, rerr := os.ReadFile(path)
		if rerr != nil || string(got) != string(body) {
			t.Errorf("staged %q: %v", path, rerr)
		}
		cleanup()
		if _, serr := os.Stat(path); !os.IsNotExist(serr) {
			t.Error("cleanup left the single-use tar behind")
		}
	})

	// Check 36: bytes that do not hash to the manifest are a verification
	// failure (image_digest_mismatch upstream), not a transport error.
	t.Run("bytes that do not match the manifest are a verification failure", func(t *testing.T) {
		railNode(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { _, _ = w.Write(body) }))
		stubManifestFetch(t, func(string) (*artifactManifest, error) {
			return &artifactManifest{SHA256: sumHex([]byte("other"))}, nil
		})
		path, _, err := fetchRailTar(context.Background(), artifact)
		if err == nil {
			t.Fatal("a tar with the wrong digest was accepted")
		}
		if !IsImageVerification(err) || !errors.Is(err, preseed.ErrDigestMismatch) {
			t.Errorf("err = %v (%T): want an ImageVerificationError wrapping ErrDigestMismatch", err, err)
		}
		if path != "" {
			t.Errorf("a path %q came back with the failure", path)
		}
		if ents, _ := os.ReadDir(os.Getenv("NOO_AGENT_STAGING_DIR")); len(ents) != 0 {
			t.Errorf("the staging dir holds %d entries after a failed verification", len(ents))
		}
	})

	// A transport failure is not a verification failure.
	t.Run("a store that fails is not a verification failure", func(t *testing.T) {
		railNode(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(500) }))
		stubManifestFetch(t, func(string) (*artifactManifest, error) { return &artifactManifest{SHA256: sumHex(body)}, nil })
		if _, _, err := fetchRailTar(context.Background(), artifact); err == nil || IsImageVerification(err) {
			t.Errorf("err = %v", err)
		}
	})

	// Check 34: the artifact name is a file name, nothing else.
	t.Run("an artifact name that is not a plain file name is refused before anything is asked", func(t *testing.T) {
		asked := stubManifestFetch(t, func(string) (*artifactManifest, error) { return &artifactManifest{SHA256: sumHex(body)}, nil })
		railNode(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { _, _ = w.Write(body) }))
		for _, bad := range []string{"", "../x.tar", "a/b.tar", `a\b.tar`, "/abs.tar", "sub/", ".", "..", ".hidden.tar"} {
			_, _, err := fetchRailTar(context.Background(), bad)
			if err == nil || !strings.Contains(err.Error(), "invalid artifact name") {
				t.Errorf("fetchRailTar(%q) err = %v, want invalid artifact name", bad, err)
			}
		}
		if len(*asked) != 0 {
			t.Errorf("the rail was asked about %v", *asked)
		}
		if ents, _ := os.ReadDir(os.Getenv("NOO_AGENT_STAGING_DIR")); len(ents) != 0 {
			t.Errorf("staging dir holds %v", ents)
		}
		// Nothing was written outside the staging dir either.
		if _, err := os.Stat(filepath.Join(os.Getenv("NOO_AGENT_STAGING_DIR"), "..", "x.tar")); err == nil {
			t.Error("a traversal name wrote outside the staging dir")
		}
	})

	// Check 35: NOO_MODEL_CACHE_URL is the production knob for the data
	// plane; with it unset there is nothing to pull from.
	t.Run("no data plane is refused before anything is asked", func(t *testing.T) {
		asked := stubManifestFetch(t, func(string) (*artifactManifest, error) { return &artifactManifest{SHA256: sumHex(body)}, nil })
		t.Setenv("NOO_MODEL_CACHE_URL", "")
		t.Setenv("NOO_AGENT_STAGING_DIR", t.TempDir())
		_, _, err := fetchRailTar(context.Background(), artifact)
		if err == nil || !strings.Contains(err.Error(), "NOO_MODEL_CACHE_URL is not set") {
			t.Errorf("err = %v, want the unset-data-plane refusal", err)
		}
		if len(*asked) != 0 {
			t.Errorf("the rail was asked about %v", *asked)
		}
	})
}
