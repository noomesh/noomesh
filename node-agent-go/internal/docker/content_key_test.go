// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 PersonifAI LLC

package docker

import (
	"context"
	"errors"
	"testing"
)

const (
	digestD = "sha256:dd46912abd4946a5c580c4a85883a559736b48f6f2c4e24162b77b307b74ea9f"
	digestE = "sha256:04ff82dc284420add2ae9f23db1e8db60f8b96b9d5a7bf50ad979d8b5dda838d"
)

// withManifest swaps the controller manifest lookup and fails the test if
// the local image store is consulted (build requirement (b), proposal i935:
// the content key comes only from the controller's manifest).
func withManifest(t *testing.T, fn func(ref string) (*artifactManifest, error)) *int {
	t.Helper()
	calls := 0
	origFetch, origLocal := contentManifestFetch, imageLocalID
	contentManifestFetch = func(_ context.Context, ref, _ string) (*artifactManifest, string, error) {
		calls++
		m, err := fn(ref)
		return m, "", err
	}
	imageLocalID = func(context.Context, *Client, string) (string, bool) {
		t.Fatal("ContentKey read the local image store; it must use only the controller's manifest")
		return "", false
	}
	resetContentKeys()
	t.Cleanup(func() { contentManifestFetch, imageLocalID = origFetch, origLocal; resetContentKeys() })
	return &calls
}

func TestContentKeyOfADigestPinnedRefDropsTheTagWithoutALookup(t *testing.T) {
	calls := withManifest(t, func(string) (*artifactManifest, error) { return nil, errors.New("must not be asked") })
	for _, c := range []struct{ ref, want string }{
		{"ghcr.io/noomesh/ollama:v0.6.25@" + digestD, "ghcr.io/noomesh/ollama@" + digestD},
		{"ghcr.io/noomesh/ollama:v0.6.26@" + digestD, "ghcr.io/noomesh/ollama@" + digestD},
		{"localhost:5000/rh/stunnel:v1@" + digestE, "localhost:5000/rh/stunnel@" + digestE},
		{"ghcr.io/noomesh/ollama@" + digestD, "ghcr.io/noomesh/ollama@" + digestD},
	} {
		if got, known := ContentKey(context.Background(), c.ref); !known || got != c.want {
			t.Errorf("ContentKey(%q) = %q, %v; want %q", c.ref, got, known, c.want)
		}
	}
	if *calls != 0 {
		t.Fatalf("a digest-pinned ref asked the controller %d time(s)", *calls)
	}
}

func TestContentKeyOfATagRefIsTheControllersLockDigest(t *testing.T) {
	calls := withManifest(t, func(string) (*artifactManifest, error) { return &artifactManifest{LockDigest: digestE}, nil })
	for _, tag := range []string{"v0.6.25", "v0.6.26"} {
		got, known := ContentKey(context.Background(), "ghcr.io/noomesh/stunnel:"+tag)
		if !known || got != "ghcr.io/noomesh/stunnel@"+digestE {
			t.Fatalf("%s: got %q, %v", tag, got, known)
		}
	}
	ContentKey(context.Background(), "ghcr.io/noomesh/stunnel:v0.6.26")
	if *calls != 2 {
		t.Fatalf("a vouched key is cached per ref: %d lookups, want 2", *calls)
	}
}

func TestContentKeyFallsBackToTheTagAndNeverTrustsAMalformedDigest(t *testing.T) {
	ref := "ghcr.io/noomesh/stunnel:v0.6.26"
	for name, fn := range map[string]func(string) (*artifactManifest, error){
		"not staged":       func(string) (*artifactManifest, error) { return nil, ErrArtifactAbsent },
		"older gateway":    func(string) (*artifactManifest, error) { return &artifactManifest{SHA256: "abc"}, nil },
		"malformed digest": func(string) (*artifactManifest, error) { return &artifactManifest{LockDigest: "sha256:not-hex"}, nil },
	} {
		t.Run(name, func(t *testing.T) {
			withManifest(t, fn)
			if got, known := ContentKey(context.Background(), ref); !known || got != ref {
				t.Fatalf("got %q, %v; want the tag ref itself, known", got, known)
			}
		})
	}
}

func TestContentKeyIsUnknownWhenTheControllerCannotBeAsked(t *testing.T) {
	withManifest(t, func(string) (*artifactManifest, error) { return nil, errors.New("dial tcp: connection refused") })
	if got, known := ContentKey(context.Background(), "ghcr.io/noomesh/stunnel:v0.6.26"); known || got != "" {
		t.Fatalf("got %q, %v; want unknown", got, known)
	}
}
