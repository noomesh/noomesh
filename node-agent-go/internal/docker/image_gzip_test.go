// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 PersonifAI LLC

package docker

import (
	"bytes"
	"compress/gzip"
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func gzipBytes(t *testing.T, b []byte) []byte {
	t.Helper()
	var out bytes.Buffer
	zw := gzip.NewWriter(&out)
	if _, err := zw.Write(b); err != nil {
		t.Fatal(err)
	}
	if err := zw.Close(); err != nil {
		t.Fatal(err)
	}
	return out.Bytes()
}

func writeTemp(t *testing.T, name string, b []byte) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), name)
	if err := os.WriteFile(p, b, 0o644); err != nil {
		t.Fatal(err)
	}
	return p
}

const gzManifest = `[{"Config":"c.json","RepoTags":["` + ownRef + `"]}]`

func TestCheckTarManifestReadsThroughGzip(t *testing.T) {
	plain := tarWith(t, map[string]string{"manifest.json": gzManifest}).Bytes()
	gz := gzipBytes(t, plain)

	if err := checkTarManifest(writeTemp(t, "a_amd64.tar.gz", gz), ownRef); err != nil {
		t.Errorf("a good .tar.gz must pass: %v", err)
	}
	if err := checkTarManifest(writeTemp(t, "a_amd64.tar", plain), ownRef); err != nil {
		t.Errorf("a good .tar must still pass: %v", err)
	}
	// The gz content is checked, not just opened: a foreign tag still refuses.
	bad := gzipBytes(t, tarWith(t, map[string]string{"manifest.json": `[{"RepoTags":["alpine:latest"]}]`}).Bytes())
	if err := checkTarManifest(writeTemp(t, "b_amd64.tar.gz", bad), ownRef); err == nil {
		t.Error("a .tar.gz tagging another image must be refused")
	}
}

func TestCheckTarManifestRefusesAMislabeledFile(t *testing.T) {
	plain := tarWith(t, map[string]string{"manifest.json": gzManifest}).Bytes()
	gz := gzipBytes(t, plain)

	err := checkTarManifest(writeTemp(t, "a_amd64.tar.gz", plain), ownRef)
	if err == nil || !strings.Contains(err.Error(), "not gzip data") {
		t.Errorf(".tar.gz holding a plain tar: err = %v, want a 'not gzip data' refusal", err)
	}
	err = checkTarManifest(writeTemp(t, "a_amd64.tar", gz), ownRef)
	if err == nil || !strings.Contains(err.Error(), "is gzip data but is not named .gz") {
		t.Errorf(".tar holding gzip: err = %v, want a mislabel refusal", err)
	}
	// Truncated gzip (right magic, no body) is an error, not a pass.
	if err := checkTarManifest(writeTemp(t, "c_amd64.tar.gz", gz[:6]), ownRef); err == nil {
		t.Error("a truncated .tar.gz must be refused")
	}
}

func stubManifestFetch(t *testing.T, f func(name string) (*artifactManifest, error)) *[]string {
	t.Helper()
	var asked []string
	prev := imageManifestFetch
	imageManifestFetch = func(_ context.Context, name string) (*artifactManifest, error) {
		asked = append(asked, name)
		return f(name)
	}
	t.Cleanup(func() { imageManifestFetch = prev })
	return &asked
}

func TestFetchImageManifestPrefersGzThenFallsBackToTar(t *testing.T) {
	const ref, arch = "reg.example/acme/x:v1", "amd64"
	gzName, tarName := ImageTarGzName(ref, arch), ImageTarName(ref, arch)

	// gz staged: one ask, the gz name.
	asked := stubManifestFetch(t, func(n string) (*artifactManifest, error) { return &artifactManifest{SHA256: "s"}, nil })
	if _, name, err := fetchImageManifest(context.Background(), ref, arch); err != nil || name != gzName {
		t.Fatalf("gz staged: name=%q err=%v", name, err)
	}
	if len(*asked) != 1 {
		t.Errorf("asked %v, want only the gz name", *asked)
	}

	// Only the old plain tar staged: gz absent → falls back to the tar.
	asked = stubManifestFetch(t, func(n string) (*artifactManifest, error) {
		if n == tarName {
			return &artifactManifest{SHA256: "s"}, nil
		}
		return nil, ErrArtifactAbsent
	})
	if _, name, err := fetchImageManifest(context.Background(), ref, arch); err != nil || name != tarName {
		t.Fatalf("fallback: name=%q err=%v", name, err)
	}
	if len(*asked) != 2 || (*asked)[0] != gzName || (*asked)[1] != tarName {
		t.Errorf("asked %v, want [gz, tar]", *asked)
	}

	// Neither staged: absent, and BOTH names were tried.
	asked = stubManifestFetch(t, func(string) (*artifactManifest, error) { return nil, ErrArtifactAbsent })
	if _, _, err := fetchImageManifest(context.Background(), ref, arch); !errors.Is(err, ErrArtifactAbsent) {
		t.Fatalf("neither staged: err = %v", err)
	}
	if len(*asked) != 2 {
		t.Errorf("asked %v", *asked)
	}

	// A route failure is NOT a reason to try the other name.
	boom := errors.New("manifest route 503")
	asked = stubManifestFetch(t, func(string) (*artifactManifest, error) { return nil, boom })
	if _, _, err := fetchImageManifest(context.Background(), ref, arch); !errors.Is(err, boom) {
		t.Fatalf("route failure: err = %v", err)
	}
	if len(*asked) != 1 {
		t.Errorf("a route failure must not fall back; asked %v", *asked)
	}
}

func TestImageNotStagedNamesBothTries(t *testing.T) {
	e := &ImageNotStagedError{Ref: "r", Arch: "amd64", Tar: "r_amd64.tar.gz", AltTar: "r_amd64.tar"}
	msg := e.Error()
	if !strings.Contains(msg, "r_amd64.tar.gz or r_amd64.tar") {
		t.Errorf("message must name both names tried: %s", msg)
	}
	solo := (&ImageNotStagedError{Ref: "r", Arch: "amd64", Tar: "r_amd64.tar"}).Error()
	if strings.Contains(solo, "r_amd64.tar or ") {
		t.Errorf("a single name must not render 'or': %s", solo)
	}
}
