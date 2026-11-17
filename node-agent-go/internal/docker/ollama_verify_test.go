// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 PersonifAI LLC

package docker

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/noomesh/noomesh/node-agent-go/internal/preseed"
)

// verifyRig is one ollama store plus a fake controller.
type verifyRig struct {
	t         *testing.T
	v         *OllamaVerifier
	store     map[string]string // kind/name -> sha256 (the controller's manifests)
	bodies    map[string][]byte // name -> body (the data plane)
	lookupErr error
	hashes    int
	repairs   []repairCall
	// repairFn runs as the repair; nil = succeed doing nothing.
	repairFn func() error
}

type repairCall struct {
	model, anchor string
	bad           []string
}

func newVerifyRig(t *testing.T, native bool) *verifyRig {
	t.Helper()
	root := t.TempDir()
	rg := &verifyRig{t: t, store: map[string]string{}, bodies: map[string][]byte{}}
	rg.v = &OllamaVerifier{
		ModelsDir: filepath.Join(root, "ollama", "models"),
		Native:    native,
		Record:    preseed.OpenVerifiedRecord(filepath.Join(root, "state", "verified", "ollama-blobs.json")),
		lookup: func(_ context.Context, kind, name string) (string, error) {
			if rg.lookupErr != nil {
				return "", rg.lookupErr
			}
			sha, ok := rg.store[kind+"/"+name]
			if !ok {
				return "", ErrArtifactAbsent
			}
			return sha, nil
		},
		fetch: func(_ context.Context, name, sha string) ([]byte, error) {
			b, ok := rg.bodies[name]
			if !ok {
				return nil, errors.New("not on the data plane")
			}
			if sum := sha256.Sum256(b); hex.EncodeToString(sum[:]) != sha {
				return nil, errors.New("digest mismatch")
			}
			return b, nil
		},
		hash: func(p string) (string, error) {
			rg.hashes++
			return preseed.HashFile(p)
		},
		repair: func(_ context.Context, model, anchor string, bad []string) error {
			rg.repairs = append(rg.repairs, repairCall{model, anchor, bad})
			if rg.repairFn != nil {
				return rg.repairFn()
			}
			return nil
		},
		now: time.Now,
	}
	return rg
}

func hexOf(b []byte) string {
	s := sha256.Sum256(b)
	return hex.EncodeToString(s[:])
}

// blob writes content into the store under its own digest.
func (rg *verifyRig) blob(content string) string {
	rg.t.Helper()
	h := hexOf([]byte(content))
	rg.writeBlobAt(h, content)
	return h
}

// writeBlobAt writes content under the NAME hex, whatever it hashes to.
func (rg *verifyRig) writeBlobAt(h, content string) {
	rg.t.Helper()
	dir := filepath.Join(rg.v.ModelsDir, "blobs")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		rg.t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "sha256-"+h), []byte(content), 0o644); err != nil {
		rg.t.Fatal(err)
	}
}

type layerSpec struct {
	media, hex string
	size       int
}

func manifestBody(config layerSpec, layers ...layerSpec) []byte {
	type d struct {
		MediaType string `json:"mediaType"`
		Digest    string `json:"digest"`
		Size      int    `json:"size"`
	}
	m := struct {
		SchemaVersion int    `json:"schemaVersion"`
		MediaType     string `json:"mediaType"`
		Config        d      `json:"config"`
		Layers        []d    `json:"layers"`
	}{SchemaVersion: 2, MediaType: "application/vnd.docker.distribution.manifest.v2+json",
		Config: d{config.media, "sha256:" + config.hex, config.size}}
	for _, l := range layers {
		m.Layers = append(m.Layers, d{l.media, "sha256:" + l.hex, l.size})
	}
	b, _ := json.Marshal(m)
	return b
}

// localManifest writes the manifest ollama reads ns/name:tag from.
func (rg *verifyRig) localManifest(ns, name, tag string, body []byte) {
	rg.t.Helper()
	p := rg.v.manifestPath(ns, name, tag)
	if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
		rg.t.Fatal(err)
	}
	if err := os.WriteFile(p, body, 0o644); err != nil {
		rg.t.Fatal(err)
	}
}

const (
	mirrorModel = "llama3.2:1b"
	mirrorStem  = "ollama+library+llama3.2+1b"
	weightsV1   = "GGUF weights, the controller's"
	configV1    = `{"model_format":"gguf"}`
	templateV1  = "{{ .Prompt }}"
)

// mirrorSetup stages a mirror on the controller and installs it locally,
// matching. Returns the model and config hexes.
func (rg *verifyRig) mirrorSetup() (model, config string) {
	model = rg.blob(weightsV1)
	config = rg.blob(configV1)
	tmpl := rg.blob(templateV1)
	body := manifestBody(layerSpec{"application/vnd.docker.container.image.v1+json", config, len(configV1)},
		layerSpec{ollamaModelMedia, model, len(weightsV1)},
		layerSpec{"application/vnd.ollama.image.template", tmpl, len(templateV1)})
	mf := mirrorStem + mirrorManifestSuffix
	rg.store["ollamamanifest/"+mf] = hexOf(body)
	rg.bodies[mf] = body
	rg.localManifest("library", "llama3.2", "1b", body)
	return model, config
}

func TestOllamaVerifyMirrorMatchingIsVerified(t *testing.T) {
	rg := newVerifyRig(t, false)
	model, _ := rg.mirrorSetup()
	res := rg.v.Verify(context.Background(), mirrorModel)
	if res.State != OllamaVerified || res.Anchor != OllamaAnchorMirror {
		t.Fatalf("got %+v", res)
	}
	if res.ModelLayer != "sha256:"+model {
		t.Errorf("model_layer = %q, want sha256:%s", res.ModelLayer, model)
	}
	if len(rg.repairs) != 0 {
		t.Errorf("a matching model was repaired: %+v", rg.repairs)
	}
}

func TestOllamaVerifyMirrorChangedBlobIsReinstalled(t *testing.T) {
	rg := newVerifyRig(t, false)
	model, _ := rg.mirrorSetup()
	rg.writeBlobAt(model, "tampered weights, same name")
	// The re-install puts the controller's bytes back.
	rg.repairFn = func() error { rg.writeBlobAt(model, weightsV1); return nil }
	res := rg.v.Verify(context.Background(), mirrorModel)
	if len(rg.repairs) != 1 || rg.repairs[0].anchor != OllamaAnchorMirror {
		t.Fatalf("re-install not attempted once from the mirror: %+v", rg.repairs)
	}
	if got := rg.repairs[0].bad; len(got) != 1 || got[0] != model {
		t.Errorf("the bad blob was not handed to the repair for removal: %v", got)
	}
	if res.State != OllamaRebuilt {
		t.Fatalf("got %+v, want rebuilt", res)
	}
}

func TestOllamaVerifyMirrorReinstallFailingRefuses(t *testing.T) {
	rg := newVerifyRig(t, false)
	model, _ := rg.mirrorSetup()
	rg.writeBlobAt(model, "tampered weights, same name")
	rg.repairFn = func() error { return errors.New("the controller is unreachable") }
	res := rg.v.Verify(context.Background(), mirrorModel)
	if len(rg.repairs) != 1 {
		t.Fatalf("re-install not attempted: %+v", rg.repairs)
	}
	if res.State != OllamaRefused {
		t.Fatalf("got %+v, want refused", res)
	}
	for _, want := range []string{mirrorModel, "sha256:" + model, "noo models pull " + mirrorModel} {
		if !strings.Contains(res.Reason, want) {
			t.Errorf("refusal %q does not name %q", res.Reason, want)
		}
	}
}

// The attacker case: the local manifest is rewritten to name a different
// blob that is perfectly self-consistent (it hashes to its own name).
func TestOllamaVerifyMirrorSelfConsistentSwapIsMismatch(t *testing.T) {
	rg := newVerifyRig(t, false)
	_, config := rg.mirrorSetup()
	evil := rg.blob("attacker weights")
	rg.localManifest("library", "llama3.2", "1b",
		manifestBody(layerSpec{"application/vnd.docker.container.image.v1+json", config, len(configV1)},
			layerSpec{ollamaModelMedia, evil, len("attacker weights")},
			layerSpec{"application/vnd.ollama.image.template", hexOf([]byte(templateV1)), len(templateV1)}))
	// Its blob is self-consistent: hashing against its own name passes.
	if vd, err := rg.v.checkBlob(evil); err != nil || vd != blobOK {
		t.Fatalf("precondition: the attacker blob should hash to its name (%v, %v)", vd, err)
	}
	rg.repairFn = func() error { return errors.New("repair refused in this test") }
	res := rg.v.Verify(context.Background(), mirrorModel)
	if len(rg.repairs) != 1 {
		t.Fatalf("a swapped manifest was not treated as a mismatch: %+v (%+v)", res, rg.repairs)
	}
	if res.Blob != "sha256:"+evil || !strings.Contains(res.Reason, evil) {
		t.Errorf("the offending blob is not the attacker's: %+v", res)
	}
	if res.ModelLayer != "sha256:"+evil {
		t.Errorf("model_layer should report what the node loads: %q", res.ModelLayer)
	}
}

const (
	ggufModel  = "harrier"
	ggufWeight = "harrier-q8_0.gguf"
	harrierBytes  = "GGUF harrier weights"
)

// ggufSetup publishes harrier.Modelfile + its GGUF on the controller and
// installs a matching local manifest. Returns the model layer hex.
func (rg *verifyRig) ggufSetup() string {
	mf := []byte("FROM ./" + ggufWeight + "\nPARAMETER num_ctx 8192\n")
	rg.store["modelfile/harrier.Modelfile"] = hexOf(mf)
	rg.bodies["harrier.Modelfile"] = mf
	model := rg.blob(harrierBytes)
	rg.store["gguf/"+ggufWeight] = model
	params := rg.blob(`{"num_ctx":8192}`)
	config := rg.blob(`{"model_format":"gguf","family":"harrier"}`)
	rg.localManifest("library", "harrier", "latest",
		manifestBody(layerSpec{"application/vnd.docker.container.image.v1+json", config, 10},
			layerSpec{ollamaModelMedia, model, len(harrierBytes)},
			layerSpec{"application/vnd.ollama.image.params", params, 16}))
	return model
}

func TestOllamaVerifyGGUFModelLayerMatchesIsVerified(t *testing.T) {
	rg := newVerifyRig(t, false)
	model := rg.ggufSetup()
	res := rg.v.Verify(context.Background(), ggufModel)
	if res.State != OllamaVerified || res.Anchor != OllamaAnchorGGUF || res.ModelLayer != "sha256:"+model {
		t.Fatalf("got %+v", res)
	}
	if len(rg.repairs) != 0 {
		t.Errorf("repaired a matching model: %+v", rg.repairs)
	}
}

func TestOllamaVerifyGGUFDifferentModelLayerIsRebuilt(t *testing.T) {
	rg := newVerifyRig(t, false)
	model := rg.ggufSetup()
	other := rg.blob("some other weights")
	writeHarrier := func(layer string) {
		rg.localManifest("library", "harrier", "latest",
			manifestBody(layerSpec{"application/vnd.docker.container.image.v1+json", hexOf([]byte("cfg")), 3},
				layerSpec{ollamaModelMedia, layer, 10}))
	}
	writeHarrier(other)
	// The rebuild (ollama create from the verified GGUF) writes the right layer.
	rg.repairFn = func() error { writeHarrier(model); return nil }
	res := rg.v.Verify(context.Background(), ggufModel)
	if len(rg.repairs) != 1 || rg.repairs[0].anchor != OllamaAnchorGGUF {
		t.Fatalf("rebuild not attempted from the GGUF: %+v", rg.repairs)
	}
	if res.State != OllamaRebuilt || res.ModelLayer != "sha256:"+model {
		t.Fatalf("got %+v, want rebuilt on sha256:%s", res, model)
	}
}

func TestOllamaVerifyGGUFRebuildFailingRefuses(t *testing.T) {
	rg := newVerifyRig(t, false)
	model := rg.ggufSetup()
	rg.writeBlobAt(model, "tampered GGUF bytes")
	rg.repairFn = func() error { return errors.New("ollama create failed") }
	res := rg.v.Verify(context.Background(), ggufModel)
	if len(rg.repairs) != 1 {
		t.Fatalf("rebuild not attempted: %+v", rg.repairs)
	}
	if res.State != OllamaRefused {
		t.Fatalf("got %+v, want refused", res)
	}
	for _, want := range []string{ggufModel, "sha256:" + model, "noo models pull " + ggufModel} {
		if !strings.Contains(res.Reason, want) {
			t.Errorf("refusal %q does not name %q", res.Reason, want)
		}
	}
}

func TestOllamaVerifyNoControllerRecordIsUnverifiedNeverRefused(t *testing.T) {
	rg := newVerifyRig(t, false)
	h := rg.blob("hand pulled")
	rg.localManifest("library", "mistral", "latest",
		manifestBody(layerSpec{"application/vnd.docker.container.image.v1+json", rg.blob("c"), 1},
			layerSpec{ollamaModelMedia, h, 11}))
	rg.repairFn = func() error { return errors.New("must not be called") }
	res := rg.v.Verify(context.Background(), "mistral")
	if res.State != OllamaUnverified || res.Anchor != OllamaAnchorNone {
		t.Fatalf("got %+v", res)
	}
	if res.Reason != "no controller record" || res.Remedy != "noo models pull mistral" {
		t.Errorf("reason/remedy = %q / %q", res.Reason, res.Remedy)
	}
	if res.ModelLayer != "sha256:"+h {
		t.Errorf("model_layer = %q", res.ModelLayer)
	}
	if len(rg.repairs) != 0 {
		t.Errorf("a model with no record was repaired: %+v", rg.repairs)
	}
}

// A controller that cannot be asked is not "no record" and not a verdict.
func TestOllamaVerifyControllerUnreachableIsErrorNotRefusal(t *testing.T) {
	rg := newVerifyRig(t, false)
	rg.mirrorSetup()
	rg.lookupErr = fmt.Errorf("dial tcp: i/o timeout")
	res := rg.v.Verify(context.Background(), mirrorModel)
	if res.State != OllamaVerifyErr || len(rg.repairs) != 0 {
		t.Fatalf("got %+v, repairs %+v", res, rg.repairs)
	}
}

func TestOllamaVerifyNativeReportsOnly(t *testing.T) {
	for _, tc := range []struct {
		name  string
		setup func(rg *verifyRig) string
	}{
		{"mirror", func(rg *verifyRig) string {
			m, _ := rg.mirrorSetup()
			rg.writeBlobAt(m, "tampered")
			return mirrorModel
		}},
		{"gguf", func(rg *verifyRig) string {
			m := rg.ggufSetup()
			rg.writeBlobAt(m, "tampered")
			return ggufModel
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			rg := newVerifyRig(t, true)
			model := tc.setup(rg)
			res := rg.v.Verify(context.Background(), model)
			if res.State != OllamaMismatch {
				t.Fatalf("got %+v, want mismatch", res)
			}
			if len(rg.repairs) != 0 {
				t.Fatalf("a native ollama was repaired: %+v", rg.repairs)
			}
		})
	}
}

func TestOllamaVerifyRecordSkipsUnchangedAndCatchesRewrite(t *testing.T) {
	rg := newVerifyRig(t, false)
	rg.mirrorSetup()
	if res := rg.v.Verify(context.Background(), mirrorModel); res.State != OllamaVerified {
		t.Fatalf("first: %+v", res)
	}
	first := rg.hashes
	if first == 0 {
		t.Fatal("the first verification hashed nothing")
	}
	if res := rg.v.Verify(context.Background(), mirrorModel); res.State != OllamaVerified {
		t.Fatalf("second: %+v", res)
	}
	if rg.hashes != first {
		t.Fatalf("unchanged blobs were re-hashed: %d hashes after %d", rg.hashes, first)
	}

	// Rewrite one blob in place with the SAME bytes and put its mtime back:
	// inode, size and mtime are as recorded; only ctime moved.
	p := rg.v.blobPath(hexOf([]byte(weightsV1)))
	fi, err := os.Stat(p)
	if err != nil {
		t.Fatal(err)
	}
	time.Sleep(20 * time.Millisecond) // past the filesystem's ctime granularity
	if err := os.WriteFile(p, []byte(weightsV1), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.Chtimes(p, fi.ModTime(), fi.ModTime()); err != nil {
		t.Fatal(err)
	}
	if res := rg.v.Verify(context.Background(), mirrorModel); res.State != OllamaVerified {
		t.Fatalf("third: %+v", res)
	}
	if rg.hashes != first+1 {
		t.Fatalf("a rewritten blob (mtime restored) was not re-hashed: %d hashes, want %d", rg.hashes, first+1)
	}
}
