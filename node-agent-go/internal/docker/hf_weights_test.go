// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 PersonifAI LLC

package docker

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/noomesh/noomesh/node-agent-go/internal/preseed"
)

func sha256Hex(s string) string {
	h := sha256.Sum256([]byte(s))
	return hex.EncodeToString(h[:])
}

// stubHFManifests answers hfManifestFn from a table (a missing repo is the
// store's 404) and points the verified-digest record at a temp state dir.
func stubHFManifests(t *testing.T, table map[string]*preseed.HFManifest) {
	t.Helper()
	prevFn, prevPath := hfManifestFn, hfRecordPath
	state := filepath.Join(t.TempDir(), "agent-state")
	hfManifestFn = func(_ context.Context, repo string) (*preseed.HFManifest, error) {
		m, ok := table[repo]
		if !ok {
			return nil, ErrArtifactAbsent
		}
		cp := *m
		cp.Files = append([]preseed.HFFile(nil), m.Files...)
		return &cp, nil
	}
	hfRecordPath = func() string { return filepath.Join(state, "verified", "hf-weights.json") }
	t.Cleanup(func() { hfManifestFn, hfRecordPath = prevFn, prevPath })
}

const fixtureRev = "1111111111111111111111111111111111111111"

// placeLocal puts a snapshot of org/m in the node's HF cache by hand.
func placeLocal(t *testing.T, hf string, files map[string]string) string {
	t.Helper()
	repo := filepath.Join(hf, "hub", "models--org--m")
	for p, body := range files {
		f := filepath.Join(repo, "snapshots", fixtureRev, p)
		if err := os.MkdirAll(filepath.Dir(f), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(f, []byte(body), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.MkdirAll(filepath.Join(repo, "refs"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(repo, "refs", "main"), []byte(fixtureRev), 0o644); err != nil {
		t.Fatal(err)
	}
	return repo
}

func fixtureManifest(files map[string]string) *preseed.HFManifest {
	m := &preseed.HFManifest{Rev: fixtureRev}
	for p, body := range files {
		m.Files = append(m.Files, preseed.HFFile{Path: p, Bytes: int64(len(body)), SHA256: sha256Hex(body)})
	}
	return m
}

var weights = map[string]string{"config.json": `{"a":1}`, "model.safetensors": "GOOD-WEIGHTS-0123456789"}

// A NEW agent against an OLD gateway (no `hf` kind): a plain refusal that
// says what this node is waiting for, never a start on unverified weights.
func TestAnOldGatewaySaysWhatTheNodeIsWaitingFor(t *testing.T) {
	hf := t.TempDir()
	t.Setenv("HF_CACHE_DIR", hf)
	placeLocal(t, hf, weights) // a local copy exists, and is still not enough
	stubHFManifests(t, nil)
	hfManifestFn = func(context.Context, string) (*preseed.HFManifest, error) { return nil, ErrArtifactKindUnknown }
	err := (&Client{}).stageHFModel(context.Background(), "vllm", "org/m")
	var refused *HFWeightsRefusedError
	if !errors.As(err, &refused) || !errors.Is(err, ErrArtifactKindUnknown) {
		t.Fatalf("want an HFWeightsRefusedError wrapping ErrArtifactKindUnknown, got %v", err)
	}
	for _, want := range []string{
		"predates verified HF weights", ">= " + hfManifestVersionFloor, "upgrade the controller first",
		"will not start vllm on unverified weights", "org/m",
	} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("message lacks %q: %s", want, err)
		}
	}
}

// The classification an old gateway's 400 gets, end to end over HTTP.
func TestAnHFKindUnknownToTheGatewayIsKindUnknown(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusBadRequest)
		_, _ = w.Write([]byte(`{"error":"unknown artifact kind 'hf' (kinds: gguf, image, modelfile, modelset, ollamablob, ollamamanifest)"}`))
	}))
	defer srv.Close()
	req, _ := http.NewRequest(http.MethodGet, srv.URL+"/api/artifacts/manifest/hf/models--org--m", nil)
	if _, err := doArtifactRequest(srv.Client(), req); !errors.Is(err, ErrArtifactKindUnknown) {
		t.Fatalf("want ErrArtifactKindUnknown, got %v", err)
	}
}

// The gateway's 409 (a blob that does not match its HF oid) is a refusal
// carrying the gateway's reason — not "absent", not a fallback.
func TestAGatewayRefusalIsCarriedVerbatim(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusConflict)
		_, _ = w.Write([]byte(`{"error":"hf snapshot models--org--m refused: model.safetensors links to LFS blob abc, but its bytes hash to def"}`))
	}))
	defer srv.Close()
	req, _ := http.NewRequest(http.MethodGet, srv.URL+"/x", nil)
	_, err := doArtifactRequest(srv.Client(), req)
	if !errors.Is(err, ErrArtifactRefused) || errors.Is(err, ErrArtifactAbsent) || !strings.Contains(err.Error(), "bytes hash to def") {
		t.Fatalf("want ErrArtifactRefused with the reason, got %v", err)
	}

	hf := t.TempDir()
	t.Setenv("HF_CACHE_DIR", hf)
	placeLocal(t, hf, weights)
	stubHFManifests(t, nil)
	hfManifestFn = func(context.Context, string) (*preseed.HFManifest, error) { return nil, err }
	serr := (&Client{}).stageHFModel(context.Background(), "vllm", "org/m")
	var refused *HFWeightsRefusedError
	if !errors.As(serr, &refused) || !strings.Contains(serr.Error(), "refuses to vouch") {
		t.Fatalf("a gateway refusal must refuse the start, got %v", serr)
	}
}

// A manifest with a file and no digest is not a manifest.
func TestAnHFManifestWithAnUndigestedFileIsRefused(t *testing.T) {
	body := []byte(`{"rev":"` + fixtureRev + `","files":[{"path":"config.json","bytes":2,"sha256":""}]}`)
	if _, err := decodeHFManifest(body); !errors.Is(err, ErrArtifactRefused) {
		t.Fatalf("want ErrArtifactRefused, got %v", err)
	}
	ok := []byte(`{"rev":"` + fixtureRev + `","files":[{"path":"config.json","bytes":2,"sha256":"` + strings.ToUpper(sha256Hex("{}")) + `"}]}`)
	m, err := decodeHFManifest(ok)
	if err != nil || m.Files[0].SHA256 != sha256Hex("{}") {
		t.Fatalf("a good manifest decodes (digest lowercased): %+v %v", m, err)
	}
}

// Controller unreachable: the local copy is checked against the manifest
// this node last verified. Intact → start; tampered → refused.
func TestControllerUnreachableFallsBackOnlyToAVerifiedLocalCopy(t *testing.T) {
	hf := t.TempDir()
	t.Setenv("HF_CACHE_DIR", hf)
	t.Setenv("NOO_MODEL_CACHE_URL", "")
	repo := placeLocal(t, hf, weights)
	stubHFManifests(t, map[string]*preseed.HFManifest{"models--org--m": fixtureManifest(weights)})
	// A first start with the controller up but its data plane refused
	// (NOO_MODEL_CACHE_URL empty → CacheURL ""): verifies the local copy
	// against the fresh manifest and records it.
	if err := (&Client{}).stageHFModel(context.Background(), "vllm", "org/m"); err != nil {
		t.Fatalf("an intact local copy must verify against the fresh manifest: %v", err)
	}
	unreachable := errors.New("manifest request failed: dial tcp: connection refused")
	hfManifestFn = func(context.Context, string) (*preseed.HFManifest, error) { return nil, unreachable }
	if err := (&Client{}).stageHFModel(context.Background(), "vllm", "org/m"); err != nil {
		t.Fatalf("controller down, local copy verified before: must start, got %v", err)
	}
	// Same size, different bytes.
	w := filepath.Join(repo, "snapshots", fixtureRev, "model.safetensors")
	if err := os.WriteFile(w, []byte(strings.Repeat("E", len(weights["model.safetensors"]))), 0o644); err != nil {
		t.Fatal(err)
	}
	err := (&Client{}).stageHFModel(context.Background(), "vllm", "org/m")
	var refused *HFWeightsRefusedError
	if !errors.As(err, &refused) || !errors.Is(err, preseed.ErrDigestMismatch) {
		t.Fatalf("a tampered local copy must be refused with ErrDigestMismatch, got %v", err)
	}
}

func TestControllerUnreachableWithNothingVerifiedIsRefused(t *testing.T) {
	hf := t.TempDir()
	t.Setenv("HF_CACHE_DIR", hf)
	placeLocal(t, hf, weights)
	stubHFManifests(t, nil)
	hfManifestFn = func(context.Context, string) (*preseed.HFManifest, error) {
		return nil, ErrArtifactManifestTimeout
	}
	err := (&Client{}).stageHFModel(context.Background(), "vllm", "org/m")
	var refused *HFWeightsRefusedError
	if !errors.As(err, &refused) || !strings.Contains(err.Error(), "never verified") {
		t.Fatalf("an unverified local copy must be refused, got %v", err)
	}
}

// The record is where no model container can reach it.
func TestTheRecordIsNeverUnderAContainerMount(t *testing.T) {
	// Runtime: a state dir placed under the HF cache disables the record.
	hf := t.TempDir()
	t.Setenv("HF_CACHE_DIR", hf)
	prev := hfRecordPath
	t.Cleanup(func() { hfRecordPath = prev })
	t.Setenv("NOO_AGENT_STATE", filepath.Join(hf, "state"))
	hfRecordPath = prev // the production path, from NOO_AGENT_STATE
	if hfVerifiedRecord().Disabled() == "" {
		t.Fatal("a record under HF_CACHE_DIR must be disabled")
	}
	models := t.TempDir()
	t.Setenv("MODELS_DIR", models)
	t.Setenv("NOO_AGENT_STATE", filepath.Join(models, "state"))
	if hfVerifiedRecord().Disabled() == "" {
		t.Fatal("a record under MODELS_DIR must be disabled")
	}
	t.Setenv("NOO_AGENT_STATE", filepath.Join(t.TempDir(), "noo-node-agent"))
	if d := hfVerifiedRecord().Disabled(); d != "" {
		t.Fatalf("a record in the agent's own state dir must be used: %s", d)
	}

	// Source: the record path derives from the agent's state dir and from
	// nothing a backend spec mounts.
	src, err := os.ReadFile("hf_weights.go")
	if err != nil {
		t.Fatal(err)
	}
	body := string(src)
	i := strings.Index(body, "var hfRecordPath = func() string {")
	if i < 0 {
		t.Fatal("hfRecordPath not found")
	}
	fn := body[i : i+strings.Index(body[i:], "\n}\n")]
	if !strings.Contains(fn, ".StateDir") {
		t.Errorf("hfRecordPath must derive from the agent's state dir:\n%s", fn)
	}
	for _, banned := range []string{"hfCacheSource", "HF_CACHE_DIR", "modelsSource", "ollamaSource", "HFCacheHost", "dataRootSource"} {
		if strings.Contains(fn, banned) {
			t.Errorf("hfRecordPath must not derive from %s:\n%s", banned, fn)
		}
	}
	// And the record is opened with every container-mounted root named, so
	// the runtime guard above sees them.
	j := strings.Index(body, "func hfVerifiedRecord() *preseed.VerifiedRecord {")
	open := body[j : j+strings.Index(body[j:], "\n}\n")]
	for _, need := range []string{"hfCacheSource", "modelsSource", "ollamaSource"} {
		if !strings.Contains(open, need) {
			t.Errorf("hfVerifiedRecord must pass %s as a mounted root:\n%s", need, open)
		}
	}
}

func TestProgressLineNamesTheModelAndGigabytes(t *testing.T) {
	if got := hfProgressText("google/gemma-4-12b-it", 2_100_000_000, 6_500_000_000); got != "verifying google/gemma-4-12b-it weights: 2.1/6.5 GB" {
		t.Fatalf("progress line = %q", got)
	}
}

// TEI reads the snapshot the agent verified: the images' own
// HUGGINGFACE_HUB_CACHE=/data would make it read HF_CACHE_DIR/models--…,
// while stageHFModel verifies HF_CACHE_DIR/hub/models--…. Checked on the
// rendered env (buildEnvList, with an override trying to move it back) and
// against the mount: env path = mount target + "/hub", mount source =
// the HF cache stageHFModel writes under.
func TestTEIReadsTheVerifiedHubSnapshot(t *testing.T) {
	specs := map[string]BackendSpec{"embedding": backendSpecs["embedding"], "reranker(tei)": rerankerSpecTEI()}
	for name, spec := range specs {
		env := buildEnvList(spec.Env, map[string]string{"HUGGINGFACE_HUB_CACHE": "/data"})
		got := ""
		for _, kv := range env {
			if v, ok := strings.CutPrefix(kv, "HUGGINGFACE_HUB_CACHE="); ok {
				got = v
			}
		}
		if got != "/data/hub" {
			t.Errorf("%s: rendered HUGGINGFACE_HUB_CACHE = %q, want /data/hub (the verified hub/ level)", name, got)
		}
		var mount *VolumeMount
		for i := range spec.Volumes {
			if spec.Volumes[i].Source == hfCacheSource {
				mount = &spec.Volumes[i]
			}
		}
		if mount == nil {
			t.Fatalf("%s: the HF cache is not mounted", name)
		}
		if rel, ok := strings.CutPrefix(got, strings.TrimRight(mount.Target, "/")); !ok || rel != "/hub" {
			t.Errorf("%s: cache %q is not <mount %s>/hub, where stageHFModel verifies", name, got, mount.Target)
		}
	}
}
