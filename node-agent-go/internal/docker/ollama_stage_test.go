// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 PersonifAI LLC

package docker

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"testing"

	"github.com/noomesh/noomesh/node-agent-go/internal/preseed"
	"github.com/noomesh/noomesh/node-agent-go/internal/preseed/preseedtest"
)

// The CLI (noo-cli/src/commands/ollama_stage.rs) writes these names and the
// node reads them: both sides carry THESE vectors, and
// tests/test_ollama_stage_parity.py pins that they stay the same.
var ollamaStemVectors = []struct{ ref, stem string }{
	{"gemma4:12b", "ollama+library+gemma4+12b"},
	{"gemma4", "ollama+library+gemma4+latest"},
	{"gemma4:latest", "ollama+library+gemma4+latest"},
	{"llama3.2:1b", "ollama+library+llama3.2+1b"},
	{"Library/Gemma4:12B", "ollama+library+gemma4+12b"},
	{"user/my-model:q4_K_M", "ollama+user+my-model+q4_k_m"},
	{"registry.ollama.ai/library/gemma4:12b", "ollama+library+gemma4+12b"},
}

func TestOllamaStoreStem(t *testing.T) {
	for _, v := range ollamaStemVectors {
		got, err := OllamaStoreStem(v.ref)
		if err != nil || got != v.stem {
			t.Errorf("OllamaStoreStem(%q) = %q, %v; want %q", v.ref, got, err, v.stem)
		}
		if !safeArtifactName(got + ".Modelfile") {
			t.Errorf("%q is not a legal artifact name", got)
		}
	}
	for _, bad := range []string{"", ":x", "x:", "hf.co/org/repo:Q4", "a/b/c", "../x", "x y", "host.example/model", "a:b:c", "x/", "/x"} {
		if got, err := OllamaStoreStem(bad); err == nil {
			t.Errorf("OllamaStoreStem(%q) = %q, want a refusal", bad, got)
		}
	}
}

const (
	stageStem = "ollama+library+gemma4+12b"
	// 64 hex digits; stands in for the registry's model-layer digest.
	stageSHA = "1111111111111111111111111111111111111111111111111111111111111111"
)

func stagedModelfile(sha string, extra string) string {
	return "# noo-ollama-stage: v1\n# source: registry.ollama.ai/library/gemma4:12b\n# model-sha256: " + sha + "\n" +
		"FROM ./" + stageStem + ".gguf\n" +
		"TEMPLATE \"\"\"{{ .Prompt }}\nFROM the user, ADAPTER /etc/shadow\n\"\"\"\n" +
		"PARAMETER stop \"<end_of_turn>\"\nPARAMETER temperature 0.7\n" + extra
}

func TestCheckStagedModelfile(t *testing.T) {
	h, err := checkStagedModelfile(stagedModelfile(stageSHA, "SYSTEM \"\"\"be brief\"\"\"\n"), stageStem)
	if err != nil || h.ModelSHA256 != stageSHA {
		t.Fatalf("a staged Modelfile must pass (words inside a quoted block are text): %v %+v", err, h)
	}
	bad := map[string]string{
		"an ADAPTER":            stagedModelfile(stageSHA, "ADAPTER /etc/shadow\n"),
		"a lower-case adapter":  stagedModelfile(stageSHA, "adapter ./x.gguf\n"),
		"a second FROM":         stagedModelfile(stageSHA, "FROM ./other.gguf\n"),
		"no marker":             strings.Replace(stagedModelfile(stageSHA, ""), "# noo-ollama-stage: v1\n", "", 1),
		"no digest":             strings.Replace(stagedModelfile(stageSHA, ""), "# model-sha256: "+stageSHA+"\n", "", 1),
		"FROM somewhere else":   strings.Replace(stagedModelfile(stageSHA, ""), "FROM ./"+stageStem+".gguf", "FROM /etc/passwd", 1),
		"an unterminated block": stagedModelfile(stageSHA, "SYSTEM \"\"\"never closed\n"),
		"a bare FROM":           strings.Replace(stagedModelfile(stageSHA, ""), "FROM ./"+stageStem+".gguf\n", "", 1),
	}
	for name, body := range bad {
		if _, err := checkStagedModelfile(body, stageStem); err == nil {
			t.Errorf("%s was accepted", name)
		}
	}
}

// ── a controller and a store in miniature ──────────────────────────────

type fakeController struct {
	mu     sync.Mutex
	files  map[string][]byte
	hits   []string
	create string // the log the fake ollama writes
}

func sha(b []byte) string { s := sha256.Sum256(b); return hex.EncodeToString(s[:]) }

// stageController serves /api/artifacts/manifest/<kind>/<name> and /gguf/<name>
// over mTLS (CONTROLLER_URL and NOO_MODEL_CACHE_URL both point at it), and
// puts a fake `ollama` first on PATH that records its argv and the Modelfile.
func stageController(t *testing.T, files map[string][]byte) *fakeController {
	t.Helper()
	clearImageEnv(t)
	pki := preseedtest.New(t)
	pki.SetNodeEnv(t)
	fc := &fakeController{files: files}
	srv := pki.Store(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fc.mu.Lock()
		fc.hits = append(fc.hits, r.URL.Path)
		fc.mu.Unlock()
		switch {
		case strings.HasPrefix(r.URL.Path, "/api/artifacts/manifest/"):
			parts := strings.SplitN(strings.TrimPrefix(r.URL.Path, "/api/artifacts/manifest/"), "/", 2)
			b, ok := fc.files[parts[1]]
			if !ok {
				http.NotFound(w, r)
				return
			}
			_, _ = w.Write([]byte(`{"sha256":"` + sha(b) + `","size_bytes":` + strconv.Itoa(len(b)) + `}`))
		case strings.HasPrefix(r.URL.Path, "/gguf/"):
			b, ok := fc.files[strings.TrimPrefix(r.URL.Path, "/gguf/")]
			if !ok {
				http.NotFound(w, r)
				return
			}
			_, _ = w.Write(b)
		default:
			http.NotFound(w, r)
		}
	}))
	t.Setenv("CONTROLLER_URL", srv.URL)
	t.Setenv("NOO_MODEL_CACHE_URL", srv.URL)
	t.Setenv("NOO_AGENT_STAGING_DIR", t.TempDir())

	bin := t.TempDir()
	fc.create = filepath.Join(bin, "create.log")
	script := "#!/bin/sh\nprintf '%s\\n' \"$@\" > '" + fc.create + "'\ncat \"$4\" > '" + fc.create + ".modelfile'\nexit 0\n"
	if err := os.WriteFile(filepath.Join(bin, "ollama"), []byte(script), 0o755); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", bin+string(os.PathListSeparator)+"/usr/bin:/bin")
	return fc
}

func (fc *fakeController) created() (string, bool) {
	b, err := os.ReadFile(fc.create)
	return string(b), err == nil
}

func stagedFiles(weight []byte, modelfileSHA string) map[string][]byte {
	return map[string][]byte{
		stageStem + ".gguf":      weight,
		stageStem + ".Modelfile": []byte(stagedModelfile(modelfileSHA, "")),
	}
}

func ggufBytes() []byte { return append([]byte("GGUF"), []byte("-weights-of-a-model")...) }

func TestAStagedTagImportsFromTheStoreWithoutTheRegistry(t *testing.T) {
	w := ggufBytes()
	fc := stageController(t, stagedFiles(w, sha(w)))
	res, err := (&Client{}).PullOllamaModel(t.Context(), "gemma4:12b")
	if err != nil {
		t.Fatalf("import: %v", err)
	}
	if res.Model != "gemma4:12b" || res.GGUF != stageStem+".gguf" || res.Via != "host" {
		t.Fatalf("result %+v", res)
	}
	log, ok := fc.created()
	if !ok || !strings.HasPrefix(log, "create\ngemma4:12b\n-f\n"+stageStem+".Modelfile") {
		t.Fatalf("ollama was not run as `create gemma4:12b -f <modelfile>`: %q", log)
	}
	// Everything this node asked for was the controller's: the two manifests
	// and the two files. (The test has no network; a registry dial would fail
	// the import, so a pass is also proof none was made.)
	for _, h := range fc.hits {
		if !strings.HasPrefix(h, "/api/artifacts/manifest/") && !strings.HasPrefix(h, "/gguf/") {
			t.Errorf("unexpected request %s", h)
		}
	}
}

func TestAStagedWeightThatIsNotTheRegistrysLayerIsRefused(t *testing.T) {
	w := ggufBytes()
	// The Modelfile says the registry's layer was something else.
	fc := stageController(t, stagedFiles(w, stageSHA))
	_, err := (&Client{}).PullOllamaModel(t.Context(), "gemma4:12b")
	if err == nil || !strings.Contains(err.Error(), "registry manifest") || !strings.Contains(err.Error(), "--force") {
		t.Fatalf("want a refusal naming the registry digest and the restage, got %v", err)
	}
	if _, ran := fc.created(); ran {
		t.Fatal("ollama create ran on a weight that does not match its staged digest")
	}
}

func TestAStagedWeightThatIsNotAGGUFIsRefused(t *testing.T) {
	w := []byte("<html>an error page</html>")
	fc := stageController(t, stagedFiles(w, sha(w)))
	_, err := (&Client{}).PullOllamaModel(t.Context(), "gemma4:12b")
	if err == nil || !strings.Contains(err.Error(), "GGUF") {
		t.Fatalf("want a GGUF-magic refusal, got %v", err)
	}
	if _, ran := fc.created(); ran {
		t.Fatal("ollama create ran on a non-GGUF weight")
	}
}

func TestAStagedModelfileWithAnAdapterIsNotRun(t *testing.T) {
	w := ggufBytes()
	files := stagedFiles(w, sha(w))
	files[stageStem+".Modelfile"] = []byte(stagedModelfile(sha(w), "ADAPTER /etc/shadow\n"))
	fc := stageController(t, files)
	_, err := (&Client{}).PullOllamaModel(t.Context(), "gemma4:12b")
	if err == nil || !strings.Contains(err.Error(), "ADAPTER") {
		t.Fatalf("want the directive named in the refusal, got %v", err)
	}
	if _, ran := fc.created(); ran {
		t.Fatal("ollama create ran a Modelfile with an ADAPTER")
	}
}

func TestATagTheControllerNeverStagedIsRefusedWithTheRemedy(t *testing.T) {
	fc := stageController(t, map[string][]byte{})
	_, err := (&Client{}).PullOllamaModel(t.Context(), "gemma4:12b")
	if err == nil || !errors.Is(err, ErrArtifactAbsent) || !strings.Contains(err.Error(), "noo models fetch ollama:gemma4:12b") {
		t.Fatalf("want the store's absence and the staging command, got %v", err)
	}
	if _, ran := fc.created(); ran {
		t.Fatal("ollama create ran for a model the store does not have")
	}
}

func TestAPlainStoreModelStillImportsUnderItsOwnName(t *testing.T) {
	w := ggufBytes()
	fc := stageController(t, map[string][]byte{
		"harrier.Modelfile": []byte("FROM ./harrier-q8.gguf\n"),
		"harrier-q8.gguf":   w,
	})
	res, err := (&Client{}).PullOllamaModel(t.Context(), "harrier")
	if err != nil || res.GGUF != "harrier-q8.gguf" {
		t.Fatalf("plain import: %v %+v", err, res)
	}
	if log, _ := fc.created(); !strings.HasPrefix(log, "create\nharrier\n-f\nharrier.Modelfile") {
		t.Fatalf("create args %q", log)
	}
}

func TestModelInStoreSeesAStagedTagOnAPlacedNodeOnly(t *testing.T) {
	w := ggufBytes()
	fc := stageController(t, stagedFiles(w, sha(w)))
	in, err := ModelInStore(t.Context(), "gemma4:12b")
	if err != nil || !in {
		t.Fatalf("a staged tag on a placed node: in=%v err=%v", in, err)
	}
	if in, err := ModelInStore(t.Context(), "qwen3:8b"); in || err != nil {
		t.Fatalf("an unstaged tag: in=%v err=%v, want (false, nil)", in, err)
	}
	// Not placed: the controller's own agent keeps pulling from the registry
	// and is not asked about (or made to depend on) a staged copy.
	t.Setenv("NOO_MODEL_CACHE_URL", "")
	n := len(fc.hits)
	if in, err := ModelInStore(t.Context(), "gemma4:12b"); in || err != nil {
		t.Fatalf("unplaced: in=%v err=%v", in, err)
	}
	if len(fc.hits) != n {
		t.Fatal("an unplaced node asked the store about a registry tag")
	}
}

func TestTheRegistryRefusalNamesTheStagingCommand(t *testing.T) {
	clearImageEnv(t)
	t.Setenv("NOO_MODEL_CACHE_URL", "https://controller:8443")
	err := preseed.OllamaRegistryPullAllowed("gemma4:12b")
	if err == nil {
		t.Fatal("a placed node must refuse a registry pull")
	}
	for _, want := range []string{"ollama_registry_pull_refused", "noo models fetch ollama:gemma4:12b", preseed.OllamaRegistryPullEnv} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("refusal lacks %q: %v", want, err)
		}
	}
}
