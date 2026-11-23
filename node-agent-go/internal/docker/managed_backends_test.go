// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 PersonifAI LLC

package docker

import (
	"context"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// ManagedContainers lists only the containers this agent's backend path
// labelled (a node workload's "agent" label and an unlabelled container are
// not in it), with their labels and creation time.
func TestManagedContainersListsOnlyThisAgentsBackendContainers(t *testing.T) {
	f := &listFakeDaemon{listStatus: 200, listBody: `[
 {"Id":"a","Names":["/noo-reranker"],"Created":1790000000,"State":"running","Labels":{"noo.managed-by":"node-agent-go","noo.backend":"reranker"}},
 {"Id":"b","Names":["/noo-stunnel-reranker"],"Created":1790000001,"State":"running","Labels":{"noo.managed-by":"node-agent-go","noo.stunnel-for":"reranker"}},
 {"Id":"c","Names":["/addon-worker"],"Created":1790000002,"Labels":{"noo.managed-by":"agent"}},
 {"Id":"d","Names":["/noo-ollama"],"Created":1790000003,"Labels":{"com.docker.compose.service":"ollama"}}
]`}
	c := newFakeDaemon(t, f)
	got, err := c.ManagedContainers(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 2 || got[0].Name != "noo-reranker" || got[0].Created != 1790000000 || got[0].Labels[BackendLabel] != "reranker" || got[1].Name != "noo-stunnel-reranker" {
		t.Fatalf("got %+v", got)
	}
	f.listStatus = http.StatusInternalServerError
	f.listBody = `{"message":"daemon broke"}`
	if got, err := c.ManagedContainers(context.Background()); err == nil {
		t.Fatalf("a list error read as %+v", got)
	}
}

// The stop path the reaper uses: the engine is stopped with a timeout (a
// serving request drains), then removed, then its door goes; nothing else is
// called, and a model file in the models dir is untouched.
func TestStopBackendDrainsThenRemovesTheEngineAndItsDoorOnly(t *testing.T) {
	models := t.TempDir()
	weight := filepath.Join(models, "bge-reranker-v2-m3-Q8_0.gguf")
	if err := os.WriteFile(weight, []byte("weights"), 0o644); err != nil {
		t.Fatal(err)
	}
	t.Setenv("MODELS_DIR", models)
	f := &listFakeDaemon{listStatus: 200, listBody: `[]`}
	c := newFakeDaemon(t, f)
	if err := c.StopBackend(context.Background(), "reranker"); err != nil {
		t.Fatal(err)
	}
	var calls []string
	for _, s := range f.seen() {
		if strings.Contains(s, "/containers/") && !strings.HasSuffix(s, "/containers/json") {
			calls = append(calls, s[strings.Index(s, "/containers/"):])
		}
	}
	want := []string{"/containers/noo-reranker/stop", "/containers/noo-reranker", "/containers/noo-stunnel-reranker/stop", "/containers/noo-stunnel-reranker"}
	if strings.Join(calls, ",") != strings.Join(want, ",") {
		t.Fatalf("calls %v, want %v (all: %v)", calls, want, f.seen())
	}
	for _, s := range f.seen() {
		if strings.Contains(s, "/volumes") || strings.Contains(s, "/images") {
			t.Fatalf("the stop path touched %s", s)
		}
	}
	if b, err := os.ReadFile(weight); err != nil || string(b) != "weights" {
		t.Fatalf("the model file changed: %q %v", b, err)
	}
}
