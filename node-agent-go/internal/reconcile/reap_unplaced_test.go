// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 PersonifAI LLC

package reconcile

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/noomesh/noomesh/node-agent-go/internal/backendreap"
	"github.com/noomesh/noomesh/node-agent-go/internal/config"
	"github.com/noomesh/noomesh/node-agent-go/internal/ctrlreach"
	dockerpkg "github.com/noomesh/noomesh/node-agent-go/internal/docker"
)

// The unplace reaper (reap_unplaced.go): a backend container is removed only
// on an explicit tombstone seen in two consecutive good reads, never because
// a placement is absent.

const (
	unplacedAt  = "2026-11-23T10:00:00.000Z"
	beforeUnix  = int64(1795000000) // 2026-11-18, before unplacedAt
	afterUnplac = int64(1795428001) // 2026-11-23T10:00:01Z, after it
)

func owned(backend string, created int64) dockerpkg.ManagedContainer {
	return dockerpkg.ManagedContainer{
		Name:    dockerpkg.ContainerNameFor(backend),
		Created: created,
		Labels:  map[string]string{"noo.managed-by": "node-agent-go", "noo.backend": backend, "com.docker.compose.project": "pai-assistant"},
	}
}

func goodDesired(unplaced ...unplacedTombstone) *desiredConfig {
	return &desiredConfig{Node: &nodeConfig{NodeID: "node-a"}, Unplaced: unplaced, GatewayFeatures: []string{"node_restarting", reapFeature}}
}

func tomb(backend, role string) unplacedTombstone {
	return unplacedTombstone{Backend: backend, Role: role, UnplacedAt: unplacedAt}
}

func plan(d *desiredConfig, confirmed []unplacedTombstone, cs ...dockerpkg.ManagedContainer) ([]reapAction, []backendreap.Orphan) {
	return planReap(reapInput{desired: d, confirmed: confirmed, containers: cs, native: map[string]string{}})
}

// Each container backend is reaped on a confirmed tombstone.
func TestEachContainerBackendIsReapedOnAConfirmedTombstone(t *testing.T) {
	for _, tc := range []struct{ backend, role string }{{"llamacpp", "chat"}, {"vllm", "chat"}, {"ollama", "embed"}, {"reranker", "rerank"}} {
		tb := tomb(tc.backend, tc.role)
		acts, orphans := plan(goodDesired(tb), []unplacedTombstone{tb}, owned(tc.backend, beforeUnix))
		if len(acts) != 1 || acts[0].backend != tc.backend || acts[0].container != dockerpkg.ContainerNameFor(tc.backend) || acts[0].unplacedAt != unplacedAt {
			t.Fatalf("%s: %+v", tc.backend, acts)
		}
		if len(orphans) != 0 {
			t.Fatalf("%s: a tombstoned container is not an orphan: %+v", tc.backend, orphans)
		}
	}
}

// Absence never reaps: a container no placement wants and no tombstone
// names is reported, never removed.
func TestAbsenceNeverReapsAndReportsTheOrphan(t *testing.T) {
	acts, orphans := plan(goodDesired(), nil, owned("reranker", beforeUnix))
	if len(acts) != 0 {
		t.Fatalf("reaped on absence: %+v", acts)
	}
	if len(orphans) != 1 || orphans[0].Backend != "reranker" || orphans[0].Container != "noo-reranker" || orphans[0].Since != "2026-11-18T11:06:40Z" {
		t.Fatalf("orphans %+v", orphans)
	}
	// A confirmed tombstone of ANOTHER backend reaps nothing here.
	acts, _ = plan(goodDesired(tomb("vllm", "chat")), []unplacedTombstone{tomb("vllm", "chat")}, owned("reranker", beforeUnix))
	if len(acts) != 0 {
		t.Fatalf("reaped the wrong backend: %+v", acts)
	}
}

// Rule 2: a placement of the backend (any role, any state) wins.
func TestAPlacedBackendIsNeverReaped(t *testing.T) {
	d := goodDesired(tomb("ollama", "chat"))
	d.Placements = []placement{{Backend: "ollama", Role: "embed", DesiredState: "stopped"}}
	acts, orphans := plan(d, []unplacedTombstone{tomb("ollama", "chat")}, owned("ollama", beforeUnix))
	if len(acts) != 0 || len(orphans) != 0 {
		t.Fatalf("acts %+v orphans %+v", acts, orphans)
	}
}

// Rule 5: no feature (an older controller) reaps nothing.
func TestNoFeatureNoReap(t *testing.T) {
	d := goodDesired(tomb("vllm", "chat"))
	d.GatewayFeatures = []string{"node_restarting"}
	if acts, _ := plan(d, []unplacedTombstone{tomb("vllm", "chat")}, owned("vllm", beforeUnix)); len(acts) != 0 {
		t.Fatalf("reaped without the feature: %+v", acts)
	}
}

// Rule 1: a null node reaps nothing, and the controller away reaps nothing.
func TestANullNodeOrAnAwayControllerReapsNothing(t *testing.T) {
	d := goodDesired(tomb("vllm", "chat"))
	d.Node = nil
	if acts, _ := plan(d, []unplacedTombstone{tomb("vllm", "chat")}, owned("vllm", beforeUnix)); len(acts) != 0 {
		t.Fatalf("reaped on a null node: %+v", acts)
	}
	acts, _ := planReap(reapInput{desired: goodDesired(tomb("vllm", "chat")), confirmed: []unplacedTombstone{tomb("vllm", "chat")},
		controllerAway: true, containers: []dockerpkg.ManagedContainer{owned("vllm", beforeUnix)}})
	if len(acts) != 0 {
		t.Fatalf("reaped with the controller away: %+v", acts)
	}
}

// Rule 4, the replay guard: a container created after the unplace (placed
// again since) is never reaped by it.
func TestAContainerCreatedAfterTheUnplaceIsNeverReaped(t *testing.T) {
	tb := tomb("llamacpp", "chat")
	if acts, _ := plan(goodDesired(tb), []unplacedTombstone{tb}, owned("llamacpp", afterUnplac)); len(acts) != 0 {
		t.Fatalf("reaped a newer container: %+v", acts)
	}
	// The same second as the unplace is not "before" (Docker's time is whole seconds).
	if acts, _ := plan(goodDesired(tb), []unplacedTombstone{tb}, owned("llamacpp", afterUnplac-1)); len(acts) != 0 {
		t.Fatalf("reaped a container of the unplace's own second: %+v", acts)
	}
	if acts, _ := plan(goodDesired(tb), []unplacedTombstone{tb}, owned("llamacpp", afterUnplac-2)); len(acts) != 1 {
		t.Fatalf("a container a second older is reaped: %+v", acts)
	}
	bad := unplacedTombstone{Backend: "llamacpp", Role: "chat", UnplacedAt: "yesterday"}
	if acts, _ := plan(goodDesired(bad), []unplacedTombstone{bad}, owned("llamacpp", beforeUnix)); len(acts) != 0 {
		t.Fatalf("an unreadable time reaped: %+v", acts)
	}
}

// Rule 6, ownership: only this agent's labelled container of that exact name.
func TestOwnershipLeavesEveryOtherContainerAlone(t *testing.T) {
	tb := tomb("ollama", "chat")
	foreign := owned("ollama", beforeUnix)
	foreign.Labels = map[string]string{"noo.managed-by": "someone-else", "noo.backend": "ollama"}
	wrongBackend := owned("ollama", beforeUnix)
	wrongBackend.Labels = map[string]string{"noo.managed-by": "node-agent-go", "noo.backend": "llamacpp"}
	prefix := owned("ollama", beforeUnix)
	prefix.Name = "noo-ollama-old"
	compose := owned("ollama", beforeUnix)
	compose.Labels["com.docker.compose.service"] = "ollama"
	workload := owned("ollama", beforeUnix)
	workload.Labels = map[string]string{"noo.managed-by": "agent", "noo.backend": "ollama"}
	for name, c := range map[string]dockerpkg.ManagedContainer{"foreign label": foreign, "other backend label": wrongBackend, "prefix-alike name": prefix, "compose service": compose, "node workload": workload} {
		if acts, orphans := plan(goodDesired(tb), []unplacedTombstone{tb}, c); len(acts) != 0 || len(orphans) != 0 {
			t.Fatalf("%s: acts %+v orphans %+v", name, acts, orphans)
		}
	}
	// A native backend (a Mac's Ollama) is never ours to remove.
	acts, orphans := planReap(reapInput{desired: goodDesired(tb), confirmed: []unplacedTombstone{tb},
		containers: []dockerpkg.ManagedContainer{owned("ollama", beforeUnix)}, native: map[string]string{"ollama": "gemma"}})
	if len(acts) != 0 || len(orphans) != 0 {
		t.Fatalf("native: acts %+v orphans %+v", acts, orphans)
	}
	acts, _ = planReap(reapInput{desired: goodDesired(tb), confirmed: []unplacedTombstone{tb},
		containers: []dockerpkg.ManagedContainer{owned("ollama", beforeUnix)}, nativeOnly: func(b string) bool { return b == "ollama" }})
	if len(acts) != 0 {
		t.Fatalf("native-only: %+v", acts)
	}
	// The harness is a host service with its own reaper.
	h := dockerpkg.ManagedContainer{Name: "noo-harness", Created: beforeUnix, Labels: map[string]string{"noo.managed-by": "node-agent-go", "noo.backend": "harness"}}
	if acts, orphans := plan(goodDesired(tomb("harness", "harness")), []unplacedTombstone{tomb("harness", "harness")}, h); len(acts) != 0 || len(orphans) != 0 {
		t.Fatalf("harness: acts %+v orphans %+v", acts, orphans)
	}
	// The exact door name with the labels is the backend's (an orphan is reported).
	door := owned("ollama", beforeUnix)
	door.Name = dockerpkg.SidecarContainerFor("ollama")
	if _, orphans := plan(goodDesired(), nil, door); len(orphans) != 1 {
		t.Fatalf("the door by exact name: %+v", orphans)
	}
}

// reapController answers desired-config with the body body() returns at each
// read (an empty string is a 500).
func reapController(t *testing.T, body func() string) *Reconciler {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b := body()
		if b == "" {
			http.Error(w, "broken", http.StatusInternalServerError)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(b))
	}))
	t.Cleanup(srv.Close)
	return &Reconciler{cfg: &config.Config{ControllerURL: srv.URL, NodeID: "node-a"}, client: srv.Client()}
}

const withTomb = `{"node":{"node_id":"node-a"},"placements":[],"gateway_features":["node_restarting","reap_unplaced_backends"],
 "unplaced":[{"backend":"reranker","role":"rerank","unplaced_at":"2026-11-23T10:00:00.000Z"}]}`

// reapPass runs fetchDesired and the reap phase with fake docker seams, and
// returns the backends stopped.
func reapPass(t *testing.T, r *Reconciler, cs []dockerpkg.ManagedContainer) []string {
	t.Helper()
	var mu sync.Mutex
	var stopped []string
	r.listManagedFn = func(context.Context) ([]dockerpkg.ManagedContainer, error) { return cs, nil }
	r.stopBackendFn = func(_ context.Context, b string) error {
		mu.Lock()
		defer mu.Unlock()
		stopped = append(stopped, b)
		return nil
	}
	tk := &tick{native: map[string]string{}}
	if r.fetchDesired(context.Background(), tk) {
		r.reapUnplacedBackends(context.Background(), tk)
	}
	return stopped
}

// Rule 3: the first pass after start never reaps; the same tombstone in two
// consecutive good reads does, once, with the heartbeat entry.
func TestTheSameTombstoneInTwoGoodReadsReapsAndOneReadDoesNot(t *testing.T) {
	backendreap.Reset()
	t.Cleanup(backendreap.Reset)
	r := reapController(t, func() string { return withTomb })
	r.reapNow = func() time.Time { return time.Date(2026, 11, 23, 10, 5, 0, 0, time.UTC) }
	cs := []dockerpkg.ManagedContainer{owned("reranker", beforeUnix)}
	if got := reapPass(t, r, cs); len(got) != 0 {
		t.Fatalf("the first pass reaped %v", got)
	}
	if got := reapPass(t, r, cs); len(got) != 1 || got[0] != "reranker" {
		t.Fatalf("the second good read: %v", got)
	}
	rs, _, _ := backendreap.Report(time.Date(2026, 11, 23, 11, 0, 0, 0, time.UTC))
	if len(rs) != 1 || rs[0].Backend != "reranker" || rs[0].UnplacedAt != unplacedAt || rs[0].At != "2026-11-23T10:05:00Z" {
		t.Fatalf("reaped report %+v", rs)
	}
	if rs, _, _ := backendreap.Report(time.Date(2026, 11, 24, 10, 6, 0, 0, time.UTC)); len(rs) != 0 {
		t.Fatalf("kept past 24 h: %+v", rs)
	}
}

// The first good pass since the agent started never reaps, even with the
// tombstone remembered.
func TestTheFirstGoodPassNeverReaps(t *testing.T) {
	r := reapController(t, func() string { return withTomb })
	r.unplacedPrev = map[unplacedTombstone]bool{tomb("reranker", "rerank"): true}
	if got := reapPass(t, r, []dockerpkg.ManagedContainer{owned("reranker", beforeUnix)}); len(got) != 0 {
		t.Fatalf("the first good pass reaped %v", got)
	}
}

// A failed read, a null node, or a changed unplaced_at between the two reads
// breaks "two consecutive good reads".
func TestABrokenSequenceNeverReaps(t *testing.T) {
	cs := []dockerpkg.ManagedContainer{owned("reranker", beforeUnix)}
	for name, between := range map[string]string{
		"failed read": "",
		"null node":   `{"node":null,"placements":[],"gateway_features":["reap_unplaced_backends"],"unplaced":[{"backend":"reranker","role":"rerank","unplaced_at":"2026-11-23T10:00:00.000Z"}]}`,
		"other time":  `{"node":{"node_id":"node-a"},"placements":[],"gateway_features":["reap_unplaced_backends"],"unplaced":[{"backend":"reranker","role":"rerank","unplaced_at":"2026-11-23T09:00:00.000Z"}]}`,
	} {
		reads := []string{withTomb, withTomb, between, withTomb}
		var mu sync.Mutex
		i := 0
		r := reapController(t, func() string {
			mu.Lock()
			defer mu.Unlock()
			b := reads[i]
			i++
			return b
		})
		r.goodReads = 5        // past the first-pass rule: only the sequence is judged
		_ = reapPass(t, r, cs) // read 1
		_ = reapPass(t, r, cs) // read 2: confirmed, reaped (not judged here)
		_ = reapPass(t, r, cs) // the break
		if got := reapPass(t, r, cs); len(got) != 0 {
			t.Fatalf("%s: reaped on the read right after the break: %v", name, got)
		}
	}
}

// Many good passes with no tombstone remove nothing; the orphan is reported.
func TestManyGoodPassesWithoutATombstoneNeverReap(t *testing.T) {
	backendreap.Reset()
	t.Cleanup(backendreap.Reset)
	r := reapController(t, func() string {
		return `{"node":{"node_id":"node-a"},"placements":[],"gateway_features":["reap_unplaced_backends"]}`
	})
	cs := []dockerpkg.ManagedContainer{owned("vllm", beforeUnix)}
	for i := 0; i < 10; i++ {
		if got := reapPass(t, r, cs); len(got) != 0 {
			t.Fatalf("pass %d reaped %v", i, got)
		}
	}
	_, os, judged := backendreap.Report(time.Now())
	if !judged || len(os) != 1 || os[0].Backend != "vllm" {
		t.Fatalf("orphan report %+v judged %v", os, judged)
	}
}

// A controller that ships no `unplaced` and no feature (one that predates
// them) never has a container removed.
func TestAnOlderControllerNeverReaps(t *testing.T) {
	r := reapController(t, func() string {
		return `{"node":{"node_id":"node-a"},"placements":[],"gateway_features":["node_restarting"]}`
	})
	r.goodReads = 5
	for i := 0; i < 3; i++ {
		if got := reapPass(t, r, []dockerpkg.ManagedContainer{owned("reranker", beforeUnix)}); len(got) != 0 {
			t.Fatalf("reaped under an older controller: %v", got)
		}
	}
}

// The controller away (ctrlreach) at the read is not a good read.
func TestAnAwayControllerReadIsNotGood(t *testing.T) {
	r := reapController(t, func() string { return withTomb })
	r.goodReads = 5
	r.unplacedPrev = map[unplacedTombstone]bool{tomb("reranker", "rerank"): true}
	ctrlreach.Failed("heartbeat", "https://ctl", errors.New("dial"), time.Now())
	t.Cleanup(func() { ctrlreach.Answered("test", time.Now()) })
	if got := r.observeUnplaced(goodDesired(tomb("reranker", "rerank"))); len(got) != 0 {
		t.Fatalf("confirmed while the controller is away: %v", got)
	}
	if r.unplacedPrev != nil {
		t.Fatal("an away read must forget the previous read")
	}
}

// A docker list error reports nothing and stops nothing; the models dir is
// never touched by the phase.
func TestAListErrorReapsNothingAndModelFilesStay(t *testing.T) {
	dir := t.TempDir()
	f := filepath.Join(dir, "m.gguf")
	if err := os.WriteFile(f, []byte("w"), 0o644); err != nil {
		t.Fatal(err)
	}
	r := reapController(t, func() string { return withTomb })
	r.goodReads = 5
	r.unplacedPrev = map[unplacedTombstone]bool{tomb("reranker", "rerank"): true}
	stopped := 0
	r.listManagedFn = func(context.Context) ([]dockerpkg.ManagedContainer, error) { return nil, errors.New("docker down") }
	r.stopBackendFn = func(context.Context, string) error { stopped++; return nil }
	tk := &tick{native: map[string]string{}}
	if !r.fetchDesired(context.Background(), tk) {
		t.Fatal("fetch")
	}
	r.reapUnplacedBackends(context.Background(), tk)
	if stopped != 0 {
		t.Fatal("stopped on a list error")
	}
	if b, err := os.ReadFile(f); err != nil || string(b) != "w" {
		t.Fatal("the models dir changed")
	}
}

// The phase runs after the placements converge (a re-place in this read has
// already been honoured) and before the image keep-list is written.
func TestTheReapPhaseRunsAfterConvergeAndCleanup(t *testing.T) {
	at := map[string]int{}
	for i, ph := range reconcilePhases {
		at[ph.name] = i
	}
	reap, ok := at["reapUnplacedBackends"]
	if !ok || !(at["convergePlacements"] < reap && at["reportAndCleanup"] < reap) {
		t.Fatalf("reap at %d (%v)", reap, at)
	}
}

// One role's unplace while another role keeps the backend placed is no reap
// authority (cf's rc.7 sequence, from a controller that still ships that
// tombstone). The embed role of ollama is unplaced at 09:35 while chat keeps
// it placed: many reads stop nothing. Then the chat role, the last
// placement, is unplaced at 10:00: the first read after it stops nothing,
// the second stops ollama, and the stop names the last unplace (10:00), not
// the 09:35 one.
const (
	embedUnplacedAt     = "2026-11-23T09:35:00.000Z"
	chatPlacedEmbedTomb = `{"node":{"node_id":"node-a"},"placements":[{"backend":"ollama","role":"chat","model":"m","desired_state":"running"}],
 "gateway_features":["node_restarting","reap_unplaced_backends"],
 "unplaced":[{"backend":"ollama","role":"embed","unplaced_at":"2026-11-23T09:35:00.000Z"}]}`
	bothUnplaced = `{"node":{"node_id":"node-a"},"placements":[],"gateway_features":["node_restarting","reap_unplaced_backends"],
 "unplaced":[{"backend":"ollama","role":"embed","unplaced_at":"2026-11-23T09:35:00.000Z"},{"backend":"ollama","role":"chat","unplaced_at":"2026-11-23T10:00:00.000Z"}]}`
)

func sequenceController(t *testing.T, reads ...string) *Reconciler {
	var mu sync.Mutex
	i := 0
	return reapController(t, func() string {
		mu.Lock()
		defer mu.Unlock()
		b := reads[len(reads)-1]
		if i < len(reads) {
			b = reads[i]
		}
		i++
		return b
	})
}

func TestAnotherRolesUnplaceGivesNoGraceToTheLastUnplace(t *testing.T) {
	backendreap.Reset()
	t.Cleanup(backendreap.Reset)
	r := sequenceController(t, chatPlacedEmbedTomb, chatPlacedEmbedTomb, chatPlacedEmbedTomb, chatPlacedEmbedTomb, bothUnplaced, bothUnplaced)
	r.reapNow = func() time.Time { return time.Date(2026, 11, 23, 10, 6, 0, 0, time.UTC) }
	cs := []dockerpkg.ManagedContainer{owned("ollama", beforeUnix)}
	for i := 0; i < 4; i++ {
		if got := reapPass(t, r, cs); len(got) != 0 {
			t.Fatalf("read %d, ollama still placed for chat: stopped %v", i+1, got)
		}
	}
	if got := reapPass(t, r, cs); len(got) != 0 {
		t.Fatalf("the first read after the last unplace stopped %v: an earlier role's tombstone counted toward the two reads", got)
	}
	if got := reapPass(t, r, cs); len(got) != 1 || got[0] != "ollama" {
		t.Fatalf("the second read after the last unplace: %v", got)
	}
	rs, _, _ := backendreap.Report(time.Date(2026, 11, 23, 10, 30, 0, 0, time.UTC))
	if len(rs) != 1 || rs[0].UnplacedAt != unplacedAt {
		t.Fatalf("the stop names %+v, want the last unplace %s (not the embed role's %s)", rs, unplacedAt, embedUnplacedAt)
	}
}

// A quick unplace -> re-place of the last role (one read between them, with
// an earlier role's tombstone shipping all along) never stops the backend.
func TestAQuickReplaceOfTheLastRoleNeverStops(t *testing.T) {
	backendreap.Reset()
	t.Cleanup(backendreap.Reset)
	r := sequenceController(t, chatPlacedEmbedTomb, chatPlacedEmbedTomb, chatPlacedEmbedTomb, bothUnplaced, chatPlacedEmbedTomb, chatPlacedEmbedTomb)
	cs := []dockerpkg.ManagedContainer{owned("ollama", beforeUnix)}
	for i := 0; i < 6; i++ {
		if got := reapPass(t, r, cs); len(got) != 0 {
			t.Fatalf("read %d stopped %v: a backend re-placed after one read was stopped", i+1, got)
		}
	}
}

// newestPerBackend keeps each backend's latest unplace, whatever order they
// come in; an older one after it never replaces it, nor does a time that does
// not parse.
func TestTheNewestTombstoneOfABackendIsTheOneActedOn(t *testing.T) {
	got := newestPerBackend([]unplacedTombstone{
		{Backend: "ollama", Role: "embed", UnplacedAt: embedUnplacedAt},
		{Backend: "reranker", Role: "rerank", UnplacedAt: unplacedAt},
		{Backend: "ollama", Role: "chat", UnplacedAt: unplacedAt},
		{Backend: "ollama", Role: "old", UnplacedAt: "2026-11-23T08:00:00.000Z"},
		{Backend: "ollama", Role: "x", UnplacedAt: "not a time"},
	})
	if len(got) != 2 || got[0].Backend != "ollama" || got[0].UnplacedAt != unplacedAt || got[1].Backend != "reranker" {
		t.Fatalf("newest per backend: %+v", got)
	}
}
