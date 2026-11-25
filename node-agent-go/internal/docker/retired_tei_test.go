// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 PersonifAI LLC

package docker

import (
	"sort"
	"strings"
	"testing"
)

// removedIDs are the container ids the daemon was asked to remove (DELETE).
func removedIDs(f *listFakeDaemon) []string {
	var ids []string
	for _, c := range f.seen() {
		if rest, ok := strings.CutPrefix(c, "DELETE "); ok {
			ids = append(ids, rest[strings.LastIndex(rest, "/")+1:])
		}
	}
	sort.Strings(ids)
	return ids
}

const agentLabel = `"noo.managed-by":"node-agent-go"`

// An install upgraded from a release that ran TEI: the containers THIS agent
// created are stopped and removed, by exact name, each reported once. The
// reranker is removed only when it runs the TEI image.
func TestRemoveRetiredTEIRemovesWhatThisAgentCreated(t *testing.T) {
	f := &listFakeDaemon{listStatus: 200, listBody: `[
 {"Id":"t1","Names":["/noo-tei"],"Image":"ghcr.io/huggingface/text-embeddings-inference:cpu-1.9.4","Labels":{` + agentLabel + `}},
 {"Id":"t2","Names":["/noo-tei-gpu"],"Image":"ghcr.io/huggingface/text-embeddings-inference:1.6","Labels":{` + agentLabel + `}},
 {"Id":"s1","Names":["/noo-stunnel-tei"],"Image":"x/stunnel:1","Labels":{` + agentLabel + `}},
 {"Id":"s2","Names":["/noo-stunnel-tei-gpu"],"Image":"x/stunnel:1","Labels":{` + agentLabel + `}},
 {"Id":"r1","Names":["/noo-reranker"],"Image":"ghcr.io/huggingface/text-embeddings-inference@sha256:abc","Labels":{` + agentLabel + `}},
 {"Id":"k1","Names":["/noo-llamacpp"],"Image":"x/llamacpp:1","Labels":{` + agentLabel + `}}
]`}
	c := newFakeDaemon(t, f)
	got, err := c.RemoveRetiredTEI(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	if ids := strings.Join(removedIDs(f), ","); ids != "r1,s1,s2,t1,t2" {
		t.Fatalf("removed %s, want the TEI containers and their doors only", ids)
	}
	if len(got) != 5 {
		t.Fatalf("reported %v, want 5 removals", got)
	}
	var rerankers int
	for _, rc := range got {
		if rc.Reranker {
			rerankers++
			if rc.Name != "noo-reranker" {
				t.Errorf("reranker flag on %q", rc.Name)
			}
		}
	}
	if rerankers != 1 {
		t.Errorf("%d reranker removals, want 1", rerankers)
	}
	// Each is stopped before it is removed.
	for _, id := range []string{"t1", "s1", "r1"} {
		if countCalls(f, "/containers/"+id+"/stop") != 1 {
			t.Errorf("%s was not stopped once: %v", id, f.seen())
		}
	}
}

// A container that is not this agent's is never removed, whatever its name:
// no agent label (someone else's, or compose-run, which carries only the
// compose project), or a name that merely contains noo-tei.
func TestRemoveRetiredTEILeavesForeignContainersAlone(t *testing.T) {
	f := &listFakeDaemon{listStatus: 200, listBody: `[
 {"Id":"f1","Names":["/noo-tei"],"Image":"ghcr.io/huggingface/text-embeddings-inference:1.6","Labels":{}},
 {"Id":"f2","Names":["/noo-tei-gpu"],"Image":"x/tei:1","Labels":{"com.docker.compose.project":"noomesh"}},
 {"Id":"f3","Names":["/noo-stunnel-tei"],"Image":"x/stunnel:1","Labels":{"noo.managed-by":"someone-else"}},
 {"Id":"f4","Names":["/noo-reranker"],"Image":"ghcr.io/huggingface/text-embeddings-inference:1.6","Labels":{}},
 {"Id":"f5","Names":["/noo-tei-proxy"],"Image":"x/proxy:1","Labels":{` + agentLabel + `}},
 {"Id":"f6","Names":["/my-noo-tei"],"Image":"x/y:1","Labels":{` + agentLabel + `}},
 {"Id":"f7","Names":["/noo-reranker"],"Image":"ghcr.io/noomesh/llamacpp:v0.6.29","Labels":{` + agentLabel + `}}
]`}
	c := newFakeDaemon(t, f)
	got, err := c.RemoveRetiredTEI(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 0 || len(removedIDs(f)) != 0 {
		t.Fatalf("removed %v / %v: a foreign container, or the llama.cpp reranker, was touched", got, removedIDs(f))
	}
	if countCalls(f, "/stop") != 0 {
		t.Fatalf("a foreign container was stopped: %v", f.seen())
	}
}

// A list error removes nothing: it is "could not ask", not "nothing there".
func TestRemoveRetiredTEIListErrorRemovesNothing(t *testing.T) {
	f := &listFakeDaemon{listStatus: 500, listBody: `{"message":"daemon busy"}`}
	c := newFakeDaemon(t, f)
	got, err := c.RemoveRetiredTEI(t.Context())
	if err == nil || len(got) != 0 || len(removedIDs(f)) != 0 {
		t.Fatalf("got %v, %v, removed %v; want an error and no removal", got, err, removedIDs(f))
	}
}
