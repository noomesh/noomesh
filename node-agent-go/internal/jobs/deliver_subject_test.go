// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 PersonifAI LLC

package jobs

import (
	"os"
	"strings"
	"testing"

	"github.com/noomesh/noomesh/node-agent-go/internal/messaging"
)

// The deliver subject must be a property of the NODE, not of the connection
// that happened to create the consumer.
//
// Consumers created while the agent held the shared credential
// recorded nats.go's default `_INBOX.<nuid>`. Binding an existing durable
// reuses that recorded subject — only the CREATE path mints a new one — so a
// node with a per-principal credential bound the durable it was entitled to
// and then subscribed to an inbox its grant denied. Four nodes, eight
// consumers, no job delivered, every status green.
func TestDeliverSubjectIsUnderThisNodesInboxPrefix(t *testing.T) {
	for _, node := range []string{"host3", "host9", "host8", "node_1"} {
		want := messaging.NodeInboxPrefix(node) + "."
		for _, kind := range []string{"dispatch", "cancel"} {
			got := deliverSubject(node, kind)
			if !strings.HasPrefix(got, want) {
				t.Errorf("deliverSubject(%q, %q) = %q, want prefix %q", node, kind, got, want)
			}
			if strings.HasPrefix(got, "_INBOX.") {
				t.Errorf("deliverSubject(%q, %q) = %q — the DEFAULT inbox is denied to nodes", node, kind, got)
			}
		}
	}
}

// The subject must be STABLE. A nuid-suffixed subject would differ on every
// rebind and mismatch the consumer this same agent created moments earlier —
// reproducing 1230 against itself, once per reconnect.
func TestDeliverSubjectIsStableAcrossCalls(t *testing.T) {
	a := deliverSubject("host3", "dispatch")
	b := deliverSubject("host3", "dispatch")
	if a != b {
		t.Fatalf("deliverSubject is not stable: %q then %q — a rebind would fight its own consumer", a, b)
	}
}

// Dispatch and cancel share a prefix but must not share a subject, or one
// consumer's deliveries land in the other's callback.
func TestDispatchAndCancelDoNotCollide(t *testing.T) {
	if deliverSubject("host3", "dispatch") == deliverSubject("host3", "cancel") {
		t.Fatal("dispatch and cancel resolve to the same deliver subject")
	}
}

// Two nodes must never share a deliver subject: that is the isolation the
// per-principal credentials exist to provide.
func TestNodesDoNotShareADeliverSubject(t *testing.T) {
	if deliverSubject("host3", "dispatch") == deliverSubject("host9", "dispatch") {
		t.Fatal("two nodes resolve to the same deliver subject")
	}
}

// Every durable this executor binds carries this node's deliver subject.
//
// Since i677 (finding b) the executor never lets nats.go create a consumer
// inside js.Subscribe (the library would then delete it on the next rebind):
// bindDurable creates it with DeliverSubject set, refuses an existing one that
// delivers elsewhere, and only then subscribes BOUND. This reads the source,
// as node_event_subjects_test.go does: the regression it guards is someone
// dropping the deliver subject, or going back to a library-created consumer.
func TestEverySubscribePassesADeliverSubject(t *testing.T) {
	src, err := os.ReadFile("executor.go")
	if err != nil {
		t.Fatalf("read executor.go: %v", err)
	}
	text := string(src)

	binds := strings.Count(text, "bindDurable(js, ")
	if binds != 2 {
		t.Fatalf("%d bindDurable call(s), want 2 (dispatch and cancel) — this guard is checking the wrong thing", binds)
	}
	withSubject := strings.Count(text, "durable, deliverSubject(e.nodeID, \"dispatch\")") +
		strings.Count(text, "cancelDurable, deliverSubject(e.nodeID, \"cancel\")")
	if withSubject != binds {
		t.Errorf("%d bindDurable call(s) but %d pass deliverSubject(...)", binds, withSubject)
	}
	if got := strings.Count(text, "js.Subscribe("); got != 1 {
		t.Errorf("%d js.Subscribe call(s): the only one must be bindDurable's, bound to a consumer it verified", got)
	}
	for _, must := range []string{
		"DeliverSubject: deliver,",
		"info.Config.DeliverSubject != deliver",
		"nats.Bind(stream, durable)",
	} {
		if !strings.Contains(text, must) {
			t.Errorf("bindDurable no longer has %q", must)
		}
	}
}
