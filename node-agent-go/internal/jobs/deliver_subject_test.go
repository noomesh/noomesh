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

// Every js.Subscribe in the executor must pass a deliver subject.
//
// The opts list cannot be introspected — nats.SubOpt's only method and the
// subOpts struct it configures are both unexported — so this reads the source,
// the same technique node_event_subjects_test.go uses and for the same reason.
// The regression it guards is someone dropping the argument, which compiles
// fine the moment natsSubOpts grows a default.
func TestEverySubscribePassesADeliverSubject(t *testing.T) {
	src, err := os.ReadFile("executor.go")
	if err != nil {
		t.Fatalf("read executor.go: %v", err)
	}
	text := string(src)

	calls := strings.Count(text, "js.Subscribe(")
	if calls == 0 {
		t.Fatal("no js.Subscribe calls found — this guard is checking nothing")
	}
	withSubject := strings.Count(text, "natsSubOpts(durable, deliverSubject(") +
		strings.Count(text, "natsSubOpts(cancelDurable, deliverSubject(")
	if withSubject != calls {
		t.Errorf("%d js.Subscribe call(s) but %d pass natsSubOpts(..., deliverSubject(...)) — "+
			"a subscribe without an explicit deliver subject inherits whatever the "+
			"existing consumer recorded, which is wrong", calls, withSubject)
	}

	// And the option itself must still be handed to nats.go.
	if !strings.Contains(text, "nats.DeliverSubject(deliver)") {
		t.Error("natsSubOpts no longer passes nats.DeliverSubject — the subject is " +
			"computed and then thrown away")
	}
}
