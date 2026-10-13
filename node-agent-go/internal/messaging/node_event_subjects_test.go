// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 PersonifAI LLC

package messaging

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// Every event a node emits must carry the node in its subject.
//
// The per-principal bus credential grants a node only the scoped forms
// (`events.node.registered.{id}` and friends). A bare subject is refused,
// and NATS reports permission violations ASYNCHRONOUSLY — Publish returns
// nil, nothing is logged, and the event never arrives. Three instances of
// that shape have now been found by reading rather than by anything
// breaking: gossip, node.registered and ingest.doc.parsed.
//
// So this scans the source rather than exercising a connection. The bug is
// a call site choosing the wrong helper, which is visible in the source and
// invisible at runtime.
func TestEveryNodeEventGoesThroughAScopingHelper(t *testing.T) {
	root := ".."
	var offenders []string
	err := filepath.Walk(root, func(path string, info os.FileInfo, err error) error {
		if err != nil || info.IsDir() || !strings.HasSuffix(path, ".go") ||
			strings.HasSuffix(path, "_test.go") {
			return err
		}
		src, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		for i, line := range strings.Split(string(src), "\n") {
			if !strings.Contains(line, ".PublishEvent(") {
				continue
			}
			// The two wrappers ARE the scoping, and they are the only
			// legitimate callers: both append SubjectToken(nodeID).
			if strings.Contains(line, "SubjectToken(c.nodeID)") {
				continue
			}
			offenders = append(offenders,
				filepath.Base(path)+":"+itoa(i+1)+" "+strings.TrimSpace(line))
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(offenders) > 0 {
		t.Errorf(
			"these call PublishEvent directly, so they publish a BARE subject the "+
				"per-principal credential refuses — silently, because NATS reports "+
				"permission violations asynchronously. Use PublishNodeEvent:\n  %s",
			strings.Join(offenders, "\n  "))
	}
}

func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	var b []byte
	for n > 0 {
		b = append([]byte{byte('0' + n%10)}, b...)
		n /= 10
	}
	return string(b)
}

// The scoping helper must use the SAME sanitisation as the job-event one,
// or the two halves of the node's own credential disagree with each other.
func TestNodeEventScopingMatchesJobEventScoping(t *testing.T) {
	src, err := os.ReadFile("nats.go")
	if err != nil {
		t.Fatal(err)
	}
	s := string(src)
	for _, want := range []string{
		`return c.PublishEvent(eventType+"."+SubjectToken(c.nodeID), data)`,
		`return c.PublishEvent("job."+kind+"."+SubjectToken(c.nodeID), data)`,
	} {
		if !strings.Contains(s, want) {
			t.Errorf("nats.go no longer contains %q — the two node-scoped publishers "+
				"must sanitise the id identically", want)
		}
	}
}
