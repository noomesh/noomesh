// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 PersonifAI LLC

package hostd

import (
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"sort"
	"strings"
	"testing"
)

// The spool schema has two ends in two languages, and nothing in the compiler
// connects them. That is not hypothetical drift: `rotate` shipped with a
// working handler in the bash watcher that its own validation list did not
// include, so every rotate request the gateway queued was rejected with
// "invalid op" before reaching code that would have worked. Nobody noticed
// because a rejected op looks identical to a slow one from the caller's side.
//
// These tests are the missing connection. They read the actual producers out
// of the repo and compare them to the op registry,
// so adding a producer without a handler — or deleting a handler a producer
// still calls — fails CI instead of failing in production six weeks later.

// repoRoot walks up from this source file to the checkout root.
func repoRoot(t *testing.T) string {
	t.Helper()
	_, self, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("cannot locate own source file")
	}
	dir := filepath.Dir(self)
	for i := 0; i < 6; i++ {
		if _, err := os.Stat(filepath.Join(dir, "docker-compose.cluster.yml")); err == nil {
			return dir
		}
		dir = filepath.Dir(dir)
	}
	t.Skip("repo root not found — running outside a checkout")
	return ""
}

// Producers pass the op as the first argument, either positionally to the
// spool helper or as an "op" key in a json! literal.
var producerPatterns = []*regexp.Regexp{
	regexp.MustCompile(`host_spool_write_command\(\s*"([a-z-]+)"`),
	regexp.MustCompile(`host_spool\.write_command\(\s*\n?\s*"([a-z-]+)"`),
	regexp.MustCompile(`(?m)^\s*write_command\(\s*\n?\s*"([a-z-]+)"`),
	regexp.MustCompile(`"op":\s*"([a-z-]+)"`),
}

// spoolHelpers are the identifiers that mean "this file writes to the spool".
// A file is a producer if it mentions one of them — that is the whole
// discovery rule.
//
// This replaced a hand-maintained list of producer FILES, which rotted in
// under 24 hours: `src/noomesh/workers/security.py` was deleted when its PKI
// rotate went native (#613), and the next unrelated PR went red. That list was
// correct when written and correct in intent — it simply named things that
// move. Helper identifiers move far less often than the files calling them,
// and when they DO move, TestEveryKnownSpoolHelperStillExists fails with the
// reason instead of leaving discovery quietly matching nothing.
//
// Two tokens, not seven. The first cut enumerated Python import FORMS ("from
// ..gateway import host_spool", …) and the existence guard immediately caught
// one of them dead — it lived in the very file whose deletion started this.
// Enumerating import spellings is the same brittleness one level down.
// `host_spool` covers the Rust helper, the Python module and every way of
// importing it, because all of them contain it.
var spoolHelpers = []string{
	"host_spool", // Rust host_spool_write_command + the Python module and its importers
	// "write_spool_command" left with its only caller,
	// POST /api/v1/settings/restart-gateway (the legacy dashboard's button).
}

// producerRoots are the trees that may contain spool writers. Scoped rather
// than scanning the repo: docs and this test file quote op names in prose, and
// a parity report with phantom entries in it is a report people learn to
// ignore — at which point a real drift sits in the same list unnoticed.
var producerRoots = []string{"gateway-rust/src", "src/noomesh"}

// discoverProducers returns path → contents for every file under
// producerRoots that mentions a spool helper.
func discoverProducers(t *testing.T, root string) map[string]string {
	t.Helper()
	found := map[string]string{}
	for _, sub := range producerRoots {
		base := filepath.Join(root, sub)
		err := filepath.WalkDir(base, func(path string, d fs.DirEntry, err error) error {
			if err != nil {
				return err
			}
			if d.IsDir() {
				if d.Name() == "tests" || d.Name() == "__pycache__" {
					return filepath.SkipDir
				}
				return nil
			}
			ext := filepath.Ext(path)
			if ext != ".rs" && ext != ".py" {
				return nil
			}
			if strings.HasSuffix(d.Name(), "_test.py") {
				return nil
			}
			b, err := os.ReadFile(path)
			if err != nil {
				return err
			}
			src := string(b)
			for _, h := range spoolHelpers {
				if strings.Contains(src, h) {
					rel, _ := filepath.Rel(root, path)
					found[rel] = src
					return nil
				}
			}
			return nil
		})
		if err != nil {
			t.Fatalf("walking %s: %v", sub, err)
		}
	}
	return found
}

// A renamed helper would make discovery match zero files, and a test that
// finds nothing to check passes. This is the guard for that: each identifier
// must still exist somewhere in the tree.
func TestEveryKnownSpoolHelperStillExists(t *testing.T) {
	root := repoRoot(t)
	producers := discoverProducers(t, root)
	all := strings.Builder{}
	for _, src := range producers {
		all.WriteString(src)
	}
	// The definition sites live in the producer trees too, so a helper with
	// zero occurrences means it was renamed or removed outright.
	for _, h := range spoolHelpers {
		if !strings.Contains(all.String(), h) {
			t.Errorf("spool helper %q appears nowhere under %v — it was renamed or removed. "+
				"Update spoolHelpers, or producer discovery silently stops finding callers.",
				h, producerRoots)
		}
	}
}

func TestEveryOpAProducerRequestsHasAHandler(t *testing.T) {
	root := repoRoot(t)
	producers := discoverProducers(t, root)

	// Floors. Discovery replaced a static list precisely so it could not rot,
	// but the failure mode it trades into is subtler — a pattern that stops
	// matching leaves the test green and checking nothing. These numbers are
	// well below the real counts (8 producer files, 8 ops at the time of
	// writing); they are a "this obviously broke" tripwire, not a target.
	if len(producers) < 5 {
		t.Fatalf("discovered only %d spool producers under %v (expected 5+) — "+
			"discovery is broken, not the codebase: %v",
			len(producers), producerRoots, sortedNames(producers))
	}

	requested := map[string][]string{}
	for rel, src := range producers {
		for _, re := range producerPatterns {
			for _, m := range re.FindAllStringSubmatch(src, -1) {
				requested[m[1]] = append(requested[m[1]], rel)
			}
		}
	}
	if len(requested) < 6 {
		t.Fatalf("extracted only %d distinct ops from %d producers (expected 6+) — "+
			"the extraction patterns have rotted", len(requested), len(producers))
	}

	for op, sites := range requested {
		if _, ok := LookupOp(op); !ok {
			t.Errorf("producers request op %q (%s) but noo-hostd has no handler — "+
				"that request will be rejected as \"invalid op\" and the caller will "+
				"wait forever for a result file", op, strings.Join(uniq(sites), ", "))
		}
	}
	t.Logf("%d producers request %d distinct ops: %v",
		len(producers), len(requested), sortedKeys(requested))
}

func uniq(in []string) []string {
	seen := map[string]bool{}
	var out []string
	for _, s := range in {
		if !seen[s] {
			seen[s] = true
			out = append(out, s)
		}
	}
	return out
}

func sortedKeys(m map[string][]string) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

func sortedNames(m map[string]string) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}
