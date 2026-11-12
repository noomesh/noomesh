// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 PersonifAI LLC

package egressfilter

import (
	"context"
	"errors"
	"io"
	"strings"
	"sync"
	"testing"
	"time"
)

// writeTokens is the test's OWN list of firewall/docker write verbs, kept
// separate from guard.go so a hole in the guard cannot also hide from the
// test that watches it.
var writeTokens = map[string]bool{
	"-A": true, "-I": true, "-D": true, "-R": true, "-N": true, "-X": true, "-F": true, "-Z": true, "-P": true,
	"add": true, "create": true, "delete": true, "flush": true, "insert": true, "replace": true,
	"connect": true, "disconnect": true, "rm": true, "prune": true, "-f": true, "-w": true,
}

// fakeRunner answers from a table, records every call, and fails the test
// on a write verb or on iptables-restore.
type fakeRunner struct {
	t     *testing.T
	mu    sync.Mutex
	table map[string]fakeAns // key: "name arg arg"
	calls []string
}

type fakeAns struct {
	rc  int
	out string
}

func newFake(t *testing.T, table map[string]fakeAns) *fakeRunner {
	return &fakeRunner{t: t, table: table}
}

func (f *fakeRunner) Capture(ctx context.Context, dir, name string, args ...string) (int, string) {
	f.t.Helper()
	f.mu.Lock()
	defer f.mu.Unlock()
	key := strings.TrimSpace(name + " " + strings.Join(args, " "))
	f.calls = append(f.calls, key)
	if strings.Contains(name, "restore") {
		f.t.Errorf("WRITE: %s", key)
	}
	for _, a := range args {
		if writeTokens[a] {
			f.t.Errorf("WRITE verb %q in: %s", a, key)
		}
	}
	// docker network inspect takes many names; match on the prefix.
	for k, ans := range f.table {
		if k == key || (strings.HasPrefix(key, "docker network inspect") && k == "docker network inspect") {
			return ans.rc, ans.out
		}
	}
	return 127, "" // absent
}

// memSysctl records every Set.
type memSysctl struct {
	val     string
	sets    []string
	getErr  error
	setErr  error
	restErr error // fail the restore (a Set back to the original)
	orig    string
}

func (m *memSysctl) Get() (string, error) {
	if m.getErr != nil {
		return "", m.getErr
	}
	return m.val + "\n", nil
}

func (m *memSysctl) Set(v string) error {
	if m.setErr != nil {
		return m.setErr
	}
	if m.restErr != nil && v == m.orig {
		return m.restErr
	}
	m.sets = append(m.sets, v)
	m.val = v
	return nil
}

// feedStream returns lines, then blocks until the context ends (like conntrack).
func feedStream(lines []string, startErr error, dieEarly bool) Streamer {
	return func(ctx context.Context, name string, args ...string) (io.ReadCloser, func() error, func() string, error) {
		if startErr != nil {
			return nil, nil, nil, startErr
		}
		pr, pw := io.Pipe()
		go func() {
			for _, l := range lines {
				_, _ = pw.Write([]byte(l + "\n"))
			}
			if dieEarly {
				_ = pw.Close()
				return
			}
			<-ctx.Done()
			_ = pw.Close()
		}()
		return pr, func() error {
			if dieEarly {
				return errors.New("exit status 1")
			}
			return nil
		}, func() string { return "conntrack: Operation not permitted" }, nil
	}
}

// clock is a controllable now().
type clock struct{ t time.Time }

func (c *clock) Now() time.Time { return c.t }
