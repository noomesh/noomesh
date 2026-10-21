// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 PersonifAI LLC

package gpuyield

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/noomesh/noomesh/node-agent-go/internal/docker"
)

const (
	embedID  = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
	oldID    = "cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc"
	voiceID  = "dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd"
	scopeFmt = "0::/system.slice/docker-%s.scope\n"
)

func scope(id string) string { return strings.Replace(scopeFmt, "%s", id, 1) }

// smiOutput builds the two nvidia-smi queries a 6 GiB 3060 would answer.
func smiProbe(used int, apps string) *SMIProbe {
	return &SMIProbe{goos: "linux", run: func(args ...string) (string, error) {
		if strings.HasPrefix(args[0], "--query-gpu") {
			return itoa(used) + ", 6144\n", nil
		}
		return apps, nil
	}}
}

func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	var b []byte
	for ; n > 0; n /= 10 {
		b = append([]byte{byte('0' + n%10)}, b...)
	}
	return string(b)
}

// controllerRig: pop-os. The agent's chat backend noo-llamacpp is stopped or
// on CPU; the compose stack's GPU embedder noo-ollama-embed and an older
// name-only noo-ollama hold the GPU.
func controllerRig(probe Probe, cg map[int]string) (*Controller, *fakeDocker, *clock) {
	d := &fakeDocker{
		ctrs: []docker.GPUBackend{{Backend: "ollama", ID: oldID, Name: "noo-ollama", Running: true}},
		owned: []docker.NoomeshContainer{
			{ID: embedID, Name: "noo-ollama-embed", Running: true, GPU: true},
			{ID: oldID, Name: "noo-ollama", Running: true, GPU: true, Orphan: true},
		},
	}
	clk := &clock{t: time.Date(2026, 10, 21, 12, 0, 0, 0, time.UTC)}
	c := New(ConfigFromEnv(env(nil)), probe, d, "")
	c.now = clk.now
	c.since = clk.now()
	c.cgroupOf = func(pid int) string { return cg[pid] }
	return c, d, clk
}

func TestComposeEmbedderIsNoomeshNotForeign(t *testing.T) {
	// The live 2026-10-21 reading: two llama-server processes, 3078 + 676 MiB.
	cg := map[int]string{11: scope(embedID), 12: scope(oldID)}
	c, d, clk := controllerRig(smiProbe(3754, "11, 3078\n12, 676\n"), cg)
	tickFor(c, clk, 300*time.Second)
	r := c.Report()
	if r.State != StateFree || len(d.stops) != 0 {
		t.Fatalf("own containers must not yield the node to itself: %+v stops=%v", r, d.stops)
	}
	if r.ForeignMB != 0 || r.NoomeshMB != 3754 || r.UnknownMB != 0 || r.Method != MethodSMI {
		t.Fatalf("want foreign 0 / noomesh 3754 / nvidia-smi, got %+v", r)
	}
	if len(r.Orphan) != 1 || r.Orphan[0] != "noo-ollama" {
		t.Fatalf("the name-only noo-ollama must be flagged orphan, got %v", r.Orphan)
	}
}

func TestForeignProcessBesideComposeEmbedderStillYields(t *testing.T) {
	cg := map[int]string{11: scope(embedID), 12: scope(oldID), 99: scope(voiceID), 98: "0::/user.slice/app.scope\n"}
	// foreign = pai-voice container (2500) + a desktop app (900) = 3400 > 2048
	c, d, clk := controllerRig(smiProbe(3754+3400, "11, 3078\n12, 676\n99, 2500\n98, 900\n"), cg)
	c.Tick(context.Background())
	if r := c.Report(); r.ForeignMB != 3400 || r.NoomeshMB != 3754 || r.Method != MethodSMI {
		t.Fatalf("foreign must count only the non-noomesh processes: %+v", r)
	}
	clk.advance(60 * time.Second)
	c.Tick(context.Background())
	r := c.Report()
	if r.State != StateYielded || len(d.stops) != 1 || d.stops[0] != oldID {
		t.Fatalf("real foreign use must still yield: %+v stops=%v", r, d.stops)
	}
	if !strings.Contains(r.Reason, "foreign GPU use 3.3 GB") {
		t.Fatalf("reason: %q", r.Reason)
	}
}

func TestUnknownAttributionFailsSafeAndSaysSo(t *testing.T) {
	tests := []struct {
		name    string
		cg      map[int]string
		ownErr  error
		wantUnk int
	}{
		{"pid gone (cgroup unreadable)", map[int]string{11: scope(embedID), 12: scope(oldID)}, nil, 5000},
		{"docker cannot list containers", map[int]string{11: scope(embedID), 12: scope(oldID), 77: scope(voiceID)}, errors.New("permission denied"), 3078 + 5000},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			apps := "11, 3078\n12, 676\n77, 5000\n"
			if tc.ownErr == nil {
				apps = "11, 3078\n12, 676\n55, 5000\n" // pid 55 has no cgroup entry
			}
			c, d, clk := controllerRig(smiProbe(3754+5000, apps), tc.cg)
			d.ownedErr = tc.ownErr
			tickFor(c, clk, 300*time.Second)
			r := c.Report()
			if r.State == StateYielded || len(d.stops) != 0 {
				t.Fatalf("unknown attribution must not yield: %+v", r)
			}
			if r.ForeignMB != 0 || r.UnknownMB != tc.wantUnk {
				t.Fatalf("unknown must be reported apart from foreign: %+v", r)
			}
			if r.Method != MethodSMIUnattributed || !strings.Contains(r.Reason, "attribution unknown") {
				t.Fatalf("method/reason must say attribution was unknown: %q %q", r.Method, r.Reason)
			}
		})
	}
}

func TestYieldedNodeStaysPausedWhileAttributionIsUnknown(t *testing.T) {
	cg := map[int]string{11: scope(embedID), 12: scope(oldID), 98: "0::/user.slice/app.scope\n"}
	probe := &fakeProbe{r: Reading{Measured: true, TotalMB: 6144, UsedMB: 7000, AppsResolved: true,
		Apps: []ComputeApp{{11, 3078}, {12, 676}, {98, 3200}}}}
	c, d, clk := controllerRig(probe, cg)
	tickFor(c, clk, 90*time.Second)
	if c.Report().State != StateYielded {
		t.Fatalf("setup: want yielded, got %+v", c.Report())
	}
	// The foreign app's pid vanishes from the cgroup table: unknown, not clear.
	delete(cg, 98)
	tickFor(c, clk, 600*time.Second)
	if r := c.Report(); r.State != StateYielded || len(d.starts) != 0 {
		t.Fatalf("must not resume on a GPU whose use it cannot attribute: %+v starts=%v", r, d.starts)
	}
}

func TestPidlessDriverWithStackEmbedderIsUnknownNotForeign(t *testing.T) {
	// WSL2-style "[Not Found]" rows: only memory accounting is possible, and
	// the compose embedder's footprint is not in the backends' expectation.
	probe := smiProbe(3754, "[Not Found], [N/A]\n")
	c, d, clk := controllerRig(probe, nil)
	d.ctrs, d.owned = nil, []docker.NoomeshContainer{{ID: embedID, Name: "noo-ollama-embed", Running: true, GPU: true}}
	tickFor(c, clk, 300*time.Second)
	r := c.Report()
	if r.State == StateYielded || r.ForeignMB != 0 || r.UnknownMB != 3754 || r.Method != MethodAccountingUnattributed {
		t.Fatalf("want unknown 3754 and no yield, got %+v", r)
	}
}

func TestPidlessDriverWithNothingOfOursStillCountsForeign(t *testing.T) {
	probe := smiProbe(3500, "[Not Found], [N/A]\n")
	c, d, clk := controllerRig(probe, nil)
	d.ctrs, d.owned = nil, nil
	tickFor(c, clk, 90*time.Second)
	if r := c.Report(); r.State != StateYielded && r.State != StateShared || r.ForeignMB != 3500 || r.Method != MethodAccounting {
		t.Fatalf("no noomesh GPU container: remaining use is foreign: %+v", r)
	}
}

func TestMacUnifiedMemoryIsStillNotMeasured(t *testing.T) {
	p := &SMIProbe{goos: "darwin", run: func(...string) (string, error) { t.Fatal("must not call nvidia-smi"); return "", nil }}
	c, d, clk := controllerRig(p, nil)
	tickFor(c, clk, 300*time.Second)
	r := c.Report()
	if r.State != StateFree || r.Method != MethodNotMeasured || r.ForeignMB != 0 || r.UnknownMB != 0 || len(d.stops) != 0 {
		t.Fatalf("mac must be unchanged: %+v", r)
	}
}
