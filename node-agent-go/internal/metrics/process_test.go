// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 PersonifAI LLC

package metrics

import (
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

// The 2026-11-11 survey's real awolf figures, as cgroup v2 files.
func fakeCgroup(t *testing.T) string {
	t.Helper()
	root := t.TempDir()
	write := func(unit, file, body string) {
		dir := filepath.Join(root, "system.slice", unit+".service")
		if err := os.MkdirAll(dir, 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(dir, file), []byte(body), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	write("noo-harness", "memory.current", "3526656\n")
	write("noo-harness", "memory.swap.current", "3040870\n")
	write("noo-harness", "memory.peak", "55513088\n")
	write("noo-harness", "cpu.stat", "usage_usec 1711766\nuser_usec 1200000\nsystem_usec 511766\n")
	write("noo-node-agent", "memory.current", "45309952\n")
	write("noo-node-agent", "cpu.stat", "usage_usec 1135038018\n")
	// noo-hostd: installed but this kernel has no memory.peak; the rest reads.
	write("noo-hostd", "memory.current", "91500000\n")
	return root
}

func TestUnitStatsReadTheRealFiguresAndSkipWhatIsAbsent(t *testing.T) {
	got := ReadUnitStats(fakeCgroup(t), []string{"noo-node-agent", "noo-harness", "noo-hostd", "noo-not-installed"})
	if len(got) != 3 {
		t.Fatalf("want 3 installed units, got %d: %+v", len(got), got)
	}
	h := got[1]
	if h.Unit != "noo-harness" || *h.MemoryBytes != 3526656 || *h.SwapBytes != 3040870 || *h.PeakBytes != 55513088 {
		t.Fatalf("harness: %+v", h)
	}
	if h.CPUSeconds == nil || *h.CPUSeconds != 1.711766 {
		t.Fatalf("harness cpu: %v", h.CPUSeconds)
	}
	if got[2].PeakBytes != nil || got[2].CPUSeconds != nil {
		t.Fatalf("hostd: absent files must stay unknown, got %+v", got[2])
	}
}

func TestTheMetricsTextNamesEachUnitAndOmitsTheUnknown(t *testing.T) {
	units := ReadUnitStats(fakeCgroup(t), NoomeshUnits)
	text := ProcessMetricsText("awolf", ProcSelf{ResidentBytes: 30000000, CPUSeconds: 1.5}, true, units)
	for _, want := range []string{
		"process_resident_memory_bytes 30000000\n",
		"# TYPE process_cpu_seconds_total counter\nprocess_cpu_seconds_total 1.5\n",
		`noo_unit_memory_bytes{node_id="awolf",unit="noo-harness"} 3526656`,
		`noo_unit_swap_bytes{node_id="awolf",unit="noo-harness"} 3040870`,
		`noo_unit_memory_peak_bytes{node_id="awolf",unit="noo-harness"} 55513088`,
		`noo_unit_cpu_seconds_total{node_id="awolf",unit="noo-node-agent"} 1135.038018`,
		`noo_unit_memory_bytes{node_id="awolf",unit="noo-hostd"} 91500000`,
	} {
		if !strings.Contains(text, want) {
			t.Fatalf("missing %q in:\n%s", want, text)
		}
	}
	if strings.Contains(text, `unit="noo-hostd"} 0`) || strings.Count(text, `noo_unit_memory_peak_bytes{`) != 1 {
		t.Fatalf("an unknown figure was exported:\n%s", text)
	}
	if strings.Count(text, "# TYPE noo_unit_memory_bytes gauge") != 1 {
		t.Fatalf("one TYPE line per series:\n%s", text)
	}
	if got := ProcessMetricsText("n", ProcSelf{}, false, nil); got != "" {
		t.Fatalf("nothing known, nothing exported: %q", got)
	}
}

func TestProcSelfCountsFieldsFromTheLastParenthesis(t *testing.T) {
	stat := "4242 (noo agent (x)) S 1 4242 4242 0 -1 4194560 2981 0 0 0 150 50 0 0 20 0 9 0 12345 1 1"
	p, ok := ParseProcSelf("30000 5000 1200 300 0 9000 0\n", stat, 4096, 100)
	if !ok || p.ResidentBytes != 5000*4096 || p.CPUSeconds != 2 {
		t.Fatalf("got %+v %v", p, ok)
	}
	for _, bad := range [][2]string{{"", stat}, {"1 2", "no paren"}, {"1 2", "1 (x) S 1"}} {
		if _, ok := ParseProcSelf(bad[0], bad[1], 4096, 100); ok {
			t.Fatalf("malformed accepted: %q / %q", bad[0], bad[1])
		}
	}
}

func TestTheLiveReadWorksOnLinux(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("/proc is linux")
	}
	p, ok := ReadProcSelf("/proc")
	if !ok || p.ResidentBytes < 1<<20 {
		t.Fatalf("live read: %+v %v", p, ok)
	}
}
