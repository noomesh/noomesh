// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 PersonifAI LLC

package metrics

// The agent's own resident memory and CPU, and the systemd units noomesh
// runs on this node (the agent, the harness, hostd), for /metrics.
//
// The 2026-11-11 efficiency survey (noomesh-internal i658) could not measure
// any of them: the agent exported no process_* series, and the harness has
// no metrics server at all. A unit's cgroup (v2) is the honest figure: it
// counts every process the unit runs (the harness's jailed CLIs too), and
// it keeps a peak and a swap figure that a process RSS cannot.
//
// Unknown is omitted, never exported as 0: an idle-looking zero would hide
// a missing cgroup or a different init.

import (
	"bufio"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
)

// NoomeshUnits are the systemd units whose cgroups /metrics reports.
var NoomeshUnits = []string{"noo-node-agent", "noo-harness", "noo-hostd"}

// UnitStats is one unit's cgroup v2 figures; nil means unknown.
type UnitStats struct {
	Unit        string
	MemoryBytes *uint64 // memory.current
	SwapBytes   *uint64 // memory.swap.current
	PeakBytes   *uint64 // memory.peak (kernel 5.19+)
	CPUSeconds  *float64
}

// ProcSelf is this process's resident memory and CPU time.
type ProcSelf struct {
	ResidentBytes uint64
	CPUSeconds    float64
}

func readUint(path string) *uint64 {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil
	}
	v, err := strconv.ParseUint(strings.TrimSpace(string(b)), 10, 64)
	if err != nil {
		return nil
	}
	return &v
}

// cpuUsageSeconds reads usage_usec from a cgroup's cpu.stat.
func cpuUsageSeconds(path string) *float64 {
	f, err := os.Open(path)
	if err != nil {
		return nil
	}
	defer f.Close()
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		if v, ok := strings.CutPrefix(sc.Text(), "usage_usec "); ok {
			n, err := strconv.ParseUint(strings.TrimSpace(v), 10, 64)
			if err != nil {
				return nil
			}
			s := float64(n) / 1e6
			return &s
		}
	}
	return nil
}

// ReadUnitStats reads each unit under cgroupRoot (normally /sys/fs/cgroup).
// A unit whose directory is absent (not installed, cgroup v1, a Mac) is
// left out.
func ReadUnitStats(cgroupRoot string, units []string) []UnitStats {
	var out []UnitStats
	for _, u := range units {
		dir := filepath.Join(cgroupRoot, "system.slice", u+".service")
		if st, err := os.Stat(dir); err != nil || !st.IsDir() {
			continue
		}
		s := UnitStats{
			Unit:        u,
			MemoryBytes: readUint(filepath.Join(dir, "memory.current")),
			SwapBytes:   readUint(filepath.Join(dir, "memory.swap.current")),
			PeakBytes:   readUint(filepath.Join(dir, "memory.peak")),
			CPUSeconds:  cpuUsageSeconds(filepath.Join(dir, "cpu.stat")),
		}
		if s.MemoryBytes == nil && s.CPUSeconds == nil {
			continue
		}
		out = append(out, s)
	}
	return out
}

// ParseProcSelf combines /proc/self/statm and /proc/self/stat. The command
// name in stat is parenthesised and may hold spaces or ')', so the fields
// are counted from after the LAST ')'.
func ParseProcSelf(statm, stat string, pageSize, ticksPerSec uint64) (ProcSelf, bool) {
	if pageSize == 0 || ticksPerSec == 0 {
		return ProcSelf{}, false
	}
	m := strings.Fields(statm)
	if len(m) < 2 {
		return ProcSelf{}, false
	}
	pages, err := strconv.ParseUint(m[1], 10, 64)
	if err != nil {
		return ProcSelf{}, false
	}
	i := strings.LastIndexByte(stat, ')')
	if i < 0 {
		return ProcSelf{}, false
	}
	f := strings.Fields(stat[i+1:])
	// Field 3 (state) is f[0]; field N is f[N-3]. utime 14, stime 15.
	if len(f) < 13 {
		return ProcSelf{}, false
	}
	ut, err1 := strconv.ParseUint(f[14-3], 10, 64)
	st, err2 := strconv.ParseUint(f[15-3], 10, 64)
	if err1 != nil || err2 != nil {
		return ProcSelf{}, false
	}
	return ProcSelf{ResidentBytes: pages * pageSize, CPUSeconds: float64(ut+st) / float64(ticksPerSec)}, true
}

// ReadProcSelf reads this process's figures under procRoot (normally /proc).
// Linux's page size and USER_HZ (100) are the kernel ABI here.
func ReadProcSelf(procRoot string) (ProcSelf, bool) {
	statm, err := os.ReadFile(filepath.Join(procRoot, "self", "statm"))
	if err != nil {
		return ProcSelf{}, false
	}
	stat, err := os.ReadFile(filepath.Join(procRoot, "self", "stat"))
	if err != nil {
		return ProcSelf{}, false
	}
	return ParseProcSelf(string(statm), string(stat), uint64(os.Getpagesize()), 100)
}

// ProcessMetricsText renders the agent's own process_* lines and the
// noo_unit_* lines; unknown figures are omitted.
func ProcessMetricsText(nodeID string, self ProcSelf, haveSelf bool, units []UnitStats) string {
	var b strings.Builder
	if haveSelf {
		b.WriteString("# TYPE process_resident_memory_bytes gauge\n")
		fmt.Fprintf(&b, "process_resident_memory_bytes %d\n", self.ResidentBytes)
		b.WriteString("# TYPE process_cpu_seconds_total counter\n")
		fmt.Fprintf(&b, "process_cpu_seconds_total %g\n", self.CPUSeconds)
	}
	type series struct {
		name, kind, help string
		val              func(UnitStats) (string, bool)
	}
	u64 := func(p *uint64) (string, bool) {
		if p == nil {
			return "", false
		}
		return strconv.FormatUint(*p, 10), true
	}
	all := []series{
		{"noo_unit_memory_bytes", "gauge", "A noomesh systemd unit's cgroup memory.current", func(u UnitStats) (string, bool) { return u64(u.MemoryBytes) }},
		{"noo_unit_swap_bytes", "gauge", "A noomesh systemd unit's cgroup memory.swap.current", func(u UnitStats) (string, bool) { return u64(u.SwapBytes) }},
		{"noo_unit_memory_peak_bytes", "gauge", "A noomesh systemd unit's cgroup memory.peak since it started", func(u UnitStats) (string, bool) { return u64(u.PeakBytes) }},
		{"noo_unit_cpu_seconds_total", "counter", "A noomesh systemd unit's cgroup CPU time", func(u UnitStats) (string, bool) {
			if u.CPUSeconds == nil {
				return "", false
			}
			return strconv.FormatFloat(*u.CPUSeconds, 'g', -1, 64), true
		}},
	}
	for _, s := range all {
		wrote := false
		for _, u := range units {
			v, ok := s.val(u)
			if !ok {
				continue
			}
			if !wrote {
				fmt.Fprintf(&b, "# HELP %s %s\n# TYPE %s %s\n", s.name, s.help, s.name, s.kind)
				wrote = true
			}
			fmt.Fprintf(&b, "%s{node_id=%q,unit=%q} %s\n", s.name, nodeID, u.Unit, v)
		}
	}
	return b.String()
}
