// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 PersonifAI LLC

package nodepolicy

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/noomesh/noomesh/node-agent-go/internal/hardware"
	"github.com/noomesh/noomesh/node-agent-go/internal/nodewl"
)

const (
	digestA = "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	digestB = "sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
)

func entry(addon, digest string) nodewl.Entry {
	return nodewl.Entry{Addon: addon, Image: nodewl.ImageRef{Digest: digest}}
}

// ---- consent -------------------------------------------------------------

func TestConsentModes(t *testing.T) {
	dir := t.TempDir()
	ap := NewApprovals(dir)
	if err := ap.Add("rhaddon", digestA); err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		name string
		mode Mode
		e    nodewl.Entry
		want string // refusal code, "" = admitted
	}{
		{"none refuses an approved entry", ModeNone, entry("rhaddon", digestA), nodewl.ReasonConsentNone},
		{"none refuses an unapproved entry", ModeNone, entry("other", digestB), nodewl.ReasonConsentNone},
		{"an unknown mode is none", Mode("bogus"), entry("rhaddon", digestA), nodewl.ReasonConsentNone},
		{"approve admits the approved pair", ModeApprove, entry("rhaddon", digestA), ""},
		{"approve refuses another add-on", ModeApprove, entry("other", digestA), nodewl.ReasonConsentUnapproved},
		{"approve refuses a new digest of an approved add-on", ModeApprove, entry("rhaddon", digestB), nodewl.ReasonConsentUnapproved},
		{"auto admits an unapproved entry", ModeAuto, entry("other", digestB), ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			g := &Gate{Mode: tc.mode, Approvals: ap}
			err := g.Check(context.Background(), tc.e)
			if got := nodewl.CodeOf(err); got != tc.want {
				t.Fatalf("code = %q (%v), want %q", got, err, tc.want)
			}
		})
	}
}

// Consent that cannot be read cannot be shown: approve mode refuses.
func TestApproveRefusesWhenTheApprovalsFileIsCorrupt(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, ApprovalsFile), []byte("{not json"), 0o600); err != nil {
		t.Fatal(err)
	}
	g := &Gate{Mode: ModeApprove, Approvals: NewApprovals(dir)}
	if code := nodewl.CodeOf(g.Check(context.Background(), entry("rhaddon", digestA))); code != nodewl.ReasonConsentUnapproved {
		t.Fatalf("code = %q", code)
	}
	if g := (&Gate{Mode: ModeApprove}); nodewl.CodeOf(g.Check(context.Background(), entry("rhaddon", digestA))) != nodewl.ReasonConsentUnapproved {
		t.Fatal("approve with no store admitted")
	}
}

func TestParseMode(t *testing.T) {
	for in, want := range map[string]Mode{"": ModeNone, "none": ModeNone, "approve": ModeApprove, " AUTO ": ModeAuto} {
		if m, ok := ParseMode(in); m != want || !ok {
			t.Errorf("ParseMode(%q) = %q, %v", in, m, ok)
		}
	}
	if m, ok := ParseMode("yes"); m != ModeNone || ok {
		t.Errorf("ParseMode(yes) = %q, %v; want none, false", m, ok)
	}
}

// ---- approvals persistence -------------------------------------------------

func TestApprovalsPersistAtomicallyAndPrivately(t *testing.T) {
	dir := t.TempDir()
	ap := NewApprovals(filepath.Join(dir, "state")) // the directory does not exist yet
	if list, err := ap.List(); err != nil || list == nil || len(list) != 0 {
		t.Fatalf("a missing file = %#v, %v; want a known-empty list", list, err)
	}
	if err := ap.Add("rhaddon", digestB); err != nil {
		t.Fatal(err)
	}
	if err := ap.Add("rhaddon", digestA); err != nil {
		t.Fatal(err)
	}
	if err := ap.Add("rhaddon", digestA); err != nil { // a repeat is a no-op
		t.Fatal(err)
	}
	// A new process reads the same answer.
	list, err := NewApprovals(filepath.Join(dir, "state")).List()
	want := []Approval{{"rhaddon", digestA}, {"rhaddon", digestB}}
	if err != nil || !reflect.DeepEqual(list, want) {
		t.Fatalf("list = %v, %v; want %v", list, err, want)
	}
	path := filepath.Join(dir, "state", ApprovalsFile)
	if fi, err := os.Stat(path); err != nil || fi.Mode().Perm() != 0o600 {
		t.Fatalf("%s: %v mode %v, want 0600", path, err, fi)
	}
	// Atomic: no temp file is left beside it.
	ents, _ := os.ReadDir(filepath.Join(dir, "state"))
	if len(ents) != 1 {
		t.Fatalf("state dir holds %d entries, want only the approvals file", len(ents))
	}
	if ok, err := NewApprovals(filepath.Join(dir, "state")).Has("rhaddon", digestA); !ok || err != nil {
		t.Fatalf("Has = %v, %v", ok, err)
	}
	if ok, _ := ap.Has("rhaddon", "sha256:"+strings.Repeat("c", 64)); ok {
		t.Fatal("an unapproved digest is approved")
	}
}

func TestApprovalsRefuseMalformedValuesAndKeepAGoodFile(t *testing.T) {
	dir := t.TempDir()
	ap := NewApprovals(dir)
	if err := ap.Add("rhaddon", digestA); err != nil {
		t.Fatal(err)
	}
	for _, bad := range [][2]string{{"", digestA}, {"Rh_Addon", digestA}, {"rhaddon", "sha256:abc"}, {"rhaddon", strings.ToUpper(digestA)}, {"rhaddon", ""}} {
		if err := ap.Add(bad[0], bad[1]); err == nil {
			t.Errorf("Add(%q, %q) succeeded", bad[0], bad[1])
		}
	}
	if list, _ := ap.List(); len(list) != 1 {
		t.Fatalf("list = %v", list)
	}
	// A corrupt file is an error, never an empty list.
	if err := os.WriteFile(filepath.Join(dir, ApprovalsFile), []byte(`{"version":1,"approvals":[{"addon":"x","digest":"d","extra":1}]}`), 0o600); err != nil {
		t.Fatal(err)
	}
	if list, err := ap.List(); err == nil {
		t.Fatalf("a corrupt file read as %v", list)
	}
	if err := ap.Add("rhaddon", digestB); err == nil {
		t.Fatal("Add overwrote a corrupt file")
	}
}

// ---- the other refusals ----------------------------------------------------

func boolp(b bool) *bool { return &b }

func profileSet(min string) nodewl.ModelSet {
	return nodewl.ModelSet{ID: "s", Revision: "r1", Needs: nodewl.Needs{Profiles: []nodewl.Profile{
		{Name: "int8", Accel: "gpu", MinCompute: min, Realtime: boolp(true)},
	}}}
}

func gpuEntry() nodewl.Entry {
	p := "int8"
	e := entry("rhaddon", digestA)
	e.Decl.Accel.GPU = 1
	e.Decl.Models = []nodewl.Slot{{Slot: "main"}}
	e.Sets = map[string][]nodewl.SetRef{"main": {{ID: "s", Revision: "r1"}}}
	e.Profile = &p
	return e
}

func autoGate(have string, haveErr error, min string) *Gate {
	return &Gate{
		Mode:       ModeAuto,
		ComputeCap: func() (string, error) { return have, haveErr },
		MainSet:    func(string, string) (nodewl.ModelSet, error) { return profileSet(min), nil },
	}
}

func TestComputeCapLowIsNumericNotLexical(t *testing.T) {
	for _, tc := range []struct{ have, min, want string }{
		{"8.6", "8.9", nodewl.ReasonComputeCapLow},
		{"7.5", "8.0", nodewl.ReasonComputeCapLow},
		{"8.9", "8.10", nodewl.ReasonComputeCapLow}, // "8.9" > "8.10" as text, below it as numbers
		{"8.10", "8.9", ""},                         // above as numbers, below as text
		{"10.0", "8.0", ""},                         // "10.0" < "8.0" as text
		{"8.0", "10.0", nodewl.ReasonComputeCapLow},
		{"8.6", "8.6", ""},
		{"8.6", "", ""}, // the profile states no minimum
	} {
		err := autoGate(tc.have, nil, tc.min).Check(context.Background(), gpuEntry())
		if got := nodewl.CodeOf(err); got != tc.want {
			t.Errorf("have %s need %s: code %q (%v), want %q", tc.have, tc.min, got, err, tc.want)
		}
	}
}

// An unknown or unparseable capability is never "low" (the i495 rule).
func TestAnUnknownComputeCapIsNeverLow(t *testing.T) {
	for name, g := range map[string]*Gate{
		"probe error":  autoGate("", errors.New("nvidia-smi timed out"), "8.9"),
		"unparseable":  autoGate("N/A", nil, "8.9"),
		"empty answer": autoGate("", nil, "8.9"),
	} {
		if err := g.Check(context.Background(), gpuEntry()); err != nil {
			t.Errorf("%s: refused with %v", name, err)
		}
	}
}

func TestProfileIsCheckedWithCheckProfile(t *testing.T) {
	e := gpuEntry()
	bad := "nope"
	e.Profile = &bad
	if code := nodewl.CodeOf(autoGate("9.0", nil, "8.0").Check(context.Background(), e)); code != nodewl.ReasonProfileInvalid {
		t.Fatalf("code = %q", code)
	}
	e.Profile = nil
	if code := nodewl.CodeOf(autoGate("9.0", nil, "8.0").Check(context.Background(), e)); code != nodewl.ReasonProfileInvalid {
		t.Fatalf("a missing profile: code = %q", code)
	}
	// A set this node does not hold yet is the provisioner's verdict, not this gate's.
	g := autoGate("1.0", nil, "9.0")
	g.MainSet = func(string, string) (nodewl.ModelSet, error) { return nodewl.ModelSet{}, errors.New("not here") }
	if err := g.Check(context.Background(), gpuEntry()); err != nil {
		t.Fatalf("refused on a set that is not held: %v", err)
	}
}

func TestNvidiaRuntimeMissingRefusesAGPUWorkloadOnly(t *testing.T) {
	g := &Gate{Mode: ModeAuto, NvidiaRuntime: func(context.Context) (bool, error) { return false, nil }}
	if code := nodewl.CodeOf(g.Check(context.Background(), gpuEntry())); code != nodewl.ReasonNvidiaRuntimeMissing {
		t.Fatalf("code = %q", code)
	}
	cpu := gpuEntry()
	cpu.Decl.Accel.GPU = 0
	if err := g.Check(context.Background(), cpu); err != nil {
		t.Fatalf("a CPU workload was refused for the runtime: %v", err)
	}
	// Unknown is not missing.
	g.NvidiaRuntime = func(context.Context) (bool, error) { return false, errors.New("docker info failed") }
	if err := g.Check(context.Background(), gpuEntry()); err != nil {
		t.Fatalf("an unknown runtime refused: %v", err)
	}
}

func TestControllerHostNeedsTheOptIn(t *testing.T) {
	g := &Gate{Mode: ModeAuto, ControllerHost: true}
	if code := nodewl.CodeOf(g.Check(context.Background(), entry("rhaddon", digestA))); code != nodewl.ReasonControllerHost {
		t.Fatalf("code = %q", code)
	}
	g.OnController = true
	if err := g.Check(context.Background(), entry("rhaddon", digestA)); err != nil {
		t.Fatalf("opted in, still refused: %v", err)
	}
	// Consent is judged first and alone.
	g = &Gate{Mode: ModeNone, ControllerHost: true}
	if code := nodewl.CodeOf(g.Check(context.Background(), entry("rhaddon", digestA))); code != nodewl.ReasonConsentNone {
		t.Fatalf("code = %q", code)
	}
}

// ---- facts ------------------------------------------------------------------

func TestMinComputeCapIsNumeric(t *testing.T) {
	for _, tc := range []struct {
		in   []string
		want string
	}{
		{[]string{"8.6"}, "8.6"},
		{[]string{"10.0", "8.9", "8.10"}, "8.9"},
		{[]string{"8.10", "8.9"}, "8.9"},
		{[]string{"9.0", "10.0", "12.0"}, "9.0"},
	} {
		if got, err := MinComputeCap(tc.in); err != nil || got != tc.want {
			t.Errorf("MinComputeCap(%v) = %q, %v; want %q", tc.in, got, err, tc.want)
		}
	}
	for _, bad := range [][]string{nil, {}, {"8.6", "[N/A]"}, {"x"}} {
		if got, err := MinComputeCap(bad); err == nil {
			t.Errorf("MinComputeCap(%v) = %q, want an error (unknown)", bad, got)
		}
	}
}

func goodFacts(dir string) *Facts {
	return &Facts{
		Mode: ModeApprove, Approvals: NewApprovals(dir), ControllerHost: true,
		ComputeCaps:    func() ([]string, error) { return []string{"8.6", "8.9"}, nil },
		NvidiaRuntime:  func(context.Context) (bool, error) { return true, nil },
		DataRootFreeGB: func() (float64, error) { return 412.54, nil },
	}
}

func TestFactsReportEverythingKnown(t *testing.T) {
	dir := t.TempDir()
	f := goodFacts(dir)
	if err := f.Approvals.Add("rhaddon", digestB); err != nil {
		t.Fatal(err)
	}
	got := f.Report(context.Background())
	want := map[string]any{
		"gpu_compute_cap":           "8.6",
		"nvidia_runtime":            true,
		"controller_host":           true,
		"data_root_free_gb":         412.5,
		"addon_workloads_policy":    "approve",
		"addon_workloads_approvals": []Approval{{"rhaddon", digestB}},
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("report = %#v\nwant     %#v", got, want)
	}
	if _, has := got["nvidia_driver_caps_ok"]; has {
		t.Fatal("nvidia_driver_caps_ok is reported, but no sound check exists")
	}
}

// Every fact whose probe fails is OMITTED, never defaulted.
func TestFactsAreOmittedWhenTheirProbeFails(t *testing.T) {
	boom := errors.New("probe failed")
	for key, break_ := range map[string]func(f *Facts){
		"gpu_compute_cap":           func(f *Facts) { f.ComputeCaps = func() ([]string, error) { return nil, boom } },
		"nvidia_runtime":            func(f *Facts) { f.NvidiaRuntime = func(context.Context) (bool, error) { return false, boom } },
		"data_root_free_gb":         func(f *Facts) { f.DataRootFreeGB = func() (float64, error) { return 0, boom } },
		"addon_workloads_approvals": func(f *Facts) { f.Approvals = NewApprovals(filepath.Join(os.DevNull, "x")) },
	} {
		f := goodFacts(t.TempDir())
		break_(f)
		if v, has := f.Report(context.Background())[key]; has {
			t.Errorf("%s = %v is reported although its probe failed", key, v)
		}
	}
	// An unparseable capability from the probe is omitted too.
	f := goodFacts(t.TempDir())
	f.ComputeCaps = func() ([]string, error) { return []string{"8.6", "N/A"}, nil }
	if _, has := f.Report(context.Background())["gpu_compute_cap"]; has {
		t.Error("gpu_compute_cap reported from an unparseable list")
	}
	// No GPU at all (no values) is unknown, not a capability.
	f.ComputeCaps = func() ([]string, error) { return nil, nil }
	if _, has := f.Report(context.Background())["gpu_compute_cap"]; has {
		t.Error("gpu_compute_cap reported with no GPU")
	}
	// Unwired probes report nothing; the policy and controller_host always exist.
	bare := (&Facts{Mode: ModeNone}).Report(context.Background())
	if !reflect.DeepEqual(bare, map[string]any{"addon_workloads_policy": "none", "controller_host": false}) {
		t.Errorf("bare report = %#v", bare)
	}
}

func TestAGoodComputeCapIsKeptAndAFailureIsNotCached(t *testing.T) {
	calls := 0
	f := &Facts{ComputeCaps: func() ([]string, error) {
		calls++
		if calls == 1 {
			return nil, errors.New("timed out")
		}
		return []string{"8.0"}, nil
	}}
	if _, err := f.MinComputeCap(); err == nil {
		t.Fatal("first probe should fail")
	}
	for i := 0; i < 3; i++ {
		if v, err := f.MinComputeCap(); err != nil || v != "8.0" {
			t.Fatalf("got %q, %v", v, err)
		}
	}
	if calls != 2 {
		t.Fatalf("probed %d times, want 2 (a failure retried, a success kept)", calls)
	}
}

func TestFreeGB(t *testing.T) {
	one := func(p []string) []hardware.DiskUsage { return []hardware.DiskUsage{{Path: p[0], AvailGB: 12.25}} }
	if gb, err := FreeGB("/data", one); err != nil || gb != 12.25 {
		t.Fatalf("FreeGB = %v, %v", gb, err)
	}
	none := func([]string) []hardware.DiskUsage { return nil }
	if _, err := FreeGB("/data", none); err == nil {
		t.Fatal("no figures was not an error")
	}
	if _, err := FreeGB("", one); err == nil {
		t.Fatal("no root was not an error")
	}
}
