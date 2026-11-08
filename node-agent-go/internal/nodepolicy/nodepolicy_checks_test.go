// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 PersonifAI LLC

package nodepolicy

import (
	"context"
	"errors"
	"math"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/noomesh/noomesh/node-agent-go/internal/nodewl"
)

// Each test here pins ONE check that the broader tests above cannot see on
// their own because a neighbouring layer gives the same answer (a corrupt file
// that reads as "nothing approved" still refuses in approve mode; Add and List
// both sort; and so on). They were found by removing each check alone.

// ---- approvals file: every way a file can be corrupt is an ERROR -----------

func TestEveryKindOfCorruptApprovalsFileIsAnErrorNotAnEmptyList(t *testing.T) {
	good := `{"addon":"rhaddon","digest":"` + digestA + `"}`
	for name, content := range map[string]string{
		"not json":                   `{not json`,
		"empty file":                 ``,
		"an unknown top-level field": `{"version":1,"approvals":[` + good + `],"extra":true}`,
		"an unknown field in a row":  `{"version":1,"approvals":[{"addon":"rhaddon","digest":"` + digestA + `","extra":1}]}`,
		"a row with an invalid name": `{"version":1,"approvals":[{"addon":"Rh_Addon","digest":"` + digestA + `"}]}`,
		"a row with an invalid hash": `{"version":1,"approvals":[{"addon":"rhaddon","digest":"sha256:abc"}]}`,
		"a row after a good one":     `{"version":1,"approvals":[` + good + `,{"addon":"","digest":"` + digestB + `"}]}`,
	} {
		t.Run(name, func(t *testing.T) {
			dir := t.TempDir()
			if err := os.WriteFile(filepath.Join(dir, ApprovalsFile), []byte(content), 0o600); err != nil {
				t.Fatal(err)
			}
			ap := NewApprovals(dir)
			if list, err := ap.List(); err == nil {
				t.Errorf("List read it as %v", list)
			}
			// Has must say "cannot tell" (an error), not "no" and never "yes".
			if ok, err := ap.Has("rhaddon", digestA); err == nil || ok {
				t.Errorf("Has = %v, %v; want false and an error", ok, err)
			}
			if err := ap.Add("rhaddon", digestB); err == nil {
				t.Error("Add went on over a corrupt file")
			}
		})
	}
}

func TestANullApprovalsListReadsAsAKnownEmptyList(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, ApprovalsFile), []byte(`{"version":1,"approvals":null}`), 0o600); err != nil {
		t.Fatal(err)
	}
	list, err := NewApprovals(dir).List()
	if err != nil || list == nil || len(list) != 0 {
		t.Fatalf("List = %#v, %v; want a non-nil empty list (the heartbeat sends [] not null)", list, err)
	}
}

func TestApprovalsAreSortedWhenReadAndWhenWritten(t *testing.T) {
	dir := t.TempDir()
	unsorted := `{"version":1,"approvals":[` +
		`{"addon":"zeta","digest":"` + digestA + `"},` +
		`{"addon":"alpha","digest":"` + digestB + `"},` +
		`{"addon":"alpha","digest":"` + digestA + `"}]}`
	if err := os.WriteFile(filepath.Join(dir, ApprovalsFile), []byte(unsorted), 0o600); err != nil {
		t.Fatal(err)
	}
	ap := NewApprovals(dir)
	want := []Approval{{"alpha", digestA}, {"alpha", digestB}, {"zeta", digestA}}
	if list, err := ap.List(); err != nil || !reflect.DeepEqual(list, want) {
		t.Fatalf("List = %v, %v; want %v", list, err, want)
	}
	// Add writes a sorted file (not just a sorted read of it).
	if err := ap.Add("beta", digestA); err != nil {
		t.Fatal(err)
	}
	raw, err := os.ReadFile(filepath.Join(dir, ApprovalsFile))
	if err != nil {
		t.Fatal(err)
	}
	last := -1
	for _, a := range []string{"alpha", "beta", "zeta"} {
		i := strings.Index(string(raw), `"addon":"`+a+`"`)
		if i < 0 || i < last {
			t.Fatalf("the file is not written in order (%s at %d, previous at %d): %s", a, i, last, raw)
		}
		last = i
	}
}

// Add replaces the file by renaming a finished temp file over it. It never
// writes through the path: a symlink at the path is replaced, and what it
// pointed to is left alone.
func TestAddReplacesTheFileInsteadOfWritingThroughIt(t *testing.T) {
	dir := t.TempDir()
	victim := filepath.Join(dir, "victim")
	// A dangling symlink reads as "no file yet"; writing through it would
	// create its target.
	if err := os.Symlink(victim, filepath.Join(dir, ApprovalsFile)); err != nil {
		t.Skipf("no symlinks here: %v", err)
	}
	if err := NewApprovals(dir).Add("rhaddon", digestA); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Lstat(victim); err == nil {
		t.Fatal("Add wrote through the symlink and created its target")
	}
	fi, err := os.Lstat(filepath.Join(dir, ApprovalsFile))
	if err != nil || fi.Mode()&os.ModeSymlink != 0 || fi.Mode().Perm() != 0o600 {
		t.Fatalf("the approvals path is %v, %v; want a regular 0600 file", fi, err)
	}
}

// ---- the gate: checks a neighbour used to mask ------------------------------

func TestUnreadableApprovalsRefuseSayingSo(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, ApprovalsFile), []byte("{not json"), 0o600); err != nil {
		t.Fatal(err)
	}
	g := &Gate{Mode: ModeApprove, Approvals: NewApprovals(dir)}
	err := g.Check(context.Background(), entry("rhaddon", digestA))
	var ne *nodewl.Error
	if !errors.As(err, &ne) || ne.Code != nodewl.ReasonConsentUnapproved || !strings.Contains(ne.Detail, "cannot be read") {
		t.Fatalf("err = %v; want consent_unapproved naming the unreadable file (not 'not approved')", err)
	}
}

func TestACPUWorkloadIsNotRefusedForTheComputeCapability(t *testing.T) {
	cpu := gpuEntry()
	cpu.Decl.Accel.GPU = 0
	if err := autoGate("5.0", nil, "9.0").Check(context.Background(), cpu); err != nil {
		t.Fatalf("a CPU workload was refused for a GPU's compute capability: %v", err)
	}
}

func TestOnlyTheChosenProfilesMinimumApplies(t *testing.T) {
	g := autoGate("8.0", nil, "")
	g.MainSet = func(string, string) (nodewl.ModelSet, error) {
		return nodewl.ModelSet{ID: "s", Revision: "r1", Needs: nodewl.Needs{Profiles: []nodewl.Profile{
			{Name: "fp16", Accel: "gpu", MinCompute: "7.0"},
			{Name: "int8", Accel: "gpu", MinCompute: "7.5"},
			{Name: "fp8", Accel: "gpu", MinCompute: "9.0"},
		}}}, nil
	}
	e := gpuEntry() // chooses int8
	if err := g.Check(context.Background(), e); err != nil {
		t.Fatalf("refused against another profile's minimum: %v", err)
	}
	fp8 := "fp8"
	e.Profile = &fp8
	if code := nodewl.CodeOf(g.Check(context.Background(), e)); code != nodewl.ReasonComputeCapLow {
		t.Fatalf("code = %q, want compute_cap_low for fp8 on 8.0", code)
	}
}

// A set the node cannot read is "not available yet" whatever the reader also
// returned with the error; a set that lists no profiles puts nothing on the
// entry's profile. Neither is the gate's refusal.
func TestAnUnavailableSetOrOneWithoutProfilesIsNotTheGatesRefusal(t *testing.T) {
	incompatible := nodewl.ModelSet{ID: "s", Revision: "r1", Needs: nodewl.Needs{Profiles: []nodewl.Profile{
		{Name: "other", Accel: "gpu", MinCompute: "9.0"},
	}}}
	g := autoGate("1.0", nil, "9.0")
	g.MainSet = func(string, string) (nodewl.ModelSet, error) { return incompatible, errors.New("not verified yet") }
	if err := g.Check(context.Background(), gpuEntry()); err != nil {
		t.Fatalf("a set that came with an error was judged: %v", err)
	}
	g.MainSet = func(string, string) (nodewl.ModelSet, error) { return nodewl.ModelSet{ID: "s", Revision: "r1"}, nil }
	if err := g.Check(context.Background(), gpuEntry()); err != nil {
		t.Fatalf("a set without profiles refused the entry: %v", err)
	}
}

// ---- facts ------------------------------------------------------------------

func TestANonFiniteOrNegativeFreeSpaceIsOmitted(t *testing.T) {
	for name, v := range map[string]float64{"NaN": math.NaN(), "+Inf": math.Inf(1), "-Inf": math.Inf(-1), "negative": -0.5} {
		f := goodFacts(t.TempDir())
		f.DataRootFreeGB = func() (float64, error) { return v, nil }
		if got, has := f.Report(context.Background())["data_root_free_gb"]; has {
			t.Errorf("%s: data_root_free_gb = %v is reported", name, got)
		}
	}
	f := goodFacts(t.TempDir())
	f.DataRootFreeGB = func() (float64, error) { return 0, nil }
	if got, has := f.Report(context.Background())["data_root_free_gb"]; !has || got != 0.0 {
		t.Errorf("a full disk (0 GB) = %v, %v; it is a fact, not an omission", got, has)
	}
}

func TestDataRootFreeGBMeasuresTheResolvedDataRoot(t *testing.T) {
	t.Setenv("NOO_DATA_ROOT", t.TempDir())
	gb, err := DataRootFreeGB()
	if err != nil || gb <= 0 {
		t.Fatalf("DataRootFreeGB = %v, %v; want the free space of the data root", gb, err)
	}
}
