// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 PersonifAI LLC

package nodewl

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

// The fixtures are a byte-identical copy of tests/fixtures/i300 (the parity
// test tests/test_i300_fixture_parity.py holds them equal); the CLI and the
// gateway read the same files.
const (
	testdata = "testdata/i300"
	// testAgentCN is the CN of the node the desired-config fixtures are for.
	testAgentCN = "node-a"
	// testAddon is the fixture add-on's name (cases.json may override per case).
	testAddon = "rhaddon"
)

type fixtureCase struct {
	File  string `json:"file"`
	Valid bool   `json:"valid"`
	Code  string `json:"code"`
	Addon string `json:"addon"`
	// Set pairs a desired case with a model-set fixture for CheckProfile.
	Set string `json:"set"`
}

func readFile(t *testing.T, rel ...string) []byte {
	t.Helper()
	b, err := os.ReadFile(filepath.Join(append([]string{testdata}, rel...)...))
	if err != nil {
		t.Fatalf("read fixture: %v", err)
	}
	return b
}

func loadCases(t *testing.T, dir string) []fixtureCase {
	t.Helper()
	var cs []fixtureCase
	if err := json.Unmarshal(readFile(t, dir, "cases.json"), &cs); err != nil {
		t.Fatalf("%s/cases.json: %v", dir, err)
	}
	if len(cs) == 0 {
		t.Fatalf("%s/cases.json has no cases", dir)
	}
	// Every fixture file is in cases.json, and every case has its file: a
	// fixture nobody asserts is how a refusal rots.
	listed := map[string]bool{"cases.json": true, "lock.json": true}
	for _, c := range cs {
		listed[c.File] = true
		if c.Valid != (c.Code == "") {
			t.Fatalf("%s/%s: valid=%v with code %q", dir, c.File, c.Valid, c.Code)
		}
	}
	ents, err := os.ReadDir(filepath.Join(testdata, dir))
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range ents {
		if !listed[e.Name()] {
			t.Errorf("%s/%s is not in cases.json", dir, e.Name())
		}
	}
	return cs
}

func check(t *testing.T, c fixtureCase, err error) {
	t.Helper()
	if c.Valid {
		if err != nil {
			t.Errorf("%s: want it to parse, got %v", c.File, err)
		}
		return
	}
	if got := CodeOf(err); got != c.Code {
		t.Errorf("%s: want code %q, got %q (%v)", c.File, c.Code, got, err)
	}
}

func TestNodeWorkloadsFixtures(t *testing.T) {
	var lock struct {
		Images map[string]string `json:"images"`
	}
	if err := json.Unmarshal(readFile(t, "node-workloads", "lock.json"), &lock); err != nil {
		t.Fatal(err)
	}
	for _, c := range loadCases(t, "node-workloads") {
		addon := testAddon
		if c.Addon != "" {
			addon = c.Addon
		}
		ds, err := ParseDecl(addon, readFile(t, "node-workloads", c.File), lock.Images)
		check(t, c, err)
		if c.Valid && len(ds) == 0 {
			t.Errorf("%s: parsed but returned no workloads", c.File)
		}
	}
}

func TestDesiredFixtures(t *testing.T) {
	for _, c := range loadCases(t, "desired") {
		es, err := ParseDesired(readFile(t, "desired", c.File), testAgentCN)
		if err == nil && c.Set != "" {
			// ParseDesired cannot see the set; the pairing is judged by CheckProfile.
			ms, perr := ParseModelSet(readFile(t, filepath.FromSlash(c.Set)))
			if perr != nil || len(es) != 1 {
				t.Fatalf("%s: paired set %s: %v (%d entries)", c.File, c.Set, perr, len(es))
			}
			err = CheckProfile(es[0], *ms)
		}
		check(t, c, err)
		if c.Valid && c.File != "valid-empty.json" && len(es) == 0 {
			t.Errorf("%s: parsed but returned no entries", c.File)
		}
	}
}

func TestDesiredDeclInvalidCarriesTheInnerCode(t *testing.T) {
	_, err := ParseDesired(readFile(t, "desired", "refuse-decl-uid-zero.json"), testAgentCN)
	e, ok := err.(*Error)
	if !ok || e.Code != ReasonDeclInvalid || e.Inner != CodeUIDInvalid {
		t.Fatalf("want decl_invalid(uid_invalid), got %v", err)
	}
}

func TestDesiredExampleIsOneProvisionedAndOneRunning(t *testing.T) {
	es, err := ParseDesired(readFile(t, "desired-node-workloads.json"), testAgentCN)
	if err != nil {
		t.Fatal(err)
	}
	if len(es) != 2 || es[0].State != StateProvisioned || es[1].State != StateRunning {
		t.Fatalf("want [provisioned, running], got %+v", es)
	}
	if es[0].Reservation != nil || es[1].Reservation == nil {
		t.Fatalf("a provisioned row holds no reservation and a running one does")
	}
}

func TestAnotherNodesAgentIsNotAdmitted(t *testing.T) {
	_, err := ParseDesired(readFile(t, "desired", "valid-running.json"), "node-b")
	if CodeOf(err) != ReasonAdmitInvalid {
		t.Fatalf("a door pinned to node-a must be refused on node-b, got %v", err)
	}
}

func TestModelSetFixtures(t *testing.T) {
	for _, c := range loadCases(t, "model-sets") {
		m, err := ParseModelSet(readFile(t, "model-sets", c.File))
		check(t, c, err)
		if c.Valid && (m == nil || m.ID == "") {
			t.Errorf("%s: parsed but is empty", c.File)
		}
	}
}

func TestRhaddonDeclarationIsAValidFixture(t *testing.T) {
	// The fixture add-on's own node-workloads.json is the same bytes as
	// valid-rhaddon.json (the parity test holds that); it parses for rhaddon.
	var lock struct {
		Images map[string]string `json:"images"`
	}
	_ = json.Unmarshal(readFile(t, "node-workloads", "lock.json"), &lock)
	ds, err := ParseDecl("rhaddon", readFile(t, "node-workloads", "valid-rhaddon.json"), lock.Images)
	if err != nil || len(ds) != 1 || ds[0].Port != 9003 {
		t.Fatalf("got %v, %v", ds, err)
	}
}

func TestEveryCodeAFixtureNamesIsProduced(t *testing.T) {
	// The reverse of "every case produces its code": every refusal code the
	// parsers can return has a fixture, so a code cannot exist unpinned.
	want := map[string]bool{}
	for _, dir := range []string{"node-workloads", "model-sets"} {
		for _, c := range loadCases(t, dir) {
			want[c.Code] = true
		}
	}
	for _, code := range []string{
		CodeBadJSON, CodeUnknownField, CodeBadFormat, CodeFieldMissing, CodeDuplicateKey,
		CodeWorkloadsInvalid, CodeDoorNameInvalid, CodeDoorNameTooLong, CodeNameDuplicate, CodeImageNotInLock,
		CodeUIDInvalid, CodeCommandInvalid, CodePortInvalid, CodeProtocolsInvalid, CodeHealthInvalid,
		CodeDrainInvalid, CodeAccelInvalid, CodeModelSlotInvalid, CodeEnvKeyOutsidePrefix,
		CodeEnvKeyRefusedPrefix, CodeEnvBoundInvalid, CodeScratchTargetBad, CodeScratchInvalid,
		CodeScratchInModelSlot, CodeLimitsInvalid,
		CodeIDInvalid, CodeRevisionInvalid, CodeKindInvalid, CodeModalityInvalid, CodeRuntimeInvalid,
		CodeSourceInvalid, CodeLicenseInvalid, CodePathInvalid, CodeSHA256Invalid, CodeFilesInvalid,
		CodeNoticeNotInFiles, CodeProfileInvalid, CodeArchInvalid, CodeFitsRequired, CodeFitsForbidden,
		CodeFitsInvalid, CodeTrustRequired,
	} {
		if !want[code] {
			t.Errorf("no fixture produces %q", code)
		}
	}
	for _, c := range loadCases(t, "desired") {
		want[c.Code] = true
	}
	for _, code := range []string{ReasonDeclInvalid, ReasonDesiredInvalid, ReasonDoorLeafMissing, ReasonImageMissing, ReasonSetMissing, ReasonSetSlotInvalid, ReasonAdmitInvalid, ReasonEnvOutOfBounds, ReasonProfileInvalid} {
		if !want[code] {
			t.Errorf("no desired fixture produces %q", code)
		}
	}
}

func TestCheckProfileRealtimeAndNames(t *testing.T) {
	yes, no := true, false
	str := func(s string) *string { return &s }
	set := ModelSet{ID: "s", Needs: Needs{Profiles: []Profile{
		{Name: "live", Accel: "cuda", Realtime: &yes},
		{Name: "unstated", Accel: "cuda"},
		{Name: "batch", Accel: "cuda", Realtime: &no},
	}}}
	rt := Decl{Accel: Accel{GPU: 1, Realtime: true}}
	for _, row := range []struct {
		name    string
		profile *string
		decl    Decl
		ok      bool
	}{
		{"named realtime profile", str("live"), rt, true},
		{"realtime unstated counts as realtime", str("unstated"), rt, true},
		{"realtime:false profile for a realtime workload", str("batch"), rt, false},
		{"realtime:false profile for a non-realtime workload", str("batch"), Decl{Accel: Accel{GPU: 1}}, true},
		{"unknown name", str("nope"), rt, false},
		{"missing", nil, rt, false},
		{"empty", str(""), rt, false},
	} {
		err := CheckProfile(Entry{Profile: row.profile, Decl: row.decl}, set)
		if row.ok && err != nil || !row.ok && CodeOf(err) != ReasonProfileInvalid {
			t.Errorf("%s: got %v", row.name, err)
		}
	}
}

func TestComputeCapIsNumeric(t *testing.T) {
	for _, row := range []struct {
		have, need string
		want       bool
	}{
		{"10.0", "8.0", true}, // a string compare would say no
		{"8.6", "8.0", true},
		{"8.0", "8.0", true},
		{"7.5", "8.0", false},
		{"8.10", "8.9", true}, // a string compare would say no
		{"8.9", "8.10", false},
		{"9.0", "8.9", true},
	} {
		got, err := ComputeCapAtLeast(row.have, row.need)
		if err != nil || got != row.want {
			t.Errorf("ComputeCapAtLeast(%q, %q) = %v, %v; want %v", row.have, row.need, got, err, row.want)
		}
	}
	for _, bad := range [][2]string{{"", "8.0"}, {"8", "8.0"}, {"abc", "8.0"}, {"8.0", "x.y"}, {"8.0.1", "8.0"}, {"-1.0", "8.0"}, {"8.6", ""}} {
		if got, err := ComputeCapAtLeast(bad[0], bad[1]); err == nil || got {
			t.Errorf("ComputeCapAtLeast(%q, %q) = %v, %v; want an error (unknown, never low)", bad[0], bad[1], got, err)
		}
	}
}

func TestSetPathRule(t *testing.T) {
	for p, want := range map[string]bool{
		"model.safetensors": true, "voices/a.pt": true, ".hidden": true,
		"": false, "/abs": false, ".": false, "..": false, "a/..": false, "../a": false,
		"a/b/c": false, "a//b": false, "a/": false, "sp ace": false, "ü": false,
	} {
		if got := ValidSetPath(p); got != want {
			t.Errorf("ValidSetPath(%q) = %v, want %v", p, got, want)
		}
	}
}

func TestDoorNameBoundary(t *testing.T) {
	if got := EnvPrefix("rh-addon"); got != "RH_ADDON_" {
		t.Fatalf("EnvPrefix = %q", got)
	}
	if len("noo-stunnel-")+maxDoorNames != 63 {
		t.Fatalf("the door label is noo-stunnel-<addon>-<workload>: 12 + %d must be 63", maxDoorNames)
	}
}

func TestReasonsAreUnique(t *testing.T) {
	seen := map[string]bool{}
	for _, r := range Reasons {
		if seen[r] {
			t.Errorf("reason %q twice", r)
		}
		seen[r] = true
	}
}
