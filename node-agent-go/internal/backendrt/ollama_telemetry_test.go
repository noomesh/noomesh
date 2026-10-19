// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 PersonifAI LLC

package backendrt

import (
	"errors"
	"github.com/noomesh/noomesh/node-agent-go/internal/refusals"
	"strings"
	"testing"
)

// fakeMac is a scripted Exec: it records every command and answers by prefix.
type fakeMac struct {
	cmds    []string
	env     map[string]string // the plist's EnvironmentVariables
	procEnv string            // `ps eww` output; "" = no process
	cmdPath string            // `ps -o command=` output; "" = a hand-run path
	loaded  string            // domain launchd holds the job in: "gui", "user", or ""
	hasGUI  bool              // gui/<uid> exists at all
	fail    map[string]bool
}

func (f *fakeMac) run(name string, args ...string) (string, error) {
	c := name + " " + strings.Join(args, " ")
	f.cmds = append(f.cmds, c)
	if f.env == nil {
		f.env = map[string]string{}
	}
	switch {
	case name == plutilBin && len(args) > 1 && args[0] == "-extract":
		v, ok := f.env[strings.TrimPrefix(args[1], "EnvironmentVariables.")]
		if !ok {
			return "", errors.New("No value at that key path")
		}
		return v + "\n", nil
	case name == plutilBin && len(args) > 3 && args[0] == "-replace":
		f.env[strings.TrimPrefix(args[1], "EnvironmentVariables.")] = args[3]
		return "", nil
	case name == "launchctl" && len(args) == 2 && args[0] == "print":
		t := args[1]
		switch {
		case f.loaded == "gui" && strings.HasPrefix(t, "gui/501/"),
			f.loaded == "user" && strings.HasPrefix(t, "user/501/"),
			f.hasGUI && t == "gui/501":
			return "state = running", nil
		}
		return "", errors.New("125: Domain does not support specified action")
	case name == "pgrep":
		if f.procEnv == "" {
			return "", errors.New("exit 1")
		}
		return "4242\n", nil
	case name == "ps" && strings.Contains(c, "command="):
		if f.cmdPath == "" {
			return "/opt/homebrew/bin/ollama serve\n", nil
		}
		return f.cmdPath + "\n", nil
	case name == "ps":
		return f.procEnv, nil
	}
	if f.fail[name] {
		return "", errors.New("boom")
	}
	return "", nil
}

func (f *fakeMac) had(sub string) bool {
	for _, c := range f.cmds {
		if strings.Contains(c, sub) {
			return true
		}
	}
	return false
}

// guard: plists names the labels whose plist exists.
func guard(f *fakeMac, plists ...string) *OllamaGuard {
	there := map[string]bool{}
	for _, l := range plists {
		there[OllamaPlistPath("/Users/m", l)] = true
	}
	return &OllamaGuard{Home: "/Users/m", UID: 501, Run: f.run, Exists: func(p string) bool { return there[p] }}
}

const (
	newBrew     = "sh.brew.ollama"
	oldBrew     = "homebrew.mxcl.ollama"
	procWith    = "4242 ?? S ollama serve OLLAMA_NO_CLOUD=1 PATH=/usr/bin HOME=/Users/m"
	procWithout = "4242 ?? S ollama serve PATH=/usr/bin HOME=/Users/m"
)

func TestConvergeAddsTheSwitchAndRestartsViaLaunchctlOnce(t *testing.T) {
	f := &fakeMac{loaded: "gui"}
	managed, restarted, err := guard(f, oldBrew).Converge()
	if err != nil || !managed || !restarted {
		t.Fatalf("managed=%v restarted=%v err=%v", managed, restarted, err)
	}
	plist := "/Users/m/Library/LaunchAgents/homebrew.mxcl.ollama.plist"
	for _, want := range []string{
		plutilBin + " -replace EnvironmentVariables.OLLAMA_NO_CLOUD -string 1 " + plist,
		"launchctl bootout gui/501 " + plist,
		"launchctl bootstrap gui/501 " + plist,
	} {
		if !f.had(want) {
			t.Errorf("missing command %q in %v", want, f.cmds)
		}
	}
	if f.had("brew services") || f.had("PlistBuddy") {
		t.Errorf("must not restart through brew, nor write with PlistBuddy: %v", f.cmds)
	}
	f.cmds = nil
	if _, restarted, _ = guard(f, oldBrew).Converge(); restarted || f.had("launchctl bootout") {
		t.Errorf("idempotent run restarted: %v", f.cmds)
	}
}

// host6, 2026-10-05: current Homebrew's label, a headless Mac reached over
// SSH whose LaunchAgents run in user/<uid> (gui/<uid> answers 125).
func TestCurrentBrewLabelOnAHeadlessMacUsesTheUserDomain(t *testing.T) {
	f := &fakeMac{loaded: "user"}
	g := guard(f, newBrew)
	if _, restarted, err := g.Converge(); err != nil || !restarted {
		t.Fatalf("restarted=%v err=%v cmds=%v", restarted, err, f.cmds)
	}
	plist := "/Users/m/Library/LaunchAgents/sh.brew.ollama.plist"
	if !f.had("launchctl bootstrap user/501 "+plist) || f.had("bootstrap gui/") {
		t.Fatalf("wrong domain or plist: %v", f.cmds)
	}
	if e := g.Report(true); e["managed"] != true || e["plist_label"] != newBrew {
		t.Fatalf("report: %v", e)
	}
}

func TestANewServiceWithNoGUISessionBootstrapsIntoTheUserDomain(t *testing.T) {
	f := &fakeMac{} // not loaded anywhere, no GUI session
	if _, _, err := guard(f, newBrew).Converge(); err != nil {
		t.Fatal(err)
	}
	if !f.had("launchctl bootstrap user/501 ") {
		t.Fatalf("%v", f.cmds)
	}
	f2 := &fakeMac{hasGUI: true}
	_, _, _ = guard(f2, newBrew).Converge()
	if !f2.had("launchctl bootstrap gui/501 ") {
		t.Fatalf("a GUI session should get the gui domain: %v", f2.cmds)
	}
}

func TestTheNewestLabelWinsWhenBothExist(t *testing.T) {
	f := &fakeMac{loaded: "gui"}
	if e := guard(f, newBrew, oldBrew).Report(true); e["plist_label"] != newBrew {
		t.Fatalf("%v", e)
	}
}

func TestConvergeTouchesNothingWithoutAPlist(t *testing.T) {
	f := &fakeMac{}
	managed, restarted, err := guard(f).Converge()
	if managed || restarted || err != nil || len(f.cmds) != 0 {
		t.Fatalf("managed=%v restarted=%v err=%v cmds=%v", managed, restarted, err, f.cmds)
	}
}

func TestConvergeRestartsOnceWhenOnlyTheProcessLacksTheSwitch(t *testing.T) {
	f := &fakeMac{env: map[string]string{"OLLAMA_NO_CLOUD": "1"}, procEnv: procWithout, loaded: "gui"}
	g := guard(f, newBrew)
	if _, restarted, _ := g.Converge(); !restarted {
		t.Fatal("expected one restart for a stale process")
	}
	f.cmds = nil
	if _, restarted, _ := g.Converge(); restarted || f.had("launchctl bootout") {
		t.Fatalf("restart loop: %v", f.cmds)
	}
}

// OLLAMA_MODELS follows the node's data root, but never hides models.
func TestModelsDirFollowsTheDataRootOnlyWhenNoModelsHide(t *testing.T) {
	want := "/Users/m/Library/Application Support/noo/ollama"
	cases := []struct {
		name      string
		current   string
		withModel map[string]bool
		move      bool
	}{
		{"models already moved there", "", map[string]bool{want: true, "/Users/m/.ollama/models": false}, true},
		{"fresh: nothing anywhere", "", map[string]bool{}, true},
		{"models still in the old store", "", map[string]bool{"/Users/m/.ollama/models": true}, false},
		{"old explicit store still full", "/Volumes/T7/ollama", map[string]bool{"/Volumes/T7/ollama": true}, false},
	}
	for _, c := range cases {
		f := &fakeMac{env: map[string]string{"OLLAMA_NO_CLOUD": "1"}, loaded: "user"}
		if c.current != "" {
			f.env["OLLAMA_MODELS"] = c.current
		}
		g := guard(f, newBrew)
		g.ModelsDir = func() string { return want }
		g.HasModels = func(d string) bool { return c.withModel[d] }
		_, restarted, err := g.Converge()
		if err != nil {
			t.Fatalf("%s: %v", c.name, err)
		}
		moved := f.env["OLLAMA_MODELS"] == want
		if moved != c.move || restarted != c.move {
			t.Errorf("%s: moved=%v restarted=%v, want %v (%v)", c.name, moved, restarted, c.move, f.cmds)
		}
		e := g.Report(true)
		if e["models_dir_wanted"] != want || e["models_dir_pending"] != false && c.move {
			t.Errorf("%s: report %v", c.name, e)
		}
		if !c.move && e["models_dir_pending"] != true {
			t.Errorf("%s: a declined switch must be reported pending: %v", c.name, e)
		}
	}
}

func TestReportJudgesPlistAndProcess(t *testing.T) {
	cases := []struct {
		name    string
		f       *fakeMac
		plist   bool
		managed bool
		missing int // -1 = key absent
		proc    string
	}{
		{"set both", &fakeMac{env: map[string]string{"OLLAMA_NO_CLOUD": "1"}, procEnv: procWith}, true, true, 0, "set"},
		{"plist lacks", &fakeMac{procEnv: procWith}, true, true, 1, "set"},
		{"process lacks", &fakeMac{env: map[string]string{"OLLAMA_NO_CLOUD": "1"}, procEnv: procWithout}, true, true, 1, "missing"},
		{"process unreadable", &fakeMac{env: map[string]string{"OLLAMA_NO_CLOUD": "1"}}, true, true, 0, "unknown"},
		{"no plist, no process", &fakeMac{}, false, false, -1, "unknown"},
	}
	for _, c := range cases {
		labels := []string{}
		if c.plist {
			labels = append(labels, newBrew)
		}
		e := guard(c.f, labels...).Report(true)
		if e["managed"] != c.managed || e["runtime"] != "native" {
			t.Errorf("%s: %v", c.name, e)
		}
		tm, has := e["telemetry_missing"].([]string)
		if c.missing < 0 {
			if has {
				t.Errorf("%s: unmanaged must not claim a proof: %v", c.name, e)
			}
			continue
		}
		if !has || len(tm) != c.missing || (c.missing == 1 && tm[0] != "OLLAMA_NO_CLOUD") {
			t.Errorf("%s: telemetry_missing %v", c.name, e["telemetry_missing"])
		}
		if e["process_env"] != c.proc {
			t.Errorf("%s: process_env %v", c.name, e["process_env"])
		}
	}
}

func TestReportProvesAnUnmanagedOllamaFromTheRunningProcess(t *testing.T) {
	cases := []struct {
		name     string
		f        *fakeMac
		proc     string
		launcher string
		missing  []string // nil = key absent
	}{
		{"manual, switch set", &fakeMac{procEnv: procWith}, "set", "manual", []string{}},
		{"manual, switch missing", &fakeMac{procEnv: procWithout}, "missing", "manual", []string{"OLLAMA_NO_CLOUD"}},
		{"app, switch missing", &fakeMac{procEnv: procWithout, cmdPath: "/Applications/Ollama.app/Contents/Resources/ollama serve"}, "missing", "ollama-app", []string{"OLLAMA_NO_CLOUD"}},
		{"app, switch set", &fakeMac{procEnv: procWith, cmdPath: "/Applications/Ollama.app/Contents/Resources/ollama serve"}, "set", "ollama-app", []string{}},
		{"no process", &fakeMac{}, "unknown", "none", nil},
	}
	for _, c := range cases {
		e := guard(c.f).Report(true)
		if e["managed"] != false || e["process_env"] != c.proc || e["launcher"] != c.launcher {
			t.Errorf("%s: %v", c.name, e)
		}
		tm, has := e["telemetry_missing"].([]string)
		if c.missing == nil {
			if has {
				t.Errorf("%s: an unproven switch must not claim a verdict: %v", c.name, e)
			}
			continue
		}
		if !has || len(tm) != len(c.missing) || (len(tm) == 1 && tm[0] != c.missing[0]) {
			t.Errorf("%s: telemetry_missing %v", c.name, e["telemetry_missing"])
		}
		if f := c.f; f.had("launchctl") || f.had("plutil") || f.had("brew") {
			t.Errorf("%s: an ollama noomesh did not start must not be touched: %v", c.name, f.cmds)
		}
	}
}

func TestReportNamesBrewServiceAsTheLauncherWhenManaged(t *testing.T) {
	e := guard(&fakeMac{env: map[string]string{"OLLAMA_NO_CLOUD": "1"}, procEnv: procWith}, newBrew).Report(true)
	if e["launcher"] != "brew-service" || e["managed"] != true || e["process_env"] != "set" {
		t.Errorf("%v", e)
	}
}

// Multi-role placements (chat + embed in ONE ollama): the merged placement
// env must reach a launchd-managed ollama through its plist.
func TestConvergeAppliesPlacementTuningToThePlist(t *testing.T) {
	f := &fakeMac{env: map[string]string{"OLLAMA_NO_CLOUD": "1"}, procEnv: procWith, loaded: "gui"}
	g := guard(f, newBrew)
	g.Tuning = func() map[string]string {
		return map[string]string{
			"OLLAMA_NUM_PARALLEL":      "4",
			"OLLAMA_MAX_LOADED_MODELS": "2",
			"OLLAMA_KEEP_ALIVE":        "-1",
			"OLLAMA_CONTEXT_LENGTH":    "32768",
			"OLLAMA_HOST":              "0.0.0.0", // not honoured
		}
	}
	managed, restarted, err := g.Converge()
	if err != nil || !managed || !restarted {
		t.Fatalf("managed=%v restarted=%v err=%v", managed, restarted, err)
	}
	plist := "/Users/m/Library/LaunchAgents/sh.brew.ollama.plist"
	for _, want := range []string{
		plutilBin + " -replace EnvironmentVariables.OLLAMA_NUM_PARALLEL -string 4 " + plist,
		plutilBin + " -replace EnvironmentVariables.OLLAMA_MAX_LOADED_MODELS -string 2 " + plist,
		plutilBin + " -replace EnvironmentVariables.OLLAMA_KEEP_ALIVE -string -1 " + plist,
		plutilBin + " -replace EnvironmentVariables.OLLAMA_CONTEXT_LENGTH -string 32768 " + plist,
		"launchctl bootout gui/501 " + plist,
		"launchctl bootstrap gui/501 " + plist,
	} {
		if !f.had(want) {
			t.Errorf("missing command %q in %v", want, f.cmds)
		}
	}
	if f.had("OLLAMA_HOST") {
		t.Errorf("a non-tuning key must not reach the plist: %v", f.cmds)
	}
	// Already right: nothing is run beyond reads, no restart.
	f.cmds = nil
	if _, restarted, _ := g.Converge(); restarted || f.had("-replace") || f.had("launchctl bootout") {
		t.Errorf("idempotent run changed things: %v", f.cmds)
	}
}

func TestConvergeWithoutAPlistRecordsThePlacementEnvLimit(t *testing.T) {
	refusals.Reset()
	t.Cleanup(refusals.Reset)
	f := &fakeMac{}
	g := guard(f)
	g.Tuning = func() map[string]string { return map[string]string{"OLLAMA_NUM_PARALLEL": "4"} }
	if managed, restarted, err := g.Converge(); managed || restarted || err != nil || len(f.cmds) != 0 {
		t.Fatalf("managed=%v restarted=%v err=%v cmds=%v", managed, restarted, err, f.cmds)
	}
	rs := refusals.List()
	if len(rs) != 1 || rs[0].Scope != "placement_env" || !strings.Contains(rs[0].Reason, "cannot set") {
		t.Fatalf("refusals = %+v", rs)
	}
}
