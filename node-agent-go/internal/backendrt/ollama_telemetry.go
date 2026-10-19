// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 PersonifAI LLC

package backendrt

// The Mac's native ollama and the vendor telemetry stance
// (docs/security/telemetry.md).
//
// On a Mac the backend is a brew-installed ollama run by launchd from
// ~/Library/LaunchAgents/<label>.plist, not a container, so the
// container env that carries OLLAMA_NO_CLOUD=1 on Linux never reaches it and
// `backend_containers.<b>.telemetry_missing` had nothing to say about it
// (`noo cluster verify` read "older agent — telemetry switches not proven").
//
// This file does the two jobs for that process:
//
//   - Converge: idempotently ensure OLLAMA_NO_CLOUD=1 and OLLAMA_MODELS (the
//     node's OLLAMA_DATA_DIR) in the plist and restart the job once when it
//     had to change, so Macs enrolled before either existed converge without
//     re-enrolling. OLLAMA_MODELS only moves when that cannot hide models:
//     the new directory already holds them, or the current one holds none.
//   - OllamaTelemetry: the heartbeat entry, judged from the plist and, when
//     readable, the running `ollama serve` process's environment.
//
// Homebrew: `brew services start` regenerates the plist from the formula and
// `stop` deletes it (Library/Homebrew/services/cli.rb), so the key can vanish
// at any later `brew services restart` or upgrade; that is why this runs on a
// loop, and why the restart is launchctl bootout/bootstrap of the plist
// (launchd caches a job's environment at bootstrap; kickstart would not
// pick up a new key) and never `brew services`.
//
// If the plist is absent the operator runs Ollama.app or something else:
// nothing is touched, and the report says `managed: false`, but it still
// reads the running process's environment and names the launcher, so the
// switch is proven (or shown missing) whatever started ollama.

// Two facts the first version assumed and host6 disproved:
//
//   - The label. Current Homebrew names the service `sh.brew.ollama`; older
//     releases `homebrew.mxcl.ollama`. Both are looked for, newest first.
//   - The launchd domain. A Mac logged in at its screen runs LaunchAgents in
//     gui/<uid>; a headless Mac reached over SSH runs them in user/<uid>, and
//     gui/<uid> answers "125: Domain does not support specified action" even
//     to root. launchd is asked where the job is, never assumed.
//
// Values are written with plutil, which takes the value as its own argument:
// PlistBuddy parses its command text, and a data root under
// "Application Support" has a space in it.

import (
	"fmt"
	"log/slog"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"

	"github.com/noomesh/noomesh/node-agent-go/internal/refusals"
)

// OllamaPlistLabels are the launchd labels Homebrew has given the ollama
// service, newest first.
var OllamaPlistLabels = []string{"sh.brew.ollama", "homebrew.mxcl.ollama"}

const (
	ollamaNoCloud = "OLLAMA_NO_CLOUD"
	ollamaModels  = "OLLAMA_MODELS"
	plutilBin     = "/usr/bin/plutil"
)

// Exec runs a command and returns its combined output. A seam so tests
// assert on the commands built; production is ExecCommand.
type Exec func(name string, args ...string) (string, error)

// ExecCommand is the production Exec.
func ExecCommand(name string, args ...string) (string, error) {
	out, err := exec.Command(name, args...).CombinedOutput()
	return string(out), err
}

// OllamaPlistPath is the brew service plist for label under home.
func OllamaPlistPath(home, label string) string {
	return home + "/Library/LaunchAgents/" + label + ".plist"
}

// OllamaGuard converges and reports the native ollama's environment.
type OllamaGuard struct {
	Home   string
	UID    int
	Run    Exec
	Exists func(string) bool
	// ModelsDir is where the node wants ollama's models (its OLLAMA_DATA_DIR,
	// rendered from the data root); "" leaves OLLAMA_MODELS alone.
	ModelsDir func() string
	// HasModels reports whether an ollama model store holds anything.
	HasModels func(string) bool
	// Tuning is the placement-derived daemon env (the reconciler's merged
	// ollama env, see SetOllamaTuning); nil = none. Only the keys in
	// OllamaTuningKeys are honoured. A native ollama is not a container, so
	// placement env cannot reach it any other way than this plist.
	Tuning func() map[string]string

	mu sync.Mutex
	// warnedNoPlist: the "agent cannot set daemon env" limit is logged once.
	warnedNoPlist bool
	// restartedForProcess: the plist was right but the running process was
	// not; restart once for that per agent process, so a process whose env
	// cannot be read in the form we expect never makes a restart loop.
	restartedForProcess bool
}

// NewOllamaGuard is the production guard for the agent's own user.
func NewOllamaGuard() *OllamaGuard {
	home, _ := os.UserHomeDir()
	return &OllamaGuard{Home: home, UID: os.Getuid(), Run: ExecCommand,
		Exists:    func(p string) bool { _, err := os.Stat(p); return err == nil },
		Tuning:    OllamaTuning,
		ModelsDir: func() string { return strings.TrimSpace(os.Getenv("OLLAMA_DATA_DIR")) },
		HasModels: func(d string) bool {
			entries, err := os.ReadDir(filepath.Join(d, "manifests"))
			return err == nil && len(entries) > 0
		}}
}

// label is the brew label whose plist exists, "" when none does.
func (g *OllamaGuard) label() string {
	for _, l := range OllamaPlistLabels {
		if g.Exists(OllamaPlistPath(g.Home, l)) {
			return l
		}
	}
	return ""
}

func (g *OllamaGuard) plist() string {
	l := g.label()
	if l == "" {
		return ""
	}
	return OllamaPlistPath(g.Home, l)
}

// domain is the launchd domain that holds the job: gui/<uid> or user/<uid>,
// whichever launchd says has it; when neither does, gui/<uid> if this user
// has a GUI session, else user/<uid>.
func (g *OllamaGuard) domain() string {
	gui, user := fmt.Sprintf("gui/%d", g.UID), fmt.Sprintf("user/%d", g.UID)
	if l := g.label(); l != "" {
		for _, d := range []string{gui, user} {
			if _, err := g.Run("launchctl", "print", d+"/"+l); err == nil {
				return d
			}
		}
	}
	if _, err := g.Run("launchctl", "print", gui); err == nil {
		return gui
	}
	return user
}

// plistValue reads one EnvironmentVariables key ("" when absent).
func (g *OllamaGuard) plistValue(key string) string {
	out, err := g.Run(plutilBin, "-extract", "EnvironmentVariables."+key, "raw", "-o", "-", g.plist())
	if err != nil {
		return ""
	}
	return strings.TrimSpace(out)
}

func (g *OllamaGuard) setPlistValue(key, value string) error {
	_, _ = g.Run(plutilBin, "-insert", "EnvironmentVariables", "-dictionary", g.plist())
	if out, err := g.Run(plutilBin, "-replace", "EnvironmentVariables."+key, "-string", value, g.plist()); err != nil {
		return fmt.Errorf("could not set %s in %s: %v: %s", key, g.plist(), err, strings.TrimSpace(out))
	}
	return nil
}

// modelsPlan is (wanted, current, move): move is true only when switching
// OLLAMA_MODELS cannot hide models.
func (g *OllamaGuard) modelsPlan() (wanted, current string, move bool) {
	if g.ModelsDir == nil {
		return "", "", false
	}
	wanted = strings.TrimSpace(g.ModelsDir())
	current = g.plistValue(ollamaModels)
	if wanted == "" || wanted == current {
		return wanted, current, false
	}
	effective := current
	if effective == "" {
		effective = filepath.Join(g.Home, ".ollama", "models")
	}
	has := g.HasModels
	if has == nil {
		has = func(string) bool { return true }
	}
	return wanted, current, has(wanted) || !has(effective)
}

// servePID is the pid of the running `ollama serve`, "" when there is none.
func (g *OllamaGuard) servePID() string {
	out, err := g.Run("pgrep", "-f", "ollama serve")
	if err != nil {
		return ""
	}
	fields := strings.Fields(out)
	if len(fields) == 0 {
		return ""
	}
	return fields[0]
}

// Launcher names what started the ollama that is serving: "brew-service"
// (a brew plist exists), "ollama-app" (the serving process runs from
// Ollama.app), "manual" (an `ollama serve` that is neither), or "none".
func (g *OllamaGuard) Launcher() string {
	if g == nil {
		return "none"
	}
	if g.label() != "" {
		return "brew-service"
	}
	pid := g.servePID()
	if pid == "" {
		return "none"
	}
	cmd, err := g.Run("ps", "-o", "command=", "-p", pid)
	if err == nil && strings.Contains(cmd, "Ollama.app") {
		return "ollama-app"
	}
	return "manual"
}

// ProcessEnv reports whether the running `ollama serve` has the switch in its
// environment: "set", "missing", or "unknown" (not running, or not readable;
// `ps eww` shows another user's environment only to root).
func (g *OllamaGuard) ProcessEnv() string {
	pid := g.servePID()
	if pid == "" {
		return "unknown"
	}
	env, err := g.Run("ps", "eww", "-p", pid)
	if err != nil || !strings.Contains(env, "ollama") {
		return "unknown"
	}
	// A readable environment carries at least PATH or HOME.
	if !strings.Contains(env, "PATH=") && !strings.Contains(env, "HOME=") {
		return "unknown"
	}
	for _, tok := range strings.Fields(env) {
		if tok == ollamaNoCloud+"=1" {
			return "set"
		}
	}
	return "missing"
}

// Converge ensures both keys and restarts the job when it had to change
// something. managed=false (nothing touched) when no brew plist exists.
func (g *OllamaGuard) Converge() (managed, restarted bool, err error) {
	if g == nil {
		return false, false, nil
	}
	if g.label() == "" {
		g.noteNoPlist()
		return false, false, nil
	}
	plist := g.plist()
	changed := false
	if g.plistValue(ollamaNoCloud) != "1" {
		if err := g.setPlistValue(ollamaNoCloud, "1"); err != nil {
			return true, false, err
		}
		slog.Warn("ollama: set OLLAMA_NO_CLOUD=1 in the brew plist (vendor telemetry switch)", "plist", plist)
		changed = true
	}
	tuning := g.tuning()
	for _, k := range OllamaTuningKeys {
		v, ok := tuning[k]
		if !ok || g.plistValue(k) == v {
			continue
		}
		if err := g.setPlistValue(k, v); err != nil {
			return true, false, err
		}
		slog.Warn("ollama: set placement tuning in the brew plist", "plist", plist, "key", k, "value", v)
		changed = true
	}
	if wanted, current, move := g.modelsPlan(); move {
		if err := g.setPlistValue(ollamaModels, wanted); err != nil {
			return true, false, err
		}
		slog.Warn("ollama: pointed OLLAMA_MODELS at the node's data root", "plist", plist, "from", current, "to", wanted)
		changed = true
	} else if wanted != "" && wanted != current {
		slog.Warn("ollama: OLLAMA_MODELS left alone — the data root's ollama dir is empty and the current store holds models; move them, then the agent switches",
			"plist", plist, "current", current, "wanted", wanted)
	}
	if changed {
		slog.Warn("ollama: restarting the job once to apply", "plist", plist, "domain", g.domain())
		return true, true, g.restart()
	}
	g.mu.Lock()
	defer g.mu.Unlock()
	if g.ProcessEnv() != "missing" || g.restartedForProcess {
		return true, false, nil
	}
	g.restartedForProcess = true
	slog.Warn("ollama: plist has OLLAMA_NO_CLOUD=1 but the running process lacks it — restarting the job once", "plist", plist)
	return true, true, g.restart()
}

func (g *OllamaGuard) restart() error {
	domain := g.domain()
	_, _ = g.Run("launchctl", "bootout", domain, g.plist())
	if out, err := g.Run("launchctl", "bootstrap", domain, g.plist()); err != nil {
		return fmt.Errorf("launchctl bootstrap %s %s: %v: %s", domain, g.plist(), err, strings.TrimSpace(out))
	}
	return nil
}

// Report is the heartbeat's `backend_containers.ollama` entry for a native
// ollama. `launcher` names what started it. `process_env` is judged from the
// running `ollama serve` whether or not noomesh manages it, so the switch is
// proven whatever launched ollama; `telemetry_missing` is [] when proven set,
// names the switch when the plist lacks it or the process demonstrably does,
// and is ABSENT for an unmanaged ollama whose process could not be read (an
// absent key reads as "not proven" to `noo cluster verify`). An ollama noomesh
// did not start is only reported on, never touched (`managed: false`).
// A managed entry also names its `plist_label` and, when the node wants a
// different model store, `models_dir` / `models_dir_wanted` /
// `models_dir_pending` (true while the agent declines to switch).
func (g *OllamaGuard) Report(running bool) map[string]any {
	e := map[string]any{"running": running, "runtime": "native"}
	e["launcher"] = g.Launcher()
	if g == nil {
		e["managed"] = false
		return e
	}
	proc := g.ProcessEnv()
	e["process_env"] = proc
	label := g.label()
	if label == "" {
		e["managed"] = false
		switch proc {
		case "set":
			e["telemetry_missing"] = []string{}
		case "missing":
			e["telemetry_missing"] = []string{ollamaNoCloud}
		}
		return e
	}
	e["managed"] = true
	e["plist_label"] = label
	missing := []string{}
	if g.plistValue(ollamaNoCloud) != "1" || proc == "missing" {
		missing = append(missing, ollamaNoCloud)
	}
	e["telemetry_missing"] = missing
	if wanted, current, move := g.modelsPlan(); wanted != "" {
		e["models_dir"] = current
		e["models_dir_wanted"] = wanted
		e["models_dir_pending"] = wanted != current && !move
	}
	return e
}

// OllamaTuningKeys are the only placement env keys the guard writes into a
// plist: the multi-model knobs a chat+embed ollama needs.
var OllamaTuningKeys = []string{"OLLAMA_NUM_PARALLEL", "OLLAMA_MAX_LOADED_MODELS", "OLLAMA_KEEP_ALIVE", "OLLAMA_CONTEXT_LENGTH"}

// tuning is Tuning() filtered to OllamaTuningKeys with non-empty values.
func (g *OllamaGuard) tuning() map[string]string {
	out := map[string]string{}
	if g == nil || g.Tuning == nil {
		return out
	}
	t := g.Tuning()
	for _, k := range OllamaTuningKeys {
		if v := strings.TrimSpace(t[k]); v != "" {
			out[k] = v
		}
	}
	return out
}

// noteNoPlist records, once logged and continuously refused, that there is
// no brew plist to carry placement env (Ollama.app or a hand-run serve).
func (g *OllamaGuard) noteNoPlist() {
	if len(g.tuning()) == 0 {
		refusals.Clear("placement_env", "ollama")
		return
	}
	refusals.Record("placement_env", "ollama",
		"this node's ollama is not a brew service (Ollama.app or a manual serve), so the agent cannot set its daemon env "+
			"(OLLAMA_NUM_PARALLEL / OLLAMA_MAX_LOADED_MODELS / OLLAMA_KEEP_ALIVE / OLLAMA_CONTEXT_LENGTH); set them where it is launched")
	g.mu.Lock()
	defer g.mu.Unlock()
	if !g.warnedNoPlist {
		g.warnedNoPlist = true
		slog.Warn("ollama: placement env cannot be applied - no brew plist; the agent cannot set the daemon env of an Ollama.app or manual ollama")
	}
}

var (
	tuningMu   sync.Mutex
	tuningHeld map[string]string
)

// SetOllamaTuning publishes the merged ollama placement env (the
// reconciler, every tick in the native branch); nil clears.
func SetOllamaTuning(env map[string]string) {
	tuningMu.Lock()
	defer tuningMu.Unlock()
	tuningHeld = nil
	if len(env) > 0 {
		tuningHeld = make(map[string]string, len(env))
		for k, v := range env {
			tuningHeld[k] = v
		}
	}
}

// OllamaTuning returns a copy of the published env.
func OllamaTuning() map[string]string {
	tuningMu.Lock()
	defer tuningMu.Unlock()
	out := make(map[string]string, len(tuningHeld))
	for k, v := range tuningHeld {
		out[k] = v
	}
	return out
}
