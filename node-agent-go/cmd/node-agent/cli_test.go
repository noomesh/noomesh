// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 PersonifAI LLC

package main

import (
	"bytes"
	"context"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"
)

// buildAgent compiles THIS package into a temp dir, stamped the way
// build-cross.sh stamps a release, and returns the binary's path. The test
// executes only this freshly built binary — never an installed agent.
func buildAgent(t *testing.T, stamp string) string {
	t.Helper()
	goBin := filepath.Join(runtime.GOROOT(), "bin", "go")
	if _, err := os.Stat(goBin); err != nil {
		goBin = "go"
	}
	out := filepath.Join(t.TempDir(), "noo-node-agent")
	vpkg := "github.com/noomesh/noomesh/node-agent-go/internal/version"
	cmd := exec.Command(goBin, "build", "-o", out,
		"-ldflags", "-X "+vpkg+".Version="+stamp+" -X "+vpkg+".Commit=abc1234",
		".")
	cmd.Env = append(os.Environ(), "CGO_ENABLED=0")
	if b, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("go build: %v\n%s", err, b)
	}
	return out
}

type runResult struct {
	code           int
	stdout, stderr string
	elapsed        time.Duration
	dirEntries     int
}

// runIsolated runs the binary in an EMPTY temp dir with an EMPTY
// environment (no NOO_TLS_*, no NODE_AGENT_PORT, no HOME, no PATH) and a
// hard deadline. A binary that started the agent instead would either
// block (a listener) or exit 1 with the agent's JSON log on stdout.
func runIsolated(t *testing.T, bin string, env []string, args ...string) runResult {
	t.Helper()
	dir := t.TempDir()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, bin, args...)
	cmd.Dir = dir
	if env == nil {
		env = []string{}
	}
	cmd.Env = env // non-nil and empty = nothing inherited
	var so, se bytes.Buffer
	cmd.Stdout, cmd.Stderr = &so, &se
	start := time.Now()
	err := cmd.Run()
	r := runResult{stdout: so.String(), stderr: se.String(), elapsed: time.Since(start)}
	if ctx.Err() != nil {
		t.Fatalf("%v did not exit within 10s — it started something (stdout=%q stderr=%q)", args, r.stdout, r.stderr)
	}
	var ee *exec.ExitError
	switch {
	case err == nil:
	case errors.As(err, &ee):
		r.code = ee.ExitCode()
	default:
		t.Fatalf("run %v: %v", args, err)
	}
	ents, _ := os.ReadDir(dir)
	r.dirEntries = len(ents)
	return r
}

func TestVersionPrintsAndExitsBeforeAnythingElse(t *testing.T) {
	bin := buildAgent(t, "v9.8.7-test")
	for _, arg := range []string{"--version", "-version", "version"} {
		r := runIsolated(t, bin, nil, arg)
		if r.code != 0 {
			t.Errorf("%s: exit %d, want 0 (stdout=%q stderr=%q)", arg, r.code, r.stdout, r.stderr)
		}
		if first := strings.SplitN(r.stdout, "\n", 2)[0]; first != "noo-node-agent v9.8.7-test+abc1234" {
			t.Errorf("%s: first line %q, want the heartbeat's app_version", arg, first)
		}
		// The agent's first act is a JSON log line; its absence is the
		// evidence that nothing past the version path ran.
		if strings.Contains(r.stdout, "{") || r.stderr != "" {
			t.Errorf("%s: agent output leaked (stdout=%q stderr=%q)", arg, r.stdout, r.stderr)
		}
		if r.dirEntries != 0 {
			t.Errorf("%s: wrote %d entries into its working dir", arg, r.dirEntries)
		}
		if r.elapsed > 2*time.Second {
			t.Errorf("%s: took %s — a version print must be immediate", arg, r.elapsed)
		}
	}
}

// Even with an environment that WOULD start an agent (a port, TLS paths),
// --version must not: it reads no env at all. A started agent here fails
// loading the missing cert and exits 1 — this asserts exit 0 and silence.
func TestVersionIgnoresAnAgentEnvironment(t *testing.T) {
	bin := buildAgent(t, "v9.8.7-test")
	env := []string{
		"NODE_AGENT_PORT=1", "NOO_TLS_CERT=/nonexistent/node.crt",
		"NOO_TLS_KEY=/nonexistent/node.key", "NOO_TLS_CA=/nonexistent/ca.crt",
		"NOO_BACKEND_FIRST_BYTE_TIMEOUT_SECS=bogus", "LOG_LEVEL=debug",
	}
	r := runIsolated(t, bin, env, "--version")
	if r.code != 0 || r.stderr != "" || strings.Contains(r.stdout, "{") {
		t.Fatalf("exit %d stdout=%q stderr=%q", r.code, r.stdout, r.stderr)
	}
}

func TestHelpPrintsUsageAndExitsZero(t *testing.T) {
	bin := buildAgent(t, "v9.8.7-test")
	for _, arg := range []string{"--help", "-h", "help"} {
		r := runIsolated(t, bin, nil, arg)
		if r.code != 0 || !strings.HasPrefix(r.stdout, "usage: noo-node-agent") || r.stderr != "" {
			t.Errorf("%s: exit %d stdout=%q stderr=%q", arg, r.code, r.stdout, r.stderr)
		}
	}
}

func TestUnknownArgumentExitsTwoAndNeverStartsTheAgent(t *testing.T) {
	bin := buildAgent(t, "v9.8.7-test")
	for _, args := range [][]string{
		{"--bogus"}, {"start"}, {"-v"}, {"--version-x"},
		{"-preseed"},                  // too few: used to fall through to the agent
		{"-preseed-file", "a"},        // too few
		{"-healthcheck", "extra-arg"}, // extra
	} {
		r := runIsolated(t, bin, nil, args...)
		if r.code != 2 {
			t.Errorf("%v: exit %d, want 2 (stdout=%q stderr=%q)", args, r.code, r.stdout, r.stderr)
		}
		if !strings.Contains(r.stderr, "NOT started") || r.stdout != "" {
			t.Errorf("%v: stdout=%q stderr=%q", args, r.stdout, r.stderr)
		}
	}
}

// Every argument list the shipped launchers and helpers pass must keep
// meaning what it meant: the systemd unit and run-agent.sh pass none;
// hostd's swap probe passes -healthcheck; the preseed helpers pass 2 or 3.
func TestParseArgsKeepsEveryShippedInvocation(t *testing.T) {
	cases := []struct {
		args []string
		want command
	}{
		{nil, cmdRun},
		{[]string{}, cmdRun},
		{[]string{"-healthcheck"}, cmdHealthcheck},
		{[]string{"-preseed", "u", "d"}, cmdPreseed},
		{[]string{"-preseed-file", "u", "d"}, cmdPreseedFile},
		{[]string{"-preseed-file", "u", "d", "sha"}, cmdPreseedFile},
		{[]string{"--version"}, cmdVersion},
		{[]string{"-version"}, cmdVersion},
		{[]string{"version"}, cmdVersion},
		{[]string{"--help"}, cmdHelp},
		{[]string{"--nope"}, cmdBad},
	}
	for _, c := range cases {
		if got, _ := parseArgs(c.args); got != c.want {
			t.Errorf("parseArgs(%q) = %d, want %d", c.args, got, c.want)
		}
	}
}

// The unit must keep starting the agent with NO arguments — anything it
// passes now would be refused with exit 2 and Restart=always would spin.
func TestUnitPassesNoArguments(t *testing.T) {
	raw, err := os.ReadFile("../../deploy/noo-node-agent.service")
	if err != nil {
		t.Fatalf("read unit: %v", err)
	}
	for _, line := range strings.Split(string(raw), "\n") {
		line = strings.TrimSpace(line)
		if strings.HasPrefix(line, "ExecStart=") {
			if got := strings.Fields(strings.TrimPrefix(line, "ExecStart=")); len(got) != 1 {
				t.Errorf("ExecStart passes arguments %q; the agent starts only with none", got[1:])
			}
		}
	}
}
