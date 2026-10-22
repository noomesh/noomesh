// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 PersonifAI LLC

package hostd

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
)

// Runner executes a host command. It exists as an interface for one reason:
// every op in this daemon is "shell out and interpret the outcome", so a real
// test of the DISPATCH logic — validation, arg allowlists, result shape,
// health-check sequencing — must be able to observe the argv without a docker
// daemon present. The bash watcher had no such seam, which is why none of its
// dispatch logic was ever tested.
type Runner interface {
	// Run executes name+args in dir. It returns the process exit code and
	// its STDERR. Stdout is deliberately discarded: it is the op's payload
	// (image IDs, compose progress), it can be megabytes, and mixing it into
	// the captured stream is how a FAILING backup once reported the text
	// "secrets: loaded 121 values from secrets/env.sops" as its error.
	Run(ctx context.Context, dir string, extraEnv []string, name string, args ...string) (rc int, stderr string)

	// Capture is Run's mirror for the commands whose ANSWER matters rather
	// than their exit status — df, docker images -q, the health probe. It
	// belongs on the interface for the same reason Run does, and learning
	// that the hard way is why it is here: while this package was being
	// written the reclaim ladder called a package-level exec helper instead,
	// so `go test` ran a real `docker image prune -f` against the developer's
	// own daemon. A seam with a hole in it is not a seam.
	Capture(ctx context.Context, dir string, name string, args ...string) (rc int, stdout string)
}

// ExecRunner is the production Runner.
type ExecRunner struct{}

func (ExecRunner) Run(ctx context.Context, dir string, extraEnv []string, name string, args ...string) (int, string) {
	cmd := exec.CommandContext(ctx, name, args...)
	cmd.Dir = dir
	if len(extraEnv) > 0 {
		cmd.Env = append(os.Environ(), extraEnv...)
	}
	var errBuf bytes.Buffer
	cmd.Stdout = io.Discard
	cmd.Stderr = &errBuf
	err := cmd.Run()
	stderr := strings.TrimSpace(errBuf.String())
	if err != nil && stderr == "" {
		// Not started at all (binary or dir missing): without this the
		// result says rc=127 and nothing about why.
		stderr = err.Error()
	}
	return exitCode(err), stderr
}

func (ExecRunner) Capture(ctx context.Context, dir string, name string, args ...string) (int, string) {
	cmd := exec.CommandContext(ctx, name, args...)
	cmd.Dir = dir
	var outBuf bytes.Buffer
	cmd.Stdout = &outBuf
	cmd.Stderr = io.Discard
	err := cmd.Run()
	return exitCode(err), strings.TrimSpace(outBuf.String())
}

// exitCode normalises the several ways os/exec reports failure into the single
// integer the Result schema carries.
//
// A command that could not be STARTED (binary missing, dir gone) has no exit
// code at all; it must not report 0, because 0 is the value every caller reads
// as success. 127 is the shell's own convention for "command not found", which
// keeps the number meaningful to an operator reading a result file.
func exitCode(err error) int {
	if err == nil {
		return 0
	}
	var ee *exec.ExitError
	if errors.As(err, &ee) {
		if code := ee.ExitCode(); code >= 0 {
			return code
		}
		return 1 // killed by signal
	}
	return 127
}

// startStreaming starts a long-lived child and hands back its stdout and
// a wait function. The follower op (journal_follow.go) reads a child that
// never exits on purpose, which neither Run nor Capture can express; it is
// here, with the rest of the exec seam, and overridable there via a
// package var so the hostd tests never start a real journalctl.
func startStreaming(ctx context.Context, name string, args ...string) (io.ReadCloser, func() error, error) {
	cmd := exec.CommandContext(ctx, name, args...)
	cmd.Stderr = io.Discard
	out, err := cmd.StdoutPipe()
	if err != nil {
		return nil, nil, err
	}
	if err := cmd.Start(); err != nil {
		return nil, nil, err
	}
	return out, cmd.Wait, nil
}

// withSecrets wraps a command so it runs with the decrypted environment.
//
// This is the one place bash survives the port, and it is a considered
// boundary rather than an unfinished edge. scripts/lib-secrets.sh is the
// single implementation of "load the authoritative SOPS+age store", shared
// with every launcher script. Reimplementing age keyring discovery and SOPS
// decryption in Go would create a SECOND implementation of the mechanism whose
// entire value is being the only one — and secrets/env.sops is authoritative
// precisely because nothing else gets to have an opinion about it.
//
// The subshell matters. Secrets exist for the lifetime of this one command and
// are never absorbed into the long-lived daemon's environment, and they are
// re-read per run, so rotating a passphrase takes effect without a restart.
// Both properties were bug fixes in the bash version: a scheduled backup once
// wrote UNENCRYPTED for weeks because the watcher had started before the
// passphrase existed, while manual runs — where the operator had sourced the
// env — looked fine.
func withSecrets(root string, name string, args ...string) (string, []string) {
	quoted := make([]string, 0, len(args)+1)
	for _, a := range append([]string{name}, args...) {
		quoted = append(quoted, shellQuote(a))
	}
	// lib-config.sh is loaded ALONGSIDE the secrets: compose renders
	// interpolate deployment vars — NOO_IMAGE_PREFIX/NOO_IMAGE_TAG above all —
	// from noomesh.yaml `compose_env:`, exactly as every launcher does.
	// Without it a spooled `recreate gateway` rendered
	// `pai-assistant/gateway:latest` and would have silently deployed a
	// day-old LOCAL build over the pinned GHCR release. Config
	// load is best-effort (a worker may have no noomesh.yaml); secrets
	// remain load-bearing.
	//
	// load_secrets also writes the compose `file:` secrets to a tmpfs directory
	// (lib-secrets.sh write_secret_files) and exports NOO_SECRET_RUNDIR for the
	// compose process it execs. Its stderr is NOT discarded: a refusal (the
	// directory is not tmpfs, the chown container could not run) explains itself
	// there, and the spool result is where the gateway and the operator read it.
	script := fmt.Sprintf(
		`. %s 2>/dev/null || true
if ! load_secrets >/dev/null; then
  echo "could not load secrets or write the secret files — cannot read the authoritative store (reason above)" >&2
  exit 1
fi
. %s 2>/dev/null && load_config >/dev/null 2>&1 || true
exec %s`,
		shellQuote(filepath.Join(root, "scripts", "lib-secrets.sh")),
		shellQuote(filepath.Join(root, "scripts", "lib-config.sh")),
		strings.Join(quoted, " "),
	)
	return "bash", []string{"-c", script}
}

// shellQuote renders s as a single-quoted shell word.
//
// Only used for paths and binaries this daemon itself resolved — never for
// spool input, which reaches argv directly through exec (no shell) after
// passing the allowlists in ops.go. Belt and braces: if a future op does route
// caller data through here, it stays one word.
func shellQuote(s string) string {
	return "'" + strings.ReplaceAll(s, "'", `'\''`) + "'"
}
