// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 PersonifAI LLC

package hostsvc

import (
	"context"
	"errors"
	"io/fs"
	"os"
	"os/exec"
	"testing"
)

// stubProbes installs a scripted systemctl/launchctl and a "unit is
// installed" stat, restoring the real ones after the test. Nothing here can
// run the real binaries.
func stubProbes(t *testing.T, isActive func(ctx context.Context) ([]byte, error),
	launch func(ctx context.Context, target string) ([]byte, error)) {
	t.Helper()
	oStat, oActive, oLaunch := statFile, runIsActive, runLaunchPrint
	t.Cleanup(func() { statFile, runIsActive, runLaunchPrint = oStat, oActive, oLaunch })
	statFile = func(string) (fs.FileInfo, error) { return nil, nil }
	if isActive != nil {
		runIsActive = isActive
	}
	if launch != nil {
		runLaunchPrint = launch
	}
}

// exitErr is a real *exec.ExitError from a child that ran to completion
// (non-zero), the shape `systemctl is-active` has for inactive/failed.
func exitErr(t *testing.T) error {
	t.Helper()
	err := exec.Command("sh", "-c", "exit 3").Run()
	var ee *exec.ExitError
	if !errors.As(err, &ee) {
		t.Fatalf("expected an ExitError, got %v", err)
	}
	return err
}

// signaledErr is an ExitError from a child killed by a signal (what a
// timeout kill looks like).
func signaledErr(t *testing.T) error {
	t.Helper()
	err := exec.Command("sh", "-c", "kill -9 $$").Run()
	var ee *exec.ExitError
	if !errors.As(err, &ee) {
		t.Fatalf("expected an ExitError, got %v", err)
	}
	return err
}

// A probe that cannot answer is Unknown, never Stopped; a non-zero exit
// WITH a state word is a real answer.
func TestSystemdStateMapping(t *testing.T) {
	nonZero := exitErr(t)
	cases := []struct {
		name string
		out  string
		err  error
		want State
	}{
		{"active", "active\n", nil, Running},
		{"inactive exits non-zero", "inactive\n", nonZero, Stopped},
		{"failed exits non-zero", "failed\n", nonZero, Stopped},
		{"activating exits non-zero", "activating\n", nonZero, Stopped},
		{"deactivating", "deactivating\n", nonZero, Stopped},
		{"exec error, empty output", "", errors.New(`exec: "systemctl": executable file not found in $PATH`), Unknown},
		{"killed, empty output", "", signaledErr(t), Unknown},
		{"exit 0, empty output", "", nil, Unknown},
		{"garbage", "Failed to connect to bus: No such file or directory\n", nonZero, Unknown},
		{"unrecognized word", "wat\n", nil, Unknown},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			stubProbes(t, func(context.Context) ([]byte, error) { return []byte(c.out), c.err }, nil)
			if got := (&systemd{}).State(context.Background()); got != c.want {
				t.Fatalf("State = %q, want %q", got, c.want)
			}
		})
	}
}

// A timeout or cancelled context is Unknown even when the killed child left
// a plausible-looking word behind.
func TestSystemdStateTimeoutIsUnknown(t *testing.T) {
	stubProbes(t, func(context.Context) ([]byte, error) { return []byte("inactive\n"), context.DeadlineExceeded }, nil)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if got := (&systemd{}).State(ctx); got != Unknown {
		t.Fatalf("State on a dead context = %q, want unknown", got)
	}
}

// The not-installed check still wins over the probe.
func TestSystemdStateAbsentStillAbsent(t *testing.T) {
	stubProbes(t, func(context.Context) ([]byte, error) { return []byte("active\n"), nil }, nil)
	statFile = func(string) (fs.FileInfo, error) { return nil, os.ErrNotExist }
	if got := (&systemd{}).State(context.Background()); got != Absent {
		t.Fatalf("State = %q, want absent", got)
	}
}

func TestLaunchdStateMapping(t *testing.T) {
	nonZero := exitErr(t)
	cases := []struct {
		name string
		out  string
		err  error
		want State
	}{
		{"running", "system/x = {\n\tstate = running\n}\n", nil, Running},
		{"waiting", "system/x = {\n\tstate = waiting\n}\n", nil, Stopped},
		{"not bootstrapped (launchctl answered, exit non-zero)", "Could not find service", nonZero, Stopped},
		{"launchctl missing", "", errors.New("exec: not found"), Unknown},
		{"killed", "", signaledErr(t), Unknown},
		{"empty output", "", nil, Unknown},
		{"no state line", "system/x = {\n}\n", nil, Unknown},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			stubProbes(t, nil, func(context.Context, string) ([]byte, error) { return []byte(c.out), c.err })
			if got := (&launchd{}).State(context.Background()); got != c.want {
				t.Fatalf("State = %q, want %q", got, c.want)
			}
		})
	}
}

func TestLaunchdStateTimeoutIsUnknown(t *testing.T) {
	stubProbes(t, nil, func(context.Context, string) ([]byte, error) {
		return []byte("state = running"), context.DeadlineExceeded
	})
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if got := (&launchd{}).State(ctx); got != Unknown {
		t.Fatalf("State on a dead context = %q, want unknown", got)
	}
}
