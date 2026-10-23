// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 PersonifAI LLC

// Command noo-hostd is the host-side executor for the gateway's command spool.
//
// It is a SEPARATE binary from noo-node-agent, sharing the same module and Go
// packages, and the separation is the security property rather than an
// accident of layout. noo-node-agent listens on :8081 with mTLS. noo-hostd
// must have no network surface at all — files in, files out, nothing to reach
// it — because it runs on the controller, which holds the age key and the CA
// key, and it can restart containers and ALTER database roles.
//
// If both roles lived in one artifact, "does it listen?" would be a
// CONFIGURATION question on the most privileged machine in the fleet. As two
// artifacts it is a fact about the code: there is no listener in this binary
// because there is no listener in this binary. It also stays small enough to
// read end to end, which is the only real audit a component like this gets.
//
// Usage:
//
//	noo-hostd install [--root DIR] [--system] [--dry-run]
//	noo-hostd run     [--root DIR] [--spool DIR] [--poll 2s]
//	noo-hostd status  [--root DIR]
//	noo-hostd drain   [--root DIR]     # process pending commands once, exit
//	noo-hostd uninstall [--system]
//	sudo noo-hostd at-rest seal-age-key --user <op> --key <path> [--pcrs 7|none|auto]
//	noo-hostd at-rest unseal-status [--json]
package main

import (
	"context"
	"flag"
	"fmt"
	"io"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"
	"time"

	"github.com/noomesh/noomesh/node-agent-go/internal/hostd"
	"github.com/noomesh/noomesh/node-agent-go/internal/version"
)

func main() {
	if len(os.Args) < 2 {
		usage()
		os.Exit(2)
	}
	cmd := os.Args[1]
	args := os.Args[2:]

	var err error
	switch cmd {
	case "run":
		err = cmdRun(args)
	case "drain":
		err = cmdDrain(args)
	case "install":
		err = cmdInstall(args)
	case "generation":
		err = cmdGeneration()
	case "uninstall":
		err = cmdUninstall(args)
	case "status":
		err = cmdStatus(args)
	case "at-rest":
		// Root, interactive only (sudo by a person; i10a). Never a spool op.
		err = hostd.RunAtRest(args, os.Stdout, os.Stderr)
	case "version", "--version", "-v":
		fmt.Println("noo-hostd", version.String())
	case "help", "--help", "-h":
		usage()
	default:
		usage()
		os.Exit(2)
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, "noo-hostd:", err)
		os.Exit(1)
	}
}

func usage() {
	fmt.Fprint(os.Stderr, `noo-hostd — host-side executor for the PAI gateway command spool

  noo-hostd install [--root DIR] [--system] [--dry-run]
        Write and start the service definition (systemd user unit by default,
        launchd on macOS). Re-run after upgrading the binary.

  noo-hostd run [--root DIR] [--spool DIR] [--poll 2s] [--heartbeat 15s]
        Run in the foreground. This is what the service definition invokes,
        and it is also the supported way to run without a service manager.

  noo-hostd status [--root DIR]
        Report whether a live daemon is serving the spool, and which ops it
        supports. Non-zero exit when it is dead or stale.

  noo-hostd drain [--root DIR]
        Process any pending commands once, then exit.

  noo-hostd uninstall [--system]

  sudo noo-hostd at-rest seal-age-key --user <op> --key <path> [--pcrs 7|none|auto]
  noo-hostd at-rest unseal-status [--json]
        Seal the SOPS age key to this machine's TPM and unseal it into RAM at
        boot (Linux controllers; see 'noo-hostd at-rest help').

`)
}

// defaultRoot resolves the project root. Preferring the binary's own location
// over the cwd matters for the service case: systemd sets WorkingDirectory,
// but an operator running `noo-hostd status` from ~ should still find the
// right spool rather than silently reporting on a nonexistent one.
func defaultRoot() string {
	if r := os.Getenv("NOO_PROJECT_ROOT"); r != "" {
		return r
	}
	if wd, err := os.Getwd(); err == nil {
		if _, err := os.Stat(filepath.Join(wd, "docker-compose.cluster.yml")); err == nil {
			return wd
		}
	}
	if self, err := os.Executable(); err == nil {
		// <root>/node-agent-go/bin/noo-hostd and <root>/bin/noo-hostd both
		// resolve by walking up to the compose file.
		dir := filepath.Dir(self)
		for i := 0; i < 4; i++ {
			if _, err := os.Stat(filepath.Join(dir, "docker-compose.cluster.yml")); err == nil {
				return dir
			}
			dir = filepath.Dir(dir)
		}
	}
	if home, err := os.UserHomeDir(); err == nil {
		return filepath.Join(home, "pai-assistant")
	}
	return "."
}

func spoolFor(root, override string) string {
	if override != "" {
		return override
	}
	if s := os.Getenv("NOO_HOST_SPOOL_DIR_HOST"); s != "" {
		return s
	}
	return filepath.Join(root, ".noo-host-spool")
}

// spoolForMode picks the spool location. A worker has no project root or
// compose checkout to anchor to — its spool is the fixed directory the agent
// (the producer) and this daemon (the consumer) both know: WorkerSpoolDir.
func spoolForMode(mode, root, override string) string {
	if mode == hostd.ModeWorker {
		if override != "" {
			return override
		}
		if s := os.Getenv("NOO_HOST_SPOOL_DIR_HOST"); s != "" {
			return s
		}
		return hostd.WorkerSpoolDir
	}
	return spoolFor(root, override)
}

// newEngine builds the Engine and its logger. The log is teed to stderr (which
// systemd captures into the journal) AND to a file in the spool, because the
// spool directory is the one place an operator is already looking when
// something spool-shaped has gone wrong.
func newEngine(root, spool string) (*hostd.Engine, func(), error) {
	if err := os.MkdirAll(spool, 0o755); err != nil {
		return nil, nil, fmt.Errorf("cannot create spool %s: %w", spool, err)
	}
	logPath := filepath.Join(spool, "hostd.log")
	var w io.Writer = os.Stderr
	closer := func() {}
	if f, err := os.OpenFile(logPath, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o644); err == nil {
		w = io.MultiWriter(os.Stderr, f)
		closer = func() { _ = f.Close() }
	}

	e := &hostd.Engine{
		Root:           root,
		Spool:          spool,
		GatewayPort:    envOr("GATEWAY_PORT", "8080"),
		Runner:         hostd.ExecRunner{},
		RestoreOnBoot:  true,
		HealthWake:     envDuration("NOO_HOSTD_HEALTH_WAKE", 15*time.Second),
		HealthTimeout:  envDuration("NOO_HOSTD_HEALTH_TIMEOUT", 180*time.Second),
		HealthInterval: envDuration("NOO_HOSTD_HEALTH_INTERVAL", 5*time.Second),
		Logf: func(format string, a ...any) {
			fmt.Fprintf(w, "[noo-hostd %s] %s\n",
				time.Now().UTC().Format("2006-01-02T15:04:05Z"), fmt.Sprintf(format, a...))
		},
	}
	return e, closer, nil
}

func cmdRun(argv []string) error {
	fs := flag.NewFlagSet("run", flag.ExitOnError)
	root := fs.String("root", defaultRoot(), "project root")
	spool := fs.String("spool", "", "spool directory (default <root>/.noo-host-spool; worker mode: /var/lib/noo-node-agent/spool)")
	poll := fs.Duration("poll", hostd.DefaultPollInterval, "spool scan interval")
	hb := fs.Duration("heartbeat", hostd.DefaultHeartbeatInterval, "heartbeat publish interval")
	mode := fs.String("mode", envOr("NOO_HOSTD_MODE", hostd.ModeController), "op table: controller|worker")
	_ = fs.Parse(argv)

	e, closeLog, err := newEngine(*root, spoolForMode(*mode, *root, *spool))
	if err != nil {
		return err
	}
	e.Mode = *mode
	defer closeLog()

	// SIGTERM is how systemd stops us. Cancelling the context lets an
	// in-flight health poll abandon its remaining wait instead of holding the
	// process open long enough for systemd to escalate to SIGKILL — which
	// would kill a detached rebuild mid-flight.
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	if err := e.Run(ctx, *poll, *hb); err != nil && ctx.Err() == nil {
		return err
	}
	return nil
}

func cmdDrain(argv []string) error {
	fs := flag.NewFlagSet("drain", flag.ExitOnError)
	root := fs.String("root", defaultRoot(), "project root")
	spool := fs.String("spool", "", "spool directory")
	_ = fs.Parse(argv)

	e, closeLog, err := newEngine(*root, spoolFor(*root, *spool))
	if err != nil {
		return err
	}
	defer closeLog()
	e.ScanOnce(context.Background())
	return nil
}

func cmdInstall(argv []string) error {
	fs := flag.NewFlagSet("install", flag.ExitOnError)
	root := fs.String("root", defaultRoot(), "project root")
	system := fs.Bool("system", false, "install a system-wide unit instead of a --user one")
	bin := fs.String("bin", "", "installed binary path (default: this executable)")
	dry := fs.Bool("dry-run", false, "print the unit instead of writing it")
	mode := fs.String("mode", envOr("NOO_HOSTD_MODE", hostd.ModeController), "unit shape: controller|worker (worker mode; always a system unit)")
	_ = fs.Parse(argv)

	return hostd.Install(hostd.InstallOptions{
		Root: *root, System: *system, BinPath: *bin, DryRun: *dry, Mode: *mode,
	})
}

func cmdUninstall(argv []string) error {
	fs := flag.NewFlagSet("uninstall", flag.ExitOnError)
	system := fs.Bool("system", false, "remove the system-wide unit")
	_ = fs.Parse(argv)
	return hostd.Uninstall(*system)
}

func cmdStatus(argv []string) error {
	fs := flag.NewFlagSet("status", flag.ExitOnError)
	root := fs.String("root", defaultRoot(), "project root")
	spool := fs.String("spool", "", "spool directory")
	_ = fs.Parse(argv)

	s, err := hostd.Status(context.Background(), spoolFor(*root, *spool))
	if err != nil {
		return err
	}
	fmt.Println(s)
	return nil
}

func envOr(k, def string) string {
	if v := os.Getenv(k); v != "" {
		return v
	}
	return def
}

func envDuration(k string, def time.Duration) time.Duration {
	v := os.Getenv(k)
	if v == "" {
		return def
	}
	if d, err := time.ParseDuration(v); err == nil {
		return d
	}
	// Bare integers mean seconds, matching the NOO_HOST_WATCHER_*_SEC vars
	// this replaces — an operator carrying "180" across should not silently
	// get the default instead.
	if d, err := time.ParseDuration(v + "s"); err == nil {
		return d
	}
	return def
}
