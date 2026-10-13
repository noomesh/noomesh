// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 PersonifAI LLC

package main

import (
	"fmt"
	"io"
	"runtime/debug"
	"strings"

	"github.com/noomesh/noomesh/node-agent-go/internal/version"
)

// command is what the argument list asks the binary to do.
type command int

const (
	cmdRun         command = iota // no arguments: start the agent (systemd, launchd)
	cmdVersion                    // print the version and exit 0
	cmdHelp                       // print usage and exit 0
	cmdPreseed                    // -preseed <repo-url> <dest-dir>
	cmdPreseedFile                // -preseed-file <url> <dest> [sha256]
	cmdHealthcheck                // -healthcheck
	cmdBad                        // anything else: exit 2, NEVER start the agent
)

// Until 2026-09-30 the binary parsed no flags: every argument that was not
// one of the three helper modes fell through to starting a SECOND agent.
// `noo-node-agent --version` on a node did exactly that twice (09-29/30),
// and only exited because NOO_TLS_* was unset in the operator's shell. The
// rule now: the ONLY way to start the agent is no arguments at all — which
// is how the systemd unit (`ExecStart=/usr/local/bin/noo-node-agent`) and
// the macOS run-agent.sh (`exec "$HOME/noomesh/bin/noo-node-agent"`) run it.

const usage = `usage: noo-node-agent [command]

With no arguments, runs the node agent. Configuration is entirely via
environment variables (/etc/noo-node-agent.env under systemd); the agent is
meant to be started by its service, not by hand.

commands:
  --version, -version, version
                  print the build version (the heartbeat's app_version) and exit
  --help, -help, -h, help
                  print this help and exit
  -healthcheck    probe the RUNNING agent's /health over mTLS (exit 0 = healthy)
  -preseed <repo-url> <dest-dir>
                  copy a HuggingFace snapshot from the controller's model store
  -preseed-file <url> <dest> [sha256]
                  copy one weight file from the controller's model store

--version and --help read no environment, open no files and start nothing.
Any other argument exits 2 without starting the agent.
`

// parseArgs maps os.Args[1:] to a command. It reads nothing but args.
// Double-dash spellings of the helper modes are accepted too.
func parseArgs(args []string) (command, string) {
	if len(args) == 0 {
		return cmdRun, ""
	}
	first := args[0]
	norm := first
	if strings.HasPrefix(norm, "--") {
		norm = norm[1:]
	}
	switch norm {
	case "-version", "version":
		return cmdVersion, ""
	case "-help", "-h", "help":
		return cmdHelp, ""
	case "-healthcheck":
		if len(args) != 1 {
			return cmdBad, "-healthcheck takes no arguments"
		}
		return cmdHealthcheck, ""
	case "-preseed":
		if len(args) != 3 {
			return cmdBad, "-preseed needs exactly <repo-url> <dest-dir>"
		}
		return cmdPreseed, ""
	case "-preseed-file":
		if len(args) != 3 && len(args) != 4 {
			return cmdBad, "-preseed-file needs <url> <dest> [sha256]"
		}
		return cmdPreseedFile, ""
	}
	return cmdBad, fmt.Sprintf("unknown argument %q", first)
}

// versionText is what --version prints. The first line is exactly the
// heartbeat's app_version (version.String(), stamped by -ldflags in
// build-cross.sh and docker/Dockerfile.node-agent-go), so an operator can
// compare it with `noo cluster status` byte for byte.
func versionText() string {
	var b strings.Builder
	fmt.Fprintf(&b, "noo-node-agent %s\n", version.String())
	detail := []string{"commit " + version.Commit}
	if version.BuildDate != "" && version.BuildDate != "unknown" {
		detail = append(detail, "built "+version.BuildDate)
	}
	if bi, ok := debug.ReadBuildInfo(); ok {
		detail = append(detail, bi.GoVersion)
		// An un-stamped build ("dev") still carries the VCS revision Go
		// embedded, which is the only thing that identifies it.
		if version.Commit == "unknown" {
			for _, s := range bi.Settings {
				if s.Key == "vcs.revision" && s.Value != "" {
					detail[0] = "vcs.revision " + s.Value
				}
			}
		}
	}
	fmt.Fprintf(&b, "%s\n", strings.Join(detail, ", "))
	return b.String()
}

// earlyExit handles --version, --help and bad arguments. It returns
// (code, true) when the process must exit now, before main touches the
// environment, the filesystem or the network.
func earlyExit(cmd command, msg string, stdout, stderr io.Writer) (int, bool) {
	switch cmd {
	case cmdVersion:
		fmt.Fprint(stdout, versionText())
		return 0, true
	case cmdHelp:
		fmt.Fprint(stdout, usage)
		return 0, true
	case cmdBad:
		fmt.Fprintf(stderr, "noo-node-agent: %s — the agent was NOT started.\n", msg)
		fmt.Fprintln(stderr, "Run `noo-node-agent --help` for usage. The agent runs from its service (systemctl status noo-node-agent).")
		return 2, true
	}
	return 0, false
}
