// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 PersonifAI LLC

package egressfilter

import (
	"context"
	"fmt"
	"io"
	"path/filepath"
	"strings"
)

// CheckReadOnly returns an error for any command this package must never run:
// a firewall write, a docker mutation, a tracker write, or a binary it has no
// business with. It is an allow-list, not a deny-list: docker may only list,
// inspect and ask for info; nft may only list; conntrack may only listen,
// list or print its version. A new call site that is not covered fails
// closed.
func CheckReadOnly(name string, args []string) error {
	base := filepath.Base(name)
	switch {
	case strings.HasPrefix(base, "iptables") || strings.HasPrefix(base, "ip6tables"):
		if strings.Contains(base, "restore") {
			return fmt.Errorf("refused: %s writes the firewall", base)
		}
		for _, a := range args {
			switch a {
			case "-A", "-I", "-D", "-R", "-N", "-X", "-F", "-Z", "-P", "-E",
				"--append", "--insert", "--delete", "--replace", "--new-chain",
				"--delete-chain", "--flush", "--zero", "--policy", "--rename-chain":
				return fmt.Errorf("refused: %s %s is a firewall write", base, a)
			}
		}
		return nil
	case base == "nft":
		listed := false
		for _, a := range args {
			switch a {
			case "add", "create", "delete", "destroy", "flush", "insert", "replace",
				"rename", "reset", "-f", "--file", "-i", "--interactive":
				return fmt.Errorf("refused: nft %s is a firewall write", a)
			case "list", "--version", "-v":
				listed = true
			}
		}
		if !listed {
			return fmt.Errorf("refused: nft is allowed to list only")
		}
		return nil
	case base == "docker":
		verbs := positional(args)
		if len(verbs) >= 1 && (verbs[0] == "info" || verbs[0] == "version") {
			return nil
		}
		if len(verbs) >= 2 && verbs[0] == "network" && (verbs[1] == "ls" || verbs[1] == "inspect") {
			return nil
		}
		return fmt.Errorf("refused: docker %s is not on the read-only list (info, version, network ls, network inspect)", strings.Join(verbs, " "))
	case base == "conntrack":
		for _, a := range args {
			switch a {
			case "-D", "-I", "-U", "-F", "-A", "--delete", "--create", "--update", "--flush", "--add":
				return fmt.Errorf("refused: conntrack %s changes the tracker", a)
			}
		}
		return nil
	}
	return fmt.Errorf("refused: %s is not a command this package runs", base)
}

// positional returns the args that are not flags. A flag that takes a value
// (--format X) is written --format=X by this package, so a plain skip is
// enough; the docker calls here use that form.
func positional(args []string) []string {
	var out []string
	for _, a := range args {
		if !strings.HasPrefix(a, "-") {
			out = append(out, a)
		}
	}
	return out
}

// GuardRunner refuses writes before they reach the inner Runner.
type GuardRunner struct{ Inner Runner }

func (g GuardRunner) Capture(ctx context.Context, dir string, name string, args ...string) (int, string) {
	if err := CheckReadOnly(name, args); err != nil {
		return 126, err.Error()
	}
	return g.Inner.Capture(ctx, dir, name, args...)
}

// GuardStreamer is GuardRunner for the long-lived child.
func GuardStreamer(inner Streamer) Streamer {
	return func(ctx context.Context, name string, args ...string) (io.ReadCloser, func() error, func() string, error) {
		if err := CheckReadOnly(name, args); err != nil {
			return nil, nil, nil, err
		}
		return inner(ctx, name, args...)
	}
}
