// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 PersonifAI LLC

package config

// One reader for every secret the node agent holds: env, `NOO_SECRET_` env,
// or a FILE — the Go twin of gateway-rust/src/secret_env.rs and
// src/noomesh/secret_env.py. tests/test_file_reader_parity.py
// parses FileBackedSecrets out of this file, checks it against the applier's
// AGENT_SECRET_KEYS and the macOS applier's list, and fails any
// os.Getenv("NAME") of a manifest name outside this file.
//
// Resolution, for Secret("NAME"):
//
//  1. `NAME_FILE` non-empty → read the file, strip exactly one trailing
//     `\n` (or `\r\n`). Unreadable or empty → an error naming the path. A
//     named file that cannot be read is a broken install, not "unset":
//     falling through to the env would make a mis-delivered secret look
//     like a missing one.
//  2. `NOO_SECRET_NAME` non-empty → that.
//  3. `NAME` non-empty → that.
//  4. "" — the caller keeps its own "unset" behaviour.
//
// `NAME` and `NAME_FILE` both non-empty is REFUSED, not resolved: it means
// two writers disagree about how this node's secret is delivered (the
// applier converts the env file to pointers, so a plain line beside a
// pointer is a merge that went wrong), and picking one silently would hide
// which of them is stale.

import (
	"errors"
	"fmt"
	"os"
	"strings"
)

// FileBackedSecrets is every secret name the agent reads through Secret.
// The Linux applier (scripts/noo-apply.sh AGENT_SECRET_KEYS) and the macOS
// applier (noo-cli node_fetch.rs AGENT_SECRET_KEYS) move exactly these into
// files; the parity guard keeps the three lists identical.
var FileBackedSecrets = []string{
	"NOO_NODE_AGENT_TOKEN",
	"NOO_CLUSTER_SECRET",
	"NATS_NODE_PASSWORD",
}

// SecretFilesCapability is the marker the appliers look for in an installed
// agent binary before they move its secrets into files: an agent without it
// reads only the plain `NAME`, so pointing it at a file would boot it with
// no credentials. It is logged at startup, which is also what keeps the
// string in the binary. Never executed to find out — the appliers grep.
const SecretFilesCapability = "noo-agent-reads-secret-files/1"

// SecretPrefix is the env-prefix convention between `_FILE` and the name.
const SecretPrefix = "NOO_SECRET_"

// SecretFileSuffix turns a secret's name into the variable naming its file.
const SecretFileSuffix = "_FILE"

// StripOneNewline strips exactly one trailing "\r\n" or "\n" — the one an
// editor or `echo` adds. A second newline, or trailing spaces, are the
// value's own.
func StripOneNewline(s string) string {
	if strings.HasSuffix(s, "\r\n") {
		return s[:len(s)-2]
	}
	return strings.TrimSuffix(s, "\n")
}

// ReadSecretFile reads path as name's secret file: an error when it is
// unreadable or empty after the one-newline strip.
func ReadSecretFile(name, path string) (string, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return "", fmt.Errorf("%s%s names %s, which cannot be read (%v); a named secret file "+
			"must exist and be readable by this process", name, SecretFileSuffix, path, err)
	}
	v := StripOneNewline(string(raw))
	if v == "" {
		return "", fmt.Errorf("%s%s names %s, which is empty; an empty secret file is a broken "+
			"delivery, not an unset secret", name, SecretFileSuffix, path)
	}
	return v, nil
}

// SecretFrom is Secret over an arbitrary lookup, so the precedence is
// testable without touching the process environment.
func SecretFrom(name string, get func(string) string) (string, error) {
	path := get(name + SecretFileSuffix)
	if path != "" {
		if get(name) != "" {
			return "", fmt.Errorf("both %s and %s%s are set — refusing to choose between a plain "+
				"value and a secret file; remove the %s line from this node's agent env "+
				"(`noo cluster provision <node>` rewrites it)", name, name, SecretFileSuffix, name)
		}
		return ReadSecretFile(name, path)
	}
	if v := get(SecretPrefix + name); v != "" {
		return v, nil
	}
	return get(name), nil
}

// Secret is the secret called name, from the process environment.
func Secret(name string) (string, error) {
	return SecretFrom(name, os.Getenv)
}

// CheckSecrets resolves every manifest name over get and joins every
// failure — the boot-time refusal, so the operator reads one error naming
// each path instead of a scatter of downstream 401s.
func CheckSecrets(get func(string) string) error {
	var errs []error
	for _, n := range FileBackedSecrets {
		if _, err := SecretFrom(n, get); err != nil {
			errs = append(errs, err)
		}
	}
	return errors.Join(errs...)
}

// SecretLookup returns a getter that answers manifest names through the
// secret reader and every other name from get — for code that takes a
// `func(string) string` (the NATS credential resolver). Any manifest name
// that cannot be resolved is an error here, never an empty answer later.
func SecretLookup(get func(string) string) (func(string) string, error) {
	resolved := make(map[string]string, len(FileBackedSecrets))
	for _, n := range FileBackedSecrets {
		v, err := SecretFrom(n, get)
		if err != nil {
			return nil, err
		}
		resolved[n] = v
	}
	return func(k string) string {
		if v, ok := resolved[k]; ok {
			return v
		}
		return get(k)
	}, nil
}

// secretOrEmpty is Secret for Load, whose contract is a value: a failure
// reads as unset. It is not swallowed — agent.New runs CheckSecrets before
// anything uses the value and refuses to start on the same failure.
func secretOrEmpty(name string) string {
	v, err := Secret(name)
	if err != nil {
		return ""
	}
	return v
}
