// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 PersonifAI LLC

package backendrt

// On a Mac the native lane is the ONLY lane for the backends it can serve.
//
// Docker on a Mac runs a Linux VM with no GPU passthrough, and a Mac node may
// have no Docker at all. Before this file, a native Ollama that was not
// serving looked exactly like "no native lane": Native.Running returned {},
// the reconciler fell through to the container start path, and the node
// reported a docker.sock dial error on every tick (followup i1156) while the
// real cause was a stopped Ollama. The fix states the fact instead: a typed
// NativeDownError that names the lane, the state and the remedy, used by the
// reconciler, the prefetch, the start-backend API and the import path.
//
// "Exclusive" is a property of the lane, not of the OS: NewNative (darwin
// only) builds a runtime "native" lane, and so does NewNativeAt (the test
// seam). The self-node's "stack" lane is not exclusive.

import (
	"os"
	"os/exec"
	"os/user"
	"strings"
)

// Exclusive reports whether this lane is the only lane for the backends it
// serves: true for the native lane (a Mac), false for the stack lane and for
// no lane at all.
func (n *Native) Exclusive() bool {
	return n != nil && n.runtime == "native"
}

// NativeOnly reports whether backend may run on this node only through this
// lane: the lane is exclusive and can serve the backend. Nothing may start it
// as a container here.
func (n *Native) NativeOnly(backend string) bool {
	if !n.Exclusive() {
		return false
	}
	_, ok := n.Endpoint(backend)
	return ok
}

// DownError is the refusal for a NativeOnly backend that is not serving.
func (n *Native) DownError(backend string) *NativeDownError {
	return NewNativeDownError(backend, OllamaBinaryPresent())
}

// NewNativeDownError is the refusal for backend, run as this agent's user.
func NewNativeDownError(backend string, binaryPresent bool) *NativeDownError {
	return &NativeDownError{Backend: backend, BinaryPresent: binaryPresent, User: nodeUser()}
}

// NativeDownError: the native lane is this node's only lane for Backend, and
// nothing answers on its loopback port.
type NativeDownError struct {
	Backend string
	// BinaryPresent: an `ollama` binary is installed (PATH or a Homebrew
	// prefix). It picks the remedy: start it, or install it first.
	BinaryPresent bool
	// User is the node's user, the one the boot service runs Ollama as
	// (`--sudo-service-user`); "" renders as "$USER".
	User string
}

// NativeDownCode is the stable code the start-backend API answers with.
const NativeDownCode = "native_backend_down"

// OllamaBootServiceCmd is the command that registers the native Ollama as a
// boot service run as user. `--sudo-service-user` makes Homebrew write
// UserName into the system plist (Library/Homebrew/services/cli.rb
// install_service_file); without it a root `brew services start` runs Ollama
// as root, with root's home and an empty model store.
func OllamaBootServiceCmd(user string) string {
	if strings.TrimSpace(user) == "" {
		user = `"$USER"`
	}
	return "sudo HOMEBREW_NO_ANALYTICS=1 brew services start --sudo-service-user " + user + " ollama"
}

// OllamaInstallCmd installs the native Ollama with Homebrew.
const OllamaInstallCmd = "HOMEBREW_NO_ANALYTICS=1 brew install ollama"

func (e *NativeDownError) Error() string {
	if e.BinaryPresent {
		return "the native Ollama isn't running on this Mac: start it with `" + OllamaBootServiceCmd(e.User) +
			"` (a boot service), or run `noo enroll --resume`"
	}
	return "the native Ollama isn't installed on this Mac: install it: `" + OllamaInstallCmd +
		"`, then start it with `" + OllamaBootServiceCmd(e.User) + "` (a boot service), or run `noo enroll --resume`"
}

// ollamaBinaryPaths are where a Homebrew ollama lands when PATH does not
// name it (a launchd-started agent gets a minimal PATH).
var ollamaBinaryPaths = []string{"/opt/homebrew/bin/ollama", "/usr/local/bin/ollama"}

// OllamaBinaryPresent reports whether an ollama binary is installed. A
// package var: tests replace it.
var OllamaBinaryPresent = func() bool {
	if _, err := exec.LookPath("ollama"); err == nil {
		return true
	}
	for _, p := range ollamaBinaryPaths {
		if st, err := os.Stat(p); err == nil && st.Mode().IsRegular() && st.Mode().Perm()&0o111 != 0 {
			return true
		}
	}
	return false
}

func nodeUser() string {
	if u, err := user.Current(); err == nil {
		return u.Username
	}
	return ""
}
