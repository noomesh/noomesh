// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 PersonifAI LLC

// Package mutant is the switchboard of the MUTANT proof branch for i300 F5b.
// DO NOT MERGE. Every check the PR adds is guarded by On("<id>"): with
// F5B_MUTANT unset every listed check is DISABLED (the all-at-once mutant);
// with F5B_MUTANT=<id> only that one check is disabled, which is how each
// check is proved red alone.
package mutant

import "os"

var only = os.Getenv("F5B_MUTANT")

// On reports whether the check id is disabled in this run.
func On(id string) bool { return only == "" || only == id }

// Only is for the few mutations that hang or panic the whole package under
// test (a worker that is restarted in a loop, a converge that never runs): they
// are red in isolation, but left on in the all-at-once run they would stop the
// other tests of the package from reporting. They are off unless selected by
// name.
func Only(id string) bool { return only == id }

// Pick returns mutated when check id is disabled, else orig. Both are
// evaluated, so they must be free of side effects.
func Pick[T any](id string, mutated, orig T) T {
	if On(id) {
		return mutated
	}
	return orig
}
