// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 PersonifAI LLC

// Package modelname holds the one rule for "is this the model the placement
// asked for", shared by the reconciler (is the backend converged) and the
// heartbeat's lanes (is the lane serving it), so the two cannot disagree.
package modelname

import "strings"

// Matches reports whether the model a runtime reports (current) is the model
// a placement asks for (desired). Path prefixes are ignored, because
// detection may report a bare filename for a placed path (compare basenames);
// an empty side matches only an empty side.
func Matches(current, desired string) bool {
	if current == "" || desired == "" {
		return current == desired
	}
	base := func(s string) string {
		if i := strings.LastIndex(s, "/"); i >= 0 {
			return s[i+1:]
		}
		return s
	}
	return base(current) == base(desired)
}
