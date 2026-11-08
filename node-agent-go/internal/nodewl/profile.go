// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 PersonifAI LLC

package nodewl

import (
	"fmt"
	"regexp"
	"strconv"
)

var computeCapRe = regexp.MustCompile(`^([0-9]{1,2})\.([0-9]{1,2})$`)

// ComputeCapAtLeast reports whether CUDA compute capability have is at least
// need. The two are compared as numbers, (major, minor), never as strings:
// "10.0" is above "8.0" and "8.10" is above "8.9". A value that does not parse
// is an error, which the caller treats as UNKNOWN, never as low (the i495
// rule: an error must not become a fact).
func ComputeCapAtLeast(have, need string) (bool, error) {
	hMaj, hMin, err := parseComputeCap(have)
	if err != nil {
		return false, err
	}
	mMaj, mMin, err := parseComputeCap(need)
	if err != nil {
		return false, err
	}
	if hMaj != mMaj {
		return hMaj > mMaj, nil
	}
	return hMin >= mMin, nil
}

func parseComputeCap(s string) (major, minor int, err error) {
	m := computeCapRe.FindStringSubmatch(s)
	if m == nil {
		return 0, 0, fmt.Errorf("compute capability %q is not <major>.<minor>", s)
	}
	major, _ = strconv.Atoi(m[1])
	minor, _ = strconv.Atoi(m[2])
	return major, minor, nil
}

// CheckProfile judges an entry's `profile` against the manifest of the set in
// its main slot (the first declared model slot), which ParseDesired cannot
// see. It refuses, with profile_invalid, a profile that is missing, that the
// set does not list, or that cannot serve live audio (realtime: false) when
// the decl asks for a realtime workload. An absent `realtime` means a
// realtime-capable profile.
func CheckProfile(e Entry, mainSet ModelSet) error {
	if e.Profile == nil || *e.Profile == "" {
		return fail(ReasonProfileInvalid, "set %s lists profiles, so the entry must name one", mainSet.ID)
	}
	for _, p := range mainSet.Needs.Profiles {
		if p.Name != *e.Profile {
			continue
		}
		if e.Decl.Accel.Realtime && p.Realtime != nil && !*p.Realtime {
			return fail(ReasonProfileInvalid, "profile %q of %s cannot serve live audio and the workload is realtime", p.Name, mainSet.ID)
		}
		return nil
	}
	return fail(ReasonProfileInvalid, "set %s has no profile %q", mainSet.ID, *e.Profile)
}
