// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 PersonifAI LLC

package docker

import (
	"reflect"
	"testing"
)

// A name NOO_BACKEND_CAP_ADD asks for outside the allow-list is refused
// (dropped), the rest granted; unset is the default set; "none" grants none.
func TestBackendCapsDecisionNamesWhatItRefused(t *testing.T) {
	d := decideBackendCaps("chown, CAP_SYS_ADMIN,sys_nice,NET_ADMIN")
	if d.Source != "env" || !reflect.DeepEqual(d.Granted, []string{"CHOWN", "SYS_NICE"}) || !reflect.DeepEqual(d.Refused, []string{"SYS_ADMIN", "NET_ADMIN"}) {
		t.Fatalf("got %+v", d)
	}
	if d := decideBackendCaps(""); d.Source != "default" || !reflect.DeepEqual(d.Granted, backendCapsDefault) || d.Refused != nil {
		t.Fatalf("unset: %+v", d)
	}
	if d := decideBackendCaps("None"); d.Source != "none" || d.Granted != nil || d.Refused != nil {
		t.Fatalf("none: %+v", d)
	}
}

// The heartbeat's backend_caps carries the refusal, the granted set and the
// allow-list, with empty lists (never null) so the controller can read them.
func TestBackendCapsReportCarriesTheRefusal(t *testing.T) {
	t.Setenv(BackendCapsEnv, "CHOWN,SYS_ADMIN")
	r := BackendCapsReport().(map[string]any)
	if r["source"] != "env" || !reflect.DeepEqual(r["granted"], []string{"CHOWN"}) || !reflect.DeepEqual(r["refused"], []string{"SYS_ADMIN"}) {
		t.Fatalf("report %v", r)
	}
	if !reflect.DeepEqual(r["allowed"], backendCapAllowedList()) {
		t.Fatalf("allowed %v", r["allowed"])
	}
	t.Setenv(BackendCapsEnv, "none")
	r = BackendCapsReport().(map[string]any)
	if g, ok := r["granted"].([]string); !ok || g == nil || len(g) != 0 {
		t.Fatalf("none must report an empty list, got %#v", r["granted"])
	}
}
