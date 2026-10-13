// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 PersonifAI LLC

package reconcile

import "testing"

func TestPlainLastLine(t *testing.T) {
	cases := []struct {
		name string
		in   string
		want string
	}{
		{
			name: "plain output, no escapes",
			in:   "pulling manifest\nverifying sha256 digest\nsuccess",
			want: "success",
		},
		{
			name: "OSC terminal query followed by CSI mode toggles",
			// \x1b]11;?\x1b\ = OSC 11 (query background color), ST-terminated
			// \x1b[6n = CSI device status report request
			// \x1b[?2026h = CSI synchronized-output mode set
			in:   "\x1b]11;?\x1b\\\x1b[6n\x1b[?2026hpulling manifest\nsuccess",
			want: "success",
		},
		{
			name: "CSI cursor hide/move around a carriage-return progress bar",
			in:   "\x1b[?25l\x1b[1Gpulling 40%\rpulling 80%\rpulling 100%\r\x1b[?25hsuccess",
			want: "success",
		},
		{
			name: "trailing blank lines and escapes after the real result",
			in:   "success\n\x1b[?25h\n  \n",
			want: "success",
		},
		{
			name: "carriage-return only progress, no trailing newline",
			in:   "verifying sha256 digest\rwriting manifest\rsuccess",
			want: "success",
		},
		{
			name: "empty input",
			in:   "",
			want: "",
		},
		{
			name: "only escape sequences, nothing else",
			in:   "\x1b]11;?\x1b\\\x1b[?2026h\x1b[?25l",
			want: "",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := plainLastLine(tc.in); got != tc.want {
				t.Errorf("plainLastLine(%q) = %q, want %q", tc.in, got, tc.want)
			}
		})
	}
}
