// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 PersonifAI LLC

package logship

import "testing"

// The same vectors as tests/test_url_userinfo_scrub.py::VECTORS and the
// Rust `redact::url_userinfo_tests`.
func TestScrubURLUserinfo(t *testing.T) {
	cases := []struct{ raw, want string }{
		{"rediss://:hunter2@redis:6379/0", "rediss://redis:6379/0"},
		{"tls://noo:s3cret@nats:4222", "tls://nats:4222"},
		{"rediss://u:p@ss@redis:6379", "rediss://redis:6379"}, // '@' in the password: cut at the LAST one
		{"https://h:1/x@y?u=a@b", "https://h:1/x@y?u=a@b"},    // '@' past the authority is data
		{"rediss://redis:6379", "rediss://redis:6379"},
		{"tls://nats:4222", "tls://nats:4222"},
		{"redis:6379", "redis:6379"}, // no scheme: readable as-is
		{"https://h/p?q=1#f", "https://h/p?q=1#f"},
		{"", ""},
	}
	for _, c := range cases {
		if got := ScrubURLUserinfo(c.raw); got != c.want {
			t.Errorf("ScrubURLUserinfo(%q) = %q, want %q", c.raw, got, c.want)
		}
	}
}
