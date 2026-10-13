// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 PersonifAI LLC

package logship

import "strings"

// ScrubURLUserinfo drops the `user:password@` part of a URL's authority, so
// a connection URL can be logged (or reported on /health) without its
// credential. NATS_URL and NOO_MODEL_CACHE_URL accept
// `scheme://user:password@host:port`; an operator who put the password
// there used to find it in the journal on every connect and every flap.
//
// Structural, not a regex over the line: it is applied to the one value
// that IS a URL, at the call site. The Go twin of the gateway's
// `redact::scrub_url_userinfo` and Python's
// `noomesh.redact.scrub_url_userinfo`; the three share the vectors in
// tests/test_url_userinfo_scrub.py.
//
// A string with no `://`, or no `@` inside the authority, comes back
// unchanged, so a bare `host:port` is still readable. The username goes
// too: it is half of the credential, and the host is what the line is for.
// A password that itself contains `@` is cut at the LAST one; an `@` past
// the authority (path, query, fragment) is data and stays.
func ScrubURLUserinfo(url string) string {
	schemeEnd := strings.Index(url, "://")
	if schemeEnd < 0 {
		return url
	}
	authStart := schemeEnd + 3
	rest := url[authStart:]
	authLen := strings.IndexAny(rest, "/?#")
	if authLen < 0 {
		authLen = len(rest)
	}
	at := strings.LastIndexByte(rest[:authLen], '@')
	if at < 0 {
		return url
	}
	return url[:authStart] + rest[at+1:]
}
