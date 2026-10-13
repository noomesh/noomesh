// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 PersonifAI LLC

package api

import "testing"

func TestIsCGNAT(t *testing.T) {
	yes := []string{"100.64.0.1", "100.64.0.17", "100.127.255.254"}          // leak-ok: CGNAT range-edge test, not a real node
	no := []string{"100.63.255.255", "100.128.0.1", "10.0.0.1", "127.0.0.1", // leak-ok: CGNAT range-edge test, not a real node
		"192.168.1.1", "::1", "fd7a:115c:a1e0::1", "not-an-ip", ""}
	for _, ip := range yes {
		if !isCGNAT(ip) {
			t.Errorf("isCGNAT(%q) = false, want true", ip)
		}
	}
	for _, ip := range no {
		if isCGNAT(ip) {
			t.Errorf("isCGNAT(%q) = true, want false", ip)
		}
	}
}

func TestItoa(t *testing.T) {
	for n, want := range map[int]string{1: "1", 8844: "8844", 65535: "65535"} {
		if got := itoa(n); got != want {
			t.Errorf("itoa(%d) = %q, want %q", n, got, want)
		}
	}
}
