// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 PersonifAI LLC

// Tailnet identity endpoints.
//
// The gateway container cannot see a caller's real tailnet address (docker
// userland-proxy SNAT, finding #52) and MUST NOT trust forwarded headers —
// any direct caller can forge them. The self-agent runs on the host, next
// to tailscaled, so it can answer the two questions tailnet-native
// enrollment needs:
//
//	GET  /tailnet/whois?ip=100.x.y.z   → machine name + tags from tailscaled
//	POST /tailnet/dialback             → fetch a nonce FROM the claimed
//	                                     address; WireGuard routing means
//	                                     only the address's true owner can
//	                                     answer, so a matching nonce proves
//	                                     possession.
//
// Both are authMW-protected: only the gateway (cluster HMAC / agent token)
// can ask. Dialback is restricted to the CGNAT range so it cannot be used
// as a generic SSRF primitive.
package api

import (
	"encoding/json"
	"io"
	"net"
	"net/http"
	"os/exec"
	"strings"
	"time"
)

// handleTailnetWhois shells `tailscale whois --json <ip>` and relays the
// fields enrollment admission needs. The tailscale CLI is the stable
// contract here (LocalAPI socket paths vary by distro).
func (s *Server) handleTailnetWhois(w http.ResponseWriter, r *http.Request) {
	ip := strings.TrimSpace(r.URL.Query().Get("ip"))
	if !isCGNAT(ip) {
		writeJSON(w, http.StatusBadRequest, map[string]any{
			"error": "ip must be a tailnet (100.64/10) IPv4 address",
		})
		return
	}
	out, err := exec.Command("tailscale", "whois", "--json", ip).Output()
	if err != nil {
		writeJSON(w, http.StatusBadGateway, map[string]any{
			"error": "tailscale whois failed — is tailscaled running on this host?",
		})
		return
	}
	var who struct {
		Node struct {
			Name string   `json:"Name"`
			Tags []string `json:"Tags"`
		} `json:"Node"`
	}
	if err := json.Unmarshal(out, &who); err != nil || who.Node.Name == "" {
		writeJSON(w, http.StatusBadGateway, map[string]any{
			"error": "unexpected whois output shape",
		})
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"name": strings.TrimSuffix(who.Node.Name, "."),
		"tags": who.Node.Tags,
	})
}

type dialbackRequest struct {
	IP     string `json:"ip"`
	Port   int    `json:"port"`
	Expect string `json:"expect"`
}

// handleTailnetDialback fetches http://<ip>:<port>/.well-known/noo-enroll
// and reports whether the body matches the expected nonce. Plain HTTP is
// sound here: the tailnet already encrypts and authenticates the path, and
// the nonce is single-use material the enrollee itself published.
func (s *Server) handleTailnetDialback(w http.ResponseWriter, r *http.Request) {
	var req dialbackRequest
	if err := json.NewDecoder(io.LimitReader(r.Body, 4096)).Decode(&req); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]any{"error": "bad JSON body"})
		return
	}
	if !isCGNAT(req.IP) || req.Port < 1 || req.Port > 65535 ||
		req.Expect == "" || len(req.Expect) > 128 {
		writeJSON(w, http.StatusBadRequest, map[string]any{
			"error": "need ip (100.64/10), port, expect (nonce, ≤128 chars)",
		})
		return
	}
	client := &http.Client{Timeout: 8 * time.Second}
	url := "http://" + net.JoinHostPort(req.IP, itoa(req.Port)) + "/.well-known/noo-enroll"
	resp, err := client.Get(url)
	if err != nil {
		writeJSON(w, http.StatusOK, map[string]any{
			"ok": false, "reason": "dialback connection failed: " + err.Error(),
		})
		return
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 256))
	got := strings.TrimSpace(string(body))
	writeJSON(w, http.StatusOK, map[string]any{
		"ok": got == req.Expect,
		"reason": map[bool]string{
			true: "", false: "nonce mismatch or empty response",
		}[got == req.Expect],
	})
}

// isCGNAT reports whether ip is an IPv4 address in 100.64.0.0/10 — the
// tailnet range. Everything else is refused so these endpoints can't be
// aimed at LAN or loopback services.
func isCGNAT(ip string) bool {
	p := net.ParseIP(ip)
	if p == nil {
		return false
	}
	v4 := p.To4()
	return v4 != nil && v4[0] == 100 && v4[1] >= 64 && v4[1] < 128
}

func itoa(n int) string {
	b := [8]byte{}
	i := len(b)
	for n > 0 {
		i--
		b[i] = byte('0' + n%10)
		n /= 10
	}
	return string(b[i:])
}
