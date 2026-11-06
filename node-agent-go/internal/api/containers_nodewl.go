// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 PersonifAI LLC

package api

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"net/http/httputil"
	"net/url"
	"regexp"
	"strings"
	"time"

	dockerpkg "github.com/noomesh/noomesh/node-agent-go/internal/docker"
)

// The relay to an agent-managed node workload (i300 F5c).
//
// A node workload's worker has no published port and no network but its own
// internal one; the only way in is its door sidecar, which pins exactly this
// agent's node leaf. So when the container the gateway names is such a
// worker, the proxy leaves the container-IP path behind entirely and dials
// the door: TLS, the node leaf as the client certificate, the cluster CA as
// the trust root, the door's name (its leaf SAN) as the server name, and the
// door's bridge address read from the daemon on THIS call. There is no
// fallback: a door that is unreachable or does not verify is a 502, never a
// plain or container-IP connection.
//
// How the gateway->agent hop is authenticated: the route is ctrlMW, the same
// as every /api/containers route. The caller proves it is the controller
// (its verified leaf, or the fleet bearer plus the principal check, or the
// controller's tunnel), so the three x-noo-* headers on it are the gateway's
// own and are trusted nowhere else.

// nodeWorkloadDoors is the docker surface the relay needs (the client, or a
// fake in tests).
type nodeWorkloadDoors interface {
	// NodeWorkloadOf: is name an agent-managed workload's worker, and whose.
	NodeWorkloadOf(ctx context.Context, name string) (addon, workload string, managed bool, err error)
	// NodeWorkloadDoorAddr is the door's host:port, read from the daemon.
	NodeWorkloadDoorAddr(ctx context.Context, addon, workload string) (string, error)
}

func (s *Server) nodeDoors() nodeWorkloadDoors {
	if s.workloadDoors != nil {
		return s.workloadDoors
	}
	if s.docker != nil {
		return s.docker
	}
	return nil
}

// The three headers the gateway sets (gateway-rust/src/routes/reservations.rs
// PEER_*_HEADER). They are the ONLY x-noo-* headers that reach a worker.
const (
	peerReservationHeader = "X-Noo-Reservation"
	peerSubHeader         = "X-Noo-Requester-Sub"
	peerRoleHeader        = "X-Noo-Requester-Role"
)

var reservationUUID = regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$`)

// nodeWorkloadPassHeaders is the allowlist, beyond the three peer headers,
// of what a worker sees of the request: the body's type, what the caller
// accepts, and the WebSocket handshake. Everything else is dropped, so the
// worker never sees Origin, Authorization, Cookie, a forwarded-for chain or
// any other x-noo-* a caller could have put there.
var nodeWorkloadPassHeaders = []string{
	"Content-Type", "Accept",
	"Sec-WebSocket-Key", "Sec-WebSocket-Version", "Sec-WebSocket-Protocol",
}

// peerHeaders reads the gateway's three headers. Each must be present exactly
// once: two values cannot be told apart as the gateway's and a client's.
func peerHeaders(h http.Header) (map[string]string, error) {
	out := map[string]string{}
	for _, k := range []string{peerReservationHeader, peerSubHeader, peerRoleHeader} {
		vs := h.Values(k)
		if len(vs) != 1 || strings.TrimSpace(vs[0]) == "" {
			return nil, fmt.Errorf("%s must be present exactly once (the gateway sets it)", k)
		}
		if len(vs[0]) > 512 {
			return nil, fmt.Errorf("%s is too long", k)
		}
		out[k] = vs[0]
	}
	if !reservationUUID.MatchString(out[peerReservationHeader]) {
		return nil, fmt.Errorf("%s must be a lower-case UUID", peerReservationHeader)
	}
	return out, nil
}

// nodeWorkloadHeader builds the outbound header set from the allowlist and
// the three peer headers; nothing else from in survives. up is the upgrade
// type the proxy already normalised ("" for a plain request).
func nodeWorkloadHeader(in http.Header, peer map[string]string, up string) http.Header {
	out := http.Header{}
	for _, k := range nodeWorkloadPassHeaders {
		for _, v := range in.Values(k) {
			out.Add(k, v)
		}
	}
	for k, v := range peer {
		out.Set(k, v)
	}
	if up != "" {
		out.Set("Connection", "Upgrade")
		out.Set("Upgrade", up)
	}
	return out
}

// doorTransport dials exactly one door: TLS with the node leaf, verified
// against the cluster CA as serverName. Nothing is reused across calls, as the
// door's address changes whenever it is recreated.
func (s *Server) doorTransport(serverName, addr string) (*http.Transport, error) {
	pool, caPath := clusterCAPool(s.cfg)
	if pool == nil {
		return nil, fmt.Errorf("the cluster CA %s is not loadable", caPath)
	}
	if s.cfg == nil || s.cfg.TLSCert == "" || s.cfg.TLSKey == "" {
		return nil, errors.New("this node has no leaf certificate to present to the door")
	}
	cert, err := tls.LoadX509KeyPair(s.cfg.TLSCert, s.cfg.TLSKey)
	if err != nil {
		return nil, fmt.Errorf("the node leaf is not loadable: %w", err)
	}
	d := &net.Dialer{Timeout: 30 * time.Second}
	return &http.Transport{
		// The URL names the door; the socket goes to the address the daemon
		// just reported for it. Both are fixed here, not taken from the request.
		DialContext: func(ctx context.Context, network, _ string) (net.Conn, error) {
			return d.DialContext(ctx, network, addr)
		},
		TLSClientConfig: &tls.Config{
			RootCAs:      pool,
			Certificates: []tls.Certificate{cert},
			ServerName:   serverName,
			MinVersion:   tls.VersionTLS12,
		},
		TLSHandshakeTimeout: 10 * time.Second,
		DisableKeepAlives:   true,
		DisableCompression:  true,
	}, nil
}

func badGateway(w http.ResponseWriter, reason string) {
	writeJSON(w, http.StatusBadGateway, map[string]string{"detail": reason})
}

// serveNodeWorkloadProxy relays one HTTP request, or one WebSocket upgrade,
// to the door of the node workload addon/workload.
func (s *Server) serveNodeWorkloadProxy(w http.ResponseWriter, r *http.Request, doors nodeWorkloadDoors, addon, workload string) {
	peer, err := peerHeaders(r.Header)
	if err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"detail": err.Error()})
		return
	}
	up := ""
	if strings.Contains(strings.ToLower(strings.Join(r.Header.Values("Connection"), ",")), "upgrade") || r.Header.Get("Upgrade") != "" {
		if !strings.EqualFold(r.Header.Get("Upgrade"), "websocket") {
			writeJSON(w, http.StatusBadRequest, map[string]string{"detail": "only a websocket upgrade is relayed to a node workload"})
			return
		}
		up = "websocket"
	}
	addr, err := doors.NodeWorkloadDoorAddr(r.Context(), addon, workload)
	if err != nil {
		slog.Warn("node workload door not found", "addon", addon, "workload", workload, "error", err)
		badGateway(w, fmt.Sprintf("the door of %s/%s is not reachable: %v", addon, workload, err))
		return
	}
	doorName := dockerpkg.WorkloadDoorName(addon, workload)
	tr, err := s.doorTransport(doorName, addr)
	if err != nil {
		slog.Error("node workload door cannot be dialled", "addon", addon, "workload", workload, "error", err)
		badGateway(w, fmt.Sprintf("the door of %s/%s cannot be dialled: %v", addon, workload, err))
		return
	}
	defer tr.CloseIdleConnections()
	target := &url.URL{Scheme: "https", Host: doorName}
	path := "/" + r.PathValue("path")
	rp := &httputil.ReverseProxy{
		Transport: tr,
		Rewrite: func(pr *httputil.ProxyRequest) {
			pr.Out.URL.Scheme = target.Scheme
			pr.Out.URL.Host = target.Host
			pr.Out.URL.Path = path
			pr.Out.URL.RawPath = ""
			pr.Out.Host = target.Host
			pr.Out.Header = nodeWorkloadHeader(pr.In.Header, peer, up)
		},
		ErrorHandler: func(w http.ResponseWriter, _ *http.Request, err error) {
			slog.Warn("node workload door call failed", "addon", addon, "workload", workload, "error", err)
			badGateway(w, fmt.Sprintf("the door of %s/%s refused or failed the call: %v", addon, workload, err))
		},
	}
	rp.ServeHTTP(w, r)
}
