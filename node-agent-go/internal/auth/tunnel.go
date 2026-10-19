// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 PersonifAI LLC

package auth

import (
	"context"
	"net/http"
)

// tunnelControllerKey marks a context whose request arrived on THIS node's
// own authenticated tunnel to the controller (internal/tunnel, followup i131
// phase 2).
//
// The marker is a value in the request's context, set in this process by the
// tunnel client and read here. It is never derived from anything a peer
// sends: not a header, not a query parameter, not a TLS property. A request
// accepted from a TCP socket is built by net/http and carries no such value,
// so no header a TCP caller writes can mint it. The tunnel client sets it
// only for a stream the controller opened on a session whose handshake it
// completed: the TLS server certificate carried the controller organization,
// and the controller signed a fresh challenge naming this node.
type tunnelControllerKey struct{}

// TunnelPrincipalHeader is a header name no one may use to ask for the
// tunnel principal. Nothing reads it as a credential. It exists so the
// tunnel client can drop it from a stream's headers and the tests can assert
// that a TCP request carrying it gains nothing.
const TunnelPrincipalHeader = "X-Noo-Tunnel-Principal"

// WithTunnelController returns ctx marked as a stream from the verified
// controller over this node's own tunnel. Only internal/tunnel calls it.
func WithTunnelController(ctx context.Context) context.Context {
	return context.WithValue(ctx, tunnelControllerKey{}, true)
}

// IsTunnelController reports whether r arrived on this node's own tunnel
// under a verified controller session.
func IsTunnelController(r *http.Request) bool {
	v, _ := r.Context().Value(tunnelControllerKey{}).(bool)
	return v
}
