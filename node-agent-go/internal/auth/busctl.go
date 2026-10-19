// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 PersonifAI LLC

package auth

import (
	"context"
	"crypto/x509"
	"net/http"
)

// busControllerKey marks a context whose request arrived over the control
// bus with a controller envelope that internal/ctrlrpc VERIFIED (cluster-CA
// chain, controller organization, signature over the whole message, fresh
// timestamp, unseen nonce).
type busControllerKey struct{}

// WithBusController returns ctx marked as a verified controller call over the
// bus. Only internal/ctrlrpc calls it, and only after Verify succeeded; the
// bus path has no TLS peer certificate, so this is the bus's equivalent of
// "the verified leaf carries the controller organization".
func WithBusController(ctx context.Context) context.Context {
	return context.WithValue(ctx, busControllerKey{}, true)
}

// IsBusController reports whether r came in over the control bus under a
// verified controller envelope.
func IsBusController(r *http.Request) bool {
	v, _ := r.Context().Value(busControllerKey{}).(bool)
	return v
}

// IsControllerCert reports whether cert carries the controller organization
// (the same test ControllerOnly applies to a TLS peer). It does NOT verify
// the chain; callers verify the chain first.
func IsControllerCert(cert *x509.Certificate) bool {
	return cert != nil && isController([]*x509.Certificate{cert})
}
