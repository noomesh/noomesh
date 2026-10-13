#!/bin/sh
# SPDX-License-Identifier: AGPL-3.0-only
# Copyright 2026 PersonifAI LLC

# Inject PAI cluster CA into system trust store.
# Works on both Debian (update-ca-certificates) and Alpine (direct append).
# Designed to be sourced (. /opt/inject-ca.sh) — never calls exit.
# No-op if NOO_TLS_CA is not set or doesn't exist.

_noo_ca_inject() {
    CA="${NOO_TLS_CA:-}"
    [ -z "$CA" ] && return 0
    [ -f "$CA" ] || return 0

    BUNDLE="/etc/ssl/certs/ca-certificates.crt"

    # Skip if already injected
    if [ -f "$BUNDLE" ] && grep -qF "$(cat "$CA")" "$BUNDLE" 2>/dev/null; then
        return 0
    fi

    # Method 1: update-ca-certificates (Debian/Ubuntu)
    if command -v update-ca-certificates >/dev/null 2>&1; then
        cp "$CA" /usr/local/share/ca-certificates/noo-cluster-ca.crt 2>/dev/null && \
            update-ca-certificates 2>/dev/null
        return 0
    fi

    # Method 2: direct append to bundle (Alpine with write access)
    if [ -f "$BUNDLE" ] && [ -w "$BUNDLE" ]; then
        cat "$CA" >> "$BUNDLE"
        return 0
    fi

    # Method 3: writable copy — set SSL_CERT_FILE for Go/Python
    TMPBUNDLE="/tmp/noo-ca-bundle.pem"
    if [ -f "$BUNDLE" ]; then
        cat "$BUNDLE" "$CA" > "$TMPBUNDLE"
    else
        cp "$CA" "$TMPBUNDLE"
    fi
    export SSL_CERT_FILE="$TMPBUNDLE"
}

_noo_ca_inject
