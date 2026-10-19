#!/bin/bash
# SPDX-License-Identifier: AGPL-3.0-only
# Copyright 2026 PersonifAI LLC

# sign-bundle — build a signed noo-apply bundle from a staging directory
#. Controller-side; the single non-Rust producer of
# the bundle format so the ansible lane and a human at a shell build EXACTLY
# what noo-cli's push-nodes builds.
#
#   sign-bundle.sh <staging-dir> <node> [signing-key] > bundle.tar
#
# <staging-dir> holds one file per KIND, named exactly as noo-apply's
# allowlist names them (ca.crt, node.crt, node.key, agent-env, agent-unit,
# agent-binary, …; the KNOWN list below). Unknown names are refused HERE too — a
# bundle that would die on the node should die on the controller, where the
# operator can still read the error.
#
# The signature (openssl dgst -sha256 with the fleet signing key) is the entire
# authority model: noo-apply refuses anything else. Keep this script boring.
#
# <node> is the node this bundle is FOR, and it is not decoration. The
# manifest carries it, the signature covers it, and noo-apply refuses a
# bundle whose node disagrees with the identity the node already has. Before
# that binding existed, a bundle was addressed to nobody: a cert bundle
# captured on its way to node A -- which carries A's node.key -- could be
# applied to node B, handing B node A's private key and, with it, A's
# identity. The same gap let an old bundle be replayed later to roll a node
# back onto a rotated cert or a superseded agent-env. The `teardown` kind
# had its own per-node check for exactly this reason; every other kind now
# gets the same protection from the manifest itself.
set -eu

STAGE="${1:?usage: sign-bundle.sh <staging-dir> <node> [ca-key] > bundle.tar}"
NODE="${2:?usage: sign-bundle.sh <staging-dir> <node> [ca-key] > bundle.tar}"
# Which key signs. §3f R26 split the fleet CODE-SIGNING key out of the
# cluster CA: `pki/signing.key` signs bundles, `pki/ca.key` signs only a
# signing-key ROLLOVER (a bundle carrying `signing-pub`). Default to the
# signing key when one exists so a hand-built bundle matches what the CLI
# produces; pass the CA key explicitly as $3 to build a rollover (it must
# carry signing-pub, and is countersigned with every retained signing key).
_PKI="$(cd "$(dirname "$0")/.." && pwd)/pki"
CA_KEY="${3:-}"
if [ -z "$CA_KEY" ]; then
    if [ -r "$_PKI/signing.key" ]; then CA_KEY="$_PKI/signing.key"; else CA_KEY="$_PKI/ca.key"; fi
fi

case "$NODE" in
    *[!A-Za-z0-9._-]*|"") echo "sign-bundle: '$NODE' is not a node name" >&2; exit 64 ;;
esac

[ -d "$STAGE" ] || { echo "sign-bundle: $STAGE is not a directory" >&2; exit 64; }
[ -r "$CA_KEY" ] || { echo "sign-bundle: cannot read CA key at $CA_KEY" >&2; exit 66; }
[ -t 1 ] && { echo "sign-bundle: refusing to write a tar to a terminal — redirect stdout" >&2; exit 64; }

KNOWN="ca.crt node.crt node.key agent-env agent-unit agent-binary teardown applier hostd-binary restart-backends host-telemetry cli-binary cli-user fetcher nats-creds fleet-secrets signing-pub harness-binary harness-env harness-unit svc-vllm.crt svc-vllm.key svc-llamacpp.crt svc-llamacpp.key svc-ollama.crt svc-ollama.key svc-tei.crt svc-tei.key svc-reranker.crt svc-reranker.key vendor-cli vendor-cli-manifest vendor-cli-2 vendor-cli-2-manifest vendor-cli-3 vendor-cli-3-manifest"

WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT
mkdir -p "$WORK/files"

# Manifest header, covered by the signature like everything else. Comment
# lines so an older applier's `while read sum kind` loop cannot mistake them
# for a payload line -- it will refuse them as an unknown kind, which is the
# correct answer from an applier that cannot enforce the binding anyway.
{
    echo "#noo-bundle 2"
    echo "#node $NODE"
    echo "#issued $(date -u +%s)"
} > "$WORK/manifest"

count=0
for f in "$STAGE"/*; do
    [ -f "$f" ] || continue
    kind="$(basename "$f")"
    case " $KNOWN " in
        *" $kind "*) : ;;
        *) echo "sign-bundle: '$kind' is not a bundle kind (known: $KNOWN)" >&2; exit 65 ;;
    esac
    cp "$f" "$WORK/files/$kind"
    printf '%s  %s\n' "$(sha256sum "$WORK/files/$kind" | awk '{print $1}')" "$kind" >> "$WORK/manifest"
    count=$((count + 1))
done
[ "$count" -gt 0 ] || { echo "sign-bundle: $STAGE contains no bundle files" >&2; exit 65; }

openssl dgst -sha256 -sign "$CA_KEY" -out "$WORK/manifest.sig" "$WORK/manifest"
MEMBERS="manifest manifest.sig"
# an earlier change A1/A2: the CA authorises a bundle only as a signing-key
# ROLLOVER, and a node that already holds a signing key also wants that
# key's countersignature. A CA-signed bundle without `signing-pub` would be
# refused on the node, so it is refused here, where the error is readable.
if [ "$(basename "$CA_KEY")" = "ca.key" ]; then
    [ "$(ls "$WORK/files")" = "signing-pub" ] || {
        echo "sign-bundle: a bundle signed with the CA key must carry signing-pub and NOTHING else — the CA delivers a public key, never code" >&2
        exit 65
    }
    _n=0
    for _k in "$(dirname "$CA_KEY")/signing.key" $(ls -1t "$(dirname "$CA_KEY")"/signing.key.*.bak 2>/dev/null | head -4); do
        [ -r "$_k" ] || continue
        openssl dgst -sha256 -sign "$_k" -out "$WORK/manifest.xsig.$_n" "$WORK/manifest"
        MEMBERS="$MEMBERS manifest.xsig.$_n"
        _n=$((_n + 1))
    done
fi
# shellcheck disable=SC2086
tar -cf - -C "$WORK" $MEMBERS files
