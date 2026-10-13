#!/bin/bash
# SPDX-License-Identifier: AGPL-3.0-only
# Copyright 2026 PersonifAI LLC

# One-time bootstrap for SOPS + age secrets-at-rest.
#
# Installs sops + age if missing, generates an age keypair (the root of trust),
# writes .sops.yaml, and encrypts the current .env → secrets/env.sops. After
# this, set NOO_SECRETS_BACKEND=sops and the launcher decrypts at deploy time —
# no plaintext secrets at rest. See docs/security/secrets.md.
#
# Safe to re-run: it won't overwrite an existing age key or an existing
# secrets/env.sops (it warns instead).
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$REPO_ROOT"

AGE_KEY_DIR="${SOPS_AGE_KEY_DIR:-$HOME/.config/sops/age}"
AGE_KEY_FILE="${SOPS_AGE_KEY_FILE:-$AGE_KEY_DIR/keys.txt}"
ENC_FILE="secrets/env.sops"

echo "== SOPS+age secrets bootstrap =="

# 1. Tooling — auto-install age + sops to ~/.local/bin (no sudo) if missing, so
# `noo onboard` can encrypt secrets with no manual step. Linux amd64/arm64 only;
# on other platforms it prints install hints and exits.
LOCAL_BIN="$HOME/.local/bin"
export PATH="$LOCAL_BIN:$PATH"
_arch() { case "$(uname -m)" in x86_64|amd64) echo amd64 ;; aarch64|arm64) echo arm64 ;; *) echo "" ;; esac; }

# PINNED DIGESTS. These downloads used to be `curl … -o file` and nothing
# else: TLS proved the bytes came from github.com, which is not the same as
# proving they are the bytes the maintainer published, and `sops` is the
# process that decrypts every secret this cluster owns. Each digest below was
# taken from the vendor's own release:
#   - sops: verified against https://github.com/getsops/sops/releases/download/
#     v3.9.1/sops-v3.9.1.checksums.txt (both lines match byte for byte).
#   - age:  v1.2.1 publishes NO checksum file, so these are pinned from the
#     release assets themselves. Residual trust: whoever served the asset the
#     day the pin was taken. That is strictly better than re-deciding on every
#     run — a substituted asset now fails everywhere instead of installing
#     silently — and the pin is reviewable in git.
# Bumping a version means bumping its digests in the same commit.
AGE_VERSION=v1.2.1
SOPS_VERSION=v3.9.1
# shellcheck disable=SC2034  # read via eval indirection in _auto_install_secrets_tools
AGE_SHA256_amd64=7df45a6cc87d4da11cc03a539a7470c15b1041ab2b396af088fe9990f7c79d50
# shellcheck disable=SC2034  # read via eval indirection in _auto_install_secrets_tools
AGE_SHA256_arm64=57fd79a7ece5fe501f351b9dd51a82fbee1ea8db65a8839db17f5c080245e99f
# shellcheck disable=SC2034  # read via eval indirection in _auto_install_secrets_tools
SOPS_SHA256_amd64=cd795109851c3a483bbaa66d15d19ddb2227ac0352b39e25d96b67d51edb6225
# shellcheck disable=SC2034  # read via eval indirection in _auto_install_secrets_tools
SOPS_SHA256_arm64=bc946fef11dbe199587adac567037b69374c4202f928ca138443539efc85b357

# Verify $1 against the expected digest $2, naming both on a mismatch.
_verify_sha256() {
    local file="$1" want="$2" got
    got="$(sha256sum "$file" 2>/dev/null | cut -d' ' -f1)"
    if [ -z "$want" ]; then
        echo "!! no pinned digest for $(basename "$file") — refusing to install" >&2
        return 1
    fi
    if [ "$got" != "$want" ]; then
        echo "!! DIGEST MISMATCH for $(basename "$file")" >&2
        echo "   expected $want" >&2
        echo "   got      $got" >&2
        echo "   Refusing to install. Either the pin in this script is stale (bump it in a" >&2
        echo "   reviewed commit) or the download was tampered with." >&2
        return 1
    fi
    return 0
}

_auto_install_secrets_tools() {
    local arch; arch="$(_arch)"
    if [ "$(uname -s)" != "Linux" ] || [ -z "$arch" ]; then return 1; fi
    mkdir -p "$LOCAL_BIN"
    local tmp; tmp="$(mktemp -d)"
    if ! command -v age >/dev/null 2>&1 || ! command -v age-keygen >/dev/null 2>&1; then
        echo "== installing age $AGE_VERSION → $LOCAL_BIN (no sudo)"
        eval "local want=\"\$AGE_SHA256_${arch}\""
        curl -fsSL "https://github.com/FiloSottile/age/releases/download/${AGE_VERSION}/age-${AGE_VERSION}-linux-${arch}.tar.gz" \
            -o "$tmp/age.tgz" \
            && _verify_sha256 "$tmp/age.tgz" "$want" \
            && tar -xzf "$tmp/age.tgz" -C "$tmp" \
            && install -m755 "$tmp/age/age" "$LOCAL_BIN/age" \
            && install -m755 "$tmp/age/age-keygen" "$LOCAL_BIN/age-keygen" || { rm -rf "$tmp"; return 1; }
    fi
    if ! command -v sops >/dev/null 2>&1; then
        echo "== installing sops $SOPS_VERSION → $LOCAL_BIN (no sudo)"
        eval "local want=\"\$SOPS_SHA256_${arch}\""
        curl -fsSL "https://github.com/getsops/sops/releases/download/${SOPS_VERSION}/sops-${SOPS_VERSION}.linux.${arch}" \
            -o "$tmp/sops" \
            && _verify_sha256 "$tmp/sops" "$want" \
            && install -m755 "$tmp/sops" "$LOCAL_BIN/sops" || { rm -rf "$tmp"; return 1; }
    fi
    rm -rf "$tmp"; return 0
}
if ! command -v age >/dev/null 2>&1 || ! command -v age-keygen >/dev/null 2>&1 \
        || ! command -v sops >/dev/null 2>&1; then
    if ! _auto_install_secrets_tools; then
        echo "!! could not auto-install age/sops. Install them and re-run:"
        echo "   Debian/Ubuntu: sudo apt-get install -y age"
        echo "   sops: https://github.com/getsops/sops/releases ($SOPS_VERSION)"
        exit 1
    fi
fi

# 2. Age keypair (root of trust) — never leaves the host, never committed.
if [ -f "$AGE_KEY_FILE" ]; then
    echo "== age key already exists at $AGE_KEY_FILE (keeping it)"
else
    mkdir -p "$AGE_KEY_DIR"; chmod 700 "$AGE_KEY_DIR"
    age-keygen -o "$AGE_KEY_FILE"
    chmod 600 "$AGE_KEY_FILE"
    echo "== generated age key at $AGE_KEY_FILE (mode 600) — BACK THIS UP SECURELY"
fi
AGE_PUB="$(age-keygen -y "$AGE_KEY_FILE")"
echo "== age public recipient: $AGE_PUB"

# 3. .sops.yaml — encrypt anything under secrets/*.sops to this recipient.
#
# A pre-existing .sops.yaml is only kept when THIS machine's key can serve
# its recipient. A leftover file pinning someone else's (or a deleted)
# recipient makes this script encrypt secrets nobody here can decrypt —
# init "succeeds" and the NEXT `noo stack start` fails closed with a
# decrypt error, far from the cause (found by the sandbox --dist
# rehearsal: a previous run's .sops.yaml survived, its key did not).
if [ -f .sops.yaml ] && ! grep -q "$AGE_PUB" .sops.yaml; then
    echo "!! .sops.yaml pins recipient(s) this machine has no key for:"
    grep -oE 'age1[a-z0-9]+' .sops.yaml | sed 's/^/     /'
    echo "   local recipient: $AGE_PUB"
    echo "   Rewriting .sops.yaml for the local key (old file → .sops.yaml.bak)."
    echo "   Multi-recipient setups: re-add the other recipients afterwards."
    mv .sops.yaml .sops.yaml.bak
fi
if [ ! -f .sops.yaml ]; then
    cat > .sops.yaml <<YAML
# SOPS creation rules — which files get encrypted, and to whom (M-S1).
creation_rules:
  - path_regex: secrets/.*\.sops$
    age: "$AGE_PUB"
YAML
    echo "== wrote .sops.yaml (recipient: $AGE_PUB)"
else
    echo "== .sops.yaml already present and includes this machine's recipient"
fi

# 4. Encrypt the current .env → secrets/env.sops (dotenv in, dotenv out).
mkdir -p secrets; chmod 700 secrets
if [ ! -f .env ]; then
    echo "!! no .env to encrypt — create it first (cp .env.example .env)"; exit 1
fi
if [ -f "$ENC_FILE" ]; then
    echo "== $ENC_FILE already exists — NOT overwriting. To re-encrypt after"
    echo "   editing .env:  sops -e --filename-override $ENC_FILE --input-type dotenv --output-type dotenv .env > $ENC_FILE"
else
    # --filename-override makes sops match the .sops.yaml creation rule against
    # the TARGET path (secrets/env.sops), not the input .env — otherwise sops
    # errors "no matching creation rules found" (the input .env matches no rule).
    SOPS_AGE_KEY_FILE="$AGE_KEY_FILE" \
        sops -e --filename-override "$ENC_FILE" --input-type dotenv --output-type dotenv .env > "$ENC_FILE"
    chmod 600 "$ENC_FILE"
    echo "== encrypted .env → $ENC_FILE"
fi

cat <<DONE

== Done. To switch the cluster onto encrypted secrets:
   1. Verify decrypt works:   sops -d --input-type dotenv --output-type dotenv $ENC_FILE | head
   2. Set in your shell/.env: NOO_SECRETS_BACKEND=sops
   3. Restart:                noo stack restart   (launcher decrypts at deploy)
   4. Once confirmed, you can remove the plaintext .env secrets (keep non-secret
      config) — the encrypted $ENC_FILE + your age key are the source of truth.

Rotation + CA/JWT procedures: docs/security/secrets.md
DONE
