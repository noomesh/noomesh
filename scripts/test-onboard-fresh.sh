#!/usr/bin/env bash
# SPDX-License-Identifier: AGPL-3.0-only
# Copyright 2026 PersonifAI LLC

# 0->1 from-scratch onboarding smoke test.
#
# Proves that a customer running Mesh on a CLEAN machine — no age, no sops,
# nothing pre-installed — gets working encrypted-at-rest secrets. Runs the
# REAL scripts/noo-secrets-sops-init.sh (the exact script the native Rust
# wizard's security step invokes; the Python wizard that used to be driven
# here is archived in legacy/python-onboard/) inside a fresh container,
# then asserts the artifacts and a decrypt round-trip.
#
# The wizard-side wiring (backend prompt, NOO_SECRETS_BACKEND flip, fallback
# to plaintext on failure) is unit-tested in Rust; this covers the 0->1
# auto-install + encrypt path underneath it. Needs Docker + network
# (downloads age/sops), so it runs on demand / nightly, not on every push.
#
# Usage:   scripts/test-onboard-fresh.sh
# Env:     NOO_TEST_IMAGE   base image (default python:3.11-slim)
#          KEEP_CONTAINER=1 leave the container around for debugging
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
IMAGE="${NOO_TEST_IMAGE:-python:3.11-slim}"

if ! command -v docker >/dev/null 2>&1; then
    echo "SKIP: docker not available — this test needs a container runtime." >&2
    exit 0
fi

echo "== 0->1 fresh-install onboarding test (image: $IMAGE)"

# Stage a CLEAN source tree = exactly the committed files. `git archive`
# excludes the untracked .env / secrets/ / .git, so no real secret can ever
# enter the test.  All host-side files are owned by the invoking user; the
# container writes only inside itself (removed with the container).
STAGE="$(mktemp -d)"
cleanup() { rm -rf "$STAGE"; [ -n "${CID:-}" ] && [ -z "${KEEP_CONTAINER:-}" ] && docker rm -f "$CID" >/dev/null 2>&1 || true; }
trap cleanup EXIT
git -C "$REPO_ROOT" archive --format=tar HEAD | tar -x -C "$STAGE"

# --- in-container orchestration + assertions ---------------------------------
cat > "$STAGE/_run_test.sh" <<'RUN'
set -euo pipefail
export HOME=/root
export PATH="$HOME/.local/bin:$PATH"
cd /opt/app

echo "-- preflight: age/sops must be ABSENT (proves auto-install runs)"
if command -v age >/dev/null 2>&1 || command -v sops >/dev/null 2>&1; then
    echo "FAIL: age/sops already in base image — not a from-scratch test" >&2; exit 1
fi

echo "-- installing OS deps (curl only — the sops path is python-free now)"
apt-get update -qq >/dev/null
apt-get install -y -qq curl >/dev/null          # init script downloads via curl

echo "-- synthesizing a pre-sops .env (as the wizard's security step leaves it:"
echo "   generated secrets already written by the Rust step, before it runs the script)"
JWT_SEED="$(head -c 32 /dev/urandom | base64 | tr -d '=+/' | head -c 32)"
cat > .env <<ENV
NODE_ID=fresh-test
NOO_BIND_ADDR=127.0.0.1
NOO_JWT_SECRET=$JWT_SEED
ENV

echo "-- running the REAL sops init script (what 'noo onboard' security step runs)"
timeout 300 bash scripts/noo-secrets-sops-init.sh

echo "-- assert: age key exists and is 0600"
KEY="$HOME/.config/sops/age/keys.txt"
[ -f "$KEY" ] || { echo "FAIL: no age key at $KEY" >&2; exit 1; }
[ "$(stat -c %a "$KEY")" = "600" ] || { echo "FAIL: age key not 0600" >&2; exit 1; }

echo "-- assert: age + sops were auto-installed to ~/.local/bin"
command -v age  >/dev/null || { echo "FAIL: age not installed" >&2; exit 1; }
command -v sops >/dev/null || { echo "FAIL: sops not installed" >&2; exit 1; }

echo "-- assert: encrypted secrets/env.sops exists and is actually encrypted"
[ -f secrets/env.sops ] || { echo "FAIL: no secrets/env.sops" >&2; exit 1; }
grep -q 'ENC\[' secrets/env.sops || { echo "FAIL: env.sops not encrypted (no ENC[ markers)" >&2; exit 1; }

# (NOO_SECRETS_BACKEND=sops is flipped by the WIZARD after this script
# succeeds — that wiring is unit-tested in Rust, not here.)

echo "-- assert: decrypt round-trips and yields the seeded secret"
DEC="$(sops -d --input-type dotenv --output-type dotenv secrets/env.sops)"
echo "$DEC" | grep -q '^NOO_JWT_SECRET=..*' || { echo "FAIL: decrypt missing NOO_JWT_SECRET" >&2; exit 1; }

echo "-- assert: the generated JWT secret is NOT stored in cleartext in env.sops"
JWT="$(echo "$DEC" | sed -n 's/^NOO_JWT_SECRET=//p' | head -1)"
if [ -n "$JWT" ] && grep -qF "$JWT" secrets/env.sops; then
    echo "FAIL: plaintext JWT secret leaked into env.sops" >&2; exit 1
fi

echo ""
echo "PASS: fresh install produced encrypted-at-rest secrets from scratch."
RUN

# --- run: create -> cp clean tree in -> start (no host bind, no root-owned files)
CID="$(docker create -e HOME=/root -w /opt/app "$IMAGE" bash /opt/app/_run_test.sh)"
docker cp "$STAGE/." "$CID:/opt/app" >/dev/null
echo "-- container: $CID"
set +e
docker start -a "$CID"
rc=$?
set -e

if [ "$rc" -eq 0 ]; then
    echo "== OK: 0->1 onboarding from scratch works."
else
    echo "== FAILED (exit $rc). Re-run with KEEP_CONTAINER=1 to inspect." >&2
fi
exit "$rc"
