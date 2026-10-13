#!/bin/sh
# SPDX-License-Identifier: AGPL-3.0-only
# Copyright 2026 PersonifAI LLC

# noo CLI installer — zero-Python standalone control plane for Mesh.
#
# Usage:
#   curl -fsSL https://raw.githubusercontent.com/noomesh/noomesh/main/noo-cli/install.sh | sh
#
# What it does: detects your OS/arch, downloads the matching static musl
# `noo` binary from the latest `noo-cli-v*` GitHub release, verifies its
# SHA-256 checksum, and installs it to ~/.local/bin/noo (no Python, no libc).
#
# Environment overrides:
#   NOO_CLI_VERSION   Pin a specific release tag (e.g. noo-cli-v0.1.0).
#                     Default: latest noo-cli-v* release.
#   NOO_INSTALL_DIR   Install directory. Default: $HOME/.local/bin
#                     Root-owned dirs (e.g. /usr/local/bin) work too: the
#                     final placement uses sudo when the dir is unwritable.
#   NOO_CLI_BASE_URL  Base URL to fetch assets from directly (skips the
#                     GitHub API/release lookup). Assets are expected at
#                     "$NOO_CLI_BASE_URL/noo-<target>", ".sha256", and the
#                     signed manifest pair "sha256sums.txt{,.sig}".
#                     Intended for a controller mirror or a local server.
#   NOO_CLI_CACERT    Path to a CA bundle (PEM) to trust IN ADDITION to the
#                     system store, for a mirror whose certificate is issued
#                     by a private CA — e.g. a controller serving
#                     /bootstrap/cli with a cluster-CA leaf. This is the
#                     ONLY supported way to talk to such a mirror: TLS
#                     verification is never disabled. On a node being
#                     enrolled the file is the controller's CA at
#                     /etc/noo/pki/ca.crt (or ~/noomesh/pki/ca.crt on Mac),
#                     which `noo enroll` pins by fingerprint.
#   NOO_CLI_ALLOW_UNSIGNED=1
#                     Install from a release that publishes no signed
#                     manifest. Needed ONLY to pin a pre-0.3.70 build, and
#                     it drops this script back to the trust level that
#                     motivated the signature in the first place. Mirrors
#                     `noo upgrade --allow-unsigned`.
set -eu

# NOO_CLI_REPO: the distribution CHANNEL knob (fu44). Default = the public
# noomesh repo, whose release assets download unauthenticated; set it to
# install from another channel (a config flip, not a script change).
# This is a declared home of the release repo (a curl|sh script cannot source
# anything): it must equal noo-cli/src/registry.rs::RELEASE_REPO, pinned by
# tests/test_release_repo_declarations.py.
REPO="${NOO_CLI_REPO:-noomesh/noomesh}"
GITHUB_API="https://api.github.com/repos/${REPO}/releases"
GITHUB_DL="https://github.com/${REPO}/releases/download"

# ---- pinned release-verification keys (an earlier change slice B) ----------------
#
# THE POINT OF THIS BLOCK. Until 2026-09-04 this installer's only integrity
# check was the `.sha256` sidecar sitting next to the binary, fetched over the
# same connection, from the same host, in the same breath. That proves the
# download was not CORRUPTED; it proves nothing about who wrote it. Whoever
# can serve you the binary can serve you the checksum of that binary, so an
# attacker positioned on the mirror — or on the wire, which the old
# NOO_CLI_INSECURE=1 escape hatch invited by turning certificate verification
# off outright — got the machine, on its very first command, before it had
# any pinned trust to fall back on. First boot is the one moment a node has
# no other anchor, which makes it the worst possible place to trust the
# channel.
#
# The project already solved this for the UPGRADE path: the release pipeline
# signs `sha256sums.txt` with an Ed25519 key whose seed exists only in the
# NOO_RELEASE_SIGNING_SEED Actions secret and the operator's off-repo copy,
# and `noo upgrade` verifies that signature against a key list compiled into
# the binary (noo-cli/src/release_sig.rs, RELEASE_PUBKEYS_HEX). Install is now
# the same deal, one step earlier: the key list is pinned HERE, in the script
# the operator read before running it, so the manifest's authenticity does not
# depend on the channel that delivered it.
#
# KEEP IN SYNC with RELEASE_PUBKEYS_HEX in noo-cli/src/release_sig.rs, current
# key first. Rotation is the same procedure as there: prepend the new public
# key, ship a CLI and this script, then swap the Actions secret — older
# releases keep verifying under the key still listed behind it.
RELEASE_PUBKEYS="13be2244d5b91b1d5c29dfffd94a3817cb774c906785cf700e10a86d7be62d43"
SIG_PREFIX="noo-sig1."
MANIFEST="sha256sums.txt"

# ---- helpers ---------------------------------------------------------------

err() {
    printf 'error: %s\n' "$1" >&2
    exit "${2:-1}"
}

info() {
    printf '%s\n' "$1" >&2
}

have() {
    command -v "$1" >/dev/null 2>&1
}

# ---- release fetch: the real cause, and retries for what is transient -------
#
# Followup i11b. download() used to silence gh, fall back to a plain curl that
# a private repo always answers with 404, and silence that too — so a GitHub
# network blip read as "no signed release manifest" or "download failed" for
# an asset that was there. Now every failure is classified (the same table as
# noo-cli/src/release_fetch.rs), said with what to do next, and only network
# errors, 5xx and rate limits are retried (bounded, with backoff; curl honours
# Retry-After). A 404 or a 401/403 refusal is asked once. TLS verification is
# never relaxed: a certificate failure is reported, not worked around.
#
# DL_CLASS / DL_REASON hold the last failure for callers that silence stderr:
# notfound | auth | rate | network | tls | server | other.
DL_CLASS=""
DL_REASON=""
DL_ATTEMPTS=4

# Classify gh's stderr (file "$1").
gh_class() {
    _m="$(tr 'A-Z' 'a-z' < "$1" 2>/dev/null || true)"
    case "$_m" in
        *"rate limit"*|*"http 429"*) echo rate ;;
        *"http 5"[0-9][0-9]*) echo server ;;
        *"no assets match"*|*"release not found"*|*"http 404"*|*"http 410"*) echo notfound ;;
        *"http 401"*|*"http 403"*|*"gh auth login"*|*"bad credentials"*|*authentication*|*"resource not accessible"*|*saml*) echo auth ;;
        *"tls handshake timeout"*) echo network ;;
        *certificate*|*x509*) echo tls ;;
        *"error connecting to"*|*"dial tcp"*|*timeout*|*"timed out"*|*"connection reset"*|*"connection refused"*|*"no such host"*|*"network is unreachable"*|*"deadline exceeded"*|*"temporary failure"*|*"unexpected eof"*) echo network ;;
        *) echo other ;;
    esac
}

# What to do next, per class.
class_hint() {
    case "$1" in
        notfound) echo "not found: check the release tag and asset name; a private repo also answers 404 to an account or anonymous request that cannot read it" ;;
        auth) echo "access refused: authenticate with an account that can read ${REPO} ('gh auth login', or export GH_TOKEN); tokens are never printed" ;;
        rate) echo "rate-limited by GitHub: wait and re-run, or authenticate ('gh auth login' / GH_TOKEN) for a higher limit" ;;
        network) echo "network error: check DNS, the proxy and connectivity, then re-run (it was retried with backoff already)" ;;
        tls) echo "TLS verification failed: fix the system trust store or the proxy's CA (NOO_CLI_CACERT adds one CA); verification is never turned off" ;;
        server) echo "server error (5xx): the server is failing; retry later (githubstatus.com for GitHub)" ;;
        *) echo "fetch failed" ;;
    esac
}

dl_fail() {
    DL_CLASS="$1"
    DL_REASON="$(class_hint "$1") [$2]"
    info "error: ${DL_REASON}"
    return 1
}

# Strip anything token-shaped from a message before it is shown.
redact() {
    # 'github_''pat_' keeps the whole prefix out of this file's text (the
    # snapshot credentials gate matches it); sed sees the joined string.
    sed -E 's/(github_''pat_|gh[pousr]_)[A-Za-z0-9_]{16,}/[redacted]/g'
}

# `gh release download` with retries for transient failures. Sets DL_CLASS on
# failure and leaves gh's message in "$3".
gh_download() {
    _gtag="$1"; _gasset="$2"; _gerr="$3"; _gout="$4"
    _n=1; _wait=1
    while :; do
        if gh release download "$_gtag" -R "${REPO}" -p "$_gasset" -O "$_gout" --clobber 2>"$_gerr"; then
            return 0
        fi
        DL_CLASS="$(gh_class "$_gerr")"
        case "$DL_CLASS" in
            network|server|rate) ;;
            *) return 1 ;;
        esac
        [ "$_n" -lt "$DL_ATTEMPTS" ] || return 1
        sleep "$_wait"; _n=$((_n + 1)); _wait=$((_wait * 2))
    done
}

# Download "$1" (url) to "$2" (path). gh for GitHub release assets, then
# curl or wget. Fails nonzero with the classified cause on stderr.
download() {
    _url="$1"
    _out="$2"
    DL_CLASS=""; DL_REASON=""
    _scratch="${tmpdir:-${TMPDIR:-/tmp}}"
    _gh_err="${_scratch}/.noo-dl-gh.$$"
    _gh_class=""
    _gh_msg=""
    # The release assets are public, so plain curl/wget works. `gh` is an
    # OPTIONAL path: when it is present and authenticated it is tried first
    # (it downloads with the caller's credentials, which also covers a mirror
    # or fork that is private, and avoids anonymous rate limits). Any failure
    # falls through to curl/wget below; behaviour is unchanged.
    if have gh && printf '%s' "$_url" | grep -q 'releases/download/'; then
        _tag="${_url##*releases/download/}"; _asset="${_tag##*/}"; _tag="${_tag%%/*}"
        if gh_download "$_tag" "$_asset" "$_gh_err" "$_out"; then
            rm -f "$_gh_err"
            DL_CLASS=""
            return 0
        fi
        _gh_class="$DL_CLASS"
        _gh_msg="$(tr '\n' ' ' < "$_gh_err" 2>/dev/null | redact)"
        rm -f "$_gh_err"
        case "$_gh_class" in
            notfound|network|server|rate|tls)
                dl_fail "$_gh_class" "gh release download ${_tag} -p ${_asset}: ${_gh_msg}"
                return 1 ;;
        esac
    fi
    # PRIVATE-CA REALITY, handled by ADDING trust rather than removing it.
    # A controller mirror serves /bootstrap/cli under a certificate issued by
    # the CLUSTER CA, which a box that has not enrolled yet does not know. The
    # old answer was NOO_CLI_INSECURE=1, which passed `-k` to curl and
    # --no-check-certificate to wget: that does not teach the client about one
    # private CA, it stops the client checking ANY certificate, so every
    # machine-in-the-middle between the node and the controller could hand it
    # a binary of their choosing on the node's first command. The narrow need
    # (one extra CA) is now met by the narrow tool: NOO_CLI_CACERT names a PEM
    # bundle that is trusted IN ADDITION to the system store, and everything
    # else about verification stays on. `noo enroll` pins that same CA by
    # fingerprint, so the operator already has the file at hand.
    _ca=""
    if [ -n "${NOO_CLI_CACERT:-}" ]; then
        [ -r "${NOO_CLI_CACERT}" ] || err "NOO_CLI_CACERT is set to '${NOO_CLI_CACERT}' but that file is not readable"
        _ca="${NOO_CLI_CACERT}"
    fi
    _also=""
    [ -n "$_gh_class" ] && _also="; gh failed first: ${_gh_msg}"
    if have curl; then
        _hdr="${_scratch}/.noo-dl-hdr.$$"
        _cerr="${_scratch}/.noo-dl-curl.$$"
        # --retry covers timeouts, 408, 429 and 5xx (honouring Retry-After),
        # --retry-connrefused adds refused connects; --retry-max-time bounds
        # the total. 404 and 401/403 are never retried by curl.
        set -- -sSL --retry $((DL_ATTEMPTS - 1)) --retry-connrefused --retry-max-time 60 -D "$_hdr" -o "$_out" -w '%{http_code}'
        case "$_url" in https://*) set -- "$@" --proto '=https' --tlsv1.2 ;; esac
        [ -n "$_ca" ] && set -- "$@" --cacert "$_ca"
        _rc=0
        _code="$(curl "$@" "$_url" 2>"$_cerr")" || _rc=$?
        _cmsg="$(tr '\n' ' ' < "$_cerr" 2>/dev/null | redact)"
        rm -f "$_cerr"
        case "$_code" in
            2??) rm -f "$_hdr"; return 0 ;;
        esac
        _rl="$(tr 'A-Z' 'a-z' < "$_hdr" 2>/dev/null | tr -d '\r' | grep -E '^(x-ratelimit-remaining: 0|retry-after:)' || true)"
        rm -f "$_hdr" "$_out"
        case "$_code" in
            404|410) dl_fail notfound "GET ${_url} -> HTTP ${_code}${_also}" ;;
            429) dl_fail rate "GET ${_url} -> HTTP 429${_also}" ;;
            403) if [ -n "$_rl" ]; then dl_fail rate "GET ${_url} -> HTTP 403${_also}"; else dl_fail auth "GET ${_url} -> HTTP 403${_also}"; fi ;;
            401|407) dl_fail auth "GET ${_url} -> HTTP ${_code}${_also}" ;;
            5??) dl_fail server "GET ${_url} -> HTTP ${_code} (after retries)${_also}" ;;
            000|"")
                # No HTTP answer: curl's exit code says why.
                case "$_rc" in
                    35|51|53|54|58|59|60|64|66|77|80|82|83|90|91) dl_fail tls "GET ${_url}: curl exit ${_rc}: ${_cmsg}${_also}" ;;
                    *) dl_fail network "GET ${_url}: curl exit ${_rc}: ${_cmsg}${_also}" ;;
                esac ;;
            *) dl_fail other "GET ${_url} -> HTTP ${_code}${_also}" ;;
        esac
        return 1
    elif have wget; then
        # Retried by hand: busybox wget has no --tries. Exit 4 (GNU wget's
        # network failure) is the only transient one wget can name.
        _n=1; _wait=1
        while :; do
            _rc=0
            if [ -n "$_ca" ]; then
                wget -q --ca-certificate="$_ca" -O "$_out" "$_url" || _rc=$?
            else
                wget -q -O "$_out" "$_url" || _rc=$?
            fi
            [ "$_rc" -eq 0 ] && return 0
            [ "$_rc" -eq 4 ] && [ "$_n" -lt "$DL_ATTEMPTS" ] || break
            sleep "$_wait"; _n=$((_n + 1)); _wait=$((_wait * 2))
        done
        rm -f "$_out"
        # wget hides the status; its exit code is the coarse class.
        case "$_rc" in
            4) dl_fail network "GET ${_url}: wget exit 4${_also}" ;;
            5) dl_fail tls "GET ${_url}: wget exit 5${_also}" ;;
            6) dl_fail auth "GET ${_url}: wget exit 6${_also}" ;;
            8) dl_fail other "GET ${_url}: the server answered an error (wget exit 8; install curl for the exact status)${_also}" ;;
            *) dl_fail other "GET ${_url}: wget exit ${_rc}${_also}" ;;
        esac
        return 1
    else
        err "need 'curl' or 'wget' to download; neither found"
    fi
}

# Fetch "$1" (url) to stdout. Transient failures retried like download().
fetch() {
    _url="$1"
    if have curl; then
        curl -fsSL --retry $((DL_ATTEMPTS - 1)) --retry-connrefused --retry-max-time 60 "$_url"
    elif have wget; then
        wget -qO- "$_url"
    else
        err "need 'curl' or 'wget'; neither found"
    fi
}

# Compute the SHA-256 of file "$1", print the bare hex digest.
sha256_of() {
    _f="$1"
    if have sha256sum; then
        sha256sum "$_f" | cut -d' ' -f1
    elif have shasum; then
        shasum -a 256 "$_f" | cut -d' ' -f1
    else
        err "need 'sha256sum' or 'shasum' for checksum verification; neither found"
    fi
}

# ---- release-signature verification ----------------------------------------
#
# Verify that "$1" (the checksum manifest) carries a signature "$2" made by one
# of the RELEASE_PUBKEYS pinned above. Prints nothing on success; returns
# nonzero on any failure, and the caller aborts — a bad signature is not a
# warning, it means the bytes on their way to this machine were touched by
# someone who is not the release pipeline.
#
# The signature is `noo-sig1.<base64url, unpadded, 64-byte Ed25519 signature>`
# over the exact manifest bytes, the same format noo-cli/src/release_sig.rs
# writes and reads. A POSIX shell has no Ed25519 of its own, so we borrow one:
# python3 first, because RFC 8032 verification is forty lines of stdlib integer
# arithmetic that behaves identically on every box, and OpenSSL 3 second, for
# the rare host with no python3 at all. LibreSSL — which is what `openssl` is
# on stock macOS — has no `pkeyutl -rawin`, hence the explicit major-version
# check rather than letting it fail and look like a forged signature.
verify_release_sig() {
    _mf="$1"
    _sig="$2"
    _body="$(tr -d '[:space:]' < "$_sig")"
    case "$_body" in
        "${SIG_PREFIX}"*) _body="${_body#"${SIG_PREFIX}"}" ;;
        *) info "signature file does not start with '${SIG_PREFIX}'"; return 1 ;;
    esac

    if have python3; then
        python3 - "$_mf" "$_body" "$RELEASE_PUBKEYS" <<'PYVERIFY'
import base64, hashlib, sys

msg = open(sys.argv[1], "rb").read()
b64 = sys.argv[2]
keys = sys.argv[3].split()

# Ed25519 verification, RFC 8032 section 5.1.7, stdlib only.
P = 2**255 - 19
D = -121665 * pow(121666, P - 2, P) % P
Q = 2**252 + 27742317777372353535851937790883648493

def recover_x(y, sign):
    if y >= P:
        return None
    x2 = (y * y - 1) * pow(D * y * y + 1, P - 2, P) % P
    if x2 == 0:
        return None if sign else 0
    x = pow(x2, (P + 3) // 8, P)
    if (x * x - x2) % P != 0:
        x = x * pow(2, (P - 1) // 4, P) % P
    if (x * x - x2) % P != 0:
        return None
    if (x & 1) != sign:
        x = P - x
    return x

def add(p1, p2):
    a = (p1[1] - p1[0]) * (p2[1] - p2[0]) % P
    b = (p1[1] + p1[0]) * (p2[1] + p2[0]) % P
    c = 2 * p1[3] * p2[3] * D % P
    e = 2 * p1[2] * p2[2] % P
    return ((b - a) * (e - c) % P, (e + c) * (b + a) % P,
            (e - c) * (e + c) % P, (b - a) * (b + a) % P)

def mul(s, pt):
    acc = (0, 1, 1, 0)
    while s > 0:
        if s & 1:
            acc = add(acc, pt)
        pt = add(pt, pt)
        s >>= 1
    return acc

GY = 4 * pow(5, P - 2, P) % P
GX = recover_x(GY, 0)
G = (GX, GY, 1, GX * GY % P)

def decompress(b):
    if len(b) != 32:
        return None
    y = int.from_bytes(b, "little")
    sign = y >> 255
    y &= (1 << 255) - 1
    x = recover_x(y, sign)
    return None if x is None else (x, y, 1, x * y % P)

def verify(pub, sig, message):
    a = decompress(pub)
    if a is None or len(sig) != 64:
        return False
    r = decompress(sig[:32])
    if r is None:
        return False
    s = int.from_bytes(sig[32:], "little")
    if s >= Q:
        return False
    h = int.from_bytes(hashlib.sha512(sig[:32] + pub + message).digest(), "little") % Q
    lhs, rhs = mul(s, G), add(r, mul(h, a))
    return ((lhs[0] * rhs[2] - rhs[0] * lhs[2]) % P == 0
            and (lhs[1] * rhs[2] - rhs[1] * lhs[2]) % P == 0)

try:
    sig = base64.urlsafe_b64decode(b64 + "=" * (-len(b64) % 4))
except Exception as exc:
    print("bad base64url in signature: %s" % exc, file=sys.stderr)
    sys.exit(1)

for k in keys:
    try:
        pub = bytes.fromhex(k)
    except ValueError:
        continue
    if len(pub) == 32 and verify(pub, sig, msg):
        sys.exit(0)
print("signature does not verify against any release key pinned in this installer", file=sys.stderr)
sys.exit(1)
PYVERIFY
        return $?
    fi

    # No python3 at all: an ALREADY-INSTALLED noo carries the same key list
    # compiled in (`noo security release-verify`, an earlier change slice B), and it
    # got onto this box through this same verified path, so it is a legitimate
    # anchor for a re-install or an upgrade. It is not available on a genuinely
    # fresh box, which is why it is the second choice and not the first.
    if have noo; then
        if noo security release-verify "$_mf" "$_sig" >/dev/null 2>&1; then
            return 0
        fi
        info "the installed 'noo security release-verify' rejected the manifest signature"
        return 1
    fi

    info "no Ed25519 verifier available on this host: install 'python3' (or an existing 'noo')"
    return 1
}

# ---- detect platform -------------------------------------------------------

os="$(uname -s 2>/dev/null || echo unknown)"
case "$os" in
    Linux) : ;;
    Darwin) : ;;
    *) err "unsupported OS '$os' — noo ships only Linux static musl binaries" ;;
esac

arch="$(uname -m 2>/dev/null || echo unknown)"
case "$os/$arch" in
    Linux/x86_64 | Linux/amd64)  target="x86_64-unknown-linux-musl" ;;
    Linux/aarch64 | Linux/arm64) target="aarch64-unknown-linux-musl" ;;
    Darwin/arm64 | Darwin/aarch64) target="aarch64-apple-darwin" ;;
    *) err "unsupported platform '$os/$arch' — supported: Linux x86_64/aarch64, macOS arm64" ;;
esac

asset="noo-${target}"
info "Detected platform: ${os}/${arch} -> ${asset}"

# ---- resolve release + build URLs ------------------------------------------

if [ -n "${NOO_CLI_BASE_URL:-}" ]; then
    # Direct base URL (testing / mirrors): skip the GitHub API entirely.
    base_url="${NOO_CLI_BASE_URL%/}"
    bin_url="${base_url}/${asset}"
    sum_url="${base_url}/${asset}.sha256"
    man_url="${base_url}/${MANIFEST}"
    sig_url="${base_url}/${MANIFEST}.sig"
    version="${NOO_CLI_VERSION:-(base-url)}"
else
    if [ -n "${NOO_CLI_VERSION:-}" ]; then
        version="$NOO_CLI_VERSION"
        # Accept the bare version too ("0.2.16"): the value is used VERBATIM
        # as the release tag in the download URL, and the tag form is
        # noo-cli-v<semver> — a natural-looking bare pin 404'd on Test 2.
        case "$version" in
            noo-cli-v*) ;;
            v*) version="noo-cli-${version}" ;;
            *)  version="noo-cli-v${version}" ;;
        esac
    else
        info "Resolving latest noo-cli release..."
        # Resolution half of the same rule as download(): `gh` is an optional
        # first path (authenticated, no anonymous rate limit); the public
        # releases API via curl is the default and the fallback.
        version=""
        if have gh; then
            version="$(gh api "repos/${REPO}/releases?per_page=30" \
                --jq '.[].tag_name' 2>/dev/null \
                | grep -E '^noo-cli-v' | head -n1 || true)"
        fi
        if [ -z "$version" ]; then
            # Grep the releases JSON for the first noo-cli-v* tag (namespaced
            # tags keep noo-cli releases distinct from other components).
            version="$(fetch "${GITHUB_API}?per_page=30" \
                | grep '"tag_name"' \
                | sed -E 's/.*"tag_name"[[:space:]]*:[[:space:]]*"([^"]+)".*/\1/' \
                | grep -E '^noo-cli-v' \
                | head -n1 || true)"
        fi
        [ -n "$version" ] || err "could not resolve a 'noo-cli-v*' release from ${GITHUB_API} — check the network (or an authenticated gh), or set NOO_CLI_VERSION to pin one"
    fi
    bin_url="${GITHUB_DL}/${version}/${asset}"
    sum_url="${GITHUB_DL}/${version}/${asset}.sha256"
    man_url="${GITHUB_DL}/${version}/${MANIFEST}"
    sig_url="${GITHUB_DL}/${version}/${MANIFEST}.sig"
fi

info "Release: ${version}"

# ---- download + verify -----------------------------------------------------

tmpdir="$(mktemp -d 2>/dev/null || mktemp -d -t noo-install)"
[ -n "$tmpdir" ] && [ -d "$tmpdir" ] || err "could not create temp directory"
trap 'rm -rf "$tmpdir"' EXIT INT HUP TERM

info "Downloading ${bin_url}"
download "$bin_url" "${tmpdir}/${asset}" || err "download failed: ${bin_url}"

# WHERE THE EXPECTED DIGEST COMES FROM. Not from the `.sha256` sidecar beside
# the binary: that file travels the same road as the binary, so anyone able to
# swap one can swap the other and the comparison always succeeds. The digest
# comes from `sha256sums.txt`, whose SIGNATURE is checked against the release
# keys pinned at the top of this script — bytes the operator obtained when they
# read the installer, not bytes the mirror handed over a moment ago. The
# sidecar stays a convenience for the corruption case, exactly as
# noo-cli/NOO_CLI.md describes for `noo upgrade`.
info "Downloading signed manifest ${man_url}"
if download "$man_url" "${tmpdir}/${MANIFEST}" 2>/dev/null \
    && download "$sig_url" "${tmpdir}/${MANIFEST}.sig" 2>/dev/null \
    && [ -s "${tmpdir}/${MANIFEST}" ] && [ -s "${tmpdir}/${MANIFEST}.sig" ]; then
    signed=1
else
    signed=0
fi

if [ "$signed" -eq 0 ] && [ -n "$DL_CLASS" ] && [ "$DL_CLASS" != notfound ]; then
    # Followup i11b: the manifest could not be FETCHED (network, auth, rate
    # limit, 5xx, TLS) — that is not a release without a signature, and
    # saying so would send the operator after the wrong problem. Still a
    # refusal: nothing installs unverified.
    err "could not fetch the signed manifest ${man_url}
${DL_REASON}
Nothing was installed; re-run once the cause above is fixed." 1
fi

if [ "$signed" -eq 0 ]; then
    # Releases before noo-cli 0.3.70 predate an earlier change and publish no
    # signature; a controller mirror that has not run `noo upgrade --nodes`
    # since then serves none either. That is the ONLY legitimate reason to be
    # here, so it takes a deliberate opt-in and says plainly what is being
    # given up. Everything else that lands here — a stripped asset list, a
    # mirror answering 404 to just these two names — is an attacker removing
    # the check, and removing a check must never be the quiet default.
    if [ "${NOO_CLI_ALLOW_UNSIGNED:-0}" != "1" ]; then
        err "no signed release manifest at ${man_url}
The release ${version} publishes no ${MANIFEST}/.sig pair, so this installer
cannot prove the binary came from the noo release pipeline rather than from
whoever answered this request. Refusing to install.
  - pinning a pre-0.3.70 build on purpose? re-run with NOO_CLI_ALLOW_UNSIGNED=1
  - installing from a controller mirror? run 'noo upgrade --nodes' on the
    controller first, which uploads the signed manifest alongside the assets" 1
    fi
    info "WARNING: NOO_CLI_ALLOW_UNSIGNED=1 — installing without a release signature."
    info "         The binary is checked only against a checksum served by the same"
    info "         host that served the binary, which proves nothing about its origin."
    download "$sum_url" "${tmpdir}/${asset}.sha256" || err "checksum download failed: ${sum_url}"
    expected="$(cut -d' ' -f1 "${tmpdir}/${asset}.sha256" | tr -d '[:space:]')"
    [ -n "$expected" ] || err "checksum file was empty or malformed: ${sum_url}"
else
    if ! verify_release_sig "${tmpdir}/${MANIFEST}" "${tmpdir}/${MANIFEST}.sig"; then
        err "release signature INVALID for ${MANIFEST} (${man_url})
The checksum manifest is not signed by any release key pinned in this
installer. Either this build of the installer predates a key rotation, or the
manifest was written by someone who is not the noo release pipeline.
Refusing to install anything from ${bin_url}." 1
    fi
    info "Release signature OK (${MANIFEST} verifies against a pinned release key)"

    # `<hex>  <name>` lines; names may carry a `./` path or a `*` binary
    # marker, so compare on the basename the way release_sig::manifest_sha_for
    # does. A manifest that verifies but does not mention this asset is a
    # failure too: it means the asset was never part of the signed release.
    expected="$(awk -v want="$asset" '
        { name = $2
          sub(/^\*/, "", name)
          n = split(name, parts, "/")
          if (parts[n] == want) { print tolower($1); exit } }' "${tmpdir}/${MANIFEST}")"
    [ -n "$expected" ] || err "the signed ${MANIFEST} does not list ${asset}
Refusing to install an asset that is not part of the signed release ${version}." 1
fi

actual="$(sha256_of "${tmpdir}/${asset}")"

if [ "$expected" != "$actual" ]; then
    err "checksum MISMATCH for ${asset}
  expected: ${expected}
  actual:   ${actual}
Refusing to install a binary that does not match its published checksum." 1
fi
info "Checksum OK (${actual})"

# ---- install ---------------------------------------------------------------

install_dir="${NOO_INSTALL_DIR:-$HOME/.local/bin}"

# Root-owned install dirs (e.g. NOO_INSTALL_DIR=/usr/local/bin) are supported
# via sudo — but only when the dir is not already writable, and never when we
# are already root. We never sudo the download/verify steps, only the final
# placement of the verified binary.
as_root=""
if ! mkdir -p "$install_dir" 2>/dev/null || [ ! -w "$install_dir" ]; then
    if [ "$(id -u 2>/dev/null || echo 1)" != "0" ] && have sudo; then
        info "${install_dir} is not writable — using sudo for the install step"
        as_root="sudo"
        $as_root mkdir -p "$install_dir" || err "could not create install dir: ${install_dir}"
    else
        err "could not create/write install dir: ${install_dir} (set NOO_INSTALL_DIR to a writable directory, e.g. \$HOME/.local/bin)"
    fi
fi

dest="${install_dir}/noo"
# Install atomically: move into place then chmod (idempotent — overwrites any
# existing noo).
# A stale self-referential symlink (earlier installers linked noo -> noo,
# which REPLACED the binary with a link to itself: "too many levels of
# symbolic links" on host6, 2026-09-03) must go before the move.
[ -L "$dest" ] && $as_root rm -f "$dest"
$as_root mv -f "${tmpdir}/${asset}" "$dest" || err "could not install to ${dest}"
$as_root chmod 755 "$dest" || err "could not chmod ${dest}"

# `noo` is the binary; a `pai` symlink keeps rename-era muscle memory working.
$as_root ln -sf "$dest" "${install_dir}/pai" 2>/dev/null || info "note: could not create the 'pai' alias symlink (non-fatal)"

info ""
info "Installed noo -> ${dest}  (alias: ${install_dir}/pai)"

# Shell completion (fu 64): best-effort, non-fatal. Drop a bash script where
# the interactive shell will source it; the binary generates it from its own
# command table so it never drifts.
if [ -w /etc/bash_completion.d ] 2>/dev/null; then
    "${dest}" completions bash > /etc/bash_completion.d/noo 2>/dev/null \
        && info "Installed bash completion -> /etc/bash_completion.d/noo"
elif [ -n "${HOME:-}" ]; then
    _comp_dir="${HOME}/.local/share/bash-completion/completions"
    mkdir -p "${_comp_dir}" 2>/dev/null \
        && "${dest}" completions bash > "${_comp_dir}/noo" 2>/dev/null \
        && info "Installed bash completion -> ${_comp_dir}/noo (new shells)"
fi
# The user-dir above is only LOADED by the bash-completion package — fresh
# Ubuntu server ships without it, and the file then sits inert (first
# contact: "tab complete wasn't working"). Say so instead of leaving a
# silent no-op; the onboard wizard also offers to install it.
if [ "$os" = Linux ] && [ -d "${HOME:-/nonexistent}/.local/share/bash-completion" ] \
    && ! [ -f /usr/share/bash-completion/bash_completion ]; then
    info "NOTE: the 'bash-completion' package is not installed — tab completion"
    info "      stays inactive until: sudo apt install bash-completion (then a new shell)"
fi

# ---- PATH check + next steps -----------------------------------------------

case ":${PATH}:" in
    *":${install_dir}:"*)
        on_path=1 ;;
    *)
        on_path=0 ;;
esac

if [ "$on_path" -ne 1 ]; then
    info ""
    info "WARNING: ${install_dir} is not on your PATH."
    info "Add it by appending this line to your shell profile (~/.bashrc, ~/.profile, or ~/.zshrc):"
    info ""
    info "    export PATH=\"${install_dir}:\$PATH\""
    info ""
    info "Then reload your shell (e.g. 'exec \$SHELL') or run noo by full path: ${dest}"
fi

# A second `noo` EARLIER on PATH silently wins, and the divergence is durable:
# on a Mac node the rail writes /usr/local/bin/noo (node_fetch.rs hardcodes it)
# while a leftover ~/.local/bin/noo keeps answering the operator's shell. The
# fleet then reports the new version and the terminal runs the old one, with
# nothing to connect the two. Seen on host6 2026-09-05: 0.3.95 installed,
# `noo --version` said 0.3.92, and `noo upgrade` would have upgraded the SHADOW
# rather than the copy the rail maintains.
if [ "$on_path" -eq 1 ]; then
    _first="$(command -v noo 2>/dev/null || true)"
    if [ -n "$_first" ] && [ "$_first" != "$dest" ]; then
        info ""
        info "WARNING: another noo earlier on your PATH will be used instead of this one:"
        info "    ${_first}   <- what 'noo' runs"
        info "    ${dest}   <- what was just installed"
        info ""
        info "Remove the shadowing copy, then reload the command cache:"
        info "    rm -f ${_first} $(dirname "${_first}")/pai && hash -r"
    fi
fi

info ""
info "Next steps:"
if [ "$on_path" -eq 1 ]; then
    info "    noo --version      # confirm the install"
    info "    noo onboard        # guided setup: bring this machine online as a controller"
else
    info "    ${dest} --version   # confirm the install"
    info "    ${dest} onboard     # guided setup: bring this machine online as a controller"
fi
info ""

exit 0
