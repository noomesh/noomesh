#!/bin/sh
# SPDX-License-Identifier: AGPL-3.0-only
# Copyright 2026 PersonifAI LLC

# noo-fetch — the PULL half of node provisioning.
#
# Installed by prep-host.sh as /usr/local/bin/noo-fetch and driven by
# noo-fetch.timer (root). Polls the controller for this node's staged
# provisioning bundle:
#
#     GET $CONTROLLER/bootstrap/bundle/$NODE   -> CMS ciphertext (or 404)
#
# The blob is ENCRYPTED to this node's birth key (generated at enrollment,
# /etc/noo/birth.key) — the rail and the gateway only ever see ciphertext.
# After decryption the plaintext is the ordinary CA-signed bundle.tar, which
# is handed to noo-apply — the SAME verifier the push lane used: content
# authenticity is the cluster CA signature, transport authenticity is
# irrelevant by design.
#
# Change detection: the sha256 of the CIPHERTEXT is recorded after a
# successful apply; an unchanged blob is skipped, so the timer can run
# forever and re-provisioning is simply "stage a new bundle" — it applies on
# the next tick with no operator contact with the node at all.
#
# Exit 0 on "nothing to do" paths (no bundle staged, unchanged) so the timer
# unit stays green.
set -eu

CONF_DIR=/etc/noo
NODE="$(cat "$CONF_DIR/node-name" 2>/dev/null || true)"
URL="$(cat "$CONF_DIR/controller-url" 2>/dev/null || true)"
KEY="$CONF_DIR/birth.key"
LAST="$CONF_DIR/last-bundle.sha256"

[ -n "$NODE" ] || { echo "noo-fetch: no $CONF_DIR/node-name — not birth-enrolled" >&2; exit 0; }
[ -n "$URL" ]  || { echo "noo-fetch: no $CONF_DIR/controller-url" >&2; exit 0; }
[ -f "$KEY" ]  || { echo "noo-fetch: no $KEY (birth key) — pull lane not armed" >&2; exit 0; }

# TLS: pin the CLUSTER CA the node already holds (birth anchor) — the
# gateway cert is signed by it, not the WebPKI, so verifying against the
# system store fails unless the box separately trusts the cluster CA.
#
# There is no -k branch and no `controller-insecure` marker any more
# (§3f R25). The marker recorded that FIRST CONTACT had nothing to verify
# against; that window closes when the anchor lands, and on an enrolled
# node the anchor is always there because it is what noo-apply verifies
# every bundle against. Nothing ever removed the marker, so the exception
# outlived its reason for the life of the node. A node without the anchor
# is not enrolled, and fetching unverified would not make it so: refuse,
# and say what to run.
if [ ! -f "$CONF_DIR/pki/ca.crt" ]; then
    echo "noo-fetch: no cluster CA at $CONF_DIR/pki/ca.crt — this node cannot verify its controller." >&2
    echo "noo-fetch: re-run enrollment on this node (\`noo enroll <noo1.blob>\`) to install the anchor." >&2
    exit 1
fi
TLS="--cacert $CONF_DIR/pki/ca.crt"

# Adaptive cadence: every tick while a bundle is EXPECTED (prep-host
# creates the marker at enrollment; a successful apply removes it), else
# every 5th tick (5 min) — a steady-state node no longer hits the
# controller once a minute forever (operator, 2026-09-02).
# Cadence: while expect-bundle exists this tick fetches; the file holds a
# countdown of fast ticks (an empty file from an older prep = 10). Every
# apply attempt — success or failure — re-arms 10 fast ticks, because a
# restage routinely follows (the applier-first handshake stages the full
# bundle 30 s after the applier-only one; a node back on the 5-minute
# cadence missed the controller's wait window on 2026-09-03).
# A controller POKE (noo-hostd's fetch-bundle op, run via `systemctl start
# noo-fetch.service` outside this timer) re-arms this same marker itself,
# right before starting the unit — so the poked run is never subject to
# the "every 3rd tick" steady-state throttle below (2026-09-29: a poke
# landed on a throttled tick and exited 0 without fetching).
EXPECT="$CONF_DIR/expect-bundle"; STATE="$CONF_DIR/fetch-state"
if [ -f "$EXPECT" ]; then
    left="$(tr -dc '0-9' < "$EXPECT" 2>/dev/null | head -c 4)"; [ -n "$left" ] || left=10
    left=$((left - 1))
    if [ "$left" -le 0 ]; then rm -f "$EXPECT"; else printf '%s\n' "$left" > "$EXPECT"; fi
else
    # Digits only before arithmetic: bash evaluates a variable's text in $(( )).
    n="$(tr -dc '0-9' < "$STATE" 2>/dev/null | head -c 9)"; n=$(( ${n:-0} + 1 )); printf '%s\n' "$n" > "$STATE"
    # Every 3rd tick: a tick is ~100 s wall-clock (60 s + jitter + run), so
    # "every 5th" was ~8 min and outlived the controller's wait (HOST3, 2026-09-03).
    [ $((n % 3)) -eq 0 ] || exit 0
fi
TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT

# HTTP-code-aware fetch: the old `-fsS … 2>/dev/null || exit 0`
# swallowed EVERY failure — TLS, DNS, 5xx — as "nothing staged". Only a 404
# stays quiet; real failures go to the journal (exit 0 keeps the timer green).
CODE="$(curl -sS $TLS --connect-timeout 10 -o "$TMP/blob" -w '%{http_code}' \
    "$URL/bootstrap/bundle/$NODE" 2>"$TMP/curlerr" || true)"
case "$CODE" in
    200) ;;
    404) exit 0 ;;  # nothing staged yet — the timer will come back
    *)
        echo "noo-fetch: bundle fetch FAILED (HTTP ${CODE:-000}): $(tr '\n' ' ' < "$TMP/curlerr")" >&2
        exit 0 ;;
esac
[ -s "$TMP/blob" ] || exit 0

SUM="$(sha256sum "$TMP/blob" | cut -d' ' -f1)"

# ── the fetch receipt ────────────────────────────────────────
#
# `fetched_at` used to be stamped by the GET above, which made it a state write
# ANY anonymous caller could make: it meant "somebody collected this
# ciphertext", never "this node did". Three controller-side wait loops read it
# to narrate progress, and a stranger could drive `provision --wait` on to stage
# the full bundle early.
#
# So the node says so itself, signed with the one credential it holds at this
# moment: the birth key. NOO_CLUSTER_SECRET is delivered INSIDE this bundle, so
# it is not available here — that is the whole reason the GET is public.
#
# `openssl dgst -sha256 -sign` is RSA PKCS#1 v1.5 over SHA-256, which is what
# the gateway verifies against the cert it recorded at enrollment
# (gateway-rust/src/birth_proof.rs). The signed string is
# "noo-bundle-<purpose>:<node>:<sha>:<ts>" — the node and the sha are IN it, so
# the receipt cannot be replayed for another node or another bundle, and the
# ±300 s window bounds replaying it for this one.
birth_proof() {
    # $1 = purpose (fetch|apply), $2 = bundle sha
    [ -r "$KEY" ] || return 1
    _ts="$(date +%s)"
    _sig="$(printf 'noo-bundle-%s:%s:%s:%s' "$1" "$NODE" "$2" "$_ts" \
        | openssl dgst -sha256 -sign "$KEY" 2>/dev/null | openssl base64 -A 2>/dev/null)"
    [ -n "$_sig" ] || return 1
    printf '%s.%s' "$_ts" "$_sig"
}

if _proof="$(birth_proof fetch "$SUM")"; then
    curl -sS $TLS --connect-timeout 10 --max-time 20 -o /dev/null \
        -H 'content-type: application/json' \
        -H "x-noo-birth-proof: $_proof" \
        -d "{\"sha\":\"$SUM\"}" \
        "$URL/bootstrap/bundle/$NODE/fetched" >/dev/null 2>&1 || true
else
    echo "noo-fetch: could not sign the fetch receipt with $KEY — fetched_at will not be stamped" >&2
fi

if [ -f "$LAST" ] && [ "$(cat "$LAST")" = "$SUM" ]; then
    exit 0  # already applied this exact bundle
fi

echo "noo-fetch: new bundle staged ($SUM) — decrypting"
if ! openssl smime -decrypt -binary -inform DER \
        -inkey "$KEY" -in "$TMP/blob" -out "$TMP/bundle.tar" 2>"$TMP/err"; then
    echo "noo-fetch: DECRYPT FAILED — bundle not encrypted to this node's birth key?" >&2
    cat "$TMP/err" >&2
    exit 1
fi

# noo-apply verifies the CA signature and refuses anything else — exactly
# the push lane's guarantee. Applying may restart the agent; that is the
# point. (noo-apply takes the bundle as a FILE argument, same as the gate's
# apply verb stages it.)
# Report the outcome to the controller (2026-09-03): the operator's
# `provision --wait` used to infer success from "agent registered", which
# was true even when the applier refused the bundle. Best-effort POST,
# never blocks the apply result; the journal keeps the full text.
#
# The report is on the NODE RAIL: it WRITES apply state and
# is audited as this node, so it is signed with NOO_CLUSTER_SECRET — the same
# request-bound v2 bearer the agent uses everywhere else. The secret is
# delivered BY a bundle (into /etc/noo-node-agent.env), so it is absent on the
# very first applier-only pass and after a failed first apply; in that case the
# report is skipped with a note rather than sent unauthenticated. `provision
# --wait` gates the applier phase on fetched_at, not on this report.
node_bearer() {
    _env=/etc/noo-node-agent.env
    [ -r "$_env" ] || return 1
    # Strip CR (\015) and any surrounding quotes; never `tr -d '\r'`, which
    # in a POSIX shell deletes literal backslashes and the letter r.
    # The applier keeps the value in a file and only a
    # NOO_CLUSTER_SECRET_FILE pointer in the env once the installed agent can
    # read one (noo-apply.sh agent_secret_files); this runs as root, so it
    # follows the pointer the same way.
    _ptr="$(sed -n 's/^NOO_CLUSTER_SECRET_FILE=//p' "$_env" | tail -1 \
        | tr -d '\015' | sed -e 's/^"//' -e 's/"$//' -e "s/^'//" -e "s/'\$//")"
    if [ -n "$_ptr" ]; then
        _sec="$(cat "$_ptr" 2>/dev/null)"
    else
        _sec="$(sed -n 's/^NOO_CLUSTER_SECRET=//p' "$_env" | tail -1 \
            | tr -d '\015' | sed -e 's/^"//' -e 's/"$//' -e "s/^'//" -e "s/'\$//")"
    fi
    [ -n "$_sec" ] || return 1
    _ts="$(date +%s)"
    # v2 binds the request: METHOD, path, sha256(body), node, time and a
    # 128-bit nonce the gateway spends once. $1 method, $2 path, $3 body.
    _bsha="$(printf '%s' "$3" | openssl dgst -sha256 -hex 2>/dev/null | sed 's/.*= *//')"
    _nonce="$(openssl rand -hex 16 2>/dev/null)"
    [ -n "$_bsha" ] && [ -n "$_nonce" ] || return 1
    _sig="$(printf 'v2\n%s\n%s\n%s\n%s\n%s\n%s' "$1" "$2" "$_bsha" "$NODE" "$_ts" "$_nonce" \
        | openssl dgst -sha256 -hmac "$_sec" -hex 2>/dev/null \
        | sed 's/.*= *//')"
    [ -n "$_sig" ] || return 1
    printf 'v2:%s:%s:%s:%s' "$NODE" "$_ts" "$_nonce" "$_sig"
}

# The node's client certificate, as `--cert <crt> --key <key>` curl words
# joined by `|` — the paths the AGENT presents (NOO_TLS_CERT / NOO_TLS_KEY
# in its env file: /etc/noo/pki/nodes/<node>/node.{crt,key}). The bundle
# that delivers the fleet secret delivers these too, so a node holding the
# secret holds its leaf; a node that does not reports on the birth proof
# alone (below). Same stripping as node_bearer.
node_tls() {
    _env=/etc/noo-node-agent.env
    [ -r "$_env" ] || return 1
    _crt="$(sed -n 's/^NOO_TLS_CERT=//p' "$_env" | tail -1 \
        | tr -d '\015' | sed -e 's/^"//' -e 's/"$//' -e "s/^'//" -e "s/'\$//")"
    _key="$(sed -n 's/^NOO_TLS_KEY=//p' "$_env" | tail -1 \
        | tr -d '\015' | sed -e 's/^"//' -e 's/"$//' -e "s/^'//" -e "s/'\$//")"
    [ -n "$_crt" ] && [ -n "$_key" ] && [ -r "$_crt" ] && [ -r "$_key" ] || return 1
    printf '%s|%s|%s|%s' --cert "$_crt" --key "$_key"
}
# The report carries the fleet token WITH the node's certificate when it has
# both, and the birth proof alone otherwise. The token never travels without
# the leaf (an earlier change: that was the gateway's `node_token_no_cert` lane,
# counted once from worker-1 during the stack-v0.2.82 roll — this report).
# The birth-proof-only case is not a fallback to something weaker — it is the
# fix for the two legitimate silences #95 recorded: the first-phase
# APPLIER-ONLY bundle (staged before this node has any secret or certificate)
# and a failed apply on a never-provisioned host. Both of those hold the birth
# key, so both can report instead of vanishing.
report() {
    REPORT_WINDOW="${NOO_REPORT_WINDOW:-90}"
    REPORT_STEP="${NOO_REPORT_STEP:-10}"
    _msg="$(tail -c 1500 "$TMP/apply.log" 2>/dev/null | tr -d '\000' | sed 's/\\/\\\\/g; s/"/\\"/g' | tr '\n\r\t' '   ')"
    _rc="$1"
    _proof=""
    _proof="$(birth_proof apply "$SUM")" || _proof=""
    _hdrs=""
    # The bearer is minted per ATTEMPT inside report_post (a v2 token is bound
    # to its request and its nonce is spent once, so a retry needs a fresh one);
    # here we only check that one can be made.
    if _tls="$(node_tls)" && node_bearer POST /x "" >/dev/null; then
        _hdrs="$_tls|-H|authorization: Bearer @NODE_BEARER@"
    fi
    if [ -n "$_proof" ]; then
        _hdrs="$_hdrs${_hdrs:+|}-H|x-noo-birth-proof: $_proof"
    fi
    if [ -z "$_hdrs" ]; then
        echo "noo-fetch: no node certificate and no usable birth key — apply report skipped (rc=$1)" >&2
        return 0
    fi
    # The report can leave while the tailnet link is DOWN: the host-telemetry
    # kind restarts tailscaled inside noo-apply, and tailscale0 is gone for a
    # few seconds after. Both credentials then fail at the TRANSPORT (curl
    # exits non-zero, no HTTP answer) within a fraction of a second. That is
    # not a verdict from the controller, so it is retried — a round is the
    # certificate attempt then the birth-proof attempt — for up to
    # REPORT_WINDOW seconds. An HTTP answer (any code) is a verdict: it ends
    # the loop. Same lesson as the fetch path: a transport
    # failure is not an answer.
    _waited=0
    while :; do
        _transport=1
        if report_post "$_rc" "$_msg" "$_hdrs"; then
            echo "noo-fetch: apply report delivered (HTTP $REPORT_CODE)" >&2
            return 0
        fi
        [ "$REPORT_CODE" = 000 ] || _transport=0
        _last="HTTP $REPORT_CODE${REPORT_ERR:+: $REPORT_ERR}"
        # A leaf the gateway's handshake refuses (expired, issued by a rotated
        # CA) fails the whole connection, not just the token. Say so, and send
        # the report on the birth proof alone rather than lose it — still never
        # the token without the leaf.
        case "$_hdrs" in
            --cert*)
                if [ "$_waited" -eq 0 ]; then
                    echo "noo-fetch: apply report with the node certificate failed ($_last) — retrying on the birth proof alone" >&2
                fi
                if [ -n "$_proof" ]; then
                    if report_post "$_rc" "$_msg" "-H|x-noo-birth-proof: $_proof"; then
                        echo "noo-fetch: apply report delivered on the birth proof (HTTP $REPORT_CODE)" >&2
                        return 0
                    fi
                    [ "$REPORT_CODE" = 000 ] || _transport=0
                    _last="HTTP $REPORT_CODE${REPORT_ERR:+: $REPORT_ERR}"
                fi ;;
        esac
        if [ "$_transport" -eq 0 ]; then
            echo "noo-fetch: apply report refused ($_last)" >&2
            return 0
        fi
        if [ "$_waited" -ge "$REPORT_WINDOW" ]; then
            echo "noo-fetch: apply report: controller unreachable for ${REPORT_WINDOW} s after the apply — tailscaled restart? ($_last)" >&2
            return 0
        fi
        sleep "$REPORT_STEP" || true
        _waited=$((_waited + REPORT_STEP))
    done
}

# $1 rc, $2 escaped msg, $3 the extra curl words joined by `|`. Split on |
# so a header VALUE containing spaces survives; `set --` would re-split it
# and `eval` would run it.
report_post() {
    _old_ifs="$IFS"; IFS='|'
    # shellcheck disable=SC2086 # deliberate word-splitting on IFS='|'
    set -- "$1" "$2" $3
    IFS="$_old_ifs"
    _r="$1"; _m="$2"; shift 2
    # Sets REPORT_CODE (000 = no HTTP answer: a transport failure) and
    # REPORT_ERR (curl's own words); returns 0 only on a 2xx. The code is the
    # only thing that distinguishes "controller said no" from "no route".
    _errf="${TMP:-/tmp}/report.err"
    _path="/bootstrap/bundle/$NODE/applied"
    _body="{\"sha\":\"$SUM\",\"rc\":$_r,\"msg\":\"$_m\"}"
    # v2 always. There is no v1 form left to sign: the controller refuses it.
    # A stale NOO_CLUSTER_TOKEN_SIGN=v1 line in the agent env is ignored. A
    # v2 refusal is reported as the 401 it is, never re-sent.
    # Substitute the bearer placeholder with a token for THIS request.
    _n=$#; _i=0
    while [ "$_i" -lt "$_n" ]; do
        _a="$1"; shift
        case "$_a" in
            "authorization: Bearer @NODE_BEARER@")
                _a="authorization: Bearer $(node_bearer POST "$_path" "$_body")" ;;
        esac
        set -- "$@" "$_a"
        _i=$((_i + 1))
    done
    if REPORT_CODE="$(curl -sS $TLS --connect-timeout 10 --max-time 20 -o /dev/null \
        -w '%{http_code}' \
        -H 'content-type: application/json' \
        -H "x-noo-content-sha256: $(printf '%s' "$_body" | openssl dgst -sha256 -hex 2>/dev/null | sed 's/.*= *//')" \
        "$@" \
        -d "$_body" \
        "$URL/bootstrap/bundle/$NODE/applied" 2>"$_errf")"; then :; else REPORT_CODE=000; fi
    case "$REPORT_CODE" in [0-9][0-9][0-9]) ;; *) REPORT_CODE=000 ;; esac
    REPORT_ERR="$(head -c 200 "$_errf" 2>/dev/null | tr '\n\r\t' '   ' || true)"
    case "$REPORT_CODE" in 2??) return 0 ;; esac
    return 1
}
# ── gzip-wrapped bundles ─────────────────────────────────────
#
# A controller at noo-cli >= 0.6.5 gzips bundle.tar BEFORE encrypting it
# (AES output does not compress, so it cannot be done after), and does so
# only for a node that reports that version or newer. The signed tar inside
# is byte-identical; noo-apply never sees the gzip. Detection is by the two
# magic bytes 1f 8b, not by anything the controller said, so an uncompressed
# bundle (an older controller) passes through untouched.
#
# gzip ABSENT or FAILED: the bundle cannot be read and nothing was applied.
# That is reported as rc 69 (the applier's "required helper missing"
# code, see its teardown/noo-deenroll refusal) with a readable reason in the
# apply log, rather than handing gzip bytes to noo-apply to be refused as
# "not a readable tar". The sha is recorded like any refused bundle, so the
# journal is not re-flooded every tick: install gzip and re-stage.
unwrap_gzip() {
    _magic="$(head -c 2 "$TMP/bundle.tar" 2>/dev/null | od -An -tx1 | tr -d ' \n')"
    [ "$_magic" = "1f8b" ] || return 0
    if ! command -v gzip >/dev/null 2>&1; then
        echo "noo-fetch: bundle is gzip-compressed but gzip is not installed on this node — install gzip, then re-stage" | tee "$TMP/apply.log" >&2
        return 69
    fi
    if ! gzip -dc < "$TMP/bundle.tar" > "$TMP/bundle.tar.plain" 2>"$TMP/err"; then
        echo "noo-fetch: gzip could not decompress the bundle ($(head -c 200 "$TMP/err" | tr '\n' ' ')) — re-stage" | tee "$TMP/apply.log" >&2
        return 69
    fi
    mv "$TMP/bundle.tar.plain" "$TMP/bundle.tar"
    echo "noo-fetch: bundle was gzip-compressed — decompressed"
    return 0
}
if unwrap_gzip; then :; else
    _grc=$?
    printf '10\n' > "$EXPECT"; printf '0\n' > "$STATE"
    printf '%s\n' "$SUM" > "$LAST"
    report "$_grc"
    exit "$_grc"
fi

echo "noo-fetch: applying via noo-apply"
# `if` keeps `set -e` from killing this script on a non-zero applier exit
# BEFORE the log is echoed and the outcome reported (that silence hid
# HOST3's exit 65 on 2026-09-03).
if /usr/local/bin/noo-apply "$TMP/bundle.tar" > "$TMP/apply.log" 2>&1; then rc=0; else rc=$?; fi
cat "$TMP/apply.log"
printf '10\n' > "$EXPECT"; printf '0\n' > "$STATE"   # a restage usually follows: poll fast for 10 ticks
if [ "$rc" -eq 0 ]; then
    printf '%s\n' "$SUM" > "$LAST"
    echo "noo-fetch: applied"
    report 0
else
    # Record the sha even on a refusal so a BAD staged bundle does not
    # re-fail every tick forever — re-staging a corrected bundle changes
    # the sha and retries naturally. The failure itself stays loud in the
    # unit's journal.
    printf '%s\n' "$SUM" > "$LAST"
    echo "noo-fetch: noo-apply failed (exit $rc) — journal has details; re-stage to retry" >&2
    report "$rc"
    exit "$rc"
fi
