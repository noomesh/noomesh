#!/bin/bash
# SPDX-License-Identifier: AGPL-3.0-only
# Copyright 2026 PersonifAI LLC

# noo-apply — the ROOT applier for signed bundles.
#
# Installed to /usr/local/bin/noo-apply (root:root 0755) by prep-host.sh.
# Its one caller is noo-fetch (noo-fetch.timer, root — the unit has no
# User=), which collects this node's staged bundle over the pull rail,
# decrypts it with the birth key, and hands the tar here. There is no
# sudoers drop-in and no SSH entry point: the noo-gate forced-command lane
# that used to reach this over `sudo -n` was retired 2026-09-05, and its
# `authorized-keys` payload kind was removed from this applier 2026-09-27.
# What makes a root applier safe is what it refuses:
#
#   NOTHING APPLIES UNLESS THE MANIFEST IS SIGNED BY THE FLEET SIGNING KEY
#   (or, for a signing-key ROLLOVER only, by the cluster CA).
#
# The transport authenticates nothing about content; the signature does.
# Whoever can put a file in front of this applier — a compromised rail, a
# stolen controller credential — installs nothing: forging a payload
# requires the signing key, which lives with noo-cli on the controller and
# never transits. CA ROTATION works because the transition bundle carrying the NEW
# ca.crt is signed with the OLD CA key — verified against the ca.crt this
# node already trusts. That is cross-signed rotation, not
# trust-on-first-use.
#
# Bundle format v2 (tar, produced by `noo security pki push-nodes`):
#   manifest        "#noo-bundle 2", "#node <id>", "#issued <unix>", then
#                   lines: "<sha256>  <kind>", kinds from the fixed set below
#   manifest.sig    openssl dgst -sha256 -sign <ca.key> over manifest
#   files/<kind>    the payload files themselves
#
# The header is what makes a bundle ADDRESSED. A v1 manifest was signed but
# anonymous and undated, so a valid bundle was valid anywhere, forever:
# a cert bundle intercepted on its way to node A carries A's node.key, and
# applying it to node B handed B A's private key and its identity -- which
# now decides what B may command (node-agent internal/auth/principal.go).
# The same gap let a months-old bundle be replayed to put a rotated cert or
# a superseded agent-env back on a node. `teardown` already carried its own
# node name for this reason; v2 gives every kind the same protection, and
# the freshness stamp closes the replay-in-time half.
#
# v1 kinds: ca.crt, node.crt, node.key. Unknown kinds are an ERROR, not a
# skip — a bundle from a newer controller must fail loudly, or "applied"
# would mean different things on different nodes.
set -eu

BUNDLE="${1:?usage: noo-apply <bundle.tar>}"

# The generation of this applier (/A2). §1b refuses to replace
# this applier with one of a LOWER generation: an older applier still has the
# CA-signed lane open by default, so a signed bundle carrying one would
# re-open the lane this applier retired. Bump it when a retirement must not
# be undone by a downgrade.
NOO_APPLY_GENERATION=1

# VERIFY-ONLY (tests): run every check, install nothing, exit 0 before the
# first write. Only in this mode may the anchor paths be redirected and the
# root check be skipped — a mode that installs nothing gains nothing from
# either. tests/test_apply_full_harness.py drives the real applier this way.
VERIFY_ONLY="${NOO_APPLY_VERIFY_ONLY:-0}"
if [ "$VERIFY_ONLY" = 1 ]; then
    PKI="${NOO_APPLY_PKI:-/etc/noo/pki}"
    NODE_ENV="${NOO_APPLY_NODE_ENV:-/etc/noo-node-agent.env}"
    SELF="${NOO_APPLY_SELF:-/usr/local/bin/noo-apply}"
else
    PKI=/etc/noo/pki
    NODE_ENV=/etc/noo-node-agent.env
    SELF=/usr/local/bin/noo-apply
    [ "$(id -u)" = 0 ] || { echo "noo-apply: must run as root (noo-fetch runs it from its root timer)" >&2; exit 1; }
fi
CA="$PKI/ca.crt"
[ -f "$CA" ] || { echo "noo-apply: no trusted CA at $CA — enroll this node first" >&2; exit 78; }

KNOWN_KINDS="ca.crt node.crt node.key agent-env agent-unit agent-binary teardown applier hostd-binary restart-backends host-telemetry cli-binary cli-user fetcher nats-creds fleet-secrets signing-pub harness-binary harness-env harness-unit svc-vllm.crt svc-vllm.key svc-llamacpp.crt svc-llamacpp.key svc-ollama.crt svc-ollama.key svc-tei.crt svc-tei.key svc-reranker.crt svc-reranker.key"

# ── 0. The tar's SHAPE, before a single byte is extracted ────
# This applier runs as root and writes into the extraction directory. A
# symlink or hardlink member would turn one of those writes (or a later
# member) into a write anywhere on the box — the review reproduced one
# overwriting signing.pub. So the member list is judged first: regular files
# and the one `files/` directory only, names from a fixed set, no duplicates.
# Kinds under files/ are judged by charset here, not against KNOWN_KINDS: a
# NEWER bundle must still reach §1b, which installs the applier that knows
# them.
# BEGIN bundle_tar_shape
_bundle_member_bad() {  # $1 = name, $2 = type char; prints the reason, or nothing
    case "$2" in
        -)
            case "$1" in
                manifest|manifest.sig|manifest.xsig.[0-9]|manifest.xsig.[0-9][0-9]) return 0 ;;
                files/*)
                    _k="${1#files/}"
                    case "$_k" in ''|.*|*[!a-z0-9.-]*) echo "$1" ;; esac
                    return 0 ;;
                *) echo "$1"; return 0 ;;
            esac ;;
        d)
            case "$1" in files|files/) return 0 ;; *) echo "$1 (directory)"; return 0 ;; esac ;;
        *) echo "$1 (type '$2': not a regular file)"; return 0 ;;
    esac
}
bundle_tar_ok() {  # $1 = tar path; 0 or 65 with the reason
    _names="$(LC_ALL=C tar -tf "$1" 2>/dev/null)" || { echo "noo-apply: REFUSED — the bundle is not a readable tar" >&2; return 65; }
    _types="$(LC_ALL=C tar -tvf "$1" 2>/dev/null | cut -c1)" || { echo "noo-apply: REFUSED — the bundle is not a readable tar" >&2; return 65; }
    _typesf="$(mktemp)"; printf '%s\n' "$_types" > "$_typesf"
    [ "$(printf '%s\n' "$_names" | wc -l)" = "$(printf '%s\n' "$_types" | wc -l)" ] \
        || { echo "noo-apply: REFUSED — the bundle's member list does not parse (a name with a line break?)" >&2; return 65; }
    _dups="$(printf '%s\n' "$_names" | sed 's#/$##' | sort | uniq -d | head -1)"
    [ -z "$_dups" ] || { echo "noo-apply: REFUSED — the bundle carries '$_dups' twice" >&2; return 65; }
    _bad=""
    while read -r _n _t; do
        _why="$(_bundle_member_bad "$_n" "$_t")"
        if [ -n "$_why" ]; then _bad="$_why"; break; fi
    done <<EOF_MEMBERS
$(printf '%s\n' "$_names" | paste -d' ' - "$_typesf")
EOF_MEMBERS
    rm -f "$_typesf"
    [ -z "$_bad" ] || { echo "noo-apply: REFUSED — bundle member '$_bad' is not one a bundle may carry" >&2; return 65; }
    return 0
}
# END bundle_tar_shape
bundle_tar_ok "$BUNDLE" || { logger -t noo-apply "REFUSED bundle: tar shape" 2>/dev/null || true; exit 65; }

WORK="$(mktemp -d)"
# The CA's public key is derived OUTSIDE the extraction directory: nothing
# the bundle carried can name or shadow it.
KEYS="$(mktemp -d)"
trap 'rm -rf "$WORK" "$KEYS"' EXIT
chmod 700 "$WORK" "$KEYS"
tar --no-same-owner --no-same-permissions -xf "$BUNDLE" -C "$WORK"
# Belt and braces after the list check: only regular files and the files/
# directory exist in what was extracted.
if [ -n "$(find "$WORK" -mindepth 1 \( ! -type f ! -type d \) -print -quit)" ] \
   || [ -n "$(find "$WORK" -mindepth 1 -type d ! -path "$WORK/files" -print -quit)" ]; then
    echo "noo-apply: REFUSED — the extracted bundle holds something other than regular files" >&2; exit 65
fi
[ -f "$WORK/manifest" ] && [ -f "$WORK/manifest.sig" ] || {
    echo "noo-apply: bundle lacks manifest/manifest.sig" >&2; exit 65
}

# ── 1. Signature: the whole trust decision ─────────────────────────────────
#
# §3f R26 — the fleet SIGNING key, not the CA key. an earlier changed (phase A)
# narrowed what is left of the CA's power to deliver code.
#
# Bundles used to be signed with the cluster CA private key, so one key both
# issued every mTLS identity and delivered root code to every box. They are
# split: `signing.pub` (delivered in a bundle) verifies bundles; the CA
# verifies exactly one thing, the ROLLOVER bundle that installs or replaces
# `signing.pub`.
#
# Two arms, and nothing else:
#   1. signing.pub, if this node has one. The normal path.
#   2. the CA, ONLY for a bundle that carries a signing-pub payload — a
#      rollover — and only when either
#        a. this node holds no signing.pub yet (first adoption: the CA is the
#           one anchor it has), or
#        b. the bundle is COUNTERSIGNED by the signing key this node already
#           holds (`manifest.xsig*`, written by the controller with every
#           signing key it has retained). A stolen CA key alone can therefore
#           no longer replace the key that authorises code on an adopted node.
#
# RETIRED (, 2026-10-10): the third arm — "the CA,
# unconditionally", the compatibility window behind NOO_APPLY_ACCEPT_CA_SIGNED
# (default open). A CA-signed bundle that is not a rollover is refused (77),
# loudly, whatever that variable says. The fleet had shown 0 uses of it.
# BEGIN signature_lane
# bundle_signature_lane PKI WORK — sets SIG_VIA or exits 77 with the reason.
bundle_signature_lane() {
    _pki="$1"; _work="$2"; _keys="$3"
    SIGNPUB="$_pki/signing.pub"
    # Outside $_work: a bundle member can never be the file this writes.
    openssl x509 -pubkey -noout -in "$_pki/ca.crt" > "$_keys/ca.pub"
    # Which kinds the SIGNED manifest names — never which files happen to be
    # on disk (an unlisted file is refused in §2, but the trust decision must
    # not depend on that ordering).
    _kinds="$(awk '!/^#/ && NF >= 2 {print $2}' "$_work/manifest" | sort | tr '\n' ' ')"
    _sig_ok() {  # $1 = pubkey PEM path, $2 = signature file (default manifest.sig)
        openssl dgst -sha256 -verify "$1" \
            -signature "${2:-$_work/manifest.sig}" "$_work/manifest" >/dev/null 2>&1
    }
    if [ -n "${NOO_APPLY_ACCEPT_CA_SIGNED:-}" ]; then
        echo "noo-apply: NOO_APPLY_ACCEPT_CA_SIGNED is retired and ignored — the CA-signed lane no longer exists" >&2
    fi
    SIG_VIA=""
    if [ -f "$SIGNPUB" ] && _sig_ok "$SIGNPUB"; then
        SIG_VIA="signing-key"
        return 0
    fi
    if [ "$_kinds" = "signing-pub " ] && _sig_ok "$_keys/ca.pub"; then
        if [ ! -f "$SIGNPUB" ]; then
            SIG_VIA="ca-rollover"
            return 0
        fi
        for _x in "$_work"/manifest.xsig*; do
            [ -f "$_x" ] || continue
            if _sig_ok "$SIGNPUB" "$_x"; then
                SIG_VIA="ca-rollover-countersigned"
                return 0
            fi
        done
        echo "noo-apply: REFUSED — a CA-signed signing-key rollover that the signing key this node already holds ($SIGNPUB) did not countersign" >&2
        echo "noo-apply: the CA key alone may not replace an adopted signing key. Re-run 'noo security pki rotate-signing-key' from a controller that still holds the previous signing key; if it is lost, re-enroll this node." >&2
        logger -t noo-apply "REFUSED bundle: CA-signed rollover without a countersignature from the installed signing key" 2>/dev/null || true
        exit 77
    fi
    if _sig_ok "$_keys/ca.pub" && case " $_kinds" in *" signing-pub "*) true ;; *) false ;; esac; then
        echo "noo-apply: REFUSED — a CA-signed bundle may carry signing-pub and NOTHING else (it carries: $_kinds)" >&2
        echo "noo-apply: the CA key delivers a public key, never code. Deliver the key alone ('noo security pki rotate-signing-key <node> --deliver-only'), then everything else signed by the signing key." >&2
        logger -t noo-apply "REFUSED bundle: CA-signed rollover carrying more than signing-pub" 2>/dev/null || true
        exit 77
    fi
    if _sig_ok "$_keys/ca.pub"; then
        echo "noo-apply: REFUSED — this bundle is signed by the cluster CA, not the fleet signing key, and it is not a signing-key rollover" >&2
        echo "noo-apply: the CA-signed apply lane is retired. On the controller: 'noo security pki rotate-signing-key --deliver-only', then 'noo cluster provision <node> --wait'." >&2
        logger -t noo-apply "REFUSED bundle: CA-signed lane retired (verified-by would have been ca-legacy)" 2>/dev/null || true
        exit 77
    fi
    if [ -f "$SIGNPUB" ]; then
        echo "noo-apply: manifest signature verifies against NEITHER $SIGNPUB nor $_pki/ca.crt — refusing" >&2
    else
        echo "noo-apply: manifest signature does NOT verify against $_pki/ca.crt — refusing" >&2
    fi
    logger -t noo-apply "REFUSED bundle: bad signature" 2>/dev/null || true
    exit 77
}
# END signature_lane
# The manifest's SHAPE, one parser for every reader below (awk, `read`, the
# header seds): header lines exactly as the builders write them, payload lines
# exactly `<64 hex><two spaces><kind>`, anchored at column 1, nothing else.
# A line any reader could split differently is refused before any is read.
# BEGIN manifest_shape
manifest_ok() {  # $1 = manifest path
    if LC_ALL=C grep -vqE '^(#noo-bundle 2|#node [A-Za-z0-9._-]{1,64}|#issued [0-9]{1,12}|[0-9a-f]{64}  [a-z0-9][a-z0-9.-]{0,63})$' "$1"; then
        echo "noo-apply: REFUSED — the manifest has a line that is not a header or '<sha256>  <kind>'" >&2
        return 65
    fi
    LC_ALL=C tr -d '\r\000' < "$1" | cmp -s - "$1" || { echo "noo-apply: REFUSED — the manifest carries a CR or NUL" >&2; return 65; }
    return 0
}
# END manifest_shape
manifest_ok "$WORK/manifest" || { logger -t noo-apply "REFUSED bundle: manifest shape" 2>/dev/null || true; exit 65; }
bundle_signature_lane "$PKI" "$WORK" "$KEYS"

# ── 1a. Header: who this bundle is for, and when it was made ───────────────
# Read AFTER the signature, never before: an unsigned header is just an
# attacker's opinion. Everything below is covered by the signature that
# just verified.
BUNDLE_VER="$(sed -n 's/^#noo-bundle *//p' "$WORK/manifest" | head -1)"
BUNDLE_NODE="$(sed -n 's/^#node *//p' "$WORK/manifest" | head -1)"
BUNDLE_ISSUED="$(sed -n 's/^#issued *//p' "$WORK/manifest" | head -1)"

if [ -z "$BUNDLE_VER" ]; then
    echo "noo-apply: this bundle has no #noo-bundle header — it was built by a controller from before bundles were addressed to a node." >&2
    echo "noo-apply: a bundle that names no node and no date can be replayed onto any node at any time, so this applier refuses it. Re-push from a current controller." >&2
    logger -t noo-apply "REFUSED bundle: v1 (unaddressed) manifest" 2>/dev/null || true
    exit 77
fi

# The node this box already knows itself to be. NOT the bundle's own
# agent-env: in a re-targeting attack the bundle carries the victim's
# agent-env too, so believing it would make the check agree with itself.
# An enrolled node has one of these; a first install has neither, and then
# the bundle IS the enrollment and there is nothing to disagree with.
INSTALLED_ID="$(grep -E '^NODE_ID=' "$NODE_ENV" 2>/dev/null | cut -d= -f2- || true)"
if [ -n "$INSTALLED_ID" ] && [ "$BUNDLE_NODE" != "$INSTALLED_ID" ]; then
    echo "noo-apply: this bundle is addressed to '$BUNDLE_NODE' but this node is '$INSTALLED_ID' — refusing" >&2
    echo "noo-apply: applying it would install another node's identity here. If this node was genuinely renamed, re-enroll it rather than replaying a bundle." >&2
    logger -t noo-apply "REFUSED bundle: addressed to $BUNDLE_NODE, this node is $INSTALLED_ID" 2>/dev/null || true
    exit 77
fi
if [ -z "$INSTALLED_ID" ]; then
    echo "noo-apply: no installed node identity yet — treating this as the first install for '$BUNDLE_NODE'"
fi

# Freshness. A signed bundle stays cryptographically valid forever, so
# without a clock the CA signature alone cannot distinguish "the controller
# is pushing this now" from "someone kept a copy". The window is generous
# because bundles are applied within seconds of being built; a node whose
# clock is badly wrong will say so here rather than fail somewhere stranger.
MAX_AGE="${NOO_APPLY_MAX_AGE:-86400}"
case "$MAX_AGE" in ''|*[!0-9]*) MAX_AGE=86400 ;; esac
NOW="$(date -u +%s)"
if [ -z "$BUNDLE_ISSUED" ]; then
    echo "noo-apply: bundle header carries no #issued stamp — refusing" >&2
    exit 77
fi
# Digits only, and few of them, BEFORE any arithmetic: bash evaluates a
# variable's text inside $(( )), so a header of `NOW[$(cmd)]` would run a
# command as root ( second review, H1). The manifest shape check
# above already pins this; this is the guard at the point of use.
if ! printf '%s' "$BUNDLE_ISSUED" | grep -qE '^[0-9]{1,12}$'; then
    echo "noo-apply: REFUSED — the #issued stamp is not a plain number" >&2
    logger -t noo-apply "REFUSED bundle: non-numeric #issued" 2>/dev/null || true
    exit 77
fi
AGE=$(( NOW - BUNDLE_ISSUED ))
if [ "$AGE" -gt "$MAX_AGE" ]; then
    echo "noo-apply: this bundle was signed ${AGE}s ago, past the ${MAX_AGE}s freshness window — refusing a replay" >&2
    echo "noo-apply: if this is a legitimate late apply, re-push from the controller; if this node's clock is wrong, fix the clock first." >&2
    logger -t noo-apply "REFUSED bundle: stale by ${AGE}s" 2>/dev/null || true
    exit 77
fi
if [ "$AGE" -lt -300 ]; then
    echo "noo-apply: this bundle claims to be signed $(( -AGE ))s in the future — this node's clock or the controller's is wrong; refusing" >&2
    exit 77
fi

# ── 1b. Applier self-update comes FIRST (2026-09-03): a bundle that carries
# a newer noo-apply must be applied BY that noo-apply, or every new kind in
# the same bundle is refused by the old one (HOST3 refused `cli-binary`
# with 76 while the controller printed success). The payload's sha is
# checked against the signed manifest here, before anything else runs;
# then the new applier is exec'd on the same bundle. NOO_APPLY_REEXEC
# guards against loops; an identical applier is skipped.
if [ -f "$WORK/files/applier" ] && [ -z "${NOO_APPLY_REEXEC:-}" ]; then
    want="$(awk '$2 == "applier" {print $1}' "$WORK/manifest")"
    have="$(sha256sum "$WORK/files/applier" | awk '{print $1}')"
    [ -n "$want" ] && [ "$want" = "$have" ] || { echo "noo-apply: applier payload does not match the signed manifest" >&2; exit 74; }
    cur="$(sha256sum "$SELF" 2>/dev/null | awk '{print $1}')"
    if [ "$cur" != "$have" ]; then
        head -1 "$WORK/files/applier" | grep -q '^#!' || { echo "noo-apply: applier payload has no shebang" >&2; exit 65; }
        grep -q 'noo-apply' "$WORK/files/applier" || { echo "noo-apply: applier payload does not look like noo-apply" >&2; exit 65; }
        # The downgrade floor: never replace this applier with
        # one of a lower generation. An applier with no generation line
        # predates the retirement of the CA-signed lane.
        _pgen="$(grep -m1 -E '^NOO_APPLY_GENERATION=[0-9]+$' "$WORK/files/applier" | cut -d= -f2)"
        if [ "${_pgen:-0}" -lt "$NOO_APPLY_GENERATION" ]; then
            echo "noo-apply: REFUSED — the bundle's applier is generation ${_pgen:-0}, older than this one ($NOO_APPLY_GENERATION); installing it would re-open retired lanes" >&2
            logger -t noo-apply "REFUSED bundle: applier downgrade (generation ${_pgen:-0} < $NOO_APPLY_GENERATION)" 2>/dev/null || true
            exit 65
        fi
    fi
    if [ "$cur" != "$have" ] && [ "$VERIFY_ONLY" != 1 ]; then
        install -m 755 -o root -g root "$WORK/files/applier" /usr/local/bin/noo-apply.next
        mv /usr/local/bin/noo-apply.next /usr/local/bin/noo-apply
        echo "noo-apply: applier updated from the bundle — re-running under the new applier"
        rm -rf "$WORK"; trap - EXIT
        NOO_APPLY_REEXEC=1 exec /usr/local/bin/noo-apply "$BUNDLE"
    fi
fi

# ── 2. Integrity + allowlist: every file must match, every kind be known ───
while read -r sum kind; do
    [ -n "$sum" ] || continue
    # Header lines were consumed above; they name no payload.
    case "$sum" in \#*) continue ;; esac
    case " $KNOWN_KINDS " in
        *" $kind "*) : ;;
        *) echo "noo-apply: unknown kind '$kind' — this node's applier is older than the bundle; refusing" >&2; exit 76 ;;
    esac
    f="$WORK/files/$kind"
    [ -f "$f" ] || { echo "noo-apply: manifest names '$kind' but the bundle lacks it" >&2; exit 65; }
    actual="$(sha256sum "$f" | awk '{print $1}')"
    [ "$actual" = "$sum" ] || { echo "noo-apply: sha256 mismatch for '$kind'" >&2; exit 74; }
done < "$WORK/manifest"
# …and every file must be NAMED by the signed manifest. Install blocks below
# key on a file's presence, so an unlisted file would be installed unsigned.
for _f in "$WORK"/files/*; do
    [ -e "$_f" ] || continue
    _k="$(basename "$_f")"
    awk -v k="$_k" '!/^#/ && $2 == k {found=1} END {exit !found}' "$WORK/manifest" || {
        echo "noo-apply: REFUSED — the bundle carries files/$_k, which the signed manifest does not name" >&2
        logger -t noo-apply "REFUSED bundle: unmanifested file $_k" 2>/dev/null || true
        exit 65
    }
done

# ── 2b. Env files and units carry only their fixed shape ( A4/A5)
#
# agent-env and harness-env are EnvironmentFiles read by pid 1, so a line in
# them can change what executes (LD_PRELOAD, PATH). They used to be checked
# only for NODE_ID; now every line must be a comment, blank, or a KEY this
# kind is rendered with (the keys of node-agent-go/deploy/*.env.tmpl — a
# guard test pins the lists to the templates), PATH and DOCKER_HOST must be
# exactly the rendered values, and no value may carry a command substitution.
# agent-unit and harness-unit must be the shipped unit's SHAPE: only the
# directives it uses, and ExecStart / User / groups / env file pinned, so a
# text file can no longer name a root command. Checked for every kind in the
# bundle BEFORE anything is installed, so a refused bundle changes nothing.
# A refusal exits 65 with the line that failed, and logs it.
# BEGIN env_unit_shape
AGENT_ENV_KEYS="NODE_ID NODE_IP NODE_TIER GPU_MODEL CONTROLLER_URL NATS_URL NOO_NODE_AGENT_TOKEN NOO_CLUSTER_SECRET NOO_PKI_DIR NOO_TLS_CA NOO_TLS_CERT NOO_TLS_KEY NOO_MTLS_NODES OLLAMA_URL NOO_SELF_NODE NOO_DATA_ROOT HF_CACHE_DIR MODELS_DIR OLLAMA_DATA_DIR NOO_MODEL_CACHE_URL PATH NOO_FORCE_GPU NOO_OLLAMA_GPU_COUNT NOO_IMAGE_PREFIX NOO_IMAGE_TAG NODE_AGENT_PORT LOG_LEVEL DOCKER_HOST"
# Inert keys an older controller still renders: accepted, never acted on.
# NOO_APPLY_ACCEPT_CA_SIGNED gated the CA-signed lane.
AGENT_ENV_INERT_KEYS="NOO_APPLY_ACCEPT_CA_SIGNED"
HARNESS_ENV_KEYS="NODE_ID NOO_GATEWAY_URL NATS_URL NATS_NODE_USER NATS_NODE_PASSWORD NOO_TLS_CA NOO_TLS_CERT NOO_TLS_KEY NOO_HARNESS_MODEL_URL NOO_NODE_AGENT_TOKEN NOO_CLUSTER_SECRET NOO_HARNESS_MODEL NOO_HARNESS_BACKEND NOO_HARNESS_MAX_TURNS RUST_LOG"
AGENT_ENV_PATH="/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin:/usr/lib/wsl/lib"
AGENT_ENV_DOCKER_HOST="unix:///var/run/docker.sock"

_shape_refuse() {  # $1 kind, $2 reason
    echo "noo-apply: REFUSED $1 — $2 (env files and units carry only their fixed shape)" >&2
    logger -t noo-apply "REFUSED bundle: $1 $2" 2>/dev/null || true
    return 65
}

# env_payload_ok FILE KIND "ALLOWED KEYS"
env_payload_ok() {
    _f="$1"; _kind="$2"; _keys=" $3 "; _n=0
    while IFS= read -r _line || [ -n "$_line" ]; do
        _n=$((_n + 1))
        _line="$(printf '%s' "$_line" | tr -d '\r')"
        case "$_line" in ''|'#'*) continue ;; esac
        _k="${_line%%=*}"
        [ "$_k" != "$_line" ] || { _shape_refuse "$_kind" "line $_n is not KEY=value"; return 65; }
        _v="${_line#*=}"
        case "$_keys" in
            *" $_k "*) : ;;
            *) _shape_refuse "$_kind" "line $_n sets '$_k', which is not a key $_kind is rendered with"; return 65 ;;
        esac
        case "$_v" in
            *'`'*|*'$('*) _shape_refuse "$_kind" "line $_n ($_k) carries a command substitution"; return 65 ;;
        esac
        case "$_k" in
            PATH) [ "$_v" = "$AGENT_ENV_PATH" ] || { _shape_refuse "$_kind" "PATH is not the rendered value"; return 65; } ;;
            DOCKER_HOST) [ "$_v" = "$AGENT_ENV_DOCKER_HOST" ] || { _shape_refuse "$_kind" "DOCKER_HOST is not the local socket"; return 65; } ;;
            NOO_APPLY_ACCEPT_CA_SIGNED) [ "$_v" = 0 ] || { _shape_refuse "$_kind" "NOO_APPLY_ACCEPT_CA_SIGNED may only say 0"; return 65; } ;;
        esac
    done < "$_f"
    return 0
}

# unit_payload_ok FILE KIND — byte-for-byte one of the units this release
# ships (node-agent-go/deploy/noo-{node-agent,harness}.service; the guard
# test pins these sums to those files). A directive check let a `User=` in
# the wrong section, a `StandardOutput=file:` that pid 1 opens as root, or a
# line hidden behind a CR through; an exact match lets nothing through.
AGENT_UNIT_SHA256="946dede0eb81ab164afb4d61e9000ffc38d550dc0424333ff792c4dc16bf02e4"
HARNESS_UNIT_SHA256="ad98f59951ee7347866dd3cae9788fac0458814413db61e87a77e50a5648d3ee"
unit_payload_ok() {
    _f="$1"; _kind="$2"
    case "$_kind" in
        agent-unit) _want="$AGENT_UNIT_SHA256" ;;
        harness-unit) _want="$HARNESS_UNIT_SHA256" ;;
        *) _shape_refuse "$_kind" "is not a unit kind"; return 65 ;;
    esac
    _have="$(sha256sum "$_f" | awk '{print $1}')"
    case " $_want " in
        *" $_have "*) return 0 ;;
    esac
    _shape_refuse "$_kind" "is not the unit this release ships (sha256 $_have)"
    return 65
}

# text_payload_ok FILE KIND — no CR and no NUL anywhere. systemd ends a line
# at a lone CR (and at NUL), while `read` and grep do not see one there, so
# a directive or key hidden behind either would reach pid 1 unchecked. Every
# text kind is held to this, including the merges (nats-creds,
# fleet-secrets), whose lines land in an EnvironmentFile.
TEXT_KINDS="agent-env harness-env nats-creds fleet-secrets host-telemetry teardown cli-user signing-pub ca.crt node.crt node.key agent-unit harness-unit restart-backends"
text_payload_ok() {
    if ! LC_ALL=C tr -d '\r\000' < "$1" | cmp -s - "$1"; then
        _shape_refuse "$2" "carries a carriage return or NUL byte"
        return 65
    fi
    return 0
}
# hostd_generation_of FILE — the highest `noo-hostd-generation=NN;` marker in
# a binary, 0 when it has none (or does not exist). Two digits, so the value
# is always a plain number before `[ -lt ]` sees it.
hostd_generation_of() {
    _g="$(LC_ALL=C grep -aoE 'noo-hostd-generation=[0-9]{2};' "$1" 2>/dev/null | tr -dc '0-9\n' | sort -n | tail -1)"
    _g="${_g#0}"
    printf '%s\n' "${_g:-0}"
}
# END env_unit_shape

# BEGIN binary_unchanged
# binary_unchanged PAYLOAD INSTALLED — true only when INSTALLED exists, is
# readable, and has the same sha256 as PAYLOAD. A missing file (first
# install), an unreadable one, or a sha that cannot be computed all return
# false, so the caller INSTALLS: the skip path needs positive proof of
# identity, never the absence of a difference. A restage that carries the
# bytes the node already runs then neither rewrites the file nor restarts the
# service for it, and the applied: summary says `<kind>=unchanged` (a
# different token from `<kind>`, which the controller reads as "installed").
binary_unchanged() {
    [ -f "$2" ] || return 1
    _bu_new="$(sha256sum "$1" 2>/dev/null | awk '{print $1}')"
    _bu_cur="$(sha256sum "$2" 2>/dev/null | awk '{print $1}')"
    [ -n "$_bu_new" ] && [ "$_bu_new" = "$_bu_cur" ]
}

# note_binary_sha KIND PAYLOAD — remember the sha256 of a binary this apply
# left running (installed or proven unchanged). Printed once at the very end
# as `binary-sha: kind=<sha256> …`: the node's own statement of what it runs,
# which is what lets the controller leave an identical binary out of the next
# bundle. Only kinds that reached a successful end are recorded; an applier
# that predates this prints none, and the controller then carries everything.
note_binary_sha() {
    _nb="$(sha256sum "$2" 2>/dev/null | awk '{print $1}')"
    [ -z "$_nb" ] || binary_shas="$binary_shas $1=$_nb"
}
# END binary_unchanged

# BEGIN config_unchanged
# config_unchanged PAYLOAD INSTALLED MODE OWNER:GROUP — the non-binary twin of
# binary_unchanged: true only when INSTALLED exists, is readable, has the same
# bytes as PAYLOAD, AND already carries the mode and owner:group the install
# would give it. A missing file (first install), an unreadable one, a stat
# that fails, or ANY difference in bytes, mode or owner returns false, so the
# caller INSTALLS exactly as before: the skip path needs positive proof of
# identity. A skipped kind sets no restart/reload flag and reports
# `<kind>=unchanged`, a token the controller's whole-token applier_applied
# lookup does not read as "installed".
config_unchanged() {
    [ -f "$2" ] || return 1
    cmp -s "$1" "$2" 2>/dev/null || return 1
    _cu_have="$(stat -c '%a %U:%G' "$2" 2>/dev/null)" || return 1
    [ "$_cu_have" = "$3 $4" ]
}
# END config_unchanged

for _k in $TEXT_KINDS; do
    [ -f "$WORK/files/$_k" ] && { text_payload_ok "$WORK/files/$_k" "$_k" || exit 65; }
done
case "$(ls "$WORK"/files/svc-*.crt "$WORK"/files/svc-*.key 2>/dev/null | head -1)" in
    "") : ;;
    *) for _f in "$WORK"/files/svc-*; do text_payload_ok "$_f" "$(basename "$_f")" || exit 65; done ;;
esac
[ -f "$WORK/files/agent-env" ] && { env_payload_ok "$WORK/files/agent-env" agent-env "$AGENT_ENV_KEYS $AGENT_ENV_INERT_KEYS" || exit 65; }
[ -f "$WORK/files/harness-env" ] && { env_payload_ok "$WORK/files/harness-env" harness-env "$HARNESS_ENV_KEYS" || exit 65; }
[ -f "$WORK/files/agent-unit" ] && { unit_payload_ok "$WORK/files/agent-unit" agent-unit || exit 65; }
[ -f "$WORK/files/harness-unit" ] && { unit_payload_ok "$WORK/files/harness-unit" harness-unit || exit 65; }

# NODE_ID resolution order matters (found live 2026-08-18): the BUNDLE's
# agent-env is authoritative — it carries the operator-adopted name, which
# may differ from the hostname. On a FIRST install /etc/noo-node-agent.env
# does not exist yet (agent-env is applied later in THIS bundle), so reading
# it here fell back to the hostname and installed certs under the wrong path
# — the agent then crash-looped, cert-not-found. Read the staged agent-env
# first, then the installed env, then hostname.
# The signed header is now the first source: it says who the controller
# built this bundle for, it cannot be edited without breaking the
# signature, and §1a has already confirmed it does not contradict this
# node's installed identity. The old order (bundle agent-env, installed
# env, hostname) stays as the fallback for the same reason it was chosen
# live on 2026-08-18 -- the operator-adopted name may differ from the
# hostname, and on a first install nothing is on disk yet.
NODE_ID="$BUNDLE_NODE"
[ -n "$NODE_ID" ] || { [ -f "$WORK/files/agent-env" ] && NODE_ID="$(grep -E '^NODE_ID=' "$WORK/files/agent-env" | cut -d= -f2- || true)"; }
[ -n "$NODE_ID" ] || NODE_ID="$(grep -E '^NODE_ID=' /etc/noo-node-agent.env 2>/dev/null | cut -d= -f2- || true)"
NODE_ID="${NODE_ID:-$(hostname)}"

if [ "$VERIFY_ONLY" = 1 ]; then
    echo "verified-by: $SIG_VIA"
    echo "verify-only: every check passed; nothing installed"
    exit 0
fi

# ── teardown — the graceful, controller-initiated node destroy ─────────────
# A signed `teardown` kind means "return this node to never-met-the-fleet".
# It runs the local de-enroll — but that script deletes noo-apply itself,
# so it CANNOT run inline: it is launched DETACHED after a short delay, so
# this applier (and noo-fetch, which invoked it) report their result to the
# controller FIRST, then the node dismantles itself.
# The payload file's content is the node name, which must match — a signed
# teardown for node A cannot be replayed to destroy node B.
if [ -f "$WORK/files/teardown" ]; then
    # Line 1 = node name (must match). Line 2 (optional) = "purge-data".
    want="$(sed -n 1p "$WORK/files/teardown" | tr -d '[:space:]')"
    directive="$(sed -n 2p "$WORK/files/teardown" | tr -d '[:space:]')"
    have="$NODE_ID"
    DEENROLL_ARGS="--from-gate"
    case "$directive" in
        *purge-data*|*factory*)      DEENROLL_ARGS="$DEENROLL_ARGS --purge-data" ;;
    esac
    case "$directive" in
        *purge-tailscale*|*factory*) DEENROLL_ARGS="$DEENROLL_ARGS --purge-tailscale" ;;
    esac
    if [ -n "$want" ] && [ "$want" != "$have" ]; then
        echo "noo-apply: teardown names '$want' but this node is '$have' — refusing" >&2
        exit 76
    fi
    DEENROLL=/usr/local/bin/noo-deenroll
    if [ ! -x "$DEENROLL" ]; then
        echo "noo-apply: teardown requested but $DEENROLL is not installed" >&2
        exit 69
    fi
    logger -t noo-apply "teardown authorized (node=$have) — dismantling in 5s, detached" 2>/dev/null || true
    echo "applied: teardown ($have) — node will dismantle itself in ~5s"
    # Finding #83: on the PULL lane this script runs inside noo-fetch.service
    # (Type=oneshot). setsid escapes the SESSION but not the CGROUP — the
    # moment the oneshot's main process exits, systemd reaps every process
    # left in the unit's cgroup, and the 5s grace guaranteed the dismantle
    # was still there to be killed. Every pull-rail teardown died this way,
    # silently, while the fetch signal made the controller print "collected".
    # A systemd-run transient unit runs in its OWN cgroup and survives; the
    # setsid fallback remains for non-systemd hosts (it always worked on
    # the retired gate/SSH lane, where no oneshot cgroup was involved).
    if command -v systemd-run >/dev/null 2>&1; then
        systemd-run --unit="noo-teardown-$$" --collect --quiet \
            sh -c "sleep 5; $DEENROLL $DEENROLL_ARGS >/var/log/noo-deenroll.log 2>&1" \
            && { logger -t noo-apply "teardown handed to transient unit noo-teardown-$$" 2>/dev/null || true; exit 0; }
        echo "noo-apply: systemd-run failed — falling back to setsid (may not survive a oneshot parent)" >&2
    fi
    setsid sh -c "sleep 5; $DEENROLL $DEENROLL_ARGS >/var/log/noo-deenroll.log 2>&1" </dev/null >/dev/null 2>&1 &
    exit 0
fi

# ── 3. Apply ───────────────────────────────────────────────────────────────
# Kinds are applied in DEPENDENCY order — env before unit before start — and
# the orchestration flags (restart? daemon-reload? first install?) are
# collected as we go, executed once at the end.
install -d -m 750 -o root -g noo-agent "$PKI/nodes/$NODE_ID"

applied=""
binary_shas=""
need_restart=0
need_daemon_reload=0
need_harness_restart=0
fresh_unit=0

# certs — root:noo-agent, group-readable
# ca.crt is a PUBLIC certificate: 644 so an unprivileged `noo upgrade` can
# pin the controller mirror to it (2026-09-03); the keys stay 640.
if [ -f "$WORK/files/ca.crt" ]; then
    if config_unchanged "$WORK/files/ca.crt" "$PKI/ca.crt" 644 root:noo-agent; then
        applied="$applied ca.crt=unchanged"
    else
        install -m 644 -o root -g noo-agent "$WORK/files/ca.crt"   "$PKI/ca.crt"; chmod 755 /etc/noo "$PKI" 2>/dev/null || true; applied="$applied ca.crt"; need_restart=1
    fi
fi
# signing-pub — the fleet code-signing PUBLIC key (§3f R26). A public key:
# 644, same as ca.crt. Installing it is what moves this node off the
# CA-signed compatibility lane, so it is applied on the same pass that
# verified it, and no agent restart is needed — only noo-apply reads it.
[ -f "$WORK/files/signing-pub" ] && { install -m 644 -o root -g noo-agent "$WORK/files/signing-pub" "$PKI/signing.pub"; applied="$applied signing-pub"; }
# node.crt / node.key: an identical file (bytes, 640, root:noo-agent) is left
# alone and does not bounce the agent.
for _nk in node.crt node.key; do
    [ -f "$WORK/files/$_nk" ] || continue
    if config_unchanged "$WORK/files/$_nk" "$PKI/nodes/$NODE_ID/$_nk" 640 root:noo-agent; then
        applied="$applied $_nk=unchanged"
    else
        install -m 640 -o root -g noo-agent "$WORK/files/$_nk" "$PKI/nodes/$NODE_ID/$_nk"; applied="$applied $_nk"; need_restart=1
    fi
done

# svc-<x>.crt / svc-<x>.key — this node's backend door leaves (an earlier change
# A). Every backend the agent starts serves through a door that requires a
# client certificate (vLLM's own listener, a noo-stunnel-<x> sidecar for the
# rest), and the door serves with $PKI/services/<x>/service.{crt,key}; the
# agent refuses to start a backend whose leaf is missing or does not name
# its door. Read by root inside the door's container, so: root:root, key
# 0600, cert 0644 (the agent reads the cert's SANs as noo-agent), dir 0755.
#
# Each pair is checked before it replaces anything: both halves present,
# the cert chains to the CA this node trusts (installed above, so a CA
# transition bundle is judged against its own anchor), and the key is the
# cert's key. Installed next to the target and renamed over it, so a reader
# sees the old file or the new one, never half of one.
#
# A leaf the bundle does not carry is left alone. Dropping a node's leaf is
# revocation, which is its own act on the controller, not a side effect of
# a restage that happens to carry fewer kinds. No agent restart: the
# reconciler re-checks the door every tick and starts the backend once its
# leaf is here; a RUNNING door keeps the leaf it started with until its
# backend is next recreated.
for _svc in vllm llamacpp ollama tei reranker; do
    _c="$WORK/files/svc-$_svc.crt"; _k="$WORK/files/svc-$_svc.key"
    [ -f "$_c" ] || [ -f "$_k" ] || continue
    [ -f "$_c" ] && [ -f "$_k" ] || { echo "noo-apply: svc-$_svc carries half a leaf (cert and key travel together) — refusing" >&2; exit 65; }
    # Identical to what is installed (bytes, key 600 / cert 644, root:root):
    # nothing to install, so no .next file is written and no rename happens.
    # The CA/key verification below is for what we are ABOUT TO INSTALL; an
    # unchanged file was verified when it was installed and is already
    # trusted, so it is not re-judged here. Any difference (or a missing or
    # unreadable file) falls through to verify + install as before.
    _d="$PKI/services/$_svc"
    if config_unchanged "$_k" "$_d/service.key" 600 root:root \
        && config_unchanged "$_c" "$_d/service.crt" 644 root:root; then
        applied="$applied svc-$_svc=unchanged"
        continue
    fi
    openssl verify -CAfile "$PKI/ca.crt" "$_c" >/dev/null 2>&1 \
        || { echo "noo-apply: svc-$_svc.crt does not verify against $PKI/ca.crt — refusing" >&2; exit 65; }
    # Compared as text, and each side must be non-empty: two failed
    # openssl calls would otherwise agree with each other.
    _cp="$(openssl x509 -in "$_c" -noout -pubkey 2>/dev/null || true)"
    _kp="$(openssl pkey -in "$_k" -pubout 2>/dev/null || true)"
    [ -n "$_cp" ] && [ -n "$_kp" ] && [ "$_cp" = "$_kp" ] \
        || { echo "noo-apply: svc-$_svc.key is not the key of svc-$_svc.crt — refusing" >&2; exit 65; }
    _d="$PKI/services/$_svc"
    install -d -m 755 -o root -g root "$PKI/services" "$_d"
    install -m 600 -o root -g root "$_k" "$_d/.service.key.next"
    install -m 644 -o root -g root "$_c" "$_d/.service.crt.next"
    mv -f "$_d/.service.key.next" "$_d/service.key"
    mv -f "$_d/.service.crt.next" "$_d/service.crt"
    applied="$applied svc-$_svc"
done

# agent-env — credentials; root-only, systemd (pid 1) reads it, not the agent
# ── grant_traverse USER PATH ──────────────────────────────────────────────
# Every EXISTING ancestor of PATH must be traversable by USER, or the agent
# sees PATH as absent: on host8 the data root sat under /media/<user>/, a
# udisks mount parent that is 750 root:root plus an ACL for that one person,
# and the agent's system user spent five days (2026-09-13 → 09-18) logging
# `mkdir /media/<user>/<drive>: permission denied` against a drive that was
# mounted the whole time. An execute-only ACL is the smallest grant that
# lets a user pass through a directory without listing it, and it is
# granted only where traverse is actually missing.
# BEGIN grant_traverse
# setfacl's presence is checked ONCE, not per path: when it is missing the
# fix this printed per line (`setfacl -m ...`) needs the very binary that
# is missing, so a worker without the `acl` package (Ubuntu 24.04 minimal
# has no ACL tools installed by default) got the same unusable paragraph
# repeated once per ancestor directory across every declared root — seven
# WARNING lines on the 2026-09-29 newcomer upgrade rehearsal. Missing-binary
# paths are queued (newline-separated string — this block is exercised
# under plain /bin/sh, no arrays) in _GT_MISSING_PATHS and reported
# together, once, by grant_traverse_flush_missing (called after all
# grant_traverse calls). The "refused" case (setfacl present but the call
# itself failed — wrong filesystem, permissions, etc.) is a per-path
# problem and keeps its per-path message.
_GT_SETFACL_PRESENT=1
command -v setfacl >/dev/null 2>&1 || _GT_SETFACL_PRESENT=0
_GT_MISSING_PATHS=""

grant_traverse() {
    _gt_user="$1"; _gt_d="$2"; _gt_list=""
    while [ -n "$_gt_d" ] && [ "$_gt_d" != "/" ] && [ "$_gt_d" != "." ]; do
        _gt_list="$_gt_d
$_gt_list"
        _gt_d="$(dirname "$_gt_d")"
    done
    # Top-down, shallowest first: `test -x` on a directory fails for every
    # directory BELOW a closed one too, so a bottom-up walk granted the whole
    # chain (host8, 2026-09-18: three grants for one closed /media/<user>).
    # Granting the shallowest refusal first makes the deeper checks pass on
    # their own merits, so only the directories that actually refuse are
    # touched. Newline-separated: a path may contain a space.
    while IFS= read -r _gt_d; do
        [ -n "$_gt_d" ] || continue
        if [ -d "$_gt_d" ] && ! runuser -u "$_gt_user" -- test -x "$_gt_d" 2>/dev/null; then
            if [ "$_GT_SETFACL_PRESENT" = 1 ] && setfacl -m "u:$_gt_user:--x" "$_gt_d" 2>/dev/null; then
                echo "noo-apply: granted $_gt_user traverse (execute-only) on $_gt_d — a declared root lives below it"
            elif [ "$_GT_SETFACL_PRESENT" = 0 ]; then
                if ! printf '%s\n' "$_GT_MISSING_PATHS" | grep -qxF "$_gt_d"; then
                    _GT_MISSING_PATHS="${_GT_MISSING_PATHS:+$_GT_MISSING_PATHS
}$_gt_d"
                fi
            else
                echo "noo-apply: WARNING: $_gt_d is not traversable by $_gt_user and could not be granted (setfacl refused) — the agent cannot reach $2; fix on this host: setfacl -m u:$_gt_user:--x $_gt_d" >&2
            fi
        fi
    done <<GT_EOF
$_gt_list
GT_EOF
}

# Reports every path queued by a missing `setfacl` binary in ONE paragraph
# instead of once per path. No-op if nothing was queued (setfacl present,
# or nothing needed a grant). Call once, after all grant_traverse calls.
grant_traverse_flush_missing() {
    [ -z "$_GT_MISSING_PATHS" ] && return 0
    echo "noo-apply: WARNING: the acl package is not installed — \`sudo apt-get install -y acl\` then re-run \`noo cluster provision <node>\` from the controller, or restage with \`noo upgrade --nodes\`" >&2
    echo "noo-apply: WARNING: until then noo-agent cannot reach:" >&2
    printf '%s\n' "$_GT_MISSING_PATHS" | while IFS= read -r _gt_p; do
        [ -n "$_gt_p" ] || continue
        echo "noo-apply: WARNING:   $_gt_p" >&2
    done
}
# END grant_traverse

# BEGIN host_telemetry
# host-telemetry — switch off tailscaled's client-log upload on this node
# (docs/security/telemetry.md, "Host software"). Delivered ONLY by an
# operator's `noo cluster host-telemetry apply`: it restarts tailscaled, which
# drops the node's tailnet link for a few seconds, so nothing sends it
# unattended. Idempotent:
#   * /etc/noo/allow-tailscale-log-upload exists -> the operator opted in
#     (Tailscale support needs the logs); touch nothing.
#   * ensure TS_NO_LOGS_NO_SUPPORT=true in /etc/default/tailscaled;
#   * restart tailscaled ONLY if the file changed or the RUNNING process
#     lacks the switch (a file edited without a restart changes nothing);
#     a tailscaled that is not running is left stopped.
# The path/stub variables exist so tests/test_host_telemetry_applier.py can
# run this block against a temp tree.
HT_MARKER="${HT_MARKER:-/etc/noo/allow-tailscale-log-upload}"
HT_DEFAULTS="${HT_DEFAULTS:-/etc/default/tailscaled}"
HT_PROC="${HT_PROC:-/proc}"
HT_SYSTEMD="${HT_SYSTEMD:-/run/systemd/system}"
# yes | no | none (not running): does the running tailscaled carry the switch?
_ht_running_state() {
    _ht_pid="$(pidof tailscaled 2>/dev/null | awk '{print $1}')"
    [ -n "$_ht_pid" ] || { echo none; return 0; }
    if { tr '\0' '\n' < "$HT_PROC/$_ht_pid/cmdline" 2>/dev/null; tr '\0' '\n' < "$HT_PROC/$_ht_pid/environ" 2>/dev/null; } \
        | grep -qE '^(-{1,2}no-logs-no-support(=(true|1))?|TS_NO_LOGS_NO_SUPPORT=(true|1))$'; then
        echo yes
    else
        echo no
    fi
}
host_telemetry_apply() {
    if [ -e "$HT_MARKER" ]; then
        echo "host-telemetry: skipped - operator opt-in ($HT_MARKER exists); tailscaled left as it is"
        return 0
    fi
    if [ ! -d "$HT_SYSTEMD" ]; then
        echo "host-telemetry: skipped - no systemd on this node"
        return 0
    fi
    if ! command -v tailscaled >/dev/null 2>&1 && [ ! -e "$HT_DEFAULTS" ]; then
        echo "host-telemetry: skipped - tailscaled is not installed here"
        return 0
    fi
    _ht_changed=0
    if ! grep -qsE '^[^#]*(no-logs-no-support|TS_NO_LOGS_NO_SUPPORT=(true|1))' "$HT_DEFAULTS"; then
        mkdir -p "$(dirname "$HT_DEFAULTS")"
        # Never glue the new line onto an unterminated last line.
        if [ -s "$HT_DEFAULTS" ] && [ -n "$(tail -c1 "$HT_DEFAULTS")" ]; then echo >> "$HT_DEFAULTS"; fi
        echo 'TS_NO_LOGS_NO_SUPPORT=true' >> "$HT_DEFAULTS"
        _ht_changed=1
    fi
    _ht_state="$(_ht_running_state)"
    if [ "$_ht_state" = none ]; then
        _ht_msg="host-telemetry: tailscaled is not running; the switch is in $HT_DEFAULTS for its next start"
        [ "$_ht_changed" = 1 ] || _ht_msg="host-telemetry: already off (not running; $HT_DEFAULTS has the switch)"
        echo "$_ht_msg"
        return 0
    fi
    if [ "$_ht_changed" = 0 ] && [ "$_ht_state" = yes ]; then
        echo "host-telemetry: already off (no change, tailscaled not restarted)"
        return 0
    fi
    systemctl restart tailscaled || { echo "host-telemetry: systemctl restart tailscaled failed" >&2; return 1; }
    for _ht_i in 1 2 3 4 5 6 7 8 9 10; do
        systemctl is-active --quiet tailscaled && break
        sleep 2
    done
    systemctl is-active --quiet tailscaled || { echo "host-telemetry: tailscaled did not come back after the restart" >&2; return 1; }
    logger -t noo-apply "host-telemetry: tailscaled restarted with log upload off" 2>/dev/null || true
    echo "host-telemetry: tailscaled client log upload off (restarted)"
}
# Exactly one non-blank line, `NODE=<name>`, naming this node. Returns 65 for
# any other content (extra lines, a command, a path, a value), 76 for another
# node's name.
host_telemetry_payload_ok() {  # $1 = payload file, $2 = this node's id
    if [ "$(grep -c '[^[:space:]]' "$1")" != 1 ] || ! grep -qE '^NODE=[A-Za-z0-9._-]+$' "$1"; then
        echo "noo-apply: host-telemetry carries nothing but NODE=<name> - refusing a payload with anything else" >&2
        return 65
    fi
    _ht_want="$(sed -n 's/^NODE=//p' "$1")"
    if [ "$_ht_want" != "$2" ]; then
        echo "noo-apply: host-telemetry names '$_ht_want' but this node is '$2' - refusing" >&2
        return 76
    fi
}
# END host_telemetry

# ── agent secrets as FILES ─────────────────────────────
# The controller renders the agent env with plain values (and nats-creds /
# fleet-secrets merge plain lines into it). The agent itself reads each of
# AGENT_SECRET_KEYS as NAME_FILE > NOO_SECRET_NAME > NAME (node-agent-go
# internal/config/secretenv.go), so once the installed binary can, this
# applier moves every plain value into its own file — 0600, owned by the
# agent's user, under AGENT_SECRET_DIR — and leaves only a NAME_FILE pointer
# in the env. The values then live in one file each and nowhere else on
# disk; the process environment carries paths.
#
# The APPLIER decides, not the controller, and it decides from the binary
# that is installed when the bundle is done (grep for the capability marker
# the agent logs at startup — the agent is never executed to ask). That is
# what makes both roll orders safe with no pre-roll step:
#   * old agent, new applier: no marker → the env stays (or goes back to)
#     plain values, so an older binary never boots pointed at a file it
#     cannot read. A rollback that reinstalls an old agent through a bundle
#     inlines the files back here and removes them.
#   * new agent, old env: the reader falls through to the plain NAME; the
#     first bundle this applier sees converts it — every bundle, whether or
#     not it carries agent-env, so `noo upgrade --nodes` converts a node that
#     is never re-provisioned.
# The same block runs in provision --local's install script (provision.rs
# extracts it between the markers), so the controller's own node converts
# too. tests/test_agent_secret_files_applier.py drives it.
# BEGIN agent_secret_files
AGENT_SECRET_KEYS="NOO_NODE_AGENT_TOKEN NOO_CLUSTER_SECRET NATS_NODE_PASSWORD"
# Retired secrets an old env or backup may still hold in plain text: never
# moved into files (nothing reads them), only stripped from the backup.
# NATS_PASSWORD is the shared bus password an earlier change retired.
AGENT_RETIRED_SECRET_KEYS="NATS_PASSWORD"
AGENT_SECRET_CAPABILITY="noo-agent-reads-secret-files/1"
# The harness (the gateway binary's `harness` subcommand) reads
# its env the same way since an earlier change — gateway-rust/src/harness_main.rs
# HARNESS_SECRET_KEYS / HARNESS_SECRET_FILES_CAPABILITY. Its own list and
# marker: the harness binary is a different binary on its own roll.
HARNESS_SECRET_KEYS="NOO_NODE_AGENT_TOKEN NOO_CLUSTER_SECRET NATS_NODE_PASSWORD"
HARNESS_SECRET_CAPABILITY="noo-harness-reads-secret-files/1"

# _asf_value FILE KEY — the last `KEY=` assignment's value as systemd reads
# it: CR dropped, one pair of surrounding quotes removed.
_asf_value() {
    sed -n "s/^$2=//p" "$1" 2>/dev/null | tail -1 | tr -d '\015' \
        | sed -e 's/^"\(.*\)"$/\1/' -e "s/^'\\(.*\\)'\$/\\1/"
}

# agent_env_secret FILE KEY — KEY's value from an agent env, following a
# KEY_FILE pointer when there is one (the reader's order, for this root
# script's own consumers: the harness pair, the fetch report bearer).
agent_env_secret() {
    _aes_p="$(_asf_value "$1" "${2}_FILE")"
    if [ -n "$_aes_p" ]; then
        cat "$_aes_p" 2>/dev/null
        return 0
    fi
    _asf_value "$1" "$2"
}

# agent_secret_files ENV DIR AGENT_BIN OWNER [BACKUP] [KEYS] [MARKER]
# Converges ENV to pointers (AGENT_BIN carries MARKER) or to plain values
# (it does not). Sets ASF_CHANGED=1 when ENV was rewritten. KEYS / MARKER
# default to the agent's; the harness passes its own.
agent_secret_files() {
    _env="$1"; _dir="$2"; _bin="$3"; _own="$4"; _bak="${5:-}"
    _keys_list="${6:-$AGENT_SECRET_KEYS}"; _marker="${7:-$AGENT_SECRET_CAPABILITY}"
    ASF_CHANGED=0
    [ -f "$_env" ] || return 0
    if [ -f "$_bin" ] && grep -qaF "$_marker" "$_bin"; then
        _mode=files
    else
        _mode=env
    fi
    _grp="$(id -gn "$_own" 2>/dev/null || echo "$_own")"
    _tmp="$(mktemp)"
    chmod 600 "$_tmp"
    cp "$_env" "$_tmp"
    _moved=""
    for _k in $_keys_list; do
        _f="$_dir/$_k"
        _plain="$(_asf_value "$_tmp" "$_k")"
        _ptr="$(_asf_value "$_tmp" "${_k}_FILE")"
        if [ "$_mode" = files ]; then
            if [ -n "$_plain" ]; then
                # A plain value is the newest word (an agent-env or a merge
                # in THIS bundle wrote it): it replaces the file.
                # Every step checked by hand: this runs as `... || exit`,
                # where the shell's errexit does not reach inside.
                # The DIRECTORY is this (root) process's, group-readable by
                # the agent's group: the agent may read its files but never
                # create an entry here, so it cannot plant a link for root
                # to write through.
                if ! { install -d -m 750 -o "$(id -un)" -g "$_grp" "$_dir" \
                        && rm -f "$_f.next" \
                        && ( umask 077; printf '%s' "$_plain" > "$_f.next" ) \
                        && chown "$_own:$_grp" "$_f.next" \
                        && chmod 600 "$_f.next" \
                        && mv -f "$_f.next" "$_f"; }; then
                    echo "noo-apply: could not write $_f for $_own — leaving $_env as it was" >&2
                    rm -f "$_f.next" "$_tmp" "$_tmp.x"
                    return 73
                fi
                grep -vE "^(${_k}|${_k}_FILE)=" "$_tmp" > "$_tmp.x" || true
                printf '%s_FILE=%s\n' "$_k" "$_f" >> "$_tmp.x"
                mv -f "$_tmp.x" "$_tmp"
                _moved="$_moved $_k"
            elif [ -n "$_ptr" ]; then
                # Already a pointer. Drop an empty `KEY=` beside it so the
                # file never shows the reader a second, blank, opinion.
                grep -vE "^${_k}=\$" "$_tmp" > "$_tmp.x" || true
                mv -f "$_tmp.x" "$_tmp"
            else
                # Nothing configured: a file left from before is residue.
                rm -f "$_f"
            fi
        else
            if [ -n "$_ptr" ]; then
                _v="$_plain"
                if [ -z "$_v" ] && [ -r "$_ptr" ]; then
                    _v="$(cat "$_ptr")"
                fi
                [ -n "$_v" ] || echo "noo-apply: WARNING: $_k points at $_ptr, which is missing or empty — the installed agent will start without it; \`noo cluster provision <node>\` redelivers it" >&2
                case "$_v" in
                    *"
"*) echo "noo-apply: $_ptr holds more than one line — not inlining $_k into $_env" >&2; rm -f "$_tmp"; return 65 ;;
                esac
                grep -vE "^(${_k}|${_k}_FILE)=" "$_tmp" > "$_tmp.x" || true
                [ -n "$_v" ] && printf '%s=%s\n' "$_k" "$_v" >> "$_tmp.x"
                mv -f "$_tmp.x" "$_tmp"
                _moved="$_moved $_k"
            fi
        fi
    done
    if ! cmp -s "$_tmp" "$_env"; then
        grep -qE '^NODE_ID=.+' "$_tmp" || { echo "noo-apply: secret-file conversion lost NODE_ID — aborting" >&2; rm -f "$_tmp"; return 70; }
        if ! { cp "$_tmp" "$_env.next" && chmod 600 "$_env.next" && mv -f "$_env.next" "$_env"; }; then
            echo "noo-apply: could not rewrite $_env" >&2
            rm -f "$_tmp" "$_env.next"
            return 73
        fi
        ASF_CHANGED=1
        if [ "$_mode" = files ]; then
            echo "noo-apply: secrets in $_env moved to files under $_dir:$_moved"
        else
            echo "noo-apply: $_bin cannot read secret files — values inlined back into $_env:$_moved"
        fi
    fi
    rm -f "$_tmp"
    # Inlined (or never used): the files go only once the env no longer
    # points at them.
    if [ "$_mode" = env ]; then
        for _k in $_keys_list; do rm -f "$_dir/$_k"; done
        rmdir "$_dir" 2>/dev/null || true
    fi
    # The container-era capture beside the env (kept for diffing) held the
    # same values in plain text. Once they live in files, strip them there:
    # a secret left lying about in a backup is exactly what this removes.
    if [ "$_mode" = files ] && [ -n "$_bak" ] && [ -f "$_bak" ]; then
        _keys="$(printf '%s %s' "$_keys_list" "$AGENT_RETIRED_SECRET_KEYS" | tr ' ' '|')"
        if grep -qE "^($_keys)=" "$_bak"; then
            grep -vE "^($_keys)=" "$_bak" > "$_bak.next" || true
            chmod 600 "$_bak.next"
            mv -f "$_bak.next" "$_bak"
            echo "noo-apply: removed the agent's secret values from $_bak"
        fi
    fi
    return 0
}
# END agent_secret_files

# agent-env replaces /etc/noo-node-agent.env WHOLE, and the node's NATS pair
# is not an agent-env key: it arrives only as `nats-creds`. A bundle that
# carries agent-env WITHOUT nats-creds therefore used to drop the pair the
# node already held, and the agent came back with no bus credential while
# still registering over HTTP (the controller's local lane did exactly that).
# So the pair the installed env holds is carried into the new one, but only
# when it is THIS node's (NATS_NODE_USER = node-<NODE_ID>): a renamed node
# never inherits another principal's credential. A bundle that carries
# nats-creds replaces the pair below, as before.
# tests/test_apply_nats_pair_carry.py drives this block.
# BEGIN agent_env_nats_carry
# agent_env_carry_nats_pair NEW_ENV OLD_ENV NODE_ID — append OLD_ENV's pair
# lines (user, password or its _FILE pointer) to NEW_ENV, a staged copy.
agent_env_carry_nats_pair() {
    _cn_new="$1"; _cn_old="$2"; _cn_id="$3"
    [ -f "$_cn_old" ] || return 0
    _cn_user="$(sed -n 's/^NATS_NODE_USER=//p' "$_cn_old" | tail -1 | tr -d '\015"'"'")"
    if [ -z "$_cn_user" ]; then
        echo "noo-apply: NOTICE: this bundle carries no nats-creds and $_cn_old holds no NATS pair — the agent starts without a bus credential; \`noo cluster nats-creds rotate $_cn_id\` delivers one" >&2
        return 0
    fi
    if [ "$_cn_user" != "node-$_cn_id" ]; then
        echo "noo-apply: NOTICE: the NATS pair in $_cn_old belongs to '$_cn_user', not node-$_cn_id — not carried; \`noo cluster nats-creds rotate $_cn_id\` delivers this node's own" >&2
        return 0
    fi
    grep -vE '^(NATS_NODE_USER|NATS_NODE_PASSWORD|NATS_NODE_PASSWORD_FILE)=' "$_cn_new" > "$_cn_new.x" || true
    for _cn_k in NATS_NODE_USER NATS_NODE_PASSWORD NATS_NODE_PASSWORD_FILE; do
        grep -E "^${_cn_k}=" "$_cn_old" | tail -1 >> "$_cn_new.x" || true
    done
    mv -f "$_cn_new.x" "$_cn_new"
    echo "noo-apply: NOTICE: this bundle carries no nats-creds — kept this node's existing NATS pair ($_cn_user) from $_cn_old"
    return 0
}
# END agent_env_nats_carry

if [ -f "$WORK/files/agent-env" ]; then
    grep -qE '^NODE_ID=.+' "$WORK/files/agent-env" \
        || { echo "noo-apply: agent-env lacks NODE_ID — refusing a config that boots an anonymous agent" >&2; exit 65; }
    STAGED_ENV="$(mktemp)"
    chmod 600 "$STAGED_ENV"
    cp "$WORK/files/agent-env" "$STAGED_ENV"
    if [ ! -f "$WORK/files/nats-creds" ]; then
        agent_env_carry_nats_pair "$STAGED_ENV" /etc/noo-node-agent.env \
            "$(grep -E '^NODE_ID=' "$WORK/files/agent-env" | tail -1 | cut -d= -f2- | tr -d '[:space:]')"
    fi
    # STAGED_ENV is the FINAL content (payload plus any carried NATS pair),
    # so that is what is compared with the installed file.
    if config_unchanged "$STAGED_ENV" /etc/noo-node-agent.env 600 root:root; then
        ae_state="agent-env=unchanged"
    else
        install -m 600 -o root -g root "$STAGED_ENV" /etc/noo-node-agent.env
        ae_state="agent-env"; need_restart=1
    fi
    rm -f "$STAGED_ENV"
    # The roots the controller declared for this node: reachable by the
    # agent's user, or the agent reports the drive as missing.
    for _k in NOO_DATA_ROOT MODELS_DIR HF_CACHE_DIR; do
        _v="$(grep -E "^$_k=" "$WORK/files/agent-env" | tail -1 | cut -d= -f2-)"
        [ -n "$_v" ] && grant_traverse noo-agent "$_v"
    done
    grant_traverse_flush_missing
    applied="$applied $ae_state"
fi

# nats-creds — the node's OWN NATS credential. Applied AFTER
# agent-env deliberately: agent-env replaces /etc/noo-node-agent.env whole,
# so a bundle carrying both must end with the credential merged in, not
# overwritten by it.
#
# The payload names its node. A signed credential for node A must not be
# replayable onto node B — that is the whole point of per-principal users,
# and it is the same guard teardown uses. NODE_ID here is already resolved
# in the bundle-first order above, so an adopted name that differs from the
# hostname is honoured.
if [ -f "$WORK/files/nats-creds" ]; then
    want="$(grep -E '^NODE=' "$WORK/files/nats-creds" | head -1 | cut -d= -f2- | tr -d '[:space:]')"
    [ -n "$want" ] || { echo "noo-apply: nats-creds has no NODE= line — refusing an unbound credential" >&2; exit 65; }
    [ "$want" = "$NODE_ID" ] || { echo "noo-apply: nats-creds names '$want' but this node is '$NODE_ID' — refusing" >&2; exit 76; }
    grep -qE '^NATS_NODE_USER=.+' "$WORK/files/nats-creds" \
        || { echo "noo-apply: nats-creds lacks NATS_NODE_USER" >&2; exit 65; }
    grep -qE '^NATS_NODE_PASSWORD=.+' "$WORK/files/nats-creds" \
        || { echo "noo-apply: nats-creds lacks NATS_NODE_PASSWORD" >&2; exit 65; }
    AGENT_ENV=/etc/noo-node-agent.env
    [ -f "$AGENT_ENV" ] || { echo "noo-apply: $AGENT_ENV does not exist — provision this node before rotating its bus credential" >&2; exit 78; }
    TMPENV="$(mktemp)"
    chmod 600 "$TMPENV"
    grep -vE '^(NATS_NODE_USER|NATS_NODE_PASSWORD)=' "$AGENT_ENV" > "$TMPENV" || true
    grep -E '^(NATS_NODE_USER|NATS_NODE_PASSWORD)=' "$WORK/files/nats-creds" >> "$TMPENV"
    # Never leave the agent without its identity: the NODE_ID line that
    # agent-env is refused for lacking must survive this rewrite too.
    grep -qE '^NODE_ID=.+' "$TMPENV" || { echo "noo-apply: merge lost NODE_ID — aborting" >&2; rm -f "$TMPENV"; exit 70; }
    # The MERGED result is compared with the installed env, not the
    # fragment. The harness env below is judged the same way; the kind is
    # `unchanged` only when neither file needed rewriting.
    nc_changed=0
    if ! config_unchanged "$TMPENV" "$AGENT_ENV" 600 root:root; then
        install -m 600 -o root -g root "$TMPENV" "$AGENT_ENV"
        nc_changed=1; need_restart=1
    fi
    rm -f "$TMPENV"
    # The harness is the same principal on the bus: the same
    # pair, merged the same way, into its own env — when it already has one
    # on disk. A node with no installed harness env has no harness YET; if
    # this same bundle also carries harness-env (first harness install),
    # that block below reads this same $WORK/files/nats-creds directly, so
    # the pair still lands — see the harness-env block's comment.
    HARNESS_ENV=/etc/noo-harness.env
    if [ -f "$HARNESS_ENV" ]; then
        TMPH="$(mktemp)"; chmod 600 "$TMPH"
        grep -vE '^(NATS_NODE_USER|NATS_NODE_PASSWORD)=' "$HARNESS_ENV" > "$TMPH" || true
        grep -E '^(NATS_NODE_USER|NATS_NODE_PASSWORD)=' "$WORK/files/nats-creds" >> "$TMPH"
        grep -qE '^NODE_ID=.+' "$TMPH" || { echo "noo-apply: harness env merge lost NODE_ID — aborting" >&2; rm -f "$TMPH"; exit 70; }
        if ! config_unchanged "$TMPH" "$HARNESS_ENV" 600 root:root; then
            install -m 600 -o root -g root "$TMPH" "$HARNESS_ENV"
            nc_changed=1; need_harness_restart=1
        fi
        rm -f "$TMPH"
    fi
    if [ "$nc_changed" = 1 ]; then applied="$applied nats-creds"; else applied="$applied nats-creds=unchanged"; fi
fi

# fleet-secrets — the FLEET-WIDE credentials every node holds.
# Two since an earlier change retired the shared NATS_USER/NATS_PASSWORD pair — a
# node's bus credential is its own, and rides nats-creds above. Same shape as nats-creds directly above, and for the same
# reasons: a dotenv fragment MERGED into the agent env rather than an
# agent-env that replaces it whole. Replacing it whole is what made this a
# push-over-SSH command for so long — the controller cannot render a live
# node's env without also re-deciding its tier, data root and image tag
# from the controller's CURRENT defaults, which is a config change wearing
# a credential's clothes.
#
# The key allowlist below is load-bearing, not tidiness. This file is read
# by systemd as an EnvironmentFile for a root unit, so a fragment that
# could name ANY key could set PATH — the key greps are what keep a
# fleet-secrets payload from being an arbitrary-environment payload.
if [ -f "$WORK/files/fleet-secrets" ]; then
    FS_KEYS='NOO_CLUSTER_SECRET|NOO_NODE_AGENT_TOKEN'
    want="$(grep -E '^NODE=' "$WORK/files/fleet-secrets" | head -1 | cut -d= -f2- | tr -d '[:space:]')"
    [ -n "$want" ] || { echo "noo-apply: fleet-secrets has no NODE= line — refusing an unbound payload" >&2; exit 65; }
    [ "$want" = "$NODE_ID" ] || { echo "noo-apply: fleet-secrets names '$want' but this node is '$NODE_ID' — refusing" >&2; exit 76; }
    # Every non-comment, non-NODE line must be a fleet key, with a
    # non-empty value. A payload carrying anything else is refused whole
    # rather than silently filtered: a filter would apply the good half of
    # a bundle someone built wrong, and say it succeeded.
    if grep -vE "^(#|NODE=|($FS_KEYS)=.+$|\$)" "$WORK/files/fleet-secrets" | grep -q .; then
        echo "noo-apply: fleet-secrets carries a line that is not a fleet key with a value — refusing" >&2
        exit 65
    fi
    grep -qE "^($FS_KEYS)=.+" "$WORK/files/fleet-secrets" \
        || { echo "noo-apply: fleet-secrets names no fleet key — nothing to converge" >&2; exit 65; }
    AGENT_ENV=/etc/noo-node-agent.env
    [ -f "$AGENT_ENV" ] || { echo "noo-apply: $AGENT_ENV does not exist — provision this node before converging its credentials" >&2; exit 78; }
    TMPENV="$(mktemp)"
    chmod 600 "$TMPENV"
    # Drop only the keys this payload actually carries: a payload that
    # names one key must not blank the other.
    carried="$(grep -oE "^($FS_KEYS)=" "$WORK/files/fleet-secrets" | tr -d '=' | paste -sd'|' -)"
    grep -vE "^($carried)=" "$AGENT_ENV" > "$TMPENV" || true
    grep -E "^($FS_KEYS)=" "$WORK/files/fleet-secrets" >> "$TMPENV"
    grep -qE '^NODE_ID=.+' "$TMPENV" || { echo "noo-apply: merge lost NODE_ID — aborting" >&2; rm -f "$TMPENV"; exit 70; }
    # Merged result vs the installed env, like nats-creds above.
    fs_unchanged=0
    config_unchanged "$TMPENV" "$AGENT_ENV" 600 root:root && fs_unchanged=1
    if [ "$fs_unchanged" != 1 ]; then
        install -m 600 -o root -g root "$TMPENV" "$AGENT_ENV"
        need_restart=1
    fi
    rm -f "$TMPENV"
    applied="$applied fleet-secrets"
    # (the line above keeps its shape: tests/test_fleet_secret_declarations.py
    # lifts the merge up to it.) Unchanged is reported as its own token.
    [ "$fs_unchanged" != 1 ] || applied="${applied% fleet-secrets} fleet-secrets=unchanged"
fi

# agent-binary — staged then atomically moved, never written in place
if [ -f "$WORK/files/agent-binary" ]; then
    # An ELF for the wrong arch "installs" fine and dies at exec — check now.
    case "$(head -c 20 "$WORK/files/agent-binary" | od -An -tx1 | tr -d ' \n')" in
        7f454c46*) : ;;
        *) echo "noo-apply: agent-binary is not an ELF executable" >&2; exit 65 ;;
    esac
    if binary_unchanged "$WORK/files/agent-binary" /usr/local/bin/noo-node-agent; then
        applied="$applied agent-binary=unchanged"; note_binary_sha agent-binary "$WORK/files/agent-binary"
    else
        install -m 755 -o root -g root "$WORK/files/agent-binary" /usr/local/bin/noo-node-agent.next
        mv /usr/local/bin/noo-node-agent.next /usr/local/bin/noo-node-agent
        applied="$applied agent-binary"; need_restart=1; note_binary_sha agent-binary "$WORK/files/agent-binary"
    fi
fi

# cli-binary — the noo CLI for the node's user (an earlier change rail work:
# the controller is the update source; `noo upgrade --nodes` puts the
# release asset in every bundle). Installed into the user's ~/.local/bin,
# owned by them; no service restart involved.
if [ -f "$WORK/files/cli-binary" ] && [ -s "$WORK/files/cli-user" ]; then
    CLI_USER="$(tr -d ' \n\r' < "$WORK/files/cli-user")"
    case "$CLI_USER" in
        root|''|*[!a-z0-9_.-]*) echo "noo-apply: REFUSED — cli-user '$CLI_USER' is not an ordinary account name" >&2; exit 65 ;;
    esac
    CLI_HOME="$(getent passwd "$CLI_USER" | cut -d: -f6)"
    case "$(head -c 20 "$WORK/files/cli-binary" | od -An -tx1 | tr -d ' \n')" in
        7f454c46*) : ;;
        *) echo "noo-apply: cli-binary is not an ELF executable" >&2; exit 65 ;;
    esac
    # The installed CLI is hashed AS THE USER too (root must not follow a
    # symlink the user planted); any failure there leaves the hash empty and
    # the CLI is installed.
    _cli_cur=""
    if [ -n "$CLI_HOME" ] && [ -d "$CLI_HOME" ]; then
        _cli_cur="$(runuser -u "$CLI_USER" -- env HOME="$CLI_HOME" sh -c 'sha256sum "$HOME/.local/bin/noo" 2>/dev/null' | awk '{print $1}')" || _cli_cur=""
    fi
    _cli_new="$(sha256sum "$WORK/files/cli-binary" | awk '{print $1}')"
    if [ -n "$CLI_HOME" ] && [ -d "$CLI_HOME" ] && [ -n "$_cli_cur" ] && [ "$_cli_cur" = "$_cli_new" ]; then
        applied="$applied cli-binary=unchanged"; note_binary_sha cli-binary "$WORK/files/cli-binary"
    elif [ -n "$CLI_HOME" ] && [ -d "$CLI_HOME" ]; then
        # Written AS THE USER, never by root into a user-owned tree: root
        # following a symlink the user planted under ~/.local would write
        # (and chown) wherever it pointed ( second review, L4).
        runuser -u "$CLI_USER" -- env HOME="$CLI_HOME" sh -c '
            set -e
            mkdir -p "$HOME/.local/bin"
            cat > "$HOME/.local/bin/noo.next"
            chmod 755 "$HOME/.local/bin/noo.next"
            mv -f "$HOME/.local/bin/noo.next" "$HOME/.local/bin/noo"
            [ -e "$HOME/.local/bin/pai" ] || ln -s noo "$HOME/.local/bin/pai" 2>/dev/null || true
        ' < "$WORK/files/cli-binary" \
            || { echo "noo-apply: cli-binary install as $CLI_USER failed" >&2; exit 73; }
        applied="$applied cli-binary"; note_binary_sha cli-binary "$WORK/files/cli-binary"
    else
        echo "noo-apply: cli-user '$CLI_USER' has no home — CLI not installed" >&2
    fi
fi

# applier is handled in §1b (before the allowlist). Under NOO_APPLY_REEXEC
# this IS the freshly installed applier: count it, or an applier-only
# bundle ends in "contained nothing to apply" (exit 65) after a successful
# self-update — exactly what HOST3 hit on 2026-09-03.
if [ -f "$WORK/files/applier" ]; then
    applied="$applied applier"   # installed by §1b (re-exec) or already this version: a successful apply either way
fi

# fetcher — noo-fetch.sh itself rides the rail (2026-09-03): it is what
# reports apply outcomes back to the controller, so it must be updatable
# without an attended converge.
if [ -f "$WORK/files/fetcher" ]; then
    head -1 "$WORK/files/fetcher" | grep -q '^#!' \
        || { echo "noo-apply: fetcher payload has no shebang" >&2; exit 65; }
    grep -q 'noo-fetch' "$WORK/files/fetcher" \
        || { echo "noo-apply: fetcher payload does not look like noo-fetch" >&2; exit 65; }
    install -m 755 -o root -g root "$WORK/files/fetcher" /usr/local/bin/noo-fetch.next
    mv /usr/local/bin/noo-fetch.next /usr/local/bin/noo-fetch
    applied="$applied fetcher"
fi

# hostd-binary — upgrade the confined-root daemon over the rail.
# noo-apply is the right owner: hostd cannot swap its own running binary +
# unit, the agent is unprivileged, and this script already runs as root on
# both lanes. Keep .prev, install, let the binary re-render its own unit
# (`install --mode worker` does daemon-reload+enable+restart), then require
# a FRESH heartbeat that advertises swap-agent — i.e. the NEW binary is the
# one running. Failure restores .prev and exits nonzero so the lane reports.
if [ -f "$WORK/files/hostd-binary" ]; then
    case "$(head -c 20 "$WORK/files/hostd-binary" | od -An -tx1 | tr -d ' \n')" in
        7f454c46*) : ;;
        *) echo "noo-apply: hostd-binary is not an ELF executable" >&2; exit 65 ;;
    esac
    HOSTD=/usr/local/bin/noo-hostd
    HB=/var/lib/noo-node-agent/spool/hostd.heartbeat.json
    if binary_unchanged "$WORK/files/hostd-binary" "$HOSTD"; then
        # Same bytes as the running helper: nothing to swap, no `install`
        # (which restarts the unit), no heartbeat wait, no revert to arm.
        applied="$applied hostd-binary=unchanged"; note_binary_sha hostd-binary "$WORK/files/hostd-binary"
    else
        # Downgrade floor for the root helper ( review L3): never
        # replace an installed hostd with one of a lower generation marker.
        _hg_new="$(hostd_generation_of "$WORK/files/hostd-binary")"
        _hg_cur="$(hostd_generation_of "$HOSTD")"
        if [ "$_hg_new" -lt "$_hg_cur" ]; then
            echo "noo-apply: REFUSED — hostd-binary is generation $_hg_new, older than the installed one ($_hg_cur)" >&2
            logger -t noo-apply "REFUSED hostd-binary downgrade ($_hg_new < $_hg_cur)" 2>/dev/null || true
            exit 65
        fi
        [ -f "$HOSTD" ] && cp -f "$HOSTD" "$HOSTD.prev"
        install -m 755 -o root -g root "$WORK/files/hostd-binary" "$HOSTD.next"
        mv "$HOSTD.next" "$HOSTD"
        if ! "$HOSTD" install --mode worker >/dev/null 2>&1; then
            echo "noo-apply: new hostd failed to install — restoring previous" >&2
            [ -f "$HOSTD.prev" ] && { mv "$HOSTD.prev" "$HOSTD"; "$HOSTD" install --mode worker >/dev/null 2>&1 || true; }
            exit 65
        fi
        hostd_ok=0
        start_epoch=$(date +%s)
        for _ in $(seq 1 20); do
            if [ -f "$HB" ]; then
                hb_mtime=$(stat -c %Y "$HB" 2>/dev/null || echo 0)
                if [ "$hb_mtime" -ge "$start_epoch" ] && grep -q 'swap-agent' "$HB"; then
                    hostd_ok=1
                    break
                fi
            fi
            sleep 3
        done
        if [ "$hostd_ok" = 1 ]; then
            rm -f "$HOSTD.prev"
            applied="$applied hostd-binary"; note_binary_sha hostd-binary "$WORK/files/hostd-binary"
            logger -t noo-apply "hostd upgraded (fresh heartbeat from the new binary)" 2>/dev/null || true
        else
            echo "noo-apply: new hostd produced no fresh heartbeat in 60s — REVERTING" >&2
            [ -f "$HOSTD.prev" ] && { mv "$HOSTD.prev" "$HOSTD"; "$HOSTD" install --mode worker >/dev/null 2>&1 || true; }
            exit 65
        fi
    fi
fi

# restart-backends — recreate/restart node-side backend containers after a
# cert or config change (fu72 #3's missing half: the 2026-08-20 vLLM
# silent-plain-HTTP incident had NO rail-driven restart). Payload = one
# container name per line, noo- prefix + safe charset enforced.
if [ -f "$WORK/files/restart-backends" ]; then
    while IFS= read -r svc; do
        [ -n "$svc" ] || continue
        case "$svc" in
            noo-*) : ;;
            *) echo "noo-apply: restart-backends refused '$svc' (must be noo-*)" >&2; exit 65 ;;
        esac
        printf '%s' "$svc" | grep -qE '^[a-z0-9-]+$' \
            || { echo "noo-apply: restart-backends refused '$svc' (bad charset)" >&2; exit 65; }
        if docker restart -- "$svc" >/dev/null 2>&1; then
            logger -t noo-apply "restarted backend $svc" 2>/dev/null || true
        else
            echo "noo-apply: docker restart $svc failed (not running here?)" >&2
        fi
    done < "$WORK/files/restart-backends"
    applied="$applied restart-backends"
fi

# host-telemetry — see host_telemetry_apply above. A FIXED operation: the
# payload may carry NOTHING but the node's own name (`NODE=<name>`, the second
# lock beside the signed header). No script, command, path or value travels in
# it, so the kind cannot do more than set TS_NO_LOGS_NO_SUPPORT=true in
# /etc/default/tailscaled and restart tailscaled; anything else is refused.
if [ -f "$WORK/files/host-telemetry" ]; then
    host_telemetry_payload_ok "$WORK/files/host-telemetry" "$NODE_ID" || exit $?
    host_telemetry_apply || exit $?
    applied="$applied host-telemetry"
fi

# agent-unit — first install is what turns a prepped host into a NODE
if [ -f "$WORK/files/agent-unit" ]; then
    grep -q '^\[Service\]' "$WORK/files/agent-unit" \
        || { echo "noo-apply: agent-unit has no [Service] section" >&2; exit 65; }
    [ -f /etc/systemd/system/noo-node-agent.service ] || fresh_unit=1
    # Identical unit (bytes, 644, root:root): no rewrite, no daemon-reload,
    # no restart. A first install (no file) is never "unchanged".
    if config_unchanged "$WORK/files/agent-unit" /etc/systemd/system/noo-node-agent.service 644 root:root; then
        applied="$applied agent-unit=unchanged"
    else
        install -m 644 -o root -g root "$WORK/files/agent-unit" /etc/systemd/system/noo-node-agent.service
        applied="$applied agent-unit"; need_daemon_reload=1; need_restart=1
    fi
fi

# ── the harness: the loop beside this node's model, delivered
# like the agent and run as its own user. Three kinds; any subset may ride.
#
# harness-env — root-only, read by pid 1. Refused without NODE_ID for the
# same reason agent-env is.
#
# The rendered file may carry an empty NATS pair: the harness is the same
# bus principal as the node agent, so the controller does not
# always know a credential to render here. If the incoming file has no
# password, the pair is taken from, in order:
#   1. this bundle's OWN files/nats-creds, if present — the common first-
#      provision case, where a fresh rotation and the harness's first
#      install ride the same bundle. The nats-creds block above already
#      tried to merge into $HARNESS_ENV, but on a first harness install
#      that file does not exist yet at that point, so nothing landed there;
#      reading the bundle payload directly here is what actually closes it.
#      (Newcomer rehearsal 2026-09-28: without this, the harness installed
#      with NODE_ID and no password, connected to NATS anonymously, and
#      crash-looped on "authorization violation" until an operator ran
#      `noo cluster nats-creds rotate <node>` by hand.)
#   2. the existing /etc/noo-harness.env — an earlier nats-creds already
#      merged a pair in; a config refresh must not log the harness out.
#   3. /etc/noo-node-agent.env — same principal, so the agent's own pair is
#      a valid fallback when nothing harness-specific is on disk yet.
# Anonymous is never the fallback: better to keep whatever pair is
# reachable than boot a harness the bus will refuse.
if [ -f "$WORK/files/harness-env" ]; then
    grep -qE '^NODE_ID=.+' "$WORK/files/harness-env" \
        || { echo "noo-apply: harness-env lacks NODE_ID — refusing a config that boots an anonymous harness" >&2; exit 65; }
    HARNESS_ENV=/etc/noo-harness.env
    TMPH=""
    if grep -qE '^NATS_NODE_PASSWORD=.+' "$WORK/files/harness-env"; then
        HE_FINAL="$WORK/files/harness-env"
    else
        NATS_SRC=""
        if [ -f "$WORK/files/nats-creds" ] && grep -qE '^NATS_NODE_PASSWORD=.+' "$WORK/files/nats-creds"; then
            NATS_SRC="$WORK/files/nats-creds"
        elif [ -f "$HARNESS_ENV" ] && [ -n "$(agent_env_secret "$HARNESS_ENV" NATS_NODE_PASSWORD)" ]; then
            # Through a NATS_NODE_PASSWORD_FILE pointer too (an earlier change:
            # the harness env is converted like the agent's), in the same
            # $WORK shape as the agent fallback below.
            NATS_SRC="$WORK/harness-nats-pair"
            { grep -E '^NATS_NODE_USER=' "$HARNESS_ENV" | tail -1
              printf 'NATS_NODE_PASSWORD=%s\n' "$(agent_env_secret "$HARNESS_ENV" NATS_NODE_PASSWORD)"; } > "$NATS_SRC"
        elif [ -f /etc/noo-node-agent.env ] && [ -n "$(agent_env_secret /etc/noo-node-agent.env NATS_NODE_PASSWORD)" ]; then
            # The agent env may hold a NATS_NODE_PASSWORD_FILE pointer
            # (agent_secret_files): read through it, into $WORK (0700, gone
            # at exit), in the shape the lines below take.
            NATS_SRC="$WORK/agent-nats-pair"
            { grep -E '^NATS_NODE_USER=' /etc/noo-node-agent.env | tail -1
              printf 'NATS_NODE_PASSWORD=%s\n' "$(agent_env_secret /etc/noo-node-agent.env NATS_NODE_PASSWORD)"; } > "$NATS_SRC"
        fi
        TMPH="$(mktemp)"; chmod 600 "$TMPH"
        grep -vE '^(NATS_NODE_USER|NATS_NODE_PASSWORD)=' "$WORK/files/harness-env" > "$TMPH"
        [ -n "$NATS_SRC" ] && grep -E '^(NATS_NODE_USER|NATS_NODE_PASSWORD)=' "$NATS_SRC" >> "$TMPH"
        HE_FINAL="$TMPH"
        unset NATS_SRC
    fi
    # HE_FINAL is the FINAL content (payload, or payload plus the resolved
    # NATS pair); an identical installed env is left alone.
    if config_unchanged "$HE_FINAL" "$HARNESS_ENV" 600 root:root; then
        applied="$applied harness-env=unchanged"
    else
        install -m 600 -o root -g root "$HE_FINAL" "$HARNESS_ENV"
        applied="$applied harness-env"; need_harness_restart=1
    fi
    [ -z "$TMPH" ] || rm -f "$TMPH"
fi

# harness-binary — the gateway binary (the harness is its subcommand);
# staged then atomically moved, ELF-checked like agent-binary.
if [ -f "$WORK/files/harness-binary" ]; then
    case "$(head -c 20 "$WORK/files/harness-binary" | od -An -tx1 | tr -d ' \n')" in
        7f454c46*) : ;;
        *) echo "noo-apply: harness-binary is not an ELF executable" >&2; exit 65 ;;
    esac
    if binary_unchanged "$WORK/files/harness-binary" /usr/local/bin/noo-gateway; then
        applied="$applied harness-binary=unchanged"; note_binary_sha harness-binary "$WORK/files/harness-binary"
    else
        install -m 755 -o root -g root "$WORK/files/harness-binary" /usr/local/bin/noo-gateway.next
        mv /usr/local/bin/noo-gateway.next /usr/local/bin/noo-gateway
        applied="$applied harness-binary"; need_harness_restart=1; note_binary_sha harness-binary "$WORK/files/harness-binary"
    fi
fi

# harness-unit — first install creates the user. NO sudo grant: see below.
#
# The user: `noo-harness`, system, no login, primary group noo-agent so it
# can read the node's certificate and key (0640 root:noo-agent), and in NO
# other group — not docker, which is root on the host.
#
# The lifecycle used to be a sudoers drop-in letting noo-agent run
# `systemctl start|stop|restart noo-harness`. It COULD NOT WORK and is now
# removed, not merely unused: noo-node-agent.service runs with
# NoNewPrivileges=true, which makes setuid binaries
# inert, so sudo can never elevate whatever the drop-in says. host3 proved
# it on 2026-09-19 with sudo's own words. The agent now asks noo-hostd —
# already root on this node, already running systemctl for restart-agent —
# for the named ops `harness-start` / `harness-stop`, which take no unit
# name from the caller. Fewer grants after the fix than before.
#
# An existing drop-in from an earlier release is DELETED here, so a node
# that upgrades does not keep a standing root grant nothing uses.
#
# Installed, daemon-reloaded, NOT enabled: the agent's reconcile starts it
# when a placement says so, after a reboot too.
if [ -f "$WORK/files/harness-unit" ]; then
    grep -q '^\[Service\]' "$WORK/files/harness-unit" \
        || { echo "noo-apply: harness-unit has no [Service] section" >&2; exit 65; }
    grep -qE '^User=noo-harness$' "$WORK/files/harness-unit" \
        || { echo "noo-apply: harness-unit does not run as noo-harness — refusing" >&2; exit 65; }
    grep -qiE '^SupplementaryGroups=.*docker' "$WORK/files/harness-unit" \
        && { echo "noo-apply: harness-unit grants the docker group — refusing" >&2; exit 65; }
    getent group noo-agent >/dev/null || { echo "noo-apply: group noo-agent is missing — this host was not prepped as a node" >&2; exit 78; }
    id -u noo-harness >/dev/null 2>&1 \
        || useradd --system --shell /usr/sbin/nologin --no-create-home --gid noo-agent noo-harness
    # Never let an earlier hand-edit leave it in docker.
    if id -nG noo-harness | tr ' ' '\n' | grep -qx docker; then
        gpasswd -d noo-harness docker >/dev/null
    fi
    # Retire the grant that could never be used. Left behind it would be a
    # standing NOPASSWD root rule for a path nothing takes.
    rm -f /etc/sudoers.d/noo-harness-lifecycle /etc/sudoers.d/noo-harness-lifecycle.next
    # Identical unit (bytes, 644, root:root): no rewrite, no daemon-reload,
    # no harness restart. The user/group/sudoers hygiene above and below runs
    # either way.
    if config_unchanged "$WORK/files/harness-unit" /etc/systemd/system/noo-harness.service 644 root:root; then
        applied="$applied harness-unit=unchanged"
    else
        install -m 644 -o root -g root "$WORK/files/harness-unit" /etc/systemd/system/noo-harness.service
        applied="$applied harness-unit"; need_daemon_reload=1; need_harness_restart=1
    fi
fi

[ -n "$applied" ] || { echo "noo-apply: signed bundle contained nothing to apply" >&2; exit 65; }

# Last env write of this apply: every merge above wrote plain lines, and the
# agent binary (if this bundle carried one) is installed — see
# agent_secret_files. The owner is the unit's User= (provision --local falls
# back to root on a host with no noo-agent user).
ASF_OWNER="$(sed -n 's/^User=//p' /etc/systemd/system/noo-node-agent.service 2>/dev/null | tail -1)"
{ [ -n "$ASF_OWNER" ] && id -u "$ASF_OWNER" >/dev/null 2>&1; } || ASF_OWNER=root
agent_secret_files /etc/noo-node-agent.env /etc/noo/agent-secrets /usr/local/bin/noo-node-agent \
    "$ASF_OWNER" /etc/noo-node-agent.env.container-backup || exit $?
if [ "$ASF_CHANGED" = 1 ]; then need_restart=1; fi
# The harness env, the same way: its binary is the gateway,
# judged by its OWN marker, and its files are the noo-harness user's under
# their own directory — the agent's are 0600 to noo-agent, which the harness
# cannot read. No noo-harness user means no harness can run here: nothing to
# convert. Both roll orders are safe for the same reasons as the agent's.
if [ -f /etc/noo-harness.env ] && id -u noo-harness >/dev/null 2>&1; then
    agent_secret_files /etc/noo-harness.env /etc/noo/harness-secrets /usr/local/bin/noo-gateway \
        noo-harness "" "$HARNESS_SECRET_KEYS" "$HARNESS_SECRET_CAPABILITY" || exit $?
    if [ "$ASF_CHANGED" = 1 ]; then need_harness_restart=1; fi
fi
logger -t noo-apply "applied:$applied (node=$NODE_ID, verified-by=$SIG_VIA)" 2>/dev/null || true
echo "applied:$applied"
echo "verified-by: $SIG_VIA"
# The CA-signed compatibility arm is gone. Printed so an
# operator reading the controller's copy of this report (`noo cluster
# provision <node> --wait`) sees the lane's state from the applier itself.
echo "ca-lane: retired"


# ── 4. Orchestrate — the agent must LOAD what changed ─────
[ "$need_daemon_reload" = 1 ] && systemctl daemon-reload
# The harness is restarted only if it is RUNNING: a placement the agent has
# not made (or has withdrawn) must not be started by a config refresh.
if [ "${need_harness_restart:-0}" = 1 ] && systemctl is-active --quiet noo-harness 2>/dev/null; then
    systemctl restart noo-harness
    applied="$applied (harness restarted)"
fi
if [ "$fresh_unit" = 1 ]; then
    # First install on this host: the old containerised agent may still hold
    # :8081, and a unit that cannot bind restarts forever while the container
    # keeps serving — the cutover failure the ansible task documents. Stop it
    # first, then enable --now.
    docker stop noo-node-agent >/dev/null 2>&1 || true
    docker update --restart=no noo-node-agent >/dev/null 2>&1 || true
    systemctl enable --now noo-node-agent
    # Poll: a fresh agent needs several seconds to connect NATS, complete
    # the mTLS handshake, and register — "activating" is normal mid-startup,
    # not a failure. A single 3s is-active false-failed a healthy birth.
    for _ in $(seq 1 20); do
        systemctl is-active --quiet noo-node-agent && break
        sleep 2
    done
    systemctl is-active noo-node-agent
elif [ "$need_restart" = 1 ]; then
    systemctl restart noo-node-agent
    # Poll: a fresh agent needs several seconds to connect NATS, complete
    # the mTLS handshake, and register — "activating" is normal mid-startup,
    # not a failure. A single 3s is-active false-failed a healthy birth.
    for _ in $(seq 1 20); do
        systemctl is-active --quiet noo-node-agent && break
        sleep 2
    done
    systemctl is-active noo-node-agent
else
    echo "no service-affecting kinds — agent left as-is"
fi

# ── 5. Companions ride the new agent binary (replaces hostd's swap-time restart)
# A sensor companion (the compose `sensors` profile, `<prefix>-node-agent-sensors`)
# may bind-mount the HOST agent binary; the rail just replaced that file, so the
# container needs a restart to run it. What is restarted is decided HERE, from
# this host, never from the bundle: a container qualifies only if its name has
# the shipped shape AND it bind-mounts /usr/local/bin/noo-node-agent. If the
# root-owned noo-hostd unit still declares NOO_HOSTD_COMPANION_CONTAINERS (the
# old swap path's list), only those names are considered — each still held to
# the same shape and mount test. A restart failure does not fail the apply (the
# host agent is healthy); it is loud, and `noo cluster verify`'s `companions`
# row shows the skew.
# BEGIN companion_restart
COMPANION_SHAPE='^[a-z0-9][a-z0-9_.-]*-node-agent-sensors$'
companion_restart() {
    command -v docker >/dev/null 2>&1 || return 0
    _declared="$(systemctl show -p Environment --value noo-hostd 2>/dev/null | tr ' ' '\n' \
        | sed -n 's/^NOO_HOSTD_COMPANION_CONTAINERS=//p' | tr ',' ' ')"
    if [ -n "$_declared" ]; then
        _cands="$_declared"
    else
        _cands="$(docker ps -a --format '{{.Names}}' 2>/dev/null || true)"
    fi
    for _c in $_cands; do
        printf '%s\n' "$_c" | grep -qE "$COMPANION_SHAPE" || continue
        docker inspect -f '{{range .Mounts}}{{.Source}}{{"\n"}}{{end}}' "$_c" 2>/dev/null \
            | grep -qx '/usr/local/bin/noo-node-agent' || continue
        if docker restart "$_c" >/dev/null 2>&1; then
            echo "companion: $_c restarted onto the new agent binary"
            logger -t noo-apply "companion $_c restarted onto the new agent binary" 2>/dev/null || true
        else
            echo "noo-apply: ALERT — companion $_c did not restart; it runs the PREVIOUS agent binary until restarted" >&2
            logger -t noo-apply "ALERT companion $_c restart failed (version skew)" 2>/dev/null || true
        fi
    done
    return 0
}
# END companion_restart
case " $applied " in
    *" agent-binary "*) companion_restart ;;
esac
# Last line of the apply, so the fetcher's tail of this log always carries it.
[ -z "$binary_shas" ] || echo "binary-sha:$binary_shas"
