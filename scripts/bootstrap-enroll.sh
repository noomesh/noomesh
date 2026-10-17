#!/bin/sh
# SPDX-License-Identifier: AGPL-3.0-only
# Copyright 2026 PersonifAI LLC

# Mesh - Bootstrap-token host enrollment
#
# Served by the gateway at GET /bootstrap. The cluster operator mints a
# single-use token with `noo cluster bootstrap-token create`, which prints
# the exact one-liner to run here:
#
#   curl -fsSL https://<controller>:8080/bootstrap | \
#       TOKEN=<token> NOO_URL=https://<controller>:8080 sh
#
# What it does:
#   1. POSTs the token to $NOO_URL/api/cluster/bootstrap
#   2. Prints the `noo cluster provision` next step for the operator
#
# It no longer installs an SSH key or a sudoers drop-in. A node ends with
# ZERO entries in /etc/sudoers.d and no controller key in authorized_keys:
# the controller reaches it over the mesh, and everything privileged on the
# node goes through noo-hostd's fixed op table (2026-09-05).
#
# Dependency-light on purpose: POSIX sh + curl. No jq — the two fields it
# extracts (an OpenSSH public key and a URL) never contain quotes or
# backslashes, so a sed capture is exact.
#
# The token is single-use and burns on this request. If anything below the
# POST fails, mint a new token and re-run.

set -eu

TOKEN="${TOKEN:-}"
NOO_URL="${NOO_URL:-}"

if [ -z "$TOKEN" ] || [ -z "$NOO_URL" ]; then
    echo "ERROR: TOKEN and NOO_URL must be set, e.g.:" >&2
    echo "  curl -fsSL <url>/bootstrap | TOKEN=<token> NOO_URL=<url> sh" >&2
    echo "(ask your cluster operator for the exact one-liner)" >&2
    exit 1
fi
NOO_URL="${NOO_URL%/}"

if ! command -v curl >/dev/null 2>&1; then
    echo "ERROR: curl is required" >&2
    exit 1
fi

# TLS: verified by default. NOO_BOOTSTRAP_INSECURE=1 is for a node that does
# not yet trust the cluster CA (the controller's certificate chains to it).
# The ONLY unverified request this script ever makes is the fetch of the CA
# certificate itself (a public document); its DER sha256 is then checked
# against the pin in the paste (NOO_CA_SHA256) and every later request —
# the token POST, the prep script that runs as root — is verified against
# THAT CA with --cacert. Nothing that carries the token or runs as root is
# ever fetched with -k (tests/test_prep_tofu_is_pinned.py enforces it).
CURL_OPTS="-fsS"
BOOT_CA=""
if [ "${NOO_BOOTSTRAP_INSECURE:-0}" = "1" ]; then
    # The fingerprint is REQUIRED here, not merely preferred (§3f R25).
    # Without it an unverified first contact is blind trust-on-first-use:
    # whoever answers becomes this node's certificate authority, and the
    # prep script and tooling that follow come from them. "WARNING" is
    # not a control; refusing is.
    if [ -z "${NOO_CA_SHA256:-}" ]; then
        echo "ERROR: NOO_BOOTSTRAP_INSECURE=1 without NOO_CA_SHA256." >&2
        echo "       There would be nothing to verify the cluster CA against, so a" >&2
        echo "       man-in-the-middle could substitute their own anchor and the" >&2
        echo "       root prep script. Re-mint the enrollment paste on the controller" >&2
        echo "       (noo cluster provision <node>) — it always carries the pin." >&2
        exit 1
    fi
    if ! command -v openssl >/dev/null 2>&1 || ! command -v sha256sum >/dev/null 2>&1; then
        echo "ERROR: NOO_BOOTSTRAP_INSECURE=1 needs openssl and sha256sum to check the CA pin." >&2
        exit 1
    fi
    BOOT_CA="$(mktemp)"
    # shellcheck disable=SC2064 # expand now: the path is fixed
    trap "rm -f '$BOOT_CA'" EXIT
    if ! curl -fsSk "$NOO_URL/bootstrap/ca.crt" -o "$BOOT_CA" || ! grep -q "BEGIN CERTIFICATE" "$BOOT_CA"; then
        echo "ERROR: could not fetch the cluster CA certificate from $NOO_URL/bootstrap/ca.crt." >&2
        exit 1
    fi
    BOOT_FP="$(openssl x509 -in "$BOOT_CA" -outform DER 2>/dev/null | sha256sum | cut -d' ' -f1)"
    if [ "$BOOT_FP" != "$NOO_CA_SHA256" ]; then
        echo "ERROR: cluster CA fingerprint MISMATCH (expected $NOO_CA_SHA256, got ${BOOT_FP:-none}) —" >&2
        echo "       whatever answered is not this mesh's controller (or the paste is stale)." >&2
        echo "       Nothing was sent: the token is NOT burned. Not proceeding." >&2
        exit 1
    fi
    echo "note: the cluster CA was fetched before it was trusted and VERIFIED against the" >&2
    echo "      paste's fingerprint pin; every request after this one is TLS-verified against it." >&2
    CURL_OPTS="-fsS --cacert $BOOT_CA"
fi

# ── Foreign-mesh guard (second-controller hardening, 2026-08-19) ────────────
# A node belongs to ONE mesh, anchored by the birth-TOFU CA: noo-apply refuses
# bundles from any other CA, so a second controller "registering" this node
# would only half-work (gate key pinned, provisioning refused) — the worst
# state. Refuse BEFORE burning the token when the machine is already enrolled
# in a mesh whose CA differs from the enrolling controller's. The anchor is
# root-readable only, hence sudo (this flow prompts for sudo anyway).
# NOTE: the unified paste runs `tailscale up` BEFORE this script, so a
# wrong-controller paste may already have SWITCHED tailnets — the message
# says so, because that breaks the node's connectivity to its real mesh.
if [ -x /usr/local/bin/noo-apply ] && sudo test -f /etc/noo/pki/ca.crt; then
    NEW_CA="$(mktemp)"
    if curl $CURL_OPTS "$NOO_URL/bootstrap/ca.crt" -o "$NEW_CA" \
        && grep -q "BEGIN CERTIFICATE" "$NEW_CA"; then
        # The fetched anchor is checked against the paste's pin BEFORE it is
        # used to verify anything else (the deenroll fetch advised below):
        # on the -k transport the pin is the only thing that makes the
        # bytes trustworthy, the same rule prep-host applies to the anchor
        # it installs.
        if [ -n "${NOO_CA_SHA256:-}" ]; then
            GOT_FP="$(openssl x509 -in "$NEW_CA" -outform DER 2>/dev/null | sha256sum | cut -d' ' -f1)"
            if [ "$GOT_FP" != "$NOO_CA_SHA256" ]; then
                rm -f "$NEW_CA"
                echo "ERROR: cluster CA fingerprint MISMATCH (expected $NOO_CA_SHA256, got $GOT_FP) — possible transport tamper; not proceeding" >&2
                exit 1
            fi
        fi
        if ! sudo cmp -s /etc/noo/pki/ca.crt "$NEW_CA"; then
            # Keep the verified anchor: the advice below pins to it. Its
            # name is stable so the printed command can be pasted.
            PINNED_CA="/tmp/noo-new-mesh-ca.crt"
            mv "$NEW_CA" "$PINNED_CA" 2>/dev/null || PINNED_CA="$NEW_CA"
            echo "ERROR: this machine is already enrolled in a DIFFERENT mesh" >&2
            echo "       (its CA anchor does not match $NOO_URL's)." >&2
            echo "  To move it: tear it down from ITS controller first" >&2
            echo "  (noo cluster teardown-node <name> --factory), then re-run this paste." >&2
            echo "  If that controller NO LONGER EXISTS (offboarded before this node" >&2
            echo "  collected its teardown — the orphan case), purge the" >&2
            echo "  dead mesh locally and re-run this paste:" >&2
            echo "    curl -fsS --cacert $PINNED_CA $NOO_URL/bootstrap/deenroll -o /tmp/noo-deenroll" >&2
            echo "    sudo sh /tmp/noo-deenroll" >&2
            echo "  ($PINNED_CA is $NOO_URL's CA, verified against this paste's pin;" >&2
            echo "   never fetch the purge script with -k.)" >&2
            echo "  NOTE: if this paste included a tailscale join, the node may have just" >&2
            echo "        switched tailnets — rejoin the original tailnet to restore its mesh." >&2
            exit 78
        fi
    fi
    rm -f "$NEW_CA"
fi

echo "Enrolling with $NOO_URL ..."
# hostname + user ride the redemption (migration 052): a name-bound token is
# checked against the hostname BEFORE burning, and the enrolling account is
# recorded so provision-node can build the inventory entry without a human.
ENROLL_USER="$(id -un)"
THIS_HOSTNAME="$(hostname)"

# --- Birth keypair + machine facts --
# Generated BEFORE the redeem so the cert can ride the same single-use POST.
# The controller encrypts this node's provisioning bundle to this cert; the
# private key never leaves the machine (prep installs it root-only at
# /etc/noo/birth.key and this script shreds the originals). Facts let
# `noo cluster provision` derive tier + binary arch with no SSH probe.
BIRTH_DIR=""
BIRTH_CERT_JSON=""
FACTS_JSON=""
if command -v openssl >/dev/null 2>&1; then
    BIRTH_DIR="$(mktemp -d)"
    chmod 700 "$BIRTH_DIR"
    if openssl req -x509 -newkey rsa:4096 -nodes -sha256 -days 3650 \
        -keyout "$BIRTH_DIR/birth.key" -out "$BIRTH_DIR/birth.crt" \
        -subj "/CN=noo-birth-$THIS_HOSTNAME" >/dev/null 2>&1; then
        # JSON-escape the PEM (newlines -> \n) without jq.
        BIRTH_CERT_JSON="$(awk 'NR>1{printf "\\n"} {printf "%s", $0}' "$BIRTH_DIR/birth.crt")"
    else
        rm -rf "$BIRTH_DIR"; BIRTH_DIR=""
        echo "WARNING: birth keypair generation failed — pull provisioning unavailable (push lane still works)" >&2
    fi
else
    echo "WARNING: openssl not found — pull provisioning unavailable (push lane still works)" >&2
fi
F_ARCH="$(uname -m)"
F_MODEL=""
[ -r /proc/device-tree/model ] && F_MODEL="$(tr -d '\0' < /proc/device-tree/model 2>/dev/null)"
[ -z "$F_MODEL" ] && [ -r /sys/class/dmi/id/product_name ] && F_MODEL="$(cat /sys/class/dmi/id/product_name 2>/dev/null)"
F_GPU=0
{ [ -e /dev/nvidia0 ] || (command -v lspci >/dev/null 2>&1 && lspci 2>/dev/null | grep -qi nvidia); } && F_GPU=1
F_MODEL_ESC="$(printf '%s' "$F_MODEL" | tr -d '"\\')"
# i11a: what tells this machine apart from another with the same hostname
# (the controller refuses a node name held by a different machine). Same
# derivation as `noo enroll`: sha256 of a domain prefix + the machine id;
# the raw id never leaves the box.
F_MACHINE_FP=""
for _mid in /etc/machine-id /var/lib/dbus/machine-id; do
    if [ -s "$_mid" ] && command -v sha256sum >/dev/null 2>&1; then
        F_MACHINE_FP="$(printf 'noomesh-machine:%s' "$(tr -d '[:space:]' < "$_mid")" | sha256sum | cut -d' ' -f1)"
        break
    fi
done
FACTS_JSON="{\"arch\":\"$F_ARCH\",\"model\":\"$F_MODEL_ESC\",\"gpu_present\":$F_GPU,\"data_root\":\"${PREP_DATA_ROOT:-/var/lib/noo}\",\"machine_fp\":\"$F_MACHINE_FP\"}"

# The node's tailnet IP, self-reported: the gateway
# container only sees the docker bridge as the peer (172.18.0.1 = the
# controller itself), which poisoned the inventory address AND broke
# --factory's tailnet-device deletion (matches by recorded IP). The node
# is the authority on its own reachable address.
NODE_TAILNET_IP="$(tailscale ip -4 2>/dev/null | head -1)" || NODE_TAILNET_IP=""
BODY="{\"token\":\"$TOKEN\",\"hostname\":\"$THIS_HOSTNAME\",\"enroll_user\":\"$ENROLL_USER\",\"facts\":$FACTS_JSON"
[ -n "$NODE_TAILNET_IP" ] && BODY="$BODY,\"tailnet_ip\":\"$NODE_TAILNET_IP\""
[ -n "$BIRTH_CERT_JSON" ] && BODY="$BODY,\"birth_cert\":\"$BIRTH_CERT_JSON\""
BODY="$BODY}"
RESP="$(curl $CURL_OPTS -X POST "$NOO_URL/api/cluster/bootstrap" \
    -H 'Content-Type: application/json' \
    -d "$BODY")" || {
    echo "ERROR: enrollment was rejected or the controller is unreachable." >&2
    echo "Tokens are single-use and expire — ask the operator for a fresh" >&2
    echo "one-liner (noo cluster bootstrap-token create)." >&2
    exit 1
}

CONTROLLER_URL="$(printf '%s' "$RESP" | sed -n 's/.*"controller_url": *"\([^"]*\)".*/\1/p')"
ROLE_HINT="$(printf '%s' "$RESP" | sed -n 's/.*"role_hint": *"\([^"]*\)".*/\1/p')"
BOUND_NODE="$(printf '%s' "$RESP" | sed -n 's/.*"node_name": *"\([^"]*\)".*/\1/p')"

# --- Step 1: no controller SSH key ---
#
# This installed the controller's public key into ~/.ssh/authorized_keys,
# pinned to `command="/usr/local/bin/noo-gate",restrict` so it granted verbs
# rather than a shell. That was the right shape for a lane that existed; the
# lane is retired (2026-09-05) and noo-gate is no longer installed, so a
# pinned key would authorize a forced command that is not there.
#
# The controller reaches a node over the mesh — the node-agent's mTLS API and
# the NATS dispatch rail — and delivers content as CA-signed bundles the node
# collects itself. None of that needs a key here.
#
# The response's ssh_public_key field is ignored rather than removed: an
# older controller still sends it, and enrollment should not fail on a field
# it no longer uses.


# --- Step 2: no sudoers drop-in ---
#
# This wrote /etc/sudoers.d/noo-cluster, a narrow passwordless grant for
# `systemctl restart noo-node-agent`. Its comment named the one unattended
# consumer honestly: "the cluster executor's node-agent revive" — which is
# an SSH path, and SSH is retired (2026-09-05).
#
# Nothing replaced it, because nothing needed to. noo-hostd already has a
# `restart-agent` op in its fixed worker table, reachable by writing a spool
# file rather than by holding a standing grant, and the agent's unit now
# restarts itself without a terminal failure state at all.
#
# A node should end with ZERO drop-ins in /etc/sudoers.d. prep-host removes
# noo-cluster (and noo-apply, and the pai-* ancestors) on every run, so a
# node enrolled before this converges the next time it is prepped.


# --- Step 3: ROOT host prep ---
#
# This is the "escalate once" moment: the operator is at
# this host, sudo is warm from step 2, and the machine gets FULLY prepared —
# docker, GPU toolkit, journald cap, data dirs, the noo-agent account, the
# /etc/noo/pki skeleton. Everything the setup playbooks used to need broad
# sudo for happens here instead, so the standing grant can stay at the one
# revive verb. Skippable (NOO_BOOTSTRAP_SKIP_PREP=1) for hosts prepared some
# other way; the prep script itself is idempotent.
if [ "${NOO_BOOTSTRAP_SKIP_PREP:-0}" != "1" ] && command -v sudo >/dev/null 2>&1; then
    PREP_TMP="$(mktemp)"
    if curl $CURL_OPTS "$NOO_URL/bootstrap/prep" -o "$PREP_TMP"; then
        # Host part of NOO_URL, for the noo-controller /etc/hosts mapping.
        CTL_HOST="$(printf '%s' "$NOO_URL" | sed -e 's#^https\{0,1\}://##' -e 's#[:/].*$##')"
        echo "* Running root host prep (one sudo, prepares the whole machine) ..."
        sudo env PREP_ENROLL_USER="$ENROLL_USER" PREP_CONTROLLER_IP="$CTL_HOST" \
            PREP_NOO_URL="$NOO_URL" PREP_INSECURE="${NOO_BOOTSTRAP_INSECURE:-0}" \
            PREP_CA_SHA256="${NOO_CA_SHA256:-}" \
            PREP_NODE_NAME="${BOUND_NODE:-$THIS_HOSTNAME}" \
            PREP_BIRTH_KEY="${BIRTH_DIR:+$BIRTH_DIR/birth.key}" \
            PREP_BIRTH_CRT="${BIRTH_DIR:+$BIRTH_DIR/birth.crt}" \
            bash "$PREP_TMP" || {
            echo "WARNING: host prep failed — enrollment stands, but run it before provisioning:" >&2
            if sudo test -f /etc/noo/pki/ca.crt; then
                # The anchor is installed: pin the fetch to it.
                echo "  curl -fsS --cacert /etc/noo/pki/ca.crt $NOO_URL/bootstrap/prep -o /tmp/noo-prep \\" >&2
                echo "    && sudo env PREP_NOO_URL=$NOO_URL PREP_CA_SHA256=${NOO_CA_SHA256:-} bash /tmp/noo-prep" >&2
            else
                # No anchor yet: only the paste carries the pin that makes a
                # first-contact fetch safe, so the answer is the paste again.
                echo "  re-run this enrollment paste (it carries the CA pin). Never fetch" >&2
                echo "  the prep script over an unverified transport and pipe it to sudo:" >&2
                echo "  whatever answered would become this node's certificate authority for life." >&2
            fi
        }
    else
        echo "WARNING: could not fetch $NOO_URL/bootstrap/prep (older controller?) — host prep skipped" >&2
    fi
    rm -f "$PREP_TMP"
fi

# --- Summary ---
THIS_IP="$(hostname -I 2>/dev/null | awk '{print $1}')" || THIS_IP=""
echo ""
echo "Bootstrap enrollment complete."
[ -n "$ROLE_HINT" ] && echo "Suggested role: $ROLE_HINT"
# The root copies live at /etc/noo/birth.{key,crt}; the user-owned originals
# must not linger in tmp.
if [ -n "$BIRTH_DIR" ]; then
    shred -u "$BIRTH_DIR/birth.key" 2>/dev/null || rm -f "$BIRTH_DIR/birth.key"
    rm -rf "$BIRTH_DIR"
fi

echo ""
echo "On the controller, finish provisioning with:"
echo ""
echo "  noo cluster provision ${BOUND_NODE:-$THIS_HOSTNAME}    # stages an encrypted bundle; this node pulls it"
echo ""
# #49: the response's controller_url is the CONTROLLER's own view (a
# standalone box says https://localhost:8080) — the URL this node just
# enrolled through is the truthful one to echo.
echo "(controller: ${NOO_URL:-$CONTROLLER_URL})"
