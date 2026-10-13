#!/bin/bash
# SPDX-License-Identifier: AGPL-3.0-only
# Copyright 2026 PersonifAI LLC

# Mesh — one-shot ROOT host preparation.
#
# Served by the gateway at GET /bootstrap/prep and run BY bootstrap-enroll.sh
# under the operator's single attended sudo — the one sanctioned escalation
# moment a node's life has ("escalate once, then de-escalate for life"). It
# does everything the setup-*-worker playbooks used to do as root, so that
# after enrollment the machine is fully prepared and no standing sudo grant
# broader than the revive verb ever needs to exist.
#
# This is a deliberate SHELL PORT of the ansible root tasks, and the
# hard-won fixes came with it — do not "simplify" these away:
#
#   * nvidia-persistenced: Debian/Ubuntu ship the unit with NO [Install]
#     section (static — `systemctl enable` refuses it) AND with
#     `--no-persistence-mode` in ExecStart. The old play "enabled" it with
#     errors sent to /dev/null and `|| true`, reported success for weeks,
#     and host8 served inference CPU-only on an RTX 3060. The drop-in
#     below fixes both, and verification asks the DRIVER, not systemd.
#   * docker default-runtime=nvidia is edited into daemon.json via python
#     json, not sed — the file may or may not exist, may or may not have
#     other keys.
#   * data-root detection prefers the largest non-root filesystem >10GB the
#     data-root policy accepts (else /var/lib/noo) and
#     records its choice in the marker file, so later tooling reads the
#     DECISION rather than re-deriving (and possibly diverging from) it.
#
# Idempotent: safe to re-run; each section checks state first.
#
# Inputs (env):
#   PREP_ENROLL_USER    the human account on this node (default: SUDO_USER)
#   PREP_CONTROLLER_IP  IP to map to `noo-controller` in /etc/hosts (optional)
#   NOO_DATA_ROOT       override the detected data root (optional)
#   PREP_CHECK=1        preflight only: unprivileged, changes nothing, exits 1
#                       if prep would fail (see "Check mode" below)
#   OS_RELEASE_FILE     os-release path (default /etc/os-release; for tests)
set -eu

# ── Platform resolution ────────────────────────────────────────────────────
# Prep names the distro family and release codename ITSELF and writes the
# Docker apt source from them; it never lets get.docker.com guess.
# Incident, 2026-10-10: a fresh Pop!_OS 24.04 box (ID=pop, ID_LIKE="ubuntu
# debian") is not an ID get.docker.com knows, so it fell back to Debian and
# read the codename from /etc/debian_version — which says `trixie/sid` on
# Ubuntu noble. It wrote `download.docker.com/linux/debian trixie`, and
# `apt-get install docker-ce` died on held broken packages. So: this script
# NEVER reads /etc/debian_version (a Debian-derived file is not evidence of
# the release a derivative is built on). The only inputs are the os-release
# fields below. Derivatives (Pop!_OS, Mint, Zorin, elementary, KDE neon) all
# ship UBUNTU_CODENAME, which is the one authoritative name for the base.
#
# os-release is shell syntax, but this runs as root: it is PARSED with sed
# (last `KEY=` line, one layer of quotes stripped), never sourced, so a
# hostile file cannot execute anything.
OSR="${OS_RELEASE_FILE:-/etc/os-release}"

osr_get() {
    # Absent or unreadable file: prints nothing (every field then reads empty).
    [ -r "$OSR" ] || return 0
    sed -n "s/^$1=//p" "$OSR" | tail -n 1 \
        | sed -e 's/^"\(.*\)"$/\1/' -e "s/^'\(.*\)'\$/\1/"
}

# Sets PLAT_FAMILY (ubuntu|debian|raspbian|fedora|rhel|arch|unknown),
# PLAT_CODENAME (release codename, or "unknown") and PLAT_PKG
# (apt|dnf|pacman|none).
resolve_platform() {
    PLAT_FAMILY=unknown; PLAT_CODENAME=unknown; PLAT_PKG=none
    local id like vcn ucn
    id="$(osr_get ID)"; like="$(osr_get ID_LIKE)"
    vcn="$(osr_get VERSION_CODENAME)"; ucn="$(osr_get UBUNTU_CODENAME)"
    case "$id" in
        ubuntu|debian)
            PLAT_FAMILY="$id"; PLAT_PKG=apt; PLAT_CODENAME="${vcn:-unknown}"; return 0 ;;
    esac
    if [ -n "$ucn" ]; then
        PLAT_FAMILY=ubuntu; PLAT_PKG=apt; PLAT_CODENAME="$ucn"; return 0
    fi
    case " $like " in
        *" ubuntu "*)
            # Ubuntu-based but no UBUNTU_CODENAME: we cannot tell which
            # release; the codename stays unknown and check mode FAILs it.
            PLAT_FAMILY=ubuntu; PLAT_PKG=apt; return 0 ;;
    esac
    if [ "$id" = raspbian ]; then
        PLAT_FAMILY=raspbian; PLAT_PKG=apt; PLAT_CODENAME="${vcn:-unknown}"; return 0
    fi
    case " $like " in
        *" debian "*)
            PLAT_PKG=apt
            if [ -n "$vcn" ]; then PLAT_FAMILY=debian; PLAT_CODENAME="$vcn"; fi
            return 0 ;;
    esac
    case "$id" in
        fedora) PLAT_FAMILY=fedora; PLAT_PKG=dnf; return 0 ;;
        rhel|centos|rocky|almalinux|alma) PLAT_FAMILY=rhel; PLAT_PKG=dnf; return 0 ;;
        arch|manjaro) PLAT_FAMILY=arch; PLAT_PKG=pacman; return 0 ;;
    esac
    case " $like " in
        *" fedora "*|*" rhel "*) PLAT_FAMILY=rhel; PLAT_PKG=dnf ;;
        *" arch "*) PLAT_FAMILY=arch; PLAT_PKG=pacman ;;
    esac
    return 0
}

# Does Docker publish a repo for this family/codename? Returns 0 yes, 1 the
# server answered 404 (curl exit 22: nothing published for this release),
# 2 could not tell (curl absent, or no network). Callers decide what each
# means; this function never exits.
DOCKER_REPO_BASE=https://download.docker.com/linux
docker_release_exists() {
    command -v curl >/dev/null 2>&1 || return 2
    local rc=0
    curl -fsI --proto '=https' --tlsv1.2 --max-time 15 \
        "$DOCKER_REPO_BASE/$1/dists/$2/Release" >/dev/null 2>&1 || rc=$?
    [ "$rc" = 0 ] && return 0
    [ "$rc" = 22 ] && return 1
    return 2
}

# ── Check mode (PREP_CHECK=1) ──────────────────────────────────────────────
# `noo enroll` runs this BEFORE it spends the single-use token, so a box prep
# is going to choke on is refused while the paste is still good (2026-10-10:
# the token was spent, prep then failed, enroll still said "complete").
# It runs unprivileged, ahead of the root guard, and changes NOTHING: no
# writes, no installs, no apt-get update. Every external tool is guarded by
# `command -v`: a missing tool is a WARN (or an ok-skip), never a crash.
# Output: one `prep-check: ok|warn|FAIL <what> — <remedy>` line per check, then
# `prep-check: platform=… codename=… pkg=…`. Exit 1 iff any FAIL.
if [ "${PREP_CHECK:-}" = 1 ]; then
    CHECK_FAILS=0
    pc_ok()   { printf 'prep-check: ok %s\n' "$*"; }
    pc_warn() { printf 'prep-check: warn %s\n' "$*"; }
    pc_fail() { printf 'prep-check: FAIL %s\n' "$*"; CHECK_FAILS=$((CHECK_FAILS + 1)); }

    if [ -r "$OSR" ]; then pc_ok "os-release readable ($OSR)"
    else pc_warn "os-release unreadable ($OSR) — platform unknown; prep will not install Docker via apt"; fi
    resolve_platform

    if [ "$PLAT_PKG" = apt ] && [ "$PLAT_CODENAME" = unknown ]; then
        pc_fail "cannot determine this release's codename (no UBUNTU_CODENAME/VERSION_CODENAME in $OSR) — install Docker by hand (https://docs.docker.com/engine/install/), then re-run"
    elif [ "$PLAT_FAMILY" = unknown ]; then
        pc_warn "platform not in the tested list — see docs/getting-started/supported-hardware.md; prep falls back to get.docker.com"
    else
        pc_ok "platform resolved ($PLAT_FAMILY $PLAT_CODENAME)"
    fi

    if [ -d /run/systemd/system ]; then pc_ok "systemd is running"
    else pc_fail "systemd is not PID 1 (needed for the node agent units) — use a systemd-based install; on WSL2 set systemd=true in /etc/wsl.conf and run wsl --shutdown"; fi

    HAVE_DOCKER=0
    command -v docker >/dev/null 2>&1 && HAVE_DOCKER=1

    if [ "$HAVE_DOCKER" = 0 ] && [ "$PLAT_PKG" = apt ] && [ "$PLAT_CODENAME" != unknown ]; then
        RC=0; docker_release_exists "$PLAT_FAMILY" "$PLAT_CODENAME" || RC=$?
        case "$RC" in
            0) pc_ok "Docker publishes a repo for $PLAT_FAMILY $PLAT_CODENAME" ;;
            1) pc_fail "Docker has no repo for $PLAT_FAMILY $PLAT_CODENAME yet ($DOCKER_REPO_BASE/$PLAT_FAMILY/dists/$PLAT_CODENAME/Release is 404) — install Docker by hand, then re-run" ;;
            *) pc_warn "could not check Docker's repo for $PLAT_FAMILY $PLAT_CODENAME (no curl or no network) — prep will fail if it is missing" ;;
        esac
    fi

    if [ "$HAVE_DOCKER" = 0 ] && [ "$PLAT_PKG" = apt ]; then
        if command -v dpkg-query >/dev/null 2>&1; then
            CONFLICTS="$(dpkg-query -W -f='${db:Status-Abbrev} ${Package}\n' \
                docker.io containerd runc podman-docker docker-compose 2>/dev/null \
                | awk '$1 == "ii" {print $2}' | tr '\n' ' ' || true)"
            CONFLICTS="${CONFLICTS% }"
            if [ -n "$CONFLICTS" ]; then
                pc_fail "conflicting packages installed ($CONFLICTS) would break docker-ce — sudo apt-get remove -y $CONFLICTS"
            else
                pc_ok "no conflicting Docker packages"
            fi
        else
            pc_warn "dpkg-query not found — could not check for conflicting Docker packages"
        fi
    fi

    if command -v apt-get >/dev/null 2>&1; then
        APT_RC=0; APT_OUT="$(apt-get check 2>&1)" || APT_RC=$?
        if [ "$APT_RC" = 0 ]; then
            pc_ok "apt dependency check clean"
        elif printf '%s' "$APT_OUT" | grep -qiE 'unmet dependencies|broken packages|held broken'; then
            pc_fail "apt reports broken dependencies — sudo apt --fix-broken install"
        else
            pc_warn "apt-get check could not run without root — not verified"
        fi
    elif [ "$PLAT_PKG" = apt ]; then
        pc_warn "apt-get not found on an apt-family platform — prep cannot install packages"
    fi

    DOCKER_LIST=/etc/apt/sources.list.d/docker.list
    if [ -r "$DOCKER_LIST" ]; then
        HAVE_LIST="$(sed -n 's#.*download\.docker\.com/linux/\([a-z]*\)[[:space:]][[:space:]]*\([a-z]*\)[[:space:]].*#\1 \2#p' "$DOCKER_LIST" | head -n 1 || true)"
        WANT_LIST="$PLAT_FAMILY $PLAT_CODENAME"
        if [ -n "$HAVE_LIST" ] && [ "$PLAT_CODENAME" != unknown ] && [ "$HAVE_LIST" != "$WANT_LIST" ]; then
            if [ "$HAVE_DOCKER" = 1 ]; then
                pc_warn "$DOCKER_LIST points at '$HAVE_LIST' but this host resolves to '$WANT_LIST' — Docker works here so prep leaves it; fix by hand if apt upgrades misbehave"
            else
                pc_ok "$DOCKER_LIST points at '$HAVE_LIST', not '$WANT_LIST' — prep will rewrite it"
            fi
        fi
    fi

    if command -v setfacl >/dev/null 2>&1; then pc_ok "setfacl present"
    else pc_warn "setfacl missing — prep installs the acl package on apt hosts"; fi

    if command -v lspci >/dev/null 2>&1; then
        if lspci 2>/dev/null | grep -qi nvidia; then
            if command -v nvidia-smi >/dev/null 2>&1 && nvidia-smi -L >/dev/null 2>&1; then
                pc_ok "NVIDIA GPU and driver working"
            else
                pc_warn "NVIDIA device on the bus but nvidia-smi absent/failing — install the vendor driver (prep installs only the container toolkit)"
            fi
        else
            pc_ok "no NVIDIA device on the bus"
        fi
    else
        pc_ok "lspci not found — NVIDIA check skipped"
    fi

    if [ -n "${NOO_DATA_ROOT:-}" ]; then
        ANC="$NOO_DATA_ROOT"
        while [ ! -e "$ANC" ] && [ "$ANC" != / ] && [ "$ANC" != . ]; do ANC="$(dirname "$ANC")"; done
        if [ -d "$ANC" ]; then pc_ok "data root $NOO_DATA_ROOT (nearest existing ancestor: $ANC)"
        else pc_fail "data root $NOO_DATA_ROOT has no existing ancestor directory — pick a path under an existing mount"; fi
        case "$NOO_DATA_ROOT" in
            /media/*) pc_warn "data root is under /media — desktop automounts may not exist at boot; add an /etc/fstab entry for that drive" ;;
        esac
    fi

    printf 'prep-check: platform=%s codename=%s pkg=%s\n' "$PLAT_FAMILY" "$PLAT_CODENAME" "$PLAT_PKG"
    [ "$CHECK_FAILS" = 0 ] || exit 1
    exit 0
fi

[ "$(id -u)" = 0 ] || { echo "must run as root (bootstrap-enroll runs this under sudo)" >&2; exit 1; }
ENROLL_USER="${PREP_ENROLL_USER:-${SUDO_USER:-}}"
MARKER=/etc/noo/host-prepped

say() { printf 'prep-host: %s\n' "$*"; }

# ── 0. Retire the pre-rename (pai-*) host residue ──────────────────────────
# A node enrolled before the noomesh rename keeps its old-name daemons and
# files next to the new set — the "renamed unit left enabled is a zombie"
# case from an earlier change W3.5. On HOST3 (2026-09-01) `pai-hostd` was still
# active as a user unit with the source clone as its state root, on a box
# that had just become a worker. Root-owned residue is removed here; the
# user units are retired by `noo enroll` itself (user context) before it
# runs this script. Idempotent: every path is checked first.
LEGACY_REMOVED=""
if command -v systemctl >/dev/null 2>&1; then
    for U in pai-node-agent.service pai-hostd.service pai-host-watcher.service; do
        if [ -f "/etc/systemd/system/$U" ]; then
            systemctl disable --now "$U" >/dev/null 2>&1 || true
            rm -f "/etc/systemd/system/$U"
            LEGACY_REMOVED="$LEGACY_REMOVED $U"
        fi
    done
fi
# `rm -rf`, not `rm -f`: on host9 (2026-09-02) /usr/local/bin/pai-node-agent
# was an empty DIRECTORY from an older agent layout, `rm -f` refused, and
# set -e ended prep before anything was installed — the node then never
# fetched its bundle. Residue can be any shape; remove it whatever it is.
for F in /usr/local/bin/pai-hostd /usr/local/bin/pai-host-watcher /usr/local/bin/pai-host-watcher.sh \
         /usr/local/bin/pai-node-agent /usr/local/bin/pai-node-agent.prev \
         /usr/local/bin/pai-gate /usr/local/bin/pai-apply \
         /usr/local/bin/pai-fetch /usr/local/bin/pai-deenroll \
         /etc/sudoers.d/pai-apply /etc/sudoers.d/pai-node-maintenance /etc/sudoers.d/pai-cluster \
         /etc/sudoers.d/noo-apply /etc/sudoers.d/noo-cluster /etc/sudoers.d/noo-node-maintenance; do
    if [ -e "$F" ] || [ -L "$F" ]; then rm -rf "$F"; LEGACY_REMOVED="$LEGACY_REMOVED $F"; fi
done
for F in /etc/pai-node-agent.env /etc/pai-node-agent.env.*; do
    if [ -e "$F" ] || [ -L "$F" ]; then rm -rf "$F"; LEGACY_REMOVED="$LEGACY_REMOVED $F"; fi
done
if [ -d /etc/pai ]; then
    # The old PKI dir: the new anchor lives under /etc/noo/pki and is
    # re-fetched below (fingerprint-pinned), so nothing here is still read.
    rm -rf /etc/pai; LEGACY_REMOVED="$LEGACY_REMOVED /etc/pai/"
fi
# Every pre-rename name this project has installed the cluster CA under.
# `noomesh-cluster-ca.crt` is the one that bit: it was left behind at 0640
# root:root, which made the WHOLE platform trust store unreadable to every
# non-root process on host3 — the harness could not reach the bus and
# crash-looped ~1900 times before anyone connected the two.
# Nothing in the tree installed that name any more, and nothing removed it
# either, so it sat there. A name this project has ever used belongs in
# this list the day it stops being used.
for CA in /usr/local/share/ca-certificates/metis-cluster-ca.crt \
          /usr/local/share/ca-certificates/pai-cluster-ca.crt \
          /usr/local/share/ca-certificates/noomesh-cluster-ca.crt; do
    if [ -f "$CA" ]; then
        rm -f "$CA"; LEGACY_REMOVED="$LEGACY_REMOVED $CA"
        command -v update-ca-certificates >/dev/null 2>&1 && update-ca-certificates >/dev/null 2>&1 || true
    fi
done
[ -n "$LEGACY_REMOVED" ] && say "retired pre-rename residue:$LEGACY_REMOVED"
if command -v systemctl >/dev/null 2>&1 && [ -n "$LEGACY_REMOVED" ]; then systemctl daemon-reload || true; fi

# ── 1. Prerequisites ───────────────────────────────────────────────────────
if command -v apt-get >/dev/null 2>&1; then
    say "installing prerequisites (apt)"
    apt-get update -qq || true
    DEBIAN_FRONTEND=noninteractive apt-get install -y -qq \
        acl apt-transport-https ca-certificates curl gnupg lsb-release rsync >/dev/null
else
    say "WARNING: not a Debian-family host — package installs skipped; ensure curl/rsync/docker exist"
fi

# ── 2. Docker ──────────────────────────────────────────────────────────────
resolve_platform
if ! command -v docker >/dev/null 2>&1; then
    if [ "$PLAT_PKG" = apt ]; then
        # Docker's own apt repo, written from the platform resolved above —
        # not get.docker.com, which guesses (see "Platform resolution").
        if [ "$PLAT_CODENAME" = unknown ]; then
            say "FATAL: cannot determine this release's codename from $OSR — install Docker by hand (https://docs.docker.com/engine/install/), then re-run"
            exit 1
        fi
        say "installing Docker from download.docker.com ($PLAT_FAMILY $PLAT_CODENAME)"
        RC=0; docker_release_exists "$PLAT_FAMILY" "$PLAT_CODENAME" || RC=$?
        if [ "$RC" != 0 ]; then
            # Never guess a neighbouring codename: that is the bug this fixes.
            say "FATAL: no Docker apt repo for $PLAT_FAMILY $PLAT_CODENAME ($DOCKER_REPO_BASE/$PLAT_FAMILY/dists/$PLAT_CODENAME/Release not reachable or 404) — install Docker by hand, then re-run"
            exit 1
        fi
        install -m 0755 -d /etc/apt/keyrings
        if ! curl -fsSL --proto '=https' --tlsv1.2 "$DOCKER_REPO_BASE/$PLAT_FAMILY/gpg" -o /etc/apt/keyrings/docker.asc \
            || ! grep -q 'BEGIN PGP PUBLIC KEY BLOCK' /etc/apt/keyrings/docker.asc; then
            say "FATAL: could not fetch Docker's signing key from $DOCKER_REPO_BASE/$PLAT_FAMILY/gpg"
            rm -f /etc/apt/keyrings/docker.asc
            exit 1
        fi
        chmod a+r /etc/apt/keyrings/docker.asc
        # OVERWRITE, never append or keep: an existing docker.list may be the
        # wrong-family line a previous get.docker.com run left behind. A
        # deb822 docker.sources from a newer installer is the same hazard in
        # the other format; left beside ours, apt would still offer its suite.
        if grep -qs 'download\.docker\.com' /etc/apt/sources.list.d/docker.sources; then
            say "removing a stale /etc/apt/sources.list.d/docker.sources (prep writes docker.list)"
            rm -f /etc/apt/sources.list.d/docker.sources
        fi
        printf 'deb [arch=%s signed-by=/etc/apt/keyrings/docker.asc] %s/%s %s stable\n' \
            "$(dpkg --print-architecture)" "$DOCKER_REPO_BASE" "$PLAT_FAMILY" "$PLAT_CODENAME" \
            > /etc/apt/sources.list.d/docker.list
        apt-get update -qq
        DEBIAN_FRONTEND=noninteractive apt-get install -y -qq \
            docker-ce docker-ce-cli containerd.io docker-buildx-plugin docker-compose-plugin >/dev/null
    else
        say "WARNING: platform '$PLAT_FAMILY' is not in the tested list (docs/getting-started/supported-hardware.md) — falling back to get.docker.com"
        say "installing Docker (get.docker.com)"
        # Downloaded to a file over pinned HTTPS, checked to be a script, its
        # sha256 said out loud, then run — never `curl | sh`, which executes
        # bytes nobody ever sees. Docker publishes no checksum or signature for
        # get.docker.com (it is generated per request), so the residual trust is
        # the vendor's domain at fetch time; what changes is that WHAT RAN is
        # recoverable afterwards. noo-cli/src/vendor.rs states the same
        # residual trust for the CLI's install path.
        DOCKER_INSTALLER="$(mktemp)"
        if curl -fsSL --proto '=https' --tlsv1.2 https://get.docker.com -o "$DOCKER_INSTALLER" \
            && head -1 "$DOCKER_INSTALLER" | grep -q '^#!'; then
            say "docker installer sha256: $(sha256sum "$DOCKER_INSTALLER" | cut -d' ' -f1)"
            sh "$DOCKER_INSTALLER"
        else
            say "FATAL: get.docker.com did not return a shell script — refusing to run it"
            rm -f "$DOCKER_INSTALLER"
            exit 1
        fi
        rm -f "$DOCKER_INSTALLER"
    fi
else
    say "Docker present: $(docker --version 2>/dev/null | head -1)"
fi

# ── 3. journald cap ─────────────────
JCONF=/etc/systemd/journald.conf.d/10-noo-cap.conf
if [ ! -f "$JCONF" ]; then
    say "capping journald disk usage"
    install -d -m 755 /etc/systemd/journald.conf.d
    cat > "$JCONF" <<'EOF'
# PAI: bound journal growth so /var/log/journal cannot fill the host.
# Peer to the docker/compose 50m log caps.
[Journal]
SystemMaxUse=500M
SystemMaxFileSize=100M
EOF
    systemctl restart systemd-journald || true
fi

# ── 4. NVIDIA (only when a GPU is actually present) ────────────────────────
GPU_PRESENT=0
if command -v nvidia-smi >/dev/null 2>&1 && nvidia-smi -L >/dev/null 2>&1; then
    GPU_PRESENT=1
elif lspci 2>/dev/null | grep -qi 'nvidia'; then
    say "WARNING: NVIDIA device on the bus but nvidia-smi absent/failing — install the driver first; toolkit setup skipped"
fi
if [ "$GPU_PRESENT" = 1 ]; then
    if ! command -v nvidia-ctk >/dev/null 2>&1; then
        say "installing NVIDIA Container Toolkit"
        curl -fsSL https://nvidia.github.io/libnvidia-container/gpgkey | \
            gpg --dearmor -o /usr/share/keyrings/nvidia-container-toolkit-keyring.gpg
        curl -sL https://nvidia.github.io/libnvidia-container/stable/deb/nvidia-container-toolkit.list | \
            sed 's#deb https://#deb [signed-by=/usr/share/keyrings/nvidia-container-toolkit-keyring.gpg] https://#g' \
            > /etc/apt/sources.list.d/nvidia-container-toolkit.list
        apt-get update -qq
        DEBIAN_FRONTEND=noninteractive apt-get install -y -qq nvidia-container-toolkit >/dev/null
        nvidia-ctk runtime configure --runtime=docker
        python3 - <<'PY'
import json, os
p = "/etc/docker/daemon.json"
cfg = {}
if os.path.exists(p):
    with open(p) as f:
        cfg = json.load(f)
cfg["default-runtime"] = "nvidia"
with open(p, "w") as f:
    json.dump(cfg, f, indent=4)
PY
        systemctl restart docker
    fi

    # nvidia-persistenced — see the header comment for why this is not a
    # plain `systemctl enable`.
    OVR=/etc/systemd/system/nvidia-persistenced.service.d/override.conf
    if [ ! -f "$OVR" ]; then
        say "fixing nvidia-persistenced (static unit + --no-persistence-mode)"
        install -d -m 755 /etc/systemd/system/nvidia-persistenced.service.d
        cat > "$OVR" <<'EOF'
# Managed by scripts/prep-host.sh (ported from ansible/setup-gpu-worker.yml —
# see the comment there for the host8 incident this fixes).
[Service]
# Clearing ExecStart first is REQUIRED: systemd appends otherwise and the
# unit would try to run the daemon twice.
ExecStart=
ExecStart=/usr/bin/nvidia-persistenced --user nvidia-persistenced --verbose
[Install]
WantedBy=multi-user.target
EOF
        systemctl daemon-reload
        systemctl enable nvidia-persistenced
        systemctl restart nvidia-persistenced
    fi
    # Verify against the DRIVER, not systemd — "active" was true on host8
    # the whole time it was doing nothing.
    PMODE="$(nvidia-smi --query-gpu=persistence_mode --format=csv,noheader 2>/dev/null | head -1 | tr -d ' ')"
    case "$PMODE" in
        Enabled) say "GPU persistence mode: Enabled" ;;
        *) say "WARNING: persistence mode reads '$PMODE' — check nvidia-smi; the GPU may need a reboot" ;;
    esac
fi

# ── 5. Service account ────────
# Only noo-agent joins the docker group. The OPERATOR deliberately does not:
# a first version granted "$ENROLL_USER docker for the provisioning epoch",
# which meant re-running prep on a converged node silently UNDID step 6
# (caught 2026-08-17, minutes before it would have re-rooted the maintainer account on both
# workers). Nothing in provisioning needs it — the playbook's docker work is
# `become: root`, the agent's is its own group, and the human uses
# `sudo docker` as break-glass. A node is born with step 6 already done.
id -u noo-agent >/dev/null 2>&1 || useradd --system --shell /usr/sbin/nologin --no-create-home noo-agent
gpasswd -a noo-agent docker >/dev/null
say "docker group: noo-agent only (operator stays out — an earlier change)"

# ── 6. System PKI home + agent state (step 3 layout, from birth) ───────────
# /etc/noo is 755: it holds the host-prepped MARKER, which noo-gate facts must
# read as the unprivileged SSH user — a 750 parent made facts report
# prepped=no fleet-wide (the third 0750-traversal bite of 2026-08-17, after
# the runner home and the PKI home). The SECRETS live one level down:
# /etc/noo/pki stays 750 root:noo-agent.
install -d -m 755 -o root -g noo-agent /etc/noo
install -d -m 750 -o root -g noo-agent /etc/noo/pki /etc/noo/pki/nodes

# The TRUST ANCHOR lands at birth (and only at birth): noo-apply refuses any
# bundle whose manifest does not verify against /etc/noo/pki/ca.crt, so a
# brand-new node needs the CA certificate before the FIRST bundle can arrive.
# Fetched over the same token-authenticated enrollment channel as this
# script — the one sanctioned trust-on-first-use moment. NEVER overwritten:
# an existing anchor only ever changes via a cross-signed bundle (noo-apply's
# ca.crt kind, verified against the OLD anchor).
if [ ! -f /etc/noo/pki/ca.crt ] && [ -n "${PREP_NOO_URL:-}" ]; then
    PREP_CURL="-fsS"
    if [ "${PREP_INSECURE:-0}" = "1" ]; then
        # An unverified transport is tolerable for exactly one artifact, and
        # only because its bytes are fingerprint-checked below. Without the
        # fingerprint this is blind trust-on-first-use: whoever answers the
        # request becomes the node's certificate authority for life. Refuse.
        # (§3f R25 — PREP_CA_SHA256 is required, not optional.)
        if [ -z "${PREP_CA_SHA256:-}" ]; then
            say "FATAL: PREP_CA_SHA256 is required when the controller cannot be verified yet."
            say "       Without the cluster CA's fingerprint there is nothing to check the"
            say "       downloaded anchor against. Re-mint the enrollment paste on the"
            say "       controller (noo cluster provision <node>) — a current controller"
            say "       always includes the pin."
            exit 1
        fi
        PREP_CURL="-fsSk"
    fi
    if curl $PREP_CURL "$PREP_NOO_URL/bootstrap/ca.crt" -o /etc/noo/pki/ca.crt.new         && grep -q "BEGIN CERTIFICATE" /etc/noo/pki/ca.crt.new; then
        # Token-bound CA verification: the bootstrap paste
        # carries the CA's DER-sha256 fingerprint, so first contact is no
        # longer blind TOFU — a tampered transport (the INSECURE=1 window)
        # cannot substitute its own CA without failing this check.
        if [ -n "${PREP_CA_SHA256:-}" ]; then
            GOT_FP="$(openssl x509 -in /etc/noo/pki/ca.crt.new -outform DER 2>/dev/null | sha256sum | cut -d' ' -f1)"
            if [ "$GOT_FP" != "$PREP_CA_SHA256" ]; then
                rm -f /etc/noo/pki/ca.crt.new
                say "FATAL: cluster CA fingerprint MISMATCH (expected $PREP_CA_SHA256, got $GOT_FP) — possible transport tamper; enrollment must not proceed"
                exit 1
            fi
            say "cluster CA fingerprint verified against the token's pin ($GOT_FP)"
        fi
        chmod 644 /etc/noo/pki/ca.crt.new   # public cert: a user CLI pins the mirror to it
        chown root:noo-agent /etc/noo/pki/ca.crt.new
        mv /etc/noo/pki/ca.crt.new /etc/noo/pki/ca.crt
        say "cluster CA trust anchor installed (birth TOFU, token-authenticated channel)"
    else
        rm -f /etc/noo/pki/ca.crt.new
        say "WARNING: could not fetch the cluster CA — the first signed bundle will be refused; fetch $PREP_NOO_URL/bootstrap/ca.crt to /etc/noo/pki/ca.crt manually"
    fi
fi
install -d -o noo-agent -g noo-agent /var/lib/noo-node-agent \
    /var/lib/noo-node-agent/spool /var/lib/noo-node-agent/staging
# ── 6a. System trust for the enrolled CA ───────────────────────────────────
# The agent verifies against /etc/noo/pki/ca.crt on its own, but the CLI,
# the MCP door, and tailscaled on this box verify against the SYSTEM store.
# The anchor is fingerprint-pinned by the blob, so trusting it here is the
# same decision `noo security trust-ca` makes on the controller. Without
# this a worker box that also runs `noo cluster status` fails UnknownIssuer
# against the new controller (HOST3, 2026-09-01).
TRUST_DST=/usr/local/share/ca-certificates/mesh-cluster-ca.crt
if [ -f /etc/noo/pki/ca.crt ] && command -v update-ca-certificates >/dev/null 2>&1 \
    && ! cmp -s /etc/noo/pki/ca.crt "$TRUST_DST" 2>/dev/null; then
    install -m 644 /etc/noo/pki/ca.crt "$TRUST_DST"
    update-ca-certificates >/dev/null 2>&1 || true
    say "cluster CA installed into the system trust store ($TRUST_DST)"
fi

# ── 6b. noo-apply / noo-fetch / noo-deenroll ────────────────────────────
# Fetched from the controller that served THIS script, over the same
# transport. No sudoers grant is written for any of these — noo-apply
# refuses any payload not signed by the cluster CA, and noo-fetch.service
# runs as root already (no User=), so authenticity rests entirely on the
# CA signature, not on a sudo grant.
if [ -n "${PREP_NOO_URL:-}" ]; then
    # By the time we get here the CA block above has already landed
    # /etc/noo/pki/ca.crt -- fingerprint-pinned when the paste carried
    # PREP_CA_SHA256. So the insecure window that first contact needs is
    # OVER, and continuing to fetch with -k would download noo-apply itself
    # over an unverified transport for no reason.
    # The CA block above has already landed /etc/noo/pki/ca.crt, pinned to
    # the paste's fingerprint. So there is a verifiable anchor by now, and
    # every fetch below — noo-apply among them, which runs as root — uses it.
    # The old `elif PREP_INSECURE` arm downloaded root-executed tooling over
    # an unverified transport; it is gone (§3f R25). No anchor, no fetch —
    # and the refusal is per-fetch, not a prep-wide exit, because the
    # embedded lane (PREP_TOOLS_DIR) installs the same scripts from disk and
    # the rest of prep (identity files, the timer) must still run.
    PREP_CURL=""
    if [ -f /etc/noo/pki/ca.crt ]; then
        PREP_CURL="-fsS --cacert /etc/noo/pki/ca.crt"
    fi
    # The SSH gate (noo-gate) exists only for the controller-SSH lane; a
    # pull-only fleet never installs it — and retires one
    # left by an earlier enrollment.
    # The gate lane is gone (2026-09-05), so noo-gate is never installed and
    # one left by an earlier enrollment is retired. PREP_GATE_LANE is no
    # longer read: an opt-in that installs a shell-adjacent verb menu plus
    # the sudoers grant it needs is exactly what "retire SSH" means to stop
    # offering.
    TOOLS="apply deenroll fetch"
    if [ -e /usr/local/bin/noo-gate ]; then rm -f /usr/local/bin/noo-gate; say "retired /usr/local/bin/noo-gate"; fi
    for tool in $TOOLS; do
        # an earlier change: `noo enroll` stages its COMPILED-IN copies in
        # PREP_TOOLS_DIR — installing from disk means no executable arrives
        # over the unverified first-contact transport. The fetch below stays
        # as the shell-paste lane's path.
        if [ -n "${PREP_TOOLS_DIR:-}" ] && [ -s "$PREP_TOOLS_DIR/noo-$tool" ] \
            && head -1 "$PREP_TOOLS_DIR/noo-$tool" | grep -q '^#!'; then
            install -m 755 "$PREP_TOOLS_DIR/noo-$tool" "/usr/local/bin/noo-$tool"
            say "installed /usr/local/bin/noo-$tool (embedded)"
            continue
        fi
        if [ -z "$PREP_CURL" ]; then
            say "WARNING: no cluster CA at /etc/noo/pki/ca.crt — refusing to download noo-$tool over an unverified transport (it runs as root). Install the anchor and re-run prep."
            continue
        fi
        if curl $PREP_CURL "$PREP_NOO_URL/bootstrap/$tool" -o "/usr/local/bin/noo-$tool.new"; then
            # Refuse a truncated/HTML-error download: must look like a script.
            if head -1 "/usr/local/bin/noo-$tool.new" | grep -q '^#!'; then
                chmod 755 "/usr/local/bin/noo-$tool.new"
                mv "/usr/local/bin/noo-$tool.new" "/usr/local/bin/noo-$tool"
                say "installed /usr/local/bin/noo-$tool"
            else
                rm -f "/usr/local/bin/noo-$tool.new"
                say "WARNING: /bootstrap/$tool did not return a script — noo-$tool not installed"
            fi
        else
            say "WARNING: could not fetch /bootstrap/$tool (older controller?) — noo-$tool not installed"
        fi
    done
    # No sudoers drop-in. It existed for ONE caller: `noo-gate apply`, which
    # ran as the enrolling user over SSH and therefore needed
    # `sudo -n noo-apply`. The gate lane is retired, and the pull lane never
    # needed it — noo-fetch.service has no User=, so it is already root and
    # calls /usr/local/bin/noo-apply directly (noo-fetch.sh:212).
    #
    # A node should end with ZERO drop-ins in /etc/sudoers.d. Anything
    # privileged goes through noo-hostd's fixed op table, which is reachable
    # only by writing a spool file — not by holding a passwordless grant.

    # ── 6c. PULL provisioning ────────────────
    # The enroll script generated a BIRTH keypair before redeeming and
    # passes the file paths down; persist the identity pieces noo-fetch
    # needs, then arm the timer. From here the node needs NO inbound
    # connection: `noo cluster provision <name>` stages an ENCRYPTED bundle
    # at the controller and this timer collects, decrypts, and noo-applies
    # it (CA signature still the only content authority).
    printf '%s\n' "$PREP_NOO_URL" > /etc/noo/controller-url
    chmod 644 /etc/noo/controller-url
    # The `controller-insecure` marker is retired (§3f R25). It meant "this
    # node has no way to verify the controller", which describes FIRST
    # CONTACT and nothing after it: the window closes the moment the anchor
    # lands, which the block above has already done. Nothing ever removed the
    # marker, so a node polled unverified for the rest of its life over a
    # reason that expired seconds earlier. noo-fetch now refuses outright
    # without the anchor, so there is no state to record. Converge a marker
    # an older prep left behind.
    if [ -e /etc/noo/controller-insecure ]; then
        rm -f /etc/noo/controller-insecure
        say "retired the controller-insecure marker — every poll verifies the cluster CA now"
    fi
    if [ -n "${PREP_NODE_NAME:-}" ]; then
        # The agent env is root-only, so the CLI could not read it before
        # redeeming; this is the definitive check. An agent that already
        # answers to another name would make the applier refuse every
        # bundle addressed to the new one (noo-apply exit 77) — stop here,
        # before arming a fetch timer that can never succeed.
        INSTALLED_ID="$(grep -E '^NODE_ID=' /etc/noo-node-agent.env 2>/dev/null | cut -d= -f2- || true)"
        if [ -n "$INSTALLED_ID" ] && [ "$INSTALLED_ID" != "$PREP_NODE_NAME" ]; then
            echo "prep-host: this host's agent is already node '$INSTALLED_ID' but the token was bound to '$PREP_NODE_NAME' — refusing." >&2
            echo "prep-host: mint the token for '$INSTALLED_ID' (noo cluster bootstrap-token create --node $INSTALLED_ID), or dismantle this node first (noo cluster teardown-node $INSTALLED_ID) to rename it." >&2
            exit 79
        fi
        printf '%s\n' "$PREP_NODE_NAME" > /etc/noo/node-name
        chmod 644 /etc/noo/node-name
        say "node identity: $PREP_NODE_NAME (adopted from the bound token)"
    fi
    if [ -n "${PREP_BIRTH_KEY:-}" ] && [ -f "$PREP_BIRTH_KEY" ]; then
        install -m 600 -o root -g root "$PREP_BIRTH_KEY" /etc/noo/birth.key
        [ -n "${PREP_BIRTH_CRT:-}" ] && [ -f "$PREP_BIRTH_CRT" ] \
            && install -m 644 -o root -g root "$PREP_BIRTH_CRT" /etc/noo/birth.crt
        say "birth key installed (bundle-encryption target registered at enrollment)"
    fi
    if [ -x /usr/local/bin/noo-fetch ] && [ -f /etc/noo/birth.key ] \
        && [ -n "${PREP_NODE_NAME:-}" ] && command -v systemctl >/dev/null 2>&1; then
        cat > /etc/systemd/system/noo-fetch.service <<'UNIT'
[Unit]
Description=PAI pull provisioning — collect the staged bundle from the controller
After=network-online.target
Wants=network-online.target

[Service]
Type=oneshot
ExecStart=/usr/local/bin/noo-fetch
UNIT
        cat > /etc/systemd/system/noo-fetch.timer <<'UNIT'
[Unit]
Description=PAI pull provisioning poll

[Timer]
OnBootSec=45s
OnUnitActiveSec=60s
RandomizedDelaySec=10s

[Install]
WantedBy=timers.target
UNIT
        systemctl daemon-reload
        systemctl enable --now noo-fetch.timer >/dev/null 2>&1 || true
        printf '10\n' > /etc/noo/expect-bundle   # 10 fast ticks (the fetcher re-arms after every apply)
        say "noo-fetch.timer armed — the node will collect its provisioning bundle itself"
    fi
else
    say "NOTE: PREP_NOO_URL not set — noo-gate/noo-apply not installed (re-run prep with it set to converge)"
fi

# ── 7. Data root (detected, decided ONCE, recorded) ────────────────────────
if [ -z "${NOO_DATA_ROOT:-}" ]; then
    # Largest WRITABLE non-root mount >10GB wins; else the standard
    # /var/lib/noo. Mounts the data-root policy refuses are skipped: /home
    # (a home directory), WSL's Windows drives (/mnt/<letter>, 9P) and system
    # paths (noo-cli data_root::shape_problem is the same rule). The ro mount
    # option is filtered AND writability is proven with a real write —
    # WSLg's read-only distro mount was the biggest candidate on a WSL2
    # node and the old picker chose it (2026-09-01).
    NOO_DATA_ROOT=""
    for CAND in $(findmnt -bnro AVAIL,TARGET,OPTIONS -t ext4,ext3,xfs,btrfs 2>/dev/null | \
        awk '$2 != "/" && $2 !~ /boot/ && $2 !~ /recovery/ && $2 !~ /wslg/ && $2 !~ /^\/(home|root|etc|usr|var|opt|tmp|snap|run)(\/|$)/ && $2 !~ /^\/mnt\/[a-zA-Z](\/|$)/ && $1 > 10737418240 && $3 !~ /(^|,)ro(,|$)/ {print $1, $2}' | \
        sort -rn | awk '{print $2}'); do
        if touch "$CAND/.noo-writable-probe" 2>/dev/null; then
            rm -f "$CAND/.noo-writable-probe"
            NOO_DATA_ROOT="$CAND/noo"
            break
        fi
    done
    [ -n "$NOO_DATA_ROOT" ] || NOO_DATA_ROOT=/var/lib/noo
fi
say "data root: $NOO_DATA_ROOT"
install -d -o noo-agent -g noo-agent "$NOO_DATA_ROOT" \
    "$NOO_DATA_ROOT/hf-cache" "$NOO_DATA_ROOT/models" "$NOO_DATA_ROOT/ollama"
# Surface unmounted large drives the way the playbook did — a decision the
# operator may want to revisit, not an error.
UNMOUNTED="$(lsblk -bnrpo NAME,SIZE,MOUNTPOINT,FSTYPE 2>/dev/null | \
    awk '$3 == "" && ($4 == "ext4" || $4 == "xfs" || $4 == "btrfs") && $2 > 107374182400 {printf "%s (%.0fGB) ", $1, $2/1073741824}')"
[ -n "$UNMOUNTED" ] && say "NOTE: unmounted large drive(s): $UNMOUNTED— mount and re-run with NOO_DATA_ROOT= to use"

# ── 8. Controller hostname ─────────────────────────────────────────────────
# Only when the value is literally an IP: NOO_URL's host may be a DNS/tailnet
# name, and a hosts line whose first field is not an address is invalid.
case "${PREP_CONTROLLER_IP:-}" in
    *[0-9].[0-9]*|*:*)
        if ! getent hosts noo-controller >/dev/null 2>&1; then
            echo "$PREP_CONTROLLER_IP  noo-controller" >> /etc/hosts
            say "mapped noo-controller -> $PREP_CONTROLLER_IP in /etc/hosts"
        fi
        ;;
    "") : ;;
    *)  say "controller '$PREP_CONTROLLER_IP' is a name, not an IP — /etc/hosts untouched" ;;
esac

# ── 9. Marker: the record of the decisions made here ───────────────────────
cat > "$MARKER" <<EOF
# Written by scripts/prep-host.sh — read this file for the values, do not
# re-derive them (a second derivation on different disk state diverges).
PREPPED_VERSION=1
PREPPED_AT=$(date -Is)
NOO_DATA_ROOT=$NOO_DATA_ROOT
ENROLL_USER=$ENROLL_USER
GPU_PRESENT=$GPU_PRESENT
INSTALLED_TAILSCALE=${PREP_TS_INSTALLED_BY_US:-0}
EOF
chmod 644 "$MARKER"
say "done — marker at $MARKER"
