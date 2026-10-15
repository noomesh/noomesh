#!/usr/bin/env bash
# SPDX-License-Identifier: AGPL-3.0-only
# Copyright 2026 PersonifAI LLC

# setup-dev.sh — prepare a Linux, WSL2 or macOS box to develop noomesh.
#
#   scripts/setup-dev.sh             # install / verify everything below
#   scripts/setup-dev.sh --dry-run   # print what it would do; change nothing
#
# This is DEVELOPER setup for a checkout of this repo. It is not how a
# controller or a node is installed: a controller is the `noo` binary plus
# `noo onboard` (docs/getting-started/install.md), and a node enrolls over the
# pull rail (`noo cluster bootstrap-token create` on the controller, then the
# printed one-liner on the node). Nothing here generates SSH keys, touches a
# firewall, or installs Ansible — none of those are part of the system.
#
# What it installs or verifies, in order (each step checks first, so a re-run
# only does what is still missing):
#   1. Platform checks. WSL2: systemd must be on in /etc/wsl.conf (it prints
#      the exact fix if not) and / should be a shared mount.
#   2. Base packages (apt on Ubuntu/Debian; Homebrew on macOS).
#   3. Docker Engine + Compose v2 (Docker CE on Linux/WSL2; on WSL2 it detects
#      Docker Desktop and leaves it alone; on macOS it verifies Docker Desktop
#      or colima and tells you how to get one).
#   4. The NVIDIA container toolkit — only when `nvidia-smi` works.
#   5. Rust via rustup (the channel in rust-toolchain[.toml] if the repo has
#      one, else stable) with clippy. The documented Rust path is still
#      scripts/cargo-docker.sh; a host toolchain is what scripts/ci-local.py
#      uses.
#   6. Go, at least the version node-agent-go/go.mod declares.
#   7. Python (the version in .python-version) and ./venv with the developer
#      guide's extras: pip install -e ".[dev,web,cache]".
#   8. Node (the major CI uses) and `npm ci` in ui/.
#   9. pre-commit's git hooks (left alone if core.hooksPath is already set).
#  10. The `noo` binary: the release installer (noo-cli/install.sh), falling
#      back to building it from noo-cli/ with cargo.
# Then it runs quick checks and points at docs/development/developer-guide.md.
#
# Supported: Ubuntu 22.04 / 24.04 (and Debian-family generally), WSL2 running
# one of those, macOS on Apple silicon with Homebrew. Elsewhere it verifies
# and tells you what to install by hand.
set -euo pipefail

DRY_RUN=0
for arg in "$@"; do
    case "$arg" in
        --dry-run|-n) DRY_RUN=1 ;;
        -h|--help)
            sed -n '2,/^set -euo pipefail/p' "$0" | sed '$d' | sed 's/^# \{0,1\}//'
            exit 0 ;;
        *) echo "setup-dev: unknown argument '$arg' (try --help)" >&2; exit 64 ;;
    esac
done

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$REPO_ROOT"

# ── output ──────────────────────────────────────────────────────────────────
if [ -t 1 ]; then B=$'\033[1m'; G=$'\033[32m'; Y=$'\033[33m'; R=$'\033[31m'; D=$'\033[2m'; N=$'\033[0m'
else B=""; G=""; Y=""; R=""; D=""; N=""; fi
STEP=0
step() { STEP=$((STEP + 1)); printf '\n%s[%d] %s%s\n' "$B" "$STEP" "$1" "$N"; }
ok()   { printf '  %s+%s %s\n' "$G" "$N" "$1"; }
note() { printf '  %s-%s %s\n' "$D" "$N" "$1"; }
warn() { printf '  %s!%s %s\n' "$Y" "$N" "$1"; WARNINGS=$((WARNINGS + 1)); }
die()  { printf '  %sx%s %s\n' "$R" "$N" "$1" >&2; exit 1; }
WARNINGS=0

# run CMD ARGS... — print it, then run it unless --dry-run.
run() {
    printf '  %s$ %s%s\n' "$D" "$*" "$N"
    [ "$DRY_RUN" = 1 ] || "$@"
}
# run_sh 'pipeline' — the same, for a command that needs a shell (pipes,
# redirects).
run_sh() {
    printf '  %s$ %s%s\n' "$D" "$1" "$N"
    [ "$DRY_RUN" = 1 ] || bash -c "$1"
}
have() { command -v "$1" >/dev/null 2>&1; }

SUDO=""
if [ "$(id -u)" != 0 ]; then SUDO="sudo"; fi

# version_ge A B — true when version A >= version B.
version_ge() { [ "$(printf '%s\n%s\n' "$2" "$1" | sort -V | head -1)" = "$2" ]; }

# ── what the repo declares ────────────────────────────────────────────────
PY_VERSION="$(tr -d '[:space:]' < .python-version 2>/dev/null || echo 3.12)"
GO_VERSION="$(awk '/^go /{print $2; exit}' node-agent-go/go.mod 2>/dev/null || true)"
GO_VERSION="${GO_VERSION:-1.26.0}"
# CI's actions/setup-node pin (ci.yml); ui/package.json declares no engines.
NODE_MAJOR="$(awk '/node-version:/{print $2; exit}' .github/workflows/ci.yml 2>/dev/null | tr -dc '0-9')"
NODE_MAJOR="${NODE_MAJOR:-22}"
RUST_TOOLCHAIN="stable"
for f in rust-toolchain.toml rust-toolchain; do
    if [ -f "$f" ]; then
        RUST_TOOLCHAIN="$(sed -n 's/^[[:space:]]*channel[[:space:]]*=[[:space:]]*"\(.*\)".*/\1/p' "$f" | head -1)"
        [ -n "$RUST_TOOLCHAIN" ] || RUST_TOOLCHAIN="$(head -1 "$f" | tr -d '[:space:]')"
        break
    fi
done
EXTRAS="dev,web,cache"

OS="$(uname -s)"
ARCH="$(uname -m)"
IS_WSL=0; IS_MAC=0; HAS_APT=0; DOCKER_DESKTOP=0
case "$OS" in
    Darwin) IS_MAC=1 ;;
    Linux)
        if grep -qi microsoft /proc/version 2>/dev/null; then IS_WSL=1; fi
        if have apt-get; then HAS_APT=1; fi ;;
    *) die "unsupported OS '$OS' — Linux, WSL2 or macOS" ;;
esac

printf '%snoomesh dev setup%s  %s\n' "$B" "$N" "$REPO_ROOT"
note "platform: $OS $ARCH$([ "$IS_WSL" = 1 ] && echo ' (WSL2)')"
note "repo declares: Python $PY_VERSION, Go >= $GO_VERSION, Node $NODE_MAJOR, Rust $RUST_TOOLCHAIN"
[ "$DRY_RUN" = 1 ] && note "--dry-run: commands are printed, not run"

# ── 1. platform checks ────────────────────────────────────────────────────
step "Platform checks"
if [ "$IS_WSL" = 1 ]; then
    if docker info --format '{{.OperatingSystem}}' 2>/dev/null | grep -qi 'docker desktop'; then
        DOCKER_DESKTOP=1
        ok "Docker Desktop's WSL integration serves docker here — the Docker CE and NVIDIA steps are skipped (Desktop owns the daemon and GPU support)"
    fi
    systemd_on=0
    if grep -Eq '^[[:space:]]*systemd[[:space:]]*=[[:space:]]*true' /etc/wsl.conf 2>/dev/null \
        && [ "$(ps -p 1 -o comm= 2>/dev/null)" = systemd ]; then
        systemd_on=1
        ok "systemd is PID 1 (/etc/wsl.conf has systemd=true)"
    fi
    if [ "$systemd_on" = 0 ]; then
        printf '  %sx%s systemd is not running in this distro. Docker CE and the stack need it. Fix:\n' "$R" "$N"
        cat <<'EOF'

      sudo tee -a /etc/wsl.conf >/dev/null <<'WSLCONF'
      [boot]
      systemd=true
      WSLCONF

    then, from Windows (PowerShell):  wsl --shutdown
    reopen the distro and re-run scripts/setup-dev.sh.
    (If /etc/wsl.conf already has a [boot] section, add systemd=true under it
    instead of appending a second one.)
EOF
        if [ "$DOCKER_DESKTOP" = 0 ] && [ "$DRY_RUN" = 0 ]; then exit 1; fi
        warn "continuing without systemd ($([ "$DRY_RUN" = 1 ] && echo 'dry run' || echo 'Docker Desktop owns the daemon'))"
    fi
    prop="$(findmnt -no PROPAGATION / 2>/dev/null || true)"
    if [ -n "$prop" ] && [ "$prop" != shared ]; then
        warn "/ is a '$prop' mount; bind mounts under /mnt fail until it is shared: sudo mount --make-rshared /"
    else
        ok "/ is a shared mount"
    fi
    note "after a WSL rebuild or distro import, if bind mounts under /mnt fail: sudo mount --make-rshared /"
    note "keep Docker's data on the distro's ext4 (never /mnt/<drive>); disk upkeep: docs/development/wsl-disk.md"
elif [ "$IS_MAC" = 1 ]; then
    have brew || die "Homebrew is required on macOS: https://brew.sh (then re-run)"
    # No vendor telemetry (docs/security/telemetry.md): Homebrew sends install analytics by default.
    export HOMEBREW_NO_ANALYTICS=1
    ok "Homebrew $(brew --version | head -1 | awk '{print $2}')"
    [ "$ARCH" = arm64 ] || warn "released noo binaries are arm64-only on macOS; on Intel the noo step builds it from source"
else
    ok "Linux"
fi
if [ "$IS_MAC" = 0 ] && [ "$HAS_APT" = 0 ]; then
    warn "no apt-get: package steps are skipped — install git, curl, jq, build tools, Docker Engine + Compose v2, Python $PY_VERSION and Node $NODE_MAJOR yourself"
fi

# ── 2. base packages ──────────────────────────────────────────────────────
step "Base packages"
APT_UPDATED=0
apt_update() {
    if [ "$APT_UPDATED" = 0 ]; then run $SUDO apt-get update -qq; APT_UPDATED=1; fi
}
apt_install() {
    local missing=()
    for p in "$@"; do
        dpkg -s "$p" >/dev/null 2>&1 || missing+=("$p")
    done
    if [ "${#missing[@]}" = 0 ]; then ok "present: $*"; return 0; fi
    apt_update
    run $SUDO env DEBIAN_FRONTEND=noninteractive apt-get install -y -qq "${missing[@]}"
}
if [ "$HAS_APT" = 1 ]; then
    # Names verified on Ubuntu 22.04 and 24.04. `netcat` is a virtual package
    # with no install candidate on 24.04; netcat-openbsd is the real one.
    apt_install ca-certificates curl gnupg git jq unzip build-essential pkg-config \
        netcat-openbsd lsb-release shellcheck
elif [ "$IS_MAC" = 1 ]; then
    for p in git jq shellcheck; do
        if brew list --formula "$p" >/dev/null 2>&1; then ok "present: $p"; else run brew install "$p"; fi
    done
fi

# ── 3. Docker ─────────────────────────────────────────────────────────────
step "Docker Engine + Compose v2"
if [ "$IS_MAC" = 1 ]; then
    if docker info >/dev/null 2>&1; then
        ok "docker daemon reachable ($(docker version --format '{{.Server.Version}}' 2>/dev/null))"
    else
        warn "no reachable Docker daemon. Install ONE of:"
        note "  Docker Desktop:  brew install --cask docker   (then open it once)"
        note "  colima:          brew install colima docker docker-compose && colima start --cpu 4 --memory 8 --disk 60"
    fi
elif [ "$DOCKER_DESKTOP" = 1 ]; then
    ok "Docker Desktop ($(docker version --format '{{.Server.Version}}' 2>/dev/null))"
elif [ "$HAS_APT" = 1 ]; then
    if have docker; then
        ok "docker installed ($(docker --version 2>/dev/null | cut -d, -f1))"
        if ! dpkg -s docker-ce >/dev/null 2>&1 && dpkg -s docker.io >/dev/null 2>&1; then
            note "this is the distro's docker.io, not Docker CE — fine if 'docker compose' (v2) works below"
        fi
    else
        # shellcheck source=/dev/null
        . /etc/os-release
        DISTRO="$ID"; case "$ID" in ubuntu|debian) ;; *) DISTRO="${ID_LIKE:-debian}"; DISTRO="${DISTRO%% *}" ;; esac
        note "installing Docker CE from download.docker.com ($DISTRO $VERSION_CODENAME)"
        run $SUDO install -m 0755 -d /etc/apt/keyrings
        run $SUDO curl -fsSL "https://download.docker.com/linux/$DISTRO/gpg" -o /etc/apt/keyrings/docker.asc
        run $SUDO chmod a+r /etc/apt/keyrings/docker.asc
        run_sh "echo 'deb [arch=$(dpkg --print-architecture) signed-by=/etc/apt/keyrings/docker.asc] https://download.docker.com/linux/$DISTRO $VERSION_CODENAME stable' | $SUDO tee /etc/apt/sources.list.d/docker.list >/dev/null"
        APT_UPDATED=0
        apt_install docker-ce docker-ce-cli containerd.io docker-buildx-plugin docker-compose-plugin
    fi
    # Log caps + a bounded BuildKit cache at the daemon (docs/development/
    # wsl-disk.md, layer 2). Written only when there is no daemon.json yet, so
    # a hand-tuned one is never overwritten.
    if [ ! -f /etc/docker/daemon.json ]; then
        run $SUDO mkdir -p /etc/docker
        run_sh "printf '%s\n' '{' '  \"log-driver\": \"json-file\",' '  \"log-opts\": { \"max-size\": \"50m\", \"max-file\": \"3\" },' '  \"builder\": { \"gc\": { \"enabled\": true, \"defaultKeepStorage\": \"5GB\" } }' '}' | $SUDO tee /etc/docker/daemon.json >/dev/null"
    else
        ok "/etc/docker/daemon.json exists (left as is; see docs/development/wsl-disk.md for the log caps)"
    fi
    if systemctl is-active --quiet docker 2>/dev/null; then
        ok "docker.service active"
    else
        run $SUDO systemctl enable --now docker
    fi
    me="${USER:-$(id -un)}"
    if id -nG "$me" | tr ' ' '\n' | grep -qx docker; then
        ok "$me is in the docker group"
    else
        run $SUDO usermod -aG docker "$me"
        warn "log out and back in (WSL: wsl --shutdown) for the docker group to apply; until then use: newgrp docker"
    fi
else
    if have docker; then ok "docker present ($(docker --version 2>/dev/null))"; else warn "install Docker Engine + Compose v2 for your distro"; fi
fi
if docker compose version >/dev/null 2>&1; then
    ok "compose $(docker compose version --short 2>/dev/null)"
elif [ "$DRY_RUN" = 0 ]; then
    warn "'docker compose' (v2) is not available yet — the stack needs it"
fi

# ── 4. NVIDIA container toolkit (GPU boxes only) ──────────────────────────
step "NVIDIA container toolkit"
if [ "$IS_MAC" = 1 ]; then
    note "not applicable on macOS"
elif ! nvidia-smi >/dev/null 2>&1; then
    note "nvidia-smi does not work here — skipped (CPU-only box, or the driver is not installed)"
elif [ "$DOCKER_DESKTOP" = 1 ]; then
    ok "GPU present; Docker Desktop provides GPU support itself"
elif [ "$HAS_APT" = 1 ]; then
    ok "GPU: $(nvidia-smi --query-gpu=name --format=csv,noheader 2>/dev/null | head -1)"
    if dpkg -s nvidia-container-toolkit >/dev/null 2>&1; then
        ok "nvidia-container-toolkit installed"
    else
        run_sh "curl -fsSL https://nvidia.github.io/libnvidia-container/gpgkey | $SUDO gpg --dearmor --yes -o /usr/share/keyrings/nvidia-container-toolkit-keyring.gpg"
        run_sh "curl -fsSL https://nvidia.github.io/libnvidia-container/stable/deb/nvidia-container-toolkit.list | sed 's#deb https://#deb [signed-by=/usr/share/keyrings/nvidia-container-toolkit-keyring.gpg] https://#g' | $SUDO tee /etc/apt/sources.list.d/nvidia-container-toolkit.list >/dev/null"
        APT_UPDATED=0
        apt_install nvidia-container-toolkit
    fi
    if docker info --format '{{json .Runtimes}}' 2>/dev/null | grep -q nvidia; then
        ok "docker has the nvidia runtime"
    else
        run $SUDO nvidia-ctk runtime configure --runtime=docker
        run $SUDO systemctl restart docker
    fi
fi

# ── 5. Rust ───────────────────────────────────────────────────────────────
step "Rust (rustup, $RUST_TOOLCHAIN, clippy)"
export PATH="$HOME/.cargo/bin:$PATH"
if have rustup; then
    ok "rustup present"
    if rustup toolchain list 2>/dev/null | grep -q "^$RUST_TOOLCHAIN"; then
        ok "toolchain $RUST_TOOLCHAIN installed"
    else
        run rustup toolchain install "$RUST_TOOLCHAIN" --profile minimal
    fi
    if rustup component list --installed --toolchain "$RUST_TOOLCHAIN" 2>/dev/null | grep -q '^clippy'; then
        ok "clippy installed"
    else
        run rustup component add clippy --toolchain "$RUST_TOOLCHAIN"
    fi
elif have cargo; then
    warn "cargo is present without rustup ($(cargo --version)); leaving it alone"
else
    # Downloaded to a file and then run — never piped into a shell.
    tmp="$(mktemp)"
    run curl --proto '=https' --tlsv1.2 -fsSL https://sh.rustup.rs -o "$tmp"
    run sh "$tmp" -y --no-modify-path --profile minimal --default-toolchain "$RUST_TOOLCHAIN" --component clippy
    rm -f "$tmp"
    note "add to your shell profile if it is not there: export PATH=\"\$HOME/.cargo/bin:\$PATH\""
fi
note "Rust builds also run with no host toolchain: scripts/cargo-docker.sh (the developer guide's path)"

# ── 6. Go ─────────────────────────────────────────────────────────────────
step "Go >= $GO_VERSION (node-agent-go/go.mod)"
export PATH="/usr/local/go/bin:$PATH"
have_go="$(go env GOVERSION 2>/dev/null | sed 's/^go//' || true)"
if [ -n "$have_go" ] && version_ge "$have_go" "$GO_VERSION"; then
    ok "go $have_go"
elif [ "$IS_MAC" = 1 ]; then
    run brew install go
else
    case "$ARCH" in x86_64) garch=amd64 ;; aarch64|arm64) garch=arm64 ;; *) die "no Go download for $ARCH" ;; esac
    tarball="go${GO_VERSION}.linux-${garch}.tar.gz"
    note "installing $tarball to /usr/local/go (sha256 checked against dl.google.com)"
    tmpd="$(mktemp -d)"
    run curl -fsSL "https://dl.google.com/go/$tarball" -o "$tmpd/$tarball"
    run curl -fsSL "https://dl.google.com/go/$tarball.sha256" -o "$tmpd/$tarball.sha256"
    run_sh "cd '$tmpd' && echo \"\$(cat $tarball.sha256)  $tarball\" | sha256sum -c -"
    run $SUDO rm -rf /usr/local/go
    run $SUDO tar -C /usr/local -xzf "$tmpd/$tarball"
    rm -rf "$tmpd"
    if ! grep -qs '/usr/local/go/bin' "$HOME/.profile"; then
        run_sh "printf '\n# Go (scripts/setup-dev.sh)\nexport PATH=\"/usr/local/go/bin:\$HOME/go/bin:\$PATH\"\n' >> '$HOME/.profile'"
    fi
fi

# ── 7. Python + venv ──────────────────────────────────────────────────────
step "Python $PY_VERSION and ./venv (.[${EXTRAS}])"
PY="python$PY_VERSION"
if [ "$IS_MAC" = 1 ]; then
    have "$PY" || run brew install "python@$PY_VERSION"
elif [ "$HAS_APT" = 1 ]; then
    if ! have "$PY" || ! "$PY" -c 'import ensurepip, venv' >/dev/null 2>&1; then
        if ! apt-cache policy "$PY" 2>/dev/null | grep -q 'Candidate: [0-9]'; then
            # Ubuntu 22.04 ships 3.10; 24.04 ships 3.12 natively.
            apt_install software-properties-common
            run $SUDO add-apt-repository -y ppa:deadsnakes/ppa
            APT_UPDATED=0
        fi
        apt_install "$PY" "$PY-venv" "$PY-dev"
    fi
fi
if have "$PY" || [ "$DRY_RUN" = 1 ]; then
    have "$PY" && ok "$($PY --version 2>&1)"
    if [ -x venv/bin/python ] && venv/bin/python -c "import sys; sys.exit(0 if '%d.%d' % sys.version_info[:2] == '$PY_VERSION' else 1)" 2>/dev/null; then
        ok "venv/ exists ($(venv/bin/python --version 2>&1))"
    else
        if [ -e venv ]; then
            warn "venv/ is not a Python $PY_VERSION venv — recreating it"
            run rm -rf venv
        fi
        run "$PY" -m venv venv
    fi
    run venv/bin/pip install -q --upgrade pip
    run venv/bin/pip install -q -e ".[${EXTRAS}]"
    note "activate it with: source venv/bin/activate"
else
    warn "$PY not found — install Python $PY_VERSION and re-run"
fi

# ── 8. Node + the console ─────────────────────────────────────────────────
step "Node $NODE_MAJOR and ui/ dependencies"
node_major="$(node --version 2>/dev/null | sed 's/^v//; s/\..*//' || true)"
if [ -n "$node_major" ] && [ "$node_major" -ge "$NODE_MAJOR" ]; then
    ok "node $(node --version)"
elif [ "$IS_MAC" = 1 ]; then
    run brew install "node@$NODE_MAJOR"
    run brew link --overwrite --force "node@$NODE_MAJOR"
elif [ "$HAS_APT" = 1 ]; then
    [ -n "$node_major" ] && warn "node v$node_major is older than $NODE_MAJOR — installing $NODE_MAJOR from NodeSource"
    run $SUDO install -m 0755 -d /etc/apt/keyrings
    run_sh "curl -fsSL https://deb.nodesource.com/gpgkey/nodesource-repo.gpg.key | $SUDO gpg --dearmor --yes -o /etc/apt/keyrings/nodesource.gpg"
    run_sh "echo 'deb [signed-by=/etc/apt/keyrings/nodesource.gpg] https://deb.nodesource.com/node_${NODE_MAJOR}.x nodistro main' | $SUDO tee /etc/apt/sources.list.d/nodesource.list >/dev/null"
    APT_UPDATED=0
    apt_update
    run $SUDO env DEBIAN_FRONTEND=noninteractive apt-get install -y -qq nodejs
else
    warn "install Node $NODE_MAJOR yourself"
fi
if [ -f ui/package-lock.json ]; then
    if have npm || [ "$DRY_RUN" = 1 ]; then
        run_sh "cd ui && npm ci --no-audit --no-fund"
    fi
fi

# ── 9. git hooks + pre-commit ─────────────────────────────────────────────
step "Git hooks (pre-commit)"
if git rev-parse --is-inside-work-tree >/dev/null 2>&1; then
    # `pre-commit install` refuses to write hooks while core.hooksPath is set
    # (a checkout that manages its own hooks), so leave those alone.
    HOOKS_PATH="$(git config --get core.hooksPath 2>/dev/null || true)"
    if [ -n "$HOOKS_PATH" ]; then
        ok "core.hooksPath=$HOOKS_PATH already set: leaving git hooks as they are"
        note "run the checks by hand: venv/bin/pre-commit run --from-ref origin/dev --to-ref HEAD"
    elif [ -x venv/bin/pre-commit ] || [ "$DRY_RUN" = 1 ]; then
        run venv/bin/pre-commit install
        note "pre-commit now runs on each commit; by hand: venv/bin/pre-commit run --all-files"
    fi
else
    note "not a git checkout — hooks skipped"
fi

# ── 10. noo ───────────────────────────────────────────────────────────────
step "The noo CLI"
[ "$DRY_RUN" = 1 ] || mkdir -p "$HOME/.local/bin"
export PATH="$HOME/.local/bin:$PATH"
if have noo; then
    ok "$(noo --version 2>/dev/null | head -1) at $(command -v noo)"
    note "update it with: noo upgrade"
else
    installed=0
    if [ "$DRY_RUN" = 1 ]; then
        run env NOO_INSTALL_DIR="$HOME/.local/bin" sh noo-cli/install.sh
        note "(if the release is not reachable: cargo build --release --locked --manifest-path noo-cli/Cargo.toml)"
    else
        printf '  %s$ NOO_INSTALL_DIR=%s sh noo-cli/install.sh%s\n' "$D" "$HOME/.local/bin" "$N"
        if NOO_INSTALL_DIR="$HOME/.local/bin" sh noo-cli/install.sh; then
            installed=1
        else
            warn "the release installer failed (private channel, or no network) — building noo from noo-cli/"
        fi
        if [ "$installed" = 0 ] && have cargo; then
            run cargo build --release --locked --manifest-path noo-cli/Cargo.toml
            run install -m 755 noo-cli/target/release/noo "$HOME/.local/bin/noo"
            installed=1
        fi
        [ "$installed" = 1 ] || warn "noo is not installed — see docs/getting-started/install.md"
    fi
fi
if ! grep -qs '.local/bin' "$HOME/.profile" "$HOME/.bashrc" "$HOME/.zshrc" 2>/dev/null; then
    note "make sure ~/.local/bin is on your PATH (export PATH=\"\$HOME/.local/bin:\$PATH\")"
fi

# ── checks ────────────────────────────────────────────────────────────────
step "Quick checks"
check() {
    local label="$1"; shift
    local out
    if out="$("$@" 2>&1 | tail -1)"; then ok "$label: $out"; else warn "$label: not ready (${out:-no output})"; fi
}
check "docker compose" docker compose version --short
check "cargo" cargo --version
check "go" go version
check "node" node --version
check "noo" noo --version
if [ -x venv/bin/python ]; then
    check "pytest collection" venv/bin/python -m pytest -q --co tests/
else
    warn "pytest collection: no venv yet"
fi

printf '\n%sDone%s' "$B" "$N"
[ "$WARNINGS" -gt 0 ] && printf ' with %d warning(s) above' "$WARNINGS"
printf '.\n'
cat <<EOF

Next:
  source venv/bin/activate
  docs/development/developer-guide.md   build, test and extend each tree
  CONTRIBUTING.md                       branch/PR flow (worktrees) and tests
  noo onboard                           a dev-mode stack from this tree (docs/getting-started/install.md)
EOF
