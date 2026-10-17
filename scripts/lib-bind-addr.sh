#!/bin/bash
# SPDX-License-Identifier: AGPL-3.0-only
# Copyright 2026 PersonifAI LLC

# Resolve NOO_BIND_ADDR for cluster-plane port binding.
#
# With the Tailscale-only network there are no LAN IPs to hand-manage: every
# node binds its published cluster ports to its OWN tailnet IP. That value is
# deterministic per node, so we auto-derive it here instead of putting a
# different IP in each node's .env.
#
# One policy knob, identical on every node:
#   NOO_BIND_MODE=tailnet   -> auto-detect this node's 100.64.0.0/10 IP (recommended)
#   NOO_BIND_MODE=local     -> 127.0.0.1 (this machine only; a single box with no tailnet)
#   NOO_BIND_MODE=all       -> 0.0.0.0 (bind all interfaces: every network this box is on)
#   NOO_BIND_MODE=<ip>      -> bind that literal address
# An explicit NOO_BIND_ADDR always wins (escape hatch). An UNSET mode is a
# refusal (2026-09-29): until then it silently meant `all`, every cluster-plane
# port on every interface (gateway, NATS, node agent, the model cache's
# 8443) with nobody having said so. `all` is a decision, so it has to be written
# down. `noo onboard` writes the value (tailnet when the box has a tailnet
# IP, else local) since 2026-09-24; an install that predates it sets one
# line in .env. tests/test_bind_mode_required.py pins the refusal.
#
# Source this, then call `resolve_bind_addr` before `docker compose ... up`.

_detect_tailnet_ip() {
    # Prefer the tailscale CLI (authoritative); fall back to scanning
    # interfaces for an address in 100.64.0.0/10 (the CGNAT range Tailscale uses).
    if command -v tailscale >/dev/null 2>&1; then
        local ts
        ts="$(tailscale ip -4 2>/dev/null | head -1)"
        if [ -n "$ts" ]; then echo "$ts"; return; fi
    fi
    ip -4 -o addr show 2>/dev/null | awk '{print $4}' | cut -d/ -f1 \
        | awk -F. '$1==100 && $2>=64 && $2<=127 { print; exit }'
}

# Resolve NODE_LOCATION — a geographic/site label for this node, surfaced in the
# eval report and dashboard. Explicit NODE_LOCATION wins; otherwise derive the
# Tailscale DERP relay region (a rough geo signal) since we're all-tailnet;
# otherwise leave empty (the collector then shows "tailnet"). Export before
# `docker compose up` so the node-agent broadcasts it in its heartbeat.
# Presentation: a kv row when the launcher loaded lib-ui.sh, plain text otherwise
# (these libs are also sourced by scripts that print nothing styled).
_say_kv() { if declare -F ui_kv >/dev/null 2>&1; then ui_kv "$1" "$2"; else echo "$3"; fi; }

resolve_location() {
    if [ -n "${NODE_LOCATION:-}" ]; then
        export NODE_LOCATION
        _say_kv "Location" "$NODE_LOCATION (explicit)" "node location: $NODE_LOCATION (explicit)"
        return
    fi
    if command -v tailscale >/dev/null 2>&1; then
        # .Self.Relay is the nearest DERP region code (e.g. "nyc", "sfo", "lhr").
        local derp
        derp="$(tailscale status --json 2>/dev/null \
            | grep -oE '"Relay"[[:space:]]*:[[:space:]]*"[^"]+"' | head -1 \
            | sed -E 's/.*"Relay"[[:space:]]*:[[:space:]]*"([^"]+)".*/\1/')"
        if [ -n "$derp" ]; then
            export NODE_LOCATION="derp:$derp"
            _say_kv "Location" "derp:$derp (Tailscale relay region)" "node location: derp:$derp (Tailscale relay region)"
            return
        fi
    fi
    _say_kv "Location" "unset — the collector will show 'tailnet'" "node location: (unset — collector will show 'tailnet')"
}

# One key out of .env.
#
# The key side tolerates spaces around `=` on purpose. The launchers' other
# .env readers do NOT, and that is a divergence from the parser that actually
# consumes this file: `docker compose` resolves `NOO_BIND_ADDR = 192.0.2.5`
# to `192.0.2.5` (measured 2026-09-18). A reader stricter than compose would
# read nothing, export the 0.0.0.0 default, and OVERRIDE the value compose
# had correctly substituted — the same silent override this whole function
# was just fixed for, one layer along. The other four readers have the same
# gap and are noted in the followup rather than changed here.
_bind_env_value() {
    [ -f ".env" ] || return 0
    grep -E "^[[:space:]]*$1[[:space:]]*=" .env | tail -1 | cut -d= -f2- | tr -d ' \t\r"'
}

resolve_bind_addr() {
    # .env is NOT in the environment here. The launcher scripts never source
    # it (lib-secrets.sh says so outright) and this function runs BEFORE
    # load_secrets — so both knobs have to be read from the file by hand.
    #
    # Without this the whole feature was inert, and worse than inert: an
    # operator who followed the security docs of the time and set
    # NOO_BIND_ADDR=<tailnet ip> in .env got 0.0.0.0 anyway, because the
    # `all` default below EXPORTS 0.0.0.0 and an exported shell variable
    # beats compose's own .env substitution (verified 2026-09-18:
    # `.env` alone → host_ip 10.9.9.9; exported 0.0.0.0 + same .env →
    # host_ip 0.0.0.0). The port stayed open and the remedy confirmed itself.
    if [ -z "${NOO_BIND_ADDR:-}" ]; then
        NOO_BIND_ADDR="$(_bind_env_value NOO_BIND_ADDR)"
    fi
    if [ -z "${NOO_BIND_MODE:-}" ]; then
        NOO_BIND_MODE="$(_bind_env_value NOO_BIND_MODE)"
    fi

    # Explicit address wins.
    if [ -n "${NOO_BIND_ADDR:-}" ]; then
        _say_kv "Bind" "NOO_BIND_ADDR=$NOO_BIND_ADDR (explicit)" "cluster-plane bind: NOO_BIND_ADDR=$NOO_BIND_ADDR (explicit)"
        export NOO_BIND_ADDR
        return
    fi

    # Fail LOUD on an unset mode. The old `:-all` default published every
    # cluster-plane port on every interface without anyone having said so.
    # `return 1` under the launchers' `set -e` stops the start before
    # `docker compose up`; a caller without `set -e` gets the same rc.
    if [ -z "${NOO_BIND_MODE:-}" ]; then
        echo "ERROR: NOO_BIND_MODE is not set (not in the environment, not in .env) — refusing to start rather than bind every cluster-plane port on every interface." >&2
        echo "       Set one of: NOO_BIND_MODE=tailnet (this node's Tailscale IP only, recommended) | local (127.0.0.1, this machine only) | all (0.0.0.0, every interface — a decision, not a default)." >&2
        echo "       'noo onboard' writes it; or add the line to .env by hand, then confirm with: noo doctor exposure" >&2
        return 1
    fi

    local mode="$NOO_BIND_MODE"
    case "$mode" in
        all|0.0.0.0)
            export NOO_BIND_ADDR="0.0.0.0"
            _say_kv "Bind" "0.0.0.0 (NOO_BIND_MODE=all)" "cluster-plane bind: 0.0.0.0 (NOO_BIND_MODE=all)"
            ;;
        local|loopback|127.0.0.1)
            export NOO_BIND_ADDR="127.0.0.1"
            _say_kv "Bind" "127.0.0.1 (NOO_BIND_MODE=local)" "cluster-plane bind: 127.0.0.1 (NOO_BIND_MODE=local)"
            ;;
        tailnet)
            local ip=""
            # Fast path on workers: NODE_IP is already this node's tailnet IP
            # (set at enrollment time), so use it without needing the tailscale CLI.
            if [ -n "${NODE_IP:-}" ] && echo "$NODE_IP" \
                | awk -F. '{exit !($1==100 && $2>=64 && $2<=127)}'; then
                ip="$NODE_IP"
            else
                ip="$(_detect_tailnet_ip)"
            fi
            if [ -n "$ip" ]; then
                export NOO_BIND_ADDR="$ip"
                _say_kv "Bind" "$ip (auto-detected tailnet IP)" "cluster-plane bind: $ip (auto-detected tailnet IP)"
                # an earlier change: docker.service does not wait for tailscaled.
                # Without ip_nonlocal_bind a reboot where Docker restarts the
                # stack first cannot bind this address, and the gateway stays
                # down. `noo doctor exposure` fails on the same condition.
                if [ "$(cat /proc/sys/net/ipv4/ip_nonlocal_bind 2>/dev/null)" = "0" ]; then
                    echo "WARNING: tailnet bind with net.ipv4.ip_nonlocal_bind=0 — a reboot where Docker starts before Tailscale leaves these ports unbound. Fix: echo 'net.ipv4.ip_nonlocal_bind=1' | sudo tee /etc/sysctl.d/60-noo-tailnet-bind.conf && sudo sysctl -p /etc/sysctl.d/60-noo-tailnet-bind.conf" >&2
                fi
                # Tailscale Serve fronts the gateway from this very address, so
                # it is the proxy whose X-Forwarded-For names the real caller.
                # Only processes on this host connect from it; remote tailnet
                # peers keep their own source address through the DNAT.
                #
                # Why not loopback alone (checked 2026-10-16, audit 05-network):
                # the serve backend `noo` writes is `https://<this tailnet
                # IP>:<port>` (noo-cli/src/tailnet_serve.rs `backend()`), not
                # `127.0.0.1`, because in tailnet mode the gateway is published
                # ONLY on that address. A host process connecting to a local
                # address is sourced from that address, so tailscaled's hop
                # arrives from the tailnet IP and loopback is never the source.
                # Trusting loopback only would make every dashboard login look
                # like it came from the bridge. The residual: any process on
                # THIS host can also connect from that address and set
                # X-Forwarded-For (it can pick its own rate-limit key and audit
                # IP; it gains no credential). Closing that needs the gateway
                # to be published on loopback as well and `serve` pointed at
                # it, which is a deploy change, not a trust-list edit.
                case ",${NOO_TRUSTED_PROXIES:-}," in
                    *",$ip,"*) ;;
                    *) export NOO_TRUSTED_PROXIES="${NOO_TRUSTED_PROXIES:+$NOO_TRUSTED_PROXIES,}$ip" ;;
                esac
            else
                # Fail CLOSED. The operator chose the tailnet; with tailscale
                # down the old fallback published every cluster-plane port on
                # every interface, which is the opposite of what was asked,
                # and said so only on stderr.
                export NOO_BIND_ADDR="127.0.0.1"
                echo "WARNING: NOO_BIND_MODE=tailnet but no tailnet IP found — binding 127.0.0.1 (this machine only) until tailscale is up; NOO_BIND_MODE=all publishes on every interface" >&2
            fi
            ;;
        *)
            # Treat any other value as a literal IP.
            export NOO_BIND_ADDR="$mode"
            _say_kv "Bind" "$mode (literal NOO_BIND_MODE)" "cluster-plane bind: $mode (literal NOO_BIND_MODE)"
            ;;
    esac
}

# The host address the cluster plane is actually REACHABLE on, for banners and
# operator instructions.
#
# This exists because the two launcher banners hardcoded `https://localhost:8080`
# while `docker-compose.cluster.yml` publishes the gateway on
# `${NOO_BIND_ADDR}:${NOO_PORT_GATEWAY}`. On the controller NOO_BIND_ADDR is the
# tailnet IP, so localhost is not bound at all and the URL the banner prints —
# the last thing an operator reads after a successful start — answers
# connection-refused. Verified live on 2026-08-14: curl to localhost:8080 gave
# exit 7 while the tailnet address returned 200.
#
# Only 0.0.0.0 makes localhost correct, because only then is the loopback
# interface among those bound. Every other value means what it says.
#
# Ports come from lib-instance.sh (NOO_PORT_*), which already applies
# NOO_PORT_OFFSET — so a second instance prints its own ports rather than the
# first one's.
bind_host_for_display() {
    case "${NOO_BIND_ADDR:-0.0.0.0}" in
        0.0.0.0|127.0.0.1|"") echo "localhost" ;;
        *)          echo "$NOO_BIND_ADDR" ;;
    esac
}

# Print the "Service URLs" block. Pass `full` for the rebuild banner's longer
# list.
#
# Which host each service takes is NOT uniform, and the split is deliberate
#: the gateway, Grafana and the GPU exporter publish on
# ${NOO_BIND_ADDR} so they are reachable across the tailnet, while Prometheus,
# the NATS monitoring port and Postgres publish on 127.0.0.1 and are loopback
# ONLY. So `localhost` is wrong for the first group and right for the second —
# printing one host for all six is what produced the bug this fixes.
print_service_urls() {
    local host; host="$(bind_host_for_display)"
    # The advertised URL (NOO_GATEWAY_URL, set by onboard to the ts.net
    # name) is what browsers and the CLI actually dial — print it first
    # when it names something other than the bind host (operator ask,
    # 2026-09-01: the banner said localhost on a MagicDNS-fronted box).
    if [ -n "${NOO_GATEWAY_URL:-}" ] && ! grep -q "://${host}:" <<<"$NOO_GATEWAY_URL"; then
        _say_kv "Gateway API" "${NOO_GATEWAY_URL}" "  Gateway API:        ${NOO_GATEWAY_URL}"
        _say_kv "Gateway (local)" "https://${host}:${NOO_PORT_GATEWAY:-8080}" "  Gateway (local):    https://${host}:${NOO_PORT_GATEWAY:-8080}"
    else
        _say_kv "Gateway API" "https://${host}:${NOO_PORT_GATEWAY:-8080}" "  Gateway API:        https://${host}:${NOO_PORT_GATEWAY:-8080}"
    fi
    if [ "${1:-}" = "full" ]; then
        # https, all three: Grafana serves its own PKI leaf; Prometheus and
        # the GPU exporter are mTLS (a browser without a cluster leaf is
        # refused). The banner must name https:// for them —
        # the URL an operator pastes first must name the transport that
        # answers. Grafana publishes on NOO_GRAFANA_BIND_ADDR (loopback by
        # default), not the cluster-plane bind.
        local ghost="${NOO_GRAFANA_BIND_ADDR:-127.0.0.1}"
        case "$ghost" in 0.0.0.0|127.0.0.1) ghost="localhost" ;; esac
        # Advertised URL first, as for the gateway:
        # GRAFANA_ROOT_URL is what the browser dials (the MagicDNS name on a
        # tailnet bind); the bind-host form follows as the local one. .env is
        # not sourced by the launchers, so read it the way the bind is read.
        local groot="${GRAFANA_ROOT_URL:-$(_bind_env_value GRAFANA_ROOT_URL)}"
        if [ -n "$groot" ] && ! grep -q "://${ghost}:" <<<"$groot"; then
            _say_kv "Grafana" "$groot" "  Grafana:            $groot"
            _say_kv "Grafana (local)" "https://${ghost}:${NOO_PORT_GRAFANA:-3000}" "  Grafana (local):    https://${ghost}:${NOO_PORT_GRAFANA:-3000}"
        else
            _say_kv "Grafana" "https://${ghost}:${NOO_PORT_GRAFANA:-3000}" "  Grafana:            https://${ghost}:${NOO_PORT_GRAFANA:-3000}"
        fi
        _say_kv "Prometheus" "https://localhost:${NOO_PORT_PROMETHEUS:-9090} (mTLS: needs a cluster leaf)" "  Prometheus:         https://localhost:${NOO_PORT_PROMETHEUS:-9090} (mTLS: needs a cluster leaf)"
        _say_kv "GPU metrics" "https://${host}:${NOO_PORT_NVIDIA_EXPORTER:-9400}/metrics (mTLS: needs a cluster leaf)" "  GPU Metrics:        https://${host}:${NOO_PORT_NVIDIA_EXPORTER:-9400}/metrics (mTLS: needs a cluster leaf)"
    fi
    # Always https: NATS runs the one shipped config (nats-tls.conf —
    # an earlier change N9 put monitoring on `https_port` behind
    # `tls { verify: true }`, so reading it needs a cluster-CA CLIENT cert).
    # The plaintext profile and the NOO_NATS_CONFIG selector are gone;
    # noomesh-start.sh refuses a .env that still names one.
    #
    # The PORT is the HOST-published one, which is instance-offset
    # (lib-instance.sh: 8222 + offset). That is why this uses the variable:
    # anything hardcoding 8222 while dialling localhost is wrong on a second
    # instance. Code that dials the CONTAINER by name is not — the
    # container's own port is 8222 on every instance.
    _nats_mon_url="https://localhost:${NOO_PORT_NATS_MON:-8222}"
    _say_kv "NATS monitoring" "$_nats_mon_url" "  NATS Monitoring:    $_nats_mon_url"
    if declare -F ui_note >/dev/null 2>&1; then
        ui_note "NATS monitoring verifies client certs — curl needs --cert/--key/--cacert from the cluster PKI"
    fi
    _say_kv "PostgreSQL" "localhost:${POSTGRES_PORT:-5433}" "  PostgreSQL:         localhost:${POSTGRES_PORT:-5433}"
    if [ "$host" != "localhost" ]; then
        if declare -F ui_note >/dev/null 2>&1; then
            ui_note "bound to $host, not loopback — the https://localhost form will refuse; this node's MagicDNS URL works too (noo stack status prints it). Prometheus, NATS monitoring and Postgres are loopback-only by design"
        else
            echo ""
            echo "  (bound to $host, not loopback — the https://localhost form will"
            echo "   refuse. This node's MagicDNS URL works too (noo stack status). Prometheus,"
            echo "   NATS monitoring and Postgres are loopback-only by design.)"
        fi
    fi
}
