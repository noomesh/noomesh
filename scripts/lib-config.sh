#!/usr/bin/env bash
# SPDX-License-Identifier: AGPL-3.0-only
# Copyright 2026 PersonifAI LLC

# Export deployment configuration from noomesh.yaml into the environment,
# so `docker compose` can interpolate it.
#
# WHY THIS EXISTS
#
# Compose substitutes ${VAR} from the process environment or from `.env`, and
# from NOTHING ELSE — it cannot read a YAML file. So the 70-odd deployment
# knobs compose needs (node identity, image tags, model names, data paths,
# TLS toggles) were stuck in `.env` no matter how much of the rest of the
# system had graduated to noomesh.yaml. This closes that gap the same way
# `lib-secrets.sh` closed it for credentials: read the real source, export,
# let compose interpolate from the environment.
#
# With this, `.env` can shrink to almost nothing:
#   secrets           -> secrets/env.sops     (lib-secrets.sh)
#   deployment config -> noomesh.yaml       (this file)
#   `.env`            -> the bootstrap flags read BEFORE either can load
#
# THE SECTION
#
# A single flat map under `compose_env:`, keys named exactly as compose
# references them:
#
#   compose_env:
#     NODE_ID: noo-controller
#     VLLM_MODEL: google/gemma-4-12B-it-qat-w4a16-ct
#     NOO_DATA_ROOT: ~/noo
#
# Flat and explicitly ENV-shaped on purpose. The nested sections in this file
# (agent:, heartbeat:, …) are read by the APPLICATION through
# `config::env_or_yaml`, which resolves at runtime inside the container.
# These are different: they must exist as environment variables on the HOST
# before a container is created. Modelling them as nested config would imply
# an application read that never happens.
#
# PRECEDENCE — an already-set variable always wins
#
# If a var is already in the environment, it is left alone. That keeps
# `FOO=bar noo stack start` working as an override, and it makes the
# migration off `.env` incremental rather than a flag day.
#
# DRIFT IS LOUD
#
# A key present in BOTH `.env` and `compose_env:` is reported, every launch.
# Two sources for one value is the exact shape of the plaintext-secrets
# problem this programme just finished removing, and a silent winner is how
# a deployed value drifts from the one an operator is reading.

# Resolve the config file the same way the app does.
_config_file() {
    local f="${NOO_CONFIG_FILE:-}"
    if [ -n "$f" ] && [ -f "$f" ]; then printf '%s\n' "$f"; return 0; fi
    for f in ./noomesh.yaml "$HOME/.config/noo/noomesh.yaml"; do
        [ -f "$f" ] && { printf '%s\n' "$f"; return 0; }
    done
    return 1
}

# config_sed_in_place — `sed -E` over a file WITHOUT replacing its inode.
#
# `sed -i` writes a temp file and renames it over the target. On a dist
# install noomesh.yaml is bind-mounted into the containers as a SINGLE FILE
#, and a rename detaches that mount: the containers keep the
# old, now-unlinked inode (mountinfo shows `//deleted`) while the host path
# points at a new one. Every read agrees with the write that made it, nothing
# warns, and the next recreate re-binds the host file. So the edit is
# rendered to a temp file, then copied back with `cat >`, which truncates and
# rewrites the SAME inode. Not crash-atomic, same trade the gateway makes for
# the same file; the rendered copy is only written back when sed succeeded,
# so a failing sed never truncates the config.
config_sed_in_place() {
    local file="$1"; shift
    local tmp rc=0
    tmp="$(mktemp)" || return 1
    if sed -E "$@" "$file" > "$tmp"; then
        cat "$tmp" > "$file" || rc=$?
    else
        rc=$?
    fi
    rm -f "$tmp"
    return "$rc"
}

# noo_bin — the noo binary this launcher should call for its own internal
# noomesh.yaml reads (`noo config launch-render <section>`), preferred over
# `python3` + PyYAML.
#
# `noo` already parses `compose_env:`/`addons:` for its own purposes
# (envfile.rs, commands/addons.rs), and it is on every host that runs this
# launcher — it is what INVOKED it. `noo`'s own `run_script`/
# `run_script_streamed` export `NOO_CLI_BIN=<current_exe>` to the child so
# the launcher calls the SAME version that started it, not whatever else is
# on PATH; `command -v noo` is the fallback for a dev checkout where the
# script is run directly.
#
# Before this (2026-09-29 upgrade rehearsal): a newcomer host with neither
# `python3` nor PyYAML got `ModuleNotFoundError: No module named 'yaml'` on
# every `noo stack start`/`noo upgrade --stack`, and compose_env / the
# add-on map / the watched-folder mounts were silently skipped — the wizard
# never told the operator any of the three had failed to load.
noo_bin() {
    if [ -n "${NOO_CLI_BIN:-}" ] && [ -x "$NOO_CLI_BIN" ]; then
        printf '%s\n' "$NOO_CLI_BIN"
        return 0
    fi
    local p
    p="$(command -v noo 2>/dev/null || true)"
    if [ -n "$p" ]; then
        printf '%s\n' "$p"
        return 0
    fi
    return 1
}

load_config() {
    # Launcher sentinel (audit item 11): every sanctioned compose path
    # sources this before `up`, so the gateway can tell launcher recreates
    # (interpolation env present) from a bare `docker compose up` (which
    # bakes EMPTY secrets and cost a crash-loop diagnosis on 2026-08-06).
    # The compose file passes it through to the gateway; gateway startup
    # warns loudly when it is missing. A compose-level `:?` guard is the
    # documented anti-pattern here — it fires file-wide on ANY compose op
    # and breaks worker-node recreates.
    export NOO_LAUNCHED=1

    # Dev-only trellion source overlay (defect #20): with no sibling
    # noo-trellion checkout, the default mount would shadow the image's
    # baked trellion package with an empty docker-created dir ("No module
    # named 'trellion.db'"). Repoint both ends at scratch paths so the
    # mount is inert on non-dev machines.
    # Content check, not bare -d: a previous bare `up` may have left a
    # docker-created EMPTY dir at exactly this path.
    if [ ! -f "${TRELLION_PATH:-../noo-trellion}/src/trellion/__init__.py" ]; then
        export TRELLION_SRC="./.trellion-src-placeholder"
        export TRELLION_SRC_DEST="/tmp/.trellion-src-unused"
    fi

    local cfg
    if ! cfg="$(_config_file)"; then
        # No config file is legitimate (fresh checkout, CI): compose still has
        # `.env` and its own ${VAR:-default} fallbacks. Say so and continue.
        echo "config: no noomesh.yaml found — compose_env not loaded" >&2
        return 0
    fi

    local rendered nb
    # Emits `KEY=VALUE` lines, or `!ERR <msg>` on a parse failure. Values are
    # NOT shell-quoted here; the read loop below never evals them.
    #
    # `noo` is the primary reader (see noo_bin above): it already parses
    # this file for itself, so this is one parser instead of two, and it
    # needs no host python3/PyYAML. `noo`'s internal reader is fixed to
    # <repo_root>/noomesh.yaml, so it only covers the common case — cfg
    # resolved to the plain `./noomesh.yaml` in the launch directory; an
    # explicit $NOO_CONFIG_FILE or the ~/.config/noo fallback still goes
    # through python3 below (both are edge cases the noo binary does not
    # try to replicate).
    # An older noo on PATH without this subcommand fails here; fall through
    # to python3 rather than load nothing.
    if nb="$(noo_bin)" && rendered="$("$nb" config launch-render compose-env "$cfg" 2>/dev/null)"; then
        :
    elif command -v python3 >/dev/null 2>&1; then
    if ! rendered="$(python3 - "$cfg" <<'PY'
import sys

try:
    import yaml
except ImportError:
    print("!ERR pyyaml not installed")
    sys.exit(0)

try:
    with open(sys.argv[1]) as fh:
        doc = yaml.safe_load(fh) or {}
except Exception as exc:  # malformed YAML is worth failing loudly on
    # Collapse to ONE line. yaml's ParserError is multi-line, and the shell
    # read loop below is line-oriented: a stray continuation line was being
    # parsed as KEY=VALUE and hit `export: invalid variable name`, hiding the
    # actual parse error behind a confusing one.
    detail = " ".join(str(exc).split())
    print(f"!ERR {type(exc).__name__}: {detail}")
    sys.exit(0)

section = doc.get("compose_env") or {}
if not isinstance(section, dict):
    print("!ERR compose_env must be a mapping of ENV_VAR: value")
    sys.exit(0)

for key, value in section.items():
    if not isinstance(key, str) or not key.replace("_", "").isalnum():
        print(f"!ERR bad key {key!r} — must be a plain ENV_VAR name")
        continue
    if isinstance(value, (dict, list)):
        # `compose_env` is a FLAT map of env vars. A nested value used to be
        # str()'d, exporting a Python repr like `updates={'FOO': 'bar'}` — a
        # real variable with a nonsense value, and no sign anything was wrong.
        # That is how a mis-shaped config write hid (#337): the keys the
        # operator meant to set were one level down and simply never exported.
        print(f"!ERR {key} is a {type(value).__name__}, not a scalar — "
              "compose_env is a flat map of ENV_VAR: value")
        continue
    if value is None:
        value = ""
    elif isinstance(value, bool):
        # YAML `true` would otherwise export as "True", which no consumer
        # here parses. Compose/env convention is lowercase.
        value = "true" if value else "false"
    else:
        value = str(value)
    if "\n" in value:
        print(f"!ERR {key} has a multi-line value — not exportable")
        continue
    print(f"{key}={value}")
PY
    )"; then
        echo "config: failed to read $cfg — compose_env not loaded" >&2
        return 1
    fi
    else
        echo "config: neither the noo CLI nor python3+PyYAML found — compose_env not read from $cfg" >&2
        return 0
    fi

    local errors=0 exported=0 preset=0 line key value
    while IFS= read -r line; do
        [ -z "$line" ] && continue
        case "$line" in
            '!ERR '*)
                echo "config: ${line#!ERR }" >&2
                errors=$((errors + 1))
                continue
                ;;
        esac
        key="${line%%=*}"
        value="${line#*=}"
        # Belt and braces: never hand anything to `export` that isn't a valid
        # identifier. Without this, any unexpected line on stdout becomes an
        # `export: invalid variable name` that masks the real message.
        case "$key" in
            [A-Za-z_]*) : ;;
            *) echo "config: ignoring unparseable line: $line" >&2
               errors=$((errors + 1)); continue ;;
        esac
        if printf '%s' "$key" | grep -qE '[^A-Za-z0-9_]'; then
            echo "config: ignoring invalid variable name: $key" >&2
            errors=$((errors + 1)); continue
        fi
        # Already set (real env, or an earlier loader) — never clobber.
        if [ -n "${!key:-}" ]; then
            preset=$((preset + 1))
            continue
        fi
        export "$key=$value"
        exported=$((exported + 1))
    done <<EOF
$rendered
EOF

    if [ "$errors" -gt 0 ]; then
        echo "config: $errors problem(s) in $cfg compose_env — see above" >&2
        return 1
    fi

    # Drift check: the same key in two places, with a silent winner, is the
    # failure mode this whole split exists to remove.
    if [ -f .env ]; then
        local dup
        dup="$(printf '%s\n' "$rendered" | grep -v '^!ERR' | cut -d= -f1 \
               | while IFS= read -r k; do
                     [ -n "$k" ] && grep -qE "^[[:space:]]*${k}=" .env && printf '%s ' "$k"
                 done)"
        if [ -n "$dup" ]; then
            echo "config: WARNING — defined in BOTH .env and $cfg compose_env: $dup" >&2
            echo "config:           .env wins for compose interpolation. Remove from .env." >&2
        fi
    fi

    if declare -F ui_kv >/dev/null 2>&1; then ui_kv "Config" "$exported value(s) from $cfg compose_env${preset:+ $(ui_muted "(${preset} already set)")}" >&2; else echo "config: loaded $exported value(s) from $cfg compose_env${preset:+ (${preset} already set)}" >&2; fi
    return 0
}

# regen_compose_override — regenerate docker-compose.override.yml from the
# `watched_folders:`/`workspace:` sections of ./noomesh.yaml.
#
# Moved out of noomesh-start.sh (unchanged in behaviour) so it can be
# called from a test with a fake `noo` on NOO_CLI_BIN, without sourcing
# the whole launcher script (arg parsing, compose-file assembly, the
# add-on block…). noomesh-start.sh sources this file before calling it;
# nothing else here depends on that caller's state.
#
# The yaml is the source of truth: the dashboard edits watched_folders /
# workspace there but cannot touch this host file, so a stale override
# silently wins otherwise — the 2026-08-09 shape of that failure was a
# workspace mounted ONLY into the gateway (where the file executor no
# longer lives) and a writable:true folder still mounted :ro.
# Mounts go into BOTH gateway and trellion; writable folders and the
# workspace are :rw.
#
# `noo` is the primary reader: it already parses `noomesh.yaml` for itself
# (envfile.rs, commands/addons.rs) and is on every host that runs this
# launcher — it IS what invoked it (`noo_bin`, above). python3+PyYAML is
# the fallback for a dev checkout with no `noo` binary handy, OR for an
# older `noo` on PATH that lacks the `config launch-render` subcommand
# (its call below fails and this falls through to python3, same as
# `load_config`'s compose-env read). Written to a temp file first and
# moved into place only on success: `> docker-compose.override.yml` would
# truncate the existing file before the command even runs, losing the
# "keep the existing file on failure" guarantee a parse error is supposed
# to have. If BOTH readers fail (or neither is present), the existing
# docker-compose.override.yml is left byte-identical — never truncated,
# never partially written.
regen_compose_override() {
    local _ov_done=false _ov_nb
    if [ -f "noomesh.yaml" ] && _ov_nb="$(noo_bin 2>/dev/null)"; then
        # A failure here is either a parse error (python would fail the same
        # way) or an older noo without the subcommand — either way try
        # python3 next.
        if "$_ov_nb" config launch-render override noomesh.yaml > docker-compose.override.yml.tmp 2>/dev/null; then
            mv docker-compose.override.yml.tmp docker-compose.override.yml
            _ov_done=true
        else
            rm -f docker-compose.override.yml.tmp
        fi
    fi
    if [ "$_ov_done" = true ]; then
        return 0
    elif [ -f "noomesh.yaml" ] && command -v python3 >/dev/null 2>&1; then
        python3 - <<'PYOVR' || echo "override regen failed — keeping existing docker-compose.override.yml" >&2
import yaml

with open("noomesh.yaml") as f:
    cfg = yaml.safe_load(f) or {}

mounts = []
wf = cfg.get("watched_folders") or {}
if wf.get("enabled"):
    for folder in wf.get("folders") or []:
        host, mount = folder.get("host"), folder.get("mount")
        if host and mount:
            mode = "rw" if folder.get("writable") else "ro"
            mounts.append(f"{host}:{mount}:{mode}")
ws = cfg.get("workspace") or {}
if ws.get("enabled") and ws.get("host") and ws.get("mount"):
    mounts.append(f"{ws['host']}:{ws['mount']}:rw")

lines = ["# Auto-generated by noo stack start from noomesh.yaml — do not edit",
         "# (watched_folders + workspace; regenerated on every start)"]
if mounts:
    lines.append("services:")
    # trellion runs the file executor; the gateway keeps the mounts for
    # ingest/scan paths. Same list, same modes, both services.
    for svc in ("gateway", "trellion"):
        lines.append(f"  {svc}:")
        lines.append("    volumes:")
        lines.extend(f"      - {m}" for m in mounts)
else:
    lines.append("services: {}")

with open("docker-compose.override.yml", "w") as f:
    f.write("\n".join(lines) + "\n")
PYOVR
    elif [ -f "noomesh.yaml" ]; then
        echo "config: neither the noo CLI nor python3+PyYAML found — watched_folders/workspace mounts not read from noomesh.yaml (docker-compose.override.yml left as-is)" >&2
    fi
}

# operator_profile_args - `--profile X` for every profile the operator listed
# in COMPOSE_PROFILES (the environment first, else the stack's .env), comma-
# separated, deduplicated, names checked. Empty when none.
#
# Compose IGNORES COMPOSE_PROFILES as soon as one `--profile` flag is given,
# and the launcher always gives some (its own profile, the GPU tier). So a
# profile the operator enables the documented way (`COMPOSE_PROFILES=embed-cpu`
# in .env, the embed-capacity runbook) never started until the launcher
# passed it on itself. Used unquoted: the empty result expands to nothing.
operator_profile_args() {
    local raw="${COMPOSE_PROFILES:-}"
    if [ -z "$raw" ] && [ -f ".env" ]; then
        raw="$(grep -E '^[[:space:]]*COMPOSE_PROFILES=' .env | tail -1 | cut -d= -f2- | tr -d " \t\r\"'")"
    fi
    local out="" p
    local -a _ps=()
    IFS=',' read -ra _ps <<< "$raw"
    for p in "${_ps[@]}"; do
        p="${p//[[:space:]]/}"
        [ -n "$p" ] || continue
        if ! [[ "$p" =~ ^[A-Za-z0-9][A-Za-z0-9_.-]*$ ]]; then
            echo "WARN: COMPOSE_PROFILES entry '$p' is not a profile name; ignored" >&2
            continue
        fi
        case " $out " in
            *" --profile $p "*) ;;
            *) out="$out --profile $p" ;;
        esac
    done
    printf '%s' "${out# }"
}

# derive_profile_env - environment a declared profile implies, so the operator
# never restates it. Today: the `embed-cpu` profile starts the CPU embedder
# behind its mTLS door, and the gateway must then count that door as an embed
# target. Deriving the address keeps ONE declaration (the profile); a typed
# PAGEINDEX_EMBEDDING_EXTRA_URLS was a second home for the same fact, the kind
# that goes stale. An address the operator already lists is kept; the door is
# appended once. Call after load_config, before compose runs.
EMBED_CPU_DOOR_URL="https://noo-stunnel-ollama-embed-cpu:11434"
derive_profile_env() {
    case " $(operator_profile_args) " in
        *" --profile embed-cpu "*) ;;
        *) return 0 ;;
    esac
    local cur="${PAGEINDEX_EMBEDDING_EXTRA_URLS:-}"
    case ",$cur," in
        *",$EMBED_CPU_DOOR_URL,"*) ;;
        ",,") export PAGEINDEX_EMBEDDING_EXTRA_URLS="$EMBED_CPU_DOOR_URL" ;;
        *) export PAGEINDEX_EMBEDDING_EXTRA_URLS="$cur,$EMBED_CPU_DOOR_URL" ;;
    esac
}
