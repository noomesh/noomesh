#!/bin/bash
# SPDX-License-Identifier: AGPL-3.0-only
# Copyright 2026 PersonifAI LLC

# Mesh - Standby Controller Bootstrap (Postgres streaming replication)
#
# Stage-2 federation substrate: replicate the primary controller's Postgres
# (conversations, PageIndex KB, node registry, heartbeat tasks) to a warm
# standby at another site, over the Tailscale overlay. Scope is deliberately
# the DATA layer only — failover orchestration and NATS mirroring are later
# stages; this script is the foundation they build on. Manual promotion by
# design: no automatic failover means no split-brain.
#
# Subcommands:
#   prepare-primary                Run ON THE PRIMARY once. Creates the
#                                  replication role, confirms the shipped
#                                  pg_hba admits replication over TLS with a
#                                  cluster-CA client certificate, bounds WAL
#                                  retention, saves the replication password
#                                  to .env, and checks the standby's leaf.
#   join --primary <host>          Run ON THE STANDBY machine (repo cloned,
#                                  Docker installed, on the tailnet).
#                                  Syncs env.sops + PKI from the primary,
#                                  takes a base backup presenting the
#                                  `postgres-standby` leaf, starts Postgres
#                                  as a streaming replica. <host> must be a
#                                  name the primary's postgres leaf carries
#                                  (its tailnet name or hostname):
#                                  sslmode=verify-full checks it.
#   status                         Show replication state (works on either
#                                  side); on a standby whose receiver is
#                                  down, says whether the primary refused
#                                  its certificate.
#   promote                        Run ON THE STANDBY to take over as
#                                  primary (e.g. primary site is down).
#
# Typical flow:
#   primary$  ./scripts/bootstrap-standby.sh prepare-primary
#   primary$  # set POSTGRES_BIND=<primary 100.x IP> in .env, then:
#   primary$  docker compose -f docker-compose.cluster.yml up -d postgres
#   standby$  ./scripts/bootstrap-standby.sh join --primary <primary tailnet name> --ssh-user <user>
#
# Requires the tailnet ACL to allow standby → primary on the Postgres port
# (see the commented controller→controller rule in config/tailscale-acl.hujson).

set -euo pipefail

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
NC='\033[0m'

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
ENV_FILE="${NOO_ENV_FILE:-$REPO_ROOT/.env}"   # override for tests
COMPOSE_FILE="$REPO_ROOT/docker-compose.cluster.yml"
# Dist overlay (#43b): postgres is `pull_policy: build` in the base file, so
# the standby bring-up on a dist install (no shipped Dockerfiles) died in a
# postgres build attempt. COMPOSE_ARGS is what the compose call below uses.
source "$REPO_ROOT/scripts/lib-dist.sh"
apply_dist_mode "$REPO_ROOT"
# Same resolution as the compose overlay, for the two raw `docker run` calls
# below. They hardcoded `pai-assistant/postgres-pgvector:latest` — a name not
# built since 2026-09-06 — while this script was already sourcing lib-dist.sh
# and getting the compose path right, so a dist standby died at base backup.
PG_IMAGE="${NOO_PG_IMAGE:-$(resolve_release_image postgres-pgvector)}"
# The file list has ONE home; the standby composes
# exactly what the primary composes, and only starts postgres from it.
source "$REPO_ROOT/scripts/lib-compose.sh"
COMPOSE_ARGS=()
while IFS= read -r _cf; do [ -n "$_cf" ] && COMPOSE_ARGS+=(-f "$_cf"); done < <(cd "$REPO_ROOT" && compose_file_list "$REPO_ROOT")
UP_FLAGS=()
if [ "${DIST_MODE:-0}" = 1 ]; then
    # dev standbys legitimately build postgres on first bring-up; only a
    # dist install must never fall back to building.
    UP_FLAGS=(--no-build)
fi

CONTAINER="noo-postgres"
REPL_USER="replicator"
PRIMARY_HOST=""
PRIMARY_PORT="5433"          # host-published Postgres port on the primary
SSH_USER="${USER:-root}"
# The standby's replication identity: a cluster-CA
# client leaf issued on the primary by `noo onboard` / `noo upgrade --stack`
# (onboard's SVC_LIST), reaching this box with the PKI sync in `join`.
STANDBY_LEAF="services/postgres-standby"
# Where the leaf is staged inside the standby's data volume, next to the
# .pgpass: owned by the postgres uid, key 0600 — libpq refuses anything wider.
STANDBY_TLS_DIR="/var/lib/postgresql/data/standby-tls"
SLOT_NAME="standby_$(hostname | tr -c 'a-zA-Z0-9' '_' | sed 's/_*$//')"

usage() {
    sed -n '2,36p' "${BASH_SOURCE[0]}" | sed 's/^# \{0,1\}//'
    exit 1
}

env_get() {  # env_get KEY [default]
    local val=""
    [ -f "$ENV_FILE" ] && val="$(grep -E "^$1=" "$ENV_FILE" | tail -1 | cut -d= -f2- || true)"
    echo "${val:-${2:-}}"
}

pki_dir() {  # the PKI dir: $NOO_PKI_DIR, else .env's, else <repo>/pki
    echo "${NOO_PKI_DIR:-$(env_get NOO_PKI_DIR "$REPO_ROOT/pki")}"
}

env_set() {  # env_set KEY VALUE — update or append in .env
    # awk, not sed: a value containing `|`, `&` or `\` corrupts the line under
    # `sed s|...|...|`, and this function's only caller writes a PASSWORD.
    # Same reasoning (and same fix) as scripts/noo-backup-rotate-passphrase.sh.
    local key="$1" val="$2" tmp
    tmp="$(mktemp "${ENV_FILE}.XXXXXX")"
    chmod 600 "$tmp"
    if grep -qE "^$key=" "$ENV_FILE" 2>/dev/null; then
        awk -v k="$key" -v v="$val" 'BEGIN{FS="="} $1==k{print k "=" v; next} {print}' \
            "$ENV_FILE" > "$tmp"
    else
        { [ -f "$ENV_FILE" ] && cat "$ENV_FILE"; printf '\n%s=%s\n' "$key" "$val"; } > "$tmp"
    fi
    mv "$tmp" "$ENV_FILE"
    # .env holds credentials; it has no business being group- or world-readable.
    chmod 600 "$ENV_FILE"
}

# psql, with the SQL on STDIN rather than in argv (tracker R27). `docker exec
# … -tAc "ALTER ROLE … PASSWORD 'secret'"` puts the password in the docker
# daemon's exec record and in /proc/<pid>/cmdline.
psql_stdin() {  # psql_stdin <container>  — SQL on stdin
    docker exec -i "$1" psql -U "$(env_get POSTGRES_USER noo)" -d "$(env_get POSTGRES_DB noo)" -tAqf -
}

psql_c() {  # psql_c <container> <sql>
    docker exec "$1" psql -U "$(env_get POSTGRES_USER noo)" -d "$(env_get POSTGRES_DB noo)" -tAc "$2"
}

ASSUME_YES=false
CMD="${1:-}"; shift || true
while [ $# -gt 0 ]; do
    case "$1" in
        --primary)   PRIMARY_HOST="$2"; shift 2 ;;
        --port)      PRIMARY_PORT="$2"; shift 2 ;;
        --ssh-user)  SSH_USER="$2"; shift 2 ;;
        --container) CONTAINER="$2"; shift 2 ;;
        --slot)      SLOT_NAME="$2"; shift 2 ;;
        --yes|-y)    ASSUME_YES=true; shift ;;
        -h|--help)   usage ;;
        *)           echo -e "${RED}Unknown argument: $1${NC}"; usage ;;
    esac
done

case "$CMD" in

# ── Run on the PRIMARY controller ──────────────────────────────────────
prepare-primary)
    echo -e "${CYAN}Preparing $CONTAINER as a replication primary...${NC}"
    docker inspect "$CONTAINER" >/dev/null 2>&1 || {
        echo -e "${RED}ERROR: container $CONTAINER is not running${NC}"; exit 1; }

    REPL_PW="$(env_get NOO_REPLICATION_PASSWORD)"
    if [ -z "$REPL_PW" ]; then
        REPL_PW="$(head -c 32 /dev/urandom | sha256sum | cut -c1-32)"
        env_set NOO_REPLICATION_PASSWORD "$REPL_PW"
        echo -e "${GREEN}✓ Replication password generated → .env (NOO_REPLICATION_PASSWORD)${NC}"
    else
        echo -e "${GREEN}✓ Using existing NOO_REPLICATION_PASSWORD from .env${NC}"
    fi

    if [ "$(psql_c "$CONTAINER" "SELECT 1 FROM pg_roles WHERE rolname='$REPL_USER'")" = "1" ]; then
        printf "ALTER ROLE %s WITH REPLICATION LOGIN PASSWORD '%s';\n" "$REPL_USER" "$REPL_PW" \
            | psql_stdin "$CONTAINER" > /dev/null
        echo -e "${GREEN}✓ Replication role '$REPL_USER' updated${NC}"
    else
        printf "CREATE ROLE %s WITH REPLICATION LOGIN PASSWORD '%s';\n" "$REPL_USER" "$REPL_PW" \
            | psql_stdin "$CONTAINER" > /dev/null
        echo -e "${GREEN}✓ Replication role '$REPL_USER' created${NC}"
    fi

    # Replication is admitted by the SHIPPED pg_hba (docker/postgres/
    # pg_hba.conf, mounted read-only): `hostssl replication … scram-sha-256
    # clientcert=verify-ca`. This used to append a password-only
    # `host replication … scram-sha-256` line to the data volume's pg_hba —
    # which the server no longer reads, on a mount that is read-only, and
    # which would have been the one door with no certificate for the role
    # that can read every byte. Confirm, never append.
    HBA_FILE="$(psql_c "$CONTAINER" 'SHOW hba_file')"
    if docker exec "$CONTAINER" grep -qE '^hostssl[[:space:]]+replication[[:space:]].*clientcert=verify-ca' "$HBA_FILE"; then
        echo -e "${GREEN}✓ pg_hba ($HBA_FILE): replication over TLS with a cluster-CA client certificate${NC}"
    else
        echo -e "${RED}ERROR: $HBA_FILE has no 'hostssl replication … clientcert=verify-ca' rule — this primary runs an older pg_hba; noo upgrade --stack re-materialises docker/postgres/pg_hba.conf${NC}"
        exit 1
    fi

    # The standby's client leaf. Onboard and `noo upgrade --stack` issue it
    # (SVC_LIST); `join` carries it over with the PKI.
    if [ -f "$(pki_dir)/$STANDBY_LEAF/service.crt" ] && [ -f "$(pki_dir)/$STANDBY_LEAF/service.key" ]; then
        echo -e "${GREEN}✓ standby client leaf present ($(pki_dir)/$STANDBY_LEAF)${NC}"
    else
        echo -e "${RED}ERROR: no standby client leaf at $(pki_dir)/$STANDBY_LEAF — issue it: noo security pki issue-service postgres-standby${NC}"
        exit 1
    fi

    # Bound WAL kept for replication slots so a long-dead standby cannot
    # fill the primary's disk (slot itself is created by the standby's
    # pg_basebackup -C).
    psql_c "$CONTAINER" "ALTER SYSTEM SET max_slot_wal_keep_size = '2GB'" > /dev/null
    psql_c "$CONTAINER" "SELECT pg_reload_conf()" > /dev/null
    echo -e "${GREEN}✓ WAL retention bounded (max_slot_wal_keep_size=2GB)${NC}"

    echo ""
    echo -e "${CYAN}Primary is ready. Two manual follow-ups:${NC}"
    echo "  1. Publish Postgres on the overlay: set in .env"
    echo "       POSTGRES_BIND=<this controller's 100.x IP>"
    echo "     then: docker compose ${COMPOSE_FILES[*]} up -d postgres"
    echo "  2. Allow standby → primary :${PRIMARY_PORT} in config/tailscale-acl.hujson"
    echo "     (uncomment the controller-to-controller replication rule) and re-push."
    ;;

# ── Run on the STANDBY machine ─────────────────────────────────────────
join)
    [ -n "$PRIMARY_HOST" ] || { echo -e "${RED}ERROR: --primary <host> is required${NC}"; exit 1; }

    echo -e "${CYAN}Syncing from primary ($SSH_USER@$PRIMARY_HOST)...${NC}"
    # The ENCRYPTED store and the PKI — never the plaintext .env.
    #
    # This used to `scp` the primary's whole `.env`: every credential on the
    # controller, in the clear, over an ad-hoc SSH session, landing in a file
    # whose mode scp does not even preserve (tracker R27). The standby needs
    # the same secrets, but `secrets/env.sops` IS those secrets, encrypted —
    # copying ciphertext costs nothing. What it cannot get this way is the age
    # key that opens it, and that is the point: the operator installs the age
    # key from their OFF-BOX backup (the one backup-controller.sh writes),
    # which is the same act as any other disaster recovery.
    rsync -a "$SSH_USER@$PRIMARY_HOST:$REPO_ROOT/secrets/env.sops" "$REPO_ROOT/secrets/env.sops" \
        || { echo -e "${RED}ERROR: could not sync secrets/env.sops from the primary${NC}"; exit 1; }
    rsync -a "$SSH_USER@$PRIMARY_HOST:$REPO_ROOT/.sops.yaml" "$REPO_ROOT/.sops.yaml" 2>/dev/null || true
    # stderr is NOT discarded here: pki/ carries this box's identity to the
    # fleet, and "the standby is a stranger the workers correctly refuse" is
    # not a failure mode to debug from a one-line warning.
    rsync -a --delete "$SSH_USER@$PRIMARY_HOST:$REPO_ROOT/pki/" "$REPO_ROOT/pki/" \
        || echo -e "${YELLOW}WARNING: could not sync pki/ (no PKI on primary, or rsync missing)${NC}"
    echo -e "${GREEN}✓ env.sops + PKI synced${NC}"

    # Open the store with THIS machine's age key. If it is not here, say so and
    # say where it comes from — do not fall back to a plaintext copy.
    # shellcheck source=scripts/lib-secrets.sh
    . "$REPO_ROOT/scripts/lib-secrets.sh" 2>/dev/null || true
    if ! load_secrets >/dev/null 2>&1; then
        echo -e "${RED}ERROR: cannot decrypt $REPO_ROOT/secrets/env.sops on this machine.${NC}"
        echo "The standby needs the SAME age private key as the primary. Restore it from"
        echo "your off-box backup before running join:"
        echo "  BACKUP_PASS='<NOO_AGE_BACKUP_PASSPHRASE>' openssl enc -d -aes-256-cbc -pbkdf2 \\"
        echo "      -in age-key_<ts>.txt.enc -out ~/.config/sops/age/keys.txt && chmod 600 ~/.config/sops/age/keys.txt"
        echo "See docs/operating/runbooks/backup-restore-secrets.md."
        exit 1
    fi
    # This machine binds its own addresses, not the primary's.
    [ -f "$ENV_FILE" ] && sed -i '/^POSTGRES_BIND=/d' "$ENV_FILE"

    # The client leaf this standby presents, from the PKI just synced.
    LEAF_DIR=""
    for d in "$REPO_ROOT/pki" "$(pki_dir)"; do
        if [ -f "$d/$STANDBY_LEAF/service.crt" ] && [ -f "$d/$STANDBY_LEAF/service.key" ] && [ -f "$d/ca.crt" ]; then
            LEAF_DIR="$d"; break
        fi
    done
    [ -n "$LEAF_DIR" ] || { echo -e "${RED}ERROR: no $STANDBY_LEAF leaf in the synced PKI — on the primary run: noo security pki issue-service postgres-standby — then re-run join${NC}"; exit 1; }

    REPL_PW="${NOO_REPLICATION_PASSWORD:-$(env_get NOO_REPLICATION_PASSWORD)}"
    [ -n "$REPL_PW" ] || { echo -e "${RED}ERROR: the store has no NOO_REPLICATION_PASSWORD — run prepare-primary on the primary first, and re-encrypt its .env into secrets/env.sops${NC}"; exit 1; }

    VOLUME="$(basename "$REPO_ROOT")_postgres-data"
    if docker volume inspect "$VOLUME" >/dev/null 2>&1; then
        echo -e "${RED}ERROR: volume $VOLUME already exists on this machine.${NC}"
        echo "A standby must start from a fresh base backup. If this machine has an"
        echo "old/abandoned Postgres volume, remove it first:"
        echo "  docker compose ${COMPOSE_FILES[*]} down postgres && docker volume rm $VOLUME"
        exit 1
    fi

    echo -e "${CYAN}Taking base backup from $PRIMARY_HOST:$PRIMARY_PORT (slot: $SLOT_NAME)...${NC}"
    # --user root: the hardened image defaults to the postgres user, which
    # cannot chown the fresh (root-owned) volume
    # The password reaches the container as PGPASSWORD, passed through from
    # this shell's environment by `-e PGPASSWORD` with NO `=value` — so it is
    # not in `docker run`'s argv, not in the container's Config.Cmd, and not in
    # `docker inspect`. It used to be spelled `password=$REPL_PW` inside the
    # conninfo string, which `-R` then copied verbatim into
    # postgresql.auto.conf in the data volume (tracker R27). `passfile=` here
    # keeps it out of that file too; the .pgpass is written below, on stdin.
    #
    # TLS: the primary's pg_hba requires TLS AND a client
    # certificate chaining to the cluster CA for replication, so the backup
    # presents the `postgres-standby` leaf with sslmode=verify-full. libpq
    # wants the key owned by the connecting uid and 0600, so it is staged to
    # /tmp as postgres for the backup, then into the data volume
    # ($STANDBY_TLS_DIR) for the WAL receiver, and the primary_conninfo that
    # -R wrote is pointed there.
    if ! PGPASSWORD="$REPL_PW" \
        docker run --rm --user root -e PGPASSWORD -v "$VOLUME":/var/lib/postgresql/data \
        -v "$LEAF_DIR/$STANDBY_LEAF":/standby-leaf:ro -v "$LEAF_DIR/ca.crt":/standby-ca.crt:ro \
        --entrypoint sh "$PG_IMAGE" -c "
            chown postgres:postgres /var/lib/postgresql/data &&
            chmod 0700 /var/lib/postgresql/data &&
            umask 077 && mkdir -p /tmp/standby-tls &&
            cp /standby-leaf/service.crt /tmp/standby-tls/client.crt &&
            cp /standby-leaf/service.key /tmp/standby-tls/client.key &&
            cp /standby-ca.crt /tmp/standby-tls/ca.crt &&
            chown -R postgres:postgres /tmp/standby-tls && chmod 600 /tmp/standby-tls/client.key &&
            DROP=\$(command -v su-exec || command -v gosu) &&
            \$DROP postgres pg_basebackup \
                -d 'host=$PRIMARY_HOST port=$PRIMARY_PORT user=$REPL_USER passfile=/var/lib/postgresql/data/.pgpass sslmode=verify-full sslrootcert=/tmp/standby-tls/ca.crt sslcert=/tmp/standby-tls/client.crt sslkey=/tmp/standby-tls/client.key' \
                -D /var/lib/postgresql/data -X stream -C -S '$SLOT_NAME' -R -P &&
            mkdir -p $STANDBY_TLS_DIR &&
            cp /tmp/standby-tls/client.crt /tmp/standby-tls/client.key /tmp/standby-tls/ca.crt $STANDBY_TLS_DIR/ &&
            chown -R postgres:postgres $STANDBY_TLS_DIR && chmod 700 $STANDBY_TLS_DIR && chmod 600 $STANDBY_TLS_DIR/client.key &&
            sed -i 's#/tmp/standby-tls/#$STANDBY_TLS_DIR/#g' /var/lib/postgresql/data/postgresql.auto.conf &&
            grep -q 'sslcert=$STANDBY_TLS_DIR/client.crt' /var/lib/postgresql/data/postgresql.auto.conf"; then
        docker volume rm "$VOLUME" > /dev/null 2>&1 || true
        echo -e "${RED}Base backup failed.${NC} If the error mentions an existing"
        echo "replication slot (stale from an earlier attempt), drop it on the primary:"
        echo "  docker exec noo-postgres psql -U noo -d noomesh -c \"SELECT pg_drop_replication_slot('$SLOT_NAME')\""
        exit 1
    fi
    # The standby streams as `replicator` forever after; primary_conninfo now
    # names a passfile instead of carrying the password, so write it — 0600,
    # owned by postgres, content on STDIN.
    printf '%s:%s:*:%s:%s\n' "$PRIMARY_HOST" "$PRIMARY_PORT" "$REPL_USER" "$REPL_PW" \
        | docker run --rm -i --user root -v "$VOLUME":/var/lib/postgresql/data \
            --entrypoint sh "$PG_IMAGE" -c '
                umask 077 &&
                cat > /var/lib/postgresql/data/.pgpass &&
                chown postgres:postgres /var/lib/postgresql/data/.pgpass' \
        || { echo -e "${RED}ERROR: could not write the replication passfile${NC}"; exit 1; }
    echo -e "${GREEN}✓ Base backup complete (standby.signal + primary_conninfo + passfile + client leaf in $STANDBY_TLS_DIR)${NC}"

    echo -e "${CYAN}Starting Postgres as a streaming replica...${NC}"
    docker compose "${COMPOSE_ARGS[@]}" up -d ${UP_FLAGS[@]+"${UP_FLAGS[@]}"} postgres
    sleep 5
    if [ "$(psql_c "$CONTAINER" 'SELECT pg_is_in_recovery()')" = "t" ]; then
        echo -e "${GREEN}✓ Standby is streaming from $PRIMARY_HOST${NC}"
    else
        echo -e "${RED}ERROR: container started but is not in recovery — check docker logs $CONTAINER${NC}"
        exit 1
    fi

    echo ""
    echo -e "${CYAN}Warm standby established.${NC} It stays read-only and current until"
    echo -e "promoted. To take over when the primary site is down:"
    echo -e "  ${CYAN}./scripts/bootstrap-standby.sh promote${NC}"
    ;;

# ── Either side ────────────────────────────────────────────────────────
status)
    if [ "$(psql_c "$CONTAINER" 'SELECT pg_is_in_recovery()')" = "t" ]; then
        echo -e "Role: ${YELLOW}STANDBY${NC} (read-only, streaming)"
        docker exec "$CONTAINER" psql -U "$(env_get POSTGRES_USER noo)" -d "$(env_get POSTGRES_DB noo)" -xc \
            "SELECT status, sender_host, received_lsn, last_msg_receipt_time FROM pg_stat_wal_receiver"
        # No receiver row = not streaming. The one cause worth naming: the
        # primary refused the certificate (or this standby has none — a
        # standby joined before an earlier change streams with sslmode=prefer
        # and no leaf, and a primary rolled since refuses it).
        if [ "$(psql_c "$CONTAINER" 'SELECT count(*) FROM pg_stat_wal_receiver')" = "0" ]; then
            REFUSAL="$(docker logs --since 30m "$CONTAINER" 2>&1 | grep -iE 'client certificate|certificate verify failed|sslcert|ssl error|does not match host name' | tail -1 || true)"
            if [ -n "$REFUSAL" ]; then
                echo -e "${RED}WAL receiver is down: the primary refused this standby's TLS certificate.${NC}"
                echo "  $REFUSAL"
                echo "  The standby presents $STANDBY_LEAF from $STANDBY_TLS_DIR. A standby joined before it"
                echo "  had one must be re-joined: remove its postgres volume, then run join again."
            else
                echo -e "${YELLOW}WAL receiver is down; its log names no certificate problem (docker logs $CONTAINER).${NC}"
            fi
        fi
    else
        echo -e "Role: ${GREEN}PRIMARY${NC}"
        docker exec "$CONTAINER" psql -U "$(env_get POSTGRES_USER noo)" -d "$(env_get POSTGRES_DB noo)" -xc \
            "SELECT application_name, client_addr, state, sent_lsn, replay_lsn, replay_lag FROM pg_stat_replication"
    fi
    ;;

promote)
    if [ "$(psql_c "$CONTAINER" 'SELECT pg_is_in_recovery()')" != "t" ]; then
        echo -e "${YELLOW}This node is already a primary — nothing to promote${NC}"; exit 0
    fi
    echo -e "${YELLOW}Promoting this standby to PRIMARY.${NC}"
    echo "Make sure the old primary is actually down (or its Postgres stopped) —"
    echo "two live primaries diverge and cannot be merged."
    if [ "$ASSUME_YES" != true ]; then
        read -r -p "Promote? [y/N] " REPLY
        case "$REPLY" in [yY]*) ;; *) echo "Aborted."; exit 1 ;; esac
    fi
    psql_c "$CONTAINER" "SELECT pg_promote(true, 60)" > /dev/null
    echo -e "${GREEN}✓ Promoted — Postgres is now read-write on this site${NC}"
    echo ""
    echo "Follow-ups (manual for now — stage-2 failover orchestration):"
    echo "  1. Start the full controller stack here: noo stack start"
    echo "  2. Re-home workers: point their 'noo-controller' /etc/hosts entry at"
    echo "     this machine's 100.x IP (noo cluster update-controller-ip, or re-enroll"
    echo "     the node). MagicDNS name for the controller makes this a no-op later."
    echo "  3. When the old site returns, DO NOT restart its Postgres as primary —"
    echo "     rebuild it as the new standby: bootstrap-standby.sh join --primary <this-ip>"
    ;;

*)
    usage
    ;;
esac
