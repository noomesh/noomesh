#!/usr/bin/env bash
# SPDX-License-Identifier: AGPL-3.0-only
# Copyright 2026 PersonifAI LLC

# The `noo.inputs` mechanism against a REAL docker compose: a plain start
# recreates only the containers whose inputs changed.
#
#   NOO_TEST_IMAGE=<image@sha256:...> bash scripts/test-start-inputs/run.sh
#
# Needs docker with the compose v2 plugin, as a NON-root user in the docker
# group (case 6 makes a file unreadable, which root reads anyway). Drives the
# launcher's OWN functions: lib-ui.sh, lib-compose.sh, lib-stuck-container.sh
# and lib-start-inputs.sh are sourced and start_inputs_full_up is called,
# exactly as noomesh-start.sh calls it for a full start. Nothing here
# re-implements the labels or the `up`.
#
# The project (compose.yml beside this file): a takes a secret file, b
# bind-mounts a config file, c has neither and depends on a, d takes a's
# secret too. Each case prints
# one `START-INPUTS <n> PASS|FAIL: ...` line; the exit status is 1 when any
# case failed. Cleans up its project and temp dir on exit.
set -uo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SCRIPTS="$(cd "$HERE/.." && pwd)"

if [ "$(id -u)" = 0 ]; then
    echo "START-INPUTS: run this as a non-root user in the docker group (case 6 needs a file root cannot be kept from)" >&2
    exit 2
fi
case "${NOO_TEST_IMAGE:-}" in
    *@sha256:*) ;;
    *) echo "START-INPUTS: NOO_TEST_IMAGE must be a digest-pinned image (name@sha256:...)" >&2; exit 2 ;;
esac
docker compose version >/dev/null 2>&1 || { echo "START-INPUTS: docker compose v2 is not available" >&2; exit 2; }
command -v python3 >/dev/null || { echo "START-INPUTS: python3 is needed (the launcher's fingerprint helper)" >&2; exit 2; }

WORK="$(mktemp -d)"
export COMPOSE_PROJECT_NAME="noo-sitest-$$"
cleanup() {
    (cd "$WORK" 2>/dev/null && docker compose -f compose.yml down -v --remove-orphans -t 1 >/dev/null 2>&1)
    chmod -R u+rwX "$WORK" 2>/dev/null
    rm -rf "$WORK"
}
trap cleanup EXIT

cp "$HERE/compose.yml" "$WORK/compose.yml"
mkdir -p "$WORK/secrets"
printf 'alpha-secret-0001' > "$WORK/secrets/a.txt"
printf 'b-config-0001\n' > "$WORK/b.conf"
chmod 0644 "$WORK/secrets/a.txt" "$WORK/b.conf"
export NOO_START_INPUTS_KEY_FILE="$WORK/key/start-inputs.key"
cd "$WORK" || exit 2

# The launcher's libraries, as noomesh-start.sh sources them.
. "$SCRIPTS/lib-ui.sh"
. "$SCRIPTS/lib-compose.sh"
. "$SCRIPTS/lib-stuck-container.sh"
. "$SCRIPTS/lib-start-inputs.sh"

FAILED=0
pass() { echo "START-INPUTS $1 PASS: $2"; }
fail() { echo "START-INPUTS $1 FAIL: $2"; FAILED=1; }

# One launcher start, in a subshell like the launcher's own process (the
# override is appended to COMPOSE_FILES once per start). $1 = true for
# --recreate. The start's own output goes to $WORK/out.
start() {
    ( COMPOSE_FILES="-f compose.yml"; PROFILE_ARGS=""; START_RECREATE="${1:-false}"
      start_inputs_full_up ) > "$WORK/out" 2>&1
    local rc=$?
    sed 's/^/    | /' "$WORK/out"
    return "$rc"
}
ids() {  # "service id" per container of the project, sorted
    docker ps -aq --filter "label=com.docker.compose.project=$COMPOSE_PROJECT_NAME" \
        | xargs -r docker inspect -f '{{index .Config.Labels "com.docker.compose.service"}} {{.Id}}' | sort
}
moved() {  # services whose container id differs between two ids() outputs
    join -j1 <(printf '%s\n' "$1") <(printf '%s\n' "$2") | awk '$2 != $3 { print $1 }' | sort | tr '\n' ' ' | sed 's/ $//'
}
same_size_edit() {  # <file> <new content of the same length>: content changes, size and mtime do not
    local f="$1" ref
    ref="$(mktemp)"; touch -r "$f" "$ref"
    [ "$(printf '%s' "$2" | wc -c)" = "$(wc -c < "$f")" ] || { echo "same_size_edit: $2 is not the size of $f" >&2; return 1; }
    printf '%s' "$2" > "$f"
    touch -r "$ref" "$f"; rm -f "$ref"
}
expect() {  # <case> <expected moved set> <before> <after> <what>
    local got; got="$(moved "$3" "$4")"
    if [ "$got" = "$2" ]; then pass "$1" "$5: recreated [${got}]"; else fail "$1" "$5: expected [${2}] recreated, got [${got}]"; fi
}

echo "compose: $(docker compose version --short 2>/dev/null || docker compose version)"

# 1. start, then start again: nothing recreated, and the start says so.
start || fail 1 "the first start failed"
b1="$(ids)"
[ "$(printf '%s\n' "$b1" | grep -c .)" = 4 ] || fail 1 "expected 4 containers after the first start, got: $b1"
start || fail 1 "the second start failed"
a1="$(ids)"
expect 1 "" "$b1" "$a1" "start, then start again"
grep -q "4 running, 0 recreated" "$WORK/out" || fail 1 "the start did not say \"4 running, 0 recreated\""

# 2. a's secret CONTENT changes (same size, same mtime). b never moves: its
#    inputs did not change. c (depends on a, mounts no secret) is recreated
#    for ITS inputs only on newer compose; older compose (2.24.x, the
#    oldest the documented route installs) also recreates a recreated
#    service's dependents. Both are compose's own rule, so the job records
#    which this compose does instead of asserting one (first run 2026-11-20:
#    the runner's compose kept c, v2.24.6 recreated it).
# 8. ...and the secret's readers, a and d, are recreated, every time.
same_size_edit secrets/a.txt 'alpha-secret-0002'
start || fail 2 "the start failed"
a2="$(ids)"
got2=" $(moved "$a1" "$a2") "
case "$got2" in
    *" b "*) fail 2 "a's secret changed: b (inputs unchanged, no dependency) must stay, recreated [${got2# }]" ;;
    *" c "*) pass 2 "a's secret changed: b kept its container; this compose also recreated c, a's dependent (older compose behaviour)" ;;
    *) pass 2 "a's secret changed: b and c (a's dependent, no secret) kept their containers" ;;
esac
case "$got2" in *" a "*) r_a=1 ;; *) r_a=0 ;; esac
case "$got2" in *" d "*) r_d=1 ;; *) r_d=0 ;; esac
if [ "$r_a$r_d" = 11 ]; then pass 8 "a shared secret changed: both its readers (a, d) recreated: [${got2# }]"
else fail 8 "a shared secret changed: both its readers (a and d) must be recreated, got [${got2# }]"; fi
grep -q "recreated a: its inputs changed (config secrets/a.txt)" "$WORK/out" \
    && grep -q "recreated d: its inputs changed (config secrets/a.txt)" "$WORK/out" \
    || fail 8 "the start did not name the changed secret file for both readers"

# 3. b's bind-mounted file changes: b only.
same_size_edit b.conf 'b-config-0002
'
start || fail 3 "the start failed"
a3="$(ids)"
expect 3 "b" "$a2" "$a3" "b's mounted config file changed"
grep -q "recreated b: its inputs changed (config b.conf)" "$WORK/out" || fail 3 "the start did not name b.conf"

# 4. --recreate: all four.
start true || fail 4 "the start failed"
a4="$(ids)"
expect 4 "a b c d" "$a3" "$a4" "--recreate"
grep -q -- "--recreate: every container is recreated" "$WORK/out" && grep -q "recreated: a, b, c, d (forced: every container)" "$WORK/out" \
    || fail 4 "the start did not say --recreate forced every container"

# 5. the key is deleted: every label moves once, all recreated, and said.
#    The state file deleted: the labels are the mechanism, nothing moves.
rm -f "$NOO_START_INPUTS_KEY_FILE"
start || fail 5 "the start failed"
a5="$(ids)"
expect 5 "a b c d" "$a4" "$a5" "the start-inputs key was deleted"
grep -q "made a new start-inputs key" "$WORK/out" && grep -q "the start-inputs key is new" "$WORK/out" \
    || fail 5 "the start did not say the key is new"
rm -f .noo-start-inputs.json
start || fail 5 "the start failed"
a5b="$(ids)"
expect 5 "" "$a5" "$a5b" "the state file was deleted (it only names files)"
grep -q "4 running, 0 recreated" "$WORK/out" || fail 5 "the start did not say \"4 running, 0 recreated\""
grep -q "cannot name what changed: no previous record" "$WORK/out" || fail 5 "the start did not say the record is missing"

# 6. an unreadable input: b is recreated on every start, and it is said.
chmod 000 b.conf
start || fail 6 "the start failed"
a6="$(ids)"
expect 6 "b" "$a5b" "$a6" "b.conf unreadable (first start)"
start || fail 6 "the start failed"
a6b="$(ids)"
expect 6 "b" "$a6" "$a6b" "b.conf unreadable (every start)"
grep -q "cannot read config file $WORK/b.conf; b is recreated on every start" "$WORK/out" \
    || fail 6 "the start did not say b.conf cannot be read"
chmod 0644 b.conf
start >/dev/null || true
a6c="$(ids)"; start || true; a6d="$(ids)"
expect 6 "" "$a6c" "$a6d" "b.conf readable again (settled)"

# 7. no container label carries a plain sha256 of an input, nor 16 hex of one.
labels="$(docker ps -aq --filter "label=com.docker.compose.project=$COMPOSE_PROJECT_NAME" | xargs -r docker inspect -f '{{json .Config.Labels}}')"
n_labelled="$(printf '%s\n' "$labels" | grep -c '"noo.inputs":"[0-9a-f]\{64\}"')"
[ "$n_labelled" = 4 ] || fail 7 "expected a noo.inputs label on all 4 containers, found $n_labelled"
leak=""
digests="$(printf 'alpha-secret-0001' | sha256sum; printf 'alpha-secret-0002' | sha256sum
            printf 'b-config-0001\n' | sha256sum; printf 'b-config-0002\n' | sha256sum)"
for d in $(printf '%s\n' "$digests" | cut -d' ' -f1); do
    for off in $(seq 0 8 48); do
        printf '%s' "$labels" | grep -q "${d:$off:16}" && leak="$leak ${d:$off:16}"
    done
done
if [ -z "$leak" ]; then pass 7 "no label holds a plain sha256 of an input (or 16 hex of one)"; else fail 7 "labels hold digest material:$leak"; fi

if [ "$FAILED" = 0 ]; then echo "START-INPUTS: all cases PASS"; else echo "START-INPUTS: FAILED"; fi
exit "$FAILED"
