#!/usr/bin/env bash
# SPDX-License-Identifier: AGPL-3.0-only
# Copyright 2026 PersonifAI LLC

# Assert the INVARIANTS of the agent identity plane against a LIVE gateway
#.
#
# Everything in that plane is currently proven by unit tests and by nothing
# else: no gateway deploy has run it. Unit tests pin pure decisions — a TTL
# clamp, an ownership predicate — and cannot see the two failures that
# matter here, because both are failures of WIRING rather than of logic:
#
#   * a guard that is correct and never called;
#   * a credential that mints and then does not work.
#
# Invariants, not a diff: each check is true of every correctly-configured
# install, so the same script means the same thing on a laptop, on the
# controller, and in a customer's cluster.
#
# Usage:
#   scripts/verify-identity-plane.sh https://controller:8080
#
# Environment:
#   NOO_TOKEN        operator JWT. USUALLY UNNECESSARY: when unset this
#                    reads the credential `noo auth login` already wrote
#                    (~/.config/mesh/credentials.json), and says so if it
#                    has expired. Set it to override, e.g. in CI.
#   NOO_PROV_KEY     an `identity`-scoped service key bound to NOO_PROV_USER
#   NOO_PROV_USER    the account that key is bound to
#   TEST_PERSONA     account to mint for; must be manageable by NOO_PROV_USER
#   ~/.config/mesh/verify-plane.env
#                    sourced when NOO_PROV_KEY is unset — put the two
#                    provisioning lines there ONCE instead of exporting
#                    them every run:
#                      NOO_PROV_KEY=noo-sk-...
#                      NOO_PROV_USER=<the account that key is bound to>
#
#   --e2e            same as HARNESS_E2E=1 (creates a task)
#   --destructive    same as DESTRUCTIVE=1
#
#   DESTRUCTIVE=1    also run the kill-switch check, which DISABLES
#                    TEST_PERSONA and re-enables it. Off by default.
set -uo pipefail

# Flags, so the opt-in checks do not need an env var every time. The env
# vars still work: this script is run from CI too, where a flag is harder
# to thread than an export.
_pos=()
for _a in "$@"; do
  case "$_a" in
    --e2e)         HARNESS_E2E=1 ;;
    --destructive) DESTRUCTIVE=1 ;;
    *)             _pos+=("$_a") ;;
  esac
done
set -- "${_pos[@]+"${_pos[@]}"}"
BASE="${1:?usage: verify-identity-plane.sh <base-url> [--e2e] [--destructive]}"
PERSONA="${TEST_PERSONA:-identity-smoke}"

# ── credentials without the ceremony ────────────────────────────────────
# Every run of this used to start with three exports, and an operator who
# forgot one got a section quietly SKIPPED rather than a failure — the
# worst outcome for a script whose job is to tell you what is broken
# (2026-09-21).
#
# So: fall back to what the CLI already knows. `noo auth login` writes a
# per-user credential; read the token straight out of that file rather
# than adding a verb that prints a bearer token to stdout, where it would
# land in shell history and terminal scrollback. An explicit NOO_TOKEN
# still wins, so CI and a different identity are unaffected.
if [ -z "${NOO_TOKEN:-}" ]; then
  _cred="${NOO_CREDENTIALS_FILE:-${XDG_CONFIG_HOME:-$HOME/.config}/mesh/credentials.json}"
  if [ -r "$_cred" ]; then
    NOO_TOKEN="$(jq -r '.access_token // empty' "$_cred" 2>/dev/null)"
    _exp="$(jq -r '.expires_at // 0' "$_cred" 2>/dev/null)"
    if [ -n "$NOO_TOKEN" ] && [ "${_exp:-0}" -gt 0 ] && [ "$_exp" -lt "$(date +%s)" ]; then
      echo "note: the stored credential expired $(( ($(date +%s) - _exp) / 60 )) min ago — run \`noo auth login\`" >&2
      NOO_TOKEN=""
    fi
    [ -n "$NOO_TOKEN" ] && export NOO_TOKEN
  fi
fi
# The provisioning key, same idea: named once in a file rather than
# exported every run. Anything the operator exports still wins.
if [ -z "${NOO_PROV_KEY:-}" ] && [ -r "${HOME}/.config/mesh/verify-plane.env" ]; then
  # shellcheck disable=SC1090
  . "${HOME}/.config/mesh/verify-plane.env"
fi
PASS=0; FAIL=0
ok()   { printf '  \033[32mok\033[0m   %s\n' "$1"; PASS=$((PASS+1)); }
bad()  { printf '  \033[31mFAIL\033[0m %s\n' "$1"; FAIL=$((FAIL+1)); }
note() { printf '       %s\n' "$1"; }

# `-w %{http_code}` with the body kept: several checks assert on the STATUS,
# and a refusal that returns 200 with an error field is the exact shape this
# repo has been removing all week.
call() { # call <method> <path> <bearer> [json]
  local m=$1 p=$2 auth=$3 data=${4:-}
  if [ -n "$data" ]; then
    curl -sS -X "$m" "$BASE$p" -H "Authorization: Bearer $auth" \
      -H 'Content-Type: application/json' -d "$data" -w $'\n%{http_code}' 2>/dev/null
  else
    curl -sS -X "$m" "$BASE$p" -H "Authorization: Bearer $auth" -w $'\n%{http_code}' 2>/dev/null
  fi
}
body()   { sed '$d' <<<"$1"; }
status() { tail -n1 <<<"$1"; }

echo "identity plane · $BASE"

# ── 1. The add-on is actually on ────────────────────────────────────────
# WITH THE TOKEN. `/health` answers anyone, but the add-on map is only in
# the authenticated body — anonymously it is liveness and nothing else.
h=$(curl -sS ${NOO_TOKEN:+-H "Authorization: Bearer $NOO_TOKEN"} "$BASE/health" 2>/dev/null)
state=$(jq -r '.addons.identity // "absent"' <<<"$h" 2>/dev/null)
case "$state" in
  enabled) ok "add-on enabled" ;;
  unlicensed) bad "add-on flagged on but UNLICENSED — install an entitlement granting 'identity'"; ;;
  disabled) bad "add-on disabled — set addons.identity: true in noomesh.yaml"; ;;
  absent)
    if [ -z "${NOO_TOKEN:-}" ]; then
      bad "/health reported no add-on map and this script sent no credential — run \`noo auth login\`, or set NOO_TOKEN"
    else
      bad "/health does not report addons.identity even with a credential — wrong build?"
    fi ;;
  *) bad "/health does not report addons.identity (state=$state) — wrong build?" ;;
esac
[ "$state" = "enabled" ] || { echo; echo "stopping: nothing below can pass"; exit 1; }

# ── 2. Discovery and JWKS are reachable UNAUTHENTICATED ─────────────────
# The point of discovery is that a client reads it before it has a
# credential. If it needs one, it is not discovery.
d=$(curl -sS -w $'\n%{http_code}' "$BASE/.well-known/oauth-authorization-server" 2>/dev/null)
if [ "$(status "$d")" = "200" ] && [ "$(jq -r '.token_endpoint' <<<"$(body "$d")")" != "null" ]; then
  ok "discovery served without a credential"
else
  bad "discovery: expected 200 with token_endpoint, got $(status "$d")"
fi
j=$(curl -sS -w $'\n%{http_code}' "$BASE/.well-known/jwks.json" 2>/dev/null)
if [ "$(status "$j")" = "200" ]; then
  n=$(jq -r '.keys | length' <<<"$(body "$j")" 2>/dev/null)
  ok "jwks served ($n key(s))"
  [ "$n" = "0" ] && note "no signing key configured: exchanged tokens are HS256 and only this gateway can verify them"
else
  bad "jwks: expected 200, got $(status "$j")"
fi

: "${NOO_PROV_KEY:?set NOO_PROV_KEY to an identity-scoped service key}"

# ── 3. An ACCOUNT subject mints, and says whose it is ───────────────────
# Retried once past the service-key cache. `service_keys::resolve` holds
# the active-key set for 60s, so a key issued moments ago does not exist
# as far as the gateway is concerned and the exchange answers 401 with no
# body. Every operator will issue a key and immediately test; without this
# they get an unexplained 401 and go looking for a bug in the door. (I
# did exactly that, for six diagnostic steps, on the first live run.)
r=$(call POST /api/identity/token "$NOO_PROV_KEY" "{\"subject_token\":\"$PERSONA\"}")
if [ "$(status "$r")" = "401" ]; then
  note "401 — the key may be newer than the gateway's 60s key cache; waiting it out once"
  sleep 62
  r=$(call POST /api/identity/token "$NOO_PROV_KEY" "{\"subject_token\":\"$PERSONA\"}")
fi
if [ "$(status "$r")" = "200" ]; then
  b=$(body "$r")
  tok=$(jq -r '.access_token' <<<"$b")
  [ "$(jq -r '.account' <<<"$b")" = "$PERSONA" ] \
    && ok "account subject mints, account reported" \
    || bad "account field missing or wrong"
  [ "$(jq -r '.act.sub' <<<"$b")" != "null" ] \
    && ok "act claim records the provisioning key" \
    || bad "act claim absent — delegation is not being recorded"
else
  bad "account mint: $(status "$r") — $(body "$r" | head -c 200)"
  tok=""
fi

# ── 4. The minted token WORKS as that account ───────────────────────────
# The check a unit test cannot make: the credential is accepted by the
# ordinary auth path, as an ordinary user token, with no special casing.
if [ -n "$tok" ]; then
  w=$(call GET /api/agents/messages "$tok")
  [ "$(status "$w")" = "200" ] \
    && ok "minted token is accepted on a normal route" \
    || bad "minted token rejected: $(status "$w") — it mints but does not work"
fi

# ── 5. A compound name is NOT an account subject ────────────────────────
r=$(call POST /api/identity/token "$NOO_PROV_KEY" "{\"subject_token\":\"$PERSONA/laptop\"}")
[ "$(status "$r")" = "400" ] \
  && ok "compound name refused as an account subject" \
  || bad "compound account subject returned $(status "$r") — attribution would go NULL silently"

# ── 6. A CONNECTION subject mints under its owner, and not elsewhere ────
CONN_T='urn:noomesh:params:oauth:token-type:connection'
r=$(call POST /api/identity/token "$NOO_PROV_KEY" \
     "{\"subject_token\":\"${NOO_PROV_USER:-$PERSONA}/smoke-1\",\"subject_token_type\":\"$CONN_T\"}")
if [ "$(status "$r")" = "200" ]; then
  b=$(body "$r")
  s=$(jq -r '.subject' <<<"$b"); a=$(jq -r '.account' <<<"$b")
  [ "$s" != "$a" ] && [ "${s%%/*}" = "$a" ] \
    && ok "connection mints: subject=$s attributed to account=$a" \
    || bad "connection subject/account wrong: subject=$s account=$a"
else
  note "connection mint returned $(status "$r") — expected when NOO_PROV_USER is unset"
fi
r=$(call POST /api/identity/token "$NOO_PROV_KEY" \
     "{\"subject_token\":\"somebody-else/smoke\",\"subject_token_type\":\"$CONN_T\"}")
[ "$(status "$r")" = "403" ] \
  && ok "a connection under another account is refused" \
  || bad "foreign connection returned $(status "$r"), expected 403"
r=$(call POST /api/identity/token "$NOO_PROV_KEY" \
     "{\"subject_token\":\"${NOO_PROV_USER:-$PERSONA}/bad.label\",\"subject_token_type\":\"$CONN_T\"}")
[ "$(status "$r")" = "400" ] \
  && ok "a label that is not a valid agent id is refused at mint" \
  || bad "dotted label returned $(status "$r") — it would mint and fail at first send"

# ── 7. Each window has its own mailbox, and its own read state ──────────
# an earlier change, the promise made to the operator: five terminals on
# one account are five identities. Mail to ONE window is that window's
# alone; mail to the ACCOUNT reaches every window, and one window reading
# it does not read it for the others. Three connection tokens under the
# key's own account stand in for three terminals — the same names the MCP
# doors mint, without needing an MCP client in a shell script.
U="${NOO_PROV_USER:-}"
if [ -z "$U" ]; then
  note "mailbox checks skipped (set NOO_PROV_USER to the account NOO_PROV_KEY is bound to)"
else
  win() { # $1 label -> access token for connection U/$1, or empty
    local r; r=$(call POST /api/identity/token "$NOO_PROV_KEY" \
      "{\"subject_token\":\"$U/$1\",\"subject_token_type\":\"$CONN_T\"}")
    [ "$(status "$r")" = "200" ] && jq -r '.access_token' <<<"$(body "$r")"
  }
  A=$(win smoke-a); B=$(win smoke-b); C=$(win smoke-c)
  # A window inherits its ACCOUNT's role (permissions are the account's,
  # provenance is the window's). An operator's windows therefore see every
  # message and may ack any — that is the operator's privilege, not a hole
  # between windows — so the sibling-isolation checks only mean something
  # under an ordinary account. Say which case this run is, rather than
  # letting an operator's key print a pass that proves nothing.
  role=$(cut -d. -f2 <<<"$A" | tr '_-' '/+' | { read -r b; printf '%s==' "$b"; } | base64 -d 2>/dev/null | jq -r '.role // "?"')
  isolated=1
  case "$role" in admin|operator) isolated=0 ;; esac
  if [ -z "$A" ] || [ -z "$B" ] || [ -z "$C" ]; then
    bad "could not mint three windows under $U — mailbox checks cannot run"
  else
    [ "$isolated" = 1 ] || note "$U is $role: its windows see everything by right; sibling-isolation checks below are skipped (bind a key to an ordinary account to run them)"
    stamp="mailbox-$$-$(date +%s)"
    # (a) A → B, one window to another
    r=$(call POST /api/agents/messages "$A" "{\"to\":\"$U/smoke-b\",\"text\":\"$stamp direct\"}")
    if [ "$(status "$r")" = "200" ]; then
      ok "a window can address a sibling by name"
      mid=$(jq -r '.message.id' <<<"$(body "$r")")
      inbox() { call GET "/api/agents/messages?to=$(printf %s "$1" | sed 's#/#%2F#g')&unread=true&limit=50" "$2"; }
      b=$(inbox "$U/smoke-b" "$B")
      jq -e --arg id "$mid" '.messages[] | select(.id==$id)' <<<"$(body "$b")" >/dev/null \
        && ok "the recipient window sees it, unread" \
        || bad "recipient window does not see its own mail (status $(status "$b"))"
      if [ "$isolated" = 1 ]; then
        c=$(call GET "/api/agents/messages?limit=200" "$C")
        jq -e --arg id "$mid" '.messages[] | select(.id==$id)' <<<"$(body "$c")" >/dev/null \
          && bad "a SIBLING window can read mail addressed to another window — isolation is broken" \
          || ok "a sibling window cannot read it"
        r=$(call POST "/api/agents/messages/$mid/ack" "$C" "{}")
        [ "$(status "$r")" = "403" ] \
          && ok "a sibling window cannot ack it" \
          || bad "sibling ack returned $(status "$r"), expected 403"
      fi
      r=$(call POST "/api/agents/messages/$mid/ack" "$B" "{}")
      [ "$(status "$r")" = "200" ] \
        && ok "the recipient window acks it" \
        || bad "recipient ack returned $(status "$r")"
    else
      bad "window-to-window send returned $(status "$r") — $(body "$r" | head -c 160)"
    fi
    # (b) A → the bare account: fan-out, then read state per window
    r=$(call POST /api/agents/messages "$A" "{\"to\":\"$U\",\"text\":\"$stamp fanout\"}")
    if [ "$(status "$r")" = "200" ]; then
      fid=$(jq -r '.message.id' <<<"$(body "$r")")
      seen() { jq -e --arg id "$fid" '.messages[] | select(.id==$id)' <<<"$(body "$(call GET "/api/agents/messages?unread=true&limit=200" "$1")")" >/dev/null; }
      seen "$B" && seen "$C" \
        && ok "mail to the account reaches every window" \
        || bad "account-addressed mail is not visible to every window"
      r=$(call POST "/api/agents/messages/$fid/ack" "$B" "{}")
      [ "$(status "$r")" = "200" ] || bad "window B ack of account mail returned $(status "$r")"
      if seen "$B"; then bad "window B still sees the mail as unread after acking it"; else ok "acking clears it for the window that acked"; fi
      if seen "$C"; then ok "…and NOT for its sibling: read state is per window"; else bad "window B's ack marked the mail read for window C"; fi
    else
      bad "window-to-account send returned $(status "$r") — $(body "$r" | head -c 160)"
    fi
  fi
fi

# ── 8. The kill switch actually reaches a live token ────────────────────
# THE check. Everything above can pass while this fails, and the failure is
# silent: revoking a key stops the next mint and an operator assumes that
# stopped the agent. It does not — disabling the ACCOUNT is what reaches a
# token already in flight, and that only works because the auth layer
# re-checks a delegated token's subject on every request.
if [ "${DESTRUCTIVE:-0}" = "1" ] && [ -n "${NOO_TOKEN:-}" ] && [ -n "$tok" ]; then
  # `/api/users/disable` with a BOOLEAN, not
  # `/api/security/users/{u}/disable`. The latter is one-way: there is no
  # matching `enable` route and no `noo security user enable` verb, so a
  # first draft of this script would have left the test account disabled
  # with no supported way back. Checked before anyone ran it.
  setdis() { call POST /api/users/disable "$NOO_TOKEN" "{\"username\":\"$PERSONA\",\"disabled\":$1}"; }
  d=$(setdis true)
  if [ "$(status "$d")" != "200" ]; then
    bad "could not disable '$PERSONA' ($(status "$d")) — kill-switch check not run"
  else
    sleep 15   # the delegated-subject cache is 10s
    w=$(call GET /api/agents/messages "$tok")
    [ "$(status "$w")" = "401" ] \
      && ok "disabling the account killed a token already issued" \
      || bad "token still works after disable ($(status "$w")) — the kill switch is cosmetic"
    # Restore, and VERIFY the restore. An account left disabled by a test
    # is a worse outcome than the test not running.
    e=$(setdis false)
    if [ "$(status "$e")" = "200" ] && [ "$(jq -r '.disabled' <<<"$(body "$e")" 2>/dev/null)" = "false" ]; then
      ok "'$PERSONA' re-enabled"
    else
      bad "COULD NOT RE-ENABLE '$PERSONA' — re-enable it by hand: POST /api/users/disable {\"username\":\"$PERSONA\",\"disabled\":false}"
    fi
  fi
else
  note "kill-switch check skipped — pass --destructive to run it; needs a login"
fi

# ── 12. The harness plane: what each node's agent REPORTS ───────────────
#
# an earlier change. The harness is a host service now, not a container,
# and the two ways it fails are invisible from the controller unless the
# heartbeat carries them: the unit is absent (the node never got a bundle
# that installs it) or it is installed and cannot start (a refusal names
# the reason). Both used to be silence — host3 spent two days crash-looping
# unseen, and half a day more exiting before main.
#
# Deliberately NOT asserted here: that every node runs a harness. Most
# fleets place one on some nodes and not others, so a node without one is
# normal and this section reports rather than fails. What it DOES fail on
# is a node that was asked for a harness and cannot give one, because that
# is the state nobody sees.
echo
echo "── harness plane ──"
#
# READ THE SURFACE THAT CARRIES THE ANSWER. `/api/cluster/status` is a
# summary: id, status, load, tier, what the node CAN host and what it IS
# hosting. It carries none of `host_services`, `backend_runtimes` or
# `reconcile_refusals`, and this section used to read it — so it reported
# "no harness" for every node in the fleet, including one with a harness
# running at that moment, and read as evidence while doing so. The agent
# reports the harness as a HOST SERVICE (`host_services.harness`, with its
# runtime and its state), and `/api/cluster/nodes` is the surface that
# carries the node record whole.
if [ -z "${NOO_TOKEN:-}" ]; then
  note "harness checks skipped — run \`noo auth login\` (this reads /api/cluster/nodes; NOO_TOKEN also works)"
elif ! command -v python3 >/dev/null 2>&1; then
  note "harness checks skipped — the node record is nested JSON and reading it needs python3"
else
  st=$(call GET /api/cluster/nodes "$NOO_TOKEN")
  if [ "$(status "$st")" != "200" ]; then
    bad "cluster nodes unreadable (HTTP $(status "$st")) — the rest of this section cannot run"
  else
    # One line per node, unit-separator (0x1f) delimited: id, harness state,
    # harness runtime,
    # the refusal reason if the node declined to start it, and a CHAT model
    # it serves (for the end-to-end check below). Empty fields stay empty
    # — an absent report is reported as absent, never invented.
    rows=$(body "$st" | python3 -c '
import json, sys
d = json.load(sys.stdin)
for n in d.get("nodes", []):
    h = ((n.get("host_services") or {}).get("harness") or {})
    reason = ""
    for r in (n.get("reconcile_refusals") or []):
        if isinstance(r, dict) and r.get("scope") == "backend_start" and r.get("target") == "harness":
            reason = r.get("reason") or "no reason recorded — that is itself a bug"
            break
    model = ""
    for b, m in (n.get("running_backends") or {}).items():
        if b in ("vllm", "llamacpp", "ollama") and m:
            model = m
            break
    # A control character, not a tab: bash collapses runs of whitespace
    # when it splits fields, so an EMPTY field between tabs would vanish
    # and the next one would slide into its place.
    print("\x1f".join(str(x).replace("\x1f", " ") for x in (n.get("id", ""), h.get("state", ""), h.get("runtime", ""), reason, model)))
' 2>/dev/null)
    [ -n "$rows" ] || note "no nodes registered"
    while IFS=$'\x1f' read -r n hstate runtime reason model; do
      [ -n "$n" ] || continue
      if [ -n "$reason" ]; then
        # The whole point of recording start failures as refusals (#233):
        # the controller can say WHY, in the node'"'"'s words.
        bad "$n: asked for a harness and cannot run one"
        note "$reason"
      elif [ "$hstate" = "running" ]; then
        # A host service always names its runtime (systemd or launchd); a
        # harness running WITHOUT one is a report with half missing.
        if [ -n "$runtime" ]; then
          ok "$n: harness running ($runtime)"
          # Remember the first one, and a CHAT model it serves, for the
          # end-to-end check below. Dispatch resolves a task to a node
          # through its model, so a task with no model resolves to the
          # default backend — which is the controller'"'"'s, and reports
          # failure on a fleet that is working.
          if [ -z "${HARNESS_NODE:-}" ] && [ -n "$model" ]; then
            HARNESS_NODE="$n"
            HARNESS_MODEL="$model"
          fi
        else
          bad "$n: harness running with no runtime named — a host service always names one"
        fi
      elif [ -n "$hstate" ]; then
        # stopped / absent / anything else the agent says: reported in the
        # agent'"'"'s own word. Neither is a failure — most fleets place a
        # harness on some nodes and not others.
        note "$n: harness $hstate"
      else
        note "$n: no harness report (not placed here, or the agent predates host-service reporting)"
      fi
    done <<<"$rows"
  fi
fi

# ── 13. End to end: a turn actually runs ON a node ──────────────────────
#
# Everything above is the controller believing a report. This is the only
# check that proves a node took a turn, and it is the thing an earlier change
# exists for. It creates a task, so it is opt-in: HARNESS_E2E=1.
#
# Why a task and not a chat turn: a task carries the node it ran on in its
# own record, so the assertion reads the system's answer rather than a log
# line that happens to mention a node.
if [ "${HARNESS_E2E:-}" = "1" ] && [ -n "${NOO_TOKEN:-}" ]; then
  echo
  echo "── harness end to end ──"
  # AIM IT AT A HARNESS. Dispatch resolves a task to a node THROUGH ITS
  # MODEL, so a task created with no model resolves to the default
  # backend — the controller's — and lands in process no matter how well
  # dispatch works. The check would have reported failure on a healthy
  # fleet and sent someone hunting the harness. Section 12 above names a
  # node with a running harness and a chat model it serves; use it.
  if [ -z "${HARNESS_MODEL:-}" ]; then
    note "no node reports a running harness beside a chat backend"
    note "nothing to dispatch TO, so there is nothing to prove here — not a failure"
  else
    payload=$(printf '{"objective":"Reply with the single word: ok","loop_budget":1,"model":"%s"}' "$HARNESS_MODEL")
    note "aiming at '$HARNESS_NODE' by its model '$HARNESS_MODEL'"
    made=$(call POST /api/tasks "$NOO_TOKEN" "$payload")
    if [ "$(status "$made")" != "200" ]; then
      bad "could not create a task (HTTP $(status "$made")) — $(body "$made" | head -c 160)"
    else
      ran_on=$(grep -o '"node":"[^"]*"' <<<"$(body "$made")" | head -1 | cut -d'"' -f4)
      tid=$(grep -o '"id":"[^"]*"' <<<"$(body "$made")" | head -1 | cut -d'"' -f4)
      # The gateway's own verdict, when it sends one. A twelve-hex node
      # is a good guess at "it stayed here" and nothing more; `dispatched`
      # is the answer, and `why` is the gateway saying what stopped it.
      verdict=$(grep -o '"dispatched":\(true\|false\)' <<<"$(body "$made")" | head -1 | cut -d: -f2)
      excuse=$(grep -o '"why":"[^"]*"' <<<"$(body "$made")" | head -1 | cut -d'"' -f4)
      case "$ran_on" in
        ""|null)
          bad "the task reports no node at all" ;;
        *)
          # A container id is 12 hex chars and means the gateway ran it in
          # process — which is correct behaviour when no node has a harness,
          # and a FAILURE of this check, which exists to prove dispatch.
          if [ "$verdict" = "false" ] || { [ -z "$verdict" ] && printf '%s' "$ran_on" | grep -qE '^[0-9a-f]{12}$'; }; then
            bad "the task ran in process on the controller ($ran_on), not on '$HARNESS_NODE'"
            note "${excuse:-the model named a node whose harness is running, and dispatch still kept the turn}"
          elif [ "$ran_on" != "$HARNESS_NODE" ]; then
            # Not a failure: another node may serve the same model. Say so
            # rather than claiming the aim worked.
            ok "a task ran on node '$ran_on' (task $tid), aimed at '$HARNESS_NODE'"
          else
            ok "a task ran on node '$ran_on' (task $tid)"
          fi ;;
      esac
    fi
  fi
else
  note "end-to-end harness check skipped — pass --e2e to run it (it creates a task); needs a login"
fi

echo
echo "$PASS passed, $FAIL failed"
[ "$FAIL" -eq 0 ]
