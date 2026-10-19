# Connecting your own Claude to noomesh

Every noomesh account can mint itself one MCP key and point a local Claude Code
(or any MCP client) at the cluster. No operator is involved once the door is
open:

```bash
noo security service-key self --note "work laptop"
```

## The two doors

> Named for **who the agent acts as**, not where the socket sits. The user
> door's original path, `/mcp/external`, was removed in stack-v0.2.40 — a
> client still on it gets `404`; point it at `/mcp/user`. The tailnet
> serve path `/mcp` that `noo onboard` used to write is not written any
> more either; on a controller onboarded before v0.2.40 it lingers and
> proxies to the removed path, so remove it once:
> `sudo tailscale serve --https=443 --set-path=/mcp off`.

The gateway serves two MCP endpoints, and they answer
different questions:

| Door | Where | Who it is for | Credential | Catalog |
|---|---|---|---|---|
| **Operator door** | `POST /mcp/operator` on the gateway (`:8080`, HTTPS) | the operator — a machine you own, acting with operator authority | a service key with the `mcp:operator` scope bound to an admin account — **mandatory** on every request, and the only credential. (The shared `NOO_MCP_TOKEN` was retired on 2026-09-30; the separate plain-HTTP listener on port `3100` was removed in stack-v0.2.40.) | the full tool registry (plus add-on fragments named in `NOO_MCP_EXTRA_MANIFEST`) |
| **User door** | `POST /mcp/user` on the gateway (`:8080`, HTTPS) | anyone acting as themselves — colleagues, a second machine, a machine account | a user-bound service key with the `mcp` scope | a curated subset, compiled into the gateway |

Calls through the operator door run as the **admin account the key is bound
to**, with operator reach; calls through the user door run **as the account
the key is bound to**, with that account's own role and scopes. Either way the
gateway mints a five-minute JWT for that account per tool call and proxies the
request to its own API with it. Identity is re-resolved from the presented key
on every request, so a revoked or narrowed key stops working immediately. (A
legacy `initialize` handshake also returns an `Mcp-Session-Id`, which only
separates two windows on one key; it grants nothing.)

This page is about the external door. The rest of the page assumes an
operator has opened it (see [Open the door](#open-the-door-operator)).

## What the key is

A bearer form of **your account** — not a set of permissions copied off it.

The key carries exactly one scope, `mcp`, which opens the external door and
nothing else. What you can actually *do* through the door is resolved per
request from your `noo_users` account: your role, your scopes, your
knowledge-base audience. So:

- widen the account and the key follows, with no re-issue
- disable the account and the key stops working (it resolves as unbound,
  and the door refuses unbound keys)
- the key can never reach something the account cannot

That is what makes self-service safe below the operator tier: issuing
yourself a key is not an escalation, because there is nothing in it you did
not already have.

## Get a key

```bash
noo security service-key self --note "work laptop"
```

The raw key (`noo-sk-…`) is printed **once**. Only its SHA-256 hash is
stored, so there is no recovery path — if you lose it, re-issue.

Re-issuing **rotates**: you get one active key, and the previous one is
revoked in the same call. The raw keys are never stored, so accumulating
several would mean holding live credentials you cannot enumerate, revoke
individually, or even recognise. Self-issued keys are named
`self:<username>` and capped at 120 requests per minute.

```bash
noo security service-key self-status    # do I have one? when was it last used?
noo security service-key self-revoke    # kill it
```

Changes reach the gateway within 5 s (the key cache TTL); disabling or demoting the account takes effect at once. A key with no per-key `--rpm` is still metered on the MCP doors (600 requests per minute per key by default; the Redis counter falls back to a per-process one if Redis is down).

You need a per-user CLI credential for these — `noo auth login <you>` first.
The shared cluster credential is refused here on purpose: a self key is
bound to the account that asks for it, and the cluster credential is not an
account.

## Point Claude at it

Add to `~/.claude.json` under `mcpServers`:

```json
"noomesh": {
  "type": "http",
  "url": "https://<controller>.<your-tailnet>.ts.net/mcp/user",
  "headers": { "Authorization": "Bearer noo-sk-…" }
}
```

Restart Claude Code. `tools/list` should return the external tool set.

Notes on the URL:

- `noo onboard` (and `noo controller promote`) map only `/mcp/user` and
  `/mcp/operator` on the controller's MagicDNS name to the same-named doors
  on the gateway with `tailscale serve` — never a bare `/mcp` alias — so you
  need to be on the tailnet, and you get a public ts.net certificate — no
  cluster CA to install. (A named instance mounts at `/<instance>/mcp/user`
  instead.) `tailscale serve status` on the controller shows the mapping;
  `noo stack status` warns when there is none.
- Hitting the gateway directly (`https://<controller>:8080/mcp/user`) works too but
  presents the **cluster** CA, which most clients will reject unless you have
  trusted it (`noo security trust-ca`).

  **Claude Code is a Node client, and `trust-ca` is not enough for it.**
  `trust-ca` installs the CA into the OS store
  (`/usr/local/share/ca-certificates/mesh-cluster-ca.crt` +
  `update-ca-certificates`). Node does not read the OS store — it ships its own
  CA list — so `claude mcp list` still fails, with
  `UNABLE_TO_VERIFY_LEAF_SIGNATURE: unable to verify the first certificate`.
  That reads exactly like the trust never took. Point Node at the file as well:

  ```bash
  export NODE_EXTRA_CA_CERTS=/usr/local/share/ca-certificates/mesh-cluster-ca.crt
  ```

  Put it in the shell profile that starts Claude Code, and prefer the
  `tailscale serve` URL below when it is available — that path presents a
  public ts.net certificate and needs no CA on the client at all.
- The `tailscale serve` mapping is set up by `noo onboard`. If port 443 on the
  controller's MagicDNS name is not listening, that step has not run on this
  install and only the direct `:8080` URL will work. Check with
  `sudo tailscale serve status` on the controller.

## Do I have to do this every time?

No. Each piece is one-time, and each is stored where it survives restarts and
upgrades:

| Thing | Where it lives | When you redo it |
|---|---|---|
| `NOO_MCP_EXTERNAL_ENABLED` | the posture store (database) | never, unless you turn the door off |
| your service key | `noo_service_keys`, hashed | if you revoke it, or `service-key self` rotates it |
| the client entry | your own `~/.claude.json` | never — restarting the client re-reads it |

The one thing that does reset all of it: **`noo offboard` followed by a fresh
`noo onboard`**. That mints a new secret store, so the posture flag and
every issued service key are gone with the old install.
After a fresh onboard, redo this page from the top. That is the intended
behaviour — an install's credentials do not outlive the install — but it is
worth knowing before you wonder why a working client stopped.

## Reaching the operator door from another machine

It used to be loopback-only, which meant "run your client on the controller or
not at all". It is now also served at `/mcp/operator` on the gateway port, over
the certificate the gateway already has. Each admin gets their **own** key for
it — issued by an operator, never self-service, because this key holds
operator authority:

```bash
noo security service-key issue alice-ops --scopes mcp:operator --user alice --note "alice laptop"
```

```json
"noomesh-operator": {
  "type": "http",
  "url": "https://<controller>.<your-tailnet>.ts.net:8080/mcp/operator",
  "headers": { "Authorization": "Bearer noo-sk-…" }
}
```

The bound account must hold the `admin` role, and that is re-checked on every
call: demote or disable the account and the key stops at once (the key cache itself is 5 s). Revoke one
person with `noo security service-key revoke alice-ops` and nobody else is
affected. There is no shared credential any more: `NOO_MCP_TOKEN` was retired
on 2026-09-30 and the door refuses it. **If your client entry (for example
in `~/.claude.json`) still sends it, that entry now gets `401` — issue
yourself a key as above and replace the header.** An old token left in the
controller's store is harmless (ignored, warned about once at boot) and
`noo security secrets tidy` removes it.

A credential is **required** on that path — the gateway port has no binding
acting as a boundary the way loopback did, so the door returns 401 rather than
serving the full toolset. Anyone who can reach it holds the operator toolset:
keep it on the tailnet.
**Do not put the key in `.env`.** Nothing reads it there, and `.env` is not a
secret store — see [Secrets](../security/secrets.md).

## What you'll be able to reach

Tool availability follows your account's role and scopes:

| Your account | Through the door |
|---|---|
| role `user` (scope `read`) | every read (`GET`), plus the chat/query surface: inference, conversations, `rag/query`, `memory/search`, uploads |
| … plus the `ingest` scope | the above, plus document ingest (`/api/v1/docs/ingest`) |
| … plus the `graph` scope | the above, plus the six graph query tools (`noo_graph_navigate`, `_traverse_with_intent`, `_explain_path`, `_semantic_search`, `_search_clusters`, `_classify_intent`), each answer limited to documents your account may read. `read` alone does not get them |
| role `operator` (scope `write`) | the above, plus the mutating control plane |
| role `admin` | everything, unrestricted knowledge-base visibility |

### Tasks

Every account, from role `user` up, gets seven task tools on the user door.
With them a client that has no loop of its own can hand the mesh an objective
and follow it. That client might be your own Claude Code, or a CLI harness
running a task it was given.

- `noo_task_delegate {objective, parent_task_id?, role?, model?, loop_budget?, token_budget?}`
  opens a task for you and starts it. `parent_task_id` makes it a sub-task of
  one of your live tasks.
- `noo_task_status {task_id?}` returns a task and its sub-tasks. With no id it
  lists your recent tasks.
- `noo_task_wait {task_id, seconds?}` returns when the task or one of its
  sub-tasks settles, or after 25 s at most with `state: running`. Then call
  it again.
- `noo_task_done {task_id, result, failed?}` finishes the task and posts the
  result to its thread.
- `noo_task_ask {task_id, question}` asks the task's owner a question the task
  cannot go on without. The running loop finishes; then the task waits.
- `noo_task_resubmit {task_id, token_budget?}` gives a task more tokens. A
  task that ran out resumes from its checkpoint.
- `noo_task_answer {task_id, text}` answers a task's question. A new loop
  starts with the question and your answer.

How token budgets work: [Token budgets](../operating/token-budgets.md).

They act only on **your own** tasks, whatever your role: an admin's door
cannot see anyone else's. Any other id answers `task not found`. Full
reference: [API → MCP doors](../reference/api.md#mcp-doors).

### Knowledge-base visibility

Documents carry audience tags. You see the union of the tiers you belong to:
your own `user:<name>`, the shared `company` tier, `system`, and any
`team:*` role granted to you. Asking for a role outside that set is clamped
back to it — a read user cannot query someone else's `user:` tier.
Machine-generated documents (heartbeat reports, research notes) carry the
`generated` tag and are only returned when you ask for that role by name.

Being an operator does **not** widen this. `write` is an API-access tier,
not a visibility tier; only `admin` reads across other users' personal
tiers.

## Open the door (operator)

The external door is closed by default and both vetted posture profiles
keep it closed. Opening it is a decision about a specific person, taken
once by an operator:

```bash
noo security posture set NOO_MCP_EXTERNAL_ENABLED 1
noo stack restart gateway            # posture is read at start
```

Until then every request to `/mcp/user` answers `404` with the reason.
`noo mcp external-setup` prints this recipe (and exits `2` — it mints
nothing; the shared external token it used to generate no longer
authenticates anything).

To give a **machine** (a CI job, a bot) access rather than a person, it gets
its own account and an operator-issued key bound to it:

```bash
noo security user create ci-bot --scope read
noo security service-key issue ci-bot --scopes mcp --user ci-bot --note "nightly"
noo security service-key list        # hashes and metadata only
noo security service-key revoke ci-bot
```

An unbound (machine-only) key is refused at the external door — it would let
a key act with more authority than any human account.

## Troubleshooting

| Symptom | Cause |
|---|---|
| `401` | no bearer presented (operator door: also an unknown key or the retired `NOO_MCP_TOKEN`) |
| `403 unknown or revoked key` | user door: key wrong, revoked or rotated out by a later `self` issue (allow up to 5 s after a change) |
| `403 key lacks the 'mcp' scope` | an operator-issued key without `--scopes mcp` |
| `403 this key is not bound to a user` | machine key, or the bound account is disabled — reissue with `--user` |
| `UNABLE_TO_VERIFY_LEAF_SIGNATURE` | the direct `:8080` URL presents the cluster CA and this client does not trust it. For a **Node** client (Claude Code included) `noo security trust-ca` alone does nothing — Node ignores the OS store. Set `NODE_EXTRA_CA_CERTS` to the CA file, or use the `tailscale serve` URL on 443, which needs no CA |
| `ENOTFOUND <controller>.<tailnet>.ts.net` | this machine is not resolving through Tailscale: `tailscaled` down, not logged in, or `/etc/resolv.conf` overwritten so `100.100.100.100` is gone. `tailscale status` and `grep nameserver /etc/resolv.conf` separate the three; `sudo tailscale set --accept-dns=true` fixes the last |
| `404` on a call with a session header | the `Mcp-Session-Id` is unknown or expired (gateway restarted, 24 h idle): the client should re-initialize |
| `404` | the door is closed (`NOO_MCP_EXTERNAL_ENABLED` unset) or the path is wrong: the user door is `/mcp/user` on `:8080` (`/mcp/external` and the loopback `:3100` listener were both removed in stack-v0.2.40 — the operator door is `/mcp/operator` on `:8080` now) |
| Query returns nothing | your account may not be in the audience for those docs — ask an operator to tag them `company`, or grant you a `team:*` role |
