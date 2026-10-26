# Security

Covers: users, secrets, PKI, scanning and CA trust (`security`), and per-user CLI credentials (`auth`).

Does not cover: exec-approval decisions (`noo approval`, under Agents & channels) or the posture flags' runtime effects, which live with the subsystem they gate.

## Disambiguation

- `noo auth` is **your** credential for this CLI (login, status, logout). `noo security user` is the **accounts** an operator administers.
- **Scopes** (`--scope read|write|admin|peer|ingest|graph`, set at `user create`/`set-scopes`) decide what a login may *do*. `read`, `write` and `admin` map to the roles User / Operator / Admin; `ingest` and `graph` are additive capabilities for a User that open exactly one thing each (document upload; the six graph query routes, see [below](#graph-scope)) and change nothing else; **KB roles** (`grant-role --role team:ops`) decide which *documents* a user can see. Different axes, different verbs.
- A **service key** (`service-key issue <consumer>`) is minted by an operator for an external system with explicit scopes and a rate cap; **your own MCP key** (`service-key self`) is bound to your account and carries your scopes — nothing more. Neither is a JWT.
- `pki rotate-all` re-issues expiring **leaf** certs and delivers them; `pki rotate-ca` replaces the **CA** with a cross-signed transition; `pki push-nodes` re-issues every registered node's cert and stages it on the pull rail in one pass, for a fleet that missed a delivery. `pki rotate` only writes local files; `issue-node` issues a cert and delivers it, waiting for the node to confirm it applied (`--mint-only` skips delivery).
- `secrets audit` reports; `secrets resync` makes a Postgres role match the value already in the store; `secrets rotate` mints a **new** value and applies it. Fleet-wide secrets are pushed with `noo cluster push-secrets` (Fleet), never rotated here.
- **Posture** gates (`posture set`) are a short allow-list of security switches stored in the database and applied at gateway boot; everything else is `noo config` (Stack & data).

## Recipes

### Log in

```sh
noo auth login alice
noo auth status
```

`login` posts your password to `/auth/token` with no other credential
attached, stores an access + refresh pair in
`~/.config/mesh/credentials.json` (mode 0600) and prints `logged in as
alice on <controller>` with your scopes. A wrong password exits 4 (an
operator can reset it with `noo security user set-password alice`).
`status` shows which credential the CLI would use — flag, env, or stored
file (there is no shared-secret credential) — and whether the gateway
accepts it. It also prints
the gateway URL with the rung that produced it, the **TLS trust anchor**
(enrolled controller / `$NOO_TLS_CA` / the cluster CA at
`$NOO_PKI_DIR/ca.crt` or `/etc/noo/pki/ca.crt` / the platform verifier), the
config root and how it was chosen, and a line for any config file whose
transport keys were ignored because it lives in a checkout this box is not
installed from. There is no unverified-TLS fallback: an unusable anchor, or a
non-loopback `http://` gateway, exits 3 (`tls_untrusted`) instead. `logout`
revokes the refresh token server-side, deletes the file, and ends the
access token it was holding: the gateway keeps a per-account "not before"
time (kept in milliseconds, so a token minted in the same second as the
logout is ordered against it correctly: one minted before is refused, a
re-login's token minted after is accepted) and the account's open dashboard sockets close.
The floor is kept for one access-token lifetime in three places, read in
this order: Redis (shared by every gateway instance), the gateway's memory,
and Postgres (`noo_session_floors`, the durable copy, loaded at boot). A
Redis outage or a restart therefore no longer forgets an account change; with
neither Redis nor Postgres readable the gateway applies the floors it holds in
memory and logs a warning rather than refusing every request.
Scripts pass `--token` or `NOO_TOKEN`; the resolution order is in
[README.md#contracts](README.md#contracts).

### Reset the admin password

```sh
noo security admin-password reset
```

Run on the controller. It writes the account through the database, so it
works with the gateway down and needs no login. The same transaction ends the
account's sessions: every refresh token is revoked and the durable
"not before" floor (`noo_session_floors`) is raised, so a running gateway
refuses the old access tokens within about five seconds (its Postgres
re-read interval) and a stopped one honours the floor at its next start. The
floor is stored in milliseconds (`floor_ms`). The
reset does not call the gateway, deliberately: it must work when the gateway
cannot be reached or the password is lost.

### Verify the audit log

```sh
noo security audit verify
```

Recomputes every row's hash, checks the hash chain for deleted or reordered
rows, and compares the chain head with the **exported head**. Every 15
minutes the gateway appends `{seq, chain_hash, time, mac}` (MAC under the
audit key) to `/data/audit-archive/chain-head.jsonl` (opened append-only, mode
0600, on the gateway's data volume, outside Postgres) and publishes it to the
operator event stream (`events.ops.audit.chain_head`). If the database head is
older than an exported head, or the same sequence carries another hash, the
newest rows were truncated or history was rewritten: the verdict is `fail` and
the exit code 1. If there is no export yet, or the file cannot be read, the
head line says `NOT CHECKED` and why; it is never reported as intact. A line
that fails its MAC fails the check and names the line; after a deliberate
audit-key rotation, move the file aside and the export starts a new one.
`chattr +a` on the file makes the kernel enforce append-only. Override the
location with `NOO_AUDIT_HEAD_FILE`.

### Create a user and give them knowledge access

```sh
noo security user create alice --scope read --scope write
noo security team create ops --description "On-call team"
noo security user grant-role alice --role team:ops
noo security user list
noo security user link alice telegram 123456789 --name "Alice"
```

`create` prompts for the password (12 characters minimum, not a common
password, not containing the username; the CLI and the gateway enforce the
same rule on `create` and `set-password`, so `--password-stdin` is checked
too, and existing accounts keep logging in; only a new or changed password
is checked) and prints `user 'alice' created with
scopes read, write` (`read` alone when `--scope` is omitted: new accounts are read-only, and `read` + `write` is the Operator tier). `team
create` makes the team and its `team:ops` KB role; `grant-role` adds it
(`alice KB roles: team:ops`; everyone already has `user:<name>`,
`company` and `system`). `link` maps a channel identity (a Telegram chat
id, a Google Chat `users/123`, a WhatsApp number) to the account so
messages from that sender run as alice; `links alice` lists them.
`set-scopes` **replaces** the scope set and is admin-only. Scopes are baked
into the JWT, so the change **ends every session of that account
immediately** (its refresh tokens are revoked, open sockets close, and a
token issued before the change is refused): the user logs in again and gets
the new scopes. `disable`, `set-role` and `set-password` do the same, and
`service-key revoke --disable-account` too. A disabled account's bound MCP
keys stop within the key cache interval (5 s) and its refresh cookie is
refused. `disable` does not revoke keys that are not bound to the account
(machine keys issued with `service-key issue`); revoke those by name.

<a id="addon-scopes"></a>
**Add-on scopes.** A scope written `<addon>:<word>` (for example
`evolve:read_items`) is accepted by `set-scopes`, `create` and
`service-key issue --scopes` only when a loaded add-on's route manifest declares
it on some route. Anything else is refused with the list of scopes the loaded
add-ons do declare (or a note that none is loaded, e.g. the add-on is off), so
a typo never reads as a permission. The check is made by the gateway, not the
CLI, and applies to a proposal that carries scopes too. An add-on scope opens
that add-on's `GET` route for an account that holds `read` plus the scope, and
nothing else; it never opens a write. Granting one is admin-only like any scope
change and ends the account's sessions, so it applies at the next login:
`noo security user set-scopes alice --scope read --scope evolve:read_items`
(the set is replaced). `noo security user list` shows them with the rest of the
scopes. A service key carrying one (with `addon`, so it can exchange) gets a
token that also holds `read`, which the route needs.

<a id="graph-scope"></a>
**The `graph` scope.** A plain `read` account is refused every
`POST /api/v1/graph/*` (the intended boundary). An account that
holds `read` **and** `graph` may call exactly six of them: `classify-intent`,
`explain-path`, `navigate`, `search-clusters`, `semantic-search` and `traverse`
(the `noo_graph_*` tools on the user MCP door, and `graph.navigate` /
`graph.traverse` through `POST /api/v1/ops`). Nothing else opens: `recluster`,
`entity-cleanup`, `extract-relations` and the prune routes stay Operator or
Admin. Every result is cut to the documents that account may read, and the
evidence behind an edge (snippet, page, page number, any reinforced edge) is
withheld, so a relationship is shown only when a single readable document
supports it. Grant it per account: `noo security user set-scopes alice --scope read --scope graph`
(the set is replaced, so list `read` too; the user logs in again to pick it up).
It needs the Intelligent tier; without it the routes answer `503`. Roll
`trellion-intel` out before `noomesh`: until it is rolled, a `graph` account
gets `503` rather than unfiltered data. The injected KB context (the graph
facts added to chat answers) is unchanged and still needs `write`. To remove
someone: `disable`, then `erase alice` shows a dry-run of what would be
deleted per store; `erase alice --yes` executes it (`--keep-account`
keeps the row). An erase keeps a copy of what it deleted for 30 days, so a
mistake can be undone, and the gateway then purges that copy automatically;
after 30 days the erase is final. `noo cluster verify --controller` fails the
`erasure archive` row if that purge stops running. Agents can propose accounts (`user proposals`); an
operator decides with `user decide <id> --approve`, which prints the
generated password once.

### Mint a service key with a quota

```sh
noo security service-key issue reranker-bot --scopes chat --scopes embeddings --rpm 60 --note "batch job"
noo security service-key list
noo security service-key set-quota reranker-bot 0        # 0 = uncapped
noo security service-key rotate reranker-bot             # new key; the old one stays live until retired
noo security service-key retire reranker-bot             # once the new key has been used
noo security service-key revoke reranker-bot
```

Scopes are `chat`, `embeddings`, `rerank`, `classify`, `mcp` (all of them
when `--scopes` is omitted). The raw key is printed once under
`raw key (shown once, store it now)` — it is the only line `--quiet`
emits — together with the client config (`base_url=https://<controller>:8080/api/external`,
`Authorization: Bearer <key>`). `list` shows state, rpm, created and
last-used; never the key (`--all` adds revoked keys). `rotate` keeps the
quota and leaves the superseded key working until `retire` deactivates it,
so the consumer can switch over without an outage; `revoke` kills every
key of the consumer at once (`--disable-account` also kills tokens already
issued). For your **own** MCP key, log in and run
`noo security service-key self` (scopes fixed to `mcp`, one active key
per account, re-running rotates); `self-status` and `self-revoke` manage
it. See [mcp-your-client.md](../channels/mcp-your-client.md).

### Check and rotate certificates

```sh
noo security pki status
noo security pki rotate-all --warn-days 30 --new-days 90
```

`status` lists every cert under the PKI dir with expiry, days left and
`OK` / `EXPIRING SOON` / `EXPIRED`. `rotate-all` **never touches the
CA**: it scans, confirms, backs up to `pki/.rotate-backup-<ts>`,
re-issues every leaf expiring within `--warn-days`, delivers node certs
on the pull rail (no fallback — a node with no birth cert on record must
be re-enrolled first), restarts the consumers with the
gateway last, health-probes, and on failure restores the backup and
restarts again (exit 1). A node that did not take its cert makes the
exit code 1 too; `--no-deliver`/`--no-reload` skip those steps and say
so. Nothing expiring prints `no certificates expiring within N days`.
Leaf rotation also runs unattended from the `cert_auto_rotate` autonomy
location when enabled.

### Rotate the CA and re-key the fleet

```sh
noo security pki rotate-ca                 # mint the next CA, transition every node, promote
noo security pki status                    # every leaf now chains to the new CA
noo security pki rotate-ca --retire-old    # later: drop the old CA from every anchor
```

`rotate-ca` mints the next CA into `pki/ca-next`, then for each remote
node re-issues its leaf under the new CA and ships a transition bundle
whose anchor is the new **and** old CA concatenated, signed with the old
key so the node's current anchor verifies it. Only when **every** node
has landed does it promote locally (new key in, old pair backed up, local
leaves re-issued, consumers reloaded); any node failing means nothing
promotes and you re-run. `--retire-old` is a separate, later step that
ships a new-only anchor once every leaf on disk chains to the new CA.
Both steps ask for confirmation. If a CA changed outside that path (a
re-onboard, for instance) and remote agents are crash-looping on
`certificate signed by unknown authority`, `noo security pki push-nodes`
re-issues each node's cert and stages a bundle carrying it plus `ca.crt`
on the pull rail for the node's own applier to collect and apply
(exit 1 if any node fails). A **fresh** node never needs
`push-nodes` — `noo cluster provision` issues its cert.

### Trust the CA on this machine

```sh
noo security trust-ca
noo security untrust-ca -y
```

`trust-ca` installs `$NOO_PKI_DIR/ca.crt` into the OS trust store with
native elevation (Linux and WSL2 `update-ca-certificates`, macOS System
keychain) and prints `CA trusted by the operating system`, then a note that
Chrome/Chromium on Linux and Firefox keep their own stores — see
[trust-the-cluster-ca.md](../getting-started/trust-the-cluster-ca.md). If it
cannot install, it prints the manual steps and still exits 0.
`untrust-ca` removes it by certificate CN, so it works after the PEM is
gone — which is why `noo stack clean --deep` runs it before deleting the
PKI dir.

### Audit and repair secrets

```sh
noo security secrets audit
noo security secrets resync --all --dry-run
noo security secrets resync POSTGRES_PASSWORD
```

`audit` decrypts `secrets/env.sops` in memory and compares it with `.env`
key by key — presence, blank values, digests — and probes the Postgres
role passwords. It never prints a value; findings are named
(`credential-in-env`, `value-drift`, `consumer-gap`, `blank-value`,
`required-key-absent`, `db-password-does-not-authenticate`, …) with a
fix line each, and the exit code is 0 regardless (use `--json` to gate
on it). When a role password is behind the store, `resync <KEY>` runs
`ALTER ROLE` to the value already in the store — no new secret, no
container recreate. It refuses when it cannot tell (a `trust` pg_hba
path) or Postgres is unreachable, and only `db-password` keys are valid
arguments. `secrets absorb-files` folds file-shaped credentials (a
service-account JSON) and any `secrets/<name>.txt` an older wizard left
beside the store into `env.sops`, shredding each file only after its value
reads back from the store; a file that disagrees with the store is reported
and left in place. `secrets tidy` moves config keys that do not belong in
the store back to `.env`; `secrets remove <key>...` deletes unused keys
(refuses any key something reads, keeps a backup; `--dry-run`); `secrets
reveal <NAME>` shows one human-held secret once on the terminal and offers
it to the clipboard.

### Rotate a secret

```sh
noo security secrets rotate --all-generated --dry-run
noo security secrets rotate REDIS_PASSWORD NOO_JWT_SECRET --restart
echo -n "$KEY" | noo security secrets rotate OPENAI_API_KEY --set-from-stdin
```

`rotate` plans, prepares a fully encrypted replacement store next to the
original, applies the datastore side (`ALTER ROLE` for database
passwords, verified by a real login and reverted on failure), then
commits with one rename — any failure earlier leaves the store
byte-identical. `--all-generated` covers every key the tool can mint and
apply itself; provider-issued keys need `--set-from-stdin` (stdin must be
a pipe, never a TTY); fleet-wide keys (`NOO_CLUSTER_SECRET`,
`NOO_NODE_AGENT_TOKEN`) are refused here — mint a value with `noo security
generate-secret cluster`, edit the store with `sops`, restart the stack,
then `noo cluster push-secrets`. The report
shows `<KEY>  len NNN  sha256 xxxxxxxx` per key, never the value, and
names the containers that still hold the old value; `--restart` recreates
the stack for you (`noo stack restart --force` otherwise — a plain
restart keeps the old environment). See
[backup-restore-secrets.md](../operating/runbooks/backup-restore-secrets.md).

### Apply a security posture

```sh
noo security posture list
noo security posture apply-profile hardened
noo security posture set NOO_EXEC_APPROVAL_MODE approval
noo stack restart gateway
```

The gates are `NOO_EXEC_APPROVAL_MODE`, `NOO_NODE_AGENT_PRIVILEGED`,
and `NOO_MCP_EXTERNAL_ENABLED`; `list` shows
`gate | running | desired (db) | source | restart` and how many are pending
a restart. (Tenant isolation is not among them — it is unconditional, not a
gate.) `NOO_NODE_AGENT_PRIVILEGED` is consumed by compose when the node-agent
container is created, not by the gateway, so `set` and `apply-profile` mirror
it into `.env` (as `true`/`false`) and **recreate the node-agent container**
when it differs; `list` and `cluster verify` report the container's actual
`HostConfig.Privileged` (`docker inspect`), so "at desired" means the
container. On a host with no such container the row says "container not
checked". The profiles are `hardened` (approval mode, unprivileged agents) and
`dev` (the opposite); **both** leave the external MCP door closed —
opening it is a decision about a specific person,
never a side effect of a bundle. `set` and `apply-profile` are
operator-only (your operator client certificate plus a token bound to it,
never an app admin and never a shared secret) and take effect at the next
gateway boot. `noo security scan` is the local complement.

**What it scanned.** The first line says which root it read and how that root
was chosen (`$NOO_REPO_ROOT`, the standalone install home, the checkout you
are standing in, or derived), and `--json` carries the same as `scanned`. On
a host that is an **enrolled node** (it has `/etc/noo/controller-url`) and has
no install of its own, it scans the node's real surfaces instead: the modes
and ownership of everything under `/etc/noo/pki` (a world-readable key is
CRITICAL), `/etc/noo-node-agent.env` (must be `0600` root), the birth key
`/etc/noo/birth.key`, a stale legacy `NATS_USER`/`NATS_PASSWORD` in the
agent's env file, and the node-agent unit (`User=` not root,
`NoNewPrivileges=true`). The controller-only rows (JWT, cluster and
controller secrets, Redis, TLS, Grafana, the audit key, mTLS, CSP, exec
approval) are listed as "not applicable on a node", never as passed. With no
install and no enrollment there is nothing to scan: it says so and exits 1.

**Never "ok" for what it could not see.** Anything it could not read is
printed as `NOT CHECKED` (and listed under `not_checked` in `--json`): the
agent's env file is `0600 root`, so a non-root scan reports the file's mode
but says its contents were not read; the gateway-side rows need an operator
login (`noo auth login`); the node-agent container needs docker. "No issues
found" then says how many surfaces were not checked.

**What it checks on a controller.** Secrets (JWT, cluster, **controller**,
node-agent token, Redis, Grafana, the bootstrap `NOO_ADMIN_PASSWORD`) for
empty values and for the **published placeholders** (`changeme`, `admin`,
`password`, `secret`, `test`, `example`, `dev-secret-change-in-production`);
the **audit key** (`NOO_AUDIT_HMAC_KEY` missing is CRITICAL: the gateway
refuses to start without it); **mTLS enforcement** judged on its effective
value (explicitly off, or no cluster CA, is HIGH); an explicit `NOO_CSP=0`/`off`
(MEDIUM; CSP is opt-in); the env-only hatches
`NOO_NATS_ALLOW_ANONYMOUS` and `NOO_ALLOW_LOCAL_PYTHON_EXEC` (HIGH each);
the gateway's running **exec approval mode** when it is neither `strict` nor
`approval` (HIGH; a not-yet-restarted `auto` row is MEDIUM);
`NOO_SANDBOX_ISOLATION=process` (MEDIUM, a downgrade from `bwrap`); the
node-agent container actually running **privileged** (HIGH, from `docker
inspect`); plaintext residue under `secrets/`; retired shared NATS names;
inline registry logins in `~/.docker/config.json`; `.env` permissions; TLS;
the PKI; and the **gateway transport**. Exit 1 on a CRITICAL, or on anything
with `--strict`; `--json` for CI. A store that is present but cannot be
decrypted — `sops` off `PATH`, no age key — is one HIGH finding that says so,
not a CRITICAL "unset" per secret. A gateway URL the CLI could not verify — a
non-loopback `http://` URL, or an `https://` one with no usable trust anchor —
is reported as `CRITICAL / Gateway Transport`; `http://` to loopback is
reported as `LOW`, because that is the local-development default.

### Sign and verify an add-on lock

An add-on releases from its own repository with its own signed lock: the
add-on's version, the commit it was built from, the stack versions it runs
on, and each image pinned by digest. The add-on's release workflow signs it
with the add-on's own Ed25519 seed, never the stack release key:

```sh
printf '%s' "$ADDON_SIGNING_SEED" | noo security addon-lock sign \
  --addon example_addon --version 1.2.0 --source-commit "$GITHUB_SHA" \
  --supports v0.6.0 \
  --image example-addon=ghcr.io/example/example-addon@sha256:<64 hex> \
  --registry ghcr.io/example/example-addon \
  --seed-file - --out addon-lock.json
noo security addon-lock verify addon-lock.json --key <pubkey hex> \
  --addon example_addon --registry ghcr.io/example/example-addon --stack v0.6.0
```

`sign` writes the lock in its one canonical JSON form and the signature
(`noo-sig1`, the stack lock's envelope) next to it as `addon-lock.json.sig`.
It reads the seed from a file, or from standard input with `--seed-file -`,
never from an environment variable, and never prints it. It refuses a lock
no verifier would accept. `--base trellion=sha256:…` records the stack image
an add-on is built on.

`verify` refuses a lock whose signature does not match a `--key` (repeat the
flag for a rotation: current key first), a lock for another add-on, an image
outside `--registry` or not pinned by digest, a lock with no stack version,
and a lock that is not in canonical form. `--stack` also requires the lock to
list that stack version exactly; an rc and its final are separate entries.

A release also signs a **bundle** lock: the same command with one
`--file <name>=<path>` per file the add-on ships beside its images (its
compose overlay, `--file docker-compose.yml=bundle/docker-compose.yml`, at
least). The lock then has format `noo-addon-lock/2` and lists each file's
sha256 under `files`, so the one signature covers them. Write it to
`--out addon-bundle.json`; `verify addon-bundle.json … --files-dir <dir>`
also refuses any listed file in `<dir>` that is missing or does not hash to
the lock. The layout both locks are published in is in
[the add-on guide](../development/addons.md#the-signed-add-on-lock).

## Related guides

- [../security/secrets.md](../security/secrets.md) — the secret store and `noo security secrets`
- [../operating/runbooks/backup-restore-secrets.md](../operating/runbooks/backup-restore-secrets.md) — SOPS/age secrets: backup, restore, rotation
- [README.md#contracts](README.md#contracts) — how the CLI picks a credential

## Command reference

<!-- BEGIN GENERATED: cli-reference section="Security" — do not edit; regenerate with scripts/gen-cli-docs.py -->
### `noo security` — Users, secrets, PKI, scanning, CA trust
| Command | Arguments | What it does |
|---|---|---|
| `noo security pki status` | — | List every certificate under the PKI dir with expiry and days left |
| `noo security pki init` | — | Generate the cluster CA in the PKI dir (refuses to overwrite an existing one) |
| `noo security pki issue` | `<node_id> <ip> [--days <n>] [--san <name>]...` | Issue a node certificate signed by the cluster CA (adds the tailnet IP SAN) |
| `noo security pki issue-service` | `<service> [--days <n>] [--san <name>]...` | Issue a service certificate with this box's derived names; --san adds more |
| `noo security pki issue-gateway` | `[<hostname>] [<ip>] [--days <n>] [--extra-ip <ip>]... [--extra-san <san>]...` | Issue the dual-purpose gateway certificate (defaults gateway/127.0.0.1) |
| `noo security pki issue-sso-key` | `[--force]` | Issue the Grafana SSO key pair (pki/sso/); --force re-mints and logs Grafana out |
| `noo security pki rotate` | `<node_id> <ip> [--days <n>]` | Hidden: alias of `pki issue` (local files only; not delivered) |
| `noo security pki fix-modes` | `[--dry-run]` | Repair PKI key modes now (upgrade and issue do too); print sudo lines for the rest |
| `noo security pki issue-client` | `<operator> [--days <n>] [--force]` | Issue and register your operator client certificate for posture writes (key 0600, own dir) |
| `noo security pki rotate-client` | `<operator> [--days <n>]` | Replace your operator certificate: register the new one, then revoke the old |
| `noo security pki revoke-client` | `<operator> [--thumbprint <tp> \| --others] [-y\|--yes]` | Revoke an operator's certificates (bare: ALL of them); asks for confirmation (-y) |
| `noo security user list` | — | List user accounts with scopes, role, and login stats |
| `noo security user create` | `<username> [--scope <scope>]... [--password-stdin]` | Create a user account (read-only unless --scope is given; prompts for password) |
| `noo security user grant-role` | `<username> -r\|--role <role>...` | Grant extra KB roles to a user |
| `noo security user revoke-role` | `<username> -r\|--role <role>...` | Revoke KB roles from a user |
| `noo security user list-roles` | — | List extra KB role grants across all users |
| `noo security user link` | `<username> <channel> <channel_user_id> [--name <display>]` | Link a channel identity to a user account |
| `noo security user unlink` | `<channel> <channel_user_id>` | Remove a channel identity link |
| `noo security user links` | `<username>` | List the channel identities linked to a user |
| `noo security user set-password` | `<username> [--password-stdin]` | Set a user's password (prompts unless --password-stdin) |
| `noo security admin-password reset` | `[--stdout] [--yes]` | On the controller, no login: reset the admin, end its sessions, show the new password once |
| `noo security user set-scopes` | `<username> --scope <scope>...` | Replace a user's auth scopes with the given set (admin-only) |
| `noo security user allowance` | `<username> [-t\|--tokens <n>] [-p\|--period day\|week\|month] [--clear]` | Show, set or clear a user's standing token allowance per period (setting is admin-only) |
| `noo security user set-org` | `<username> <org_id>` | Assign a user to an org |
| `noo security user disable` | `<username> [-y\|--yes]` | Disable a user account (undo with `user enable`); asks for confirmation (-y) |
| `noo security user enable` | `<username>` | Re-enable a disabled user account |
| `noo security user erase` | `<username> [--yes] [--keep-account]` | Erase a user's data (dry-run preview without --yes; -y executes) |
| `noo security user proposals` | — | List agent-filed user proposals and their status |
| `noo security user decide` | `<id> (--approve \| --deny) [--reason <text>]` | Approve or deny a user proposal (prints a generated password once) |
| `noo security team list` | — | List registered teams with members and doc counts |
| `noo security team create` | `<name> [--description <text>]` | Create a team and its team:<name> KB role |
| `noo security team delete` | `<name> [--force] [--yes]` | Delete a team; asks for confirmation (-y); --force deletes with members/docs |
| `noo security team link-space` | `<team> <channel> <space_id>` | Link a channel space to a team as a shared space |
| `noo security team unlink-space` | `<channel> <space_id>` | Unlink a channel space from its team |
| `noo security team spaces` | `<team>` | List the channel spaces linked to a team |
| `noo security org list` | — | List orgs with member counts |
| `noo security org create` | `<org_id> [--name <name>] [--description <text>]` | Create an org |
| `noo security tailnet policy` | `[--merge \| --push] [--yes]` | Compare live tailnet policy to declared; --merge adds what is missing, --push replaces |
| `noo security audit verify` | — | Verify audit hashes, the chain, and its head against the exported head (operator-only) |
| `noo security audit list` | `[--since <30m\|24h\|7d\|time>] [--event <type>] [--actor <name>] [-n <limit>] [--cursor <c>]` | List security audit rows, newest first, with source address (operator-only) |
| `noo security at-rest status` | `[--json]` | Show TPM facts, how to enable one, and your recorded at-rest encryption decision |
| `noo security at-rest opt-out` | — | Record that you accept unencrypted data at rest (audited; needs your own login) |
| `noo security at-rest opt-in` | — | Withdraw the at-rest opt-out (audited; needs your own login) |
| `noo security at-rest create-volume` | `[--size <GiB>] [--pcrs 7\|none\|auto] [--defer-recovery-key] [--dry-run]` | Create the TPM-unlocked encrypted state volume; shows its recovery key once |
| `noo security at-rest seal` | `[--pcrs 7\|none\|auto] [--dry-run]` | Seal the age key to this TPM; unsealed into RAM at boot, plaintext kept until finalize |
| `noo security at-rest finalize` | `[--dry-run] [-y\|--yes]` | Remove the plaintext age key once a reboot unsealed it and a fresh backup decrypts |
| `noo security at-rest migrate` | `[--dry-run] [--rollback] [--yes] [--confirm-offbox <phrase>]` | Move this controller's state onto the encrypted volume: backup first, reversible |
| `noo security at-rest wipe-plaintext` | `[--dry-run] [--hours <N>] [--confirm <phrase>]` | Delete the old plaintext state after a verified migration and a day of healthy running |
| `noo security at-rest recovery-key` | `[--dry-run]` | Enroll a new recovery key, shown once; the old one is removed only after you confirm |
| `noo security at-rest reenroll` | `[--pcrs 7\|none\|auto] [--dry-run]` | Re-enroll the TPM after a firmware or Secure Boot change and reseal the age key |
| `noo security at-rest preflight-firmware` | `[--json]` | Before a BIOS or firmware update: check the recovery key and a fresh backup |
| `noo security posture list` | — | List security posture gates: running vs desired value (operator-only) |
| `noo security posture set` | `<key> <value>` | Set a posture gate; needs an operator cert (`pki issue-client`); restart to apply |
| `noo security posture apply-profile` | `<profile> [--include-bridges]` | Apply a posture profile (needs an operator cert); leaves rollout bridges; restart to apply |
| `noo security service-key issue` | `<consumer> [--scopes <scope>]... [--note <text>] [--rpm <n>] [--user <username>]` | Issue a service key, shown once; scopes default to chat,embeddings,rerank,classify,mcp |
| `noo security service-key list` | `[--all] [--callers]` | List service keys (hashes only); --all adds revoked ones, --callers retired add-on callers |
| `noo security service-key revoke` | `<consumer> [--disable-account] [-y\|--yes]` | Revoke a consumer's keys, for good (-y); --disable-account also kills issued tokens |
| `noo security service-key rotate` | `<consumer> [--scopes <scope>]... [--note <text>]` | Rotate a consumer's key; scopes and rpm kept, old key live until `retire` |
| `noo security service-key retire` | `<consumer>` | Finish a rotation: deactivate the superseded key, once the new one has been used |
| `noo security service-key provision` | `<name> [--scopes <s>]... [--wait <secs>] [-y]` | Show the declared grant and confirm, then mint, store, recreate and PROVE the key |
| `noo security service-key set-quota` | `<consumer> <rpm>` | Set the per-minute request cap for a consumer's keys (0 = uncapped) |
| `noo security service-key self` | `[--note <label>]` | Mint or rotate the caller's own MCP key (raw key shown once) |
| `noo security service-key self-status` | — | Show whether the caller has an active MCP key and when it was used |
| `noo security service-key self-revoke` | — | Revoke the caller's own MCP key |
| `noo security generate-secret` | `[<type>] [--length <bytes>]` | Print a random secret: general (jwt, cluster alike) or fernet; --length not for fernet |
| `noo security entitlement keygen` | `[--out <file>]` | Hidden: create the entitlement signing key, mode 600 (vendor builds only) |
| `noo security entitlement issue` | `--sub <customer> (--terms <version>\|--no-terms) [--tier intelligent] [--features a,b] [--days <n>] [--id <id>] [--addon <name>=<registry>:<key>[,<key>]]... [--pull-host <host>] [--bind-key <hex>] [--key <file>]` | Hidden: sign an entitlement token for a customer (vendor builds only) |
| `noo security entitlement install` | `<token> [--enable] [--ci] [--accept-terms <version>]` | Verify and store a token as NOO_ENTITLEMENT; --enable mints and switches on what it grants |
| `noo security entitlement show` | — | Show the installed entitlement, its validity, and which add-ons it unlocks |
| `noo security entitlement verify` | `<token>` | Verify a token offline against this build's entitlement key |
| `noo security entitlement pubkey` | — | Print this controller's add-on key (hex) for the vendor to bind the entitlement to |
| `noo security release-sign` | `<file> [--seed-file <path>] [--out <file.sig>]` | Hidden: sign sha256sums.txt with the release key (CI only) |
| `noo security release-verify` | `<file> [<file.sig>]` | Verify a release manifest signature against the keys baked into this build |
| `noo security addon-lock sign` | `--addon <name> --version <v> --source-commit <sha> --supports <tag>[,<tag>]... --image <name>=<ref@digest>... [--base <image>=<digest>] [--file <name>=<path>]... [--registry <root>] --seed-file <path\|-> --out <path>` | Hidden: sign an add-on lock with the add-on's own key (add-on CI only) |
| `noo security addon-lock verify` | `<path> --key <pubkey>... --addon <name> --registry <root> [--sig <path>] [--stack <tag>] [--files-dir <dir>] [--dev-key <pubkey>]...` | Verify a signed add-on lock against the add-on's release keys and registry root |
| `noo security secrets tidy` | `[-y\|--yes]` | Thin the store to secrets only: move config to .env, drop retired keys, blank .env copies |
| `noo security secrets audit` | `[--sops-file <path>] [--env-file <path>]` | Compare env.sops against .env by digest and report findings (no values shown) |
| `noo security secrets resync` | `<key>... \| --all [--dry-run] [--sops-file <path>] [--pg-container <c>] [--pg-db <db>] [--pg-superuser <user>]` | Make Postgres role passwords match the values already in the SOPS store |
| `noo security secrets remove` | `<key>... [--yes] [--dry-run] [--sops-file <path>]` | Remove unused keys from env.sops; refuses any key something reads, keeps a backup |
| `noo security secrets rotate` | `<key>... [--all-generated] [--dry-run] [--yes] [--prompt] [--set-from-stdin] [--stdout] [--restart] [--sops-file <path>] [--pg-container <c>] [--pg-db <db>] [--pg-superuser <user>]` | Rotate secrets in env.sops, Postgres and the backup files atomically; confirms unless -y |
| `noo security secrets reveal` | `<NAME> [--no-clipboard] [--stdout] [--sops-file <path>]` | Show one human-held secret once on this terminal and offer it to the clipboard |
| `noo security scan` | `[--strict]` | Scan this install's or node's posture; exit 1 on a CRITICAL, or any finding with --strict |
| `noo security pki rotate-all` | `[--warn-days <n>] [--new-days <n>] [--yes] [--reload \| --no-reload] [--no-deliver]` | Re-issue expiring certs, deliver to nodes, restart consumers; asks for confirmation (-y) |
| `noo security pki rotate-ca` | `[--ca-days <n>] [--leaf-days <n>] [--yes] [--retire-old]` | Cross-signed CA rotation across every node; asks for confirmation (-y) |
| `noo security pki rotate-signing-key` | `[<node>] [--deliver-only] [--yes]` | Mint the fleet code-signing key and deliver its public half to every node (-y to confirm) |
| `noo security secrets absorb-files` | `[-y\|--yes]` | Fold file credentials and legacy secrets/*.txt into env.sops; shreds what reads back (-y) |
| `noo security pki issue-node` | `<node> [<ip>] [--days <n>] [--mint-only]` | Issue a node cert and deliver it, waiting for the node to confirm it applied |
| `noo security pki push-nodes` | `[<node>] [--days <n>] [--yes]` | Re-issue node certs plus ca.crt and stage them on the pull rail for each node |
| `noo security trust-ca` | `[<ca_path>]` | Install the cluster CA into the OS trust store (default $NOO_PKI_DIR/ca.crt) |
| `noo security untrust-ca` | `[--yes]` | Remove the cluster CA (by name) from the OS trust store; asks for confirmation (-y) |

### `noo auth` — Per-user CLI credentials
| Command | Arguments | What it does |
|---|---|---|
| `noo auth connect` | `google [--drive] [--gmail] [--pair]` | Connect Google in a browser; --pair displays a code to approve on your phone |
| `noo auth login` | `[<username>] [-u <username>] [--password-stdin]` | Log in to the gateway and store a per-user access/refresh credential |
| `noo auth status` | — | Show which credential this CLI would use and whether the gateway accepts it |
| `noo auth logout` | — | Revoke the stored refresh token server-side and delete the local credential |
<!-- END GENERATED -->
