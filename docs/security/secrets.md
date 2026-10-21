# Secrets and the three configuration planes

Every configuration value has exactly one home. Secrets live in an
encrypted store the launcher decrypts at start and hands to each container
that reads them — as a file under `/run/secrets` for noomesh's own
containers (see [How secrets reach a container](#how-secrets-reach-a-container));
everything else lives in `noomesh.yaml`; a handful of security gates live
in the database. `noo onboard` sets the encrypted store up by default —
this page is how to keep it healthy.

```bash
noo security secrets audit          # does the store agree with .env? (never prints a value)
```

## The three planes

| Plane | Home | Holds | Applied by |
|---|---|---|---|
| **Secrets** | `secrets/env.sops` — dotenv text encrypted with [SOPS](https://github.com/getsops/sops) + [age](https://age-encryption.org) | passwords, API keys, tokens, passphrases, file-shaped credentials | `load_secrets` in the launcher (`scripts/lib-secrets.sh`), before compose runs |
| **Config** | `noomesh.yaml` | everything else — nested sections read by the application (env → yaml → default), and a flat `compose_env:` map exported for compose interpolation and host scripts | `load_config` (`scripts/lib-config.sh`) |
| **Posture** | `noo_security_posture` table | the allow-listed security gates (`NOO_EXEC_APPROVAL_MODE`, `NOO_NODE_AGENT_PRIVILEGED`, `NOO_MCP_EXTERNAL_ENABLED`, `NOO_SELF_CALL_SHARED_SECRET` — `POSTURE_KEYS`; retired keys (`NOO_CLUSTER_LEGACY_FULL_ACCESS`, `NOO_BOOTSTRAP_ACCEPT_UNSIGNED_FETCH`, `NOO_BUS_PRINCIPAL`, `NOO_APPROVAL_BREAK_GLASS`) refuse the boot while a row holds one open; `NOO_NATS_LEGACY_SHARED_CREDS` was retired with the shared bus user; `NOO_MULTI_USER` is gone, tenant isolation is unconditional) | `noo security posture set` / `apply-profile hardened` (which `noo onboard` applies), read once at gateway start |
| **Add-ons** | `noomesh.yaml` `addons:` | which add-ons this install runs | read by the launcher for compose overlays and by the gateway for routing — never `.env`, which `noo stack start` now refuses to start with the retired flags in it |
| *(bootstrap)* | `.env` | the flags the launcher must read **before** the store or the DB can be opened: `NOO_SECRETS_BACKEND`, `NOO_INSTALL_MODE`, `NOO_INSTANCE`, `NOO_PORT_OFFSET` — plus compose-interpolated non-secrets the wizard writes there (channel allow-lists, model choices) | read directly by the launcher scripts |

### `NOO_SECRETS_BACKEND`

`sops` is the only backend `noo onboard` produces, and what `.env.example`
ships. The rule is "always sops, never plaintext".

| Value | Meaning |
|---|---|
| `sops` | decrypt `secrets/env.sops` at launch. No plaintext secrets at rest. Fails closed: a missing `sops` binary, a missing store, or an unavailable age key stops the launch with a message naming `scripts/noo-secrets-sops-init.sh`, rather than starting with no secrets |
| `env` | **retired (2026-09-30).** Secrets in plaintext `.env`. `noo onboard --secrets-backend env` is refused (exit 2), and the wizard never falls back to it: a missing or failing SOPS init script stops onboarding with exit 1 before any secret is minted. The launcher refuses to start an install that predates this (below), as does everything else that judges it |

An install still on `env`, or holding any secret-class value in `.env`
beside the store, is found and refused:

| Where | What it says |
|---|---|
| `noo cluster verify --controller` | row `secrets at rest` **FAILS**, naming the keys (never a value) |
| `noo security scan` | **CRITICAL** `Secrets At Rest` — the scan exits 1 |
| `noo upgrade --stack` | refuses the roll before anything moves (`plaintext_secrets`); nothing is auto-migrated |
| `noo stack start` / `restart` / `rebuild` (the launcher scripts) | refuse before any compose command, naming the keys and the remedy (`noo config launch-check secrets-at-rest`, called by `scripts/lib-secrets.sh` `check_secrets_at_rest`). A `noo` too old to have the check warns and starts |
| `noo onboard` | stops at the secrets step if the store cannot be armed |

The remedy is the same everywhere: `noo onboard --reconfigure --only secrets --secrets-backend sops`, then `noo security secrets tidy`. The onboard run creates the store
if there is none, carries every `.env` secret into it (on an `env` install
`.env` was the live copy, so its values win; on a `sops` install the store's
do) and blanks each `.env` slot. `tidy` then blanks any secret-class value
still in `.env` **that the store already holds** — it refuses on an `env`
install, and leaves (and fails on) a value whose only copy is `.env`, so it
can never drop the last copy of a secret. `tidy`'s other half moves CONFIG
out of the store back to `.env`; it never moves a secret-class key (before
noo-cli v0.5.71 it judged by the name alone, and moved `NOO_ENTITLEMENT` and
`NOO_FILECRED_GOOGLE_CHAT_B64` into plaintext `.env`).

The `secrets at rest` row opens the store before it says anything about a
copy: it names which `.env` secrets live **only** in `.env` (the onboard carry
moves those in first; never blank them by hand) and which are a stale copy of
a value the store holds (`noo security secrets tidy` alone clears those). If
the store cannot be read, it says so and claims nothing.

"Secret-class" is the registry's word, not a new list: a file-backed name
(`secrets_delivery.rs` `TIER1`), any rotation-registry row
(`secrets.rs` `CORE_REGISTRY` and the add-on rows), or a credential-shaped name
(`looks_like_credential`, which spares the bootstrap flags such as
`NOO_SECRETS_BACKEND`). The shared definition is
`noo-cli/src/commands/plaintext_env.rs`.

An unknown value is a hard error (`scripts/lib-secrets.sh`), never a silent
fallback to either.

Decide with these questions, in order:

1. **Would leaking it hurt?** → `secrets/env.sops`. Never also in `.env`:
   the launcher loads the store first and `.env` second, so a `.env` copy
   is a silent duplicate that `secrets audit` flags as `credential-in-env`.
2. **Is it one of the five posture gates?** → `noo security posture set`.
   Not `noomesh.yaml`: `noo config set` is reachable by any `write`-scope
   account, which could then flip a gate meant to constrain it.
3. **Must it exist before the store or the DB can be read?** → `.env`.
4. **Everything else** → `noomesh.yaml`: a nested section if the
   application reads it at runtime, `compose_env:` if compose or a host
   script interpolates it.

**If the system already declares a fact, config must not restate it.** A
value present in two planes becomes a stale override that silently wins —
a key in both `.env` and `compose_env:` is warned about on every launch,
and `.env` wins for compose.

Paths are relative to the install root: the repository checkout, or
`~/.noo` on a [standalone controller](../getting-started/standalone-controller.md).
`secrets/` and `.env` are git-ignored.

## How the store works

- **Recipient.** `.sops.yaml` holds one creation rule — `secrets/.*\.sops$`
  encrypted to one age public key. The matching private key lives at
  `~/.config/sops/age/keys.txt` (or wherever `SOPS_AGE_KEY_FILE` points),
  mode `0600`. `scripts/noo-secrets-sops-init.sh` installs `age` and
  `sops` into `~/.local/bin` if needed, generates the key (never
  overwriting an existing one), writes the rule, and encrypts the current
  `.env` into the store.
- **Loading.** `load_secrets` decrypts the store into memory (never to a
  file) and exports every `KEY=VALUE` so compose inherits it. It fails
  closed: no `sops` on `PATH`, no store, or a decrypt error aborts `noo
  stack start`; a stack whose `POSTGRES_PASSWORD`, `NOO_JWT_SECRET` or
  `NOO_CLUSTER_SECRET` would be blank is refused. `NOO_IMAGE_TAG` is the one
  key deliberately never exported from the store.
- **Backend switch.** `NOO_SECRETS_BACKEND=sops` (what onboarding always
  writes) activates all of this. `env` — compose reading plaintext `.env` —
  is retired: onboarding refuses it, the launcher will not start an install
  still on it, and verify, scan and upgrade fail it (see [`NOO_SECRETS_BACKEND`](#noo_secrets_backend)).
  Any other value is an error.
- **File-shaped credentials.** A Google service-account key is stored as
  `NOO_FILECRED_GOOGLE_CHAT_B64` and consumed as a VALUE: the gateway parses
  `GOOGLE_CHAT_CREDENTIALS_JSON` in memory. Nothing is written to disk. The
  launcher used to decode it into `secrets/.runtime/` at every start (it
  aimed for `0640`, widened to `0644` when it could not `chgrp`, and relied on
  `noo stack stop` to remove it); that mechanism is gone, but a file written
  before the change outlives it until the next stop, so `noo security scan`
  reports any file under `secrets/.runtime/` as **CRITICAL** with the
  `shred -u` to run.
- **Finding `sops`.** The installer puts `sops` and `age` in `~/.local/bin`,
  which an interactive shell has on `PATH` and a systemd unit, cron job, host
  watcher or `ssh host noo …` does not. The launcher and the CLI both look
  there (then `/usr/local/bin`, then beside the `noo` binary) before
  concluding it is missing, and a store that is present but unreadable —
  `sops` not found, no age key, a key that does not open it — is reported as
  exactly that, never as "every secret is unset".
- **Precedence in the CLI.** `noo` resolves a value as process env → secret
  store → `noomesh.yaml` `compose_env` → `.env`.

The wizard mints `NOO_JWT_SECRET`, `NOO_CLUSTER_SECRET`,
`NOO_CONTROLLER_SECRET`, `REDIS_PASSWORD`,
`NOO_NODE_AGENT_TOKEN`, `POSTGRES_PASSWORD`, `NOO_AGENT_REVIEW_KEY`,
`NOO_AUDIT_HMAC_KEY` (see [The audit key](#the-audit-key)), the
per-system Postgres role passwords
(`NOO_APP_DB_PASSWORD`, `NOO_TRELLION_DB_PASSWORD`, …), the two backup
passphrases (`NOO_BACKUP_PASSPHRASE`, `NOO_AGE_BACKUP_PASSPHRASE` — see
below) and the admin credential; channel tokens, provider API keys and the Tailscale OAuth
client land there when you configure them.

## How a service reads a secret

Every tier-1 secret — the ones the stack's own services trust each other
with (`NOO_JWT_SECRET`, `NOO_CLUSTER_SECRET`, `NOO_CONTROLLER_SECRET`,
`NOO_NODE_AGENT_TOKEN`, `REDIS_PASSWORD`, `NOO_AUDIT_HMAC_KEY`,
the NATS and Postgres role passwords, the agent-review,
JWKS-signing and entitlement keys) — and every provider or channel
credential (`ANTHROPIC_API_KEY`, `OPENAI_API_KEY`, `GOOGLE_API_KEY`,
`TAVILY_API_KEY`, `BRAVE_SEARCH_API_KEY`, `TELEGRAM_BOT_TOKEN`,
`WHATSAPP_TOKEN`, `GOOGLE_CHAT_BEARER_TOKEN`, `GOOGLE_CHAT_CREDENTIALS_JSON`)
is read through one helper per language: `secret_env` in the Rust gateway and `noomesh.secret_env` in the
Python worker and CLI. The helper exports the list of names it reads, and
`tests/test_file_reader_parity.py` keeps the two lists agreeing with each
other and with what compose actually delivers to each container, and fails
on any reader that takes a listed name straight from the environment
(`std::env::var("NAME")`, `os.getenv("NAME")`) — such a reader sees nothing
once compose delivers that name as a file.

For `NAME`, the helper looks, in order, at:

| Tier | Variable | Meaning |
|---|---|---|
| 1 | `NAME_FILE` | a path; the secret is the file's content minus **one** trailing newline (`\n` or `\r\n`). Nothing else is trimmed — a secret is bytes. |
| 2 | `NOO_SECRET_NAME` | the older prefix convention |
| 3 | `NAME` | the plain variable — what the containerised node agent and nats still receive (below) |

An empty value at any tier counts as unset and falls through.

Both `NAME` and `NAME_FILE` set is a refusal to start, never a choice: one
of them is stale and nothing says which. Both readers keep the file's bytes
(no newline translation) and strip one trailing `\n` or `\r\n`, so one
file answers the same in both runtimes (`tests/test_secret_env.py` pins the
byte vectors against the Rust test).

## How secrets reach a container

Since 2026-09-29 noomesh's own containers — `noo-gateway`, `noo-worker`
(and its replicas), `noo-redis`, `noo-postgres`, `noo-grafana`,
`noo-browser` — receive every tier-1 secret as a **file**, and hold no
secret in their environment at all. From stack-v0.2.80 the provider and
channel credentials travel the same way: the gateway gets every one of
them, the worker the four channel ones it checks to report which channels
are configured (`TELEGRAM_BOT_TOKEN`, `WHATSAPP_TOKEN`,
`GOOGLE_CHAT_BEARER_TOKEN`, and the Google Chat service-account key, whose
store key is `NOO_FILECRED_GOOGLE_CHAT_B64` and whose file is
`GOOGLE_CHAT_CREDENTIALS_JSON_FILE`):

1. The launcher decrypts `secrets/env.sops` into its **own** process
   environment (`load_secrets`), as it always has.
2. `load_secrets` then **writes each secret to a file on a tmpfs** (see
   [Where the files live](#where-the-files-live) below). `docker-compose.cluster.yml`
   declares each secret at top level as
   `file: ${NOO_SECRET_RUNDIR}/<name>` with an `x-noo-source: VAR` naming the
   launcher variable the file is written from (compose ignores `x-` keys; the
   launcher reads them). An add-on overlay declares the secrets only it takes
   (its own gateway key, its pgpass body) the same way; compose merges
   top-level `secrets:` across files, and the launcher reads every
   `docker-compose.*.yml` beside the base. Compose bind-mounts each file into
   the consumer as `/run/secrets/<target>`, read-only, with the file's owner and
   mode: `0400`, owned by the user the image runs as.
3. The service's environment carries only a pointer:
   `NOO_JWT_SECRET_FILE=/run/secrets/noo_jwt_secret`, and the reader above
   follows it. Native consumers use their own spelling:
   `POSTGRES_PASSWORD_FILE` (the postgres image),
   `REDIS_PASSWORD_FILE` (`docker/redis-entrypoint.sh`), and
   `GF_SECURITY_ADMIN_PASSWORD=$__file{/run/secrets/…}` for Grafana, which
   expands `$__file{}` itself. (Not `GF_…__FILE`: that suffix is implemented
   by the upstream Grafana image's `run.sh`, which the hardened image does not
   have — measured, it was silently ignored.)

Nothing is written anywhere else. The value exists in the launcher's process
while it runs, in one RAM-backed file per secret, and inside each consumer
through a bind of that file: not in a container's environment, not in its
writable layer (`docker diff` shows no secret), not on a disk.

### Where the files live

The gateway, the worker (and its replicas) and trellion run with a read-only
root filesystem ([networks-and-containers.md](networks-and-containers.md)),
and compose refuses to create an `environment:`-sourced secret in a read-only
service (it would copy the value into the container's layer; `file` is the
sole supported option). So the launcher (`write_secret_files` in
`scripts/lib-secrets.sh`, called by `load_secrets`, which every launcher,
noo-hostd and the onboarding wizard's compose wrapper run first) writes them:

| Launched as | Directory |
|---|---|
| root (`sudo noo …`, a system-unit noo-hostd) | `/run/noo/secrets` |
| the operator (an interactive `noo stack start`, a user-unit noo-hostd: the controller's normal case) | `/dev/shm/noo-secrets-<uid>` |
| `NOO_SECRET_RUNDIR` set | that directory |

`/run/user/<uid>` would be the usual home for an operator's runtime files and
is deliberately not the default: it is unmounted at the last logout unless
linger is on, and a container's restart policy re-resolves its bind sources, so
a crashed service could not come back. `/dev/shm` lives until reboot.

Each start rewrites every file (a temp name, then an atomic rename) before
compose creates anything:

* one file per secret, mode `0400`, owned by the uid its consumers run as. The
  uid is read from the `uid:` on the service entries in the compose file; a
  secret shared with a root-in-container service (the browser, the opt-in node
  agent) is owned by the non-root consumer, and root reads it through the
  default `CAP_DAC_OVERRIDE` (a test fails if such a service drops it); two
  different non-root uids on one secret are refused at launch. As root the
  launcher `chown`s; as the operator it runs a throwaway container
  (`alpine`, no network, only `CAP_CHOWN`) over a bind of the directory, the
  pattern `lib-reown.sh` uses, which sees file names and uids but never a value;
* the directory is `0700`, owned by the launcher's user, not a symlink, and
  must report `tmpfs` (or `ramfs`) for `stat -f -c %T`. Anything else is refused
  with the reason and the remedy, and nothing is written;
* a secret the store does not hold is an **empty** file (compose needs the
  bind source to exist) and its `_FILE` pointer stays unset, so it reads as
  unset;
* `noo stack stop` (the whole stack), `noo stack clean --deep`, `noo offboard`
  and the controller teardown script delete the files and the directory.

### After a reboot

The directory is RAM, so a reboot empties it, while dockerd starts every
container whose restart policy says so as soon as it is up. A container whose
bind source does not exist cannot be created for that start, and dockerd does
not retry it (a restart policy governs a container that started and exited, not
one that never could): it stays in `Created` until something starts it. Before
the files moved to tmpfs the values lived in each container's layer and the
stack simply came back, so noo-hostd, which a controller already runs at boot,
restores that. When it starts and finds the secret directory missing or empty
(`BootRestore`, `node-agent-go/internal/hostd/boot.go`) it:

1. runs `load_secrets`, which decrypts `secrets/env.sops` with the age key
   already on disk (`~/.config/sops/age/keys.txt`) and rewrites every file;
2. `docker start`s exactly the stopped (`created`/`exited`) containers that
   bind a file from that directory. It pulls, builds and recreates nothing, and
   a container that does not bind a secret is never touched;
3. retries for about two minutes while docker is not up yet, takes the same
   compose lock as every other mutating step, and logs `BOOT-RESTORE gave up:
   run noo stack start` if it cannot. If the directory is already populated (a
   hostd restart, not a reboot) it does nothing, so a service an operator
   stopped by hand stays stopped.

What this relies on: noo-hostd must be running at boot, as the user who owns
the age key. A controller installs it as a systemd **user** unit
(`WantedBy=default.target`), which starts at boot only with linger on:
`sudo loginctl enable-linger <user>` (`noo-hostd install` prints this line).
Without linger the user manager, and so hostd, starts at first login, and the
stack stays down until then or until `noo stack start`. A boot that cannot
decrypt the store (age key missing) writes nothing and starts nothing, loudly,
rather than starting services with empty credentials.

If a launcher is older than the compose file (a stale checkout, an older
`noo`), `NOO_SECRET_RUNDIR` is unset and compose binds a path that does not
exist: creating the container fails with `bind source path does not exist:
/nonexistent/noo-secret-rundir-unset/<name>`. It never starts a service with
no credentials. Run `noo upgrade --all`, which swaps the CLI (and with it the
launcher and compose files) before the stack.

**Add-on overlays ship before or with the stack change.** An overlay that
`extends` the read-only trellion service (trellion-intel) must source its own
secrets from `file:` + `x-noo-source:`, like the stack's. The launcher refuses
a start, before touching anything, when an overlay still declares
`environment:` secrets while extending a service (`_secret_form_conflicts`):
the error names the overlay and the secret and says `noo addons upgrade` or
`addons.<name>: false`. So the add-on's `file:` overlay ships **with or before** the stack that
introduces `write_secret_files`, never after: a new stack with the old overlay
is refused at launch (above); an old stack with the new overlay starts intel
with no secret files (`bind source path does not exist`, only intel affected),
so `noo upgrade --all` moves both in one step. An independent add-on that does not
extend a read-only service (noo-evolve) keeps working with `environment:`
secrets.

**Database passwords travel as pgpass.** No DSN carries a password any more
(`postgresql://noo_app@postgres:5432/noomesh?sslmode=…`). The gateway and the
worker each get `/run/secrets/pgpass` and `PGPASSFILE` pointing at it; sqlx
and libpq read it natively when the URL has no password, and both **ignore**
a pgpass with group or other permission bits, which is why it is `0400`. The
launcher derives the bodies from the role passwords
(`derive_file_secrets` in `scripts/lib-secrets.sh`): the gateway's has lines
for `noo` and `noo_app`, the worker's for `noo_app`, noo-trellion's (which
noo-trellion-intel inherits) for `noo_app`, `noo_trellion` and
`noo_trellion_ddl`, noo-evolve's for `noo_evolve` and `noo_evolve_ddl`. The
add-ons connect through psycopg, so theirs are libpq bodies. The two drivers disagree
about escaping in the password field — libpq needs `\\` and `\:`, sqlx takes
the rest of the line verbatim — so each body is written for the driver that
reads it.

**A declared system's flag and passwords travel in one file.** The gateway
has no `env_file`, so a variable reaches it only if compose names it.
trellion's and evolve's role passwords have their own lines; a system core
does not name (any other entry under `systems:` in `noomesh.yaml`) cannot.
For those the launcher writes ONE secret, `noo_systems_secrets`
(`_systems_secrets_body` in `scripts/lib-secrets.sh`, called from
`derive_file_secrets`): `KEY=VALUE` lines, `0400` to the gateway's uid, on the
same tmpfs as every other secret file. It holds, for each declared system, its
`enabled_when` flag (from `.env`, where `noo systems enable` sets it) and its
`password_env` / `ddl_password_env` values (from `secrets/env.sops`). A variable
a compose secret already delivers by name is not repeated, and a variable with
no value is left out. Values are written verbatim (no quoting), so a value
with a newline is refused with a warning that names the variable, never the
value. The gateway gets one pointer, `NOO_SYSTEMS_SECRETS_FILE`, and the broker
reads each name from its own environment first and from this file second.
Adding a system needs no compose line and no gateway change. The launcher
learns the declared systems from `noo config launch-render systems` (the CLI's
own `systems:` parser). An older `noo` without that section prints a warning
when `systems:` is present, and the launch goes on.

**A role's password is not the only thing that opens it.** Every login to
`noo`, `noo_app`, `noo_trellion` and `noo_trellion_ddl` also needs the client
leaf issued for that role (CN = the role: `gateway/pg/<role>.*`,
`services/<owner>/pg/<role>.*`, `0640` handed to the container's uid), checked
by `pg_hba.conf` with `clientcert=verify-full`. The leaves are not secrets in
the store: they are minted by `noo onboard`, `noo upgrade --stack` and the
launchers, rotated by `noo security pki rotate-all` like every other leaf, and
a rotated password does not touch them. The add-on roles `noo_evolve` and
`noo_evolve_ddl` still need only a cluster-CA certificate plus the password
(see [Networks and containers](networks-and-containers.md)).

**Optional secrets stay optional.** The launcher makes every source variable
exist, empty when the store has no value, and writes an empty file for it.
Each pointer is written `${NAME:+/run/secrets/…}`, so it is unset too: an
unset optional secret reads as unset, not as a broken mount.

**A bare `docker compose up` fails loud.** Without the launcher
`NOO_SECRET_RUNDIR` is unset, the secret files do not exist, and compose
refuses to create the services that take one (`bind source path does not
exist: /nonexistent/noo-secret-rundir-unset/…`). Use `noo stack start`.

**Images must read the files.** A gateway or worker image older than the
readers would see neither the value nor the pointer and start with no
credentials. The compose file declares the oldest stack whose images read
them (`x-noo-secrets-floor`), and `noo stack start --dist`,
`noo stack restart` and `noo upgrade --stack` all refuse a tag below it
(stack-v0.2.80 since the provider and channel keys became files; a
v0.2.79 gateway would start with no search key, bot token or Chat
credential and say only "not configured"),
naming `noo upgrade --stack`. Rolling back below the floor needs the `noo`
CLI that shipped that release.

**The add-ons too.** Since the add-on flip (stack-v0.2.80 images) the
add-on containers — `noo-trellion`, `noo-trellion-intel`, `noo-evolve` —
receive their secrets the same way: every HMAC secret, the bus and redis
passwords, the provider and channel keys the trellion pair uses, each
add-on's own gateway key, and a pgpass file in place of the DSN passwords.
Their readers are noomesh's helper (the trellion pair's process is
noomesh's worker pool) and a copy of the same helper in each add-on's own
repository. `noo-trellion-intel` is built by extending `noo-trellion`, and
compose merges both the environment and the secrets list, so it overrides
exactly one entry: its `NOO_GATEWAY_KEY_FILE` points at a file sourced from
its **own** key (`NOO_SVC_KEY_TRELLION_INTEL`), never trellion's. Two values
the trellion pair used to receive and never read are no longer delivered at
all: `NOO_TRELLION_DB_PASSWORD` (role creation moved to the gateway's
broker) and `NOO_TAILSCALE_API_KEY` (read only by a Python CLI command no
container runs; the gateway mints join keys).

**The node agent.** The Go agent reads its three secrets —
`NOO_NODE_AGENT_TOKEN`, `NOO_CLUSTER_SECRET` and `NATS_NODE_PASSWORD` — through the same
`NAME_FILE` → `NOO_SECRET_NAME` → `NAME` rule, and refuses to start when a
named file is unreadable or empty, or when both `NAME` and `NAME_FILE` are
set. The opt-in containerised agent (compose profiles `node-agent-compose`,
`sensors`) gets them as `/run/secrets` files like every other container.
The host agent every node runs gets them from its applier: the provision
bundle still carries `/etc/noo-node-agent.env` with plain values (encrypted
to the node's birth key in transit), and at the end of every apply
`noo-apply` moves each value into `/etc/noo/agent-secrets/<NAME>` — `0600`,
owned by the agent's user, in a root-owned `0750` directory — and leaves
only `<NAME>_FILE=` pointers in the env file. It does this only when the
installed agent binary can read them (it looks for a marker string in the
binary; it never runs it), and inlines the values back when an older agent
is installed, so neither roll order boots an agent without its credentials.
Because it runs on every apply, `noo upgrade --nodes` converts a node that is
never re-provisioned; the controller's own node rides the same rail (onboard's
first install runs the same step), and a Mac's applier does it under
`~/noomesh/secrets/`. The container-era backup
`/etc/noo-node-agent.env.container-backup` loses its secret lines at the
same time. No operator step is involved.

**The node-hosted harness** (the gateway binary's `harness` subcommand) holds
the same bus password and model-endpoint bearer in `/etc/noo-harness.env`
(`~/noomesh/harness.env` on a Mac). It reads them through the gateway's
`NAME_FILE` rule and refuses to start on an unreadable or doubly-set one,
and the same applier step moves them into `/etc/noo/harness-secrets/<NAME>`
(`0600`, owned by `noo-harness`; `~/noomesh/harness-secrets/` on a Mac). The
harness binary is judged by its own marker, not the agent's, because the two
binaries roll separately.

**Rolling an agent back.** Every agent binary now arrives through the
applier, in a provision bundle (`noo cluster provision <node> --wait`, which
`noo cluster upgrade-agents` and `noo upgrade --nodes` both run), so the
applier's marker check above is the only one. The second check that lived in
`noo-hostd`, for its own binary swap, went with that swap.

**Still environment, and why.** The NATS server has no environment at all
since the shared bus user was retired: every user in its `users.conf` is a bcrypt digest, and
the shared `$NATS_USER` / `$NATS_PASSWORD` principal it used to expand (the
reason it kept those two variables — removing them early took a
controller's bus down on the v0.2.78 roll) is retired, together with the
pair and its `NOO_NATS_LEGACY_SHARED_CREDS` bridge. `NOO_SELF_CALL_SHARED_SECRET` is a posture flag (`"0"` closes
the bridge), not a credential. `HF_TOKEN` / `HUGGING_FACE_HUB_TOKEN`
stay environment by design: no noomesh container receives them — they go
only to third-party model images (vLLM, TEI, the reranker, Whisper), which
read them natively, and through the node agent to the backends it starts.
Moving the rest is not done yet.

**Proving it.** `noo cluster verify --controller` has a `secrets not in
env` row: it reads the NAMES (never values — the docker template drops the
value before it leaves the docker CLI) of every running stack container's
environment and fails on any file-backed name (tier-1 or a provider/channel
key), or any `*_PASSWORD`, `*_SECRET`, `*_TOKEN`, `*_KEY` name not on a
reasoned allow-list (paths to PEM files, the Grafana pointer, the posture
flag `NOO_SELF_CALL_SHARED_SECRET`, the model-hub token third-party images
read).
nats is a warning, not a failure, until it moves; a plain secret on an
add-on or a containerised node-agent container is a failure like anywhere
else. The same
row fails on any file under `secrets/` other than the encrypted store, its
`.bak_*` copies and the reveal log. `noo security secrets audit` adds a
check that every file compose delivers is present in its consumer
(a stat through the docker API — status only, never the file — with a 20 s
budget; a container it cannot reach in time is reported as not checked,
never as a pass) and that no `_FILE` pointer names a missing file.

To see what a container holds, by name only:

```sh
docker inspect noo-gateway --format '{{range .Config.Env}}{{index (split . "=") 0}}{{println}}{{end}}'
docker inspect noo-gateway --format '{{range .Mounts}}{{if eq .Type "bind"}}{{println .Destination}}{{end}}{{end}}' | grep /run/secrets
docker diff noo-gateway    # nothing under /run/secrets, /tmp/pki or any secret: the layer holds none
```

**Fail loud.** A `NAME_FILE` that names a file which cannot be read, or
which is empty, is an error carrying the path — never a fall-through to
tier 2 or 3. A mis-mounted secret that quietly read as "unset" would send
the operator to the store to check a value that was configured fine; the
2026-09 add-on 401 storm was four days of exactly that shape.

**One way, not two.** At start the gateway (preflight check
`secret_files`, critical), the worker (before its NATS connect) and the
redis entrypoint each refuse to run when any manifest name has BOTH
`NAME` and `NAME_FILE` set. That is a skew between what the launcher
exported and what compose mounted — one of the two values is stale and
nothing says which — not a choice to resolve by precedence. It is what
stops a half-applied change (a hand-edited compose file that restores a
plain `TAVILY_API_KEY=` beside the pointer, say) from running on whichever
value happens to win.

The add-on repositories carry the same helper with the same rules (one
trailing newline stripped, fail loud on an unreadable or empty file, refuse
`NAME` and `NAME_FILE` both set), which is what let their overlays switch
to files.

## Read or change a value

There is no `secrets get` or `secrets set` — the store is edited with
`sops`, and the file is dotenv named `.sops`, so **both type flags are
required** on every call. A bare `sops -d` guesses JSON and fails;
`--input-type` alone fails differently; and a broken decrypt returns
*zero keys*, which reads exactly like "the key is missing". Do not conclude
a value is absent until a known-present key decrypts too.

```sh
sops -d --input-type dotenv --output-type dotenv secrets/env.sops | grep -c =    # sanity: key count
```

**Never re-encrypt the store from `.env`.** That path is a full replace
and silently drops every key `.env` lacks — which, on a sops install, is
all of them. Decrypt → edit → re-encrypt at a rule-matching path, and diff
the key sets before installing:

```sh
sops -d --input-type dotenv --output-type dotenv secrets/env.sops > /tmp/e
# ...edit /tmp/e...
cp /tmp/e secrets/env.new.sops        # the path must match the .sops.yaml rule
sops -e -i --input-type dotenv --output-type dotenv secrets/env.new.sops
diff <(sops -d --input-type dotenv --output-type dotenv secrets/env.sops | grep -oE '^[A-Z_0-9]+=' | sort) \
     <(sops -d --input-type dotenv --output-type dotenv secrets/env.new.sops | grep -oE '^[A-Z_0-9]+=' | sort)
mv secrets/env.new.sops secrets/env.sops && shred -u /tmp/e
```

sops matches its creation rule against the **input** path, so encrypting a
file in `/tmp` matches no rule; `--filename-override secrets/env.sops` is
the alternative when you must encrypt from elsewhere. For values the
rotation tool knows about, prefer `noo security secrets rotate
--set-from-stdin` below — it never writes plaintext to disk at all.

A changed value reaches a container only on **recreate**, not restart:
`noo stack restart --force <service>`. Each start rewrites the secret files
under a new inode and a running container keeps the one it was created with,
so `secrets rotate` (which writes the store and then runs
`noomesh-restart.sh --force`, re-running `load_secrets`, which rewrites the
files) recreates the consumers and they get the new file, pgpass bodies
included. (A container that is merely *restarted* re-resolves its bind path
and picks up whatever the launcher last wrote, so avoid restarting a single
consumer by hand between a store edit and the recreate.)

**A plain `noo stack start <service>` does not apply a rotated secret.**
Compose decides whether to recreate from the service's configuration, and a
changed secret *value* is not part of it (the source variable's name did not
change), so `up -d` leaves the running container — and its old file — in
place. Use `noo security secrets rotate` (it recreates the consumers) or
`noo stack restart --force <service>` after changing a value by hand.

Verify what a container actually received with `docker inspect`, not
`docker exec … printenv` (the gateway image has no shell, so `printenv`
produces nothing — which reads exactly like "unset"). For a file-delivered
secret the environment shows only the `_FILE` pointer, and `.Mounts` lists
`/run/secrets/<name>` as a bind of a file under the secret directory:

```sh
docker inspect noo-gateway --format '{{range .Config.Env}}{{println .}}{{end}}' | grep '^NOO_JWT_SECRET'
docker inspect noo-gateway --format '{{range .Mounts}}{{println .Source "->" .Destination}}{{end}}' | grep /run/secrets
```

## Audit the store

```bash
noo security secrets audit [--sops-file <path>] [--env-file <path>] [--json]
```

Compares `secrets/env.sops` with `.env` by key name, length and
`sha256[:8]` — no code path in it can print a value. Always exits `0`;
read the findings:

| Finding | Level | Meaning |
|---|---|---|
| `credential-in-env` | ERROR | a credential is in `.env` — remove it; the store copy is the one that loads |
| `blank-value` | ERROR | a key is present but empty |
| `required-key-absent` | ERROR | a key the registry requires (always, or because its feature flag is on) is missing |
| `db-password-does-not-authenticate` | ERROR | the stored password no longer logs in to its Postgres role — run `resync` |
| `value-drift` | WARN | the same key differs between the two files |
| `consumer-gap` | WARN | (env backend only) a consumer is missing a key it needs |
| `db-password-not-verifiable` | INFO | Postgres is down, or the connection path accepted a wrong password (a `trust` rule), so the probe cannot mean anything |
| `registry-key-absent` / `unclassified-credential` | INFO | informational |

The live Postgres probe runs `psql` inside the postgres container against
the container's routable address (the unix socket is `trust`, and a check
that cannot fail proves nothing), over TLS with the server's own leaf
presented as the client certificate — since 2026-09-28 `pg_hba` refuses
any TCP client without one (`docker/postgres/pg_hba.conf`); since the per-role
client leaves, the role-named certificate that other containers must present
is not needed for a login from the postgres container itself (the `samehost`
rule; see [Networks and containers](networks-and-containers.md)). It leaves one
`password authentication failed` line per role in the Postgres log — that
is the negative control working. A probe refused with `connection requires
a valid client certificate` is reported as the check's own
misconfiguration, never as evidence about the password.

## What `scan` checks

```bash
noo security scan [--strict] [--json]
```

Local posture, no gateway. Exit `1` on a CRITICAL finding, or on any finding
with `--strict`. `--json` adds `store_problem` (`null`, or
`sops_not_found` / `age_key_missing` / `decrypt_failed`) so a gate can tell
"checked and clean" from "could not check".

| Check | Level | Fires when |
|---|---|---|
| `Secret Store` | HIGH | `secrets/env.sops` exists and could not be decrypted — the credential checks below are skipped and the finding says why; nothing in that scan is evidence a secret is unset |
| `JWT Secret` | CRITICAL | `NOO_JWT_SECRET` blank or the published default |
| `Cluster Secret` / `Node Agent Token` | HIGH | blank |
| `Redis Password` | MEDIUM | blank |
| `Grafana Password` | CRITICAL / MEDIUM | a published placeholder / blank |
| `Backup Passphrase Plaintext` / `Secret File Plaintext` | CRITICAL | a `secrets/*.txt` an older wizard wrote — `reveal` or `absorb-files` |
| `Runtime Residue Plaintext` | CRITICAL | any file under `secrets/.runtime/` — a materialised copy nothing reads; `shred -u` it |
| `Retired NATS Credential` | LOW | `NATS_USER`, `NATS_PASSWORD` or `NOO_NATS_LEGACY_SHARED_CREDS` is still set in the store or `.env` — retired with the shared bus user, read by nothing. Remove by hand (`sops secrets/env.sops`, delete the lines; the same lines from `.env`): no `noo` verb removes a store key and nothing deletes one automatically. `noo security secrets audit` reports the same keys as `retired-key` |
| `Registry Credentials` | MEDIUM | `~/.docker/config.json` holds an inline base64 login with no credential helper — registries named, never the blob; `ghcr.io` is the one the launcher pulls with, the rest are `docker logout` candidates |
| `.env Permissions` | MEDIUM | world-readable (skipped on NTFS/drvfs) |
| `TLS` | MEDIUM | `NOO_TLS_CERT` unset |
| `Gateway Transport` | CRITICAL / LOW | the CLI's gateway URL has no usable trust anchor / plain `http://` to loopback |
| `Cluster PKI` | LOW | no CA |

## Re-sync Postgres roles

```bash
noo security secrets resync --all [--dry-run]
noo security secrets resync POSTGRES_PASSWORD NOO_APP_DB_PASSWORD
```

Postgres roles are **cluster-global**, and a restored dump or a replayed
migration chain can leave a role's password different from the store's.
`resync` makes the role match the store — it never mints, never writes the
store, never recreates a consumer. It refuses to act when Postgres is down
or when the result could not have failed (a `trust` rule on the path), and it
re-probes after the `ALTER ROLE` rather than trusting the exit status.
Anything that replays the migration chain into a throwaway database must
run against a Postgres it created, with `NOO_DB_SCHEMA_ONLY=1`, so the
role migrations leave existing roles untouched.

## Remove a stale key

`noo security secrets remove <KEY>... [--yes] [--dry-run] [--sops-file <path>]`
takes keys out of `secrets/env.sops`. It exists for the leftovers the audit
reports (`node-password-unused`: `NATS_NODE_PASSWORD_HOST8` beside the real
`NATS_NODE_PASSWORD_HOST8`), which used to end in "edit the sops file by hand".

Each key is judged first, and **any refusal aborts the whole run with nothing
changed**. A key is refused when something still reads it: a registry
consumer (core or add-on `x-noo-addon`), a running container holding it
(`KEY` or `KEY_FILE` in its environment), a root `docker-compose*.yml` or
`noomesh.yaml` that names it, or a `NATS_NODE_PASSWORD_*` whose node `users.conf`
still authorises. A node password is removable only when `users.conf` lists
node principals and none maps to it; an unreadable file refuses. Allowed:
keys the audit flags as unused, retired keys, and keys unknown to every reader.
The plan prints the reason for each key either way.

```
noo security secrets remove NATS_NODE_PASSWORD_HOST8 --dry-run   # the plan, nothing touched
noo security secrets remove NATS_NODE_PASSWORD_HOST8             # confirms, names the key
```

The write is the store's usual one: decrypt in memory (never to disk), drop the
key, re-encrypt, prove the new file decrypts to exactly the remaining keys,
keep an encrypted `env.sops.bak_<unix-time>` beside it (the output names it),
rename atomically. No restart is needed: nothing reads an unused key. A
`secret_removed name=<KEY> by=<user>` line (name only) is appended to
`secrets/reveal-audit.log`.

## Rotate a secret

```bash
noo security secrets rotate NOO_JWT_SECRET [--dry-run] [--yes] [--restart]
noo security secrets rotate --all-generated
noo security secrets rotate TELEGRAM_BOT_TOKEN --set-from-stdin < token.txt
```

Rotation is plan → prepare → apply → commit: refusals abort the whole
invocation before anything is touched; the new store is encrypted on a
pipe, decrypted back and checked for an identical key set; the previous
store is kept as `secrets/env.sops.bak_<epoch>`, and the newest
`NOO_SECRETS_KEEP_BACKUPS` (3) of those are retained while older ones are
deleted — each is encrypted to the same age recipient as the live store, so
an unbounded pile would leave every rotated value readable and rotation
would revoke nothing; Postgres roles are
altered and verified with a real login, and reverted if a later step
fails. The date is recorded in `secrets/rotations.json` — dates only, no
values, readable without the age key — which is what makes the 90-day
credential review interval something `security secrets audit` can check
rather than a sentence in a document. The report names the containers that must be recreated
(`--restart` runs the restart for you). That restart RECREATES the
consumers (`noomesh-restart.sh --force`), which is what puts the new value
into their `/run/secrets` file — a running container keeps the file it was
created with, so a plain `noo stack start` of a running service keeps the old file.
A provider key the store does not hold yet (a first search or Telegram key)
is added the same way: `--set-from-stdin` writes it to the store, and the
recreate delivers it.

| Keys | Disposition |
|---|---|
| `POSTGRES_PASSWORD`, `NOO_APP_DB_PASSWORD`, `NOO_TRELLION_DB_PASSWORD`, `NOO_TRELLION_DDL_PASSWORD`, `NOO_EVOLVE_DB_PASSWORD`, `NOO_EVOLVE_DDL_PASSWORD`, `REDIS_PASSWORD`, `NOO_JWT_SECRET`, `NOO_AGENT_REVIEW_KEY`, `NOO_CONTROLLER_SECRET` | generated — `--all-generated` covers exactly these eleven |
| `ANTHROPIC_API_KEY`, `OPENAI_API_KEY`, `GOOGLE_API_KEY`, `TAVILY_API_KEY`, `BRAVE_SEARCH_API_KEY`, `HF_TOKEN`, `TELEGRAM_BOT_TOKEN`, `WHATSAPP_TOKEN`, `GOOGLE_CHAT_BEARER_TOKEN`, `NOO_FILECRED_GOOGLE_CHAT_B64`, `NOO_TAILSCALE_API_KEY`, `NOO_TAILSCALE_OAUTH_CLIENT_SECRET`, `GRAFANA_PASSWORD`, `NOO_ADMIN_PASSWORD` | provider-issued — supply the new value with `--set-from-stdin` (one key at a time; refuses a TTY) |
| `NATS_GATEWAY_PASSWORD`, `NATS_WORKER_PASSWORD`, `NATS_TRELLION_PASSWORD`, `NATS_TRELLION_INTEL_PASSWORD`, `NATS_NODE_PASSWORD` | **refused** — the server verifies a bcrypt digest; `noo cluster nats-creds rotate <gateway\|worker\|trellion\|trellion_intel\|node>` mints, re-renders `users.conf`, HUPs the server and delivers |
| `NOO_SVC_KEY_WORKER`, `NOO_SVC_KEY_TRELLION`, `NOO_SVC_KEY_TRELLION_INTEL`, `NOO_SVC_KEY_EVOLVE` | issued by this install's own gateway — `noo security service-key provision <consumer>` shows the grant, asks, then mints, stores, recreates and proves each one. The worker's row is written in the CLI; every add-on's row is **derived** from its overlay's `x-noo-addon` block (below) |
| `NOO_CLUSTER_SECRET`, `NOO_NODE_AGENT_TOKEN` | **refused** — fleet-wide; every node holds a copy. The refusal prints the manual sequence, which includes `noo cluster push-secrets` |
| `NOO_AUDIT_HMAC_KEY` | generated — by name only, never in `--all-generated`: rows signed under the previous value stop verifying (see [The audit key](#the-audit-key)) |
| `NOO_BACKUP_PASSPHRASE`, `NOO_AGE_BACKUP_PASSPHRASE` | generated — and rotation re-encrypts every matching file in `$NOO_BACKUP_DIR` old → new as part of the same run, so existing backups stay openable. The new value is shown ONCE on a terminal and written to no file (`--set-from-stdin` to supply your own). Both are **required**: the backup refuses to run without them. Not in `--all-generated`: rotating one rewrites backup files and needs a terminal handover, so it is done by naming the key |

Consequences worth knowing before you rotate: `NOO_JWT_SECRET` invalidates
every issued token and refresh chain, and makes the audit rows written
before the audit-key checkpoint unverifiable (they were signed with a key
derived from it); `NOO_AGENT_REVIEW_KEY` makes every
previously sealed agent message unreadable; `REDIS_PASSWORD` needs server
and clients recreated together.

**Retired credentials.** `NOO_MCP_TOKEN` and `NOO_MCP_TOKEN_PREVIOUS` (the
operator MCP door's shared bearer, retired 2026-09-30 — the door takes only
per-admin `mcp:operator` service keys) have no rotation plan and no reader.
`secrets audit` reports a value still held as `retired-key`, `security scan`
as *Retired Credential*, and `noo security secrets tidy` drops it from the
store and blanks it in `.env`. `secrets absorb-files` shreds a legacy
`secrets/mcp_token.txt` instead of folding it in.

`noo security generate-secret [general|jwt|cluster|fernet]` prints a fresh
random value for a manual procedure; it writes nothing.

### Every delivered secret has a reader

The store is only half of "never plaintext": a value compose hands a
container sits in that container's environment — `docker inspect`,
`/proc/<pid>/environ`, every child process — whether or not the code ever
reads it. So a secret is delivered **only** to containers whose code reads
that variable, and `tests/test_secret_env_has_a_reader.py` holds the line:
every credential-shaped key in the composed projection must have a reader
in the tree that runs in that container (or be a variable native to a
third-party image, named in the guard's allow-list). A config another
component renders counts as a reader: the NATS server kept `NATS_USER` /
`NATS_PASSWORD` for exactly that reason — `noo cluster nats-users render`
wrote the legacy principal into its `users.conf` with those two variables —
until the principal was retired and both variables together (the
renderer now emits no `$VAR`; `tests/test_nats_legacy_principal_env.py`). That is why the trellion images no longer receive
`NOO_ADMIN_PASSWORD`, the Tailscale OAuth client or API key
(gateway-only readers) or `NOO_TRELLION_DB_PASSWORD`, and why `SLACK_BOT_TOKEN`, `TELEGRAM_SECRET_TOKEN`,
`WHATSAPP_VERIFY_TOKEN` and `WHATSAPP_APP_SECRET` are delivered nowhere: no
tree reads them. A registry row's `consumers` list is the same fact from
the rotation side — it names exactly the containers that hold the value.

## The audit key

Every row of the security audit log (`noo_security_audit`) carries an
`entry_hash`, keyed with `NOO_AUDIT_HMAC_KEY`. From v0.2.83 it is hash
**v2** (stored as `v2:<hex>`): HMAC-SHA256 over every column but the hash
itself, which means the row's `id`, its `timestamp` (the stored microseconds),
`event_type`, `severity`, `actor`, `resource`, `outcome`, `request_id`,
`details` (where an auth row's `source_ip` lives) and `prev_hash`. Rows
written before then carry hash **v1** (bare hex), which covered only
`event_type`, `severity`, `actor`, `resource`, `outcome` and `request_id`.
Editing a row without the key is detectable; that is the whole point, so
the key is its own secret:

- **The gateway does not start without it.** A missing or blank
  `NOO_AUDIT_HMAC_KEY` is a boot refusal (exit 2, naming the fix), not a
  gateway that serves while every audit row is refused. It cannot strand an
  upgrade: `noo upgrade --stack` mints the key into `secrets/env.sops` before
  anything else moves, and `noo stack start|restart|rebuild` mints it first if
  it is still absent (an existing key is never rotated). An install with no
  encrypted store is refused with the command that moves it onto one, and the
  key is never written to plaintext `.env`. `noo security scan` reports a
  missing key as CRITICAL and `noo cluster verify` fails its `audit key` row
  (read locally, so it answers even when the gateway is down).
- **It is the only signing key.** The gateway, the worker and the two
  knowledge add-ons (every process that writes audit rows) receive it as a
  file. A process without it REFUSES to write the row and logs
  `audit_write_refused_no_key` at error — it never signs with anything
  else. `noo onboard` mints it, and `noo upgrade --stack` mints it into
  an existing install's store when it is absent — before anything in the
  roll moves, so a store it cannot write stops the upgrade with nothing
  changed. Neither ever touches a key that is already there, and neither
  writes it to plaintext `.env`: an install with no `secrets/env.sops` is
  refused and told to move onto the store first (`noo onboard
  --reconfigure --only secrets --secrets-backend sops`).
- **Before it existed, the key was derived from `NOO_JWT_SECRET`** (and,
  where even that was unreadable, from a public literal). Anyone holding
  the login secret could therefore re-sign an edited row. That derivation
  is now a VERIFY-ONLY key, held by the gateway alone.
- **One checkpoint row links the two.** The first gateway boot with the
  key finds the newest row signed under the derived key and appends one
  `audit_key_checkpoint` row, signed under that derived key, naming a
  fingerprint of the new key (never the key), that last row's hash, and
  the time. Every later row is signed with the new key. An install with no
  derived-key rows gets a *genesis* checkpoint, signed with the new key.
  The boot is idempotent: the row is written once per key.

`noo security audit verify` (`GET /api/security/audit/verify`, operator
only) runs in the gateway, because only it holds both keys. Rows before
the checkpoint must verify under the derived key; rows after it under
`NOO_AUDIT_HMAC_KEY` **only** — a post-checkpoint row that verifies under
the derived key was written by someone holding the login secret, and is
reported as that. Each row that fails is named. `noo cluster verify
--controller` carries the same verdict as its `audit log` row, and fails
it outright when the key is missing.

One exception covers the roll itself. Up to v0.2.81 the Python writers
(noo-worker, worker-extra, trellion, trellion-intel) fell back to the
derived key, and an old-image container can still be running for a moment
after the new gateway writes the checkpoint. A derived-key row after the
checkpoint is therefore a **warning**, not a failure, when it is stamped
within 15 minutes of the checkpoint (`ROLL_WINDOW_SECS`) and is one of the
two events those writers sign with a fixed actor: `audit_logger_started`
by `worker_pool`, or `bus_principal_refused` by `bus`. The warning names
the writer and the count, both in `noo security audit verify` and on the
`audit log` row of `noo cluster verify`; the verdict stays ok. Any other
derived-key row after the checkpoint (another actor or event, or later
than the window) still fails. That row is v1, so its timestamp is not
covered by its hash: someone with database access and the login secret
could place a row in that window later. It can only say one of those two
things, and it is counted in the warning.

**Hash v2 and its marker.** A v1 hash did not cover the row's
time, id or details, so anyone with database write access could re-time a
row, change its `source_ip`, or copy it under a new id without breaking its
hash. The first v0.2.83 gateway boot appends one `audit_hash_v2` row, hashed
v2 under the audit key, right after the checkpoint. A v1 row is accepted
before that marker and **fails** after it. The marker's place is fixed by its
own signed timestamp, never by a date. The roll gets the same allowance as
above: a v0.2.82 Python writer still running signs v1 under the audit key, so
a v1 row after the marker is a **warning** when it is one of those same two
events and is stamped within 15 minutes of the marker. A v0.2.81 writer's
row (v1, derived key) is the checkpoint's window above, unchanged. A marker
that is missing while both v1 and v2 rows exist fails the verify. So does a
v2 row stamped more than the window before the marker, which means an
earlier marker was deleted and a later boot wrote this one. Rolling the
gateway back below v0.2.83 makes its rows v1 after the marker, and they
fail by name.

What it reports without failing: rows written before hashing existed
(`unhashed`), pre-checkpoint rows signed with the public literal
(`public fallback` — not tampered, not evidence either), and, after a
`NOO_JWT_SECRET` rotation, the whole pre-checkpoint epoch as
`unverifiable` (the gateway no longer holds the key that signed it). Run
the verify before rotating the login secret if you need a record that
the old epoch held.

Rotating `NOO_AUDIT_HMAC_KEY` itself has no hand-over yet: the gateway
would need the previous value to sign a checkpoint, and nothing keeps it.
Rows signed under the old value stop verifying. Rotate it deliberately,
after a verify, and record when.

### The hash chain: deleted and reordered rows

The per-row hash shows an EDITED row, not one that is simply gone. Since
the chain landed every row is also **linked** to the one before it:
`chain_seq` is a gapless counter and `chain_hash` is
`HMAC(NOO_AUDIT_HMAC_KEY, seq, the previous row's chain_hash, this row's
entry_hash)`. Delete a middle row and the sequence skips and the next
row's link no longer follows; swap two rows and both fail. `noo security
audit verify` reports the first break and names the row after the gap.

- **One sealing writer, no sealer task.** All four writers (the gateway
  and the three Python containers) take the same transaction-scoped
  Postgres advisory lock, read the newest chained row, pick a time no
  earlier than its, sign, insert and commit. The lock is released by
  commit or rollback, so a crashed writer cannot wedge the log. The link is
  made at insert because the application role cannot update a row later
  (below).
- **Where it starts.** On the first boot after the upgrade the gateway
  appends one `audit_chain_genesis` row (seq 1). Its signed `resource`
  carries the count of every earlier row and a keyed digest over their ids
  and hashes. Rows before it are not re-written; deleting or swapping one
  of them changes the digest, which the verify recomputes. A row written
  unchained by an old-image container within 15 minutes of the genesis is a
  warning; later, it fails.
- **Partitions and retention.** `chain_seq` runs across monthly partitions.
  Before the retention job drops a month it writes a signed, chained
  `audit_retention_checkpoint` row naming the dropped `from..through` seq
  range and the `chain_hash` of the last dropped row; the verify reads
  a gap that exactly such a checkpoint covers as retention, not tampering,
  and says how many rows retention removed. The job stops if it cannot
  write the checkpoint, and the database's drop function refuses a
  partition whose chained rows have none (so a retention job from an old
  worker image retains rather than drops).
- **What it cannot show.** Cutting off the NEWEST rows leaves a shorter,
  valid chain. `verify` prints the chain head (`seq` and `chain_hash`):
  record it where the database owner cannot write (a ticket, a signed
  message) and compare it later. The verifier holds the key the writers
  hold, so the chain proves the log is intact, not who held the key.
- **No key, no judgement.** Without `NOO_AUDIT_HMAC_KEY` the verify reports
  the chain as *not checked*. Rows that exist with none chained yet (the
  genesis failed or the gateway has not restarted) fail the verify and say so.

### The application role is INSERT-only

The gateway and the Python writers connect as `noo_app`. Since the chain
landed that role holds INSERT and SELECT on `noo_security_audit` and
**no UPDATE, DELETE or TRUNCATE**, on the table and on every partition.
The owner (`noo`, which runs migrations) is unchanged and creates
partitions through `noo_ensure_audit_partition`, which revokes the same on
each new one (default privileges would otherwise give the app role full
DML on it). The routine `GRANT ... ON ALL TABLES` that runs on every
migration pass would undo the revoke, so the gateway re-asserts it as the
last step of each pass. Retention still runs as the owner through the
`SECURITY DEFINER` function `noo_drop_audit_partition`.

What this does not cover: an attacker holding the OWNER or a superuser
credential can still change the table, and `noo_app` can still call the
drop function for a month older than the current one. Neither can forge a
chain link or a checkpoint without the audit key, so the first leaves a
break and the second leaves a gap with no signed checkpoint, which the verify
reports as deleted rows. If the gateway still connects as the superuser
(`DATABASE_URL` names `noo`, not `noo_app`), the restriction has no effect:
check the user in the gateway's `DATABASE_URL`.

### Reading the log, and where a row came from

`noo security audit list` (`GET /api/security/audit/list`, Operator and
above) lists rows newest first with filters for time, event type and actor.
Every row written through the gateway's audit helper records `source_ip`
(the same rule as the login rows: `X-Forwarded-For` / `X-Real-IP` count only
from a trusted proxy, otherwise the socket peer) and, for an event inside an
agent turn, `conversation_id`, in `details`. A row written from a background
task or a websocket session, which has no request in scope, carries neither
rather than a guessed value.

### Audit retention

Audit rows live in monthly partitions. The weekly `audit_log_rotate`
heartbeat task (seeded at gateway boot, enabled, `created_by system`) exports
every partition older than the retention window (12 months by default,
`retention_months` on the task, 1 to 120) to
`/data/audit-archive/noo_security_audit_YYYY_MM.jsonl` on the persistent
`noo-data` volume, one JSON object per row with every column (so the archive
can still be verified against the key), checks the file against the row
count, and only then drops the partition. An export that cannot be verified
drops nothing and fails the run; the current and future months are never
dropped. Only the `local_dir` backend is implemented in the gateway; with any
other `backend` the partitions are kept and the task fails, so the gap is
visible. `archive_dir` must stay under `/data/`. The task defaults to a dry
run if its `dry_run` is removed; the seeded row applies. Disable it with
`noo heartbeat toggle audit_log_rotate --off`, or tune it with the task's config.

### Agent mail retention and archive

Agent-to-agent messages (`noo_agent_messages`) are kept 90 days in Postgres
(`days` on the weekly `agent_messages_retention` task, seeded enabled and
applying). Past that window a message is ARCHIVED before it is deleted, so the
record can still be used later (an evaluation set, a fine-tune):

- **Where.** `/data/audit-archive/noo_agent_messages_YYYY_MM.jsonl.gz`, one gzip
  JSONL file per UTC month of `received_at`, in the same directory and on the
  same `noo-data` volume as the audit archive (`archive_dir` on the task, under
  `/data/`). Each line is the whole row, every column.
- **Still sealed.** The body is stored exactly as the table holds it
  (`enc: "sealed"` or `"e2e"`, `body: {"ct": ...}`, `enc_meta`). The archive
  holds no plaintext and the gateway needs no key to write it.
- **Archive, verify, then delete.** The month's file is written to a temp file,
  fsynced, read back from disk, and renamed into place; only then are exactly
  the archived ids deleted. A failed export (unwritable directory, disk full, an
  unreadable existing file, a count mismatch) deletes nothing for that month,
  leaves any existing archive untouched, and fails the run so it is visible.
  A run that crashes between the export and the delete is safe to repeat: the
  merge de-duplicates by message id, so each id appears in the archive once.
- **Backed up.** `scripts/backup-controller.sh` writes the whole archive
  directory (audit partitions, chain heads, agent mail) to
  `archive_<ts>.tar.enc`, encrypted with `NOO_BACKUP_PASSPHRASE`, and it goes
  wherever `NOO_BACKUP_OFFSITE` sends the dump. Archived rows no longer exist
  in Postgres, so the dump does not contain them: this file is their backup. A
  run that cannot back the archive up fails.
- **Reading it back (operator only).** `noo agents archive list` shows the
  files, months and row counts; `noo agents archive export 2026-03 --out m.jsonl`
  writes a month as JSONL with bodies still sealed. `--decrypt` asks the
  gateway to open the bodies with the cluster review key (`NOO_AGENT_REVIEW_KEY`,
  which never leaves the gateway) and write the plaintext to `--out` only (mode
  0600, never the terminal). Each decrypt writes an `agent_archive_decrypt`
  audit row naming who opened which month, BEFORE any plaintext is produced; if
  the row cannot be written the decrypt is refused. A non-operator is refused
  and the refusal is audited too. If the cluster has no review key, nothing
  can be opened.

## A service that holds its own gateway key

The controller's own services used to sign their gateway calls with
`NOO_CONTROLLER_SECRET` — **one value every one of them shared**. That made a
rotation all-or-nothing and only as good as the recreate that followed it: a
container the recreate missed kept making 401'd calls that nothing attributed.

An add-on container such as `noo-trellion-intel` can instead hold a key of its own: a named row in
`noo_service_keys`, scoped, quota-capped, revocable, with a `last_used_at`.
It is delivered to that one container as `NOO_GATEWAY_KEY` and to no other.

**It is required.** There is no shared-HMAC fallback: a
container with no key sends no credential and is refused, and the gateway
refuses an HMAC signed with the controller secret from every caller (counted
as `controller_shared_secret_refused`). `noo onboard` mints every required
key; `noo cluster verify --controller` fails its `service keys` row when one
is missing.

To give it one:

```bash
noo security service-key provision trellion-intel
```

That shows what the add-on asks for before minting anything:

```
trellion-intel asks for a gateway key          declared in addons/trellion_intel/docker-compose.yml
  consumer   svc:trellion-intel
  store key  NOO_SVC_KEY_TRELLION_INTEL
  recreates  noo-trellion-intel
scope       opens
addon       POST /api/addon/token (always added)
chat        POST /v1/chat/completions, POST /api/external/chat/completions, …
embeddings  POST /api/external/embeddings, …
metrics     POST /api/metrics/increment, POST /api/metrics/gauge
Grant these to svc:trellion-intel? [y/N]
```

The route column comes from the gateway (`GET /api/security/service-keys/scopes`),
not from a copy in the CLI, and a word the gateway would refuse stops the verb
before anything is minted. On a re-run it rotates, and adds a `+ … − …` line
against the key in use. `-y` answers the question; without a terminal and
without `-y` it refuses rather than granting unseen; `--json` prints the
request and mints nothing unless `-y` is also given. `--scopes` still
overrides the request, and says so. It then mints, stores, recreates and
waits for the key to be presented.

### Where an add-on key's grant comes from

An add-on's overlay declares its key at the top of the file:

```yaml
x-noo-addon:
  addon: trellion_intel            # the addons:<name> key in noomesh.yaml
  consumer: svc:trellion-intel     # the noo_service_keys row
  key: NOO_SVC_KEY_TRELLION_INTEL  # the store key, delivered as NOO_GATEWAY_KEY
  containers: [noo-trellion-intel] # every container that holds it
  scopes: [chat, embeddings, metrics]
```

For an overlay that ships in this tree (trellion), the CLI reads the copy
compiled into it. A licensed add-on's overlay travels in the add-on's signed
bundle, and the CLI reads it from `addons/<name>/docker-compose.yml` only
while its bytes still hash to the signed lock the add-on is pinned to: an
edited copy declares nothing, so it cannot widen the request. From the
declaration the CLI derives the registry row that `secrets rotate`, `secrets audit` and `doctor
secrets` use, the default grant `provision` shows, and the key `cluster
verify` requires while the add-on is on. The overlay only asks: the operator
grants at `provision`, and the gateway decides what each word opens.

When a release widens what an add-on asks for, the key already minted keeps
its old grant, and the new calls are refused. `noo cluster verify` warns on
its **service-key grants** row, naming the missing words and the `provision`
command that re-grants them.

If you mint by hand instead, the four steps are
`service-key issue svc:trellion-intel --scopes …`,
`secrets rotate NOO_SVC_KEY_TRELLION_INTEL --set-from-stdin --yes`,
`stack restart --force trellion-intel`, and `service-key list`, and the last
of those is the one that matters. It is not a formality. A key that is stored but never presented is
indistinguishable from no key at all: the container keeps working, because it
falls back to the shared HMAC, and you would believe it had moved when it had
not. `last_used_at` for `svc:trellion-intel` must be recent. If it still reads
`never`, the container did not pick the value up — check that it was recreated
rather than restarted (`docker inspect -f '{{.Created}}' noo-trellion-intel`).

To take it away again, clear the value and recreate: the fallback is
unconditional, so there is no window where the container has no credential.

## The login signing secret stays on the gateway

`NOO_JWT_SECRET` signs and verifies logins with HS256, so any container that
can verify a login can also forge one. Only `noo-gateway` receives it.

A worker still has to call the gateway as the person who asked. For
example, a `noo_graph_stats` tool call that a user makes from a chat. The
gateway mints a short-lived user token for each `worker.tool.generic`
dispatch and sends it in the request envelope (`delegated_token`). The worker
presents that token and does not mint one of its own.

The token has these properties:

- It names the user, with the role and scopes the gateway resolved. It also
  carries `act: {sub: "svc:worker", task: <tool call id>}` and a `jti`.
- It expires after the worker timeout plus 30 seconds, and never lives longer
  than 5 minutes.
- It is signed ES256 with `NOO_JWT_SIGNING_KEY` when that key is set.
  Otherwise the gateway signs it HS256 with its own secret.
- The gateway accepts it only on the routes in the tool manifest
  (`gateway-rust/mcp-tools-local.json`) and returns `403` everywhere else.
  Because it carries `act`, a disabled account stops it at once.
- It is never stored. The worker removes it from the request before its
  handler runs, and the gateway removes it from a dead-letter row.

`noo cluster verify --controller` fails its `secrets not in env` row when
`NOO_JWT_SECRET` or `NOO_JWT_SECRET_FILE` appears in any container other than
the gateway.

## No secret is shared between holders

Each credential a controller service holds is its own:

| Holder | Gateway credential | Bus-principal key | Browser door |
|---|---|---|---|
| noo-gateway | — (it is the gateway) | all three (it signs for every audience) | `NOO_BROWSER_KEY` (signs; hands it to browsers it starts on nodes) |
| noo-worker, noo-worker-extra | `NOO_SVC_KEY_WORKER` | `NOO_BUS_KEY_WORKER` | `NOO_BROWSER_KEY` (signs) |
| noo-trellion | `NOO_SVC_KEY_TRELLION` | `NOO_BUS_KEY_TRELLION` | — |
| noo-trellion-intel | `NOO_SVC_KEY_TRELLION_INTEL` | `NOO_BUS_KEY_TRELLION_INTEL` | — |
| noo-evolve | `NOO_SVC_KEY_EVOLVE` | — (runs no worker_pool) | — |
| noo-browser | — | — | `NOO_BROWSER_KEY` (verifies) |

`NOO_CONTROLLER_SECRET` is held by the gateway alone. It signs nothing, and
the gateway refuses an HMAC signed with it from any caller.
`NOO_CLUSTER_SECRET`, the fleet secret, is every node's credential: among the
controller's services only the gateway, which verifies node tokens, and the
containerised node agents hold it. The gateway refuses a fleet token presented
with a controller service certificate, or from a container on its own network
with no node certificate. A leak of one holder's key exposes that holder's
doors only. The bus keys and the browser key are `controller-local`. Onboard
and `noo upgrade --stack` mint any that is absent or blank, and
`noo security secrets rotate <KEY>` rotates one, recreating its holders
together.

`noo cluster verify --controller` judges this in its `shared secrets` row. For
every running container it reads the variable names, the one non-secret value
`NOO_BUS_AUDIENCE`, which of a fixed list of `/run/secrets` files exist (a stat
through the docker API, no content), and — for the key files only, one
`docker cp` each — a salted digest, which it compares with the store's. Each
key's bytes are hashed in memory and dropped: values never leave the process,
and no other secret's file is opened. A key file that exists but cannot be
digested is "not judged", which fails. The row fails in any of these cases:

- the controller secret reaches any container but the gateway;
- the fleet secret reaches anything but the gateway and the node agents;
- a verifier holds no key of its own, names the wrong audience, holds another
  holder's key, or holds a copy that differs from the store's;
- the four per-service keys in the store are not distinct from each other and
  from the two shared secrets;
- nothing could be judged.

## Secrets a human must hold

Almost every secret here is consumed by a process on this box, and the right
way to look at one is `noo security secrets audit`, which shows `set` /
`BLANK` / `missing` and a digest and never a value.

Two are different. **`NOO_BACKUP_PASSPHRASE`** and
**`NOO_AGE_BACKUP_PASSPHRASE`** have no consumer on this machine at all: they
exist so that a *person*, on a *different* machine, months later, can open an
encrypted backup. A secret whose only consumer is a human is worthless unless
the human can read it.

| Secret | Opens | Where it must end up |
|---|---|---|
| `NOO_AGE_BACKUP_PASSPHRASE` | `age-key_*.txt.enc` — the age private key, which opens every other secret | a password manager, off this machine |
| `NOO_BACKUP_PASSPHRASE` | `pg_*.sql.gz.enc` — the Postgres dumps | a password manager, off this machine |

### Reading one back

```bash
noo security secrets reveal NOO_AGE_BACKUP_PASSPHRASE
```

It prints the value once, offers to put it on the clipboard (and clears the
clipboard 45 s later where the platform allows), and appends a line to
`secrets/reveal-audit.log` recording the name, the time, who asked and a
digest — never the value.

What it refuses, and why:

- **stdout that is not a terminal.** A value in a pipe is a value in whatever
  that pipe writes to. `--stdout` overrides it when you genuinely mean to
  capture it; there is no way to do it by accident.
- **`--json`, with no override.** A machine-readable stream of secret values
  is never what anyone meant.
- **Any name not in the table above.** `reveal` is not a general `secrets
  get`. The refusal is identical whether or not the box holds that secret, so
  the error message is not an oracle.
- **The age private key itself** (`SOPS_AGE_KEY`, `NOO_AGE_KEY`, …), with no
  flag to force it. It is not a string a person transcribes, and the supported
  way to carry it off-box already exists: the encrypted `age-key_*.txt.enc`
  backup, opened with `NOO_AGE_BACKUP_PASSPHRASE` — which `reveal` *will*
  show you. Printing the key would add a second, weaker copy of the root of
  trust and buy no recovery power the first copy lacks.

**The gate is the local age key, not a role.** `reveal` reads
`secrets/env.sops` in this process; anyone who can run
`sops -d --input-type dotenv --output-type dotenv secrets/env.sops` can
already read every value in it by hand. What this verb adds over that pipeline
is the allow-list, the terminal requirement and the audit line — guard rails,
not authorisation. Keep the age key (and `sudo` on the controller) as the
thing that actually controls access.

### No plaintext copy

`noo onboard` used to write `secrets/age_backup_passphrase.txt` in the clear
and then warn you to copy it somewhere safe. Nothing ever removed the file, so
the passphrase protecting the root of trust sat unencrypted in the repo on
every controller ever installed. Onboard no longer writes either file: it
shows both values once on the console, waits for you to confirm you stored
them, and if there is no terminal (`--non-interactive`, `--tui`, `--web`) it
prints the `reveal` command to run later instead.

The same was true, less visibly, of every other credential the wizard mints:
`secrets/jwt_secret.txt`, `cluster_secret.txt`, `postgres_password.txt` and
thirteen more were written beside `env.sops` on every install and never read
by anything at runtime — the wizard used their existence to recognise an
install it had already set up. It now reads that from the store, and writes
no `secrets/<name>.txt` at all.

An install that predates either change still has the files.
`noo security scan` reports each as **CRITICAL**; `noo onboard` offers to
shred them; `noo security secrets absorb-files` folds each into `env.sops`
(verifying the value reads back before touching the only copy) and shreds it,
and reports rather than shreds a file whose value disagrees with the store.
For the two passphrases, `reveal` offers to shred right after showing you the
value:

```bash
noo security scan                                          # names the file
noo security secrets reveal NOO_AGE_BACKUP_PASSPHRASE      # read it, store it, say y to the shred
noo security scan                                          # clean
```

## Absorb a file credential

```bash
noo security secrets absorb-files
```

Folds the Google Chat service-account JSON (`GOOGLE_CHAT_KEY_FILE` in
`.env`, or `secrets/service_account_key.json`) into the store as
`NOO_FILECRED_GOOGLE_CHAT_B64`, verifies the round-trip, then shreds the
plaintext and removes the `.env` pointer. `noo onboard` offers this during
the channels step; run it by hand if that was declined. Recreate the
gateway afterwards.

## Back up and restore the age key

The age private key is the root of trust: without it the store is
unreadable and the whole install is unrecoverable. It lives **outside**
the install root (`~/.config/sops/age/keys.txt`), so a copy of the repo or
of `~/.noo` does not include it.

- `scripts/backup-controller.sh` writes it as `age-key_<ts>.txt.enc`,
  encrypted with `NOO_AGE_BACKUP_PASSPHRASE` — which must be **different**
  from `NOO_BACKUP_PASSPHRASE`, or recovery is circular. There is no
  unencrypted path: without that passphrase the script refuses to run at all
  and exits non-zero, which noo-hostd reports as a failed backup and
  the `database_backup` action raises as an operator alert. (Before
  2026-09-11 it copied the private key in the clear instead, every six hours,
  because the passphrase was optional and nothing set it.) It keeps the newest
  three and never age-prunes them. `scripts/restore-drill.sh` proves the store
  decrypts using only a restored copy, and **fails** while any plaintext
  `age-key_*.txt` remains in the backup directory.
- `noo onboard` generates `NOO_AGE_BACKUP_PASSPHRASE` into the store, which
  means it lives in `env.sops` — the file the age key decrypts. That is fine
  for running and worthless for recovery, so it must **also** be kept off this
  machine. It is the key to the key.
- `noo migrate export` seals the age key, `secrets/env.sops`,
  `.sops.yaml`, `.env`, `noomesh.yaml`, the `pki/` tree and a fresh
  `pg_dump` into one passphrase-encrypted archive; it refuses to run
  without the age key. `noo onboard --from-archive <file>` restores the
  key first and refuses if a *different* key already sits at the default
  path. (`noo bundle export` carries the deploy slice only — no secrets, no
  key.)
- Restoring onto a fresh machine, in order: install `age` + `sops` →
  restore the age key → restore `secrets/env.sops` and verify it decrypts →
  restore the database → `noo stack start`.

The full procedure, the two passphrases, retention and the scheduled
backup task are in the
[backup runbook](../operating/runbooks/backup-restore-secrets.md).
