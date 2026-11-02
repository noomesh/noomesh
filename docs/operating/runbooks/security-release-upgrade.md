---
title: "Security Release Upgrade"
domain: "security"
architecture: "polyglot"
tools_referenced: []
---

# Security Release Upgrade

> **This page is the record of the `stack-v0.2.39` and `v0.2.40` rolls
> (September 2026).** Read it for an install that is still on a release before
> those tags, or to understand why a control exists; a current install has
> nothing to roll from here, and several steps can no longer be run as
> written (the posture bridges below are retired or refused). What still
> applies to any install: A1 (channel links), A4 (backup passphrases), C1
> (`apply-profile hardened` semantics), C3 (rolling node agents), C4 (the
> fleet signing key) and the Part D checks. Every `curl` against the NATS
> monitoring port (`:8222`) must present a client certificate; the examples
> are shortened.
>
> **Historical for the bus steps.** The `NOO_NATS_LEGACY_SHARED_CREDS` bridge,
> `noo cluster nats-users render --drop-legacy` and the shared
> `NATS_USER` / `NATS_PASSWORD` pair this procedure opens and closes were
> retired: the posture key no longer exists (`posture set`
> refuses it), `--drop-legacy` is a deprecated no-op, and a release after it
> re-renders users.conf itself before launching. For an install that still
> carries the shared user, follow
> the bus rollout in Part C2
> instead of steps A3, C1's bridge line and the `--drop-legacy` step below.

## Purpose

One ordered procedure for taking an **existing** controller and fleet onto
`stack-v0.2.39` / `noo-cli-v0.5.27` — the release that lands the posture
review. (Not `stack-v0.2.38`: that tag produced no release at all, because
the llamacpp image build failed, so there is nothing to deploy under it. It
is a dead tag, not an earlier version of this one.)

This release is different from an ordinary tag roll. Several changes **fail
closed on purpose**, and a control that fails closed fails your upgrade if
you meet it in the wrong order:

- the gateway **exits 2** at startup while `security.exec_approval_mode` is
  still in `noomesh.yaml`;
- the exec-approval gate's no-configuration default became `strict`, and
  removing the YAML key does **not** carry your old value across;
- a client that presents the shared bus credential is **refused**, unless
  the legacy bridge is on *before* the new images start;
- the chat bot refuses **every** sender who is not linked, including you;
- the next scheduled backup **refuses** on a controller with no passphrases;
- redis **refuses to start** on an empty password;
- a node refuses a controller-chosen path outside its declared host roots.

So the order below is the procedure, not a suggestion. Read the whole page
before starting; the "before" section takes longer than the deploy.

New installs need none of this — see
[What a fresh install gets](#what-a-fresh-install-gets).

## Scope

Written for a controller (`controller-1` in this fleet) plus enrolled Linux nodes
(`node-4` and others) and any Mac nodes. Everything is run **on the
controller** unless a step says otherwise.

The page covers **two** tags: Parts A–D take an existing controller onto
`stack-v0.2.39`, and [v0.2.40 — the bus principal](#v0240--the-bus-principal)
is the next one, kept separate because its gate did not ride into
`v0.2.39`.

Two things this page does not replace:

  rollout. This page places its steps in the release order and adds the one
  thing that is new here.
  This page names the two commands this release adds.

## The prerequisite table

Everything that will break an upgrade if skipped, in the order it appears
below.

| # | Prerequisite | Why it breaks the upgrade |
|---|---|---|
| A1 | Link your own channel ids | The bot refuses every unlinked sender, you included |
| A2 | Record the exec-approval mode, then remove `security.exec_approval_mode` from `noomesh.yaml` | The gateway exits 2 while the key is present |
| A3 | Turn the legacy bus bridge **on** | The first container recreated onto the new image refuses the credential it holds |
| A4 | Mint both backup passphrases with `noo security secrets rotate`, read them off the terminal, store them off-box, shred plaintext age keys and any lingering `secrets/*_passphrase.txt` | The next scheduled backup refuses and alerts; the old shell script would have emptied the store (R42) |
| A5 | Declare every browsable folder by host path | The `/host-fs` mounts are gone; the picker can only navigate declared roots |
| A6 | Declare `tools.allowed_paths` | An install that declares nothing can now read nothing |
| A7 | Confirm `REDIS_PASSWORD` is non-empty | Redis refuses to start on an empty password |
| A8 | Configure the CI environments | The approval gate is repository settings, not YAML |
| A9 | Rename the required check in the branch ruleset | The old matrix-named checks no longer exist |
| A10 | Get the new `scripts/noo-fetch.sh` onto every enrolled node | Bundle apply reports 401 until it lands |

## Part A — before you pull the tag

### A1. Link your own channel identity

Chat ingress is default-deny against `noo_user_channel_links`. There is no
config allow-list any more, and `TELEGRAM_ALLOWED_USERS` no longer admits
anyone.

```sh
noo security user link <you> telegram <your numeric id>
noo security user link <you> google_chat users/<id>     # if Chat is in use
noo security user links <you>
```

Do this for every human who talks to the bot. After the deploy the gateway
logs one line per id still sitting in `TELEGRAM_ALLOWED_USERS`, each
carrying the `noo security user link` command that converts it; run those,
then drop the variable.

### A2. Record the approval mode, then retire the YAML key

The exec-approval gate is posture-only now. A leftover
`security.exec_approval_mode` in `noomesh.yaml` is a **startup refusal**
(exit 2), not a silent ignore.

```sh
noo config show | grep -A5 '^security:'          # record exec_approval_mode
```

Write the value down — step C1 puts it back. Then remove the key from the
live `noomesh.yaml` (the `security:` section keeps
`exec_approval_timeout`, which is the Python worker's window and is not a
gate).

There is no `noo` verb that deletes a config key; edit the file. A write
through `noo config set` is refused for the `security` section anyway —
`security`, `tls`, `tools`, `workspace` and `watched_folders` now require an
Admin JWT and refuse every cluster-token caller.

### A3. Turn the legacy bus bridge on

```sh
noo security posture set NOO_NATS_LEGACY_SHARED_CREDS 1
```

**Before** the new images start. That one command writes the DB row *and*
mirrors the key into `.env`; both are needed, because every bus client opens
its connection before it has a database handle. If the mirror fails the
command says so — add the line by hand.

### A4. Backup passphrases

The backup script no longer has an unencrypted branch, and the age private
key is never written in plaintext again. Both passphrases are resolved in a
preflight, before anything is dumped.

```sh
cd ~/.noo                              # install root on a standalone controller; your checkout otherwise
. scripts/lib-secrets.sh && load_secrets
printenv NOO_BACKUP_PASSPHRASE     >/dev/null && echo "pg: set"  || echo "pg: MISSING"
printenv NOO_AGE_BACKUP_PASSPHRASE >/dev/null && echo "age: set" || echo "age: MISSING"

# If either is missing, mint it. This is ONE command now — it writes the
# store correctly, re-encrypts every existing backup file old -> new, and
# hands you the new value on the terminal:
noo security secrets rotate NOO_BACKUP_PASSPHRASE NOO_AGE_BACKUP_PASSPHRASE
```

It prints each generated value ONCE and makes you type `stored` before it
commits, so run it **from the box's terminal, never piped** — piped, it
refuses and changes nothing, because a generated passphrase that reaches a
log instead of you has destroyed access to every backup it was about to
re-encrypt. `--dry-run` first if you want to see the file count.

> **Do not use `scripts/noo-backup-rotate-passphrase.sh` on a release before
> this one.** On a sops-first install it re-encrypted `secrets/env.sops` from
> `.env` — a full replace — which would have reduced a ~30-secret store to
> `.env`'s two bootstrap flags and written both passphrases there in
> plaintext. Nothing had run it; it was caught in `--dry-run`. On this release the script is a
> thin wrapper that execs the verb above, so either spelling is safe — but
> the verb is the one to learn.

Store **both** off this machine — a password manager, not `~/`. The age one
is the key to the key: it lives in `env.sops`, which the age key is what
decrypts. A copy that only exists inside the store it protects is not a
backup.

If the passphrases already existed (so `--generate` was not run) and you do
not have them, read them back — once, on the terminal, audited:

```sh
noo security secrets reveal NOO_AGE_BACKUP_PASSPHRASE
noo security secrets reveal NOO_BACKUP_PASSPHRASE
```

On a controller onboarded before the secret store these are also still sitting in
plaintext under `secrets/`. `noo security scan` reports that as CRITICAL, and
`reveal` offers to shred the file the moment you have read it:

```sh
noo security scan | grep -i "Backup Passphrase Plaintext"   # expect: nothing, after the shred
```

Then prove the refusal is real before trusting the success:

```sh
env -u NOO_AGE_BACKUP_PASSPHRASE scripts/backup-controller.sh   # expect: REFUSING, exit 1
scripts/backup-controller.sh                                    # expect: both .enc files
scripts/restore-drill.sh                                        # expect: PASSED
                                                                # (prints the drill image it resolved)

ls -l ~/noo-backups/age-key_*.txt 2>/dev/null && shred -u ~/noo-backups/age-key_*.txt
```

`restore-drill.sh` **fails** while any plaintext `age-key_*.txt` remains, so
the shred is part of the drill passing, not tidying afterwards.

### A5. Declare every folder the picker needs

The gateway and trellion no longer bind-mount `/home`, `/mnt` and `/media`
at `/host-fs`. The directory picker now builds its browsable set from what
the operator declared — `watched_folders.folders[]`, `workspace` and
`tools.allowed_paths` — each of which the generated compose override
bind-mounts individually.

The honest cost: the picker can no longer **discover** a folder, only
navigate a declared one. Adding a location is a typed host path plus a
restart. List the roots people actually use now, and declare any that are
not already declared.

### A6. Declare the read roots

The tool-layer read policy seeded itself with the process temp dir and the
gateway's own working directory. Both are gone. Roots are now **only**
`tools.allowed_paths`, the watched-folder mounts and the workspace — and an
install that declares nothing can read nothing.

If anything depended on reading a path outside those three, declare it now.
A deny-list sits behind the declaration and cannot be opened by config, so
declaring `/` still does not hand the model the gateway's keys.

### A7. Redis password

```sh
grep '^REDIS_PASSWORD=' .env | cut -d= -f2- | wc -c   # expect > 1
```

Redis reads the password from its environment and writes a 0600 config
inside the container; an empty value now **refuses to start** rather than
coming up with authentication disabled.

### A8. CI environments (repository settings)

The YAML routes the PR-triggered self-hosted jobs through an environment,
and GitHub evaluates an environment's protection rules before dispatching
the job to a runner. **The YAML alone does nothing.** In Settings →
Environments:

- `ci-pr-selfhosted` → **Required reviewers**: the maintainers.
- `ci-push` → no protection rules.

### A9. Branch ruleset

The Python test matrix is gone; there is one interpreter and it is the one
that ships. The ruleset "noomesh CI gates" must require **`test`**, not
`test (3.11)` / `test (3.12)` / `test (3.13)` — those check names no longer
exist, so the rule can never be satisfied.

### A10. Get the new applier fetcher onto the nodes

`scripts/noo-fetch.sh` now signs **two** things, and must reach every enrolled
node **with or before** the controller upgrade:

- the bundle-**apply report**, with the fleet secret (the report route is
  authenticated) *or* with the node's birth key;
- a new bundle-**fetch receipt** (`POST /bootstrap/bundle/<node>/fetched`),
  signed with the node's birth key. That receipt is what stamps `fetched_at`.
  It used to be stamped by the public GET, which made it a state write any
  anonymous caller could make — so it meant "somebody collected this
  ciphertext", never "the node did".

The failure mode is bounded and worth knowing, and this release keeps it
bounded on purpose: apply reports 401 and fetch receipts do not arrive until
the new script lands, and the compatibility window
(`NOO_BOOTSTRAP_ACCEPT_UNSIGNED_FETCH`, on by default) keeps the old,
unsigned stamp working for one release so a straggler shows up as a missing
status line in `noo cluster provision --wait`, not as a broken provision.

**The window exists because of the ordering, not despite it.** `noo-fetch` is
delivered *by* the provisioning lane it gates, and the controller is upgraded
first — so on day one every enrolled node is still running the old script.
Close the window in [C8](#c8-next-release-removals) once they are not.

On the shipped rail this rides the provision bundle, so in practice
step C3's `noo upgrade --nodes` carries it. If you have a node you cannot
reach that way, copy the script to it by hand before starting.

## Part B — the deploy

### B1. The CLI first

```sh
noo upgrade --check
noo upgrade --version 0.5.27
noo --version
```

`noo-cli-v0.5.27` is the floor for this release, cut at `97861f95`. It is the
first CLI whose Mac agent cross-build succeeds at all, so on a fleet with Mac
nodes an older CLI cannot deliver a working darwin bundle.

It is a floor, not a ceiling, and one thing genuinely wants the next release:
a Mac provisioned by 0.5.27 still sends no bundle apply report, so its apply
outcome is only readable on the node itself — see the Mac notes in
[C3](#c3-roll-the-node-agents) and [V10](#part-d--verification-checklist).

### B2. The stack

Standalone controller:

```sh
noo upgrade --stack --tag stack-v0.2.39
```

`noo upgrade --stack` manages **standalone** installs only; on a repo
checkout it refuses and names the alternative. For a checkout controller:

```sh
git pull
noo stack start --dist --tag stack-v0.2.39
```

Do not recreate the gateway by hand with `docker compose`. A container
started outside the launcher runs without the injected secrets. See the
[operator manual](../operator-manual.md) for the lifecycle rules.

### B3. Confirm it came up

```sh
noo stack status
noo health
docker logs noo-gateway 2>&1 | tail -40
```

If the gateway exited 2, re-read A2 — the message names the key and the
command that replaces it. If it refuses on the bus, re-read A3. Both have a
host-level fix in [When the gateway is already down](#when-the-gateway-is-already-down).

## Part C — after the deploy

### C1. Posture, and putting the approval mode back

```sh
noo security posture apply-profile hardened
noo security posture set NOO_EXEC_APPROVAL_MODE <the value from A2>
noo security posture list
noo stack restart --force gateway
```

Both steps matter. `apply-profile hardened` is what makes "hardened is the
distribution default" true on an install that predates it — the posture
table was empty on every controller onboarded before this release, so every
gate fell through to `.env`. And the profile sets the approval gate to
`approval`, which is **not** necessarily what you were running: removing the
YAML key does not carry your old value over, and with nothing configured at
all the gate is now `strict`.

**C1 does not touch the rollout bridges.** `apply-profile` sets GATE keys
only; `NOO_NATS_LEGACY_SHARED_CREDS` (step A3),
`NOO_CLUSTER_LEGACY_FULL_ACCESS` and `NOO_BOOTSTRAP_ACCEPT_UNSIGNED_FETCH`
are **bridges** and are left exactly as you set them. The command lists each
one with its current value and warns when one is still open, so C1 is also
your checkpoint on what is still bridged. This is new in this release: C1
used to close the bus bridge and undo A3, which took a node off the bus
mid-upgrade until the bridge was restored by hand (§3f R43).

Close a bridge only when its migration is finished — for the bus that is
after [C2](#c2-the-bus-rollout), when every node has its own credential:

```sh
noo security posture set NOO_NATS_LEGACY_SHARED_CREDS 0   # one bridge, deliberately
# ...or all of them at once, once every migration is done:
noo security posture apply-profile hardened --include-bridges
```

Either form writes the `.env` mirror as well as the DB row for the keys that
need it — `NOO_NATS_LEGACY_SHARED_CREDS` is read by the workers and the
node-agent before any database handle exists, so a DB row alone reaches one
reader out of three. (`apply-profile` did not mirror at all before this
release: the row went to `0`, `.env` kept saying `1`, and the gateway refused
to serve while the workers carried on.)

Posture is restart-to-apply, so the rows do nothing until the gateway is
recreated. Use `restart --force`: a plain restart keeps the old container
environment.

> **`apply-profile hardened` closes the external MCP door.** Profiles no
> longer touch rollout **bridges** — `NOO_NATS_LEGACY_SHARED_CREDS` is left
> exactly as [A3](#a3-turn-the-legacy-bus-bridge-on) set it, and
> `apply-profile` reports which bridges it left alone and which are still
> open. Closing bridges is opt-in now.
>
> `NOO_MCP_EXTERNAL_ENABLED` is deliberately **not** a bridge: it is a gate,
> both profiles set it to `0`, and closing a door is the safe direction. So if
> this install serves the external MCP door, C1 closes it and you re-open it
> as its own decision:
>
> ```sh
> noo security posture list | grep NOO_MCP_EXTERNAL_ENABLED
> noo security posture set NOO_MCP_EXTERNAL_ENABLED 1   # only if you use that door
> ```
>
> Opening it is a decision about a specific person, which is why no bundle
> does it for you. Read the before/after diff `apply-profile` prints rather
> than assuming which way a gate moved.

### C2. The bus rollout

Two things belong
to this release specifically.

**The render is also a grant migration.** The node principal gained four
harness subjects that an existing `users.conf` does not have: it publishes
`harness.turn.<id>.>` and `harness.ready.<id>`, and subscribes to
`harness.run.<id>` and `harness.task.<id>`. Nothing renders them for you —
neither `noo upgrade --stack` nor `noo upgrade --nodes` touches
`users.conf`, so the render below is the only thing that grants them.

It folds into the rollout's existing first step rather than being a step of
its own, and it does **not** force a gateway-first ordering: the `gateway`
principal holds `>` in both directions, so only the node's grant changed.

**One ordering does matter, from 0.5.40.** The turn subject became
`harness.turn.<node>.<conversation>` and the grant narrowed to match
(`harness.turn.<id>.>`). A harness still on an older release publishes the
old, node-less subject, which the narrowed grant refuses — so **upgrade the
nodes' harnesses before re-rendering `users.conf`**. The gateway listens on
both shapes for this one release, so the other order (render last) is safe
and the reverse is a silent outage: the old harness's publishes are refused
asynchronously and every dispatched turn times out.
Until the render runs, a node harness placement binds nothing and runs
nothing — and NATS drops a denied publish and returns success to the caller,
so it will not announce itself.

```sh
noo cluster nats-users render
docker kill -s HUP noo-nats      # render signals it too; this is the fallback
```

The render reads the fleet from the gateway registry, so every enrolled node
gets its principal re-rendered with the current grant set. It reuses every
password the store already holds and mints only what is missing — re-running
it rotates nothing.

Then follow the runbook: `noo cluster nats-creds rotate <node>` one node at
a time, `noo stack restart --force` for the workers and trellion, the
gateway last, and `/connz?auth=1` after each.

**Do not run `--drop-legacy` or turn the bridge off yet.** Both wait until
every node — Mac nodes included — is on its own credential. That is step C6.

### C3. Roll the node agents

The node-agent binary is the artifact that carries the node/controller wall:
declared host roots, the container capability floor, the placement env
allow-list, controller-identity on the work routes, and the refusal channel
that reports all of it back on the heartbeat.

**Validate on one GPU node before the fleet.** Backend containers now run
`CapDrop ALL` + `no-new-privileges` with a narrow `CapAdd` set, and that set
could not be tested against a real GPU backend in the change that introduced
it. GPU access itself needs no capability — the NVIDIA container runtime
works through device cgroups and bind-mounted driver libraries — but an
image may want one for its own entrypoint.

**One verb, on either install.** Agent binaries reach a node only in a
provision bundle signed by the fleet signing key, over the pull rail:

```sh
noo cluster provision <one-gpu-node> --wait
noo cluster show <one-gpu-node>          # confirm the agent version moved
```

`noo cluster provision` is the same code `noo upgrade --nodes` runs per
node. It extracts the agent from the released `node-agent:<tag>` image and
**checks the extracted binary actually carries that tag**, refusing rather
than shipping a stale one — the failure that once delivered a whole
release's node-agent fixes to nobody while reporting exit 0. It falls back
to a source cross-build only where a source tree exists. `--wait` blocks
until the node reports its apply verdict.

`noo cluster upgrade-agents <node> -y` is now the same restage for the
named nodes, serially. It used to be a separate checkout-only lane — a
cross-build, then `/pull kind=binary` and a root swap by hostd on the
strength of a manifest the gateway signed — and that lane is **retired**
. An older CLI that still tries it is refused: the agent
answers `/pull kind=binary` with 410 and the reason.

Then, either way, validate the backends:

```sh
noo cluster place <one-gpu-node> vllm <model>
noo cluster place <one-gpu-node> llamacpp <model>
noo cluster show <one-gpu-node>
```

Confirm both serve. If an image needs more, add
`NOO_BACKEND_CAP_ADD=<CAP>` to that node's `/etc/noo-node-agent.env` and
restart the agent — node-local, no code change.

Watch that node's journal for two new refusal lines:

```sh
journalctl -u noo-node-agent -n 100 | grep -E 'models_dir_refused|start_failed'
```

A `models_dir` that sits outside the node's declared roots
(`MODELS_DIR`, `NOO_DATA_ROOT`, `HF_CACHE_DIR`, `OLLAMA_DATA_DIR`,
`NOO_SKILLS_HOST_DIR`, `NOO_HOST_ROOTS`) is now **refused**, not warned
about — the mount does not happen and GGUF placements that depend on it are
skipped. Fix is one line in that node's env, or correct the `node_config`
row.

Then the rest of the Linux fleet, on either install:

```sh
noo upgrade --nodes
```

This restages a provision bundle for every pull-capable node, uploads the
CLI release assets the nodes fetch, and handles the controller's own agent —
which the pull rail structurally cannot reach — last. It is the same
per-node staging as `noo cluster provision`, so on a standalone controller
this is the fleet verb.

**Then every Mac, one at a time:**

```sh
noo cluster provision <mac> --wait
```

The darwin bundle did not carry the node's own NATS credential until this
release; Mac agents have been on the shared `noo` user. Each Mac must be
re-provisioned with the new CLI **before** the bridge goes off in C6, or it
drops off the bus the moment the shared pair stops being accepted.

**Expect the Mac to look like it half-worked, and do not act on that.** On
`noo-cli-v0.5.27` and older the darwin poller sends no apply report — that
lane had no credential for the authenticated report route until after this
release — so `provision --wait` collects the bundle and the controller then
says the node **"fetched the bundle but reported no apply outcome"**. It says
that on a successful apply too. Confirm from the node's own side instead:

```sh
noo cluster logs <mac>
```

and check the bus, which is the thing you actually came for:

```sh
P=~/.noo/pki; curl -s --cacert $P/ca.crt --cert $P/gateway/gateway.crt --key $P/gateway/gateway.key \
  "https://127.0.0.1:8222/connz?auth=1" | grep -c 'node-<mac>'
```

From the next CLI release the report lands and the outcome shows on the
controller. Same caveat applies to [V10](#part-d--verification-checklist).

Two node-side changes worth expecting rather than debugging:

- **Client certificates are now required.** A node with a cluster CA
  configured requires and verifies a client certificate; the controller-only
  routes answer **503** (not 403) on a node that cannot identify callers at
  all, naming the missing `NOO_TLS_CA` / `NOO_TLS_CERT` / `NOO_TLS_KEY`. The
  shipped enrollment order lands the certificates before the agent ever
  starts, so there is no window on that lane — but a node installed by the
  retired SSH edge script will answer 503 until its certificates are placed
  where the rest of the system looks for them.
- **stdio MCP placements are refused, and node-local ones are contained.**
  The controller may say *which* servers a node runs; the node owns *what*
  runs, from a root-owned `/etc/noo/mcp-servers.json`. A legacy stdio
  placement comes back through the refusal channel with the file named, and
  `noo mcp server add --transport stdio` prints a ready-to-paste entry.

  What is new in this release is the floor underneath it: a node-local server
  runs in a **container**, under the same host config as `/api/skills/run` —
  non-root, `CapDrop ALL`, `no-new-privileges`, a pid cap, no host network,
  binds only under declared roots. So every entry needs an `image`, and an
  entry without one **does not start** (the refusal names the field). There
  is no plain-exec fallback: the old lane ran the server as `noo-agent`, which
  is in the `docker` group.

  Nothing in the fleet is migrated by this — `/etc/noo/mcp-servers.json` does
  not exist on any node today, so the first entry an operator writes is the
  first exercise of the path. A node with no Docker now runs no node-local MCP
  server at all and says so on the refusals channel.

### C4. Roll the fleet signing key

The key that signs root code is no longer the key that issues identities.
`ca.key` keeps the certificates; a new `signing.key` signs the node bundles
that deliver the agent, the applier and fleet secrets.

```sh
noo security pki rotate-signing-key --deliver-only -y    # deliver the existing key
# or, to mint a new one and roll it:
noo security pki rotate-signing-key -y
```

Confirm on the controller:

```sh
ls $NOO_PKI_DIR/signing.key $NOO_PKI_DIR/signing.pub
ls $NOO_PKI_DIR/nodes/*/signing-adopted
```

and on each node:

```sh
ls -l /etc/noo/pki/signing.pub
journalctl -u noo-fetch -n 30 | grep verified-by     # expect: verified-by: signing-key
```

Adoption is per node and recorded on the controller, so a node that has not
confirmed keeps receiving CA-signed bundles and nothing breaks while the
fleet converges.

**Read the closing summary carefully — only one of its three outcomes is
work.** The marker needs positive proof (an apply report of exit 0), and a
node that cannot report is not the same as a node that failed:

| Outcome | Meaning | Re-run for it? | Gates C8? |
|---|---|---|---|
| **adopted** | ran `noo-apply` on this bundle, exit 0 | no | — |
| **no report** | collected it, but this node has never reported an apply for anything — a Mac on `noo-cli-v0.5.27` or older sends nothing on success *or* failure | no. Verify by hand per [V10](#part-d--verification-checklist), then give it a current CLI | **no** |
| **straggler** | a node that *can* report and did not adopt, or any node whose bundle was never collected | **yes** | **yes** |

An un-collected bundle is a straggler even on a silent node: the *gateway*
records the fetch, so that is a dead fetch timer rather than an old CLI.

The command exits non-zero only for stragglers, so it is safe to gate on:

```sh
noo security pki rotate-signing-key --json --deliver-only -y \
  | jq '{ok, complete, adopted, no_report, failed, orphaned_material}'
```

`ok` is false only when there are stragglers; `complete` is false if
anything at all is unproven. **`orphaned_material`** lists key material for
nodes the registry does not know — see [C7](#c7-loose-ends).

> **Roll every node before the next release.** The compatibility arm that
> still accepts a CA-signed bundle WARNs on every apply and is removed in the
> release after this one. A node that never adopted can then only be
> recovered by re-enrolling it. It is arm 1 of two — see
> [C8](#c8-next-release-removals).

### C5. Monitoring service leaves and the Grafana password

Prometheus and promtail mounted the gateway's private key. That leaf carries
`O="Mesh Cluster Gateway"`, which is the entire basis on which a node decides
a caller is the controller — so two containers whose jobs are "GET some URLs"
and "ship some logs" held a credential good for `/start`, `/stop`, `/clean`
and `/api/skills/run` on every node they could reach.

```sh
noo security pki issue-service prometheus
noo security pki issue-service promtail      # skip on stacks past fleet logging phase 4: promtail is gone
noo security pki status | grep -E 'prometheus|promtail'
```

Recreate the three monitoring containers so they pick up the narrowed
mounts. The narrow mount is the load-bearing half — a narrowed scrape config
over a wide mount leaves the gateway key one `cat` away.

```sh
noo stack restart --force prometheus promtail grafana

docker exec noo-prometheus ls /app/pki/gateway     # expect: No such file or directory
curl -s http://127.0.0.1:9090/api/v1/targets | grep -c '"health":"up"'
```

Grafana: `noo security scan` now reports a published placeholder
(`changeme` / `admin`) as CRITICAL. Re-running `noo onboard` replaces the
environment value — but Grafana copied the old one into its own database on
first boot, so the env var alone does not change the login:

```sh
docker exec noo-grafana grafana cli admin reset-admin-password '<new>'
```

Grafana keeps its own users. It is not fronted by the gateway's auth, and
its port binds `127.0.0.1` by default.

### C6. Close the bus rollout

Only once `/connz?auth=1` shows no session on `noo` — every Linux node
rotated, every Mac re-provisioned, workers and gateway on their own
principals:

```sh
noo cluster nats-users render --drop-legacy
docker kill -s HUP noo-nats
noo security posture set NOO_NATS_LEGACY_SHARED_CREDS 0
noo stack restart --force
```

That last pair is what makes the isolation enforced: a gateway that resolves
the shared pair now refuses to serve, and the `nats_isolation` preflight row
goes critical.

### C7. Loose ends

- **Stale proposal rows.** `noo_cluster_proposals` rows sitting in
  `approved` or `executing` will never be picked up — nothing polls them any
  more. They are not pending work; a `revive_node` row means a node was down
  an hour ago. There is no migration and none is needed.
- **`noo cluster set-primary`** no longer promotes Postgres itself. Run the
  promotion on the target, then pass `--promoted`.
- **`sshd` on the nodes is now an operator decision.** Nothing in the mesh
  dials it. Whether it stays as break-glass is a choice to make deliberately,
  not residue to leave.
- **`NOO_TLS_INSECURE` is retired.** Exporting it is now an **error** naming
  the fix, not a no-op. The CLI has no verification-off lane at all.
- **Running `noo` from a checkout on an enrolled box.** While
  `/etc/noo/controller-url` exists, the five transport keys
  (`NOO_GATEWAY_URL`, `CONTROLLER_URL`, `NOO_TLS_CA`, `NOO_TLS_CERT`,
  `NOO_TLS_KEY`) are honoured only from a declared root or the process
  environment — never from a cwd-derived clone. `noo auth status` reports
  any file it ignored and why. The escapes are `--gateway`, exporting the
  variable, or `NOO_REPO_ROOT=$PWD`.
- **Re-enrolling with an old paste fails.** A blob minted before this
  release carries no `ca` field and is now refused. Re-mint with
  `noo cluster provision <node>`.
- **A forgotten node's leftover key material.** This used to be reported as
  a signing-key straggler forever, because the rollout decided who still
  needed the key from what was on disk under `$NOO_PKI_DIR/nodes/` — and
  nothing was ever going to collect a bundle for a node that no longer
  exists. Targets now come from the node registry, and
  [C4](#c4-roll-the-fleet-signing-key) reports such a directory under
  **orphaned material**, before the rollout, with the purge command and an
  explicit note that it is not a straggler:

  ```
  orphaned material (not stragglers)
    node-3: key material on this controller, no such node in the registry
      rm -rf /home/<user>/.config/mesh/pki/nodes/node-3
    left in place — this command never deletes key material
  ```

  Run the `rm -rf` when you are satisfied the node is gone. It is your
  decision, not the tool's: this is a private key, and C4 will not delete
  one. `noo cluster forget` no longer leaves material behind — it archives
  the directory to `$NOO_PKI_DIR/.forgotten-<node>-<timestamp>`, which is
  dot-prefixed so nothing reads it as a node. Older forgets predate that, so
  their directories are still there to purge.

### C8. Next-release removals

> **Retired.** `NOO_CLUSTER_LEGACY_FULL_ACCESS`,
> `NOO_BOOTSTRAP_ACCEPT_UNSIGNED_FETCH` and `NOO_BUS_PRINCIPAL` are no longer
> bridges: their code paths are deleted, and a gateway built with that change
> **refuses to start** while a posture row (or its env) still holds one open,
> naming the key. `noo security posture set <key> <closed value>` — `0`, `0`,
> `required` — is the one write still accepted for them, and clears it. On
> such a build, skip every step below that OPENS one of them.

Two compatibility arms used to accept something weaker and WARN every time
they did. **Both are retired now** — arm 2 in v0.2.82, arm 1 with the
CA-signed lane — and the table is kept for what each one was and what replaced it.

| # | Arm | On is | What it accepts | Close it with |
|---|---|---|---|---|
| 1 | `NOO_APPLY_ACCEPT_CA_SIGNED` | node-side | a CA-signed bundle that is not a signing-key rollover | nothing to do: **retired**. The applier refuses such a bundle (77) whatever the variable says, and the controller no longer renders it. A node that has not adopted takes a CA-signed *rollover* instead — `noo cluster provision <node> --wait` — see below |
| 2 | `NOO_BOOTSTRAP_ACCEPT_UNSIGNED_FETCH` | controller-side, a posture key | an **unsigned** `fetched_at` stamp or apply report on the provisioning pull lane | nothing to do: **retired in v0.2.82**, an unsigned receipt is always refused and the gateway refuses to start while the key is open (see the banner above). Every node still needs `scripts/noo-fetch.sh` to sign its receipts |

**Arm 1 is retired.** It was never closeable by a hand edit
(`noo-fetch.service` carries no `EnvironmentFile`), then
the controller rendered it closed per node, and now it is gone from both
appliers. What replaced it for a node that has not adopted the signing key:
`noo cluster provision` delivers the key alone first (the CA signs
`signing-pub` and nothing else), records the adoption from the node's report,
then signs the real bundle with the signing key.

**The positive check is the applier's own account, not the file.** Re-stage the
node and read the line under the apply outcome:

```sh
noo cluster provision <node> --wait
# > <node> reported: applied (exit 0)
#   verified against the fleet signing key · CA-signed lane retired on this node
```

`verified against the cluster CA — a signing-key rollover (first adoption)` is
a node adopting on this apply; the next restage reads `fleet signing key`. A
refusal (`REFUSED … CA-signed apply lane is retired`, or `… did not
countersign`) is named per node in `noo cluster verify`'s `legacy lanes` row.

**Check adoption, not a variable.** The adoption list is what says the fleet
is off the CA:

```sh
noo security pki status        # the "fleet signing key" section
```

It names the fingerprint, the nodes that have adopted, and the nodes that
have not. **A node that has not adopted adopts on its next restage**: provision
first sends the key alone, CA-signed (the only anchor it can verify and the
only thing the CA may sign), waits for the node's report, then the bundle:

```sh
noo cluster provision <node> --wait     # adopts; the next restage reads "fleet signing key"
```

`rotate-signing-key <node> --deliver-only` still works and does the same
thing with a smaller bundle.

**The controller's own node is rolled like any other.** `rotate-signing-key`
used to filter the local hostname out of its targets, from when a controller
was never also a node. With the self-node lane it is one, it polls and applies
bundles, and it needs the signing key for the same reason every node does —
excluded, it answered "not registered with this controller" while
`cluster status` listed it Online, and verified every bundle on the
since-retired compatibility lane.

**Arm 2, in order.** The rollout order is forced: `noo-fetch` is delivered by
the provisioning lane it gates, so the controller is necessarily upgraded
before any node has the script that satisfies it.

```sh
noo upgrade --nodes                     # restages a bundle carrying the new noo-fetch
noo cluster provision <mac> --wait      # each Mac, one at a time

# Then confirm nothing is still writing unsigned. One line per unsigned write:
docker logs noo-gateway 2>&1 | grep -E 'bundle_pull_write_unsigned|bundle_get_stamped_fetched_at'
```

Read one warning per node as normal and a repeating one as the signal. The
GET stamps on the way past before the node has hashed the blob it is about to
sign, so the first poll after a gateway restart warns about every node
whatever it holds. Once a node posts a signed receipt the gateway stops
stamping for it, so a node that keeps appearing is a node that is genuinely
not signing — name it rather than the fleet. The positive check is the
receipt itself:

```sh
docker logs noo-gateway 2>&1 | grep -E '"path":"/bootstrap/bundle/[a-z-]+/fetched"'
```

Expect a 200 per node. That, not the absence of warnings, is what says the
fleet can live without the window. A healthy fleet returns 200 for every node, the Mac included.

Wait for a fetch cycle on the slowest node (the steady-state cadence is one
poll every ~5 minutes) and re-check. When the grep names nobody twice:

```sh
noo security posture set NOO_BOOTSTRAP_ACCEPT_UNSIGNED_FETCH 0
noo stack restart --force gateway       # posture is restart-to-apply
```

> **One caveat while this release is current.** The `hardened` bundle sets
> this arm to `1` on purpose — [C1](#c1-posture-and-putting-the-approval-mode-back)
> applies the profile *before* [C3](#c3-roll-the-node-agents) delivers the
> `noo-fetch` that satisfies it, so closing it in the bundle would stop the
> step that closes it from running. The consequence: after you set it to `0`,
> re-running `apply-profile hardened` puts it back to `1`. Set the single key
> again if you do. The next release deletes the arm, and the bundle row with
> it, so the interaction disappears rather than being something to remember.

Then prove the refusal rather than trusting the quiet — this is [V13](#part-d--verification-checklist).

#### Confirm every Mac can sign, before you close it

A Linux node that cannot sign is loud: `noo-fetch` writes to the journal every
tick. A **Mac** was not, until `noo-cli-v0.5.29` — it posted its apply report
unsigned and let the controller answer 403, so the only visible symptom was a
missing apply outcome and a gateway line about a header the Mac never sent
(seen on a Mac).

So a Mac needs one positive check each, not an absence of complaints:

```sh
# ON THE MAC. Both must succeed; the second must print a byte count, not 0.
ls -l ~/noomesh/birth.key
printf 'noo-bundle-apply:%s:%s:%s' "$(cat ~/noomesh/node-name)" \
    "$(printf 'x%.0s' $(seq 64))" "$(date +%s)" \
  | openssl dgst -sha256 -sign ~/noomesh/birth.key | wc -c
openssl version          # macOS ships LibreSSL, not OpenSSL
```

Then, on the controller, confirm the Mac's receipts are actually landing
signed:

```sh
docker logs noo-gateway 2>&1 | grep -c 'bundle_pull_write_unsigned'   # want: 0
docker exec noo-postgres psql -U noo -d noomesh -At -c \
  "SELECT node_name, fetched_at, applied_at, apply_rc FROM mesh.noo_provision_bundles ORDER BY node_name;"
```

`applied_at` null on a node whose bundle demonstrably applied is the signal
that its report is being refused. On a Mac, the reason is in **that Mac's** log
(`log show --predicate 'process == "noo"' --last 30m`, or the fetch daemon's
stderr) — since v0.5.29 the Mac names it there rather than posting unsigned.

A Mac that cannot sign must be re-enrolled (`noo enroll`) **before** the window
closes, or its provisioning fails outright rather than merely reporting
nothing.

A node left behind does **not** stop provisioning: its bundle still fetches
and still applies (the GET stays public — the blob is ciphertext the node's
birth key opens, and the node holds no fleet credential at that moment). What
it loses is `fetched_at`, so `noo cluster provision --wait` narrates
"staged → …" and times out at the fetch stage instead of naming it. The fix is
to get the script there, not to re-open the window.

### C9. v0.2.40 — both MCP doors move

Applies to the **v0.2.40** roll, not this one. Every item below is on `dev`.

Two of them compose: each MCP door loses a spelling it had kept for
compatibility. Both are recorded here rather than in the release notes alone
because in each case the thing that breaks is a *client or proxy config*
written months ago — so the roll cannot fix it, and there is nothing on the
box to explain the failure.

#### C9a. The user door: `/mcp/external` is gone

`/mcp/external` is removed from the gateway. It had been an alias of the user
door since the door was renamed `/mcp/user`, and it sat in the
self-authenticating public path list — so every day it survived was another
client config that never migrated. After the roll the router answers **404**
for it. Clients POST to `/mcp/user`.

`NOO_MCP_EXTERNAL_ENABLED` keeps its name: it is the gate, not the path.

**The part that breaks quietly.** A controller onboarded before v0.2.40 has a
`tailscale serve` mapping whose `/mcp` path fronted `/mcp/external`. That
mapping lives on the tailnet, not in the gateway, so the roll cannot fix it
and nothing in the container logs mentions it — the serve proxy keeps
answering and faithfully returns the gateway's 404.

**Re-running the wizard does not clear it.** The serve plan no longer writes
the ts.net `/mcp` path at all — it writes `/mcp/user` and `/mcp/operator`,
the same two names on both sides — and `tailscale serve` never removes a path
it was not told about. So `noo onboard --reconfigure` leaves the stale `/mcp`
exactly where it was. Clear it once, by hand, on the controller:

```sh
sudo tailscale serve --https=443 --set-path=/mcp off
tailscale serve status        # confirm /mcp is gone and the two doors remain
```

A freshly onboarded controller never has the path and needs nothing.

#### C9b. The operator door: the `:3100` listener is gone

The gateway's plain-HTTP operator-door listener on `127.0.0.1:3100` is
**removed**, which closes the DNS-rebinding row by removing its cause rather
than guarding it. The operator door is `/mcp/operator` on the gateway port,
and a credential is **mandatory on every request**: an `mcp:operator` service
key bound to an admin account, or the `NOO_MCP_TOKEN` bearer.

The behaviour change worth stating plainly: on the old listener an **empty**
`NOO_MCP_TOKEN` meant *unauthenticated*, because the loopback binding was
treated as the boundary. On the gateway door an empty token **refuses** — it
never opens. There is no "empty means open" arm left.

**Before the roll**, mint yourself a key, because the door you are about to
depend on will not accept an absent credential:

```sh
noo security service-key issue <you> --scopes mcp:operator --user <admin>
```

The key is shown once. `mcp:operator` requires the bound account to be an
admin.

**After the roll**, repoint every MCP client entry:

| was | now |
|---|---|
| `http://127.0.0.1:3100/mcp` | `https://127.0.0.1:8080/mcp/operator` |

with the bearer set, and the cluster CA trusted so the client can verify the
gateway's certificate — the old lane was plain HTTP and needed no trust at
all:

```sh
noo security trust-ca
```

`noo mcp tools` reads `NOO_MCP_KEY` (your personal `mcp:operator` key) or
`NOO_MCP_TOKEN`.

**Retired and now unread** — delete them rather than leaving them to imply a
control that no longer exists: `NOO_MCP_HOST`, `NOO_MCP_PORT`,
`NOO_MCP_REMOTE`, `NOO_MCP_BIND_ADDR`, `NOO_MCP_GATEWAY_HOST_PORT`, and
`mcp.port` in `noomesh.yaml`. They all addressed the removed listener. This
matters more than tidiness: `NOO_MCP_BIND_ADDR` and `NOO_MCP_REMOTE` were the
pair an operator used to reason about how far that door reached, so a stale
value left in place reads as a boundary that is no longer there.

#### C9c. Host-process nodes stop needing a hand-shipped helper image

Only relevant if you hand-ran a `sync-images` on a host-process node to get
model preseeding working. You can stop.

The agent's host operations — creating the models dir, preseeding weights —
run inside an image, and a **host-process node has no local copy of it**: it
is not a container itself, so nothing ever put one there. Before v0.2.40 the
helper simply failed to create and the preseed treated that as a *store
miss*, falling through to a public HuggingFace download and logging
`model-cache preseed miss; downloading from HF`. The node had quietly stopped
using the weight cache and quietly started fetching weights from the
internet, while reporting success.

The pre-v0.2.40 workaround was to ship the image by hand:

```sh
# NO LONGER NEEDED after the v0.2.40 roll
noo cluster sync-images <node> -i ghcr.io/noomesh/node-agent:<tag> --no-restart
```

The `-i` was load-bearing: a bare `noo cluster sync-images <node>` named the
unprefixed local build names, so on a released node it shipped nothing the
node would ever ask for — and said it succeeded.

After the roll, both halves are fixed — **this one has landed**. The helper
arrives over the artifact rail as a digest-verified tar, pulled by the node
as its own identity, and a helper that genuinely cannot be supplied is a
**typed refusal** carrying the `sync-images` command rather than a silent
fallback. The controller's default `sync-images` set now covers the release
ref too, so the bare command means what it looks like.

And the preseed no longer asks for a helper at all. Copying a file needs no
container: the agent binary already carries the preseed code, so the HF
snapshot mirror and the verified GGUF fetch run **in the agent process**
against the host path, over the same `:8083` rail with the same manifest
digest check. The helper rail above still matters — the remaining host
operations (creating the models dir, probing host files) genuinely need root
inside a container — but a node that never runs those can preseed weights
with no image on it at all.

**Verify** — place a backend on a host-process node and read that node's
journal:

```sh
noo cluster place <host-process-node> vllm <model>
journalctl -u noo-node-agent -n 200 | grep -iE 'helper|preseed'
```

Expect `model preseeded from controller store` with a file count, and **no**
`model-cache preseed miss; downloading from HF`. That absence is the whole
point: the old failure's only symptom was a log line that looked like a
routine cache miss, so a green placement proved nothing. If a refusal appears
instead, it names the `sync-images` command to run — which is the correct
outcome, not a regression.

#### C9d. The audit log was silently dead

On this fleet the audit table had **never** received a row. It is
RANGE-partitioned by month, an insert whose month has no partition fails
outright, and the startup hook that was supposed to create partitions asked
for the function in the wrong schema — so it logged one warning a boot and
created nothing, while every writer discarded its own insert error.

Two things worth being blunt about:

- **The history is not recoverable.** Nothing buffered those rows. Every
  auth failure, posture change, config refusal and ingress denial that
  should have been recorded before this fix is simply gone. Nothing in the
  upgrade brings them back.
- **A green install proved nothing.** The audit log is what the other
  controls are *read through*, so its silence looked exactly like "nothing
  bad happened". That is why V1's row half could not be confirmed on the
  walk.

**Verify after the roll** — take a baseline, do something auditable, take it
again:

```sh
docker exec noo-postgres psql -U noo -d noomesh -c \
  "SELECT count(*), max(created_at) FROM mesh.noo_security_audit;"

noo auth login <you>          # any login is enough

docker exec noo-postgres psql -U noo -d noomesh -c \
  "SELECT count(*), max(created_at) FROM mesh.noo_security_audit;"
```

The count must **grow** and `max(created_at)` must move to now. A count that
stays put is the same failure again, not an install with nothing to say —
check the gateway log for a partition warning at boot.

Do this before relying on V1, V2 or V4, all of which read the audit trail as
their evidence.

#### C9e. The Telegram approval notice never arrived

Distinct from C9d and worth its own retest. The approval notice is sent as
Markdown, and the tool name was interpolated unescaped — so a tool whose name
contains an underscore opened an italic span the notice never closed, and
Telegram rejected the whole message with HTTP 400. The send error was then
swallowed at the call site.

The part that makes this more than a formatting bug: **`python_tool` and
`skill_execute` both contain underscores.** Those are the two HIGH-risk tools
the approval gate exists for. `browser`, which has no underscore, delivered
fine. So the gate was blocking calls and silently failing to tell anyone, for
exactly the calls it was built to gate — the request sat until the window
expired and the operator saw nothing.

Google Chat was unaffected and passed end to end on v0.2.39.

**Retest over Telegram after the roll**, with a tool whose name has an
underscore, because a clean run with `browser` would reproduce the old false
pass:

```sh
noo approval pending      # before: note what is there
```

Then, from the linked Telegram chat, ask for something that triggers
`python_tool`. Expect the approval card to **post in that chat**, then reply
with a bare `y` and confirm the call runs. If no card appears, check the
gateway log — a refused notice is now logged with its chat id instead of
vanishing.

#### C9f. `HF_CACHE_DIR` is an HF_HOME, not a hub directory

One line, because the corrected page carries the detail:
[../../models/weight-cache.md](../../models/weight-cache.md). `HF_CACHE_DIR`
must be the directory that **contains** `hub/`, not a bare archive of
`models--*` directories — point it at the latter and there is nothing for the
cache to serve.

**Verify** the cache is actually serving weights:

```sh
# From a node: the store requires the node's own certificate (mTLS on 8443).
PKI=/etc/noo/pki
curl -s --cacert $PKI/ca.crt --cert $PKI/node.crt --key $PKI/node.key https://<controller>:8443/hf/
```

Expect `models--<org>--<name>` entries, or `[]` if the cache holds no models
yet — both mean the layout is right. A **404** now answers with the expected
layout and the `mkdir`/`mv` command that fixes it, rather than looking like a
missing model. Worth doing while you are here: this is the same class of
failure as [C9c](#c9c-host-process-nodes-stop-needing-a-hand-shipped-helper-image)
— a cache that silently serves nothing sends every node to HuggingFace
instead.

#### Verify the door moves

The serve mapping for C9a — check the **mapping**, not the gateway path,
because the mapping is the thing that changed:

```sh
tailscale serve status
```

Expect `/mcp/user` and `/mcp/operator`, and **no `/mcp`**. If `/mcp` is still
listed, run the `off` command above; nothing else removes it.

Then prove the door that should work does:

```sh
curl -sS -o /dev/null -w '%{http_code}\n' \
  -X POST -H 'content-type: application/json' \
  -d '{"jsonrpc":"2.0","id":1,"method":"initialize","params":{}}' \
  https://<controller>.ts.net/mcp/user
```

A JSON-RPC reply, or a 401 if the door is gated — both mean you reached it.
A 404 here means the serve mapping was never written; re-run
`noo onboard --reconfigure`, which *does* write the two current paths even
though it cannot retract the old one.

The old operator listener is gone:

```sh
curl -sS http://127.0.0.1:3100/mcp
# expect: connection refused — nothing listens on 3100 any more
```

A **reply** here means something else has taken the port, which is worth
knowing before you assume it is the gateway.

And the new operator door refuses an anonymous caller:

```sh
curl -sS -o /dev/null -w '%{http_code}\n' --cacert "$NOO_PKI_DIR/ca.crt" \
  -X POST -H 'content-type: application/json' \
  -d '{"jsonrpc":"2.0","id":1,"method":"tools/list","params":{}}' \
  https://127.0.0.1:8080/mcp/operator
# expect: 401
```

Then repeat it with `-H "Authorization: Bearer <your key>"` and expect the
tool catalog. Both halves matter: the 401 proves the credential is mandatory,
and the success proves you did not just break your own access.

Client configs that still name `/mcp/external` or `:3100` need editing too;
the client instructions in
[../../channels/mcp-your-client.md](../../channels/mcp-your-client.md) carry
the current paths.

## Part D — verification checklist

Each row proves one control by making it refuse. A control you have not
watched refuse is a control you are taking on faith.

| # | Control | Probe | Expected |
|---|---|---|---|
| V1 | Chat ingress is default-deny | DM the bot from an unlinked account | The "I don't know who you are" reply quoting your channel id, `channel_ingress_denied` **with that id** in `docker logs noo-gateway`, **and** the matching `noo_security_audit` row. On the walk the row did not land — the audit table was silently dead — so check the row explicitly, and confirm the table is alive first with [C9d](#c9d-the-audit-log-was-silently-dead) |
| V2 | Approvals bind to who asked | As a linked Operator, trigger a HIGH-risk call, then `noo approval pending` | The row names **you** as requester and the conversation; a bare `y` in that same conversation decides it. **Google Chat: verified live on v0.2.39** end to end — card posted, bare `y`, the call ran. **Telegram: retest after v0.2.40** — the notice never reached Telegram at all on v0.2.39, so that half is unproven, not passing; see [C9e](#c9e-the-telegram-approval-notice-never-arrived) |
| V3 | A person is not an agent | Open `/ws/agent` with a User JWT | Refused — at user, operator and admin tier alike |
| V4 | Operator ≠ Admin | As an Operator, `POST /api/security/users` with `scopes: ["admin"]` | **403**, naming both tiers |
| V5 | No unverified TLS lane | `NOO_TLS_INSECURE=1 noo health` | Exit **3**, `tls_untrusted`, and the message names the two fixes (`$NOO_TLS_CA`, `noo security trust-ca`) — setting the variable is an **error**, not a no-op |
| V5b | The anchor is a resolved rung, not an absence | `noo auth status` | A **named** anchor, never "unverified". On an enrolled controller the observed line is `the system trust store (this box is enrolled through /etc/noo/controller-url, which put the mesh CA there)` — that is the platform rung carrying the mesh CA, which is why V5 cannot be probed by unsetting `NOO_TLS_CA` |
| V6 | Per-principal bus credentials | `/connz?auth=1` on `:8222` (https, with the gateway leaf as client certificate) after the shared user is retired | One `authorized_user` per principal (`gateway`, `worker`, `node-<id>`); **no** `noo` |
| V7 | A node refuses a path outside its roots | Set a `models_dir` outside the node's declared roots and reconcile | `reconcile.models_dir_refused` in the node journal, and the refusal on the heartbeat as one operator alert per node per day |
| V8 | Backups refuse without a passphrase | `env -u NOO_AGE_BACKUP_PASSPHRASE scripts/backup-controller.sh` | `REFUSING`, exit 1, and **no files left behind** |
| V9 | The scanner can gate | Plant a CRITICAL (e.g. set `GRAFANA_PASSWORD=changeme`), then `noo security scan` | Exit code **non-zero**. Restore the real value and re-run; exit 0 |
| V10 | Signing key adopted | **Linux:** on the controller, `ls $NOO_PKI_DIR/nodes/*/signing-adopted` — the marker holds the fingerprint the node accepted. **Mac on `noo-cli-v0.5.27` or older:** `noo cluster logs <mac>` and read the agent's own account of the apply | Linux: a marker per node. Mac: `verified-by: signing-key` in the agent's own log. C4 classifies that Mac as **no report** rather than a straggler, and says so in its own words — "has never reported an apply for anything … adoption is UNKNOWN rather than failed". It does not hold the exit code non-zero and it does not gate [C8](#c8-next-release-removals). See the note below |
| V11 | Monitoring holds no gateway key | `docker exec noo-prometheus ls /app/pki/gateway` | `No such file or directory`. Standalone stacks run the monitoring set too since 2026-09-28 (older ones ran no prometheus or grafana — skip there rather than recording a pass for a container that does not exist); promtail is retired |
| V12 | Node work routes are controller-only | Call `/gpu` on a node agent with another node's leaf | Refused; the controller's own call still succeeds |
| V13 | `fetched_at` is evidence, not a guess | With the window closed ([C8](#c8-next-release-removals)): `curl -k -X POST -H 'content-type: application/json' -d '{"sha":"<the staged sha>"}' https://<controller>:8080/bootstrap/bundle/<node>/fetched` | **403**, naming the birth key and the header. Then `GET /api/cluster/provision-bundle/<node>/status` still shows the real `fetched_at` the node stamped |
| V14 | A node-local MCP server is contained | On a node with an entry in `/etc/noo/mcp-servers.json`, remove its `image` and restart the agent | The server does not start; `noo cluster show <node>` carries the refusal naming `image`. `docker inspect noo-mcp-<id>` on a working one shows `CapDrop: [ALL]`, `no-new-privileges`, a non-root `User` and `NetworkMode: none` |

On V6 and V7, read the **server's** answer, not the client's. NATS reports a
permissions violation asynchronously: a denied publish returns success to
the caller and is visible only in `docker logs noo-nats`. A probe that
produces no violation line has not proved a grant is open — it may equally
have never reached the server.

On V9, check the exit code, not the text. `noo security scan` used to return
0 on every path, including the one that printed "N critical issue(s) found".

**On V5, do not probe with a stripped `NOO_TLS_CA`.** That was this page's
first version of the check and it is not a valid one: unsetting the variable
does not leave the CLI with nothing to verify against. `resolve_trust` has
five rungs and the last is the **platform verifier**, so on a controller where
`noo security trust-ca` has put the cluster CA into the system store, a
CA-less call to the tailnet URL verifies through the system store and exits
**0**. That is a verified lane behaving correctly, not a hole — reading it as
a failed probe is how a working control gets "fixed".

What V5 has to prove is that the **unverified** lane is gone, and the only way
to ask for that lane is the retired variable. `NOO_TLS_INSECURE` refuses
loudly and on purpose: an operator who exports it believes verification is
off, and a CLI that quietly verified anyway would be lying in the other
direction. V5b then shows which rung actually answered, which is the question
the stripped-variable probe was reaching for.
## v0.2.40 — the bus principal

> **Retired.** `NOO_CLUSTER_LEGACY_FULL_ACCESS`,
> `NOO_BOOTSTRAP_ACCEPT_UNSIGNED_FETCH` and `NOO_BUS_PRINCIPAL` are no longer
> bridges: their code paths are deleted, and a gateway built with that change
> **refuses to start** while a posture row (or its env) still holds one open,
> naming the key. `noo security posture set <key> <closed value>` — `0`, `0`,
> `required` — is the one write still accepted for them, and clears it. On
> such a build, skip every step below that OPENS one of them.

Everything above takes you onto `stack-v0.2.39`. This section is the next
tag, and it is **separate on purpose**: `NOO_BUS_PRINCIPAL` did not ride into
`v0.2.39`, so an operator already on that tag reads it here rather than
working out which parts of Part A still apply.

This places the bus steps in the release order.

**What changes.** The gateway attaches a signed `Noo-Principal` header to
every `worker.*` NATS message, and the workers refuse a message they cannot
attribute. Until now the bound on `worker.tool.generic` — which reaches
`noo_config_set`, `noo_mint_join_key` and the device tools by name — was
entirely *who may publish*.

**Why the ordering matters more than usual.** The **workers** do the
refusing. A worker recreated onto the new image before the gateway refuses
*everything* — retrieval, knowledge base, recall, heartbeat delegation —
while the gateway publishes unsigned and notices nothing. That is a total
outage of the Python surface for as long as the window lasts. The bridge is
what makes the window harmless, and like the legacy bus bridge in A3 it goes
**on first**.

**The CLI first**, as in B1: `v0.2.40` pairs with `noo-cli-v0.5.28`, and
the controller needs it before E6 — `noo kiosk invite` does not exist in
0.5.27. `noo upgrade --stack` also bakes its paired tag at build time, so
an older binary rolls an older stack.

```sh
noo upgrade --version 0.5.28
noo --version
```

### E1. Bridge on, before you pull the tag

```sh
noo security posture set NOO_BUS_PRINCIPAL optional
noo stack restart
```

Posture is restart-to-apply — it is read at process start, so the restart is
the step, not a tidy-up after it.

**Then verify it on the worker**, which is the process that acts on it:

```sh
docker exec noo-worker printenv NOO_BUS_PRINCIPAL     # -> optional
docker exec noo-trellion printenv NOO_BUS_PRINCIPAL   # -> optional
```

An **empty answer means the gate is at its default, which is `required`**.
Do not deploy on an empty answer — that is the outage above. Check the
posture row landed (`noo security posture list`) and that the restart
actually recreated the container.

### E2. Deploy

```sh
noo stack start --dist --tag stack-v0.2.40
```

While the bridge is on, every unsigned message a worker serves is logged:

```sh
docker logs noo-worker 2>&1 | grep bus_principal.unsigned_accepted | tail
```

That line is the rollout's progress bar. It appears as soon as a new worker
is up and stops once the new gateway is signing. Still seeing it minutes
after the gateway restarted means the gateway is not signing — E3.

### E3. Confirm the gateway is signing

Absence of the line above is a weak signal on its own, so read the gateway's
own:

```sh
docker logs noo-gateway 2>&1 | grep -E 'bus_principal|NOO_CONTROLLER_SECRET' | tail
```

Two lines to act on:

- `NOO_CONTROLLER_SECRET is not set` — the gateway cannot sign at all. Mint
  it and recreate the controller **before** E4; with the gate at `required`
  every worker message would be refused.

  ```sh
  noo security secrets rotate NOO_CONTROLLER_SECRET
  ```

- `publishing with no principal in scope` — a code path lost the caller
  between the request and the publish. The line names the subject. Not a
  blocker (the message is signed as a scopeless internal actor and the
  handlers that need scope will refuse it), but it is a real gap: file it
  with the subject.

### E4. Close it, which is what makes it enforced

```sh
noo security posture set NOO_BUS_PRINCIPAL required
noo stack restart
docker exec noo-worker printenv NOO_BUS_PRINCIPAL     # -> required
```

From here an unsigned `worker.*` message is refused with a reply error and
written to `noo_security_audit`. Watch for refusals that are not an attack:

```sh
docker logs noo-worker 2>&1 | grep bus_principal.refused | tail
```

- `reason=expired` **in bulk** is clock skew between the gateway and worker
  containers, not a replay. The window is ±60 s.
- `reason=missing` after the flip means something is still publishing on the
  old code. Check for a stale image before assuming the worst — the
  `worker.code_source` boot line says which Python is actually running.
- `reason=missing` on **everything**, with a gateway that logs no signing
  error, means the header is not surviving the server. NATS has carried
  headers since 2.2 and the pinned image is far newer, but a server started
  with `no_header_support`, or an operator-supplied older binary, strips them
  silently — the publish succeeds and the subscriber sees no header, which is
  indistinguishable from a gateway that never attached one. Check the
  server's own answer before touching anything else:

  ```sh
  docker exec noo-nats nats-server --version   # >= 2.2
  docker logs noo-nats 2>&1 | grep -i header   # nothing = supported
  ```

**Rolling back** is E1 again. `optional` is a one-release bridge, not a
setting: while it is on, the workers serve messages whose caller they cannot
verify, which is the state §3f R31/R32 describes.

### E5. Verification

| # | Control | Probe | Expected |
|---|---|---|---|
| V13 | The bus refuses an unattributed message | With the gate at `required`, publish to `worker.rag.query` with no header — e.g. `nats pub` with the worker credential, or any client that is not the new gateway | A reply error naming the principal refusal, and a `bus_principal_refused` row in `noo_security_audit`. **Not** a served answer |
| V14 | A tool call reaches the gateway as the user | As a linked User-tier account, trigger a gateway-proxied tool from chat | The gateway's access log attributes the callback to **that account**, not to `mcp-server`; a HIGH-risk call raises an approval row naming them |

V13 is the one worth actually doing. Everything else in this section is a
log line saying a thing did not happen, and the only way to know a refusal
works is to be refused.

### E6. The kiosk display, if you are bringing one up

`v0.2.40` is also the first tag that can serve an unattended display: the
gateway mechanisms, the console half that was missing from `ui/`, and the
host seat all land here. Skip this section if you are not deploying a
display — nothing above depends on it.

The display is a **viewer, not a node**: it runs no node-agent, holds no
node credential, and nothing reconciles it. Do not enroll it.

**On the controller**, once the stack is up:

```sh
noo kiosk invite <display-name>
```

That is the whole controller side. It declares `tag:kiosk` in the tailnet
policy (owners: `autogroup:admin` and `tag:controller`, the same
co-ownership `tag:worker` needs so the OAuth client can mint for it), adds
**two** rules, mints a single-use tagged auth key, and prints the two lines
to paste on the display. Re-running is safe; the policy edits are
idempotent and the auth key is re-minted.

**It issues no service key, and that is the design.** The display stores
nothing durable. To get its 15-minute token it proves it IS the tagged
tailnet device: it serves a nonce on its own tailnet address for the few
seconds a mint takes, and the controller comes to read it. WireGuard
routing means only the true owner of that address can answer, so the nonce
is the proof. Same admission as node enrollment, applied to a viewer.

That is why there are two rules rather than one:

| Rule | What it is for |
|---|---|
| `tag:kiosk → tag:controller:443` | the display reads the page |
| `tag:controller → tag:kiosk:8099` | the controller reads the dialback nonce |

The dialback listener is **ephemeral** — opened for the mint, closed
whether it succeeded or not — and it binds the display's own tailnet
address specifically. A wildcard bind would answer on the local network
too, where no tailnet ACL applies, so `noo kiosk setup` **refuses to mint**
if it cannot resolve that address rather than falling back.

Port 443 is deliberate and it is the only port the rule opens. The display
reaches the gateway through `tailscale serve`, whose certificate is
publicly trusted; the gateway's own `:8080` carries the cluster-PKI leaf,
which Chromium will not trust and cannot be taught to from the OS store.
`noo kiosk setup` refuses a `:8080` URL for that reason. Confirm serve is
actually fronting the gateway before you start:

```sh
tailscale serve status                       # expect / → the gateway
```

**Run `invite` before you tag the display, and not the other way round.**
The order above is not cosmetic. A laptop that joined the tailnet with a
personal login carries a *user* identity, and a tailnet whose policy
grants user devices access to the controller is giving it 443 that way
today. Re-authenticating it with `--advertise-tags=tag:kiosk` **replaces**
that identity: from then on its access is whatever the policy grants
`tag:kiosk`, which is nothing at all until `invite` has written the rule.
Tag first and the display goes dark, with `tailscale ping` still
succeeding — the host is reachable, the port is not.

The same shape explains a confusing reading of this fleet: a **drop** on
443 from one machine while 8080 answers on the same address is an ACL
difference, not a missing listener. A listener that is not there refuses
immediately. Before concluding the serve front is down, re-probe from a
machine on the *other* side of the policy:

```sh
curl -m 5 -sS -o /dev/null -w '%{http_code}\n' https://<controller>.<tailnet>.ts.net/health
```

**On the display** (Linux, a screen, no keyboard):

```sh
sudo apt install cage python3
# Ubuntu ships no .deb Chromium — its `chromium` package is a snap stub,
# and the snap relocates the profile and ~/.pki away from the seat's
# user-data-dir. Google Chrome is the same engine in a real .deb:
wget https://dl.google.com/linux/direct/google-chrome-stable_current_amd64.deb
sudo apt install ./google-chrome-stable_current_amd64.deb

sudo tailscale up --auth-key=<key from invite> --force-reauth --ssh=false
noo upgrade                                  # needs noo-cli >= 0.5.31
noo kiosk setup --mode <dedicated|shared> --url https://<controller>.<tailnet>.ts.net --view health
noo kiosk status
```

There is no key to pass: `--key` and `--key-stdin` are retired and refuse
with a pointer to `service-key revoke` for any key an earlier setup left
behind. `--dry-run` prints every file it would write first — there is no
longer anything in them to mask. `--view graph`, `--rotate <secs>` and
`--browser <bin>` are the other knobs.

**`--mode` is required, and it decides whether this machine is still a
usable computer afterwards.** There is deliberately no default: choosing
it for someone is how a laptop loses its desktop to a dashboard.

| | `dedicated` | `shared` |
|---|---|---|
| The box is | a display, and nothing else | a laptop that also shows a dashboard |
| Terminal | takes tty1 | takes tty8 (`--vt <n>`) — switch with Ctrl+Alt+F8 |
| Display manager | disabled | untouched |
| Console logins | `NAutoVTs=0`, `ReserveVT=0`, and it offers to mask `getty@.service` | untouched |
| Behind the dashboard | nothing | your desktop, protected by its own lock |

Dedicated is the right answer for a screen on a wall. Nothing runs on the
box but the display, so pressing keys at it gets you the display — there
is no session behind it to escape to, and it comes back on its own after
a reboot.

Shared keeps the machine yours. The dashboard is only unattended while
its terminal is the active one, and what protects the desktop behind it
is the desktop's own lock, not anything installed here. Say so out loud
before putting a shared display somewhere the public can reach it.

**The one step that can lock you out.** In dedicated mode, `NAutoVTs=0`
and `ReserveVT=0` stop a login prompt appearing when someone switches
terminals — which is the point, because by default systemd spawns one on
demand and `systemctl list-units 'getty@*'` does not reveal it (the units
do not exist until the switch). Setup then *asks* before masking
`getty@.service`, because if `kiosk.service` later fails to start there
is no console login left. On a box without SSH that is a lockout
recoverable only from installation media. Answer no and the automatic
prompt is still gone; only the deliberate one remains.

`noo kiosk teardown` reverses all of it — unmask, re-enable the display
manager, remove the override — and says so when it does.

**Full-disk encryption.** If the display's disk is LUKS-encrypted, a
power cut leaves it at a passphrase prompt until somebody walks over. For
an unattended screen, either enrol the TPM so it unlocks itself, or
accept that a power cut needs a visit. Enrolling the TPM trades one for
the other: the disk then protects against a stolen drive, not against
someone switching the machine on.

**A display manager on that box is a lock screen nobody can dismiss.** The
seat runs `cage` directly on tty1 as the `kiosk` user; a greeter sitting on
the same tty wins the race on reboot, and a desktop session would idle-lock
over the top of the page. The unit `Conflicts=` it and `setup` disables an
enabled one, but check:

```sh
systemctl is-enabled display-manager.service   # expect disabled/not-found
sudo systemctl restart systemd-logind          # applies the lid/idle overrides
```

**Where the credential lives, and why the browser never sees it.** The
page holds nothing — no token store, no bearer, no storage key. A bearer
token in the DOM of a machine standing in a corridor is extractable, and
"locked in kiosk mode" means no window manager, not no USB port and no
devtools. So `kiosk-serve.service` (`noo kiosk serve`) runs on the
display, mints a 900-second token by tailnet proof, renews it in process,
serves the bundle, and proxies a fixed allow-list of reads with the bearer
attached. **The browser's only hop is `127.0.0.1:8088`** and it never
learns the controller URL.

That proxy is not optional plumbing — it is the only thing that
authenticates. If `kiosk-serve.service` is down, the browser has nothing
to talk to; if its mint is failing, it answers 401 and the page shows
*credential rejected*. `noo kiosk status` reports both, and the proxy
writes its reason to `/var/lib/kiosk/last-error`, which status also
prints.

**What the credential can do**, which is the point of the mechanism: a
`kiosk` JWT is refused on any method other than GET/HEAD/OPTIONS, in
middleware, before dispatch, on **every** path including ones added after
the middleware was written — 403 `read_only`, distinguishable from a 401 so
the page can tell "not permitted" from "logged out". It is also scoped to
the display's own nine reads, so a token lifted off the box reads a
dashboard rather than everything a person can read. The proxy enforces
the same list locally and 404s anything else without forwarding it.
**Revocation is the tailnet device** — remove it from the admin console
and the display can never mint again.

**The cost of this shape is availability, not secrecy**, and it is worth
knowing before you debug it at 2am. A stored key needed only *outbound*
reach to mint. This needs the tailnet working in *both* directions at every
renewal, so a one-way partition, a dropped `tag:controller → tag:kiosk`
grant, or tailscaled restarting on the display all fail a renewal. It fails
dark rather than leaking, which is the trade. The proxy renews two minutes
before expiry, and it is the same process that uses the token, so there is
one place to be wrong about expiry rather than two. A transient failure
keeps serving with the token already held; a sustained one shows
"credential rejected" on the screen and says why in
`noo kiosk status` and `journalctl -u kiosk-serve.service`.

**The browser has no debugging port.** It used to listen on loopback, and
TCP has no file permissions, so any local user on the display could attach,
drive the browser to anything the display's tailnet identity reaches, and
evaluate script in the page. Since 0.6.16 Chrome runs with
`--remote-debugging-pipe` as the child of `noo-kiosk-cdp broker`, which holds
the only end of that pipe. The broker publishes the page's heartbeat and
build to `/var/lib/kiosk/page.json` (world-readable, nothing secret), which
is what `noo kiosk status`, the watchdog and the seat heartbeat read. It
takes one verb, `reload`, on `/run/kiosk/cdp.sock`, and checks each caller
with `SO_PEERCRED`: root, the display user, and on an enrolled seat the seat
user. No raw CDP is offered there, so even an allowed caller cannot navigate
or evaluate.

**What is still soft, stated rather than left to be discovered.** The local
proxy, `noo-kiosk-serve` on `127.0.0.1:8088`, answers the kiosk read list with
the display's token attached for any local user. That is the same scoped,
read-only data the screen shows, but reaching it does not require being the
display user. A browser cannot load a page over a unix socket, so closing
it means checking the uid of a loopback TCP peer. That is not done.

| # | Control | Probe | Expected |
|---|---|---|---|
| V15 | The page is served | `curl -I https://<controller>.<tailnet>.ts.net/kiosk.html` | 200. A 404 with an explanation means the UI artifact predates PR #133 |
| V18 | The browser has no debugging port | On the display: `ss -ltnp \| grep -c 9222`, then `noo kiosk reload` as a user who is not root, the display user or the seat user | `0`, and the reload is refused with `refused: uid N may not drive this display`. A listener means the launcher predates 0.6.16: run `noo kiosk setup` or let the seat restage |
| V16 | The kiosk credential cannot write | Mint a token via `POST /api/kiosk/token`, then `POST` anything with it | 403 `{"error":{"type":"read_only"}}` — **and try a route the middleware never heard of**, which is the control that a per-handler implementation fails years later |
| V17 | The stream is alive, and silence means dead | Watch `GET /api/events/stream` with the token; then stop the gateway | `hello` with `keepalive_ms`, a `: keepalive` comment every 15 s, then the band goes red within 3 × that. A stream that goes quiet without the band reddening is the failure this whole design exists to avoid |

Two known limits at this tag, neither a defect to chase: the graph view is
cluster-level and needs a licensed add-on, so on an
unlicensed install that view is legitimately empty; and
`heartbeat.task.ok` reports schedule state rather than the last run's
verdict, so a silently failing task still reads healthy. Both are known.

## When the gateway is already down

Both of these are **host-level** fixes: they need root or the operator
account on the controller (the database through `docker exec`), never a
shared secret — there is no CLI break-glass any more. Prefer the `noo`
verbs; reach for these only when the gateway will not start and therefore
cannot serve the posture API.

**Down on the retired YAML gate (exit 2).** Remove
`security.exec_approval_mode` from `noomesh.yaml` and restart. The refusal
message names the key and the replacement command. There is nothing else to
undo — posture already outranked the YAML; the key's only remaining effect
was to arm this failure.

**Down on a retired posture bridge.** The bus bridge
(`NOO_NATS_LEGACY_SHARED_CREDS`) no longer exists, so there is no row to
open. What can still stop a gateway is a retired bridge held open
(`NOO_CLUSTER_LEGACY_FULL_ACCESS`, `NOO_BOOTSTRAP_ACCEPT_UNSIGNED_FETCH`,
`NOO_BUS_PRINCIPAL=optional`): it refuses to start and names the key.
`noo security posture set` needs a gateway to talk to, so write the closed
value directly (`0`, `0`, `required` respectively) and restart:

```sh
docker exec noo-postgres psql -U noo -d noomesh -c \
  "UPDATE mesh.noo_security_posture SET value = 'required', updated_by = 'host-sql', updated_at = NOW()
   WHERE key = 'NOO_BUS_PRINCIPAL';"
noo stack restart --force gateway
```

The table lives in schema `mesh` (the gateway's pool pins `search_path` to
`mesh,public,...`, so an unqualified name from `psql` would resolve
somewhere else); `host-sql` in `updated_by` says which door was used. Remove
any `.env` line that still names the key.

## What a fresh install gets

`noo onboard` on a clean machine is born in the state Part A and Part C
converge an existing install to. Each of these is the wizard's own step, not
something the operator does afterwards.

| | What onboard does |
|---|---|
| **Hardened posture** | A `security_posture` step POSTs `{"profile": "hardened"}` to the posture API once the gateway is up — the same route `noo security posture apply-profile` calls. Not a question: every gate in the bundle is the code default or stricter. If the gateway is down it fails loud and prints the exact command; it never reports a success it did not get. It does **not** restart the gateway, which is safe because until the rows take effect the process sits at `strict` — tighter than the `approval` the bundle sets. |
| **Isolated NATS users** | The wizard writes `NATS_GATEWAY_USER=gateway` / `NATS_WORKER_USER=worker`, mints their passwords with the other generated secrets, and renders `users.conf` with no shared user before the stack first starts — so a fresh install has **no shared user on the server at all**. A render failure **aborts** the onboard; its previous behaviour was to warn and continue, which made the outcome of a failed security step a working stack with the security off. |
| **Harness grants** | Not at onboard time, and nothing is missing. The harness subjects live only in the **node** principal's grant, and a fresh controller has no nodes yet — its `users.conf` holds `gateway` and `worker` alone. Each node's grant, harness subjects included, is rendered when that node is provisioned. A fresh install therefore never needs the grant migration in [C2](#c2-the-bus-rollout); an existing one always does. |
| **Backup passphrases** | Both `NOO_BACKUP_PASSPHRASE` and `NOO_AGE_BACKUP_PASSPHRASE` are generated (independently — they are required to differ, or recovery would be circular) and set in the environment. **No plaintext file is written** — that was the old behaviour, and `secrets/age_backup_passphrase.txt` was never removed by anything, so the passphrase protecting the root of trust lived in the clear on every controller. On a console with a terminal the wizard now shows both values once and waits for the operator to confirm they are stored off-box; without a terminal it shows nothing and prints `noo security secrets reveal <NAME>` to run later. A legacy plaintext file is reported and offered for shredding (never shredded silently, and never when the value cannot be found anywhere else). |
| **No Telegram allow-list prompt** | The allow-list prompt is gone. A channel id is declared in one place, the link table, and a second declaration in config is the one that drifts. `TELEGRAM_ALLOWED_USERS` survives in the environment tables only as a retired name read for one release, to print the conversion command. |
| **A real Grafana password** | `GRAFANA_PASSWORD` is a generated 24-byte token. On a **re-run** against an existing install the wizard also repairs a published placeholder — the one path that ever sees such an install again — and tells you that Grafana copied the old value into its own database on first boot, so the env var alone does not change the login. |
| **Monitoring service leaves** | `prometheus` is on the wizard's service-certificate list, so a fresh install issues it its own narrow leaf rather than letting it mount the gateway's key (`promtail` was too, until its retirement). |
| **Encrypted secrets from zero** | The security step runs the real sops bootstrap: it installs `age` and `sops` with no sudo, generates a 0600 age key, encrypts `.env` into `secrets/env.sops`, and the default secrets backend is now `sops` rather than `env`. |

The one thing a fresh install still does not do for you is **link your own
channel identity**. Onboard mints the admin account; it does not know your
Telegram id. Run A1 on a new install too, or the bot refuses you exactly as
it refuses a stranger.

## Related

- [backup-restore-secrets.md](backup-restore-secrets.md) — the two recovery artifacts, the restore drill, passphrase rotation
- [../operator-manual.md](../operator-manual.md) — stack lifecycle, dev vs dist, and why the gateway is not recreated by hand
