# Setup & host

Covers: what this box is (`whoami`), the setup wizard (`onboard`), joining or leaving a fleet as a worker (`enroll`, `node`, `offboard`), self-update (`upgrade`), host-plane health checks with guided recovery (`doctor`, `health`), moving a controller to another device (`migrate`), warm-standby failover (`controller`), signed bundle inspection (`bundle`) switching optional systems and add-ons on or off (`systems`, `addons`), backups (`backups`) and the display kiosk (`kiosk`).

Does not cover: the Docker stack on this host (`noo stack`), schema migrations (`noo db upgrade` — `noo migrate` moves a controller, NOT schemas), or the fleet of nodes (`noo cluster`).

## Disambiguation

- `noo onboard` sets **this machine** up as a controller; `noo enroll` joins this machine to an **existing** controller as a worker. A box can be both.
- `noo migrate` moves a **controller** to another device (export an archive, import it there). `noo db upgrade` applies pending **schema** migrations to the databases and never leaves the host.
- `noo offboard` tears down a **controller** install to bare prep; the node-side counterpart is `noo cluster teardown-node <node>` from the controller (or `sudo noo-deenroll` on an orphaned node).
- `noo upgrade` updates the **binary** (and, with `--stack`/`--nodes`, the stack and the fleet's agents); `noo stack rebuild` rebuilds **images from source** on a checkout.
- `noo health` asks the **gateway** how its dependencies are; `noo doctor docker` inspects the **Docker daemon** on this host and works when the gateway is down.
- `noo tui` is retired — the web dashboard is the interactive UI and `noo chat` covers the terminal; the command answers with that pointer and exits 1.

## Recipes

Every recipe below runs on the controller unless it says otherwise. The
handlers gate themselves: a controller-only verb run on a node-only box
exits 2 with `wrong_host_role`.

### Find out what this box is

```sh
noo whoami
```

Reads only local markers (`~/.noo/.noo-standalone` or a checkout's `.env`
+ `noomesh.yaml` for the controller side; `/etc/noo/node-name` and
`/etc/noo/controller-url` for the node side). No network, no sudo. Output
is one of:

```
this box: controller + node 'controller-1' (standalone, /home/you/.noo)
this box: node 'worker-1' → controller https://noo-controller.example.ts.net:8080
this box: no install on this box (client-only, fresh, or offboarded)
```

followed by `cli: noo <version>`. On a node-only box it also lists which
groups work here (`cluster status`, `health`, `chat`) and which do not
(`stack`, `offboard`, `controller`). `--json` gives
`{controller, node, label, cli_version}`.

### Set up a controller

```sh
noo onboard                 # interactive wizard
noo onboard --tui           # same wizard, full-screen (needs a TTY)
noo onboard --web           # same wizard in a browser (--port to move it)
noo onboard --ci            # accept defaults and env; never blocks
```

The wizard runs eleven steps in dependency order — prerequisites,
environment, secrets and admin account, Tailscale, PKI and cluster
enrollment, storage, services, first model, channels, add-ons, summary —
and writes: `.env`, the secret store `secrets/env.sops` (the seven minted
secrets: jwt, agent review key, controller secret, cluster secret, redis,
node-agent token, postgres; each NATS principal's password is minted
separately), the cluster CA and gateway cert under `pki/`,
`noomesh.yaml` seeded from `noomesh.yaml.example`, and the storage
subdirectories under `NOO_DATA_ROOT`. It ends with `setup complete`, a
summary block, the endpoints (dashboard, Grafana) and
`You're all set. Welcome to Noomesh!`.

Exit code: `0` only when the wizard completed (or you declined a question
that was yours to answer, such as a LAN-only install). A missing
prerequisite, a failed step or an abort exits `1` with
`onboarding did NOT complete` above it, in `--ci` and interactive runs
alike, so a wrapper can trust the status.

With no repo checkout on the box it switches itself to standalone mode
(`no repo checkout found — onboarding in STANDALONE mode`), materialising
the embedded deploy slice under `~/.noo`; `--standalone` asks for that
explicitly and `--standalone --bundle <url|path>` uses a fetched bundle
(`noo bundle export` makes one) instead of the embedded copy. See
[standalone-controller.md](../getting-started/standalone-controller.md).

Re-running on a configured host is safe: the wizard detects the install,
prints `This machine appears to be already onboarded:` and asks
`Reconfigure this installation?` (default no). `--reconfigure` skips the
question; `--only env,channels` redoes just those sections (valid names:
`prereqs env secrets tailscale enrollment storage services model channels
addons`); `--dry-run` writes nothing and ends `dry run complete — nothing
was changed`. In `--ci` mode, existing postgres/redis/nats data makes the
wizard **refuse** (exit 2) rather than onboard on top of it.

### Check the host after setup

```sh
noo health          # the gateway and its dependencies; exit 5 if degraded
noo doctor docker   # the Docker daemon itself; read-only
```

`noo health` calls `GET /health`, prints `status` and a dependencies table
(`✓ ok`, `✗ down`, `⚠ not reported`) and exits 0 only when the gateway
reports `healthy`/`ok` — otherwise 5, with a guide (`noo stack status`,
`noo stack logs <dep>`). `noo doctor docker` looks for the unclean-shutdown
damage signature (ghost container records, empty names, `Exited (255)`
rows); a clean daemon prints `no unclean-shutdown damage signature` and
exits 0, a damaged one prints the recovery recipe and exits 1. It never
changes anything.

### Join this machine to a fleet

On the controller, mint a token bound to the node's name:

```sh
noo cluster bootstrap-token create --node gpu-2
```

It prints a one-liner. Paste that on the node — it is the only `sudo` the
node ever needs. The three forms `noo enroll` accepts are the blob the
one-liner carries (`noo enroll noo1.<base64>`), an explicit
`--url <controller> --token <t>`, and `--via-tailnet <https://controller>`
(no token: identity is proved by Tailscale `whois` plus a dial-back). The
command installs Tailscale if needed, registers with `POST
/api/cluster/bootstrap`, prints `registered as gpu-2`, installs the
host prep (agent, fetch timer, CA anchor at `/etc/noo/pki/ca.crt`; no
controller SSH key goes in, and a gate-pinned key line or SSH-lane sudoers
drop-in left by an older enrollment is removed), and ends `enrollment complete`. Then on
the controller run `noo cluster provision gpu-2 --wait` — see
[fleet.md](fleet.md#enroll-a-node-end-to-end).

A machine already anchored to a **different** mesh is refused before the
token is burned (`this machine is already enrolled in a DIFFERENT mesh`,
exit 78). On macOS the agent arrives through the `net.noomesh.fetch`
LaunchDaemon, which runs `noo node fetch` every minute; `noo enroll
--resume` re-runs only that arming step. `noo node fetch` refuses to run on
Linux (nodes there use the systemd `noo-fetch` timer).

### Upgrade

```sh
noo upgrade --check          # report current vs latest; change nothing
noo upgrade                  # swap the binary (verifies the .sha256 and the release signature)
noo upgrade --stack          # then move a standalone controller's stack to the paired release tag
noo upgrade --nodes          # then restage every pull-enrolled node's agent bundle
noo upgrade --all            # binary + stack + nodes, waiting for gateway health in between
```

The binary swap prints `noo upgraded 0.3.9 → 0.3.11` (or `no change: noo
… is already current`), then re-execs the **new** binary for anything
after it, so `--stack` always uses the new release's assets and its baked
stack tag (`--tag vX.Y.Z` overrides the pairing). `--stack` manages
standalone installs only; on a checkout use `noo stack start`/`rebuild`.
`--nodes` ends `bundles staged for all N node(s) — each applies on its next
fetch tick`. An enrolled node upgrades its own binary from the controller's
mirror (`/bootstrap/cli`), so nodes need no GitHub access. Private release
assets are fetched via `NOO_CLI_BASE_URL` (a mirror), `gh` on `PATH`, or a
`GH_TOKEN`/`GITHUB_TOKEN` token, in that order; if the install directory is
root-owned, re-run with `sudo` or set `NOO_INSTALL_DIR`.

`noo upgrade --controller` is for a checkout: it rebuilds the controller's
own host daemons (node-agent, hostd) and installs only what changed.

### Switch an add-on on

```sh
noo addons list
noo security entitlement install <token>     # licensed add-ons only
noo addons enable evolve
noo stack restart --force                    # applies it (a plain restart keeps the old env)
```

An add-on's switch is the `addons:` map in `noomesh.yaml`, never an env
flag. `noo addons enable <name>` does the whole job in order: plans the
add-on's gateway key, mints its absent credentials into the sops store,
issues the key if none is active, and only then declares it ON, so a
refusal leaves `noomesh.yaml` untouched; nothing restarts until you do.
`addons disable` declares it OFF. `noo systems` is the lower-level half:
the `systems:` block of `noomesh.yaml` declares which database-extending
systems exist (trellion, mandatory; evolve, which follows `addons.evolve`
and needs a licence). `systems status` shows each system's state, gate and
whether its credentials exist in `secrets/env.sops`; `systems enable
<name>` only mints the **absent** credentials (an existing role is never
rewritten; a licensed system without an installed entitlement is refused
with `noo security entitlement install <token>`) and does **not** switch an
add-on on; `--dry-run` previews both verbs. `systems disable` clears intent
only — role, schema and rows stay. The gateway provisions the role and
schema on its next boot. See [add-ons.md](../getting-started/add-ons.md).

### Move the controller to another device

On the old box:

```sh
noo migrate export -o noo-migrate.tar.gz.enc
```

Needs a running postgres container (it takes a fresh `pg_dump`) and the
age key. The archive carries `.env`, `.sops.yaml`, `noomesh.yaml`,
`secrets/`, the full `pki/` including `ca.key`, the age key, the dump and a
manifest — not models, caches, images or the tailnet device identity. It is
AES-256 encrypted with a passphrase (`--passphrase-file`, or a hidden
double prompt), self-verified, and ends `migration archive sealed (N MB)`
with the reminder that workers stay trusted because the CA travels.

On the new box, with the binary installed:

```sh
noo migrate import noo-migrate.tar.gz.enc --passphrase-file pass.txt
```

`import` hands over to `noo onboard --from-archive`, which opens the
archive before touching anything, installs the age key (refusing if a
different one is already there), pre-fills secrets, config and PKI where
nothing exists yet — live files always beat the archive — and restores the
database during the services step. `--data-root` seeds the storage step.
See [backup-restore-secrets.md](../operating/runbooks/backup-restore-secrets.md).

### Fail over to a warm standby

The failover mechanism is the stable Tailscale role name `noo-controller`:
nodes are pinned to it, so whichever host holds the name is the controller.
On the standby (which must already be an install):

```sh
noo controller promote --restage-nodes
```

It claims the name (`sudo tailscale set --hostname=noo-controller`; if the
old controller still holds it you get `could not claim … — is the OLD
controller still holding it?`), re-issues the gateway cert for the new
MagicDNS name and IP, rewrites the gateway URL in `.env` and
`noomesh.yaml`, rebinds `tailscale serve`, restarts the gateway and — with
`--restage-nodes` — re-provisions each inventory node; without it, nodes
reconverge on their own because they follow the role name. On the old
controller, `noo controller demote` releases the name back to the
hostname, resets `tailscale serve`, and leaves the stack running as the new
warm standby.

### Leave the fleet or retire a controller

```sh
noo offboard --check     # read-only audit: exit 0 fresh, 1 leftovers
noo offboard             # confirms each step
noo offboard -y --purge-secrets --uninstall
```

`offboard` works on standalone installs (a checkout's controller state is
retired to a dated `~/noo-backups` directory instead). It warns if the
gateway still lists worker nodes, then walks: stop the self-heal daemons;
remove the stack (containers **and volumes — all data**), pulled images,
host daemons and `/etc/noo/pki`, the storage root, the CA from the OS
trust store, the Tailscale serve config and identity, and the standalone
home. The age key is kept unless `--purge-secrets`; the binary and shell
completion stay unless `--uninstall`; `--keep-tailnet` leaves the machine
on the tailnet. It ends with a silent re-audit and `offboard complete`.

## Related guides

- [../getting-started/install.md](../getting-started/install.md) — install the binary, first run
- [../getting-started/standalone-controller.md](../getting-started/standalone-controller.md) — a controller from the binary and Docker alone
- [../getting-started/add-ons.md](../getting-started/add-ons.md) — the optional systems `noo systems` switches on
- [../getting-started/multi-instance.md](../getting-started/multi-instance.md) — several stacks on one host
- [../operating/runbooks/backup-restore-secrets.md](../operating/runbooks/backup-restore-secrets.md) — what `noo migrate export` seals and how to restore it
- [../operating/operator-manual.md](../operating/operator-manual.md) — day-to-day operation and troubleshooting

## Command reference

<!-- BEGIN GENERATED: cli-reference section="Setup & host" — do not edit; regenerate with scripts/gen-cli-docs.py -->
### `noo whoami` — What this box is: controller, node, both, or client-only
| Command | Arguments | What it does |
|---|---|---|
| `noo whoami` | — | Report what this box is: controller, node, both, or client-only |

### `noo onboard` — Setup wizard
| Command | Arguments | What it does |
|---|---|---|
| `noo onboard` | `[--tui\|--web [--port <n>]] [--non-interactive\|--ci] [--dry-run] [--reconfigure] [--standalone [--bundle <url\|path>]] [--from-archive <f> [--passphrase-file <f>]] [--only <sections>] [--skip-tailscale] [--skip-security] [--skip-storage] [--skip-services] [--skip-trellion] [--skip-model] [--skip-channels] [--mcp-door\|--no-mcp-door] [--skip-addons] [--secrets-backend sops]` | Run the setup wizard to bootstrap a controller (secrets, PKI, .env, compose, model) |

### `noo enroll` — Join this machine to a noomesh fleet as a worker
| Command | Arguments | What it does |
|---|---|---|
| `noo enroll` | `<noo1.blob> \| --url <u> --token <t> \| --via-tailnet <u> [--ca-sha256 <hex>] [--ts-authkey <k>] [--node <name>] [--skip-tailscale] [--skip-prep] [--data-root <dir>] [--resume]` | Enroll this machine as a worker of the given controller |

### `noo offboard` — Leave the fleet: stop the agent, remove enrollment state (confirms)
| Command | Arguments | What it does |
|---|---|---|
| `noo offboard` | `[--check] [-y\|--yes] [--keep-tailnet] [--purge-secrets] [--uninstall]` | Tear a standalone controller down to bare prep; destructive, confirms each step (-y) |

### `noo upgrade` — Self-update the CLI; --stack/--nodes/--controller roll the rest
| Command | Arguments | What it does |
|---|---|---|
| `noo upgrade` | `[--check] [--version <X.Y.Z>] [--stack] [--nodes] [--all] [--tag <vX.Y.Z>] [--controller] [--allow-unsigned] [--force] [--skip-gateway-key-check] [--stage2] [--channel <public\|rollback\|custom>] [--release-repo <owner/repo>] [--image-prefix <registry/path>] [--base-registry <registry/path>] [--yes]` | Self-update noo, optionally stack and nodes; --channel moves release channel |

### `noo doctor` — Host-plane health checks with guided recovery
| Command | Arguments | What it does |
|---|---|---|
| `noo doctor docker` | — | Detect unclean-shutdown docker damage (ghosts, empty names) and print recovery |
| `noo doctor privileges` | — | Report standing power on this box: sudoers drop-ins, gate binaries, SSH keys |
| `noo doctor orphans` | — | Report containers compose still runs that no compose file declares |
| `noo doctor secrets` | — | Report containers running a secret value that .env has moved past |
| `noo doctor exposure` | — | Report which published ports are reachable from outside the tailnet |
| `noo doctor strangers` | `[--minutes N]` | Gateway callers the tailnet does not account for, and any caller in a refusal storm |

### `noo health` — Gateway health probe
| Command | Arguments | What it does |
|---|---|---|
| `noo health` | — | Probe gateway /health and report per-dependency state; exit 5 if degraded |

### `noo migrate` — Move this controller to another device (export/import; NOT schema migrations)
| Command | Arguments | What it does |
|---|---|---|
| `noo migrate export` | `[-o <file>] [--passphrase-file <f>]` | Seal controller state (secrets, age key, PKI, env, pg_dump) into one archive |
| `noo migrate import` | `<archive> [--passphrase-file <f>] [--data-root <dir>]` | Forward to `noo onboard --from-archive <f>` to restore a controller from an archive |

### `noo controller` — Warm-standby failover: promote/demote via the stable role name
| Command | Arguments | What it does |
|---|---|---|
| `noo controller promote` | `[--name <n>] [--restage-nodes] [-y\|--yes]` | Claim the controller role name on the tailnet, re-issue cert and restart gateway |
| `noo controller demote` | `[--name <hostname>] [-y\|--yes]` | Release the controller role name back to the machine hostname and reset serve |

### `noo bundle` — Signed bundle inspection
| Command | Arguments | What it does |
|---|---|---|
| `noo bundle export` | `<out.tar.gz>` | Write the embedded standalone deploy slice as a bundle plus .sha256 sidecar |

### `noo systems` — Enable/disable optional systems (mints their secrets into sops)
| Command | Arguments | What it does |
|---|---|---|
| `noo systems status` | — | Show each manifest system's enabled state and whether its credentials exist |
| `noo systems enable` | `<name> [--dry-run]` | Enable a database-extending system and mint its credentials if absent |
| `noo systems disable` | `<name> [--dry-run]` | Clear a system's enable intent; keeps its role, schema and data |

### `noo addons` — Which add-ons this install runs — the `addons:` map, without opening the file
| Command | Arguments | What it does |
|---|---|---|
| `noo addons list` | — | Show every add-on: declared, effective and whether the licence grants it |
| `noo addons enable` | `<name> [--force]` | Mint an add-on's absent credentials and key, then declare it ON; restart applies it |
| `noo addons disable` | `<name>` | Declare an add-on OFF in noomesh.yaml; restart applies it |

### `noo kiosk` — The unattended display's host seat: cage + Chromium showing /kiosk.html
| Command | Arguments | What it does |
|---|---|---|
| `noo kiosk invite` | `<display-name> [--expiry-minutes <n>] [--url <https://…ts.net>]` | Controller: tag:kiosk, its two rules, a tagged auth key, the display's commands |
| `noo kiosk labels` | `on\|off\|status` | Controller: entity names on the kiosk graph (kiosk.graph_labels; audited, no restart) |
| `noo kiosk reload` | — | Reload the page on the display and report the console build either side |
| `noo kiosk serve` | `[--port <n>]` | Hidden: the display's local proxy, run by kiosk-serve.service (internal) |
| `noo kiosk setup` | `--mode dedicated\|shared --url <https://…ts.net> [--vt <n>] [--user <name>] [--view health\|graph] [--rotate <secs>] [--poll <secs>] [--quality lean\|full] [--browser <bin>] [--dry-run] [-y\|--yes]` | Install the display seat: kiosk user, cage + Chromium unit, token launcher, watchdog |
| `noo kiosk status` | — | Report the seat: units, mint, expiry, heartbeat, graph labels (no privilege needed) |
| `noo kiosk teardown` | `[-y\|--yes]` | Remove the seat's units and files; keeps the kiosk user; asks for confirmation (-y) |

### `noo backups` — Where backups go — and whether anyone has decided
| Command | Arguments | What it does |
|---|---|---|
| `noo backups status` | — | Where backups go, how many there are, and whether an off-site copy was ever decided |
| `noo backups setup` | `[--set <ssh:…\|dir:…\|s3:…\|portable\|none>]` | Decide where a copy of each backup goes; asks unless --set is given |
<!-- END GENERATED -->
