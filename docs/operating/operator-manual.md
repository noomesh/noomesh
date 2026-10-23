# Operator manual

The controller is a Docker Compose stack driven entirely by `noo stack`;
the fleet of nodes around it is driven by `noo cluster`. This page is the
day-two reference for the stack: what runs where, how to start, stop,
rebuild and reset it, how add-ons and profiles switch services on, how to
upgrade, and what to check when something is wrong. Prove the stack is up:

```sh
noo stack status && noo health      # every container, then per-dependency gateway health (exit 5 = degraded)
```

Setup itself is [getting-started/install.md](../getting-started/install.md)
and the wizard is `noo onboard`. Adding machines is `noo enroll` (see `noo --help`).

## What runs where

`noo stack start` reads `docker-compose.cluster.yml` (project name
`noomesh`, containers named `noo-<service>`) and brings up the
`controller` profile:

| Service | Container | Published port | What it is |
|---|---|---|---|
| `gateway` | `noo-gateway` | `8080` (HTTPS API, dashboard, WebSocket, both MCP doors) | the Rust gateway: coordinator, inference routing, channels, jobs, heartbeat, autonomy, both MCP doors |
| `worker` | `noo-worker` | — | the slim Python runtime: generic tools, approvals, proactive loop, CRUD stores. Always on |
| `postgres` | `noo-postgres` | `127.0.0.1:5433` | pgvector; the system of record (conversations, knowledge base, node registry, config). Data at `NOO_DATA_ROOT/postgres` |
| `redis` | `noo-redis` | — | job queue, session cache, rate limits, autonomy counters. Reachable only on the internal `noo-db` network |
| `nats` | `noo-nats` | `4222` (clients), `6222` (routes), `127.0.0.1:8222` (monitor) | JetStream bus: node registry KV, gossip, job dispatch, worker subjects |
| `sandbox` | `noo-sandbox` | — | the air-gapped `python_exec` executor; on the `noo-sandbox` network only, no egress |
| `model-cache` | `noo-model-cache` | `8443` (mTLS only) | nginx serving cached model weights to nodes by their own certificate |
| `prometheus` | `noo-prometheus` | `127.0.0.1:9090` | scrapes gateway, node-exporter, nvidia-exporter and node-agents over mTLS |
| `alertmanager` | `noo-alertmanager` | `127.0.0.1:9093` | receives the bundled alert rules (no-op receiver until you configure one) |
| `grafana` | `noo-grafana` | `127.0.0.1:3000` (HTTPS; `NOO_GRAFANA_BIND_ADDR` moves it) | dashboards; open from the console (**Open Grafana**) — noomesh accounts are its only login |
| `loki` | `noo-loki` | — | the log store; every node's agent (the controller's own host agent included) ships container and journal lines through the gateway's ingest route — no container holds the Docker socket |
| `node-exporter` | `noo-node-exporter` | `9100` | host metrics |
| `nvidia-exporter` | `noo-nvidia-exporter` | `9400` | GPU metrics; scaled to 0 automatically when the host has no NVIDIA runtime |
| `node-agent` | — | — | not in the `controller` profile (only the `node-agent-compose` profile): the controller's own agent runs on the host as a systemd service (`noo onboard --only services` installs it), never as a container |

Monitoring is part of the `controller` **and** the `standalone` profile —
every controller runs it, and there is no separate monitoring stack to
start (until 2026-09-28 a standalone install ran it only after
`noo onboard --with-monitoring`, and lost it again on its first
`noo upgrade --stack`). Ports bind to `NOO_BIND_ADDR` (default
`0.0.0.0`) unless listed as `127.0.0.1`; a named instance offsets them
(see [multi-instance](../getting-started/multi-instance.md)).

Three Docker networks separate the planes: `noo-cluster` (everything that
talks to the gateway; created by the launcher, `external` to compose),
`noo-db` (internal; the only network Postgres and Redis answer on, and
only their clients join it: the gateway, the worker, trellion and the
add-ons that use the database) and `noo-sandbox` (internal; the executor's
only link). Postgres also sits on `noo-pg-host`, a bridge that exists only
so Docker can publish its host port. See
[networks-and-containers.md](../security/networks-and-containers.md).

Inference backends (`noo-vllm`, `noo-ollama`, `noo-llamacpp`) are **not**
started by the stack. They are started by a node-agent
when you declare a placement — on the controller host
as much as on a worker.

### Add-ons and opt-in services

| Switch | Where | Adds |
|---|---|---|
| `addons.trellion: true` (default 1) | `noomesh.yaml` | the overlay `docker-compose.trellion.yml` → `noo-trellion`, the knowledge add-on (RAG, memory, graph, recall); composed as a file, no profile. Off: the container is not started and knowledge routes answer 503 with an explanation; `noo health` shows `addons.trellion=disabled` |
| `addons.trellion_intel: true` (default 0) | `noomesh.yaml` | the add-on's own overlay from its signed bundle, `addons/trellion_intel/docker-compose.yml` → `noo-trellion-intel` (extends the trellion service; composed as a file, no profile). `noo addons enable` / `noo addons upgrade` put it there |
| `addons.voice: true` (default 0) | `noomesh.yaml` | the overlay `docker-compose.voice.yml` → `noo-whisper` (STT) and `noo-piper` (TTS); composed as a file, no profile |
| `addons.evolve: true` (default 0) | `noomesh.yaml` | the evolve overlay — `addons/evolve/docker-compose.yml` from evolve's signed bundle, or the dev overlay in a `NOO_EVOLVE_PATH` checkout — composed as a file; no profile |
| `noo stack start --profile <p>` | one-off | an extra compose profile on top of the base: `vllm-secondary`, `ollama`, `llamacpp`, `gpu-tier2`, `monitoring` are additive; any other name *replaces* the base profile |

How the add-ons are licensed and switched on is
[getting-started/add-ons.md](../getting-started/add-ons.md). `tei-compose`
(HuggingFace TEI embedders and reranker) and `sensors` (a second, tier-5
node-agent container) exist in the compose file but no launcher flag
selects them; embeddings resolve through Ollama or a node-agent by default.

### Where configuration lives

Three planes, one home each. Details: [reference/config.md](../reference/config.md)
and [reference/env.md](../reference/env.md).

| Plane | File | Holds |
|---|---|---|
| secrets | `secrets/env.sops` | passwords, API keys, tokens — decrypted by the launcher, never in `.env` |
| config | `noomesh.yaml` (`~/.noo/noomesh.yaml` on a standalone controller — its install root, not `~/.config/noo`) | everything else, including the `addons:` map; `compose_env:` is exported for compose interpolation |
| posture | `noo_security_posture` table | the security gates (`noo security posture …`), restart to apply |
| bootstrap | `.env` | only the flags the launcher must read before secrets exist: `NOO_SECRETS_BACKEND`, `NOO_INSTALL_MODE`, `NOO_DEFAULT_PROFILE`, `NOO_INSTANCE` / `NOO_PORT_OFFSET`, `NOO_IMAGE_TAG`. Add-ons are never `.env` flags — an `NOO_*_ENABLED` var is refused |

`docker compose config` reads `.env`, not what the launcher injects, so it
misleads. Check a container instead:

```sh
docker inspect noo-gateway --format '{{range .Config.Env}}{{println .}}{{end}}' | grep '^NOO_TLS'
```

(The gateway image has no shell, so `docker exec noo-gateway printenv`
prints nothing and looks exactly like "unset".)

## Start, stop, restart

```sh
noo stack start                     # build if needed (dev) or pull (dist), then up -d --force-recreate
noo stack stop                      # down --remove-orphans, plus any node-agent-started backends
noo stack stop --volumes            # also remove volumes
noo stack restart                   # compose restart
noo stack restart --force gateway   # recreate: needed after an env or secret change
noo stack status                    # docker ps for noo-* containers
noo stack logs gateway -f           # one container's logs
```

`start` refuses to run with an empty or placeholder (`changeme`, `admin`, …)
`POSTGRES_PASSWORD`, `NOO_JWT_SECRET`, `REDIS_PASSWORD` or `GRAFANA_PASSWORD`
(the gateway itself refuses to boot without its cluster and controller secrets), checks the
published ports are free, creates the `noo-cluster` network, regenerates
`docker-compose.override.yml` from the `watched_folders` and workspace
sections of `noomesh.yaml`, and — if `noo-ollama` is running — pulls
`OLLAMA_MODEL`. On a GPU host it appends `gpu-tier1` (≥10 GB VRAM) or
`gpu-tier2` (4–10 GB) automatically.

Before any `up`, `start`, `restart --force` and `rebuild` check every
bind-mount source of the services they are about to start. A source that
is missing, or a directory where a file is expected, stops the start
before anything is recreated. Docker would otherwise create each missing
path as an empty root-owned directory, and a container expecting a file
dies with `… is a directory`. The refusal prints one line per path: the
service, the mount target, the host path, what is wrong and the command
that fixes it. The launcher creates nothing itself, except its own
`.*-placeholder` scratch directories.

A plain `restart` keeps the old container environment. Anything that
changes env or secrets (`noo security secrets rotate`, editing
`compose_env`, a new `.env` flag) needs `restart --force` or a fresh
`start`. Do not recreate the gateway by hand with `docker compose`: a
container started outside the launcher runs without the injected secrets.

Do not drive `docker compose` directly for lifecycle: the launcher sets a
`NOO_LAUNCHED` sentinel, layers the right files, and decrypts secrets. A
bare `docker compose up` bakes empty secrets into the containers.

## Dev mode and dist mode

| Mode | `NOO_INSTALL_MODE` | `noo stack start` does |
|---|---|---|
| dev (repo checkout) | absent or `dev` | builds images from `docker/Dockerfile.*` (`--build` forces a rebuild, `--pull` refreshes third-party images) |
| dist | `dist` | layers `docker-compose.dist.yml` last, sets `NOO_IMAGE_PREFIX=ghcr.io/noomesh` (unless already set), pulls the tag (up to three attempts) and never builds |

`noo stack start --dist [--tag vX.Y.Z]` forces one dist run from a
checkout; `--dev` forces a source run on a dist install. The tag ladder is
`--tag` → `NOO_IMAGE_TAG` in the environment → `.env` → the newest local
`stack-v*` git tag; an explicit `--tag` is persisted into `noomesh.yaml`.
A `stack.lock` beside the compose file pins image digests for that tag.

## Rebuild after a code change (dev mode)

```sh
noo stack rebuild                    # deps-core → deps-base → sandbox-base → gateway, node-agent, postgres, trellion (+ voice), recreate, prune
noo stack rebuild gateway            # one service
noo stack rebuild --quick            # just `compose restart gateway` (no image build)
noo stack rebuild --no-cache
noo stack rebuild --background       # hand the build to noo-hostd; follow with rebuild-status
noo stack rebuild-status --follow
```

`--background` needs noo-hostd, the controller-mode user unit `noo
onboard` installs (`systemctl --user status noo-hostd`; reinstall with
`noo onboard --only services`). The same executor runs scheduled
backups, certificate rotation and disk reclaim from the spool. A
background rebuild logs to `.noo-host-spool/<name>.rebuild.log` and refuses `--profile`
and the engine flags. On a dist install `rebuild` builds but refuses to
recreate — upgrade instead.

The gateway needs no host Rust toolchain: in a checkout,
`scripts/cargo-docker.sh check` type-checks it in a container without a
full image build (a development tool; see
[development/developer-guide.md](../development/developer-guide.md)).

## Upgrade

**Standalone controller (no checkout):**

```sh
noo upgrade --check                 # what is newer
noo upgrade                         # the CLI binary itself (GitHub release, checksum-verified)
noo upgrade --stack [--tag vX.Y.Z]  # materialise the paired assets, write stack.lock, noo stack start --dist
noo upgrade --nodes                 # re-provision every pull-capable node with the new agent
noo upgrade --all                   # both
```

After any of the above rolls a node or the stack, `noo cluster verify` is
the post-upgrade health view: it checks every node and the controller
against their invariants (version paired with the release, certificate
state, bus principal, harness state) and names the first thing that does
not hold, rather than leaving you to read `noo cluster status` for a
verdict it does not give.

**Repo checkout:** `git pull`, then `noo stack rebuild` (dev) or
`noo stack start --dist --tag vX.Y.Z` (released images). `noo upgrade
--stack` refuses on a checkout and says so.

After the stack is up, schema migrations run inside the gateway on start;
`noo db status` shows every stamp, `noo db upgrade` applies anything
pending (mesh via the gateway's runner, then trellion's Alembic step).

Roll node agents without touching the stack: `noo cluster upgrade-agents`
(serial `noo cluster provision <node> --wait` — each node's signed bundle
over the pull rail, applied with a health-checked restart). Its old
gateway-signed binary swap is retired.

### Breaking changes to expect on upgrade

Newest first. Anything here changes behaviour on an install that already
works, so read it before you pull.

#### A 0.6.9 Mac node and the 0.6.10 bundle (2026-10-23)

A Mac node still on 0.6.9 cannot take a bundle staged by a 0.6.10 controller:
its applier checks `agent-env` before it hands over to the CLI the bundle
carries, and refuses the two keys 0.6.10 added
(`REFUSED agent-env -- line N sets 'NODE_AGENT_BIND', which is not a key
agent-env is rendered with`, exit 65). The node keeps its previous state, and
`noo cluster verify` keeps saying `host agent v0.6.9`. From 0.6.11 the
controller withholds `NODE_AGENT_BIND` and `NOO_CLUSTER_TOKEN_V1` from a Mac
that reports a CLI older than 0.6.10 (or none), and the Mac applier installs
the CLI a bundle carries before it judges any kind or env key; run
`noo cluster provision <node>` once the node reports 0.6.10 to apply the two
keys.

If your controller is already on 0.6.10, update the daemon's copy of the CLI
on the Mac by hand, then restage. `noo upgrade` in a shell updates only the
shell's copy (`~/.local/bin/noo`); the applier is root's `/usr/local/bin/noo`:

```sh
noo upgrade                                                    # on the Mac: the shell's copy
sudo install -m 755 -o root -g wheel ~/.local/bin/noo /usr/local/bin/noo
/usr/local/bin/noo --version                                   # 0.6.10
noo cluster provision <node> --wait                            # on the controller
```

#### Add-on flags moved out of `.env` (2026-09-04)

**`noo stack start` refuses to run** while `.env` still contains
`NOO_PRO_ENABLED`, `NOO_TRELLION_ENABLED`, `NOO_TRELLION_INTEL_ENABLED` or
`NOO_VOICE_ENABLED`. It prints the block to write and exits 1.

Which add-ons run is now declared once, in `noomesh.yaml`:

```yaml
addons:
  trellion: true
  evolve: true          # if you had NOO_PRO_ENABLED=1
  trellion_intel: true  # if you had NOO_TRELLION_INTEL_ENABLED=1
  voice: true           # if you had NOO_VOICE_ENABLED=1
```

Then delete those lines from `.env`. `noo onboard --only addons` does both
for you and is the shorter path.

**Why a refusal and not a fallback.** Reading the old flag as a default would
leave it in the file as dead text while the map silently decided something
else. For a licensed add-on that means it changing state on an
upgrade, with no message. The one-time stop is the smaller cost.

Two things this fixes:

- The same boolean lived in several places and they could disagree, so an
  add-on could be on in one place and silently unprovisioned in another.
  There is one declaration now.
- `addons: {trellion: false}` was not bootable on a fresh install, because
  the gateway's start-up check required tables that only trellion's
  migrations create. It asks for them only when trellion is enabled now.

A name left out of the map is **not** the same as `false`: it means "not
stated", and resolves to that add-on's own default (trellion on, the licensed
ones off).

## Reset

```sh
noo stack reset                     # clean --deep → noo onboard --skip-services → start
noo stack reset --dist --tag vX.Y.Z # the same, from released images (a fresh-install rehearsal)
noo stack reset --ci --keep-env -y  # non-interactive
```

Reset is destructive and asks you to type `reset`. It ends with the
wizard, so have your answers ready or pass `--keep-env` to keep the
current `.env`.

## Clean

```sh
noo stack clean                     # down, remove project containers, builder cache, dangling images
noo stack clean --volumes           # + named volumes (keeps hf-cache, and postgres/redis unless --deep)
noo stack clean --images            # + the built noomesh/* images (and any legacy-namespace layers still on disk)
noo stack clean --hf-cache          # + the HuggingFace model cache
noo stack clean --deep -y           # everything above, wipes the data root, removes pki/ (after untrust-ca) and the secret files
```

`--deep` is the only clean that touches Postgres data, the PKI and
secrets. Every enrolled node will be stranded on the old CA afterwards;
plan to re-enroll them.

## Backups

Postgres is the system of record; Redis is deliberately not backed up.
The `database_backup` heartbeat task dumps it every six hours through
noo-hostd's `backup` op, and the age key that unlocks `secrets/env.sops` is backed up
alongside it under a separate passphrase. The full procedure — what is
backed up, where it should live, the restore drill, restoring onto a fresh
machine, and `noo migrate export/import` — is
[runbooks/backup-restore-secrets.md](runbooks/backup-restore-secrets.md).
Run the drill monthly:

```sh
~/.noo/scripts/restore-drill.sh     # restores the newest dump into a throwaway container
```

The script ships in the standalone deploy slice under `~/.noo`; from a
checkout, run `scripts/restore-drill.sh` there instead.

## Routine checks

```sh
noo health                          # gateway + postgres/nats/redis + add-ons; exit 5 if degraded
noo cluster status                  # every node: status, bus, load, running backends
noo heartbeat status                # scheduler ticking; noo heartbeat history for failed runs
noo autonomy status                 # self-healing locations enabled
noo logs errors -m 60               # warning/error lines across containers in the last hour
noo security pki status             # days left on every certificate
df -h "$NOO_DATA_ROOT"              # the disk_watermark location alerts at 85%
```

Operator alerts (node offline, quarantine, cert expiry, disk watermark,
failed heartbeat tasks) arrive on your configured channel; the
`noo autonomy locations` command lists every location. Dashboards and metrics: [monitoring.md](monitoring.md).

## Troubleshooting

| Symptom | Check | Fix |
|---|---|---|
| `noo stack start` refuses: "required secret empty" | `noo security secrets audit` | the secret store is missing a key; `noo onboard --only secrets` or `noo security secrets rotate <KEY>` |
| `start` refuses: "REFUSED: N bind-mount source(s) are missing or the wrong type" | the printed lines | run each line's `fix:`. A **missing** file or leaf gets its issuing command, e.g. `noo security pki issue-sso-key` or `noo security pki issue-service <svc>`, or `noo onboard --only enrollment` / `--only storage`. For a **directory where a file is expected** (a ghost from an earlier start), run `sudo rmdir <path>` first and then the issuing command. Start again. |
| a container dies with `read <path>: is a directory` | `ls -ld` the host source of that mount | an earlier start let Docker create the missing file as a directory. `sudo rmdir` it, produce the real file, then `noo stack start`. Since the bind-source check the launcher refuses this case before `up`. |
| `start` refuses: port in use | `ss -ltnp \| grep 8080` | another instance or stray container; `noo stack status`, or run this stack as a named instance with a port offset |
| gateway restarts in a loop | `docker logs noo-gateway --tail 200` | Postgres role password drift (`noo security secrets resync --all`), a missing cert (`noo security pki status`), or a migration failure (`noo db status`) |
| `noo health` exit 5, `nats` or `postgresql` down | `docker logs noo-nats` / `noo-postgres` | `noo stack restart nats`; for Postgres check disk and the data root permissions |
| every container `Exited (255)` after a reboot (WSL2) | `noo doctor docker` | follow the printed recovery, then `noo stack start` |
| knowledge commands answer 503 | `noo health` → `addons.trellion` | `addons.trellion: false` in `noomesh.yaml`, or `noo-trellion` crashed: `docker logs noo-trellion` |
| env change had no effect | `docker inspect <container> … Env` | `noo stack restart --force <service>` — a plain restart keeps the old env |
| a node stopped receiving jobs after NATS was recreated | `noo cluster status` bus column | `noo cluster restart-agent <node>` |
| "No backend available" | `noo cluster status` running column | nothing placed, or a backend in cooldown |
| `noo logs query` says Loki is not configured although `noo-loki` runs | `noomesh.yaml` `services.loki_url` | set it (`https://loki:3100`, the compose network name); the gateway reads `NOO_LOKI_URL` / that key, not the compose-level `LOKI_URL` |
| Grafana refuses the login, or Open Grafana answers 503 | `noo cluster verify --controller` (`grafana door`, `grafana sso`) | Grafana has no password login: open it from the console. A 503 means single sign-on is off — `noo upgrade --stack` fills `GRAFANA_ROOT_URL` |
| Open Grafana shows a certificate error (`ERR_CERT_AUTHORITY_INVALID`) on a tailnet controller | `noo cluster verify --controller` (`grafana door`) | Grafana is published straight on the tailnet IP, or nothing fronts its port. `noo upgrade --stack` adds the `tailscale serve` entry that presents the tailnet's certificate, then moves Grafana to loopback. If the roll warns that the entry could not be written, run the `tailscale serve --bg --https=3000 https://127.0.0.1:3000` line it prints (tailscaled up), then `noo upgrade --stack` again. If the row says the port carries another entry, that entry is yours: noo will not overwrite it |
| Open Grafana fails from another machine on a `local`/`all`/LAN controller | `noo cluster verify --controller` (`grafana door`) | Grafana is on the controller's loopback only. Tunnel first: `ssh -L 3000:127.0.0.1:3000 <you>@<controller>`, then Open Grafana |
| disk full | `noo logs errors`; alerts | the `disk_watermark` location can reclaim Docker space once you opt in |

Emergency stop: `noo stack stop` (or, when the launcher itself cannot
run, `cd ~/.noo && docker compose -f docker-compose.cluster.yml kill` —
the compose file is in the standalone deploy slice; use the checkout
root instead on a dev box).
Crash recovery: check Docker is up, `noo doctor docker`, then
`noo stack start` — a fresh start recreates every container.

## Reference: every `noo stack` verb

| Command | Does |
|---|---|
| `noo stack start [--profile <p>] [--pull] [--build] [--dist] [--dev] [--tag <t>]` | `scripts/noomesh-start.sh` |
| `noo stack stop [--volumes]` | `scripts/noomesh-stop.sh` |
| `noo stack restart [--profile <p>] [--force] [<service>...]` | compose restart; `--force` recreates (`--no-deps` when services are named) |
| `noo stack rebuild [<service>...] [--quick] [--no-cache] [--profile <p>] [--background]` | `scripts/noomesh-rebuild.sh`, or spool it to noo-hostd (`--background`) |
| `noo stack rebuild-status [--follow]` | the newest background rebuild result and log |
| `noo stack status` | `docker ps -a` filtered to `noo-` |
| `noo stack logs [<service>...] [--follow] [--tail <n>]` | `docker logs` for one service, compose logs for several |
| `noo stack clean [--volumes] [--images] [--all] [--deep] [--cache] [--hf-cache] [-y]` | `scripts/noomesh-clean.sh` |
| `noo stack reset [--dist] [--tag <t>] [--ci] [--keep-env] [-y]` | `scripts/noomesh-reset.sh` |
| `noo stack install-watcher` | retired stub: the bash host watcher is gone; noo-hostd runs host commands (`noo onboard --only services`) |
| `noo stack sync-assets` | refresh the standalone deploy slice from the binary's embedded assets |
| `noo stack sandbox up [--fresh] \| status \| run <cmd>... \| rehearse \| down [--keep-data]` | a throwaway docker-in-docker stack, isolated from the live one |
| `noo stack ollama [--container <name>] [<ollama-args>...]` | `docker exec noo-ollama ollama <args>` (default `list`) |

The generated reference for the whole section, including `noo db`,
`noo logs`, `noo config` and `noo heartbeat`, is
[cli/stack-and-data.md](../cli/stack-and-data.md).
