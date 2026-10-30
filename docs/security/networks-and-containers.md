# Networks and container hardening

What each Docker network carries, who may reach the database and the cache,
and which hardening the long-running controller containers run under.

## Networks

| Network | Internal | Members | Purpose |
|---|---|---|---|
| `noo-cluster` | no (external to compose, created by the launcher) | gateway, worker, trellion, the bus, the inference backends and their stunnel doors, the monitoring images, `model-cache` | everything that talks to the gateway |
| `noo-db` | **yes** | `postgres`, `redis`, and their clients: gateway, worker (and `worker-extra`), trellion, and the add-ons that use the database (trellion-intel, evolve) | the only network Postgres and Redis answer on |
| `noo-pg-host` | no | `postgres` only | lets Docker publish Postgres' host port |
| `noo-sandbox` | **yes** | gateway, worker, trellion, `sandbox` | the code-execution link, no egress |
| `noo-browser` | no | gateway, worker, trellion, `browser` | the headless browser, which has to reach the web |

### Postgres and Redis are on `noo-db` only

A container on `noo-cluster` that is not a database client has no route to
`postgres:5432` or `redis:6379`. That matters because `noo-cluster` holds
software that parses untrusted input (inference backends reading model files,
nginx, the monitoring images, tool code in the worker): a compromise of one of
them reaches the database only if it can open a connection, and it cannot.
The TLS client-certificate requirement and the role passwords stay in front of
the database as before; the network is what keeps a leaf stolen from another
container from being tried against them.

`noo-db` is `internal: true`, and Docker does not publish a port for a
container attached only to internal networks. Postgres' host publish
(`127.0.0.1:5433`, or `POSTGRES_BIND` for a warm standby) therefore goes
through `noo-pg-host`, a bridge that holds Postgres and nothing else.
Redis publishes no port.

`tests/test_db_networks_are_isolated.py` holds the member list. Adding a
service to `noo-db` is a reviewed edit of that file.

### Each role is reachable only with its own certificate

Every TCP client needs a certificate from the cluster CA **and** its role
password, and for every role this stack's own containers connect as, the
certificate's CN must also **be that role**. Each such role has its own client
leaf, `CN=<role>`, kept inside the directory its container already mounts:

| Role | Presented by | Leaf |
|---|---|---|
| `noo`, `noo_app` | gateway | `gateway/pg/<role>.crt` |
| `noo_app` | worker, `worker-extra` | `services/worker/pg/noo_app.crt` |
| `noo_app`, `noo_trellion`, `noo_trellion_ddl` | trellion | `services/trellion/pg/<role>.crt` |
| the same three | trellion-intel | `services/trellion-intel/pg/<role>.crt` |

`docker/postgres/pg_hba.conf` matches each of those roles with
`scram-sha-256 clientcert=verify-full`: with `scram-sha-256`, Postgres then
requires the certificate's CN to equal the database role being asked for, and
the password is still required (a `map=` with the `cert` method would have
dropped it). So the gateway's own leaf logs in as no role at all, `noo_app`'s
leaf cannot log in as `noo`, and a stolen role leaf alone reaches the password
check for **its one role**. Checked against a real Postgres by
`tests/test_postgres_role_identity.py`. A CN mismatch is logged by Postgres
as `password authentication failed for user "<role>"` with a `DETAIL` naming
the `verify-full` line it matched; `noo cluster verify --controller` →
`postgres role identity` and `noo security scan` → `Postgres Role Identity`
name the role and the half (leaf or rule) that is missing.

Two other tiers precede and follow the per-role lines:

- A connection from one of the server's **own** addresses (`samehost`, a
  process inside the postgres container) needs a cluster-CA certificate and
  the password but not a role-named one. `noo security secrets rotate|audit`
  proves a rotated password by logging in as the role from inside the
  container with the server's own leaf; the same process can already use the
  `local` socket rule, and a peer on `noo-db` arrives from its own address,
  not the server's.
- Roles whose clients live in **other repos** (`noo_evolve`, `noo_evolve_ddl`
  in the evolve add-on) and the warm standby's `replicator` keep
  `clientcert=verify-ca`: any cluster-CA leaf reaches their password check
  until their repos present a leaf named for the role and get a per-role line.
  The network above stays the control for those.

**Upgrade.** `noo upgrade --stack` issues the role leaves before it moves
anything (`-1c`) and refuses the roll if one cannot be issued ("nothing was
changed"); `noo stack start|restart|rebuild` does the same before the
launcher; `noo onboard` issues them with the other leaves. The new
`pg_hba.conf`, the compose DSNs and the leaves therefore arrive together; the
running stack keeps its old rules until it is recreated.

The `local` (unix socket) rules stay `trust`: the socket exists only inside
the container, the backup script, `noo security secrets rotate` and the
health check connect over it as the role `noo` from an OS user that is not
named `noo` (so `peer` would refuse them), and first initialisation runs
before any role exists. Reaching it takes `docker exec`, which is
root-equivalent on the host already.

## Backend doors

Every inference backend sits behind a stunnel sidecar that requires a client certificate from the cluster CA
(`verify = 2`) and pins the peer by the DNS name in its leaf (`checkHost`):
only the gateway, worker, trellion, trellion-intel and evolve leaves pass the
handshake, so a node's or a monitoring container's certificate is refused.
The backend runs in its door's network namespace and listens on 127.0.0.1
only, so the door is the only way in. vLLM (`vllm`, `vllm-secondary`) served
TLS itself until it moved behind `stunnel-vllm` / `stunnel-vllm-secondary`,
as the node agent's vLLM did in door generation 5: each door joins
`noo-cluster` under the engine's names (`vllm`, `noo-vllm`), so every caller's
URL stays `https://noo-vllm:8000`. That own listener admitted any cluster-CA
leaf.

The ollama, ollama-embed, ollama-embed-cpu, llamacpp and both vLLM doors are also dialled
by the controller's own node-agent with its **node** certificate, whose only
distinguishing name is the controller's node id. stunnel cannot match
organisation, and a static file cannot list the id, so those doors append
`checkHost = $NODE_ID` at start (the `stunnel-self-pin` entrypoint in
`docker-compose.cluster.yml`). If `NODE_ID` is unset, `auto` or not a plain
node name the door **refuses to start** (exit 78) and says to set it in `.env`;
it never falls back to accepting any cluster certificate, and never starts
silently locking the host agent out. Pinned by
`tests/test_stunnel_door_pinning.py`, which runs the entrypoint.

The controller's stunnel doors and `nvidia-exporter` run as the unprivileged
uid 65532 (`USER nonroot` in `docker/Dockerfile.stunnel` and
`docker/Dockerfile.nvidia-exporter`, `user: nonroot` in compose, a name rather
than a number because Docker 27 resolves the string by name); their
leaf keys are `0640` handed to that uid like every other non-root service
(`SERVICE_KEY_READERS` in `noo-cli/src/pki.rs`). Doors a **node's** agent
starts keep running as root with a root-owned `0600` copy of their leaf: the
agent sets `User: "0"` on them explicitly.

## Container hardening

| Service | `cap_drop` | `no-new-privileges` | Read-only root filesystem |
|---|---|---|---|
| `sandbox`, `sandbox-extra` | ALL, plus `SETUID`, `SETGID` and `KILL` for the launcher (below) | yes | yes (tmpfs `/tmp` 100m, `/run` 10m) |
| `gateway` | ALL | yes | yes (tmpfs `/tmp` 512m, `/home/nonroot` 64m) |
| `worker`, `worker-extra` | ALL | yes | yes (tmpfs `/tmp` 256m, `/home/nonroot` 64m) |
| `trellion` | ALL | yes | yes (tmpfs `/tmp` 1g, `/home/nonroot` 256m) |
| `stunnel-*` (the nine backend doors) | ALL | yes | yes (tmpfs `/tmp` 16m; non-root) |
| `llamacpp` | ALL, plus the agent's backend set (below) | yes | yes (tmpfs `/tmp` 64m; non-root in the image) |
| `vllm`, `vllm-secondary`, `ollama`, `ollama-embed`, `ollama-embed-cpu`, `tei`, `tei-gpu`, `reranker`, `airllm` | ALL, plus `CHOWN`, `DAC_OVERRIDE`, `FOWNER`, `SETGID`, `SETUID` (the node agent's backend set) | yes | no (below) |

**Backends that keep a writable root, and why** (measured with `docker diff`
on running containers, awolf, 2026-10-28):

- `vllm`: runs as root and writes `/tmp` (torch inductor, cutlass), `/root/.nv`
  (CUDA compute cache), `/root/.triton` (kernel cache) and `/etc/ld.so.cache`
  (the GPU runtime at start). Read-only needs those as tmpfs or a cache
  volume, and a test that the NVIDIA runtime still starts on a read-only
  root; non-root needs the Hugging Face cache owned by that user.
- `ollama` (all three): writes its model store under `/root/.ollama` (a
  volume) as root; non-root needs the volume re-owned and `HOME` moved.
- `tei`, `tei-gpu`, the TEI `reranker`: write the model cache under `/data` as
  root; same re-own as Ollama.
- `airllm`: a local build, not measured.
- The node agent's own doors run as root (not the image's non-root user) to
  read the node's root-owned `0600` service key with `DAC_OVERRIDE`; they are
  read-only except on the `alpine` fallback image, which installs stunnel at
  start.

The gateway, the worker and trellion run as an unprivileged user, bind ports
above 1024 and use no capability, so dropping all of them removes nothing they
need.

### The sandbox executor user

The sandbox is the one service that runs code it does not trust, so the code
and the server are two different uids. The container starts as root only for
its first instruction: `setpriv` keeps `CAP_SETUID`, `CAP_SETGID` and
`CAP_KILL` as ambient capabilities and execs uvicorn as `sandbox-server`
(uid 65590); no root process remains. Each `python_exec` call is then launched through `setpriv`
again into one of 64 executor uids (`sandbox-exec`, 65600 and up, one per
concurrent call) with every capability cleared, in both isolation modes. What
that buys, measured in the image on 2026-10-21:

* the code cannot read the sandbox's own leaf key, which is `0640` and
  sandbox-server's (`cat: Permission denied`), so it cannot present the sandbox's
  identity to anything on `noo-sandbox`;
* it cannot signal the server or another call (`kill: Operation not
  permitted`), and `ptrace` across uids needs a capability it does not have;
* it cannot return to either uid (`setresuid failed: Operation not
  permitted`), and `no-new-privileges` stops a file capability from granting
  anything at exec;
* a call that times out is killed by process group and then by uid, which
  reaches a snippet that left the group with `setsid()`; `RLIMIT_NPROC` is
  the call's own, so a fork bomb in one call starves no other;
* the scratch directory is made by the executor (0700) and removed as the
  executor; the server never hands the code a directory it owns.

A non-root process keeps no effective capability, so without this launcher
the `cap_add` lines were inert and the code ran as the server. `/health`
reports the executor under `executor`; a null uid means the image has no
`sandbox-exec` user or the container was started without the launcher, and
the code runs as the server's uid as it did before.

The server's uid is its own: no other service runs as 65590. Docker without
userns-remap counts `RLIMIT_NPROC` per real uid across the whole host, so the
sandbox's `nproc: 256` bounds its own threads only while nothing else shares
the uid. Through 0.6.11 the server ran as `nonroot` (65532) beside redis, the
monitoring set, the voice doors, stunnel and the Python services; on a busy
controller those held 256 threads between them, every thread the server
tried to start failed (`can't start new thread`), and `/health` answered
500. `/health` reports the server's uid under `server`, and `noo cluster
verify --controller` fails the `sandbox executor` row when it is not 65590
or when `/health` answers 5xx. An upgrade hands the existing sandbox key from
65532 to 65590 in the same mode pass it runs before the launcher (`noo
security pki fix-modes` on demand): by ACL or group as the operator, through
`sudo -n` when that is all that can, and loudly, never quietly, when neither
can.

#### AppArmor on Ubuntu 24.04 and later

Docker's `docker-default` profile denies every mount in a container, and on
hosts that restrict unprivileged user namespaces through AppArmor it denies
the user namespace too. Bubblewrap needs both, so under `docker-default` on
such a host every call fails ("No permissions to create new namespace",
"Failed to make / slave") and `/health` reports the isolation as unusable. The
stack ships `docker/apparmor-noo-sandbox`: `docker-default` verbatim, with
`userns,`, `mount,` and `pivot_root,` in place of `deny mount,` and nothing
else loosened (pinned by `tests/test_sandbox_apparmor_profile.py`). On a
host whose active LSM is AppArmor (`/sys/kernel/security/lsm`, not the
distribution name), `noo onboard`'s services step installs it into
`/etc/apparmor.d/noo-sandbox`, loads it and sets
`NOO_SANDBOX_APPARMOR=noo-sandbox`, and fails the run loudly with both
commands when sudo cannot; on SELinux and LSM-less hosts it installs
nothing; the mounts a call makes stay inside its
own user namespace, since the container holds no `CAP_SYS_ADMIN`.
`unconfined` remains only for a parser older than 4.0, which cannot load
the `userns,` rule. The `sandbox executor` row of `noo cluster verify`
fails, with that install as its remedy, whenever the sandbox reports that
its isolation cannot run.

#### No /proc inside the per-call jail

Docker masks paths under every container's `/proc` (`/proc/kcore`,
`/proc/keys` and others with `/dev/null`; `/proc/sys`, `/proc/irq` and
others read-only). Inside a call's new user namespace those mounts are
locked, and the kernel then refuses a fresh procfs (no procfs in the mount
namespace is fully visible). Through 0.6.13 the jail asked for one
(`--proc /proc`), so with the AppArmor profile in place every call still
failed, with "Can't mount proc on /proc: Operation not permitted" (pop-os,
2026-10-26). The jail now mounts no `/proc` at all and keeps every
namespace. The other ways out were each worse:

- binding the container's `/proc` shows the code this server and the other
  calls;
- `systempaths=unconfined` lifts the masks for the server too;
- no capability helps, because the refusal does not depend on one.

Code in the jail therefore has no `/proc/self/*`, `/proc/meminfo`,
`/proc/cpuinfo`, `/dev/fd` or `/dev/stdin`. Reading one fails with a plain
`FileNotFoundError` naming the path, and the sandbox adds one line under
the traceback saying there is no `/proc`. `os.cpu_count()`,
`os.sched_getaffinity(0)` and the `resource` module still answer.

Before the first call the sandbox runs a self-test inside the jail. It
checks that the code is in its own PID namespace, sees loopback alone,
cannot see the server's process or `/tls`, runs as its executor uid and
starts in `/work`. `/health` reports the facts under
`isolation.self_test`, and the mode is usable only when they pass.

### Read-only root filesystem

Since 2026-10-19 the four services above cannot write to their image. The
write set was measured, not guessed: `docker diff` on the live controller
listed, outside mounts, only

* a copy of the PKI tree under `/tmp/pki` (the gateway's `stage_pki`, and the
  leaf-key copy `db/engine.py` makes in the worker and trellion), the CA
  bundle `/tmp/noo-ca-bundle.pem` and the mount points of the dev-mode source
  overlays: all under `/tmp`;
* `/tmp/.ses` and the onnxruntime id and event store under
  `~/.cache/Microsoft` in trellion (the latter is vendor telemetry and is
  switched off, [telemetry.md](telemetry.md));
* Python bytecode under `/app/src/**/__pycache__`.

Each service gets a size-capped tmpfs for `/tmp` and for its home directory
(`/home/nonroot`, owned by uid 65532, mode 0700). The caps bound host RAM, not
disk, and are not reservations. Because they are RAM, the **key copies in
`/tmp/pki` no longer persist in the container's layer** (before this change
`docker diff` showed `/tmp/pki/gateway/gateway.key`, readable by anyone with the
docker group); a tmpfs is gone when the container stops. Bytecode is compiled
at image build (`python -m compileall /app/src` in `Dockerfile.worker` and
`Dockerfile.trellion`) and `PYTHONDONTWRITEBYTECODE=1` stops the runtime
writing it. The mounted `noomesh.yaml`, `prompts/`, the compose override, the
`/data` volume and the host spool are bind mounts and volumes, not image
paths; they stay writable where they were (the worker mounts `noomesh.yaml`
read-only because nothing in it writes the file; the gateway's settings route
does).

Secrets are the other thing a writable layer would have kept. Compose refuses
an `environment:`-sourced secret in a read-only service, so they are `file:`
secrets bind-mounted from a tmpfs directory the launcher writes
([secrets.md](secrets.md#where-the-files-live)): nothing plaintext reaches a
disk or a layer.

What to expect when a path is missed: the write fails with `Read-only file
system` (EROFS) naming it, in that service's log, not at build time. A
configuration that points a worker tool at a directory inside the image
(`workspace_dir`, `output_dir`, the audit archive) now fails the same way; the
defaults are `/data` and `/tmp`. Verify a roll with:

```sh
docker inspect -f '{{.Name}} {{.HostConfig.ReadonlyRootfs}}' noo-gateway noo-worker noo-trellion
docker diff noo-gateway noo-worker noo-trellion    # only mount points (A /opt/noo/addon-routes, /opt/noo/addon-bundle-routes, /root/.claude): no files
```

`NOO_NODE_AGENT_PRIVILEGED` defaults to `false` for the opt-in
`node-agent-compose` lane. The containerised agent holds no Docker socket and
never uses the GPU itself, so it needs no privilege; set it to `true` only for
a deliberate bootstrap that must reach a device.
