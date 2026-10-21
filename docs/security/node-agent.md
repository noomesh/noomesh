# The node-agent trust contract

What the controller may make a node do, and what it may not.

Work in this mesh flows controller → node. The controller holds the
database, and the database is where desired state lives: which backends a
node runs, where its models live, which external MCP servers it hosts. A
node reads that state and converges toward it.

The question this page answers is the next one. **A controller that has been
taken over — a compromised gateway process, an edited `noo_node_config` row,
a stolen gateway certificate — is inside the trust boundary for issuing
instructions. It must not thereby own the boxes.** The node agent runs as
`noo-agent` in the `docker` group, which is host-root-equivalent; if desired
state can name any path, any image and any command, then one row in one table
is root on every node in the fleet.

So the node bounds what it will act on. The controller **proposes**; the node
**disposes**. Every bound below is compiled into the agent or read from the
node's own `/etc/noo-node-agent.env` — never from a request field and never
from a database row, because an allow-list the controller can extend is not
an allow-list.

---

## The contract

### The controller MAY

| Instruction | Bound |
|---|---|
| Start a backend from the agent's own spec table (`vllm`, `llamacpp`, `ollama`, `embedding`, `reranker`, `airllm`, `harness`) | The container shape is the agent's. The placement chooses model, image, port, TLS and *tuning* env |
| Choose the `/models` mount source (`node_config.models_dir`) | The path must resolve **under a root this node declared** — see [Declared host roots](#declared-host-roots) |
| Set placement `env` | Only keys on the [tuning allow-list](#placement-env-allow-list) |
| Run a skill in the skills sandbox (`POST /api/skills/run`) | Non-root, `CapDrop ALL`, `no-new-privileges`, pid cap, no host network, bind sources under the declared skill roots (or inline `files`) |
| Start a managed container (`POST /api/containers/start`) | The same floor as a skill, plus an image allow-list |
| Place an external MCP server | `streamable_http` only — a URL the node dials out to. **A stdio server cannot be placed at all**; those are declared on the node |
| Call a tool on a placed MCP server, read logs, read metrics, run inference, clean disk, restart the agent | Controller identity required — see [Who is the controller](#who-is-the-controller) |
| Preseed a model weight from the controller's store | Only against a **digest the controller states in its artifact manifest** |
| Benchmark the running chat model (`POST /bench`) | Controller identity required, one bench at a time, 600 s in all — see [Harness profile](#harness-profile) |
| Set the node's harness profile (desired-config `harness_profile`) | Numbers and enums the agent applies to its own bounds; the env on the box still wins — see [Harness profile](#harness-profile) |

### The controller MAY NOT

- **Mount an arbitrary host path.** Not `/`, not `/etc`, not a user's home,
  not anywhere outside the node's declared roots.
- **Run an arbitrary host command.** There is no exec verb, and there is no
  longer a stdio MCP placement either — see below.
- **Use host networking.** Neither skills nor managed containers. A container
  on the node's loopback is in reach of every service that trusts
  `127.0.0.1`, the agent's own control API included.
- **Read the agent's environment.** Child processes get a built environment
  (`PATH`, `HOME`, `LANG`, `LC_ALL`, `TZ` plus their own resolved values),
  never `os.Environ()`. Secret references in an MCP spec resolve against a
  node-local file the operator wrote — not against the agent's env, which
  holds the fleet secret, the node-agent token and the NATS password.
- **Give a container capabilities.** Backends, skills and managed containers
  all run `CapDrop ALL` + `no-new-privileges`.
- **Run a tool on the node.** Tools run in the gateway's tool gate, which
  owns approval, sandboxing and audit. The `tool_exec` job type refuses.
- **Reach a node that cannot identify it.** See below.

---

## Who is the controller

Every route below `/health` is gated by a bearer that is either
`NOO_NODE_AGENT_TOKEN` or an HMAC signed with `NOO_CLUSTER_SECRET`. Both are
**fleet** secrets — every node holds them, because every node needs them to
talk to the controller. A token signed with a shared key names its caller,
but that name is a claim, so the token answers "is this the fleet?" and never
"is this the controller?".

**The HMAC is bound to the request (v2).** The original token signed only
`<actor>:<time>`, so a copy of one `Authorization` header worked on any route,
with any body, for five minutes. The current form signs

```
v2 \n METHOD \n path?query \n sha256(body) \n actor \n time \n nonce
```

and travels as `v2:<actor>:<time>:<nonce>:<signature>`, with a fresh 128-bit
nonce per request. A verifier checks the signature against *the request in
front of it*, so the same header cannot be moved to another path, method or
body, and remembers every nonce it accepted for the five-minute window, so a
captured request cannot be sent twice (the gateway keeps the set in Redis,
falling back to its own memory; a node agent keeps it in memory, bounded, and
refuses new tokens rather than admit unchecked if it ever fills). It applies
in both directions: nodes sign their calls to the controller (registration,
heartbeat, log shipping, desired-config, manifests, the apply report) and the
agent verifies v2 from the peers and the controller that call it. A body over
64 MiB (gateway) or 32 MiB (agent) is refused instead of admitted unbound.

The old form is still accepted while the fleet rolls, and **every use is
counted** under the `cluster_hmac_v1` lane (`noo cluster verify
--controller`, row `legacy lanes`, names the callers; `cluster_hmac_v2` is the
comparator). Roll the controller first (it must understand v2 before a node
sends it), then the nodes. Once the row shows no v1 callers, close the door
on the gateway with the posture bridge `NOO_CLUSTER_TOKEN_V1`:

```
noo security posture set NOO_CLUSTER_TOKEN_V1 0
```

(on a release that introduces the key, add `NOO_CLUSTER_TOKEN_V1` to
`compose_env:` first and set it after the roll; a gate cannot be set before
the release that defines it). A v1 token is then answered `401
cluster_token_v1_refused` with the fix in the body, and counted as a refusal,
not a use: under `cluster_hmac_v1_refused` (gateway and agents alike), so
`cluster_hmac_v1` stays admissions only and the `legacy lanes` row names a
refused caller in a warning of its own. A node agent honours the
same switch from its own environment (`NOO_CLUSTER_TOKEN_V1=0`), and
`noo cluster provision` renders it from the controller's posture, so after
`posture set` the next bundle (`noo upgrade --nodes`, or `noo cluster provision
<node>`) closes the door on each node too; the agents keep counting v1 callers
until then. The provision output says `NOT CHECKED` when it could not read the
posture. A node rolled
*before* its controller can pin the old form with `NOO_CLUSTER_TOKEN_SIGN=v1`.

One claimed name is refused outright: an HMAC whose actor is the `noo` CLI
(`cli`, or `cli-` followed by a purpose) gets a `403` on every route, valid
signature or not. No CLI calls a node with the shared secret — the CLI talks
to the controller with the operator's own login — so such a token is either
a stale client or the shared secret being spent under the CLI's name.

The certificate answers it. The cluster CA stamps a different Organization on
each kind of leaf:

| Organization | Holder |
|---|---|
| `Mesh Cluster Gateway` | the controller — the gateway alone. The worker, trellion, trellion-intel and Prometheus each present their own service leaf |
| `Mesh Cluster Node` | a node agent |
| `Mesh Cluster Service` | a sidecar |

A node cannot obtain a gateway leaf: issuing one needs the CA key, which
lives on the controller. So the client certificate decides, and revocation
stays the PKI's job.

Because the leaf decides, two callers need no bearer at all:

- **The controller.** A request with no `Authorization` header and the
  controller's leaf is admitted on every route the gateway calls. The agent
  reports `controller_leaf_only: true` on registration and every heartbeat,
  and the gateway stops sending `NOO_NODE_AGENT_TOKEN` to that node. An agent
  that has not reported it keeps getting the token.
- **This node's own harness** (the agent loop placed beside a model). Its
  request needs this node's leaf (`CN=` the node id, `O=Mesh Cluster Node`)
  and must come from a loopback socket. It is admitted on
  `POST /v1/chat/completions` only. `/health` tells that caller
  `own_harness_leaf_only: true`, and the harness drops the token once it
  reads it. A peer node's leaf, or this node's leaf from another host, is
  refused as before.

`GET /tailnet/whois` answers "who is this tailnet IP" for any IP it is asked
about, so it is the controller's alone: a peer node holding the fleet secret
is refused (`403`).

A request that carries a bearer is still judged by the bearer, so an older
gateway or harness keeps working. Every use of the static token is counted
(`noo cluster verify --controller`, row `legacy lanes`).

**An agent that cannot identify its callers refuses the controller's routes
outright — `503`, naming the missing configuration.** It does not serve them
with a warning. On a node with no `NOO_TLS_CA`/`NOO_TLS_CERT`/`NOO_TLS_KEY`,
every caller looks alike, so serving would mean any holder of the fleet
secret — that is, every other node — could start, stop, pull, clean, run a
skill or read container logs on that box. The agent reports its own posture
as `peer_identity_enforced` on registration, and the gateway raises an
operator alert when a node registers without it.

**The control API is mTLS-only, and an agent without its material does not
start.** `:8081` (and `:8082` for the sensors instance) requires a
cluster-CA client certificate at the handshake, always. It also **listens only
where it is reached**: on the address the controller dials this node on (`NODE_IP`
as registered, else the source address of the route to the controller) and on
loopback, not on every interface. A docker bridge, a second NIC or a public
address no longer sees the port. `NODE_AGENT_BIND` overrides: `all` (or
`0.0.0.0`) restores every interface, or a comma list of IPs binds exactly
those; a hostname is refused at start with a message naming the setting. Set it for the fleet on the controller (`NODE_AGENT_BIND` in `.env` / `compose_env`): `noo cluster provision` renders it into each node's env with every bundle, and refuses an invalid value before staging anything. When
no usable address is known the agent falls back to every interface and logs
that it did, and a derived address that later changes (DHCP, tailscale coming
up after the agent) is followed within a minute by a rebind. There is no
plaintext listener and no weaker mode: with any of `NOO_TLS_CA`,
`NOO_TLS_CERT`, `NOO_TLS_KEY` unset or unreadable the agent exits at
startup with an error naming the missing file and the fix — `noo cluster
provision <node>` delivers all three (Linux `/etc/noo/pki`, macOS
`~/noomesh/pki`). A node that only ran `noo enroll` has the CA anchor and
no node certificate yet; it is not listening until provisioned. The
refusal is deliberate: an agent that "helpfully" served plaintext registered
as reachable and was not, which read as a network fault.

`NOO_MTLS_NODES` no longer selects anything. It once relaxed the handshake
to "verify if given"; a stale `false`/`0`/`no`/`off` line now **refuses the
start**, naming the line to remove, so a downgrade someone once chose is
loud rather than silently dropped. Any other value (including the empty
one `noo cluster provision` renders) is inert. `noo cluster verify <node>`
fails a node whose agent reports `peer_identity_enforced: false`.

`/health` is the one unauthenticated route, and it answers two shapes. An
anonymous caller gets liveness and the build version, because a Docker
healthcheck and a reachability probe must work without being anybody.
Everything *about* the node — its id, its NATS URL and bus username, its
disk layout and free space — is behind the bearer.

---

## Control over the bus

Small controller-to-node control calls no longer need the node's inbound
`:8081` listener. A node that holds an outbound NATS connection answers them
as NATS request/reply on `node.<id>.rpc.<op>` (followup i131, phase 1). The
ops: `health`, `gpu`, `stats`, `models`, `start`, `stop`, `restart`, `clean`,
`cleanup` (`images` | `logs`), `logs` (a container tail, or the container
list), `pull`, `skills.run`, `mcp.call`, `mcp.servers`. Each runs **the same
handler the HTTPS route runs** (`internal/api/rpc.go` builds the request the
route would have received and calls that handler), so status, headers and
body are the HTTPS answer; `TestEveryOpAnswersWhatItsHTTPSRouteAnswers` pins
it. Streaming and bulk stay on HTTPS until the tunnel (phase 2): inference
SSE, embeddings, the container proxy, device blobs, `/metrics`, logs over one
bus message (the node answers `413` with `Noo-Overflow` and the gateway reads
the same logs over HTTPS). There is no `tools` op: the agent has no such route.

`pull` and `skills.run` can take minutes. The node acks at once (`202`,
`Noo-Async: 1`) and publishes a keepalive every 10 s, then the result, on
`node.<id>.evt.<op_id>`; the gateway chooses the `op_id`, subscribes first,
and treats 45 s of silence as the node being gone. `start` already returns at
once over HTTPS; over the bus its eventual outcome is also published on its
event stream.

### Two gates, and why there are two

1. **The bus.** nats-server permissions (`noo cluster nats-users render`): a
   node may *subscribe* only `node.<its id>.rpc.>`, may *publish* only
   `node.<its id>.evt.>` and its reply inbox, and no principal but the gateway
   may publish `node.*.rpc.>` (the worker, every add-on and every node carry
   an explicit deny). This gate is silent when it refuses, because NATS
   returns success to a denied publisher, so it is never the only one.
2. **The envelope.** Every message carries `{op, node, ts, nonce, arg, query,
   op_id, timeout_s, body_sha256}` signed by the controller's leaf key (the
   gateway's own `NOO_TLS_KEY`), with that leaf attached. The node verifies
   the chain to the cluster CA, that the leaf carries the controller
   organization (the test `ControllerOnly` applies to a TLS peer), the
   signature over the whole message including a hash of the body, a 300 s
   window, and an unseen nonce. The nonce set is bounded (16 384); if it is
   full of unexpired entries the node refuses rather than forget one. A
   refused message gets a `403` naming the reason and never reaches a handler.

**Why the leaf and not the fleet signing key.** The signing key that verifies
rail manifests is deliberately not on the gateway (`scripts/noo-apply.sh`: a
gateway compromise must not be able to sign code). Using it here would put it
there. The controller leaf is the identity nodes already trust for `:8081`, so
this adds no new trust and removes none: a holder of the leaf can do over the
bus exactly what it can do over HTTPS today, and nothing the signing key
guards.

### When the bus is not available

| Situation | What happens |
|---|---|
| Old node (no `nats_rpc`) | HTTPS, as before |
| New node, controller NATS file from before this change (the subscription is denied) | The node detects the refusal (it flushes after subscribing and reads the server's async permission error), logs it with the remedy, does **not** advertise `nats_rpc`, and retries every minute; control stays on HTTPS |
| A grant dropped later, or a reply/event publish denied | Any permission violation naming this node's subjects withdraws `nats_rpc` at the next heartbeat |
| Gateway's bus is down | Routing, not a retry: nothing was sent, so the call goes over HTTPS |
| Bus call fails (no responders, timeout) on `health`, `gpu`, `stats`, `models`, `logs`, `mcp.servers` | One fall-back read over HTTPS, logged and counted (`control_calls.fallbacks`) |
| Bus call fails on `start`, `stop`, `restart`, `clean`, `cleanup`, `pull`, `skills.run`, `mcp.call` | The node is reported unreachable, as the HTTPS path reports it. **Never retried over HTTPS**: the node may have run it |

`NOO_CONTROL_OVER_BUS=0` on the gateway sends everything over HTTPS again.
`GET /api/cluster/nodes` carries `control_calls` per node (`bus`,
`https_control`, `https_other`, `fallbacks`, since the gateway started): the
number the later "outbound-only" gate reads. `noo cluster verify` has a
`control over bus` row per node: a `health` round trip over NATS, **NOT
CHECKED** (a warning, never ok) for a node that does not advertise `nats_rpc`,
**FAIL** for a node that advertises it and does not answer.

### Roll order

1. Upgrade the controller (gateway, CLI) first. Nothing changes: no node
   advertises `nats_rpc` yet.
2. `noo cluster nats-users render` on the controller (a stack roll re-renders it too). This writes the new
   grants and reloads NATS; the `rpc`/`evt` grants are static, so they survive
   the reload. Node credentials do **not** change and need no re-delivery over
   the rail: only the controller-side permission file is new.
3. Upgrade the nodes (`noo upgrade --nodes`, the rail). A new node subscribes,
   proves the subscription, and starts advertising on its next heartbeat. A
   node upgraded **before** step 2 simply keeps taking control over HTTPS and
   picks up the bus within a minute of the render.
4. `noo cluster verify`: every node shows `control over bus` green.

Rollback: set `NOO_CONTROL_OVER_BUS=0` on the gateway (no node change), or
roll a node back (it stops subscribing and stops advertising).

---

## Declared host roots

A node declares where its data lives in its own environment. The controller
may choose a path **under** one of these, never a new one:

| Variable | Meaning |
|---|---|
| `MODELS_DIR` | the model store |
| `NOO_DATA_ROOT` | the node's data tree |
| `HF_CACHE_DIR` | the HuggingFace cache |
| `OLLAMA_DATA_DIR` | ollama's blob store |
| `NOO_SKILLS_HOST_DIR` | the skills tree |
| `NOO_HOST_ROOTS` | the operator's explicit widening — a `PATH`-style list |

`noo cluster provision` writes the first four into
`/etc/noo-node-agent.env` on every node, so this is not new configuration.

A path is canonicalized (symlinks resolved, including through components
that do not exist yet) before it is compared, and the boundary is a path
separator — `/data-evil` is not inside `/data`. A node that declares nothing
accepts nothing.

**A refused path refuses the placement.** The models dir is not created, it
is not mounted, and GGUF placements that depend on it are skipped. It does
not fall back to the node's own default: a backend running against a
different models dir than the placement describes is a wrong answer wearing
a success.

## Placement env allow-list

Placement `env` is a `jsonb` blob the gateway ships verbatim. A placement's
job is to **tune** a backend, so it may set model/runtime tuning keys and
nothing else:

- exact: `MODEL_PATH` `MODEL_ID` `MODEL_NAME` `PORT` `HOST` `N_GPU_LAYERS`
  `N_CTX` `N_THREADS` `N_BATCH` `N_PARALLEL` `GPU_MEMORY_UTILIZATION`
  `TENSOR_PARALLEL_SIZE` `GPU_COUNT` `OLLAMA_MODEL` `OLLAMA_HOST`
  `OLLAMA_NUM_PARALLEL` `OLLAMA_KEEP_ALIVE` `OLLAMA_MAX_LOADED_MODELS`
  `OLLAMA_CONTEXT_LENGTH` `LOG_LEVEL` `RUST_LOG`
  (embed placements: `--env OLLAMA_NUM_PARALLEL=4` is the declared way to raise
  an ollama embedder's concurrency; an EMBEDDER's context window is not a
  placement setting, the gateway sends `options.num_ctx` on each embed
  request; `OLLAMA_CONTEXT_LENGTH` sets the daemon-wide default for CHAT
  models, which a vendor CLI harness needs: e.g. `--env
  OLLAMA_CONTEXT_LENGTH=32768`)
- prefixes: `VLLM_` `LLAMA_ARG_` `TEI_` `RERANK_`

Refused, by construction: `LD_*` and `PATH` (the dynamic loader reads them
before the program starts), `PYTHONPATH`/`PYTHONSTARTUP` (both execute chosen
code at interpreter start), `NVIDIA_*` (device visibility is the node's
decision), every credential including `HF_TOKEN`, and the whole `NOO_*` and
`NATS_*` namespaces. Widening the list is a code change in the agent.

The hardware target (`noo cluster place --on cpu|gpu`) is a placement
**field**, not an env key, for the same reason `NVIDIA_*` is refused: device
visibility is the agent's decision. On `target: cpu` the agent itself
withholds the GPU device request, sets `CUDA_VISIBLE_DEVICES` empty, and (for
llama.cpp) forces `N_GPU_LAYERS=0`. For llama.cpp it also mirrors the
allow-listed `N_THREADS` / `N_CTX` / `N_BATCH` / `N_PARALLEL` /
`N_GPU_LAYERS` onto llama-server's own `LLAMA_ARG_*` names (which the
upstream ARM image reads), and raises the container's CPU quota to the
placement's `N_THREADS`, never above the node's cores. A llama.cpp placement's `memory_limit_bytes`
(derived by the gateway from the fit estimate, capped by the usage profile)
replaces the container's fixed 8 GiB memory limit.

## Container floor

Every container the agent creates on a controller's instruction runs with:

- `no-new-privileges`
- `CapDrop: ALL`, plus — for backends only — `CHOWN`, `DAC_OVERRIDE`,
  `FOWNER`, `SETGID`, `SETUID`, which is what the entrypoint pattern these
  images share needs (start as root, chown the cache directory, drop to a
  service user). GPU access needs none of them: the NVIDIA container runtime
  works through device cgroups and bind-mounted driver libraries.
- skills and managed containers additionally run as a non-root user with a
  process cap.

`NOO_BACKEND_CAP_ADD` (node-local) widens the backend set for an image that
genuinely needs more; `NOO_CONTAINER_RUN_USER` and
`NOO_CONTAINER_IMAGE_ALLOW` do the same for managed containers.

## Backend doors on a node

Every backend the agent starts serves TLS with a cluster-CA **client
certificate required** at the door a caller reaches, the same set of doors
the controller's compose file fronts
A listener that admits any peer on the `noo-cluster` bridge hands every
prompt and reply to whatever else runs there; since 2026-09-29 none does.
The backend's own port is never published on the host.

| Backend | Door | What requires the certificate |
|---|---|---|
| vLLM | `https://noo-vllm:8000` | the server itself: `--ssl-certfile/--ssl-keyfile` (`services/vllm`), `--ssl-ca-certs ca.crt`, **`--ssl-cert-reqs 2`**. Unconditional — `NOO_VLLM_TLS` no longer gates it; a missing leaf exits (78), never serves plain. The healthcheck presents the container's own leaf |
| llama.cpp | `https://noo-stunnel-llamacpp:8085` | a stunnel sidecar the agent runs beside it (`verify = 2`, the `llamacpp` leaf); llama-server has no TLS listener |
| Ollama | `https://noo-stunnel-ollama:11434` | the same sidecar shape, the `ollama` leaf |
| TEI (`embedding`) | `https://noo-stunnel-tei:443` | the same, the `tei` leaf — `:443` is what compose's `stunnel-tei.conf` accepts on, so one URL reaches either |
| reranker | `https://noo-stunnel-reranker:443` | the same, the `reranker` leaf, whichever engine (`llama-server --reranking` on 8085 or TEI on 80) sits behind it |
| airllm | `http://noo-airllm:8000` | **plaintext, by the same named exception as compose**: opt-in, experimental; the deferred private-network step covers it |

The sidecar is one shape reused per backend (`internal/docker/sidecar.go`):
the compose `Dockerfile.stunnel` image when a node has it (`STUNNEL_IMAGE`,
then `NOO_IMAGE_PREFIX/stunnel:NOO_IMAGE_TAG`, then `noomesh/stunnel:latest`),
else plain alpine with stunnel installed at first start; the conf travels
in `STUNNEL_CONF` (the agent owns no host directory a root-in-container
sidecar should read from); `no-new-privileges`, `CapDrop ALL` plus
`DAC_OVERRIDE` to read the leaf key, and `NET_BIND_SERVICE` only for a
door below 1024. The agent runs it as root (`User: "0"`) whatever the image's
`USER` says: the published image runs the controller's doors as uid 65532, but
a node's leaf is a root-owned `0600` file. The sidecar forwards plaintext to the backend container
on the bridge; the backend's raw port stays reachable to OTHER containers
on that bridge until each backend gets a private network (a deferred step
the operator is exploring) — the sidecar is the door every client is
pointed at, the private network makes it the only one.

**What a node must hold.** Each door serves with a service leaf under
`$NOO_PKI_DIR/services/<x>/service.{crt,key}` (`vllm`, `llamacpp`,
`ollama`, `tei`, `reranker`) that **names the door** in its SANs
(`noo-vllm`, `noo-stunnel-<x>`; the controller's own service leaves carry
these — `onboard/steps.rs svc_extra_hostnames`). The agent checks the
leaf, the CA and the SAN **before touching the running container**: a
node without the leaf refuses to start that backend, records a
`backend_tls` refusal the heartbeat carries (a `noo cluster verify` row),
and whatever ran before keeps running. A provision bundle carries
`ca.crt` + the node cert only; delivering service leaves on the rail is a
deferred step — until then they are issued and copied by hand

**Who dials, with what.** The agent's inference proxy, `/rerank` and
`/embed` proxies, job executor, GPU-watchdog probe and heartbeat model
inventory all present the **node leaf** (`NOO_TLS_CERT`/`NOO_TLS_KEY`)
and verify the door against the cluster CA. The gateway never dials a
backend on a node directly: it dials the agent (`https://<ip>:8081`). Which
URL the agent dials is decided by the **running containers' declaration**
(`docker.BackendDialURL`): a vLLM whose command carries `--ssl-cert-reqs`
over https, a backend whose `noo-stunnel-<x>` runs at the sidecar — the
same read on a controller's compose backends and a node's agent-started
ones — and, with no declaration readable, the TLS door. A running backend
that declares **neither** is a pre-door container (created by an older
agent, or by compose before 2026-09-28): it is dialled plain, a
`backend_door` refusal names it on the heartbeat, and the reconciler
recreates it on its next tick (`BackendDoorGeneration` is part of the
spec hash, so the binary roll itself is the trigger — once the leaf is
there).

**The retired switches.** `NOO_VLLM_TLS`, `NOO_LLAMACPP_TLS`,
`NOO_OLLAMA_TLS`, `NOO_TEI_TLS`, `NOO_RERANKER_TLS` select nothing.
`provision` renders them empty; a `false`/`0`/`no`/`off` value **refuses
the agent's start**, naming the line, like `NOO_MTLS_NODES`.

**The one plaintext hop that stays.** A host-native Ollama — the
operator's own process outside Docker (macOS Metal, or a Linux install the
agent adopts) — is reached at `http://127.0.0.1:11434`: loopback on the
host, so the bytes never leave the machine and no container on the bridge
can reach it. The agent does not own that process and runs no listener in
front of it. The standalone controller's own `ollama-embed` is **not**
this exception: the agent's "stack" lane reaches it at the
`stunnel-ollama-embed` door's loopback publish,
`OLLAMA_URL=https://127.0.0.1:11434`, presenting the node leaf
(`backendrt/native.go` `laneTransport`; probes, model pulls, the model
inventory and the inference proxy alike). An https `OLLAMA_URL` with
`NOO_TLS_CA`/`NOO_TLS_CERT`/`NOO_TLS_KEY` unset or unreadable is an error the
lane reports on every call, never a bare client.

**How a host agent reaches a door.** The agent is a host process
(systemd on Linux, launchd on macOS); container names do not resolve on
the host. Every door dial goes through the host-mode dialer
(`internal/containerdial`), which swaps the container name for an address
the host can reach **at socket level** — the URL, and with it TLS SNI and
hostname verification, stay on the door's name (`noo-vllm`,
`noo-stunnel-<x>`), which is the SAN the door leaf carries. The CA the
proxy verifies doors with is the agent's `NOO_TLS_CA` (the container path
`/app/pki/ca.crt` only for a containerised agent).

| Host | Address the dialer uses | Published on the host |
|---|---|---|
| Linux | the door container's bridge IP, on the door port | **nothing** |
| macOS (Docker Desktop) | `127.0.0.1:<ephemeral>` — the door's loopback publish, read back from `docker inspect` | the **door only** (vLLM's own listener, or the `noo-stunnel-<x>` sidecar's accept port) on `127.0.0.1`; never the raw port of a sidecar-fronted backend, never `0.0.0.0` |

Docker Desktop runs containers in a VM whose bridge IPs the Mac cannot
route to, so there the door is published on loopback (a macOS-only line
in the reconciler's spec hash recreates a pre-publish container once). A
name that **is** a container is never handed to the system resolver: a
door that refuses (a vLLM still loading its model) is reported as
`container noo-vllm (host-mode dial <addr>): … connection refused`, not
as a DNS miss — until 2026-09-29 the fallback surfaced every cold load as
`lookup noo-vllm on 100.100.100.100:53: no such host`.

`tests/test_node_backends_require_client_certs.py` pins the node door set
to the compose one; `tests/test_backend_listeners_require_client_certs.py`
is the compose half.

## MCP servers

`streamable_http` placements are a URL and headers — the node dials **out**,
so the controller may place them freely. That is the transport to reach for.

`stdio` servers are a different thing wearing the same word: a command, its
arguments, its working directory and its environment, which the node
**executes**. The controller may not supply one, in any shape.

An earlier pass bounded this with an agent-side command allow-list and kept
the placement. That is not enough, and the reason is worth stating because
it generalises: the commands an operator would allow-list for MCP are
`uvx`, `npx`, `python`, `node` — and every one of them runs arbitrary code
from its *arguments*, which the placement also carried. An allow-listed
interpreter with attacker-chosen argv is the same hole wearing a hat.

So the split follows the rest of this page. The controller keeps the half
that is about coordination — which servers, running or stopped, by id — and
the node owns every byte of what actually runs.

### Declaring one

`/etc/noo/mcp-servers.json`, overridable with `NOO_MCP_STDIO_FILE`. A JSON
array; absent means this node runs no stdio MCP server, which is every node
until an operator writes the file.

```json
[
  {
    "id": "git",
    "image": "ghcr.io/noomesh/mcp-runtime:v1",
    "command": "/usr/local/lib/noo-mcp/mcp-server-git",
    "args": ["--repository", "/srv/repos/app"],
    "sha256": "9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08",
    "env": {"GIT_AUTHOR_NAME": "noo", "GITHUB_TOKEN": "$GITHUB_TOKEN"},
    "volumes": {"/srv/repos/app": "/srv/repos/app"},
    "network": "none",
    "disabled": false
  }
]
```

| Field | Rule |
|---|---|
| `id` | `[a-z0-9][a-z0-9_-]{0,63}` — it becomes the `mcp_<id>_<tool>` prefix |
| `image` | **required.** The container the server runs in. Must be in this node's `NOO_CONTAINER_IMAGE_ALLOW`. An entry without it is **refused** — see [The floor](#the-floor) |
| `command` | **absolute path**, root-owned, not group/world-writable. No `PATH` lookup: `PATH` is environment, and resolving through it means what runs depends on state other than this file. It is bind-mounted **read-only into the container at that same path** |
| `args`, `cwd` | as given; `cwd` must be absolute |
| `sha256` | optional. Verified on every load when present — a binary swapped underneath the file stops the server instead of running |
| `env` | `$NAME` resolves from the node's MCP secrets file (below) |
| `volumes` | optional extra read-only binds, host path → container path. Sources must sit under this node's **declared host roots** (`MODELS_DIR`, `NOO_DATA_ROOT`, `NOO_HOST_ROOTS`, …) |
| `network` | `none` (default) or a named docker network. `host` is refused |
| `memory` | optional Docker-style size (`"512m"`) |
| `disabled` | keeps the entry without running it |

**The file and its directory must be owned by `root` (uid 0) and must not be
group- or world-writable, or the agent refuses the whole file.** That check
is the entire trust basis: the agent runs as `noo-agent`, so a file
`noo-agent` could write would let anything that compromised *the agent* hand
the agent a new binary to run — and the point of this wall is that a
control-plane compromise does not become code execution.

A bad *entry* is refused on its own and reported; the other entries still
run, because a typo in the fifth server must not take the other four
offline. A bad *file* — unreadable, wrongly owned, not a JSON array — stops
everything it would have started. That one is not a typo.

Changes take effect on the next agent restart:
`sudo systemctl restart noo-node-agent`.

### Secrets

Secret references (`$NAME`, in a stdio entry's `env` or an http placement's
`headers`) resolve against `/etc/noo/mcp-secrets.env` — a `KEY=VALUE` file
the node's operator writes, overridable with `NOO_MCP_SECRETS_FILE`. They
deliberately do **not** resolve against the agent's own environment: that
would let a placement write `headers: {"X-Api-Key": "$NOO_CLUSTER_SECRET"}`
and post the fleet secret to any URL it named.

A server's environment is **built**, never inherited: `LANG`, `LC_ALL`, `TZ`
plus its own resolved values (`PATH` and `HOME` come from the image). The
agent's environment holds the fleet secret, the node-agent token and the NATS
password, and a child that inherits its parent's secrets has its parent's
reach.

### The floor

A node-local MCP server runs **in a container, under the same sandbox floor as
`/api/skills/run`** — literally the same `HostConfig` object, not a copy of it
(`docker.SkillFloorHostConfig`):

| | |
|---|---|
| user | non-root (`NOO_SKILL_RUN_USER`, default `65534:65534`) |
| capabilities | `CapDrop: ALL` |
| privilege escalation | `no-new-privileges` — a setuid binary in the image cannot buy root back |
| processes | `PidsLimit` — a fork bomb cannot take this node's backends with it |
| network | `none` by default; `host` is refused outright |
| filesystem | the declared `command`, read-only, plus `volumes` under declared roots |

JSON-RPC rides the container's attached stdio (`ContainerAttach`, frames
demultiplexed with `stdcopy`), so nothing about how a server is written has to
change — only where it runs.

**An entry with no `image` does not start.** There is no plain-exec fallback
and no flag that restores one. It used to run as `noo-agent`, and `noo-agent`
is in the `docker` group: an operator-chosen binary that was compromised
upstream — the realistic case for anything pulled from a package registry —
could open `/var/run/docker.sock` and be root on the host.

That could not be fixed in place. Dropping a supplementary group needs
`CAP_SETGID`, which a non-root agent does not have, and Go offers no hook
between `fork` and `exec` in which to call `prctl(PR_SET_NO_NEW_PRIVS)`. Both
come free inside a container, which is why the transport moved rather than the
flags.

Still treat an entry in this file as you would a line in `/etc/sudoers`: the
floor bounds what a compromised server reaches, it does not make one safe. Pin
the `sha256`.

A node with no Docker runs no node-local MCP server at all, and says so by
name on the refusals channel. Register it as `streamable_http` and give the
node a URL to dial instead.

## Model weights

A GGUF preseed from the controller's weight cache proceeds only when the
controller's artifact manifest states a `sha256` for those bytes, which the
helper verifies while streaming. A missing manifest **refuses the preseed**;
it does not copy the bytes unverified. The manifest route hashes the same
directory the cache serves, so a missing manifest means the cache does not
hold the file either.

This needs a gateway at `stack-v0.2.25` or newer. Against an older gateway a
node never preseeds GGUFs — ship the file with `noo cluster
sync-model-files`, or roll the gateway first.

## Backend door leaves

Every backend the agent starts serves through a door that requires a
cluster-CA client certificate: vLLM's own listener, a `noo-stunnel-<x>`
sidecar in front of llama.cpp, ollama, TEI and the reranker. Each door
serves with a service leaf at `$NOO_PKI_DIR/services/<x>/service.{crt,key}`
whose SANs name the host the agent dials it by, and the agent refuses to
start a backend whose leaf is missing or does not name its door.

Those leaves reach a node on the rail, the same as its node certificate:

| Bundle kind | Controller source | Node install path | Mode |
|---|---|---|---|
| `svc-<x>.crt` | `$NOO_PKI_DIR/nodes/<node>/services/<x>/service.crt` | `/etc/noo/pki/services/<x>/service.crt` (Mac: `~/noomesh/pki/services/<x>/`) | 0644 |
| `svc-<x>.key` | `$NOO_PKI_DIR/nodes/<node>/services/<x>/service.key` (0600, the CLI only) | `/etc/noo/pki/services/<x>/service.key` | 0600, root on Linux (read by root inside the door's container); on a Mac the `~/noomesh` tree belongs to the enrolling user, who runs the agent and Docker Desktop |

`<x>` is one of `vllm` (doors `noo-vllm`, `noo-vllm-secondary`), `llamacpp`,
`ollama`, `tei`, `reranker` (door `noo-stunnel-<x>`). The table is
`noo-cli/src/commands/node_leaves.rs` `NODE_DOOR_LEAVES`;
`tests/test_node_backend_leaves_on_the_rail.py` pins it against the
applier's install loop and the agent's own door table.

- **One leaf per node per door, node-scoped on the controller.** No node
  holds another node's key or the controller's own `services/<x>` key.
- **The fixed set, not the placements.** Every node gets all five, so a
  backend placed later is not refused while nobody re-provisions. A leaf
  for a door the node never opens grants nothing: it is a `Mesh Cluster
  Service` leaf, which neither the gateway nor any node agent admits to
  anything: both open `/metrics` to `CN=prometheus` only, so a node's door
  leaves cannot read another node's metrics.
- **Delivered by** `noo cluster provision <node>` and `noo upgrade --nodes`
  (both issue or renew first) and by any cert bundle —
  `noo security pki rotate-all`, `push-nodes`, `issue-node` — which
  carries whatever pairs are on disk.
- **A Mac below noo-cli 0.5.63 gets them one restage later.** Its applier
  is the Mac's `noo` binary, which refuses a kind it does not know and
  with it the whole bundle, so `noo cluster provision` withholds the
  `svc-*` kinds from a Mac whose agent reports an older CLI
  (`node_leaves::applier_knows_leaf_kinds`). That bundle carries the new
  CLI. `noo upgrade --nodes` (and `--all`) then waits for each such Mac to
  report the new CLI, up to 10 minutes (`NOO_UPGRADE_MAC_LEAVES_WAIT_SECS`,
  `0` to skip the wait), and restages it with the leaves. A Mac that does
  not report in time is named in the closing failure with
  `noo cluster provision <node>` as the remaining step. A direct
  `noo cluster provision <mac>` does not wait; its note asks you to run it
  again once the node reports the new CLI.
- **Checked before install.** The applier refuses a half pair, a
  certificate that does not chain to the CA the node trusts, and a key
  that is not the certificate's. Each file is written beside its target
  and renamed over it.
- **Never deleted by a restage.** A leaf the bundle does not carry stays.
  Revoking one node's leaf is a separate act: delete
  `nodes/<node>/services/<x>/` on the controller and re-provision (a new
  leaf with a new key replaces the node's copy). There is no revocation
  list, so a leaf copied off the node stays valid until it expires (90
  days).
- **No agent restart.** The reconciler starts a refused backend on its
  next tick once the leaf is there. A running door keeps the leaf it
  started with until its backend is recreated.

`noo cluster verify <node>` judges this in its `backend doors` row: for
each door-backed backend on the node, no `backend_tls` or `backend_door`
refusal, the controller's copy names the door and is not expiring, and the
node's own copy does too.

The node's copy is what the agent reports. On every heartbeat, and on
registration, it sends `backend_leaves`: for each door service it holds a
parseable `$NOO_PKI_DIR/services/<x>/service.crt` for, the certificate's
DNS SANs and NotAfter (unix seconds):

```json
"backend_leaves": {
  "vllm": {"dns": ["vllm", "localhost", "noo-vllm", "noo-vllm-secondary"], "not_after": 1790000000},
  "tei":  {"dns": ["tei", "localhost", "noo-stunnel-tei"], "not_after": 1790000000}
}
```

- **Certificates only.** The agent reads `service.crt` and never opens
  `service.key`; nothing secret leaves the node.
- **Absent is absent.** A service with no leaf, or one that does not parse
  (logged once as `backend_leaves.unparseable`), is missing from the map,
  never an entry with nulls. The map itself is always sent, `{}` when the
  node holds none.
- **Reported, not judged.** An expired or misnamed leaf is reported as it
  is; the verdict is `cluster verify`'s.
- **Cheap.** A beat stats each of the five paths and re-parses only a file
  whose size or mtime moved (`node-agent-go/internal/backendleaves`).

An agent that does not send `backend_leaves` (an older agent) makes the row a warning, not a pass: until the agent reports them,
the controller can prove only its own copy and the absence of a refusal.
`noo upgrade --nodes <node>` clears it.

### A door that is still warming up

The first `cluster verify` after a bundle apply can catch a backend the
reconciler has just recreated: the node has no leaf for its door yet, or
the agent refused to start it for that reason a moment ago. The controller
never runs `docker inspect` on a node, so the agent reports each running
backend container's start time and health on every heartbeat and on
registration, as `backend_containers`:

```json
"backend_containers": {
  "vllm":      {"running": true, "started_at": 1790000000, "health": "starting"},
  "embedding": {"running": true, "started_at": 1789990000}
}
```

`health` is left out when the container has no healthcheck. The map is
left out entirely when docker cannot be listed.

The `backend doors` row reads **starting**, not a failure, only when every
problem on it is "the node holds no leaf yet" or that `backend_tls`
refusal, and every backend involved is reported running, started less than
180 s ago, with health `starting` or none. It is not a pass: the verb
still exits 1, and `noo cluster verify <node> --wait` polls until the row
settles. Past 180 s the row fails and names the backend. A security fault
never reads as starting, however new the container is. That covers a leaf
that does not name its door, an expiring leaf, a plaintext door
(`backend_door`), any other `backend_tls` reason, or a wrong copy on the
controller. An agent that does not send `backend_containers` leaves the
row exactly as it was.

### Backend images

Each entry also carries the ref the container was created from (`image`)
and whether that ref can move under it (`image_floating`: no `@sha256`
digest, tag `latest` or none, and not one of our rail-only images). The
agent refuses to *create* a backend from a floating ref, but a container an
older agent made before that refusal keeps running on one. The `backend
images` row fails and names it. The agent never replaces a running
container by itself, so the remedy is to remove it on the node (`docker rm -f
noo-ollama`): the agent recreates it from the stack lock's pinned ref, which
the controller sends in desired-config for every placement with no image of
its own (from 0.6.9; before that only a manual `/start` carried it, and a
recreate fell back to the node's versioned default with no digest, which the
agent refuses).

The controller never sends a floating ref either. An operator
`VLLM_IMAGE`, `VLLM2_IMAGE` or `OLLAMA_IMAGE` set to `:latest` (or with no
tag) is skipped with a warning. Compose renders `VLLM_IMAGE` into the
locked variable too, so in that case the node uses its own versioned
default. Pin an override as `repo:version@sha256:…`, or unset it to use the
lock.

---

## Harness profile

The controller resolves a per-node **harness profile** (a tier default,
refined by a per-node override and by a measured model speed) and sends it in
desired-config as `harness_profile`. The agent keeps the last good one: a
fetch that fails, or a profile that does not parse, keeps it; a desired-config
with no `harness_profile` clears it, and no profile is exactly the behaviour
from before profiles. The agent applies four of its fields:

- **`first_byte_secs`** is the inference proxy's wait for a backend's
  response headers. Precedence: `NOO_BACKEND_FIRST_BYTE_TIMEOUT_SECS` on the
  box (the operator's override, read once) > the profile > 290 s. It is
  live: the proxy builds its transport per request, and each build reads the
  bound in force, so a profile change applies to the next request with no
  agent restart (a request already in flight keeps the bound it started
  with). An unusable env value is not an override; the profile or the
  default applies.
- **`ollama_context`** is the default `OLLAMA_CONTEXT_LENGTH` for this node's
  ollama when the ollama placement's env does not set the key; a placement
  that sets it is never touched. On Linux it joins the container env before
  the spec hash is taken, so a changed default recreates the container like
  any placement env edit. On macOS it reaches a brew-managed ollama through
  the plist tuning, and the guard rewrites the key and boots the job out and
  back once, as for its other tuning keys (it never removes a key, so
  clearing the profile leaves the last value in the plist).
- **`foreign_kinds`** lists the foreign harness kinds this node offers. After
  the kind checks above (wire, table, runner, vendor CLI), a foreign kind the
  profile does not list is refused (`backend_start` / `harness`) with:
  harness kind "claude-code": this node's profile (tier 3) does not offer it;
  set it with noo cluster profile &lt;node&gt; --set foreign_kinds=… (the
  node's id in place of &lt;node&gt;). `noo` is never refused by the profile,
  and with no profile there is no new refusal.
- The whole resolved object is passed to the node's own harness as `profile`
  in `GET /harness/placement` (omitted when there is none); the harness reads
  `stream_idle_secs`, `thinking` and `claude_prompt` from it. The profile
  carries numbers, enums and kind names, never a secret, and the placement
  env beside it keeps its secret-looking-key filter.

`POST /bench` measures the running chat model for the measured
`first_byte_secs`. It is a controller-only route (`ctrlMW`, the class of
`/restart` and `/gpu/hold`; a peer node, a service leaf and the node's own
harness are refused): a bench occupies the GPU, so it is a command. It
benches the desired placement with role chat (409 when there is none, or its
backend is not running; 409 while another bench runs), dialled exactly as the
inference proxy dials it (same door, TLS and client certificate; the header
wait is the bench budget, not the first-byte bound it measures):

1. `load_secs`: time to the first token of a streamed one-token completion,
   **as found**: a model already loaded gives a warm number, one that is not
   gives its cold load.
2. A deterministic ~8192-token prompt (one leading nonce line so a prefix
   cache cannot answer it) streamed with `max_tokens` 64 and
   `stream_options.include_usage`: `prefill_tps` = prompt tokens / time to
   first token, `decode_tps` = tokens after the first / the time after it.
   Token counts come from the backend's `usage`; without one the prompt is
   counted at chars/4 and the completion by content chunks.

The whole bench is bounded at 600 s (504 on expiry, 502 on a backend error).
The answer is the heartbeat's `model_bench`
(`{"model","backend","load_secs","prefill_tps","decode_tps","prompt_tokens","at"}`),
kept in memory and sent beside `host_services` on every heartbeat after; it
is absent until a bench has run on this agent process.

## When a node refuses

The node records what it declined and carries it to the gateway on the next
heartbeat as `reconcile_refusals` — scope, target, reason, and when it was
first seen. The gateway stores it on the node record and raises one operator
alert per node per day.

This matters because `noo_backend_placements` records *intent* and nothing
else. Without the report, a node that refused an instruction on purpose looks
from the controller exactly like a node that was never asked — and a wall the
operator cannot see is a wall they will debug as a bug.

The fix for a refusal is one of two things, and the message says which:

- the instruction was wrong — change the placement or the node config; or
- the node's declaration is too narrow — widen it in
  `/etc/noo-node-agent.env` and restart that agent; or
- the node lacks material the instruction needs — a `backend_tls` row
  names the service leaf a backend's door serves with (see Backend doors
  above); a `backend_door` row names a running backend that still serves
  plaintext and will be recreated once that leaf is there.

## Checking which agent a node runs

`noo cluster show <node>` reports the running agent's version from its
heartbeat, and needs nothing on the node. On the node itself,
`noo-node-agent --version` is **safe** since 2026-09-30: it prints the
version (first line identical to the heartbeat's `app_version`) and exits 0
before it reads the environment, opens a file or binds a port; `--help`
does the same. Any other argument exits 2 and starts nothing. Only running
the binary with **no** arguments starts an agent — leave that to the
service (`systemctl restart noo-node-agent`).

An agent binary older than that fix parses no flags: `--version` on it
starts a SECOND agent, which exits only because the operator's shell lacks
`NOO_TLS_*`. On a node not yet upgraded, read the version from
`noo cluster show <node>` or `journalctl -u noo-node-agent`, never by
running the binary. The fix reaches nodes through
`noo cluster provision <node> --wait` (or `noo upgrade --nodes`).

## Container images come from the controller

A node holds **no registry credential**, and nothing in this design gives
it one. Every image a node runs reaches it the way weights do: the
controller pulls it with its own login, stages a `docker save` tar on the
mTLS model-cache, and the node's agent pulls that tar as its own identity
and verifies its sha256 against the gateway's artifact manifest before
`docker load` ([weight-cache.md](../models/weight-cache.md#container-images)).

What this does and does not add:

- **No new remote capability.** The node pulls; the controller pushes
  nothing. A placement or container request still names an image, and the
  agent's allow-lists still judge it; the rail only changes where the bytes
  come from.
- **The integrity root is the manifest the node asks for** over mTLS with
  its cluster-HMAC bearer. A tar whose bytes do not hash to it is refused
  before `docker load`; an archive that holds more than one image or tags
  anything but the requested ref is refused before `docker load`; a loaded
  image that does not resolve under the requested ref, or is built for
  another architecture, is refused before a container starts. Those are
  VERIFICATION failures: never run, never fallen back from. A TRANSPORT or
  disk failure (cache unreachable, timeout, no space) with the image already
  present runs the local copy, reported as `local`, and the rail is not
  retried for 30 minutes.
- **What this does NOT protect against, said plainly.** The manifest is
  authenticated, not signed: under this design **a compromised gateway (or
  anyone who can write the controller's image store) chooses the bytes
  behind every allow-listed image name** a node pulls over the rail — the
  digest it serves is whatever the store holds. The manifest's
  `lock_digest` is **informational**: no node checks it against anything.
  Verifying images on the node against the release-signed stack lock is
  a planned later phase (a `chain.json` from the lock's index digest to the
  per-platform manifest to the config digest, and a release-key verifier in
  the agent). Until then the rail moves *where* the
  bytes come from (no registry, no credential on the node); it does not
  raise the bar above "the controller vouches".
- **Our images are rail-only.** A not-staged image of ours is a refusal
  naming `noo cluster sync-images <node> -i <image>` / `noo upgrade`, never
  a registry pull.
- **Vendor CLIs are rail-only too.** A harness kind's vendor CLI (and the
  runtime it runs on) is fetched by the controller with
  `noo cluster vendor stage`, verified against the sha256 pinned in
  `config/harness-kinds.json`, and carried in the node's signed bundle; the
  node never fetches it
  ([../getting-started/supported-agent-harnesses.md](../getting-started/supported-agent-harnesses.md#vendor-clis-are-staged-by-the-controller)).
- **Rollout switch.** `NOO_IMAGE_SOURCE=rail|legacy` (node-local env). The
  first release that ships the rail defaults to `legacy` — the pre-rail
  behaviour (local image, else its registry) — while the controller stages
  and `noo cluster verify` reports provenance anyway. Set `rail` one node at
  a time for the dry-run.
- **Third-party public images** may fall back to their registry only under
  `NOO_IMAGE_REGISTRY_FALLBACK=public` (node-local; the default). Set it to
  `off` for a node that must never reach an internet registry. Every
  fallback is logged and shows on `noo cluster verify` as source
  `registry`.

The agent has exactly one registry pull (`ImagePull`, in the fallback and
the legacy mode) and no `ImageCreate`; a guard test keeps it that way.

## Foreign CLIs run in a jail

A foreign harness kind (`claude-code`, `copilot`, `codex`) runs a vendor
CLI whose file tools act at the model's direction, so at the direction of
whoever wrote the task. **Foreign CLIs run in a Landlock jail, and never
without one.** The harness (`noo-gateway harness`) builds a Landlock
ruleset before it starts the CLI, and the CLI's process applies it
(`PR_SET_NO_NEW_PRIVS`, then `landlock_restrict_self`) between `fork` and
`exec`. The ruleset handles every filesystem right the kernel's Landlock
ABI knows, so anything not granted below is denied:

| Access | Paths |
|---|---|
| read + execute | `/usr`, `/lib`, `/lib64`, `/lib32`, `/bin`, `/sbin`, `/opt/noo/vendor`, and the directory the CLI's executable resolves to |
| read | `/proc`; the directories `/etc/ssl/certs`, `/etc/ca-certificates`, `/etc/ld.so.conf.d` |
| read (one file each) | `/etc/resolv.conf`, `/etc/hosts`, `/etc/nsswitch.conf`, `/etc/passwd`, `/etc/group`, `/etc/localtime`, `/etc/ld.so.cache`, `/etc/ld.so.conf`, `/etc/host.conf`, `/etc/gai.conf`, the cluster CA file (`NOO_TLS_CA`, the file and never its directory), and the run's MCP config file |
| read + write + ioctl | `/dev/null`, `/dev/zero`, `/dev/urandom`, `/dev/random` (not `/dev/tty`) |
| everything | the task's working directory, its HOME and its TMPDIR |

Paths that do not exist on the node are left out. Nothing else is
reachable: not `/etc/noo/pki/nodes`, `/etc/noo-*.env`,
`/etc/noo/harness-secrets`, the data root, `/run`, the docker socket,
`/home` or `/root`. The jail refuses to start if any granted path is, or
contains, one of those.

- **Other processes.** `/proc` is readable because runtimes read
  `/proc/self`. Landlock also scopes ptrace: a jailed process cannot pass a
  ptrace read check against a process outside its own Landlock domain, and
  `/proc/<pid>/environ`, `mem` and `fd/` are gated on that check. So the
  CLI cannot read the harness's environment, which holds the node's bus
  password and agent bearer, and it cannot read another task's CLI either.
  The harness also makes itself non-dumpable when it starts, so no other
  process of its user can read its `/proc` files, jailed or not.
- **Network is not restricted.** The CLI must reach the loopback
  translator, whose port is chosen per run, and the gateway's user door.
- **Fail closed.** A kernel without Landlock (ABI v1 is the floor), with
  Landlock disabled at boot, or with a seccomp filter that hides its
  syscalls cannot run a foreign kind. Each task is checkpointed with the note
  `harness jail unavailable: <why>; foreign CLIs never run unjailed`, and the
  harness logs `harness_jail_refused`. At startup the harness logs
  `harness jail: landlock ABI <n>`, or the refusal, once, so
  `noo cluster logs <node> harness` shows it before any task runs.
- **The unit.** `noo-harness.service` runs as user and group `noo-harness`,
  in no other group. It reads its own copy of the node's certificate and
  key, `/etc/noo/pki/harness/node.{crt,key}` (`root:noo-harness`, 0640,
  installed by the applier from the same bundle files as the agent's
  pair). The agent's pair, env file and secret files are
  `InaccessiblePaths=` for it. So even a CLI that escaped the jail runs
  with a uid and gid that cannot read the agent's key material.
- **macOS.** The CLI runs under `/usr/bin/sandbox-exec` with a profile that
  denies the whole of `~/noomesh` (pki, birth key, env files, secrets) and
  the data root, names `~/noomesh/pki`, `~/noomesh/secrets`,
  `~/noomesh/harness-secrets` and both env files in a deny of their own,
  then re-allows the CLI's own `~/noomesh/vendor` and `~/noomesh/bin`, the
  CA file, and the task's directories. On a Mac the harness runs as the
  operator's own user, so the profile first denies that user's whole real
  home (`~/.ssh`, `~/Documents`, keychains), re-allowing under it only
  those same paths and a `stat` of `~` and `~/noomesh`; the self-test
  plants a file in the real home and proves it unreadable. No
  `sandbox-exec` means a refusal, the same as on Linux.
- **Other processes on a Mac.** macOS has no Landlock, and the harness and
  the agent run as the same user as the CLI, so a plain process could read
  their arguments and environment with `sysctl(KERN_PROCARGS2)` (what
  `ps -E` uses) and their details with `proc_pidinfo`. The profile closes
  both: `(deny process-info*)` then `(allow process-info* (target self))`,
  and `(deny sysctl-read (sysctl-name "kern.procargs2") (sysctl-name
  "kern.procargs"))`. Apple does not document the profile language; these
  forms are the ones Apple's own WebKit WebContent profile and Chromium's
  profiles use, and the self-test below checks the result on each node.
- **Secrets are files, never environment, on both systems.** A secret the
  agent or the harness reads arrives as a `NAME_FILE` pointer, never as a
  value in its environment: on Linux the applier rewrites
  `/etc/noo-node-agent.env` and `/etc/noo-harness.env` (systemd
  `EnvironmentFile=`), and on a Mac `noo node fetch` rewrites
  `~/noomesh/agent.env` and `~/noomesh/harness.env` (sourced by
  `run-agent.sh` and `run-harness.sh`). The keys are
  `NOO_NODE_AGENT_TOKEN`, `NOO_CLUSTER_SECRET` and `NATS_NODE_PASSWORD`.
  Each value goes to its own 0600 file: `~/noomesh/secrets/` for the agent
  and `~/noomesh/harness-secrets/` for the harness on a Mac,
  `/etc/noo/agent-secrets/` and `/etc/noo/harness-secrets/` on Linux. The
  rewrite runs after every write to the env file, and only when the
  installed binary carries the marker that says it reads files (an older
  binary gets plain values back, so it never boots pointed at a file it
  cannot read). So even a process that could read the agent's environment
  would find only paths, and the jail denies those paths.
- **The self-test.** A jail that is wrong on some node's kernel or OS
  release must not be trusted on faith. When a harness for a foreign kind
  starts (after it makes itself non-dumpable, before it takes any task or
  turn), it proves the jail on this node. It creates a scratch workspace
  under its task directory root (`NOO_HARNESS_WORKDIR`), plants a secret
  file outside it (Linux: a fresh directory beside it that is not on the
  allow-list; macOS: under `~/noomesh/secrets`), and starts an
  ordinary unjailed process of its own user with a unique canary in its
  environment. Then it runs `/bin/sh` through the same jail a CLI gets.
  The shell must be able to read and write its workspace. It must NOT be
  able to read the planted secret, the canary process's environment, the
  harness's own environment (`/proc/<pid>/environ` on Linux, `ps -E` on
  macOS), or the node's real secrets where they exist (`/etc/noo/pki`
  including the harness's own key pair, the secret directories and the env
  files on Linux; `~/noomesh/pki`, both secret directories and both env
  files on a Mac). Each must-fail check is judged on what the shell
  printed: the canary or secret text must be absent, so a nonzero exit is
  not enough. If the same read also fails OUTSIDE the jail, the check
  proves nothing, and the result lists it as unproved instead of passed.
  On success the harness logs `harness jail self-test: ok (<os>,
  <mechanism>)`, with what was proved and how long it took (well under a
  second on a Linux node). On failure it logs
  `harness_jail_selftest_failed: <what leaked>` and refuses every foreign
  task and turn for the life of the process, with the same checkpoint note
  as a missing jail. The verdict is kept until the harness restarts and
  runs the test again. It is visible in the harness's log only: the
  agent's heartbeat reports the harness service's state, not this verdict.

## The helper image

Every host operation the agent performs — create the models dir, chown it,
test whether a weight file is present, copy weights out of the controller's
store — runs in a short-lived container built from **one** image: the agent's
own. On a released node that resolves to
`$NOO_IMAGE_PREFIX/node-agent:$NOO_IMAGE_TAG` (the pair `noo cluster
provision` writes into `/etc/noo-node-agent.env`); `NOO_HELPER_IMAGE`
overrides it.

**A host-process node does not start with that image.** The agent is
installed as a *binary*; nothing ever asked Docker for the image whose name
that binary derives, and the registry is private, so the daemon cannot fetch
it either — the node holds no registry credential, by design.

So the node fetches it **over the artifact rail**: the controller's exported
tar, digest-verified, pulled by the node as its own identity — the same path
backend images arrive on, and the same one that carries model weights. No
registry, no credential, no controller-side push. The fetch happens lazily,
on the first host operation that needs it, so a node that never runs one
never transfers the bytes.

When the rail cannot supply it, that is a **refusal**, not a fallback. It
reaches the controller on the heartbeat with the exact command to fix it:

```
noo cluster sync-images <node> -i <the ref> --no-restart
```

The `-i` matters. A bare `noo cluster sync-images <node>` ships the
*unprefixed local build* names, so on a released node it reports success
having shipped nothing the node will ever look for. (`default_sync_images`
now derives the release ref from the controller's own
`NOO_IMAGE_PREFIX`/`NOO_IMAGE_TAG`, which closes that skew — but a
controller whose env names no release pair still needs the explicit `-i`.)

**Why the agent image, and not a small dedicated one.** The helper needs a
shell (`mkdir`, `chown`, `test`) *and* the agent binary, because the preseed
steps are the agent's own `-preseed` / `-preseed-file` subcommands — the
digest-verifying fetch has to be the same code as the agent that asked for
it. The released agent image already **is** "Alpine plus that binary"
(~17 MB locally, ~5 MB as an exported tar), so a dedicated helper would be
the same picture minus a couple of megabytes, at the cost of a second
artifact to build, publish, export and keep in lockstep with the binary
whose subcommand it runs. A version skew there would be silent and would
corrupt weights. One image, one version, no skew.

**Why provision does not ship the image to the node.** It does not need to:
the node fetches it on demand, so shipping ~5 MB into every provision bundle
would pay for bytes most nodes already have and the rest can get when they
first need them. What provision *must* guarantee is the other end — that the
controller has **exported a tar** for the node's release ref, which is what
the `default_sync_images` fix above is for. The failure was never "the node
could not receive it"; it was "nobody offered it".

## What is still root

`noo-hostd` is root on the node, and deliberately so: it has no listener, it
reads a file spool, and it runs a fixed list of operations. Host filesystem
work the agent needs (creating and chowning the models dir) runs through a
short-lived helper container rather than through the agent itself, with the
path validated against the declared roots and every externally-supplied value
passed as a shell **argument**, never interpolated into a command line.

The node agent itself is not root and not a privileged container: it is a
systemd host process running as `noo-agent` with `NoNewPrivileges=true` and
membership of the `docker` group. The docker socket is the agent's real
privilege, and it is why every bound on this page exists.
