# Monitoring

Every controller ships its own monitoring: Prometheus scrapes the gateway,
the node-agents and the host exporters over mTLS, Grafana renders them,
every node's agent — the controller's own included — ships container and
journal logs to Loki through the gateway, and Alertmanager receives the
bundled rules. All of it is in the `controller` and the `standalone`
profile — nothing extra to start, on either install shape. Prove it:

```sh
noo health                                        # gateway + dependencies, exit 5 if degraded
# the registry Prometheus scrapes, read with the scraper's own leaf (on the controller):
P="${NOO_PKI_DIR:-$HOME/.config/mesh/pki}"
curl -s --cacert "$P/ca.crt" --cert "$P/services/prometheus/service.crt" --key "$P/services/prometheus/service.key" https://localhost:8080/metrics | head
```

Open Grafana from the console (**Open Grafana**): it signs you in with your
noomesh account, and that is the only way in — Grafana has no login of its
own (see "Single sign-on" below). Prometheus at
`https://127.0.0.1:9090` requires a cluster client certificate from every
caller, so a browser is refused; read it through Grafana, or through
`GET /api/metrics/query` with an Operator or Admin login.

You never type Grafana's address: **Open Grafana** in the console opens it.
Where that address is depends on `NOO_BIND_MODE`.

**On a `tailnet` controller**, the address is
`https://<controller-tailnet-name>:3000`. `tailscale serve` answers port
3000 of the controller's tailnet name with the same Let's Encrypt
certificate the console gets, and passes each request on to Grafana, which
is published on loopback. Grafana keeps its own address (port 3000) rather
than a path under the console's, so a Grafana page never runs on the
console's origin.

Onboarding and `noo upgrade --stack` add that serve entry. They touch only
port 3000, and never an entry already on that port: if you have put
something there yourself, it is left alone and `noo cluster verify` says
so. Grafana moves to loopback only after the serve entry is confirmed. If
the entry cannot be written (Tailscale not installed, `tailscaled` down, or
the port taken), Grafana stays published on the tailnet IP and the roll
warns, naming the command to run by hand. The browser then shows a
certificate error (the cluster CA, `ERR_CERT_AUTHORITY_INVALID`), and on a
`ts.net` name it cannot be clicked through. That was every tailnet
controller before this change.

**On a `local` or `all` controller, or one bound to a LAN address**, the
address is `https://localhost:3000`, published on loopback, as before this
change. Only a browser on the controller itself reaches it. From another
machine, open a tunnel first and then use **Open Grafana** as usual:

```sh
ssh -L 3000:127.0.0.1:3000 <you>@<controller>
```

**A bookmark of Grafana leads back to the console.** Grafana has no login
form, so on its own a bookmark or typed `https://<controller-tailnet-name>:3000`
(or a tab whose session expired) shows a bare "Welcome to Grafana" page. On
a `tailnet` controller, onboarding and `noo upgrade --stack` add one more
serve entry on port 3000: `/login` goes to Grafana's `/logout`, which
redirects to the console at `https://<controller-tailnet-name>/#/observability?open=grafana`
(`NOO_GRAFANA_CONSOLE_URL`). The console asks for its own login if needed,
then opens Grafana in the same tab. If the tab comes straight back within a
minute, the console does not reopen Grafana; it asks you to click **Open
Grafana**. The entry is added the same way as the first one: only that
path, never over an entry already there, and checked by reading it back.
If it cannot be written, the roll warns and names the command to run by
hand. On a `local` controller the bookmark still shows the bare page; use
**Open Grafana**.

`noo cluster verify --controller` reports which case you are in on the
`grafana door` row. It FAILs whenever no browser path exists, or when the
only path meets the cluster CA's certificate.

Onboarding writes `GRAFANA_ROOT_URL` and `NOO_GRAFANA_BIND_ADDR` from
`NOO_BIND_MODE`, and `noo upgrade --stack` fills them on an install that
predates that. It never inherits `NOO_BIND_ADDR`: `all` puts the
cluster plane on every interface, not Grafana. Prometheus binds loopback and
has no login of its own at all — its containment IS the loopback binding,
and Grafana reaches it over the compose network, so in practice Grafana's
login is Prometheus's login too.

```
node-agent (:8081/metrics) ──┐
node-exporter (:9100)      ──┼──▶ prometheus (127.0.0.1:9090) ──▶ grafana (:3000)
nvidia-exporter (:9400)    ──┤              │
gateway (:8080/metrics)    ──┘              ▼
                                       alertmanager (127.0.0.1:9093)

containers + journal ──▶ node-agent (every node, the controller too) ──▶ gateway ──▶ loki ──▶ grafana / `noo logs query`
```

## What is scraped

The live Prometheus configuration is the inline `configs:` block at the
end of `docker-compose.cluster.yml` (`monitoring/prometheus.yml` is a
reference copy). Every job is HTTPS with the cluster PKI client cert,
15-second interval.

**Which** client cert is the point. Every job presents
`services/prometheus/service.{crt,key}` — `CN=prometheus`,
`O="Mesh Cluster Service"`. Four of them used to present
`gateway/gateway.{crt,key}`, and the container mounted the whole PKI
directory besides. That leaf is the controller's identity: a node agent
reads `O="Mesh Cluster Gateway"` as "this caller may command me", so the
scraper held a key good for `/start`, `/stop`, `/clean`, `/pull`,
`/api/skills/run` and `/logs/{container}` on every node it could reach
— the reason that changed. The service org opens `GET /metrics` and nothing else, and
`gateway.key` is no longer mounted into the monitoring containers at all
(nor was it in promtail, now retired, which carried it only to dial Loki). Each
monitoring container (loki and the exporters included) mounts `ca.crt` and
its own `services/<name>/` leaf, never the PKI directory.

Existing installs mint the leaves once (`noo security --help`).

| Job | Target | Notes |
|---|---|---|
| `gateway` | `gateway:8080/metrics` | the service leaf alone: the gateway admits `CN=prometheus` on `GET /metrics` and nothing else (needs mTLS enforcement, which is the default; `NOO_MTLS_GATEWAY=false` turns it off); people need an Operator or Admin login |
| `noo_node_agent` | `node-agent:8081/metrics` | the service leaf alone, no bearer — the agent refuses this route to anything that is not the controller or a cluster service |
| `node` | `node-exporter:9100` | host CPU, memory, disk, network |
| `nvidia_gpu` | `nvidia-exporter:9400` | GPU temperature, power, memory, utilisation (`nvidia_gpu_*`); the launcher scales this exporter to 0 on hosts without an NVIDIA runtime |
| `prometheus` | `localhost:9090` | self |

Worker nodes are not scraped by the controller's Prometheus; their
node-agent exposes the same `/metrics` on `:8081`. There is no `worker`
compose profile (there was one, carrying a node-exporter and a promtail
nothing scraped or could reach; it went with promtail): a node runs a
native agent, never compose.

## The gateway `/metrics` endpoint

`GET /metrics` is the one canonical registry. It emits, per scrape:

| Metric | Type | Source | Use |
|---|---|---|---|
| `noo_gateway_up{engine="rust"}` | gauge | constant 1 | liveness (`GatewayDown` rule) |
| `noo_gateway_start_time_seconds` | gauge | process start (unix seconds) | the window every in-memory `_total` counter was counted over; `time() - noo_gateway_start_time_seconds` is the uptime |
| `noo_legacy_lane_uses_total{lane,…}` | counter | auth middleware, on every ADMITTED request that used a legacy credential lane | retirement evidence for the shared-secret and token-only lanes — see [Legacy credential lanes](#legacy-credential-lanes) |
| `pages_embedding_backlog` | gauge | DB query | pages awaiting embedding; sustained growth means the embedder is down or overloaded |
| `temporal_edges_total` | gauge | DB | graph growth |
| `conversations_total`, `entries_total` | gauge | DB | coarse usage |
| `nats_dlq_pending`, `nats_dlq_abandoned` | gauge | DB | messages awaiting the DLQ drain / given up on. **`abandoned > 0` needs eyes** |
| `noo_auth_failures_5m`, `noo_exec_denials_5m` | gauge | DB (security audit) | the security alert rules read these |
| `noo_cluster_nodes_total`, `…_online`, `…_busy`, `…_offline` | gauge | cluster collector | fleet size and health, the same counts `noo cluster status` prints |
| `noo_embed_queue_pending`, `…_ack_pending`, `…_waiting` (label `model`) | gauge | JetStream consumer info | bulk embedding queue per model: batches waiting, batches a node holds unacknowledged, and open node fetches. `waiting` of 0 with `pending` growing means no node is pulling, and the gateway runs those jobs itself after 2 minutes. Omitted for a model whose consumer cannot be read |
| `noo_embed_pull_jobs_total` (label `path`) | counter | gateway | embedding jobs by path: `pull` (a node claims it) or `push` (the gateway runs it, including a job flipped after a pull stalled) |
| `noo_embed_pull_failures_total` (label `reason`) | counter | gateway | `flipped_to_push_run`: a pulled job stalled and the gateway took it over; `result_refused`: a node returned vectors for the wrong model, count or width, and the job was failed |
| `noo_cluster_tier1_nodes`, `…_tier2_…`, `…_tier3_…` | gauge | cluster collector | worker-tier mix. Edge (4), companion (5) and monitor (6) nodes count in the total but have no series of their own |
| `noo_cluster_vram_total_gb` | gauge | cluster collector | fleet VRAM |
| `noo_node_load{node}`, `noo_node_tier{node}`, `noo_node_vram_gb{node}`, `noo_node_backends_running{node}` | gauge | cluster collector | per node. **A value that is not known is not emitted** — a node absent from gossip has an unknown load, and an absent series reads as "no data" where a `0` would read as "idle, send it work" |
| `nats_dlq_drain_succeeded_total{subject}`, `nats_dlq_drain_failed_total{subject}`, `nats_dlq_abandoned_total{subject}` | counter | DLQ drain loop (every 30s) | recovery and failure rate per subject |
| `nats_publish_retry_exhausted_total{subject}`, `nats_dlq_insert_failed_total` | counter | worker client | NATS health; the second means NATS *and* the DB were down |
| `memory_provider_calls_total` | counter | memory provider seam | trellion traffic |
| `context_injection_layer_chars`, `…_invocations_total`, `…_latency_ms_total{layer}` | counter | coordinator | cost of each context layer (rag, memory, channel, companion, …) |
| `pages_embeddings_completed_total`, `pages_embedding_failures_total`, `temporal_extraction_*`, `query_embedding_cache_hits_total` / `…_misses_total` | counter | pushed by trellion over NATS | embedding throughput, extraction health, cache effectiveness |

The `noo_cluster_*` / `noo_node_*` families come from
`collect_cluster_nodes` — the same helper behind `/api/cluster/status` and
`/api/cluster/nodes` — so the dashboard cannot disagree with the CLI about
how many nodes exist. They were queried by the shipped Grafana dashboard
long before anything emitted them, which is why its cluster panels used to
read "No data" next to working node-exporter panels.

Counters need no registration: a Rust caller does
`state.metrics.inc_counter("name", labels, 1)` and the name appears at the
next scrape. An add-on increments its own counters with
`POST /api/metrics/increment` (`{"name": "<x>_total", "value": 1, "labels": {…}}`)
and sets its gauges with `POST /api/metrics/gauge` (`{"name": "<x>", "value":
12.5, "labels": {…}}`; any finite number, last write wins), both under scope
`metrics` on its key; they appear as `noo_addon_<name>{addon="<source>"}`,
typed counter or gauge, the source taken from the credential, at most 256
series per add-on across both. The `noo_gateway` client package
(`packages/noo-gateway-client`) batches them: `Counters.inc(...)` and
`Counters.gauge(...)`. There is no NATS path: the `metrics.>` subscriber was
removed, so a publish on `metrics.counter` or
`metrics.gauge` reaches nothing. DB-backed gauges are one cheap query each
in `gateway-rust/src/metrics.rs::collect_db_gauges`.

### Legacy credential lanes

Four ways in are kept only until nothing uses them. The gateway counts
each one it admits, and the replacements beside them, so the ratio is
visible. Counting never refuses anything; the lane still works exactly as
before. The one exception is `addon_shared_secret_refused`, a lane that
was retired once the add-ons stopped sending it: it counts refusals, so a caller still on it
has a name.

| `lane` | other labels | counted when |
|---|---|---|
| `self_call_shared_secret` | `door` (`controller` \| `cluster`), `caller` | a shared-secret HMAC buys inference (`/v1/*`, `/api/external/*`) — the `NOO_SELF_CALL_SHARED_SECRET` bridge |
| `cluster_hmac_non_inference` | `kind` (`controller` \| `cluster`), `route_class`, `caller` | a shared-secret HMAC gets full (internal) access on any other route (an add-on never appears here: its HMAC is refused, next row) |
| `addon_shared_secret_refused` | `door` (`controller` \| `cluster`), `caller`, `route_class` | **refused**, not admitted: a shared-secret HMAC whose actor is an add-on's (`trellion`, `trellion-intel`, `evolve`). The gateway answers 403 naming `noo security service-key provision <add-on>`. A count is an add-on image from before the add-ons dropped their HMAC fallback, or one with no key — every gateway call it makes is failing |
| `node_token_no_cert` | `node` (as the token claims it), `route_class` | a node token reaches a node route with no client certificate on the connection |
| `node_token_with_cert` | `node` (from the certificate) | the same with the node's certificate — the good case |
| `addon_exchanged_token` | `caller`, `route_class` | an add-on on its own exchanged token — the good case |
| `operator_client_cert` | `caller` (the operator's account), `route_class` | a posture write admitted on an operator client certificate and a token bound to it — the good case for the CLI's posture writes |
| `cluster_hmac_v1` | `caller`, `route_class` | a fleet-secret HMAC admitted in the old v1 form (not bound to its request); `cluster_hmac_v2` (`caller`) is the good case |
| `cluster_hmac_v1_refused` | `caller`, `route_class` | REFUSED, not admitted: a v1 cluster token after `NOO_CLUSTER_TOKEN_V1=0`. Every count is a caller whose calls all fail until it signs v2; each node agent reports its own under the same name in `legacy_lanes` |
| `cli_shared_secret_refused` | `caller` (`cli`, `cli-posture`, `cli-onboard`, `cli-break-glass`), `route_class` | REFUSED, not admitted: a `noo` binary signed a request with the controller secret. Every count is an old CLI that needs `noo upgrade --all` |

The `noo` CLI is on none of the admitted lanes. The CLI never
signs with a shared secret (no `--break-glass`, no onboard `cli-onboard`),
and the gateway refuses the controller-secret HMAC of any actor a CLI ever
used, on every route, with a 403 naming `noo upgrade --all`. Those
refusals are counted as `cli_shared_secret_refused`; `noo cluster verify
--controller` warns on any, naming the caller. `cluster_hmac_non_inference`
therefore holds only the add-ons' HMAC fallback.

`route_class` is the path's first segment from a fixed list (`cluster`,
`rag`, `graph`, `inference`, …; `other` past it), never the path itself.
`caller` and `node` take at most 32 distinct values each, then read
`other`. The counters live in memory and reset with the gateway, which is
why `noo_gateway_start_time_seconds` sits beside them: a zero means
something only with its window.

Each node agent counts its own two lanes — `static_token` (a request
admitted by the static `NOO_NODE_AGENT_TOKEN` rather than the HMAC token)
and `whois_non_controller` (`GET /tailnet/whois` served to a caller whose
certificate is not the controller's) — as
`noo_node_legacy_lane_uses_total{node_id,lane}` on its `/metrics`, and
reports them on every heartbeat as `legacy_lanes`
(`{since_unix, static_token, whois_non_controller}`).

The logs say who: a `node_token_no_cert` use logs a WARN once per node per
hour; a `cluster_hmac_non_inference` use logs at DEBUG once per
kind/route class/caller per ten minutes; the self-call bridge's existing
per-use WARN names the peer (`ip=… leaf=…`). Nothing here reaches a
channel.

`noo cluster verify --controller` reads all of it as its `legacy lanes`
row:

| verdict | reads |
|---|---|
| OK | `0 uses — uses since gateway start <age> ago; nodes: shortest agent uptime <age>: self_call_shared_secret 0, … [comparators: node_token_with_cert N, addon_exchanged_token N, operator_client_cert N]`; a window under seven days adds `under 7 days, not yet retirement evidence` |
| WARN | `in use: <lane>, … — …` with each lane's count and who used it (`self_call_shared_secret 12 (trellion 10, worker 2)`); or `/metrics` not readable; or a gateway without `noo_gateway_start_time_seconds` (older than the counters; `noo upgrade --stack`); or an online node that does not report `legacy_lanes` (`noo cluster provision <node> --wait`) |

A lane is ready to retire after zero uses over at least seven days of
uptime — gateway uptime for the gateway lanes, every node's agent uptime
for the node lanes — spanning a weekly heartbeat run.

### Useful queries

```promql
rate(pages_embeddings_completed_total[5m]) * 3600        # embeddings per hour
increase(nats_dlq_abandoned_total[1h])                    # anything > 0 needs triage
rate(query_embedding_cache_hits_total[5m])
  / (rate(query_embedding_cache_hits_total[5m]) + rate(query_embedding_cache_misses_total[5m]))
noo_node_load                                             # per node-agent
noo_legacy_lane_uses_total > 0                            # a legacy credential lane in use; `caller`/`node` names who
nvidia_gpu_memory_used_bytes / nvidia_gpu_memory_total_bytes
```

`noo_metrics_query` (MCP, operator door) and `GET /api/metrics/query` (Operator
or Admin only) proxy PromQL to
Prometheus at `services.prometheus_url` (`NOO_PROMETHEUS_URL`, default
`https://prometheus:9090`).

Three read-only siblings, operator door and Operator/Admin only, give the
rest of what Grafana shows plus alerts:

| MCP tool | route | answers |
| --- | --- | --- |
| `noo_metrics_range` | `GET /api/metrics/range` | `query_range` (`query`, `start`, `end`, `step`); refused above 11,000 points per series, truncated to 100 series |
| `noo_metrics_discover` | `GET /api/metrics/discover` | metric names, or one label's values (`label`), narrowed by `selector` and `prefix`; capped at 500 |
| `noo_alerts_list` | `GET /api/alerts/list` | every alerting rule with state, severity, summary, `activeAt`, `for`, merged from Prometheus rules and alerts, plus Alertmanager's active/silenced/inhibited list (`NOO_ALERTMANAGER_URL`, default `https://alertmanager:9093`; a section that reports its own error if Alertmanager is down) |

None writes: no silences, no acknowledgements. Dashboards are not listed
here yet.

## Node-agent metrics

Every node-agent serves `/metrics` on `:8081` (the controller, or a cluster
service leaf such as the scraper's),
labelled `{node_id}` and, for GPU rows, `{gpu}`:

`noo_node_info`, `noo_node_load`, `noo_gpu_utilization_percent`,
`noo_gpu_memory_utilization_percent`, `noo_gpu_memory_used_mb`,
`noo_gpu_memory_total_mb`, `noo_gpu_temperature_celsius`,
`noo_gpu_power_draw_watts`, and `noo_node_legacy_lane_uses_total{node_id,lane}`
([legacy credential lanes](#legacy-credential-lanes)).

`docker/nvidia-smi-exporter.py` is the separate pynvml exporter behind
`noo-nvidia-exporter` (`nvidia_gpu_temperature_celsius`,
`nvidia_gpu_power_draw_watts`, `nvidia_gpu_power_limit_watts`,
`nvidia_gpu_memory_used_bytes`, `nvidia_gpu_memory_total_bytes`,
`nvidia_gpu_utilization_gpu_ratio`, `nvidia_gpu_utilization_memory_ratio`,
`nvidia_gpu_fan_speed_percent`, all `{gpu_index, gpu_name}`, plus
`nvidia_gpu_exporter_up`). It answers `/health` with `ok` and reports
`nvidia_gpu_exporter_up 0` when pynvml is absent.

## Alert rules

`monitoring/alerts/*.yml` is mounted into Prometheus; Alertmanager routes
to a `null` receiver until you edit `monitoring/alertmanager/alertmanager.yml`
(Slack and webhook examples are in the file, commented out).

Alertmanager's listener is HTTPS with a **required cluster-CA client
certificate** (`monitoring/alertmanager/web-config.yml`, loaded by the
service's `--web.config.file=` flag — the mount alone does nothing, and
without the flag `:9093` would answer plain HTTP with
no auth while Prometheus dialled it as https). Its one client is Prometheus
with `services/prometheus`; the container's healthcheck is `amtool`
presenting `services/alertmanager` to itself (`amtool-http.yml`). To reach
it by hand: `curl --cacert ca.crt --cert services/prometheus/service.crt
--key services/prometheus/service.key https://localhost:9093/-/healthy`.
`noo cluster verify --controller` reports the `image family` row (each
running redis/monitoring container's image comes from `NOO_BASE_REGISTRY`,
default `ghcr.io/noomesh/dhi`, and runs as the uid its key is handed to),
the `voice images` and `voice models` rows (with `addons.voice` on,
noo-whisper and noo-piper run as uid 65532, the uid their keys are handed
to, the configured whisper model and piper voice are staged on the
controller, and both containers run with `HF_HUB_OFFLINE=1`; "not checked"
when off),
the `monitoring web config` row
(every mounted web-config is named by its command) and one `<name> at rest`
row per data directory — loki, postgres, redis, nats, prometheus, grafana,
noo-data, pki, age key — OK on a dm-crypt device, WARN otherwise: nothing
here encrypts its own files. The WARN's remedy states the plan (operator
decision i10a, no full-disk LUKS): the data-root rows point at a LUKS2 volume
unlocked by the machine's TPM, the `pki` and `age key` rows at keys sealed to
the TPM. Both protect a stolen or lost drive, not root on the running machine,
and neither is built yet.

| Rule | Fires when |
|---|---|
| `TargetDown` | `up == 0` for a scrape target |
| `GatewayDown` | `noo_gateway_up` absent or 0 |
| `NatsDLQBacklog` | `nats_dlq_pending > 100` |
| `AuthFailureSpike` | `noo_auth_failures_5m > 20` |
| `ExecDenialSpike` | `noo_exec_denials_5m > 10` |
| `SecurityAuditSinkStalled` | both security gauges are exactly 0 while the gateway has been up more than 30 minutes — the audit sink stopped writing |

Operational alerts (node offline, quarantine, certificate expiry, disk
watermark, failed heartbeat tasks, and a stale autonomy loop — every loop
calls `record_tick`, and a monitor pages through `operator_alert` with
cooldown dedup when one goes quiet) do not go through Alertmanager: the
gateway's autonomy engine sends them to your chat channel directly. See
`GET /api/agent/loops` for current loop liveness.

### What a channel alert carries, and what stays in the logs

A chat channel is outside the trust boundary,
so an operator alert arrives as three lines and nothing else:

```text
🔌 Backend `vllm` on `node-1` is advertised in the mesh, but the node agent cannot resolve the backend's address — its door to the backend is broken, not the model, so recreating the backend will not help.
Next: `noo cluster verify node-1`
Ref: ref-3f9c2b1e0a (detail in the gateway log: `noo logs search ref-3f9c2b1e0a`)
```

- **The sentence** uses the operator's own vocabulary — node names, backend
  kinds, task names, counts — and never an address, container name, path,
  setting name, raw error or JSON body.
- **Next** is the one command that starts the investigation. It follows the
  class of failure: for an unreachable backend a DNS, TLS or network failure
  sends you to `noo cluster verify <node>` (a recreate cannot fix those),
  a refused port to the same command, a timeout or an HTTP error to that
  backend's logs.
- **Ref** is on the gateway's `operator_alert` log line together with the
  full detail — the upstream error, the address that was dialled, the proxy's
  body. `noo logs search ref-…` finds it.

The `events.ops.<kind>` stream carries the same channel text as `message`
plus `detail` and `ref`, for consumers inside the boundary.

A user whose message fails in a channel gets the same treatment: `I couldn't
answer that — reference ref-…`, with the error on the `channel_error_reply`
log line under that reference.

## Grafana

Provisioning lives in `configs/grafana/`: two datasources
(`prometheus.yml` over HTTPS with the PKI client cert, `loki.yml`), the
dashboard provider (`dashboards/dashboard.yml`, refreshed from disk every
10 seconds, UI edits allowed) and one dashboard,
`dashboards/cluster-overview.json` ("PAI Cluster Overview", 30-second
refresh). Its node-exporter, nvidia and `noo_node_load` panels populate
from the scrapes above; the panels that query `noo_cluster_*` and
`noo_node_vram_gb` / `noo_node_backends_running` / `noo_node_tier` are
populated by the same cluster collector described in the metrics table
above (`gateway-rust/src/routes/core.rs`). `noo cluster status` shows the
same underlying counts from the CLI.

Grafana serves HTTPS on `:3000` with its own service certificate from the
cluster PKI (`services/grafana/service.crt`; `GF_SERVER_PROTOCOL=https`),
and mounts that leaf plus `ca.crt` — not the PKI directory, which would have
handed a dashboard server the gateway's private key. On a tailnet
controller, `tailscale serve` is the only thing that dials that port from
outside the compose network: it connects to `https://127.0.0.1:3000` and
checks the leaf against the cluster CA in the OS trust store, as it does
for the console's `/` mapping. The gateway still reaches Grafana at
`https://grafana:3000` on the compose network, for single sign-on and the
data-source check.

### Opening Grafana: noomesh accounts, no Grafana password

Grafana logs people in with their **noomesh account**. In the console's
Observe panel, **Open Grafana** asks the gateway for a session
(`POST /api/monitoring/grafana-session`) and opens Grafana in a new tab with
it. There is no Grafana login form and no sign-out menu; the only way in is
that button (or the same route from a script, with a login token).

What the gateway does on each click:

- re-reads your account from `noo_users` — a **disabled or deleted account
  is refused** on the spot (403), whatever login token the browser still
  holds;
- takes your **live** tier (never the access token's claim) and mints an
  ES256 token for it with a dedicated key pair, `sso/grafana.key` under the
  PKI directory (`noo security pki issue-sso-key`; `noo onboard` issues it).
  Grafana verifies it with `sso/grafana.pub`, the one `sso/` file it mounts;
- writes one audit row, `grafana_session_issued`.

The gateway picks the org role from one table, `GRAFANA_ORG_ROLES` in
`gateway-rust/src/auth.rs`: **admin → Admin, operator → Editor, user →
Viewer**. That table is the place to tighten the mapping: drop a row and
that tier is refused. The role travels in the token, and Grafana re-applies
it on **every request** (strict), so a demotion in noomesh takes effect at
the next click. Nobody becomes a Grafana *server* admin this way.

What each role can do:
- **User (Viewer).** Sees dashboards only: it cannot edit or save them,
  open Explore, or change data sources or org settings
  (`viewers_can_edit = false`). Its queries are held to the provisioned
  dashboards' own at the gateway (below): a panel renders, a query it
  wrote itself is refused, and it reads no logs.
- **Operator (Editor).** Edits dashboards and alert rules, and uses Explore.
- **Admin.** Manages the org.

To limit *which* dashboards Viewers see, use Grafana folder permissions.
A 403 from Open Grafana always says why, and which tiers open Grafana.

**Data sources go through the gateway.** In open-source Grafana every user,
a Viewer included, can `POST /api/ds/query` with a query of its own; no
Grafana setting closes that. So Grafana's Prometheus and Loki data sources
(`configs/grafana/datasources/*.yml`) dial the gateway at
`https://gateway:8080/api/grafana-ds/{prometheus,loki}`, presenting
Grafana's service leaf, and the gateway decides each query:

- **Who.** Only Grafana's leaf opens `/api/grafana-ds/*`; no login token
  does. Grafana sends the signed-in login as `X-Grafana-User`
  (`[dataproxy] send_user_header = true`) and overwrites any value the
  browser sent; the gateway believes it from that leaf alone and re-reads
  the account's **live** tier (cached 10 s). A disabled account's panels go
  blank within seconds, not at the end of its Grafana session.
- **Operator, admin.** The Prometheus and Loki read APIs. Never an admin,
  write, delete or tail endpoint.
- **User (Viewer).** Only a query that is byte-for-byte one of the
  provisioned dashboards' panel expressions (`configs/grafana/dashboards/`,
  compiled into the gateway), plus their template variables' value lists.
  No series or label listing, and **no Loki**. A panel an operator adds in
  Grafana's UI renders for operators only until it lands in the provisioned
  file. Refusals are `403` with a sentence, logged as `grafana_ds_refused`.
- **Grafana with no user.** A Grafana-managed alert rule evaluates with no
  `X-Grafana-User`, so it gets the read-only policy: a rule on any other
  query errors. Alerting proper is Prometheus rules and Alertmanager.
  Public (shared) dashboards are off (`[public_dashboards] enabled = false`).

**Read-only Viewers fail closed.** A read-only account opens Grafana only
when both of these hold. Otherwise Open Grafana answers 403 with the reason;
operators and admins are not affected.

- The gateway's compose file declares `NOO_GRAFANA_DS_VIA_GATEWAY=1`. The
  compose file ships with the same CLI as `configs/grafana/`, so a stack
  rolled by an older `noo` (whose Grafana configs still dial Prometheus and
  Loki directly) lacks it.
- The running Grafana reports both data sources pointing at the gateway and
  shared dashboards off. The gateway asks Grafana itself as
  `noo.gateway-probe`, a Viewer user Grafana creates on first use. A good
  answer is cached for 60 s and a bad one for 15 s.

The fix in both cases is `noo upgrade --all` with the current CLI.

Each person has their own rate-limit bucket (`svc:grafana:<login>`), since
every Grafana user reaches the gateway from Grafana's one address. The
`grafana door` row of `noo cluster verify --controller` FAILs when a data
source dials Prometheus or Loki directly, or when either `grafana.ini`
switch above is off.

**The 5-minute bound.** Grafana's JWT auth is stateless: the token *is* the
session, and it lasts `NOO_GRAFANA_SESSION_TTL` minutes (5 by default,
60 at most). No Grafana session outlives it — a disabled account's open tab
dies at `expires_at`. It is shorter than the console's own 15-minute login
token on purpose: the token travels in the URL (`?auth_token=`, Grafana's
`url_login`), because a browser navigation cannot set the `X-JWT-Assertion`
header and the console sends the person to Grafana's own origin, not through
the gateway — so there is no proxy hop that could carry it in a header or a
cookie instead. Five minutes is the shortest session that is still usable,
and it bounds how long a token left in browser history, a `Referer` or an
access log works. When the tab expires, Grafana sends it to its `/login`. On a tailnet
controller that leads back to the console, which opens Grafana again with a
fresh token. On a `local` controller Grafana shows its login-disabled page,
and you click **Open Grafana** again. The token travels in the tab's URL
(`?auth_token=`), so it sits in browser history for those minutes; it is
worth nothing at the gateway, which refuses it by audience.

**What it needs.** `GRAFANA_ROOT_URL` set to the URL the *browser* uses
together with `NOO_GRAFANA_BIND_ADDR` publishing it there, and the key pair.
`noo onboard` writes both from `NOO_BIND_MODE` and `noo
upgrade --stack` fills them on an install that has none, with one line
saying so. Missing either, the button answers 503 naming the fix; `noo
cluster verify --controller` has a `grafana sso` row for the key pair and a
`grafana door` row that FAILs when the URL is unset, the running gateway
predates it, Grafana has a login of its own, Grafana calls home (below), a
data source skips the gateway, or its port is published wider than loopback
or the tailnet. It WARNs when a bookmark of the tailnet door would dead-end. Rotating the key
(`issue-sso-key --force`) logs every open Grafana tab out at once and needs
the gateway and Grafana recreated together (`noo stack restart --force`);
`pki rotate-all` never touches it.

**No phone-home.** By default Grafana contacts grafana.com: it reports
usage, checks for new Grafana and plugin versions (the "New version
available!" line), and loads its news feed, plugin catalog and signing
keys. `grafana.ini` turns each of these off: the `[analytics]` switches,
`[news]`, `[snapshots] external_enabled`, `[security] disable_gravatar`,
plugin admin, key retrieval and preinstall, and `[cloud_migration]`. The
catalog and angular-detection calls have no switch, so `[grafana_com]
api_url` points them at a closed port on Grafana's own loopback. With
12.4.11 we captured Grafana's DNS lookups and outbound connections: the
defaults reached grafana.com and storage.googleapis.com within a minute,
and the shipped file reached nothing. The `grafana door` row FAILs if any
of these settings is back on in the running checkout's `grafana.ini`, so a
stale file is visible. `noo upgrade --stack` lays the release's file down
and recreates Grafana.

**No local login.** `grafana.ini` sets `[auth] disable_login = true` and
`[auth.basic] enabled = false`, so Grafana checks no username or password
anywhere — not the form, not `POST /login`, not `curl -u`. With only the form off,
basic auth would still log the local admin in as the
Grafana server admin. The admin account still exists, seeded from
`GRAFANA_PASSWORD` (sops, delivered to Grafana as a file) so it is never
`admin/admin`; it logs in nowhere. With the gateway down, Grafana is down
for people too; `docker exec noo-grafana grafana cli admin …` reaches the
server-admin account from the controller itself.

## Logs

Container logs are capped at 3×50 MB each by the compose logging defaults
and shipped to Loki by the node-agent on each host — on the controller by
the controller's own agent, which runs as a host process in worker mode
like any node's — labelled `node`, `source` (`docker` / `journal` /
`file`), `name`, `stream`, `level` and `compose_service`
([below](#every-node-ships-its-logs)). promtail and its read-only
`docker-socket-proxy` did this job on the controller until fleet logging
shipped from every node; nothing in the stack holds the Docker socket now.

### Reviewing logs: three doors, one answer

Every log line the fleet produces lands in Loki (fleet logging plan): the
node-agent on each node ships container output, its own ring and the host
units, and the gateway relays the batch with the node's **verified** id.
Three doors read it, all Operator/Admin only (`auth::LOGS_READ_PREFIX`; a
User-tier login gets 403 on every `/api/logs/*` route):

| door | verbs |
| --- | --- |
| CLI | `noo logs errors`, `noo logs tail`, `noo logs search` (+ `containers`, `query`, `status`) |
| MCP, operator door only | `noo_logs_errors`, `noo_logs_tail`, `noo_logs_search` |
| HTTP | `POST /api/logs/errors`, `/api/logs/tail`, `/api/logs/search` (+ the GETs) |

The gateway builds the LogQL from typed fields; nobody at these doors
writes LogQL (`noo logs query` / `GET /api/logs/query` is the raw door,
also operator-only, when you want to). `errors` and `tail` are answered
from Loki when it is configured and up and from a `docker logs` scan
through the node-agents when it is not — **every answer says which**
(`"backend": "loki"` or `"agent-scan"`; the CLI footer reads `via loki` or
`via agent scan (Loki not reachable: …)`; the MCP text says `PARTIAL VIEW`).
A scan reaches only the containers the node-agents could list, and only
their json-file tail; it is not the fleet view and is never presented as
one. `search` has no fallback: Loki down is a 503 with the reason.

### The label vocabulary

The shipper attaches a fixed, low-cardinality label set; `logs_ingest.rs`
drops anything else and overwrites `node`:

| label | values |
| --- | --- |
| `node` | the node id **as the gateway verified it** (`node-1`, `controller-1`); never what the body claimed |
| `source` | `docker` (a container), `journal` (a host unit), `self` (the node-agent's own ring), `file` (macOS plist logs) |
| `name` | the container (`noo-gateway`, `noo-vllm`, `noo-postgres`; the bare form `gateway` is accepted by the log tools and matches the same streams) or the unit (`noo-hostd`, `noo-harness`, `docker`) |
| `stream` | `stdout` / `stderr` |
| `level` | `debug` / `info` / `warn` / `error` / `unknown` — extracted from the line by a small matcher; a line the matcher cannot read stays `unknown` |
| `compose_service` | the compose service label, controller containers only |

`--name` / `name` is an exact match on that label; `--container` /
`container` is a substring match (`noo-gateway` and `gateway` both find
`gateway`). `--since` / `--until` take a duration ago (`30m`, `2h`, `1d`)
or an RFC 3339 time; the window is capped at 7 days and the answer says
`range_clamped` when it was moved; `limit` is capped at 2000.

### Examples

```sh
# Every `noo logs` verb and every /api/logs/* route needs an Operator or Admin login.

# "What happened on node-1 at 14:02?" — the five minutes around it, oldest first
noo logs search --node node-1 --since 2026-09-28T14:00:00Z --until 2026-09-28T14:05:00Z

# "Show me every error across the fleet in the last hour"
noo logs errors --since 1h                      # Loki: {level=~"error|warn"}, every node
noo logs search --level error --since 1h        # the same through search (errors only, no warns)

# One node's warnings, one container's errors
noo logs errors --node node-1 --since 2h
noo logs errors -c vllm --since 30m
noo logs search "CUDA error" --name vllm --since 1d    # free text = a |= line filter
noo logs search --source journal --node node-1 --since 6h   # host units only (hostd, harness, agent, fetch, docker, tailscaled)

# A tail: oldest first, from Loki when up, else that container's docker logs
noo logs tail gateway -l 200                    # optionally -n <node>, --since 30m, --grep 502
noo logs tail --name noo-hostd -n node-1 --since 1h   # a host unit (journal), by its label

noo logs containers                             # containers on every node, via the node-agents
noo logs status                                 # Loki reachable?
noo logs query '{node="node-1", level="error"} |= "CUDA"' -l 50   # raw LogQL, when you want it
noo logs search --newest -q '{compose_service="gateway"} |= "backend_resolved"'  # raw LogQL via search: capped like everything else
```

Through the MCP operator door the same questions are
`noo_logs_search(node="node-1", since="2026-09-28T14:00:00Z",
until="2026-09-28T14:05:00Z")` and `noo_logs_errors(since="1h")`; the
tool text ends with the backend line, so the agent knows whether it read
the fleet or a scan.

**How node logs arrive.** A node never talks to Loki. Its node-agent pushes
batches of its own lines to the gateway at
`POST /api/cluster/nodes/<its own id>/logs` (a node route: the fleet
credential plus, where mTLS is on, the node's client certificate — an
operator login or a stack service is refused), and the gateway relays them
to Loki over the stack network with its own certificate. The gateway
**overwrites the `node` label with the verified node id**, so `{node="node-1"}`
in Loki was pushed by node-1 and by nothing else; it keeps only the fixed
label set `source`, `name`, `stream`, `level`, `compose_service` and drops
anything else, caps a push at 4 MB (gzip accepted) and each node at
8 MB / 120 pushes a minute (`NOO_LOGS_INGEST_BYTES_PER_MIN`,
`NOO_LOGS_INGEST_REQUESTS_PER_MIN`), and buffers nothing: while Loki is
down it answers 503 and the node keeps its batch. `noo_logs_ingest_lines_total`,
`noo_logs_ingest_bytes_total`, `noo_logs_ingest_refused_total{reason}` and
`noo_logs_last_seen_unix` on `/metrics` say, per node, what arrived and when.
The shipper inside the node-agent calls this route from every node; see
"Every node ships its logs" below.

`search`, `query` and `status` need Loki; `errors` and `tail` read Loki
when it answers and fall back to a per-node Docker scan when it does not
(the answer names its backend either way); `containers` always reads the
node-agents. For Loki the gateway reads
`NOO_LOKI_URL`, which compose sets to `https://loki:3100` (the compose
network name; override in `.env`, or `services.loki_url` in `noomesh.yaml`).
The gateway dials it with its own leaf over mTLS. `noo cluster verify
--controller` carries three rows for it: `loki` (the gateway reaches it —
FAIL on "not configured", which is exactly how an install answers
when compose does not hand the gateway `LOKI_URL`),
`loki listener` (the shipped config requires a client certificate from
every caller and compose publishes no port) and `loki at rest` (below).

**Loki's first `/ready` is not a warm-up miss.** Loki's `/ready` asks the
ingester's ring lifecycler (dskit `Lifecycler.CheckReady`), which honours
`ingester.lifecycler.min_ready_duration` (default 15s). Its clock starts
the first time `/ready` is *called* and finds the ring healthy, not when
the ring became healthy, and it answers 503 `Ingester not ready: waiting
for 15s after being ready` until 15s have passed since that call. Nothing
polls Loki's `/ready` (its compose healthcheck is disabled: the image is
distroless and the listener is mTLS-only), so with the default the first
`noo cluster verify` after a stack recreate always failed the `loki` row,
however long Loki had been up (it could be ingesting, with one miss at the
moment verify ran). The shipped
`monitoring/loki/loki-config-tls.yml` sets it to `0s`: a single-binary
Loki on an in-memory ring has no peer to wait for. If that 503 body comes
back, check the config Loki actually loaded before chasing the network.

### Retention and disk

`NOO_LOKI_RETENTION` in `.env` (default `720h`, 30 days; a multiple of
24h) is how long Loki keeps lines, and also the oldest line it accepts
(`reject_old_samples_max_age` is the same value, so a node that buffered
logs offline can replay them). Compose passes it to the container and Loki
expands it itself (`-config.expand-env=true`). Measured on one controller: ~43 MB/day of container output, almost all of it
the gateway, and a budget of ~20 MB/day per inference node; Loki's chunks
compress text 5–10×, so on disk the fleet writes roughly **15–30 MB/day**:

| `NOO_LOKI_RETENTION` | on disk (worst case) |
|---|---|
| `168h` (7 days) | ≈ 0.2 GB |
| `720h` (30 days, default) | ≈ 0.9 GB |
| `2160h` (90 days) | ≈ 2.7 GB |

Change it in `.env`, then `noo stack restart --force loki`.

### At rest

Loki's filesystem store writes chunks and its index under
`${NOO_DATA_ROOT}/loki` **in the clear** — Loki has no chunk-level
encryption for the filesystem object store (its encryption options exist
for S3). In transit everything is mTLS (node-agent → gateway → Loki,
Grafana → Loki). What protects the logs on disk is the host's disk
encryption (planned, i10a: a LUKS2 volume for the data root, unlocked by the
machine's TPM; it covers a stolen drive, not root on the running machine):
`noo cluster verify
--controller` reports `loki at rest` as OK only when the mount holding the
data root sits on a dm-crypt device, WARNs when it does not, and says
"could not determine" when it cannot tell — it never assumes. Access to
the files is root on the controller, the same as for Postgres.

`containers` reads Docker through the gateway and the node-agents; so do
`errors` and `tail` when Loki is not there. `search`, `query` and `status`
need Loki: `services.loki_url` in `noomesh.yaml` (`NOO_LOKI_URL`;
`https://loki:3100` from inside the stack network). Empty means `noo logs
status` reports Loki as not configured even though the `noo-loki` container
is running, `noo logs search` answers 503, and `errors`/`tail` say
`via agent scan`.

### Every node ships its logs

Each node-agent (workers and the controller's own) ships to Loki through
the gateway: `POST /api/cluster/nodes/<node>/logs`, presenting the node
leaf and the cluster token exactly as its heartbeat does, gzip JSON. The
gateway verifies the node, **overwrites the `node` label with the verified
id** (a node cannot write another node's streams), and forwards to Loki over
the stack's mTLS. Loki is never published; nothing on a node dials it.

What ships, with the fixed label set (`node`, `source`, `name`, `stream`,
`level`, and `compose_service` when a container carries the compose label):

| `source` | what | `name` | `stream` |
|---|---|---|---|
| `docker` | stdout/stderr of every compose-labelled or `noo-` container on the node, followed live from "now" (never a container's history) | container name | `stdout` / `stderr` |
| `journal` | the journal of `noo-node-agent`, `noo-hostd`, `noo-fetch`, `noo-harness` and `docker` (Linux) | unit name | `journal` |
| `file` | the launchd log files on macOS (`/var/log/noo-hostd.log`, `/tmp/noomesh-harness.log`) | `noo-hostd` / `noo-harness` | `stdout` |

`level` is `debug`, `info`, `warn`, `error` or `unknown`, read from the
line (JSON `"level"`, `level=`, a leading `WARN`/`ERROR`/…; journal records
fall back to their syslog priority). Everything else stays in the line —
`{node="node-1", level="error"} |= "vllm"` is the shape of a query.

The agent cannot read the journal (it is unprivileged and the journal group
would open every journal on the box), so `noo-hostd` runs the read-only
`journal-follow` op on its behalf: `journalctl --output=json --follow` for
the allowlisted units, written to `/var/lib/noo-node-agent/spool/journal.follow`
(rotated at 16 MB, one predecessor kept), which the agent tails. hostd has no
network; the agent has no journal. A hostd older than the op reports
`hostd predates journal-follow` in the heartbeat and only container logs
ship until `noo upgrade --nodes` delivers both binaries.

Delivery: batches flush every 2 s or 1000 lines, split under 3 MB, 64
streams and 20 000 values. The gateway's answer decides: 204 accepted;
400/413 (malformed, too large, Loki refused) drops that batch and is
logged once per reason per 5 minutes; 401/403 (a credential problem),
429 (`Retry-After` honoured — the gateway allows 8 MB and 120 pushes per
node per minute), 503 (Loki away) or no answer at all keeps the batch and
retries with backoff (1 s → 60 s, jitter); a refusal body's `retry` flag
is believed when present. Memory holds 10 000 lines / 8 MB, then a
disk spill under `/var/lib/noo-node-agent/logship` (≤ 2 × 64 MB, oldest
lines dropped past that and counted) carries an outage; nothing is lost to
an agent restart.

Operator switches, in `/etc/noo-node-agent.env` on the node:

| variable | effect |
|---|---|
| `NOO_LOG_SHIP=0` | shipping off on this node (default: on whenever the agent has its TLS material) |
| `NOO_LOG_SHIP_UNITS=noo-hostd,docker` | journal units to request; hostd still enforces its own allowlist |
| `NOO_AGENT_STATE=/var/lib/noo-node-agent` | where the spill and tail offsets live |

Judging it: every heartbeat carries `log_ship` —
`{enabled, queued, shipped_total, dropped_total, redacted_total,
last_accepted_unix, last_error, route_ready, spill_pending, journal}`.
`enabled:false` names its reason in `last_error` (switched off, or no TLS
material), so "off by choice" never looks like "an agent too old to ship".

### What gets redacted

Any service can print a credential — a request error renders the URL it
failed on, a startup banner echoes its environment, a curl in a heartbeat
action prints the header it sent. Once shipped, such a line is no longer one
`docker logs` away: it sits in the node's spill file and in Loki for the
retention window, readable by every operator. So the shipper scrubs every
line **at intake**, before its memory queue, its spill and the wire, and the
gateway runs the **same table** again on ingest (for an agent older than the
scrubber). Each match becomes `<redacted:KIND>` and nothing else of the line
changes; nothing of the secret is kept, not a prefix, not a length. The
shipper counts what it scrubbed in the heartbeat's `log_ship.redacted_total`
and logs a per-batch line at debug; the gateway counts what the shipper
*missed* per node in `noo_logs_ingest_redacted_total{node}` on `/metrics` —
a steady non-zero there names an agent that predates the scrubber.

The table, in the order it runs (the order matters: a PEM body is taken
before a `private_key=` pair could half-eat it, and the header and pair
shapes run before the specific ones so a placeholder is never re-wrapped):

| kind | shape |
|---|---|
| `pem` | `-----BEGIN … PRIVATE KEY-----` … `-----END … PRIVATE KEY-----` on one line (escaped newlines); the body goes, the markers stay. Without an END marker, the rest of the line goes |
| `pem-body` | a line that is **nothing but** 64 base64 characters (70 for OpenSSH) and not a hex digest: one line of a key body printed one per line (`cat key.pem`), whether each is its own log entry or a line of one multi-line message |
| `pem-tail` | the key body's short **last** line, recognised by context: the line straight after a `pem-body` line (within one message, or the next entry of the same container/unit and stream) that is nothing but base64 and carries `=` padding, a digit, `+` or `/` — or any such line with an `-----END` marker right after it. A plain word after a key body (`done`) is left alone |
| `age-key` | `AGE-SECRET-KEY-1…` <!-- leak-ok: the prefix of the shape, not a key --> |
| `authorization` | the value of an `Authorization:` header (`=` or `:`, quoted or not); the scheme word (`Bearer`, `Basic`, …) stays |
| `bearer` | `Bearer <16+ chars>` anywhere |
| `cookie` | the value of a `Cookie:` / `Set-Cookie:` header: its `name=value` pairs and attributes, up to the first unjoined space |
| `kv` | a key **ending** in `password`, `passwd`, `pwd`, `secret`, `token`, `api_key`/`apikey`/`api-key`, `access_key`, `private_key` or `signing_key` (case-insensitive: `NOO_CLUSTER_SECRET`, `refresh_token`, `X-Api-Key`) followed by `=value`, `: value`, or a JSON/YAML quoted value. `tokens=`, `token_count=`, `secret_name=`, `password_reset=` are not matched. Also any `NOO_…_KEY` (so `NOO_GATEWAY_KEY`, `NOO_AUDIT_HMAC_KEY`; a `NOO_TLS_KEY` path goes too), and `key = value` with whitespace **before** the `=` (TOML/INI); `password= next` with nothing after the `=` is still left alone |
| `dsn` | `scheme://user:PASSWORD@host` — the user stays, the password goes |
| `userinfo` | `user:PASSWORD@host` without a scheme (a proxy setting); the user stays. `name:tag@sha256:…` (an image pinned by digest) is not one |
| `pgpass` | a `.pgpass` line alone on its line, `host:port:db:user:PASSWORD` (port digits or `*`) |
| `redis-auth` | Redis `AUTH <pass>` / `AUTH <user> <pass>` at a prompt or the start of a line, MONITOR's `"AUTH" "…"`, `requirepass`/`masterauth` as a config line, a `--flag` or `CONFIG SET`, `redis-cli -a`/`--pass` |
| `cluster-token` | `<actor>:<unix ts>:<32 or 64 hex>`, the cluster HMAC bearer every node and the gateway mint |
| `service-key` | `noo-sk-…`, as `noo security service-key issue` prints it |
| `addon-key` | `noo-ak-…`, the caller key the gateway presents to an add-on (minted at each gateway start). The same 64 hex without the prefix is an image digest and is left alone |
| `bootstrap-token` | `noo-bt-…`, a node-enrolment token as `noo cluster bootstrap-token create` prints it |
| `refresh-token` | `noo-rt-…`, the `noo_refresh` session value the gateway sets at login and rotates on every refresh |
| `jwt` | `eyJ…` `.` `…` `.` `…` (three base64url segments) |
| `telegram-token` | `<8–10 digits>:<35 chars>` (`/bot<token>/` in a Telegram URL) |
| `api-key` | `sk-…` (OpenAI-style, 20+ chars) |
| `tailscale-key` | `tskey-…` |
| `tailscale-login-url` | `https://login.tailscale.com/a/…` (tailscaled's one-time login link) |
| `github-token` | `ghp_`/`gho_`/`ghu_`/`ghs_`/`ghr_` + 20+ chars, `github_pat_…` |
| `aws-key` | `AKIA`/`ASIA` + 16 upper-case alphanumerics (an access key id) |
| `bcrypt` | `$2a$NN$` + 53 (a NATS `users.conf` digest: not a secret, but a verifier anyone can guess against offline) |
| `aws-secret` | a bare run of **exactly** 40 standard-base64 characters with an upper, a lower, a digit and a non-hex character, no `-`/`_`/`=` beside it and not opening with `/` (an AWS secret access key without its `aws_secret_access_key=`). A git SHA has no upper case and is left alone |
| `opaque-token` | a bare run of **exactly** 43 base64url characters with an upper, a lower and a digit, no `+`/`=` beside it: 32 random bytes unpadded — a bootstrap or refresh token minted before the `noo-bt-`/`noo-rt-` prefixes, `token_urlsafe(32)` |

Redaction is **shape-based**: it needs no copy of any secret, so a rotated
key, a second bot or a credential this node never held are all caught — and
a secret in a shape the table does not name **ships**. The add-on caller key
from a gateway released before the `noo-ak-` prefix (64 hex, no prefix,
indistinguishable from an image digest) is not recognised, nor is a PEM
body's last line made only of letters, unpadded, with no END marker after
it (a few percent of keys). The two bare shapes (`aws-secret`,
`opaque-token`) trade the other way: a 40/43-character mixed-case
identifier with a digit in it is redacted from a log line though it is not
a secret.

The same table also scrubs every message the assistant sends over a
**channel** (Telegram, Google Chat, …) — except those two bare shapes,
which a reply a person reads skips: an identifier the user asked about
comes back intact, while every prefixed or structured credential
(`noo-rt-…`, `noo-sk-…`, a JWT, a PEM, a header) is still redacted.
Platform-written alerts run the full table.
The two tables (`node-agent-go/internal/logship/redact.go`,
`gateway-rust/src/redact.rs`) are held equal by one corpus
(`tests/fixtures/redaction_corpus.json`), which also carries the lines that
must **not** be touched — image digests, UUIDs, timestamps, `level=info`,
URLs without a password — so a shape that grows greedy fails a unit test.
Add a shape by adding it to both tables, a case to the corpus, and a row
here; `tests/test_log_redaction_parity.py` holds the four in step.

### Verifying it: the `cluster verify` rows

`noo cluster verify <node>` and `noo cluster verify --controller` carry
the rows below (phase 6). A row's remedy is printed beside it when it
fails; what each verdict means:

| row | where | OK | WARN | FAIL | remedy |
|---|---|---|---|---|---|
| `log shipper` | per node, from the heartbeat's `log_ship` | `shipped N, last accepted <age> ago` (or `enabled, nothing to ship yet`); an agent that has not reported it yet also reads OK, with the wording "predates the shipper" once its heartbeat is old | off by choice (`last_error` names why: `NOO_LOG_SHIP=0` or no TLS material); the gateway's ingest route not answering (`route_ready:false`, an older gateway); nothing accepted yet with lines queued and no error; the host journal not following (the string carries its own fix, e.g. `hostd predates journal-follow`) | `shipping stalled since <age>: <last_error>` — enabled, lines queued or spilled, nothing accepted for 15 min; or nothing ever accepted and the gateway refuses | `noo cluster logs <node> agent`, then `noo logs status` on the controller; for "off": `NOO_LOG_SHIP` in `/etc/noo-node-agent.env` or `noo cluster provision <node>`; for the route: `noo upgrade --stack`; for the journal: `noo upgrade --nodes` (or `noo cluster provision <node> --wait` for one node) |
| `logs last seen` | controller, from the gateway's `noo_logs_last_seen_unix{node}` gauge on `/metrics` | `N node(s) shipping, oldest accepted <age> ago`; offline nodes are skipped and named | `no logs ever received from <node>` (the roll has not reached it, or shipping is off there; the gauge is in memory, so a just-restarted gateway reads this way for a minute); `/metrics` not readable | an ONLINE node whose last accepted push is over 15 min old | `noo cluster verify <node>` (its `log shipper` row says why), then `noo cluster logs <node> agent`; for "never": `noo upgrade --nodes` (or `noo cluster provision <node> --wait`) |
| `logs access` | controller | an anonymous `GET /api/logs/query` is refused (401/403) | the probe got neither a refusal nor a body, or the gateway did not answer | the anonymous GET answered 2xx: the log doors are open to anyone who can reach the port | `noo upgrade --stack` to a gateway with `auth::LOGS_READ_PREFIX` |

`logs access` says in its own detail what it did **not** prove: the
User-tier refusal. That needs a User credential, and the verb runs as the
operator — the controller holds no User token (a kiosk's lives on the
kiosk seat; a `noo auth` session is the operator's own), and minting one
to probe with is a side effect a verify verb must not have. The User-tier
refusal is pinned in the gateway's own tests (`auth.rs
log_reads_are_operator_and_admin_only`) and probed by hand as a runbook
step: log in as a User and `noo logs status` must answer 403
("Fleet logs not arriving").

Roll order matters: the gateway image with the ingest route **first**, then
`noo upgrade --nodes`. An agent that meets a gateway without the route (404)
starts no source, logs it once and re-probes every 10 minutes — harmless in
either order, silent in the wrong one.

The controller's own lines are `{node="<controller id>", source="docker"}`
— its agent runs in worker mode on the controller host and ships exactly
as a node's does. promtail's streams (`container_name` / `node_name`, no
`source` label) stop at the retention horizon; nothing writes them since
phase 4. **After rolling to a stack without promtail**, an existing
controller keeps a `noo-promtail` and a `noo-docker-socket-proxy`
container *running*: the launcher's `up -d --force-recreate` never passes
`--remove-orphans` (only `noo stack stop` does, and a running controller
avoids that verb), so compose warns "Found orphan containers" and leaves
them be — and promtail keeps shipping duplicates until you remove it.
`noo doctor orphans` lists them; then `docker rm -f noo-promtail
noo-docker-socket-proxy` (the container prefix is `NOO_CONTAINER_PREFIX`).

## Health endpoints

| Service | Endpoint | Returns |
|---|---|---|
| gateway | `GET /health` | **Anonymous:** `status` (`healthy` / `degraded`) and the status code — HTTP 503 when Postgres or NATS is down. That is what every probe reads. **With a credential:** adds `engine`, `version`, `peers`, `dependencies` (`postgresql`, `nats`, `redis` — redis is optional) and `addons`. `noo health` authenticates and exits 5 on degraded; without a login it shows status alone and says so |
| gateway | `GET /api/cluster/status` | node counts and the node list |
| node-agent | `GET /health` on `:8081` | `{"status": "healthy", "node_id": …}` |
| vLLM | `GET /health` on `:8000` | backend health |
| llama.cpp | `GET /v1/models` on `:8085` | backend health |
| Ollama | `GET /api/tags` on `:11434` | loaded models |
| nvidia exporter | `GET /health` on `:9400` | `ok` |

## Operator playbook

| Signal | Likely cause | Action |
|---|---|---|
| `nats_dlq_pending` rising | NATS reachable but slow, or a worker subject unbound | watch — the drain runs every 30s; if it keeps rising check `noo-worker` / `noo-trellion` logs for the subject |
| `nats_dlq_abandoned > 0` | a subject failing permanently after its retry budget | `SELECT subject, last_error, attempt_count FROM noo_nats_dlq WHERE next_retry_at IS NULL AND succeeded_at IS NULL` in Postgres; fix the consumer, then the rows can be retried |
| `pages_embedding_backlog` sustained > 500 | embedder down or overloaded | find the live embedder (`PAGEINDEX_EMBEDDING_BACKEND`, default `ollama`, or a node-agent-routed embed placement) and read its logs; pause ingest until it drains. Above 5000 the autonomy loop stops scheduling embed jobs on its own |
| `temporal_extraction_errors_total` jumps | the LLM backend is down | `noo cluster status` |
| `noo_auth_failures_5m` spikes | credential guessing or a misconfigured client | `noo_security_audit` table for the source IPs; the `failed_auth_spike` autonomy location alerts at > 10 |
| `up == 0` for `noo_node_agent` | the controller's host agent is down | `systemctl status noo-node-agent` on the controller |
