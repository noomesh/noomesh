# Environment Variable Reference

Every variable listed here is read by code in this tree — the Rust gateway,
the `noo` CLI and launcher scripts, the Go node-agent and host daemon, the
Python workers, or `docker-compose.cluster.yml`. Variables nothing reads
are not listed. Most values do **not** belong in `.env`: read
[config.md — Where does a value go](config.md#where-does-a-value-go) first.
Secrets go in the secret store; topology goes in `noomesh.yaml` (each
`services.*` key names its env override); only the bootstrap flags and the
TLS switches live in `.env`.

Two repo-wide indirections apply to the tier-1 secrets below (the stack's
own trust fabric: `NOO_JWT_SECRET`, `NOO_CLUSTER_SECRET`,
`NOO_CONTROLLER_SECRET`, `NOO_NODE_AGENT_TOKEN`, `REDIS_PASSWORD`,
`NOO_AUDIT_HMAC_KEY`, the `NATS_*_PASSWORD`s, the
`NOO_*_DB_PASSWORD`s, the agent/JWKS/entitlement keys), read in ONE place
per language (`gateway-rust/src/secret_env.rs`, `noomesh.secret_env`), in
this order:

1. **`<NAME>_FILE`** (e.g. `NOO_JWT_SECRET_FILE=/run/secrets/noo_jwt_secret`)
   — the value is the file's content, minus one trailing newline. A named
   file that is unreadable or empty is a **refusal**, not "unset". This is
   what lets a multi-line PEM (`NOO_JWT_SIGNING_KEY_FILE`) arrive as
   `openssl` wrote it instead of base64 on a dotenv line.
2. **`NOO_SECRET_<NAME>`** (e.g. `NOO_SECRET_NOO_JWT_SECRET`) — the older
   prefix convention, still honoured.
3. **`<NAME>`** — the plain variable. noomesh's own containers no longer
   receive this form: compose delivers every tier-1 secret to the gateway,
   worker, redis, postgres, grafana and browser as a `/run/secrets` file
   with a `<NAME>_FILE` pointer (and `PGPASSFILE` for database passwords).
   The add-on containers still receive the plain variable until their
   images read `_FILE`. See
   [secrets.md — How secrets reach a container](../security/secrets.md#how-secrets-reach-a-container).

Setting both `<NAME>` and `<NAME>_FILE` is a compose/launcher skew, and
the gateway (preflight `secret_files`), the worker and the redis
entrypoint refuse to start on it rather than pick one. See
[secrets.md — How a service reads a secret](../security/secrets.md#how-a-service-reads-a-secret).
There is no `PAI_SECRET_*` any more — that prefix predates the `noomesh`
rename and is gone from this tree.

Check what a container actually received (the gateway image has no shell,
so `printenv` is not an option):

```bash
docker inspect noo-gateway --format '{{range .Config.Env}}{{println .}}{{end}}' | grep '^NOO_'
docker diff noo-gateway | grep /run/secrets     # which secret files it was given (names only)
```

## Bootstrap flags (`.env`, read by the launcher before anything else)

> **Add-ons are not here.** Which add-ons run is declared in `noomesh.yaml`
> under `addons:` — one map, read by the launcher to compose each enabled
> add-on's overlay file (add-ons have no compose profiles) and by
> the gateway for routing and refusals. The four flags that used to sit in
> this table (`NOO_PRO_ENABLED`, `NOO_TRELLION_ENABLED`,
> `NOO_TRELLION_INTEL_ENABLED`, `NOO_VOICE_ENABLED`) are **retired**, and
> `noo stack start` refuses to run while any of them is still in `.env`.
> See [add-ons](../getting-started/add-ons.md).

| Variable | Default | Read by | Purpose |
|---|---|---|---|
| `NOO_SECRETS_BACKEND` | `env` when unset (onboarding always writes `sops`) | `scripts/lib-secrets.sh` | `sops` decrypts `secrets/env.sops` into the launcher environment; `env` (plaintext `.env`) is retired — the launcher refuses to start it, and verify, scan and upgrade fail it ([secrets](../security/secrets.md#noo_secrets_backend)) |
| `NOO_INSTALL_MODE` | `dev` | `scripts/noomesh-start.sh` | `dist` starts from published images (`docker-compose.dist.yml`); `dev` builds from source |
| `NOO_INSTANCE`, `NOO_PORT_OFFSET` | unset, `0` | `scripts/lib-instance.sh` | a second stack on one host: compose project `noo-<instance>`, container prefix, network, and every host port shifted by the offset ([multi-instance](../getting-started/multi-instance.md)) |
| `NOO_IMAGE_PREFIX`, `NOO_IMAGE_TAG` | `ghcr.io/<owner>`, newest `stack-v*` tag | launcher, compose | which images dist mode pulls; `NOO_IMAGE_DIGEST_<IMAGE>` pins are exported from `stack.lock` |
| `NOO_<NAME>_PATH` | `../noo-<name>` (`_` in the add-on name becomes `-`) | `scripts/lib-addons.sh` `addon_overlay`, `noo security secrets` | a development checkout of a licensed add-on (`<NAME>` is its `addons:` key upper-cased, e.g. NOO_EVOLVE_PATH): its own `docker-compose.<name>.yml` is composed instead of the overlay from its signed bundle, `addons/<name>/docker-compose.yml` |
| `NOO_PULL_POLICY` | `build` in dev, `missing` in dist | launcher exports it; the trellion overlay's `pull_policy:` | whether compose builds or pulls the add-on images. Set by `NOO_INSTALL_MODE`, not by hand |
| `NOO_DATA_ROOT` | — | compose, `lib-instance.sh` | host root for every stateful volume; instances must use `<root>/instances/<name>` |
| `NOO_BIND_MODE` | unset (loopback) | `scripts/lib-bind-addr.sh`, `noo cluster verify` | where the published ports bind: `tailnet` (auto-detect this box's 100.64.0.0/10 address — recommended for a controller), `local` (`127.0.0.1`), `all` (`0.0.0.0`) or a literal IP. Sets `NOO_BIND_ADDR`, `NOO_GRAFANA_BIND_ADDR` and `GRAFANA_ROOT_URL`; apply with `noo stack restart --force` |
| `COMPOSE_PROFILES` | unset | the launcher (start, restart, rebuild), which passes each as `--profile` | profiles enabled beside the launcher's own `--profile` flags (compose alone ignores this variable once a flag is given). Declare it in `noomesh.yaml` `compose_env`, not `.env`. Today's one operator use is `embed-cpu` (the optional CPU-only embedder `ollama-embed-cpu` + its mTLS sidecar; the launcher derives its door for `PAGEINDEX_EMBEDDING_EXTRA_URLS`, so never type it; embed-capacity runbook); `sensors` is the other. Keep any profiles already listed. A profile only gates a compose service — it is not an add-on (add-ons are the `addons:` map) |

## Transport security (`.env`, written by `noo onboard`)

| Variable | Read by | Purpose |
|---|---|---|
| `NOO_TLS_CA`, `NOO_TLS_CERT`, `NOO_TLS_KEY` | gateway (`tls.rs`, `state.rs`), node-agent (`internal/config`), `noo` CLI (`http.rs`), workers | certificate material. **The gateway requires all three**: it serves HTTPS only and refuses to start (naming each unset, missing or unreadable file, and `noo onboard --only enrollment` as the remedy) when any is unusable — there is no plaintext listener (`tests/test_gateway_refuses_plaintext.py`). The gateway auto-enables Postgres `sslmode=verify-ca` and NATS TLS when `NOO_TLS_CA` is set. **A set-but-unusable `NOO_TLS_CA` is fatal everywhere**: the agent refuses to start, the CLI refuses the request (exit 3, `tls_untrusted`), and a `tls://` NATS URL whose config cannot be built is a hard error rather than a plaintext connect. With `NOO_TLS_CA` unset the CLI falls back to the cluster CA at `$NOO_PKI_DIR/ca.crt` or `/etc/noo/pki/ca.crt`, then the platform verifier — never to an unverified connection |
| `NOO_REPO_ROOT` | `noo` CLI (`envfile.rs`) | declares which checkout is this box's install. On an **enrolled** box (`/etc/noo/controller-url` exists) `NOO_GATEWAY_URL`, `CONTROLLER_URL`, `NOO_TLS_CA`, `NOO_TLS_CERT` and `NOO_TLS_KEY` are read from a config file only when the repo root was declared this way (or is the standalone install home) — not from whichever checkout the cwd happens to be inside. `noo auth status` names any file whose keys were dropped |
| `NOO_MTLS_GATEWAY` | gateway | **Enforced by default.** Unset or empty means ON whenever `NOO_TLS_CA` names an existing file (and the gateway boots with a loud warning if there is no usable CA). Enforcing means: a cluster token whose actor disagrees with the presented client certificate is refused, and so is a fleet-secret token that arrives with NO node certificate (only this host's own loopback is exempt), so a node cannot name another node by leaving its certificate out; the refusals are counted as `fleet_secret_off_node_refused` / `fleet_token_no_cert_refused`. A client with no certificate still connects — the dashboard, CLI and MCP doors share this listener, and they do not use the fleet token — but a certificate that is not signed by the cluster CA is rejected at the handshake. `true/1/yes/on` is the same as unset but the gateway refuses to start if `NOO_TLS_CA` is unset or missing. `false/0/no/off` is the explicit opt-out: the gateway logs a warning at every boot that a node can then present a fleet token naming another node; `noo cluster verify` warns too (remedy: remove `NOO_MTLS_GATEWAY=false` from `.env` and recreate the gateway). Anything else is read as unset |
| `NOO_MTLS_NODES` | node-agent | **retired**. :8081 is mTLS-only — a cluster-CA client certificate is required at the handshake, and an agent without `NOO_TLS_CA`/`NOO_TLS_CERT`/`NOO_TLS_KEY` refuses to start (no plaintext listener). A stale `false`/`0`/`no`/`off` line is a startup **refusal** naming the line to remove; any other value is inert. Remove it from `/etc/noo-node-agent.env` / `.env` |
| `NOO_NATS_TLS`, `NOO_REDIS_TLS` | workers, compose | transport encryption on the Python side and for the service containers. `NOO_REDIS_TLS` is **no longer read by the Python Redis helpers** (`noomesh/cache.py`): the Redis service is TLS-only, so a `redis://` URL is refused with the reason and the CA/leaf kwargs are always applied; onboarding still writes it for the containers |
| `NATS_GATEWAY_USER` / `NATS_GATEWAY_PASSWORD` | gateway (`state.rs`) | the gateway's own bus credential. Unset ⇒ the gateway **refuses to connect** |
| `NATS_WORKER_USER` / `NATS_WORKER_PASSWORD` | noo-worker; trellion and trellion-intel only as the one-release fallback (`cluster/messaging.py`) | the worker bus credential. Unset ⇒ the pool **refuses to connect** |
| `NATS_ADDON_USER` / `NATS_ADDON_PASSWORD` (`_FILE`) | trellion (`trellion`), trellion-intel (`trellion_intel`) | an add-on's OWN bus principal: subscribe on exactly its subjects, reply on `_INBOX_gw.<name>.>`. The user is a literal in the add-on's overlay; the password file is delivered only when the store holds `NATS_TRELLION_PASSWORD` / `NATS_TRELLION_INTEL_PASSWORD`. No password (or a user naming another add-on), the pool presents the worker pair and logs `nats_addon_principal_fallback` |
| `NATS_NODE_USER` / `NATS_NODE_PASSWORD` | node-agent (`internal/messaging`), node harness | that node's bus credential, delivered over the rail. Unset ⇒ the agent **refuses to connect** |
| `NATS_USER` / `NATS_PASSWORD` | **retired** — nothing reads them, no compose service is handed them, the server no longer defines the shared user | the shared fleet credential, retired. A client whose own pair is unset refuses and names the verb that mints it; a still-set `NATS_USER` only makes that refusal say "retired". Remove the stored values by hand (`noo security scan` / `secrets audit` name them) |
| `NOO_NATS_LEGACY_SHARED_CREDS` | **retired** | was the posture bridge to the shared pair. Not in the posture catalog, not read by any process; `noo cluster verify --controller` FAILs while it is set on anywhere (WARN for a stale closed value) |
| `NOO_NATS_ALLOW_ANONYMOUS` | all three | `1` → connect with no credential at all. Without it a process with neither pair set **refuses to connect**: an empty user is not "no auth", it is an anonymous connection the server accepts, which removes bus authentication silently. Local dev against a password-less NATS only |
| `NOO_PG_SSLMODE`, `NOO_PG_SSLROOTCERT`, `NOO_PG_TLS_REQUIRED` | workers | Postgres transport fallbacks for a DSN that names none; the compose DSNs carry `sslmode=verify-full` and the client certificate themselves, and the server accepts nothing else |
| `NOO_PKI_DIR` | gateway, workers, compose | the PKI directory mounted for stunnel sidecars and cert-expiry checks |
| `NOO_VLLM_TLS`, `NOO_LLAMACPP_TLS`, `NOO_OLLAMA_TLS`, `NOO_TEI_TLS`, `NOO_RERANKER_TLS` | **retired** | per-backend TLS switches. Every backend door is mTLS unconditionally (vLLM natively, the rest behind a `noo-stunnel-<x>` sidecar), so there is nothing to switch. The node env template renders them empty and inert; a leftover `false`/`0`/`no`/`off` is a node-agent **refusal to start** naming the line ([node-agent.md](../security/node-agent.md)) |
| `NOO_NODE_CERT_ORG`, `NOO_SERVICE_CERT_ORG`, `NOO_CONTROLLER_CERT_ORG` | **retired** | certificate-organisation overrides. The orgs are fixed by the PKI; a value still set is a node-agent **refusal to start** naming the variable (`internal/auth/principal.go`) |

The three per-principal NATS pairs above are **minted**, not hand-written:
`noo onboard` mints the gateway's and the workers' on a fresh install and
renders `monitoring/nats/users.conf` before the stack starts, and each node's
own pair rides its provision bundle. The server verifies a bcrypt digest from
that file, so changing one of these values without re-rendering it leaves the
holder looping on `Authorization Violation` — `noo cluster nats-users render
--rotate` is the rotation, and `noo security secrets rotate` refuses these
keys for that reason. `noo cluster nats-users render` also writes
`NATS_GATEWAY_USER` / `NATS_WORKER_USER` into `.env` when they are absent,
so one command is a whole migration.

## Posture gates (DB-authoritative; `.env` is the fallback)

Set with `noo security posture set`; the gateway copies the DB values into
its environment at boot. See [config.md](config.md#where-does-a-value-go).

| Variable | Default | Read by |
|---|---|---|
| `NOO_EXEC_APPROVAL_MODE` | `strict` | `middleware.rs`, workers. Posture-only: a `noomesh.yaml` `security.exec_approval_mode` is a startup refusal, not an override |
| `NOO_NODE_AGENT_PRIVILEGED` | `true` | compose (`privileged:` on the node-agent service) |
| `NOO_MCP_EXTERNAL_ENABLED` | off | `mcp_external.rs`, compose |
| `NOO_APPROVAL_BREAK_GLASS` | **retired** | approval decisions always take a named operator login. A posture row or gateway env value still open (`1`, `true`, `yes`, `on`) makes the gateway **refuse to start**, naming it; clear it with `noo security posture set NOO_APPROVAL_BREAK_GLASS 0` (a closed row is deleted at the next start) |
| `NOO_SELF_CALL_SHARED_SECRET` | closed (unset = closed; `1` opens it) | `auth.rs`, `posture.rs`. Proposal-53 bridge: whether a shared-secret token still buys inference, instead of a per-consumer key. Does **not** retire `NOO_CONTROLLER_SECRET`, whose one remaining job is the gateway's boot guard (no controller secret, no start) |
| `NOO_BUS_PRINCIPAL` | **retired** | workers always require a verified `Noo-Principal` on `worker.*`. A posture row or gateway env value still at `optional` makes the gateway **refuse to start**, naming it; clear it with `noo security posture set NOO_BUS_PRINCIPAL required` |

## Gateway (Rust)

Service endpoints have a YAML home (`services.*`); the env name is the
override. Everything else below is env-only.

| Variable | Default | Purpose |
|---|---|---|
| `DATABASE_URL`, `NATS_URL`, `REDIS_URL`, `OLLAMA_URL`, `NOO_GATEWAY_URL`, `NOO_PROMETHEUS_URL`, `NOO_LOKI_URL`, `NVIDIA_EXPORTER_URL` | see [config.md](config.md#services--endpoints-gateway--workers) | overrides for `services.*` |
| `PAGEINDEX_EMBEDDING_URL`, `PAGEINDEX_EMBEDDING_BACKEND`, `PAGEINDEX_EMBEDDING_MODEL`, `EMBEDDING_DIM` | ollama-first | the embedder (`embedding_client.rs`); `TEI_URL` / `TEI_MODEL` / `EMBEDDING_MODEL` are read only as legacy fallbacks |
| `PAGEINDEX_EMBEDDING_EXTRA_URLS` | empty | comma-separated extra static embed endpoints (same model and wire format as `PAGEINDEX_EMBEDDING_URL`), balanced with the mesh nodes and the primary — e.g. the optional CPU embedder, `https://noo-stunnel-ollama-embed-cpu:11434` (runbook) |
| `OLLAMA_EMBED_NUM_PARALLEL`, `OLLAMA_EMBED_CPU_NUM_PARALLEL` | `4`, `4` | compose-only: `OLLAMA_NUM_PARALLEL` for `ollama-embed` / `ollama-embed-cpu` (concurrent requests per loaded model; container-wide) |
| `NOO_REFUSAL_STORM_PER_MIN` | `120` | `middleware.rs` request logger: refusals (401/403/429) one peer may collect in a minute before the gateway pages `auth.refusal_storm` (one page per peer per hour). `0` disables. A caller retrying a rejected credential is an outage that reads as traffic — 17k refused calls/hour went unread for ten hours on 2026-09-22; `noo doctor strangers` shows the same as a `refused … STORM` row |
| `NOO_LOGS_INGEST_BYTES_PER_MIN`, `NOO_LOGS_INGEST_REQUESTS_PER_MIN` | `8388608`, `120` | `routes/logs_ingest.rs`: what one node may push to `POST /api/cluster/nodes/{node_id}/logs` in a minute (decoded bytes, pushes) before the gateway answers 429 with `Retry-After`. Zero or garbage keeps the default; the body cap (4 MB) is fixed |
| `NOO_STT_URL`, `NOO_STT_BACKEND`, `NOO_STT_MODEL`, `NOO_STT_API_KEY_ENV`, `NOO_TTS_URL`, `NOO_TTS_BACKEND`, `NOO_TTS_VOICE`, `NOO_TTS_API_KEY_ENV` | `https://noo-whisper:8000`, `https://noo-piper:8000` | voice providers (`stt_client.rs`, `tts_client.rs`). https only: an `http://` URL is refused, never dialled. The voice add-on's `noo-whisper`/`noo-piper` require a cluster-CA client certificate, and an https URL on the cluster's own names (`noo-whisper`, `whisper`, `noo-piper`, `piper`, `localhost`) is dialled with the gateway's leaf; any other https host (a cloud provider) with the public roots and no client certificate (`noo cluster verify --controller` → `voice listeners`) |
| `VLLM_IMAGE`, `VLLM2_IMAGE`, `LLAMACPP_IMAGE`, `OLLAMA_IMAGE`, `TEI_IMAGE` | — | **not compose-only**: `routes/cluster.rs` reads these directly at runtime when starting a backend on a node, pinning that node's image tag to the controller's own rather than letting it fall through to the node's local `.env` |
| `NOO_KIOSK_TAILNET_MINT`, `NOO_KIOSK_TAILNET_TAG` | on, — | `routes/kiosk.rs`. `NOO_KIOSK_TAILNET_MINT=0` is the kill switch for the keyless kiosk mint; `NOO_KIOSK_TAILNET_TAG` is the tailnet tag a mint's `whois` must carry |
| `NOO_KIOSK_GRAPH_LABELS` | — | **Retired and ignored** (2026-10). Kiosk graph labels are the controller setting `kiosk.graph_labels` now — a `noo_settings` row, default off, switched with `noo kiosk labels on\|off\|status` (Operator/Admin, audited, no restart; see [config.md](config.md#behavioural-flags)). The setting has no env layer, so this variable cannot stand in for it; a gateway that still has it set logs a warning once |
| `NOO_CONTROLLER_HOSTNAME` | `controller` | `self_node.rs`. Middle fallback in the controller's own node-id precedence: `NOO_CONTROLLER_NODE_ID` → `NOO_CONTROLLER_HOSTNAME` → `NODE_ID` |
| `NOO_SELF_AGENT_URL` | derived from the controller's own tailnet URL, port 8081 | `routes/bootstrap.rs`. Overrides where the gateway dials the controller's self-agent (tailnet whois/dialback) for node enrollment and the keyless kiosk mint |
| `NOO_NATS_MONITOR_URL` | derived from `NATS_URL`'s scheme | `preflight.rs`. Overrides the whole base URL for NATS subject-monitoring reads, for an operator who moved or closed that endpoint |
| `NOO_ARTIFACT_DIGEST_CACHE` | `/data/artifact-digests.json` | `routes/artifacts.rs`. Path to the artifact-rail digest cache file |
| `NOO_SKILL_CORPUS_REQUIRED` | unset | `prompt_skills.rs`. CI-only: set so a missing `prompts/skills` corpus mount panics the differential test rather than silently reporting a skip as a pass |
| `NOO_JWT_SECRET` (or `NOO_SECRET_NOO_JWT_SECRET`) | insecure well-known default → auth fails closed | JWT signing secret; **secret store** |
| `NOO_BEHIND_TLS_PROXY` | unset | set when a TLS-terminating proxy fronts the gateway: the refresh cookie is then issued with `Secure` even though the gateway speaks plain HTTP behind it |
| `NOO_CSP` | unset (not sent) | `1` sends a built-in Content-Security-Policy; a literal policy string is sent as-is. Opt-in because the dashboard is a prebuilt artifact and a blind policy can break a pane. The other security headers are always on |
| `NOO_APPROVAL_CHAT_SENDERS` | unset | **retired and unread.** It used to make a channel id equivalent to the operator role. Approving from chat now requires a LINKED account with the operator role, and nothing else |
| `NOO_MCP_REMOTE` | **retired, unread** (stack-v0.2.40) | declared that the plain-HTTP operator-door listener was published beyond loopback. That listener no longer exists; the door is `/mcp/operator` on the gateway port with a credential on every request. Nothing reads this key; the old text: it made `NOO_MCP_TOKEN` mandatory because the loopback binding was the boundary |
| `NOO_MCP_BIND_ADDR` | **retired, unread** (stack-v0.2.40) | host address the dedicated plain-HTTP operator door on 3100 was published on. There is no such listener any more; the door is served over HTTPS at `/mcp/operator` on the gateway port |
| `NOO_CLUSTER_SECRET` | — | the fleet secret, every node's credential: among the controller's services only the gateway (it verifies node tokens) and the containerised node agents hold it; **secret store** |
| `NOO_CONTROLLER_SECRET` | unset → the gateway **refuses to start** | the gateway's own secret; while set, `NOO_CLUSTER_SECRET` tokens reach only the node rail. Held by the gateway ALONE: it signs nothing, and an HMAC signed with it is refused from every caller; never pushed to nodes; **secret store** |
| `NOO_BUS_KEY_WORKER`, `NOO_BUS_KEY_TRELLION`, `NOO_BUS_KEY_TRELLION_INTEL` | unset → that audience's worker refuses every `worker.*` message | the bus-principal keys, one per audience: the gateway holds all three and MACs every message once per audience; minted by onboard and `noo upgrade --stack`; **secret store** |
| `NOO_BROWSER_KEY` | unset → the browser container answers 503 | the browser door's own key: the gateway and noo-worker sign with it, noo-browser verifies with it, and the gateway hands it to the browser containers it starts on nodes; **secret store** |
| `NOO_BUS_KEY` + `NOO_BUS_AUDIENCE` | unset → the container refuses every `worker.*` message | in noo-worker, noo-trellion and noo-trellion-intel: this container's OWN bus key (a file) and the audience it is (`worker` / `trellion` / `trellion-intel`, plain) |
| `NOO_CLUSTER_LEGACY_FULL_ACCESS` | **retired** | the bridge that kept every fleet-secret token an operator's is gone: a fleet token is only ever a node. A posture row or env value still truthy makes the gateway **refuse to start**, naming it; clear it with `noo security posture set NOO_CLUSTER_LEGACY_FULL_ACCESS 0` |
| `NOO_BOOTSTRAP_ACCEPT_UNSIGNED_FETCH` | **retired** | the provisioning pull lane always requires a birth-key proof (or, on the apply report, the fleet credential); an unsigned `fetched_at` / apply-report write is refused and the public bundle GET stamps nothing. A posture row or env value still open (anything but `0`) makes the gateway **refuse to start**; clear it with `noo security posture set NOO_BOOTSTRAP_ACCEPT_UNSIGNED_FETCH 0` |
| `NOO_NODE_AGENT_TOKEN` | — | bearer the gateway presents to node-agents; **secret store** |
| `NOO_AGENT_REVIEW_KEY` | unset (bodies travel in plaintext, boot log warns) | seals agent-to-agent message bodies; rotating it makes older sealed messages unreadable (`agent_crypto.rs`) |
| `NOO_AGENT_SIGNING_KEY` | unset (signatures derive from the review key) | optional second secret: when set, agent-message signatures derive from it and the review key becomes decrypt-only, so reading history no longer implies being able to forge it |
| `NOO_AUDIT_HMAC_KEY` | — (minted by `noo onboard`) | the security audit log's signing key — the only one; unset, audit rows are refused. Secret store, delivered as a file ([secrets.md](../security/secrets.md#the-audit-key)) |
| `NOO_ADMIN_USER`, `NOO_ADMIN_PASSWORD`, `NOO_OPERATOR_USER` | `admin`, —, — | bootstrap admin login before users exist; the operator identity for posture writes. The password reaches the **gateway only** (`routes/core.rs`); the Python images receive `NOO_ADMIN_USER` alone (`heartbeat.py`) |
| `NOO_TOKEN_EXPIRE_MINUTES`, `NOO_REFRESH_TOKEN_DAYS` | `15`, `30` | access / refresh token lifetimes (`auth_refresh.rs`) |
| `NOO_REFRESH_GRACE_SECS` | `10` | how long after a rotation a re-presentation of the OLD refresh token reads as a benign double-refresh (two tabs) rather than a stolen chain: `409`, no sweep, no audit row, only while the successor is still live and unused. `0` disables the window — every re-presentation is a replay (`auth_refresh.rs`) |
| `NOO_EXEC_APPROVAL_TIMEOUT_SECS` | `300` (clamped 1–3600) | the Rust exec-approval gate and `GET /api/exec-approval/status`. The YAML `security.exec_approval_timeout` is a **separate** key read only by the Python worker's approval manager — the two do not override each other ([config.md](config.md#security--exec-approval)) |
| `NOO_TRUSTED_PROXIES` | — (loopback only; in tailnet mode the launcher adds this node's own tailnet address, which is where Tailscale Serve connects from) | comma list of proxies whose `X-Forwarded-For` is honoured (`middleware.rs`); the client is the rightmost entry that is not itself a trusted proxy — never the leftmost, which the caller writes. **Exact container addresses of proxies on the gateway's own docker network** — never the bridge itself: on a published port every remote client arrives FROM the bridge, so a bridge entry lets each one pick its own rate-limit bucket and audit IP. The gateway refuses to start on an entry covering a network it is attached to |
| `NOO_MCP_TOKEN`, `NOO_MCP_TOKEN_PREVIOUS` | **retired, ignored** (2026-09-30) | were the shared bearer for the operator MCP door `/mcp/operator` and its rotation grace value. The door now takes only a per-admin `mcp:operator` service key (`noo security service-key issue <you>-mcp --scopes mcp:operator --user <admin>`). A gateway that still finds either set logs one boot WARN and never compares a bearer against it; compose no longer delivers it. Remove it with `noo security secrets tidy` (`secrets audit` and `security scan` report it as retired). `NOO_MCP_HOST` / `NOO_MCP_PORT` are **retired, unread** since stack-v0.2.40 — they addressed the removed plain-HTTP listener |
| `NOO_MCP_KEY` | — | **client side** (`noo mcp tools`): your personal `mcp:operator` service key, sent as the bearer on `/mcp/operator` |
| `NOO_MCP_EXTRA_MANIFEST` | — | path to an add-on's extra tool manifest fragment merged into the local door |
| `NOO_PORT`, `NOO_SELF_URL` | `8080`, — | the external door's advertised port / URL (`mcp_external.rs`) |
| `GATEWAY_PORT` | `8080` | loopback port for operator alerts |
| `NOO_TOOL_TIMEOUT_SECS` | `120` | tool execution timeout (RAG queries can take 30–60 s) |
| `NOO_BACKEND_TIMEOUT_SECS` | `300` | whole-request bound on every gateway → node-agent / backend call, so on a non-streaming completion it caps the entire generation. Raise it on CPU-only boxes, where a 12B model can outrun 300 s and the caller sees `502 backend_unreachable` — and raise the node's `NOO_BACKEND_FIRST_BYTE_TIMEOUT_SECS` with it, because the lower of the two is the one that fires |
| `NOO_SESSION_CACHE_MAX_COUNT` | `1000` | coordinator session cache size |
| `NOO_SANDBOX_URL` | `https://sandbox:9000` | the airgapped executor for `python_exec` (also `sandbox.url`). mTLS only: the sandbox requires a cluster-CA client certificate, and an `http://` value is refused, never dialled (`noo cluster verify --controller` → `sandbox listener`) |
| `NOO_SANDBOX_ISOLATION` | `bwrap` | per-call isolation inside the sandbox container: `bwrap` (own root, PID space, no network per call) or `process` (container isolation only, chosen by name — the executor refuses to run code rather than fall back). `/health` reports the active mode |
| `NOO_SANDBOX_APPARMOR` | `docker-default` | AppArmor profile for the sandbox container; `unconfined` on hosts whose AppArmor blocks unprivileged user namespaces (Ubuntu 24.04+), where Bubblewrap otherwise fails with "No permissions to create new namespace" |
| `NOO_SANDBOX_EXEC_MEM_MB` | `384` | per-call data-segment limit (`RLIMIT_DATA`) inside the sandbox; CPU is capped at the call's timeout |
| `NOO_WORKER_TIMEOUT_SECS` | `120` | `worker.*` request timeout (also `worker.timeout_secs`) |
| `NOO_SEARCH_PROVIDER`, `NOO_SEARCH_SEARXNG_URL` | key-implied (`ddg` with no key), — | which backend `web_search` asks (YAML `search.*`) |
| `BRAVE_SEARCH_API_KEY`, `TAVILY_API_KEY` | — | search provider keys; **secret store**, never `noomesh.yaml`; add one with `noo security secrets rotate <KEY> --prompt --restart`, and it picks the provider when NOO_SEARCH_PROVIDER is unset |
| `NOO_HEARTBEAT_TZ` | `America/New_York` | heartbeat scheduler (YAML `heartbeat.tz`; also has a `noo_settings` override). `NOO_HEARTBEAT_GATEWAY_URL` is retired: heartbeat actions call the gateway in process and read no URL |
| `NOO_OPS_WAIT_<TYPE>_SECS` | `0`/`3`/`12` per type | seconds a long route holds a request before answering `202` with an operation handle (`GRAPH_RECLUSTER` 0, `GRAPH_EXTRACT_RELATIONS`/`GRAPH_ENTITY_CLEANUP`/`SNAPSHOTS_CONSOLIDATE`/`RAG_INGEST`/`DOCS_INGEST` 3, `GRAPH_NAVIGATE`/`GRAPH_TRAVERSE` 12; at most 25). Also a `noo_settings` override, hot-reloaded — [config.md](config.md#asynchronous-operations) |
| `NOO_OPS_RESULT_TTL_SECS` | `86400` | how long a finished operation's result is kept (60 to 2592000); `noo_settings` override |
| `NOO_OPS_MAX_ACTIVE_PER_OWNER` | `8` | live operations one account may have at once (`429` beyond) |
| `NOO_GATEWAY_INSTANCE` | the hostname | which gateway owns an operation's run: boot fails that instance's orphans, the sweeper fails runs whose instance stopped heartbeating |
| `NOO_HEARTBEAT_LLM_CONCURRENCY`, `NOO_HEARTBEAT_LLM_TIMEOUT_SECS`, `NOO_HEARTBEAT_DISPATCH_DEADLINE_SECS`, `NOO_HEARTBEAT_BOOT_GRACE_SECS` | — | heartbeat action tuning |
| `NOO_REPORTS_DRIVE_FOLDER_ID` | — | Google Drive folder heartbeat reports are uploaded to (also a `noo_settings` override via `POST /api/settings/flags/set`, applied within ~15s; a task's `config.drive_folder_id` wins) |
| `NOO_TASK_APPROVE_REQUIRE_CERT_BOUND` | off | `routes/users.rs`. `1` → approving a scheduled destructive task needs a token bound to the operator's client certificate, so a password or a stolen login token on a shared shell is not enough. Off by default because not every install issues client certificates |
| `NOO_CLI_REPO` | `noomesh/noomesh` | `routes/bootstrap.rs`, `noo upgrade`, `install-noo.sh`. The release repo a fresh node installs the `noo` CLI from; the one setting that moves a release |
| `NOO_GRAFANA_DS_VIA_GATEWAY` | set by compose (`1`) | `auth.rs`. Marks that Grafana's datasources reach Prometheus and Loki through the gateway's authenticated proxy; compose sets it, an operator does not |
| `NOO_CODING_TASK_ENABLED` | off | Python `gateway/coding_tool.py`. Enables the `coding_task` tool's Claude Code subprocess; default OFF so code execution is an explicit opt-in |
| `NOO_SANDBOX_EXEC_NPROC`, `NOO_SANDBOX_EXEC_FILE_MB` | `96`, `32` | `sandbox/app.py`. Per-call process-count (`RLIMIT_NPROC`) and file-size limits inside the sandbox, beside `NOO_SANDBOX_EXEC_MEM_MB` |
| `NOO_AGENT_ALERT_CHANNEL`, `NOO_AGENT_ALERT_RECIPIENT` | — | where operator alerts go (`operator_alert.rs`). The recipient is **required**; for `google_chat` it must be a space resource name (`spaces/<id>`). Unset, alerts are refused rather than sent. |
| `NOO_APPROVAL_TELEGRAM_CHAT`, `NOO_APPROVAL_GCHAT_SPACE` | — | where exec-approval prompts are posted |
| `TELEGRAM_BOT_TOKEN` | — | Telegram channel ([channels/telegram.md](../channels/telegram.md)); **token = secret store** |
| `TELEGRAM_ALLOWED_USERS` | — | **retired.** It admits nobody and confers no approval authority; chat ingress is default-deny on `noo_user_channel_links` (`noo security user link <username> telegram <id>`). Compose no longer delivers it; the launcher warns while `.env` still carries it, and the gateway logs one WARN if it reaches it anyway |
| `GOOGLE_CHAT_CREDENTIALS`, `GOOGLE_CHAT_PUBSUB_SUBSCRIPTION` | — | Google Chat channel ([channels/google-chat.md](../channels/google-chat.md)) |
| `WHATSAPP_TOKEN`, `WHATSAPP_PHONE_ID` | — | outbound WhatsApp send (`routes/communication.rs`). `WHATSAPP_VERIFY_TOKEN` / `WHATSAPP_APP_SECRET` are **not delivered**: they would authenticate an inbound webhook, and no such route exists |
| `NGROK_DOMAIN` | — | public hostname for webhook-style channels |
| `NOO_DISK_WATERMARK_PERCENT`, `NOO_DISK_WATCH_PATHS` | `85`, — | the `disk_watermark` autonomy location |
| `NOO_CONTROLLER_NODE_ID`, `NODE_ID` | — | the controller's own node id (autonomy, shard key) |
| `NOO_SHARD_KEY` | `NODE_ID` → `default` | conversation shard tag |
| `NOO_HOST_SPOOL_DIR`, `NOO_RESTART_FLAG` | `/var/run/noo-spool`, `/tmp/noo-restart-needed` | the host spool and the restart-needed marker. (`NOO_HOSTFS_ROOT` and the `/host-fs` mount are gone: nothing reads them, and the settings browser lists only declared roots) |
| `NOO_DATA_DIR` | `/data` | persistent data dir inside the container (Python `settings_store.py`, research pipeline) |
| `NOO_SKILLS_DIR`, `NOO_SKILLS_HOST_DIR`, `NOO_PROMPT_SKILLS_ROOT` | — | skill registry dirs (container / host view) and the prompt-skill root |
| `NOO_ARTIFACT_GGUF_DIR`, `NOO_ARTIFACT_IMAGE_DIR` | `/artifacts/models`, `/artifacts/images` | the artifact rail the nodes pull from |
| `NOO_ARTIFACT_BIN_DIR` | — | retired with the gateway-signed agent swap: the gateway serves no `binary` manifest, so nothing reads it |
| `NOO_CLUSTER_INVENTORY`, `NOO_BOOTSTRAP_SCRIPT_URL`, `NOO_CONTROLLER_SSH_PUBKEY` | — | fleet provisioning inputs. `NOO_CONTROLLER_SSH_PUBKEY` is still served to enrolling nodes for compatibility and ignored by every current enroller (the `noo-gate` forced-command entry it once pinned is retired); nothing in this repo dials it (the controller→node SSH lane was REMOVED 2026-09-11) |
| `NOO_ENROLL_TAILNET`, `NOO_ENROLL_TAILNET_TAG`, `NOO_TAILSCALE_API_KEY`, `NOO_TAILSCALE_TAILNET`, `NOO_TAILSCALE_OAUTH_CLIENT_ID`, `NOO_TAILSCALE_OAUTH_CLIENT_SECRET` | — | tailnet enrollment; **keys = secret store**. The OAuth client is read by `routes/cluster.rs` alone and is delivered to the gateway only |
| `NOO_EVOLVE_URL` | `https://noo-evolve:8090` | the evolve container the proxy forwards to. **Must be `https://`**: the gateway refuses a plaintext override (503, `state: misconfigured`) because every add-on call carries its bearer |
| `NOO_EVOLVE_TLS_CERT`, `NOO_EVOLVE_TLS_KEY`, `NOO_EVOLVE_TLS_CLIENT_CA` | set by the evolve overlay | evolve's listener: its `services/evolve` leaf and the cluster CA it requires callers' certificates to chain to. All three required — evolve serves HTTPS only and refuses to start without them |
| `NOO_TRELLION_DB_PASSWORD`, `NOO_TRELLION_DDL_PASSWORD`, `NOO_EVOLVE_DB_PASSWORD`, `NOO_EVOLVE_DDL_PASSWORD`, `NOO_APP_DB_PASSWORD` | — | role passwords the broker uses when it must *create* a role (`system_provision.rs` reads the name the systems manifest gives as `password_env` / `ddl_password_env`); **secret store**, delivered to the gateway as `/run/secrets` files (`<NAME>_FILE`). The gateway's and worker's DSNs carry no password — `PGPASSFILE` does; the add-on containers still get theirs inside the DSN until their images read `_FILE` |
| `NOO_MESH_MIGRATOR`, `NOO_DB_AUTOHEAL` | — | migration runner selection; dependency-watchdog repair switch |
| `NOO_LOCAL_AGENT_URL`, `NOO_DEFAULT_AGENT_URL` | — | agent URLs for the dashboard and log proxy |
| `NOO_SELF_MODIFY_AUDIT_PATH` | `/data/noo_self_modify_audit.jsonl` | JSONL audit trail for stack restart/rebuild + other self-modifying actions |
| `NOO_LAUNCHED` | — | set by the launcher; the gateway warns when started any other way |
| `NOO_CONFIG_PATH` | resolved | write path for `noo config set` |
| `VLLM_MAX_MODEL_LEN`, `VLLM_MAX_TOKENS` | `16384`, `4096` | token budget (`inference.*`). `4096` is the one default (`DEFAULT_VLLM_MAX_TOKENS` in `agent_loop.rs`), used both to size the request and as the output reserve the context budget subtracts from `VLLM_MAX_MODEL_LEN` |
| `CLOUD_PROVIDERS_ENABLED` | off | behavioural flag — prefer the dashboard / `noo_settings` ([config.md](config.md#behavioural-flags)). Gates `claude-*` / `gpt-*` / `gemini-*` models, which run the full agent loop (tools, memory, context) on the controller against the provider |
| `NOO_EVOLVE_HOFSTADTER_ENABLED` | on (with the evolve add-on) | behavioural flags — prefer the dashboard / `noo_settings` ([config.md](config.md#behavioural-flags)) |
| `NOO_AGENT_AUTORETRY`, `NOO_AGENT_ESCALATE_NOTIFY`, `NOO_AGENT_AUTODISABLE`, `NOO_AGENT_ACTIVITY_*` | off | add-on gates — read by the **evolve** container, not the gateway; set them in its compose environment |
| `RUST_LOG` | — | tracing filter |

## `noo` CLI

The CLI reads `.env`/`noomesh.yaml` only through the rules in
[config.md](config.md#where-does-a-value-go); these are the variables it reads
from its own process environment (`noo-cli/src`).

| Variable | Default | Purpose |
|---|---|---|
| `NOO_GATEWAY_URL`, `NOO_TOKEN`, `NOO_CONFIG`, `NOO_REPO_ROOT` | see [transport security](#transport-security-env-written-by-noo-onboard) and [config.md](config.md#where-the-file-is-found) | which gateway, with which bearer, which `noomesh.yaml`, which checkout |
| `NOO_HOME` | `~/.noo` | the CLI's state root (`envfile.rs`) |
| `NOO_CREDENTIALS_FILE` | `$XDG_CONFIG_HOME/mesh/credentials.json`, else `~/.config/mesh/credentials.json` (`mesh/<instance>/` for a non-default instance) | where `noo auth login` stores the login |
| `NOO_OPERATOR`, `NOO_OPERATOR_CERT_DIR` | the stored login's subject; `operator/` beside the credentials file | the account posture writes act as, and the directory holding that operator's client certificate |
| `NOO_AUTH_QUIET` | off | `1` silences the one-time "credentials withheld from this URL" warning |
| `NOO_TLS_INSECURE` | **refused** | there is no unverified-TLS lane: any value other than empty/`0` makes the CLI exit naming the fix (`NOO_TLS_CA` or `noo security trust-ca`) |
| `NOO_COLOR`, `NO_COLOR`, `CLICOLOR_FORCE`, `NOO_PAGER` / `PAGER` | auto, `less -R -F -X` | output styling (`NOO_COLOR=always\|never` wins, then `NO_COLOR`, then `CLICOLOR_FORCE`, then a terminal probe) and the pager (`cat` or empty = none) |
| `NOO_ALLOW_UNSIGNED` | off | `1` lets `noo upgrade` deploy by tag when the release signature cannot be fetched |
| `NOO_CLI_BASE_URL`, `NOO_CLI_REPO`, `NOO_CLI_CACERT` | the GitHub release of `noomesh/noomesh` | where `noo upgrade` and `install.sh` fetch the CLI: a mirror serving `noo-<target>` + `.sha256`, or another release repo |
| `NOO_UPGRADE_MAC_LEAVES_WAIT_SECS` | `600` | how long `noo upgrade --nodes` waits for a macOS node to report the new CLI before restaging it (`0` = do not wait) |
| `NOO_TAILSCALE_API_BASE` | `https://api.tailscale.com/api/v2` | Tailscale API base for `mint-join-key` / `set-primary` (a test seam) |
| `NOO_MODEL_ORIGINS` | all | `noo models` catalog scope: comma list of `us`, `eu`, `cn` … filters model families by lab origin; a scope matching nothing is ignored |
| `HF_ENDPOINT` | `https://huggingface.co` | the Hugging Face API base the catalog and pulls use (the standard `huggingface_hub` variable) |
| `NOO_CONTROLLER_DNS` | the controller's MagicDNS name | the floating service name nodes are told to phone home to (`cluster provision`); HA operators set it to their mesh's name, so a promoted standby takes over without re-provisioning |
| `NOO_CONTROLLER_IP` | detected | the LAN address `noo onboard` records for the controller |
| `NOO_ONBOARD_ADOPT_DATA` | unset | `1` lets a non-interactive `noo onboard` adopt data directories that already hold a live install; without it that is a refusal |
| `NOO_USER_DIRS`, `NOO_WORKSPACE_DIR` | — | non-interactive onboard: colon-separated read-only ingest directories, and the writable workspace |
| `NOO_KIOSK_URL` | derived from this machine's tailnet DNS name | the controller URL `noo kiosk` hands a display (`--url` wins) |
| `SOPS_AGE_KEY`, `SOPS_AGE_KEY_FILE` | — / `~/.config/sops/age/keys.txt` | the age key `sops` decrypts `secrets/env.sops` with (a key file path or the key itself) |
| `GH_TOKEN`, `GITHUB_TOKEN` | — | optional GitHub token for `noo upgrade` release downloads when `gh` is not installed: the `noomesh/noomesh` releases are public, so this only lifts the anonymous rate limit or reads a private `NOO_CLI_REPO` fork |

## Node-agent and host daemon (Go)

The agent does not read `noomesh.yaml`; `noo cluster provision` renders
`/etc/noo-node-agent.env` from `node-agent-go/deploy/noo-node-agent.env.tmpl`.

| Variable | Default | Purpose |
|---|---|---|
| `NODE_ID` | `auto` (hostname) | node identity |
| `NODE_TIER` | `3` | 1 GPU-high, 2 GPU-mid, 3 CPU, 4 edge, 5 companion, 6 monitor |
| `NODE_IP` | auto-detect | LAN / tailnet address to register |
| `NODE_LOCATION` | — | site label |
| `NODE_AGENT_PORT` | `8081` | control API port |
| `CONTROLLER_URL` | `https://gateway:8080` | the gateway |
| `NATS_URL` | `nats://nats:4222` | with `NATS_NODE_USER` / `NATS_NODE_PASSWORD`; unset is a refusal to connect unless `NOO_NATS_ALLOW_ANONYMOUS=1`. There is no shared fallback (retired) |
| `HEARTBEAT_INTERVAL` | `30` | seconds |
| `GPU_MODEL`, `VRAM_GB` | detected | manual overrides |
| `NOO_FORCE_GPU`, `NOO_NO_GPU` | — | `1` forces the GPU probe result either way |
| `NOO_OLLAMA_GPU_COUNT` | — | GPUs reserved for the Ollama container |
| `NOO_NODE_AGENT_TOKEN`, `NOO_CLUSTER_SECRET` | — | accepted credentials on :8081 (at least one required) |
| `NOO_TLS_CA`, `NOO_TLS_CERT`, `NOO_TLS_KEY`, `NOO_MTLS_NODES` | — | see transport security |
| `NOO_COMPOSE_PROJECT` | `pai-assistant` | the `com.docker.compose.project` label the node agent stamps on backends it starts and filters its container stats by (`node-agent-go/internal/docker/backends.go`, `stats.go`). It is a label of the agent's own containers, not the controller's compose project (`noomesh`); the legacy default value is kept for compatibility with existing installs, since changing it drops running backends from stats until they are recreated |
| `NOO_AGENT_STATE` | `/var/lib/noo-node-agent` | the agent's writable state directory (log shipper spill and tail offsets) |
| `NOO_LOG_SHIP`, `NOO_LOG_SHIP_UNITS` | on, built-in unit list | `0`/`off` switches this node's log shipping to the controller's Loki off (it also needs the agent's TLS material); `NOO_LOG_SHIP_UNITS` is a comma list of journal units to request — `noo-hostd` still refuses any outside its own allowlist. Operator overrides edited by hand in `/etc/noo-node-agent.env`; see [monitoring](../operating/monitoring.md) |
| `NOO_DATA_ROOT_POLICY`, `NOO_DATA_ROOT_OWNER` | `warn`, — | `internal/dataroots`. `enforce` makes the agent refuse backend starts and controller-supplied host paths until the data root passes the shape-and-ownership rule (not under a system prefix, owned by the agent's account or root, not group/world-writable); `warn` only reports it in the heartbeat as `data_roots.policy`. `NOO_DATA_ROOT_OWNER` names one more uid allowed to own the root (a controller's self-agent sharing the operator's root); only the node's own environment can set it |
| `NOO_SELF_NODE` | off | marks the node on the controller's own device; reported in the heartbeat as `self_node` and branched on by fleet views and node verbs |
| `NOO_AGENT_HOST_MODE` | auto | `1`/`0` forces the "agent runs on the host, not in a container" decision that is otherwise taken from `/.dockerenv` and systemd's `INVOCATION_ID` (`internal/containerdial`) |
| `NOO_SKILL_RUN_USER`, `NOO_SKILL_BIND_ROOTS` | `65534:65534`, `NOO_SKILLS_HOST_DIR` + `NOO_DATA_ROOT` | the user a skill container runs as (`""` restores the image's own), and the roots a skill bind-mount source may live under. Node-local on purpose: no request field widens either |
| `NOO_CONF_DIR`, `NOO_FETCH_PLIST` | `/etc/noo`, `/Library/LaunchDaemons/<fetch label>.plist` | host-daemon paths `noo-fetch.sh` reads config from and (macOS) finds the fetch job definition at. Overridden only by tests |
| `NOO_AGENT_SECRET_DIR`, `NOO_AGENT_ENV_FILE` | — | retired with hostd's `swap-agent`, the only reader of these test overrides; no longer read |
| `NOO_APPLY_ACCEPT_CA_SIGNED` | **retired** | `noo node fetch`/apply (`node_fetch.rs`, `noo-apply.sh`). The CA-signed compatibility lane it gated is gone: a CA-signed bundle that is not a signing-key rollover is refused (77) whatever this says, and a set value is reported as ignored. The controller no longer renders it into the agent env |
| `NOO_HOSTD_SIGNER_ORG` | — | retired: it named the gateway certificate organisation hostd accepted on a signed agent-swap manifest; the swap is refused, so nothing reads it |
| `STUNNEL_IMAGE` | `$NOO_IMAGE_PREFIX/stunnel:$NOO_IMAGE_TAG`, else a plain alpine fallback | overrides the image of the `noo-stunnel-<x>` sidecar the agent starts in front of a backend |
| `NOO_IMAGE_SOURCE` | `legacy` | node agent (`internal/imagesource`). The rollout switch for images over the artifact rail: `rail` makes every container start take its image from the controller's staged store (verify, refuse on a verification failure, run the local copy on a transport failure); `legacy` — the default for the first release that ships the rail — is the pre-rail behaviour (local image, else its registry). Reported on the heartbeat as `image_source_mode`. See [weight-cache.md](../models/weight-cache.md#container-images) |
| `NOO_IMAGE_REGISTRY_FALLBACK` | `public` | node agent (`internal/docker/image_source.go`). With `NOO_IMAGE_SOURCE=rail`: where a container image may come from when the controller has NOT staged it on the artifact rail. `public`: a public third-party image (upstream llama.cpp for ARM, ollama, the alpine sidecar fallback) may be pulled from its registry, logged at WARN and reported as `image_sources[].source = "registry"`; `off`: rail-only, the start is refused with the staging command. Our own images (`ghcr.io/noomesh/*`, `$NOO_IMAGE_PREFIX/*`, local build names) are rail-only under every value — a node holds no registry credential. Any other value means `off`. See [weight-cache.md](../models/weight-cache.md#container-images) |
| `RERANK_N_CTX` | `8192` | context size of the llama.cpp reranker backend the agent starts |
| `OLLAMA_KEEP_ALIVE`, `OLLAMA_MAX_LOADED_MODELS`, `OLLAMA_NUM_PARALLEL`, `N_GPU_LAYERS`, `N_CTX`, `N_THREADS`, `N_BATCH`, `N_PARALLEL`, `GPU_MEMORY_UTILIZATION`, `TENSOR_PARALLEL_SIZE`, `MODEL_PATH`, `LOG_LEVEL`, `VLLM_*` … | backend defaults | an allowlist, not a list of agent settings: the only environment keys a desired-state placement (`node_config.placements`) may set on a backend container (`internal/reconcile`, `placementEnvExact` / `placementEnvPrefixes`). `NOO_*`, `NATS_*`, `PYTHON*`, `LD_*`, credentials and `NVIDIA_*` are refused |
| `NOO_BIND_ADDR` | `0.0.0.0` | bind address for the published ports (compose) |
| `MODELS_DIR`, `LLAMACPP_IMAGE`, `LLAMACPP_PORT`, `RERANK_IMAGE`, `RERANK_ENGINE` | — | backend container spec inputs |
| `MODELS_DIR`, `NOO_DATA_ROOT`, `HF_CACHE_DIR` (an **HF_HOME** — see [models/weight-cache.md](../models/weight-cache.md)), `OLLAMA_DATA_DIR`, `NOO_SKILLS_HOST_DIR`, `NOO_HOST_ROOTS` | — | the host roots this node **declares**. A controller-chosen path (`node_config.models_dir`) must resolve under one of them or the placement is refused ([node-agent.md](../security/node-agent.md)) |
| `NOO_BACKEND_CAP_ADD` | `CHOWN,DAC_OVERRIDE,FOWNER,SETGID,SETUID` | capabilities a backend container keeps after `CapDrop ALL`; `none` keeps nothing |
| `NOO_CONTAINER_IMAGE_ALLOW`, `NOO_CONTAINER_RUN_USER` | `noo-browser` + the release namespace, `65534:65534` | what `POST /api/containers/start` **and a node-local MCP server** may run, and as whom |
| `NOO_MCP_STDIO_FILE` | `/etc/noo/mcp-servers.json` | the **root-owned** file declaring this node's MCP servers. The controller cannot place one; absent = this node runs none. Each entry needs an `image` — the server runs in a container under the skills sandbox floor, and an entry without one is refused ([node-agent.md](../security/node-agent.md)) |
| `NOO_MCP_SECRETS_FILE` | `/etc/noo/mcp-secrets.env` | the node-local `KEY=VALUE` file MCP `$NAME` references resolve against — never the agent's own environment |
| `NOO_MODEL_CACHE_URL` | — | the LAN weight cache to preseed from ([models/weight-cache.md](../models/weight-cache.md)); also the rail the helper image itself arrives on |
| `NOO_HELPER_IMAGE` | `$NOO_IMAGE_PREFIX/node-agent:$NOO_IMAGE_TAG` | the image host operations (models dir, weight preseed) run in. Absent locally, it is fetched over the artifact rail; unfetchable, it is a refusal ([node-agent.md](../security/node-agent.md)) |
| `NOO_LOCAL_EMBED_URL`, `NOO_LOCAL_RERANK_URL`, `NOO_LOCAL_RERANK_ENGINE` | — | where the embed / rerank proxies forward |
| `NOO_BACKEND_FIRST_BYTE_TIMEOUT_SECS` | `290` | how long the inference proxy waits for the backend's response headers. A cold model load and a whole non-streaming completion both happen before those headers arrive, so this is the bound a slow node hits first. Keep it just under the gateway's `NOO_BACKEND_TIMEOUT_SECS` so the gateway stays the decider; an unparseable or non-positive value keeps the default rather than removing the bound |
| `NOO_NETWORK_TYPE` | detected | force the reported network type (companions) |
| `NOO_THERMAL_FAIR_C`, `NOO_THERMAL_SERIOUS_C`, `NOO_THERMAL_CRITICAL_C` | — | thermal-state thresholds |
| `NOO_SENSOR_CAMERA_DEVICE`, `NOO_SENSOR_CAMERA_DISABLE`, `NOO_SENSOR_GPS_DEVICE`, `NOO_DEVICE_LAT`, `NOO_DEVICE_LON`, `NOO_DEVICE_ADDRESS` | detected | companion sensor overrides |
| `GATEWAY_PORT` | `8080` | controller port hint |
| `LOG_LEVEL` | info | agent log level |
| `NOO_HOSTD_MODE` | `controller` | `controller` \| `worker` op table for `noo-hostd` |
| `NOO_HOSTD_HEALTH_INTERVAL`, `NOO_HOSTD_HEALTH_TIMEOUT`, `NOO_HOSTD_HEALTH_WAKE` | — | hostd health polling (controller-mode recreate). `NOO_HOSTD_CA`, `NOO_HOSTD_ALLOW_UNSIGNED` and `NOO_HOSTD_COMPANION_CONTAINERS` served only the worker `swap-agent` op and were removed with it; setting them changes nothing — a swap is refused either way |
| `NOO_HOST_SPOOL_DIR_HOST`, `NOO_PROJECT_ROOT`, `NOO_AGENT_BIN`, `NOO_AGENT_UNIT`, `NOO_AGENT_STAGING_DIR`, `NOO_CLI_BIN`, `NOO_HELPER_IMAGE`, `COMPOSE_LOCK_FILE`, `DOCKER_HOST` | sensible per-host defaults | hostd paths and the docker endpoint |
| `NOO_FETCH_UNIT` | `noo-fetch.service` | **node-agent side, not gateway.** `internal/hostd/worker_ops.go`: the systemd oneshot unit `prep-host` installs beside its 60s timer, run immediately on demand instead of waiting for the next tick |

## Python workers

| Variable | Default | Purpose |
|---|---|---|
| `NOO_WORKER_SURFACES` | `all` when unset (a typo falls back to `all` with a warning) | `core` \| `ml` \| `ml-intel` — which handler set this container registers (`workers/__init__.py`). The images bake it: `noo-worker` runs `core`, `noo-trellion` `ml`, `noo-trellion-intel` `ml-intel`; it is not an operator knob, and it is not an add-on switch (add-ons are the `addons:` map) |
| `NOOMESH_ADDON_PACKAGES` | — | comma list of add-on package names noomesh should read extensions from where the package is mounted rather than installed (an installed add-on registers itself through the `noomesh.addons` entry point and needs no entry here). Each package declares what it contributes (CLI groups, MCP tool definitions) in `NOOMESH_EXTENSIONS`; noomesh names no package (`addon_roles.py`) |
| `NOO_WORKER_GLOBAL_CONCURRENCY`, `NOO_WORKER_TIMEOUT_SECS`, `NOO_WORKER_RSS_LIMIT_MB` | `32`, `120`, `0` | limits (`worker.*` in YAML) |
| `NOO_WORKER_SUPERVISOR`, `NOO_WORKER_MEM_LIMIT` | — | compose-side supervision |
| `NOO_HARNESS_DEFAULT_POLICY` | `manual` | the harness policy a node is born with (`auto`, `manual`, `off`) — stamped on its config row when provisioning or a first placement creates it, and applied to a node with no row; per node: `noo cluster provision <node> --harness …` / `noo cluster set-config <node> --harness …`. Overridable in `noo_settings` |
| `NOO_TASK_STALE_SECS` | 2 × `NOO_HARNESS_TURN_TIMEOUT_SECS` | how long a live task may go without a checkpoint before it is reported stale (`task.stale` operator alert, `stale` in `noo tasks list`); never acted on automatically |
| `NOO_TASK_LOOP_BUDGET` | `20` | the loop budget a task gets when neither the request nor the node it lands on says otherwise (`noo cluster set-config <node> --loop-budget <n>`); 1..=500. Overridable in `noo_settings` |
| `NOO_COLLAB_WAIT_SECS` | `300` | how long `POST /api/agents/collaborate` waits for its role tasks before answering with whatever has settled (`wait: 0` in the body returns the task ids at once) |
| `NOO_HARNESS_DISPATCH` | `1` | the operator's brake on node-hosted turns: `0` keeps every turn on the controller even where a harness is placed (`coordinator/dispatch.rs`) |
| `NOO_HARNESS_TURN_TIMEOUT_SECS` | `900` | how long a turn handed to a node's harness may take end to end before the gateway reports it failed |
| `NOO_HARNESS_MODEL_URL`, `NOO_HARNESS_MODEL`, `NOO_HARNESS_BACKEND`, `NOO_HARNESS_MAX_TURNS` | — | read by `noo-gateway harness` (the loop on a node); the node agent sets them from the harness placement — never by hand |
| `NOO_SANDBOX_EXTRA` | `0` | extra anonymous sandbox replicas (`sandbox-extra`, same image and hardening as `noo-sandbox`); they share the `sandbox` DNS name, which Docker rotates across them, so `python_exec` calls spread without a client change |
| `NOO_WORKER_EXTRA` | `0` | extra anonymous worker replicas (`worker-extra`, same image/env as `noo-worker`); they share the `workers` NATS queue group so each request runs once. Measure with `scripts/bench-sessions.py` before raising it |
| `NOO_TRELLION_DATABASE_URL` | compose-injected (`noo_trellion@postgres/noomesh`) | trellion's own DSN |
| `NOO_TRELLION_EMBEDDING_URL`, `NOO_TRELLION_LLM_URL`, `NOO_TRELLION_GATEWAY_URL` | compose (all three default to the gateway) | trellion's view of the embedder, the LLM and the gateway. Trellion never dials a backend directly: its embeddings and its LLM calls (graph extraction, answer synthesis, image descriptions) go through the gateway, which routes them over the mesh like any chat |
| `DATABASE_URL`, `PAGEINDEX_DSN`, `PGVECTOR_URL` | — | DSN, resolved in that order for the Python side. No password in the URL on the gateway or worker: libpq/sqlx take it from `PGPASSFILE` |
| `PGPASSFILE` | `/run/secrets/pgpass` when the store holds a role password | the pgpass file compose delivers (0400). The launcher derives its body — `noo` + `noo_app` for the gateway, `noo_app` for the worker (`derive_file_secrets`, `scripts/lib-secrets.sh`) |
| `NOO_PGPASS_GATEWAY`, `NOO_PGPASS_WORKER` | derived | **launcher-process only** — the two pgpass bodies compose copies into the containers; never in `.env`, the store, or any container's environment |
| `PAGEINDEX_EMBEDDING_URL`, `PAGEINDEX_EMBEDDING_BACKEND`, `PAGEINDEX_EMBEDDING_MODEL`, `EMBEDDING_DIM`, `EMBEDDING_MODEL` | — | embedding (same client rules as the gateway) |
| `PAGEINDEX_LLM_URL`, `PAGEINDEX_LLM_MODEL` | — | the worker's direct LLM endpoint, and the model name trellion asks the gateway for (an exact-match routing hint: place that model on the node you want extraction to run on) |
| `NOO_EMBEDDING_BACKPRESSURE_THRESHOLD` | `5000` | pause ingest when the embed queue is deep |
| `NOO_MIGRATIONS_ENVS` | — | which Alembic envs the migration step runs |
| `NOO_CONFIG`, `NOO_SETTINGS_FILE` | — | config file path; settings snapshot path |
| `NOO_GATEWAY_URL`, `CONTROLLER_URL`, `PIPELINE_GATEWAY_URL` | — | the gateway, for handlers that call back over HTTP |
| `NOO_JWT_SECRET`, `NOO_CLUSTER_SECRET`, `NOO_NODE_AGENT_TOKEN`, `NOO_AUDIT_HMAC_KEY`, `NOO_ENCRYPTION_KEY` | — | shared credentials; **secret store** |
| `NOO_EXEC_APPROVAL_MODE` | posture (unset → `strict`) | same gates as the gateway |
| `NOO_ALLOW_LOCAL_PYTHON_EXEC` | off | run `python_exec` in-process instead of the sandbox (dev only) |
| `NOO_EGRESS_ALLOWLIST` | — | hosts tools may reach |
| `NOO_PROACTIVE_ENABLED` | — | the proactive loop |
| `NOO_DESIRED_MODELS`, `NOO_MODEL_VENDORS`, `NOO_MODEL_TASKS`, `NOO_MODEL_PUBLISHERS`, `NOO_MODEL_PUBLISHER_MODE`, `NOO_MODEL_FILTER_MODE` | — | model catalog filters |
| `RESEARCH_MAP_MODEL`, `RESEARCH_REDUCE_MODEL` | — | research pipeline |
| `RETRIEVAL_TRACKER_PATH`, `RETRIEVAL_BANDIT_PATH` | compose sets `/data/retrieval_tracker.json`, `/data/retrieval_bandit.json` | retrieval state persisted as JSON on the shared `noo-data` volume, written and read by add-on containers; `RETRIEVAL_TRACKER_FLUSH_*` and `RETRIEVAL_TRACKER_MAX_RECORDS` are add-on-only tuning |
| `BROWSER_PORT`, `BROWSER_IDLE_TIMEOUT`, `BROWSER_MAX_SESSION`, `BROWSER_URL_ALLOWLIST`, `BROWSER_URL_BLOCKLIST`, `BROWSER_VIEWPORT_WIDTH`, `BROWSER_VIEWPORT_HEIGHT` | — | the browser tool |
| `ANTHROPIC_API_KEY`, `OPENAI_API_KEY`, `OPENAI_BASE_URL`, `GOOGLE_API_KEY`, `CLOUD_DEFAULT_PROVIDER` | — | cloud providers (needs `CLOUD_PROVIDERS_ENABLED`); **keys = secret store** |
| `OTEL_EXPORTER_OTLP_ENDPOINT`, `OTEL_EXPORTER_OTLP_INSECURE` | — | tracing export |
| `NOO_PLUGIN_DIR` | `~/.noo/plugins` | plugin discovery |
| `NOO_SKILLS_DIR`, `NOO_SKILLS_HOST_DIR` | `~/.noo/skills` | skill registry |
| `NOO_HOST_SPOOL_DIR`, `NOO_DATA_DIR`, `NOO_DATA_ROOT`, `NOO_PKI_DIR` | — | paths |
| `NOO_TOKEN`, `NOO_JWT_TOKEN` | — | a bearer for the reference CLI |

### Add-on containers

The add-on workers read most of the variables in this file (`NATS_*`,
`NOO_TLS_*`, `PAGEINDEX_*`, `EMBEDDING_DIM`, `NOO_WORKER_*`,
`RETRIEVAL_TRACKER_PATH`), and compose hands them in from the stack
environment; which add-ons run is the `addons:` map, never a variable. Tuning
that only an add-on reads is documented with the add-on, because that code
lives in its own repository.

Variables the stack sets for them:

- **trellion** (`docker-compose.trellion.yml`): `NOO_TRELLION_EMBEDDING_URL`,
  `NOO_TRELLION_LLM_URL`, `NOO_TRELLION_GATEWAY_URL`, `NOO_WORKER_MEM_LIMIT`,
  `NOO_PROACTIVE_ENABLED`, `CLOUD_DEFAULT_PROVIDER`, `OPENAI_BASE_URL`,
  `PAGEINDEX_LLM_MODEL`, `TRELLION_EMBED_MAX_INFLIGHT` (requests in flight per
  process, default 1) and `TRELLION_EMBED_BATCH_MAX` (largest batch, default
  32), the last two set in `noomesh.yaml` `compose_env`. Other `TRELLION_*`
  variables (`TRELLION_ENTITY_QUALITY`, `TRELLION_ENTITY_QUALITY_CONFIG`,
  `NOO_TRELLION_SCHEMA`, the rest of `TRELLION_EMBED_*`) are not passed
  through by compose; setting one means adding it to the service's
  `environment:`. The recall-memory directory is `NOO_RECALL_MEMORY_PATH`
  (default `/data/video_memory`; the directory keeps its historical name), and
  the deprecated `NOO_VIDEO_MEMORY_PATH` is still honoured with a warning
  (the new name wins when both differ).
- **Intelligent tier** (its bundled overlay, `addons/trellion_intel/docker-compose.yml`): reads
  `RETRIEVAL_TRACKER_PATH` / `RETRIEVAL_BANDIT_PATH` plus the trellion
  variables above.
- **evolve** (its bundled overlay, `addons/evolve/docker-compose.yml`): the `NOO_EVOLVE_*` variables
  and the `NOO_AGENT_*` gates above are read by the evolve container from its
  compose environment, not by the gateway.

## Compose-only (interpolated into service definitions)

These never reach application code as config; compose substitutes them
into image names, ports, mounts and backend command lines. Put them in
`compose_env:` in `noomesh.yaml`.

| Group | Variables |
|---|---|
| Node identity | `NODE_ID`, `NODE_IP`, `NODE_TIER`, `NODE_LOCATION`, `CLUSTER_MODE`, `CONTROLLER_IP`, `CONTROLLER_URL`, `GPU_MODEL`, `VRAM_GB`, `GPU_COUNT`, `NOO_AGENT_NVIDIA_VISIBLE` |
| Postgres init | `POSTGRES_DB` (`noomesh`), `POSTGRES_USER` (`noo`), `POSTGRES_PASSWORD`, `POSTGRES_PORT` (`5433` on the host), `POSTGRES_BIND`, `NOO_PG_DATA` |
| Redis / NATS | `REDIS_PASSWORD` (env only — never a `command:` argument; `docker/redis-entrypoint.sh` reads it and refuses to start on an empty value), `NATS_GATEWAY_USER`, `NATS_GATEWAY_PASSWORD`, `NATS_WORKER_USER`, `NATS_WORKER_PASSWORD`, `NATS_NODE_USER`, `NATS_NODE_PASSWORD`, `NOO_NATS_ALLOW_ANONYMOUS`, `NATS_IMAGE` (the nats service carries no `environment:` at all — its users are the digests in `monitoring/nats/users.conf`; `NATS_USER` / `NATS_PASSWORD` / `NOO_NATS_LEGACY_SHARED_CREDS` are retired) (`NOO_NATS_CONFIG` is retired: NATS runs `nats-tls.conf` only, and `scripts/noomesh-start.sh` refuses a `.env` that still sets it) |
| Host ports | `NOO_BIND_ADDR`, `NOO_PORT_GATEWAY`, `NOO_PORT_MCP` (trellion's parked mapping), `NOO_PORT_NODE_AGENT`, `NOO_PORT_NATS`, `NOO_PORT_NATS_CLUSTER`, `NOO_PORT_NATS_MON`, `NOO_PORT_PROMETHEUS`, `NOO_PORT_ALERTMANAGER`, `NOO_PORT_GRAFANA`, `NOO_PORT_NODE_EXPORTER`, `NOO_PORT_NVIDIA_EXPORTER`, `NOO_MODEL_CACHE_PORT`, `NOO_SENSOR_AGENT_PORT` |
| vLLM | `VLLM_IMAGE`, `VLLM_MODEL`, `VLLM_QUANTIZATION`, `QUANTIZATION`, `GPU_MEM_UTIL`, `TENSOR_PARALLEL_SIZE`, `VLLM_TOOL_PARSER`, `VLLM_MAX_MODEL_LEN`, `VLLM_USE_V2_MODEL_RUNNER`, `VLLM_WSL2_ENABLE_PIN_MEMORY`; the secondary instance: `VLLM2_IMAGE`, `VLLM2_MODEL`, `VLLM2_GPU_MEM_UTIL`, `VLLM2_MAX_MODEL_LEN`, `VLLM2_TOOL_PARSER` |
| llama.cpp | `LLAMACPP_MODEL`, `LLAMACPP_PORT`, `N_GPU_LAYERS`, `N_CTX`, `N_THREADS`, `MODELS_DIR` |
| Ollama | `OLLAMA_IMAGE`, `OLLAMA_MODEL`, `OLLAMA_DATA_DIR`, `OLLAMA_URL` |
| AirLLM | `AIRLLM_MODEL`, `MAX_VRAM_GB`, `COMPRESSION` |
| Embedding / rerank | `TEI_MODEL`, `EMBEDDING_MODEL`, `EMBEDDING_DIM`, `RERANK_MODEL`, `HF_TOKEN`, `HF_CACHE_DIR` (an **HF_HOME** — see below) |
| Voice | `WHISPER_MODEL`, `WHISPER_DEVICE`, `PIPER_VOICE`, `PIPER_USE_CUDA` |
| Monitoring | `GRAFANA_PASSWORD`, `NOO_GRAFANA_BIND_ADDR`, `GRAFANA_ROOT_URL`, `NOO_GRAFANA_CONSOLE_URL`, `NOO_GRAFANA_SESSION_TTL`, `NOO_GRAFANA_SSO_KEY`, `GF_SERVER_PROTOCOL`, `LOKI_PUSH_URL`, `NOO_PROMETHEUS_URL`, `NOO_LOKI_URL`, `NOO_LOKI_RETENTION` |
| Images | `NOO_IMAGE_PREFIX`, `NOO_IMAGE_TAG`, `NOO_IMAGE_DIGEST_*`, `NOO_BASE_REGISTRY`, `NOO_ADDON_IMAGE_*` (set only by the launcher from verified add-on pins), `DEV_MODE`, `NOO_SRC_OVERLAY*`, `NOO_UI_STATIC_OVERLAY*`, `TRELLION_PATH`, `TRELLION_INTEL_PATH` (**retired**, inert: intel builds from its own repository now; an operator may still have it set), `TRELLION_SRC*` |
| Channels | `TELEGRAM_BOT_TOKEN`, `GOOGLE_CHAT_KEY_FILE`, `GOOGLE_CHAT_CREDENTIALS`, `GOOGLE_CHAT_BEARER_TOKEN`, `GOOGLE_CHAT_PROJECT_ID`, `GOOGLE_CHAT_PUBSUB_SUBSCRIPTION`, `NOO_GCHAT_PUBSUB_ENGINE` (obsolete selector, warn-and-ignore — see below), `NOO_TELEGRAM_ENGINE` (same), `WHATSAPP_TOKEN`, `WHATSAPP_PHONE_ID`, `NGROK_DOMAIN` (also read directly, see the Gateway table above) — **retired/unread, compose passthrough only, no reader anywhere in this tree**: `TELEGRAM_ALLOWED_USERS` (no longer admits anyone — see the Gateway table above), `TELEGRAM_WEBHOOK_URL`, `NOO_GENERIC_WEBHOOK_CHANNELS`, `CHANNEL_HISTORY_LIMIT`. **Retired and no longer passed through either** (a credential nothing reads is plaintext for nothing — `tests/test_secret_env_has_a_reader.py`): `TELEGRAM_SECRET_TOKEN`, `SLACK_BOT_TOKEN`, `WHATSAPP_VERIFY_TOKEN`, `WHATSAPP_APP_SECRET` |
| Misc | `NOO_ENTITLEMENT`, `NOO_HOST_GID`, `NOO_ARTIFACT_DIR`, `NOO_AUDIT_LOG_FILE`, `NOO_ENROLL_*`, `NOO_TAILSCALE_*`, `NOO_SENSOR_AGENT_PRIVILEGED`, `HOME`, `PWD` |

`NOO_BASE_REGISTRY` (default `ghcr.io/noomesh/dhi`) is where the six third-party runtime images come from: redis, loki, prometheus, alertmanager, grafana and node-exporter, as `${NOO_BASE_REGISTRY}/<name>:<tag>`. The default is the DHI mirror family. Every service key and data volume is handed to uid 65532: the DHI runtime images' `nonroot`, and the compose `user:` of the two `-dev` variants (redis, grafana), which do not run as root. `ghcr.io/noomesh` without `dhi/` publishes the upstream official images under the same names and tags. Those run as other uids (nobody, 10001, 472), and pointed there the monitoring containers restart-loop on `permission denied`. noo 0.6.0 and 0.6.1 wrote that value when switching to the public channel. From 0.6.2, `noo upgrade` on a public-channel install corrects exactly `ghcr.io/noomesh` to `ghcr.io/noomesh/dhi` in `~/.noo/.env`, prints one line saying so, and never touches any other value. The `image family` row of `noo cluster verify --controller` fails when a running container's image or uid is not the family its key is handed to.

Add-on images (`trellion-intel`, `evolve`) are licensed and released from the add-ons' own repositories, each with its own signed lock (docs/development/addons.md). The controller pins them by digest in `addons.lock`, beside `stack.lock`. The pins are written by `noo addons enable|upgrade` and `noo upgrade --stack`, which pull the images with the store's `NOO_ADDON_REGISTRY_TOKEN` when it is set (the vendor override, from GHCR), and otherwise from the entitlement's `pull` location (the vendor's add-on registry, with the entitlement as the credential). A `--dist` start exports `NOO_ADDON_IMAGE_<NAME>` (for example `NOO_ADDON_IMAGE_TRELLION_INTEL`, `NOO_ADDON_IMAGE_EVOLVE`) only from a pin that re-verifies offline for the running tag and whose image is local. Otherwise it refuses, naming the add-on and `noo addons upgrade`. The launcher never pulls an add-on, and any `NOO_ADDON_IMAGE_*` already in the environment is dropped. `NOO_INTEL_IMAGE`, `NOO_EVOLVE_IMAGE` and their `*_PREFIX` twins are **retired** and ignored; the launcher warns when `.env` still sets one.

### Model weights

| Variable | Default | Notes |
|---|---|---|
| `HF_CACHE_DIR` | `$NOO_DATA_ROOT/hf-cache` | An **HF_HOME**, not a hub directory: the path that *contains* `hub/`. Compose binds it to `/root/.cache/huggingface` for the vLLM-family backends and to `/hf-store` for the weight cache, whose nginx `location /hf/` aliases `/hf-store/hub/`. Point it at a bare hub archive (`models--*` at the top level) and the stack still starts: `/hf/` answers `404`, every node's preseed fails, and nothing says "wrong layout". Verify with `ls "$HF_CACHE_DIR/hub" \| grep '^models--'` — see [models/weight-cache.md](../models/weight-cache.md) |
| `MODELS_DIR` | `$NOO_DATA_ROOT/models` | Bare `*.gguf` files, served at `/gguf/`. Flat, no `hub/`. |

### Monitoring

| Variable | Default | Notes |
|---|---|---|
| `GRAFANA_PASSWORD` | *(none)* | Seeds Grafana's OWN admin account so it is never admin/admin — not `NOO_ADMIN_PASSWORD`, and not a login anywhere (`grafana.ini` disables Grafana's password login and basic auth). `noo onboard` mints it into the secret store. `.env.example` ships it **empty on purpose**: it used to read `changeme`, and the launcher guard only refused blank, so the placeholder booted. The launcher now refuses `changeme`/`admin`/`password`/… too, and `noo security scan` reports one as CRITICAL. Grafana copies this into its own DB on FIRST boot only — changing the var later does not change the login. |
| `NOO_GRAFANA_BIND_ADDR` | `127.0.0.1` | Where Grafana's port is published: loopback. On a `NOO_BIND_MODE=tailnet` controller, `tailscale serve --https=<3000+offset>` fronts that port on the tailnet name with the tailnet's certificate, and Grafana moves from the tailnet IP to loopback only once that entry is confirmed. If it cannot be written, Grafana stays on the tailnet IP, where browsers refuse the cluster-CA certificate. `noo onboard` writes it with `GRAFANA_ROOT_URL`. `noo upgrade --stack` fills it and moves a wider value (`0.0.0.0`, a LAN IP) back. Deliberately **not** `NOO_BIND_ADDR`, whose default is `0.0.0.0`. |
| `GRAFANA_ROOT_URL` | written by `noo onboard` | The URL the **browser** uses for Grafana: `https://localhost:<3000+offset>`, or `https://<tailnet-name>:<3000+offset>` on a tailnet controller (answered by `tailscale serve`, which `noo onboard` and `noo upgrade --stack` configure). The gateway receives it as `NOO_GRAFANA_URL` and sends people there from the console's "Open Grafana" with a short token for their noomesh account; empty = Grafana single sign-on is off (that route answers 503, `noo cluster verify` FAILs `grafana door`). `noo upgrade --stack` fills an empty one. An operator-set value is kept. |
| `NOO_GRAFANA_CONSOLE_URL` | written by `noo onboard` on a tailnet controller | Where a bookmark of Grafana is sent: `https://<tailnet-name>[/<instance>]/#/observability?open=grafana`, the console's Observe panel, which opens Grafana after the console's own login. Grafana gets it as `[auth] signout_redirect_url`, and `tailscale serve` maps `/login` on Grafana's port to Grafana's `/logout`, which redirects there. Empty (the loopback door) = a bookmark shows Grafana's bare welcome page. `noo upgrade --stack` fills an empty one; an operator-set value is kept. |
| `NOO_GRAFANA_SESSION_TTL` | `15` | Grafana session length in minutes, clamped to 1–60. Grafana JWT auth is stateless, so this is exactly how long a disabled noomesh account's open Grafana tab keeps working. |
| `NOO_LOKI_URL` | `https://loki:3100` (compose) | Where the gateway (and the worker's security-audit task) reach Loki; the gateway dials it with its own leaf over mTLS. Compose set the unread name `LOKI_URL` until 2026-09-28, so `noo logs status` answered "not configured" on every install. `services.loki_url` in `noomesh.yaml` is the fallback when the env is empty. |
| `NOO_ALERTMANAGER_URL` | `https://alertmanager:9093` (compose) | Where the gateway reads Alertmanager for `noo_alerts_list` (`GET /api/alerts/list`), over the same cluster-CA mTLS as Prometheus; read-only. `services.alertmanager_url` in `noomesh.yaml` is the fallback. |
| `NOO_LOKI_RETENTION` | `720h` | How long Loki keeps log lines AND the oldest line it accepts (`reject_old_samples_max_age` is the same value, so a node replaying a buffered window is not refused). A multiple of 24h. `720h` ≈ 0.9 GB on disk fleet-wide, `2160h` ≈ 2.7 GB — see [monitoring.md](../operating/monitoring.md#retention-and-disk). Change it, then `noo stack restart --force loki`. |
| `NOO_GRAFANA_SSO_KEY` | `/app/pki/sso/grafana.key` (compose) | Gateway-side path of the P-256 private key that signs Grafana session tokens (`noo security pki issue-sso-key`; onboard issues it). Grafana mounts only the public half. |
| `NOO_MODEL_CACHE_TLS_PORT` | `8443` | The model-weight store's host port (mTLS: a node or gateway leaf is required), published on `NOO_BIND_ADDR`. `NOO_MODEL_CACHE_PORT` (the plaintext 8083 listener) was removed with the plaintext listener (2026-09-29) and is no longer read by compose. See `docker/model-cache.nginx.conf`. |

`NOO_GCHAT_PUBSUB_ENGINE` and `NOO_TELEGRAM_ENGINE` are accepted but
ignored — both pipelines are Rust and in-process; the gateway warns on any
other value.

## Host scripts only (backups)

Read by `scripts/backup-controller.sh`, `scripts/restore-drill.sh` and
`scripts/noo-backup-rotate-passphrase.sh`. They never reach a container.

| Variable | Default | Meaning |
|---|---|---|
| `NOO_BACKUP_PASSPHRASE` / `NOO_BACKUP_PASSPHRASE_FILE` | unset | AES-256 passphrase for the Postgres dump. **Required** — with no value the backup refuses to run rather than write plaintext. `noo onboard` generates it. |
| `NOO_AGE_BACKUP_PASSPHRASE` / `NOO_AGE_BACKUP_PASSPHRASE_FILE` | unset | AES-256 passphrase for the age-key backup. **Required** whenever an age key is present, and must DIFFER from the above or recovery is circular. Keep a copy OFF the machine — it is the key to the key. |
| `NOO_BACKUP_DIR` | `~/noo-backups` | output directory, forced to mode 0700 |
| `NOO_BACKUP_RETAIN_DAYS` | `7` | age-based retention for pg dumps |
| `NOO_BACKUP_KEEP_MIN` | `3` | newest dumps kept regardless of age |
| `NOO_SECRETS_KEEP_BACKUPS` | `3` | copies of `secrets/env.sops` kept beside it; every commit takes one, and each is readable with the same age key, so the pile is bounded. Floored at 1 — the newest copy is the only rollback from a bad rotation. |
| `NOO_SECRETS_MAX_AGE_DAYS` | `90` | credential review interval; `security secrets audit` reports keys older than this against `secrets/rotations.json` |
| `NOO_BACKUP_OFFSITE` | unset | where a copy of each backup goes: `ssh:user@host:/path`, `dir:/path`, `s3:s3://bucket/prefix`, `portable`, `none`. **Unset is not "no"** — it means nobody has decided, and `noo backups status` says so. Set it with `noo backups setup`. |
| `SOPS_AGE_KEY_FILE` | `~/.config/sops/age/keys.txt` | which age key is backed up |

`NOO_BACKUP_ENCRYPT_REQUIRED` was removed on 2026-09-11. Encryption is not
optional, so there is nothing to opt in to.
