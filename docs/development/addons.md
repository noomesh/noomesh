# Building an add-on

An add-on is a separate service the gateway reaches, deployed alongside it
and gated by the `addons:` map in `noomesh.yaml` plus (for licensed ones) a
signed entitlement — there is no per-add-on environment variable. Four are
declared in the gateway's `ADDONS` table (`gateway-rust/src/addons.rs`)
today: **trellion** (the ML knowledge pack, on by default), **identity**
(free, on by default), **evolve** (opt-in) and **trellion-intel** (trellion's licensed tier, opt-in).
A fifth, **voice** (whisper STT + piper TTS), is launcher-only: it composes
an overlay the same way but is never in `ADDONS` and never reported by
`/health`.

This page is the contract. Follow it and your add-on plugs into the gateway
without a single new line of gateway routing code. An HTTP add-on does not even
need a row in `ADDONS`: the gateway's runtime registry
(`gateway-rust/src/addon_registry.rs`) registers any add-on the operator turns
on, from the route manifest its image delivers, once its signed lock has been
verified (see "Registration" in step 2a).

## The two layers

Every add-on shares the **declaration** layer and picks **one** transport.
They are deliberately separate: presence and messaging are the same problem
for every add-on, but NATS and HTTP are genuinely different surfaces and
pretending otherwise would make both worse.

| Layer | Where | What it decides |
|---|---|---|
| Declaration | `gateway-rust/src/addons.rs` — one `Addon` row (the add-ons that shipped with the stack); a third-party HTTP add-on is declared by the operator (`addons.<name>: true`) and registered at runtime | Is it supposed to be here? What flag, which polarity, which entitlement, what does a refusal say? |
| Transport (HTTP) | your repo's route manifest, delivered to `/opt/noo/addon-routes/<name>/routes.json` | Which paths the gateway proxies to it (validated and mounted at startup) |
| Transport (NATS) | a subject prefix, matched in `worker_client.rs` | Which subjects it answers |

Pick HTTP if your add-on serves an API. Pick NATS if it answers worker
subjects on the existing bus. Trellion does the second; evolve does the
first.

## What your repo must provide

The gateway side is one table row. Everything else lives in your repo,
because everything else is something only you can keep true.

| # | Artifact | Where | Why it is yours |
|---|---|---|---|
| 1 | The service | your `src/`, serving the declared paths + `/health` | — |
| 2 | Route manifest | in your package and image (the example below: `src/example_addon/example-addon.routes.json`) | the gateway mounts your HTTP surface from it at runtime; the core names none of your routes |
| 3 | Contract test | `tests/test_gateway_route_contract.py` | the gateway cannot tell whether you serve what your manifest declares; only you can |
| 4 | Manifest delivery | a one-shot service in your overlay that writes the manifest into a volume the gateway mounts read-only (dev: bind-mount the file) | the manifest the gateway reads must be the one in the image beside it |
| 5 | CI that runs 3 | a workflow | an unrun check is documentation |
| 6 | MCP tool fragment | `mcp-tools-<addon>.json`, named by `NOO_MCP_EXTRA_MANIFEST` | optional — only if your add-on should appear as MCP tools |
| 7 | Compose overlay | `docker-compose.<addon>.yml` with an explicit env allowlist | the launcher composes it when `addons.<name>` is declared on in `noomesh.yaml` |
| 8 | Gateway client | e.g. `gateway_client.py` | everything in the gateway's domain routes back over HTTP, and only you know which calls you make |
| 9 | Database declaration | `system.json` in your signed bundle | optional: your schema and roles, provisioned by the gateway (see [Declaring a database](#declaring-a-database)) |
| 10 | Workload declaration | `workloads.json` in your signed bundle | optional: containers noomesh may start, stop and drain for you (see [Declaring workloads](#declaring-workloads)) |

## A minimal worked example: `example-addon`

`example-addon` is fictional. It is the smallest add-on that has all eight
artifacts, so each one is shown once, in the form the rest of this page
defines.

```text
example-addon/
  src/example_addon/
    app.py                          # 1  the service: /health + the declared paths
    example-addon.routes.json       # 2  the route manifest
    gateway_client.py               # 8  calls back into the gateway over HTTP
  tests/test_gateway_route_contract.py   # 3  manifest == what app.py serves
  .github/workflows/ci.yml          # 5  runs 3
  mcp-tools-example-addon.json      # 6  optional MCP tool fragment
  docker-compose.example-addon.yml  # 7  overlay, 4  manifest delivery
```

1. **The service** serves `GET /health` and the one path it declares.
2. **The manifest** declares that one path (shape in step 2a):

   ```json
   {
     "version": 1,
     "addon": "example-addon",
     "base_url_env": "NOO_EXAMPLE_ADDON_URL",
     "base_url_default": "https://noo-example-addon:8090",
     "routes": [
       { "name": "status", "method": "GET", "path": "/api/example-addon/status", "min_role": "operator" }
     ]
   }
   ```

3. **The contract test** is the one in step 4, pointed at that file.
4. **Manifest delivery**: the overlay runs a one-shot service from the
   add-on's own image that copies the manifest into a named volume; the
   gateway mounts that volume read-only at
   `/opt/noo/addon-routes/example-addon` and waits for the one-shot to finish.
5. **CI** runs the contract test on every push.
6. **MCP fragment** (optional): `mcp-tools-example-addon.json`, named by
   `NOO_MCP_EXTRA_MANIFEST`, exposes `status` as a tool.
7. **Overlay**: `docker-compose.example-addon.yml`, an explicit `environment:`
   allowlist, no `profiles:`.
8. **Gateway client**: `gateway_client.py` sends the cluster-HMAC bearer the
   gateway expects on each call and is the only place the add-on talks to the
   gateway.


**Why 3 and not "the gateway checks it".** The gateway proxies a path; it
cannot know whether the far end answers. A path is a string in your manifest
and in your handlers, and renaming one leaves everything compiling and the
route 404ing in production with nobody watching. An MCP tool can sit in exactly that state indefinitely
(served by the add-on, never mounted by the gateway, advertised to every MCP
client) when neither side compares the two lists.

This is the same convention the console already uses: `ui/` vendors
`contracts/openapi.json` and runs an audit against the gateway's router,
with a changelog as the coordination channel. Follow it.

## Step 1 — declare it

An add-on that is not shipped with the stack needs no row: skip to step 2a,
where the operator's `addons.<name>: true` and your manifest are the whole
declaration. The row below is for add-ons the stack itself ships (it carries
the polarity, licence feature and refusal text).

One row in `ADDONS` (`gateway-rust/src/addons.rs`):

```rust
Addon {
    name: "yourthing",                       // the /health `addons.<name>` key
    default_on: false,                       // opt-in; `true` = opt-out
    disabled_msg: YOURTHING_DISABLED_MSG,    // what an operator sees
    requires_feature: Some("yourthing"),     // None for an open add-on
    unlicensed_msg: YOURTHING_UNLICENSED_MSG,
}
```

There is deliberately no `env` field: the switch is the `addons.<name>` key
in `noomesh.yaml`, read by both the launcher (compose overlays) and the
gateway (routing/refusals) from the same file. No per-add-on environment
variable exists or is accepted. Set `routes_manifest: true` on the row only to
make a missing manifest a loud refusal (the diagnostic for an image from before
manifests shipped); the registry reads the manifest of every enabled add-on
whether or not its row says so.

`default_on` is the whole polarity decision. An open pack people expect to
have (trellion) is opt-out; anything licensed is opt-in.

The two messages matter more than they look. A disabled add-on, an
unlicensed one and a broken one must stay **three distinguishable answers** —
that is the reason this table exists rather than a scattering of env reads.

## Step 2a — declare your routes (HTTP add-ons)

Write your manifest in your own repo and ship it in your image. The gateway
reads it at startup from `/opt/noo/addon-routes/<name>/routes.json` when your
switch is on (`gateway-rust/src/addon_registry.rs`, `addon_proxy.rs`); you touch
no gateway code.

### Registration

The gateway keeps a **runtime registry** of HTTP add-ons, built at startup. An
add-on is registered when all three hold:

1. the operator switched it on: `addons.<name>: true` in `noomesh.yaml`;
2. its image delivered a manifest the gateway accepted (below);
3. the launcher vouches for its signed lock: `noo addons enable|upgrade` verified
   the lock against the add-on's key in the installed entitlement and checked
   that it lists this stack (`supports_stack`), and `noo stack start|restart`
   re-verified it offline and handed the gateway the verdict
   (`NOO_ADDONS_VERIFIED`).

An add-on that fails 2 or 3 is **refused, never silently skipped**: no routes,
`/health` reads `addons.<name>: "unhealthy"`, and the log says why. A missing
lock reads: "add-on `<name>` is enabled in noomesh.yaml but has no verified lock
for this stack ... Run `noo addons upgrade <name>`". A lock verified for another
stack is refused the same way, naming both stacks.

When `noo stack start|restart` cannot verify an add-on's pin for the running
stack (a lock for another stack, a bad signature, edited bundle files, an
expired development key, its image not local), it leaves **that add-on** out of
the start and starts the rest: it prints `REFUSED add-on <name>: <why>` with the
remedy (`noo addons upgrade <name>`, or `noo addons disable <name>`), does not
compose its overlay, hands the gateway none of its bundle declarations, stops a
container left from an earlier start, and ends with "Services started WITHOUT
add-on(s) <name>". The add-on is absent from `NOO_ADDONS_VERIFIED`, so its
routes are refused (even from a `routes.json` an earlier start left in the
routes volume), and it is named in `NOO_ADDONS_REFUSED`, so the systems broker
runs no DDL for it. `noo addons list|show` read it as refused and the
`add-on pins` row of `noo cluster verify --controller` fails naming it. A
`stack.lock` that is missing or for another tag still refuses the whole start.

Names are lowercase letters, digits, `-` and `_`, starting with a letter (at
most 32). A name with `-` reads its upstream override from the variable with `_`
(`pai-voice` reads `NOO_PAI_VOICE_URL`; the host stays `noo-pai-voice`) and may
declare scopes as `pai-voice:<word>`.

The routes are mounted once, when the router is built at startup. A reload
rebuilds the registry (what is registered, what is delegated), but an add-on that
appears later gets its routes at the next start.

**Getting a lock the operator trusts.** A third-party add-on is released as a
signed `noo-addon-lock/2` bundle (see "The signed add-on lock" below). The
operator trusts your signing key with `noo addons trust-key <name> <pubkey>
--registry <root>` (the CLI ships no key for you), and your images must sit
under that registry root and be pullable anonymously.

**Development keys.** To develop and test an add-on on your own mesh before it
ships in a release, the operator can trust a temporary development key instead
of your release key:

```bash
noo addons trust-key yourthing <dev-pubkey> --registry <root> --dev --expires 14d
noo addons enable yourthing --lock ./addon-lock.json
```

- `--expires` is required with `--dev` (a whole number of `d`, `h` or `m`, at
  most `30d`) and refused without it. The key is stored under
  `addon_trust.yourthing.dev_keys` with `dev: true` and an absolute UTC
  `expires_at`, never among the release `keys`. Trusting it again renews it.
- It is scoped to that one add-on name on this mesh. No entitlement, flag or
  release can carry it: an anchor read from JSON never holds a development key.
- A key is never both: trusting a key without `--dev` that is a development key
  for any add-on is refused, and the reverse.
- A lock that only the development key signed verifies until `expires_at`. After
  that the launcher refuses it exactly like an untrusted key, naming the expiry
  and the renew command, and a gateway that is still running stops serving the
  add-on's routes and reports it `unhealthy` with the reason.
- While it is live, `/health` keeps `addons.yourthing: "enabled"` and adds
  `addons_dev.yourthing: "dev (expires <date>)"`; `noo addons list` shows it
  under "third-party" as `DEV until <date>` (`DEV EXPIRED <date>` after), and
  `noo addons verify` says `signed by DEV key`.
- It never ships. Your release verifies the lock with
  `noo security addon-lock verify ... --key <release key>`, which refuses a
  `--key` that is a development key and a lock that only a development key
  signed (it knows the keys given with `--dev-key` and every development key in
  the install's noomesh.yaml). The stack release records image digests only and
  never reads an add-on key. Shipping means re-signing with your release key;
  nothing about the development key carries over.
- `noo addons untrust-key yourthing --dev` removes the add-on's development keys
  (`untrust-key yourthing <pubkey> --dev` removes one).

Enrolling a development key is a local operator action on the controller: the
CLI edits the install's noomesh.yaml, and the gateway accepts a write of the
`addon_trust` section only from an admin.

**Upgrading.** An install that upgrades keeps its enabled add-ons working on the
first boot: the new launcher already verified every composed licensed add-on's
pin before the gateway started. If the gateway is started by an older launcher
that does not report a verdict, it loads only the add-ons it already knew, as
before, and logs that `noo upgrade` updates the launcher; it never extends that
to a name it did not know.

```json
{
  "version": 1,
  "addon": "yourthing",
  "base_url_env": "NOO_YOURTHING_URL",
  "base_url_default": "https://noo-yourthing:8090",
  "timeout_secs": 60,
  "routes": [
    { "name": "status", "method": "GET", "path": "/api/yourthing/status", "min_role": "user" },
    { "name": "list", "method": "GET", "path": "/api/yourthing/items", "query": true,
      "min_role": "operator", "scopes": ["yourthing:read_items"] },
    { "name": "detail", "method": "GET", "path": "/api/yourthing/items/{item_id}",
      "params": { "item_id": "uuid" }, "min_role": "operator" },
    { "name": "run", "method": "POST", "path": "/api/yourthing/run", "min_role": "operator" },
    { "name": "internal_tick", "method": "POST", "path": "/api/yourthing/tick",
      "internal": true }
  ]
}
```

| Field | Meaning |
|---|---|
| `name` | Stable key. Gateway code calls a route by this, never by its path. |
| `method` | `GET`, `POST`, `PUT`, `PATCH`, `DELETE`, or `WS` (a WebSocket route, see "WebSocket routes"). Every method but `GET` and `WS` is a **write** and follows the `POST` rule: `operator` or `admin` unless `owner_scoped`, no `scopes`, never where the front door admits a User. `PUT`/`PATCH`/`DELETE`/`WS` need a gateway from the release that reads them. |
| `aliases` | Extra gateway paths reaching the same route — for a path that shipped under more than one spelling. |
| `params` | `{"id": "uuid"}` (`uuid` or `string`). A malformed uuid is a 400 from the gateway; garbage never reaches your URL. |
| `query` | Pass the caller's query string through. |
| `internal` | Callable from gateway code, **not mounted** on the public API. |
| `timeout_secs` | Per route (1–600); falls back to the manifest's. |
| `min_role` | `user`, `operator` or `admin`: the lowest role that may call this public route. **Absent means `operator`**, for every method. Any other value refuses the whole manifest. A write (`POST`, `PUT`, `PATCH`, `DELETE`) cannot be `user` unless `owner_scoped`. |
| `scopes` | Optional, `GET` only: add-on scopes written `<yourname>:<word>` that also open the route to an account holding `read` plus the scope, below `min_role`. Always namespaced, so a manifest can never name a core scope (`graph`, `ingest`, …). |
| `owner_scoped` | A write at `min_role: "user"` whose add-on keeps every row to the calling account (see below). |
| `max_message_bytes` | `WS` only: largest message (and frame) either way, bytes. Default 1048576 (1 MiB), at most 16 MiB. |
| `idle_timeout_secs` | `WS` only: no frame either way for this long closes the socket (1001). Default 300, 1–3600. |
| `max_connections_per_user` | `WS` only: sockets one account may hold open on this route. Default 4, 1–64; the next is a `429`. |
| `note` | Free text for whoever reads the file. |

Any other field is refused.

A third **top-level** key serves your own web UI (see "Serving a UI"):

| Key | Meaning |
|---|---|
| `ui` | `{"upstream_path": "/", "min_role": "user", "title": "Example"}`. The gateway serves your UI on an origin of its own, `https://<host>:<your port>/<rest>`, from `<your upstream><upstream_path>/<rest>`. `upstream_path` defaults to `/` (a plain path, no `{param}`); `min_role` as on a route (absent = `operator`); `title` is 1–64 plain characters for the console's link; `timeout_secs` 1–600. Any other field refuses the manifest. A manifest with a `ui` may declare no routes. |

Two **top-level** keys (beside `routes`, not inside a route) prepare an add-on
to act for a present person through that person's own tasks:

| Key | Meaning |
|---|---|
| `delegate` | `"tasks"` is the only value. Declares that the add-on asks to create and steer a present person's tasks. An unknown value refuses the manifest. |
| `task_events` | `{"method": "POST", "path": "/..."}`: where the gateway POSTs task events for this add-on. Valid only with `delegate: "tasks"`; the method must be `POST`; the path is plain (no `{param}`) and must not equal or match **any public route** of the same manifest (aliases and `{param}` routes included), so it is never reachable through the front door. An `internal` route's path is allowed. |

A route-level boolean keeps the delegated token off routes that never need it
(a GPU media route, say): `"receives_delegation": true` on a **public** route
means the gateway may send that route the token. It defaults to false, is valid
only when the manifest declares `delegate: "tasks"` (otherwise the manifest is
refused), is refused on an `internal` route and on a route that shares the
`task_events` path. The registry answers
`route_receives_delegation(method, path)`, matching the way the proxy picks a
route (aliases and `{param}` routes included; when several routes match, all must
opt in). The token is minted only when that is true **and** `operator_enabled()`.

Declaring `delegate` grants nothing. The operator must also enable it for the
add-on, in `noomesh.yaml`:

```yaml
addon_delegation:
  yourthing:
    tasks: true
```

The default is off, and each half alone is off: the registry's
`operator_enabled()` is true only when the manifest declares `delegate: "tasks"`
**and** `addon_delegation.<name>.tasks` is true. The `addon_delegation` section
is admin-only to write through the config API (a gated section), and the
gateway reads it at startup. Minting the delegated token and delivering task
events are separate changes (noomesh-internal i143); this release parses,
validates and exposes the keys. A gateway that predates them refuses a manifest
that carries them (unknown keys fail the whole manifest), so ship them with a
`supports_stack` that starts at the release that reads them.

### Delivering it

Your overlay hands the file to the gateway read-only: a one-shot service from
the add-on's own image writes the manifest into a named volume, the gateway
mounts that volume at `/opt/noo/addon-routes/<name>` (`:ro`) and waits for the
one-shot to complete.
A file, not a fetch: nothing at boot depends on the network or on the add-on
being up first, and an image upgrade rewrites the file.

### What the gateway checks

The gateway still decides what it exposes. A manifest declares paths, an
upstream and the permission each route needs, and the gateway refuses the whole
add-on when any of these fails:

- `version` is 1 and `addon` is the add-on it was delivered for;
- the upstream is your own service: `base_url_env` is `NOO_<NAME>_URL` and
  `base_url_default` is `https://noo-<name>[:port]`, no other host, no
  credentials, path or query;
- paths are plain segments (no `..`, no wildcard), every `{param}` is
  declared, public paths live under `/api/` and outside the gateway's own
  namespaces (`/api/addons/`, `/api/security/`, `/api/config`, … —
  `RESERVED_PREFIXES`);
- routes the gateway calls by name (`CALLED_BY_NAME`: the console and CLI
  pieces and the gateway's own scheduled calls) are `internal`;
- a public `POST` is one the front door already refuses a User-tier caller,
  so a manifest cannot place a write where a User is admitted, unless the
  route declares `"owner_scoped": true` (see "Who may call a route");
- `min_role` is `user`, `operator` or `admin` (never anything else, never read
  as `user`), a write (`POST`, `PUT`, `PATCH`, `DELETE`) is `user` only with
  `owner_scoped`, and `scopes` are `<name>:<word>` on a `GET`;
- a `WS` route lives under `/ws/addons/<name>/`, is never `internal`, and its
  limits are in range; the WS limits appear on no other method;
- `ui.upstream_path` is a plain path and `ui.min_role` a known role;
- `delegate` is `"tasks"` or absent; `task_events` appears only with
  `delegate`, is a `POST`, and names a path no public route of the manifest
  covers;
- no public route collides with a core route.

### Who may call a route

Add-on routes are scoped by permission like every core route, with the same
tiers (User, Operator, Admin). The gateway enforces `min_role` before it
forwards anything, for every method: the global auth middleware runs in front
of every mounted route exactly as it does for core routes, and the add-on
receiver checks again (which also covers `admin` routes and aliases). A caller
is allowed when its role is at least `min_role`, or, on a `GET` that lists
`scopes`, when it holds `read` plus one of them. A refusal is a `403` naming the
role needed, before your service is dialled.

Choose the role by what the route returns. Anything that describes the whole
installation (reflection text, genomes, rewards, policy state, fleet-wide
counts) is `operator`. `user` is for what is per-account and safe for any
signed-in person. Writes are `operator` or `admin` and a scope never widens
them.

**Absent `min_role` is `operator`.** An add-on that does not say who may read a
route (an older release, a third-party add-on) is readable by Operators and
Admins only. Before this field a manifest's `GET` routes were readable by any
User-tier token; that is the one behaviour this narrows, and only for Users.
Declare `"min_role": "user"` on a route a User should keep.

Add-on scopes are checked against the scopes in the caller's token. They are
grantable: `noo security user set-scopes <user> --scope read --scope
<addon>:<word>` (and `service-key issue --scopes <addon>:<word>`) accept a scope
exactly when a loaded manifest declares it on some route, and refuse any other
`<addon>:<word>` with the list of declared ones. The grant ends the account's
sessions; the scope opens that add-on's `GET` route (with `read`) and nothing
else.

#### `owner_scoped`: a User's own writes

The default is: declare it, or it is Operator. A write (`POST`, `PUT`, `PATCH`,
`DELETE`) cannot be `min_role: "user"`, because the front door refuses a User's
writes.

A route may opt out with `"owner_scoped": true`, and only a write at
`"min_role": "user"` may (the flag on any other shape is refused at load, not
ignored). It means the add-on **promises to read and write only rows owned by
the account the gateway forwards**, for example a person's own voice sessions,
notes and tasks. The gateway does not check that promise; add the flag only to
routes that keep it. What the gateway does:

- the tier gate lets a User through to exactly that route (method and path), and
  nothing else the add-on declares;
- it forwards the verified caller on every request, in headers it **sets**
  (the outbound request is built from nothing, so a copy a client sends is
  never passed on): `X-Noo-Requester-Sub` (the account),
  `X-Noo-Requester-Connection` (the session), `X-Noo-Requester-Role` (resolved
  at validation, never re-derived from scopes), `X-Noo-Requester-Scopes`
  (comma-separated), beside the gateway's bearer;
- a call with no verified caller is refused (`401`) rather than forwarded, so
  the add-on never has to guess whose row it is.

The add-on must key every query and every write on `X-Noo-Requester-Sub`, take
no owner from the body or path, and treat an absent header as the gateway
itself, never as "anyone".

```json
{ "name": "voice_session_create", "method": "POST", "path": "/api/voice/sessions",
  "min_role": "user", "owner_scoped": true, "timeout_secs": 30,
  "note": "creates a session owned by the calling account" }
```

An add-on image that declares `owner_scoped` is refused whole by a gateway that
predates the field, for the same reason; roll the gateway first.

Rolling: the gateway rolls first. A gateway that predates `min_role` refuses an
unknown manifest field outright (unknown keys fail the whole manifest), so an
add-on image that declares `min_role` must not meet an older gateway; a new
gateway with an older add-on image treats every route as `operator`.

### When it is missing or wrong

Switched on, with no manifest, an invalid one, or no verified lock for this
stack: **none** of your routes are mounted, never a partial surface. The gateway logs the reason at startup,
`/health` reports `addons.<name>: "unhealthy"`, and every internal call to
you answers with the reason (an image from before manifests shipped with the
add-on is named as the likely cause, with the fix). Switched off: nothing is
read or mounted and the gateway starts normally.

Your routes are not in the public OpenAPI spec or the console's contract;
your own surface types them from your manifest.

### `internal` is a security boundary, not a convenience

A route marked `internal` is reachable from gateway code and from nowhere
else. Use it for anything that should not be triggerable by a caller with API
access: a route only the gateway's own scheduled work calls (`internal_tick`
in the manifest above) is the typical case.

### WebSocket routes

```json
{ "name": "audio_stream", "method": "WS", "path": "/ws/addons/example-addon/stream",
  "min_role": "user", "query": true,
  "max_message_bytes": 1048576, "idle_timeout_secs": 300, "max_connections_per_user": 2 }
```

A `WS` route is a WebSocket the gateway terminates for the client and opens
again to you. In order, for every handshake:

1. **Credential.** A browser cannot set `Authorization` on a WebSocket, and a
   token in a URL ends up in access logs, so `?token=` is never a credential
   under `/ws/addons/`. There are three ways in:
   - **From your own UI** (see "Serving a UI"): open
     `wss://<host>:<your port>/ws/addons/<name>/…` on your UI's origin. The
     origin's session cookie authenticates the upgrade, and the `Origin`
     header must be that origin. No ticket.
   - **From another browser page on the console origin**: call
     `POST /api/addons/<name>/ws-ticket` with `Authorization: Bearer <token>`,
     get `{"ticket": "...", "param": "ticket", "expires_in": 30}`, and open
     `wss://<console host>/ws/addons/<name>/…?ticket=<ticket>` within 30
     seconds. A ticket is random, bound to that person and that add-on, and
     consumed by the first handshake that presents it (valid or not).
   - **A non-browser client**: `Authorization: Bearer` on the handshake to
     the console port.
2. **Permission.** The route's `min_role` is checked against the person
   (`403` naming the role), then the per-account cap (`429`), all before you
   are dialled.
3. **Dial, then upgrade.** The gateway opens `wss://noo-<name>[:port]<path>`
   with the cluster CA and its own client certificate (same door as your
   HTTP routes), the gateway bearer and the `X-Noo-Requester-*` headers it
   **sets** (see "Step 3b"), and the delegated task token when the route has
   `receives_delegation`. The query is passed on only with `"query": true`,
   always without `ticket` and `token`. Subprotocols the client asked for
   (`Sec-WebSocket-Protocol`, plain tokens only) are passed on and the one you
   select is echoed to the client. Only when you answered `101` is the client
   upgraded; if you refuse (`4xx`) the client gets your status, if you are
   down it gets a `503` with the reason.
4. **Frames.** Text, binary, ping, pong and close are piped both ways; a close
   code you send reaches the client when it is a sendable one (1000–1003,
   1007–1014, 3000–4999). Each direction awaits the other side's write before
   reading the next frame, so a slow reader slows its writer and nothing
   buffers without bound. Oversize: `1009` to the sender. Idle: `1001` to both.
   The person's access token expiring, or a logout or session revocation,
   closes the client with `4401` (the console's convention: refresh, mint a
   new ticket, reconnect) and you with `1001`.

Serve your socket on your mTLS listener at the same path as the manifest
(`/ws/addons/<name>/…`), read the account from `X-Noo-Requester-Sub` exactly
as on an HTTP route, and keep a User's stream to that account. A gateway
older than this release refuses a manifest with a `WS` route (unknown method),
so ship it with a `supports_stack` that starts at this release.

### Serving a UI

```json
"ui": { "min_role": "user", "title": "Example add-on" }
```

**Your UI gets an origin of its own.** The console keeps the person's access
token in the browser on the console's origin, and no add-on script may read
it. An origin is scheme + host + port, and the fleet is reached at a single
tailnet name (`noo-controller.<tailnet>.ts.net`, no subdomains), so the
gateway gives each add-on with a `ui` an HTTPS listener on a port of its own,
from `NOO_ADDON_UI_PORTS` (default `8450-8459`, room for ten add-on UIs;
widen it, e.g. `8450-8499`, when more add-ons serve one, at the cost of one
published port each). The port comes from a hash of your add-on's name, so
the same set of add-ons always gets the same ports. The listener uses the gateway's certificate, and the console origin
never serves add-on UI.

On that origin, everything is yours and nothing else is there:

| On `https://<host>:<your port>` | Goes to |
|---|---|
| `/`, `/app.js`, `/assets/x.wasm` (any other GET/HEAD) | your upstream, `<upstream_path>/<path>`, unchanged: no prefix, no HTML rewriting |
| `/api/<your routes>` | your manifest's HTTP routes (same handler, same `min_role`) |
| `/ws/addons/<name>/…` | your `WS` routes |
| `/__noo/session` | the gateway's session handoff |
| any other `/api/…`, `/ws/…`, `/__noo/…` | 404 |

So build the UI to be served from `/`, with root-relative or relative paths
to its assets, its API and its sockets.

**Finding and opening a UI.** `GET /api/addons/ui` (any signed-in account)
answers `{"uis": [{"addon", "title", "port", "url_base", "can_open"}]}`: a
User sees the UIs its role may open, an Operator or Admin sees all of them.
The console's **Add-ons** tab lists them with an **Open** button.

**Session handoff.**

1. The console calls `POST /api/addons/<name>/ui-session` on its own origin
   with `Authorization: Bearer`. The gateway checks `ui.min_role` and answers
   `{"code", "port", "path", "url", "expires_in": 30, "session_idle_secs",
   "session_max_secs"}`. The code is random, single use, valid for 30
   seconds, and bound to that person, that add-on and this browser: the same
   answer sets a cookie `noo_handoff_<name>` (HttpOnly, Secure,
   SameSite=Strict, `Path=/__noo/session`, 30 s). Cookies ignore ports, so
   the browser that minted the code presents it on your origin; any other
   browser does not have it.
2. The console opens `url` (`https://<host>:<port>/__noo/session?code=…`) in
   a new tab. Your origin redeems the code only when the binding cookie
   matches and the request is a top-level navigation no other site started
   (no foreign `Origin`, no `Sec-Fetch-Site: cross-site`, `Sec-Fetch-Mode:
   navigate` when the browser sends it). It sets its own cookie
   `noo_ui_<name>` (HttpOnly, Secure, SameSite=Strict, host-only, `Path=/`).
   The cookie holds an opaque session id, never a token, and the binding
   cookie is cleared. The browser is then redirected to `/`.
3. The session **slides**: it ends after `NOO_ADDON_UI_SESSION_IDLE_SECS`
   (default 8 h) without a request and after `NOO_ADDON_UI_SESSION_MAX_SECS`
   (default 24 h) however active. It is not tied to the console's short
   access token, and no refresh token ever reaches your origin. Instead,
   every request re-checks the person:
   - the session floor (logout, password change, disable);
   - the live role (a demotion below the session's role ends it);
   - your add-on still being enabled.

   An open socket re-checks every minute and on a logout broadcast, then
   closes with `4401`.
4. On your origin that cookie authenticates your UI, your API routes and
   your sockets, and nothing else does: a bearer token is not accepted
   there, and the console port never reads a `noo_ui_*` cookie.

When the session ends, your origin answers `401` and a socket closes with
`4401`. Show the person a link back to the console's **Add-ons** tab.

**Residual login-CSRF risk.** An attacker who holds an account can mint a
code for themselves. Opening that code in a victim's browser fails, because
the victim has no matching binding cookie. What remains: someone who can
already run script on the console origin, or plant cookies on this host (a
compromised add-on origin on the same host can set a host-only cookie for
`Path=/__noo/session`, but cannot read the victim's console token), could
fixate a session. The window is 30 seconds and one use.

**Writes and sockets from your UI.** Cookies ignore ports, so the browser
also sends your cookie to other add-ons' ports on the same host. On your
origin:

- a request that carries an `Origin` header must carry yours;
- a WebSocket upgrade must carry your `Origin`;
- a write (`POST`, `PUT`, `PATCH`, `DELETE`) must carry your `Origin` **and**
  the header `X-Noo-Addon-Request: 1`. Send it on every write, e.g.
  `fetch('/api/<name>/x', {method: 'POST', headers: {'X-Noo-Addon-Request': '1', 'Content-Type': 'application/json'}, body})`.

The gateway answers no CORS preflight, so no other origin can send that
header.

**What the gateway does to a UI response.**

- Status and body pass through, streamed.
- Response headers are an allow-list: `Content-Type`, `Content-Length`,
  `Content-Encoding`, `Content-Language`, `Content-Range`,
  `Content-Disposition`, `Accept-Ranges`, `Cache-Control`, `ETag`,
  `Last-Modified`, `Expires`, `Vary`, `Content-Security-Policy`. Everything
  else is dropped, notably `Set-Cookie`, CORS headers, HSTS,
  `Clear-Site-Data`, `Service-Worker-Allowed`, `X-Frame-Options`, `Refresh`
  and `Link`. A `Location` survives only when it stays on your origin; your
  own `<upstream_path>/…` is rewritten to `/…`.
- The gateway's Content-Security-Policy is always added:
  `default-src 'self'; script-src 'self' 'wasm-unsafe-eval'; style-src 'self'
  'unsafe-inline'; img-src 'self' data: blob:; media-src 'self' blob:
  mediastream:; font-src 'self' data:; connect-src 'self'; worker-src 'self'
  blob:; object-src 'none'; base-uri 'none'; form-action 'self';
  frame-ancestors <console origin>`. `connect-src 'self'` is your own origin
  only, which covers your API and your sockets. `frame-ancestors` is
  `NOO_CONSOLE_ORIGIN` when set, otherwise this host on 443 and on the
  gateway port. Your own CSP is kept beside it; the browser enforces both, so
  yours can only narrow it.
- `X-Content-Type-Options: nosniff`, `Referrer-Policy: same-origin`,
  `Cross-Origin-Resource-Policy: same-origin`, and `Cache-Control: private,
  no-cache` when you sent none.
- Request headers passed to you: only `Accept`, `Accept-Language`,
  `If-None-Match`, `If-Modified-Since`, `Range`, `If-Range`, plus the
  identity headers the gateway sets. Never the cookie.
- Refused with `400`: a `.` or `..` segment, an empty segment, any `%`
  (percent-encoding is refused, not decoded), or a character outside
  `[A-Za-z0-9._~@+-]`. Refused with `403`: a service-worker script fetch.

**Exposing the ports (operator).** The gateway publishes the range on
loopback (`${NOO_ADDON_UI_BIND_ADDR:-127.0.0.1}:${NOO_ADDON_UI_PORTS}`, with
the same number inside and out). The browser reaches each port through
`tailscale serve` with the tailnet's certificate, exactly like Grafana's own
origin. After every successful `noo stack start` and `noo stack restart`, the
launcher asks the gateway which ports are allocated (`GET /api/addons/ui`)
and then:

- fronts each one: `tailscale serve --bg --https=<port> https://127.0.0.1:<port>`;
- removes its own entry (only `/` → `https://127.0.0.1:<port>`) from any
  port in the range that is no longer allocated (`tailscale serve
  --https=<port> off`);
- leaves alone, and reports, a port that carries anything else.

It never touches the tailnet policy. If tailscale refuses the change (no
operator permission and no passwordless sudo), it prints the exact
`sudo tailscale serve …` line to run.

- An install without tailscale sets `NOO_ADDON_UI_BIND_ADDR` to the address
  browsers use.
- Set `NOO_CONSOLE_ORIGIN=https://noo-controller.<tailnet>.ts.net` when the
  console is reached under a different origin than the default (this host on
  443 and on the gateway port). It is the CSP `frame-ancestors` of the add-on
  origins.
- The add-on origin listeners carry the console router's request logging,
  rate limiting, audit-address and panic layers.

## Step 2b — claim a subject prefix (NATS add-ons)

Add your prefix to the matcher in `addons.rs` (`is_trellion_subject` is the
model) and the guard in `worker_client.rs` refuses your subjects with the
add-on's message instead of letting them time out. A timeout reads like an
outage; that is the failure this replaces.

## Step 3 — serve it

Nothing exotic. Serve the declared paths, and a `/health`. Where you need
something the gateway owns — its config, its knowledge graph, a heartbeat
task, an activity, a channel message — **go back over HTTP** rather than
reaching into its tables. The `gateway_client.py` of the example above mints
the cluster-HMAC token per request.

Own your own tables outright, on your own connection, as a single writer.
Everything else routes back. That split is what keeps an add-on from becoming
a second authority on a fact the gateway already owns — the single most
repeated failure in this codebase's history.

## Step 3b — know who called you

Every proxied request now arrives with the gateway's own credential and, when
a person was behind it, that person's identity. Both are set by the gateway on
a request it builds from nothing, so a client cannot forge either by sending
the headers itself — they are dropped at the proxy and re-set.

| Header | Meaning |
|---|---|
| `Authorization: Bearer <token>` | the gateway itself. Verify it (below) before trusting anything else. |
| `X-Noo-Requester-Sub` | the mesh **account** the call acts for. |
| `X-Noo-Requester-Connection` | the live session, when the account was reached through one. |
| `X-Noo-Requester-Role` | `user`, `operator` or `admin`, resolved when the credential was validated. |
| `X-Noo-Requester-Scopes` | comma-separated, in credential order. |

**An absent `X-Noo-Requester-Sub` means the gateway itself** — a heartbeat
digest, the meta-loop, a scheduled evaluator. It does not mean "anyone", and
it must never be read as unrestricted. Treat it the way the gateway treats an
internal caller on the way in: a machine with no human behind it, authorized
by what it is, not by what it claims.

This is the reverse of the key your add-on presents when it calls the gateway
(`NOO_GATEWAY_KEY`). Both are rows in the same table with the
same properties; they are not interchangeable, and neither is accepted where
the other belongs.

### Delegated tasks

An add-on that should do background work for a person who is present declares
`"delegate": "tasks"` in its manifest and marks the routes that need it with
`"receives_delegation": true`. The operator must also enable delegation for the
add-on (default off). Both are required.

**What you receive.** On a request to an opted-in route, in addition to the
headers above, the gateway sets `X-Noo-Delegation`: a short-lived token (five
minutes) for that person, acting through your add-on (`act.sub` is
`addon:<name>`). A client-sent `X-Noo-Delegation` is dropped, and a request
whose own token is already delegated never receives another. Keep the token in
memory for the request; never store it, log it, or send it to a model.

**Confinement.** Present it to the gateway as a bearer on these routes only,
and nowhere else (every other route answers 403):

| Route | Use |
|---|---|
| `POST /api/tasks` | create a task; `Idempotency-Key` makes a retry return the same task (`idempotent_replay: true`); optional `context` (at most 32 KiB) |
| `GET /api/tasks`, `GET /api/tasks/{id}` | list and read |
| `POST /api/tasks/{id}/stop`, `/ask`, `/answer` | steer |
| `POST /api/tasks/{id}/context` | `{text, revision}`: push context, picked up at the next loop |
| `GET /api/tasks/{id}/events?after=<seq>` | pull events |
| `POST /api/tasks/stop` | `{via: "addon:<name>"}`: revoke your own background work |

`resubmit` (it spends the person's tokens) is not available: it needs the
person directly. The token is refused when the account is disabled or its role
is lower than the token's, and when the add-on is switched off or its
delegation is disabled.

**Isolation.** The token sees only the tasks your add-on created for that
person (`created_via = addon:<name>`). Any other task, including another
person's, one created directly, or another add-on's, answers 404, even when the
person is an operator. Listing never takes the operator's all-tasks view.

**Lifetime.** Authority tracks presence: each proxied request carries a fresh
token, and five minutes after the person leaves you can start nothing new.
Running tasks continue on noomesh; keep task ids, not tokens. Switching the
add-on off does not stop its tasks.

**Revoke.** The person (or you, with a token) calls `POST /api/tasks/stop
{via}`; an operator runs `noo tasks stop --via addon:<name> [--user <u>]`.

### Verifying the bearer

The token is a row in `noo_service_keys` under the consumer
`addon-caller:gateway`, minted fresh on every gateway start
(`gateway-rust/src/addon_auth.rs`). The raw value exists only in the gateway
process; what is stored is its sha256. Each start revokes the previous row,
and deletes revoked `addon-caller:*` rows older than 7 days; no other
consumer's revoked row is ever deleted. `noo security service-key list
--all` leaves the retired caller rows out, and `--callers` shows them.

The value is `noo-ak-` followed by 64 hex characters, and the stored hash is
of that whole string, prefix included. Hash exactly what you were presented;
do not strip the prefix, and do not check the length or alphabet — a gateway
released before the prefix presents the same 64 hex without it, and its row
verifies the same way. If you want to know when those are gone, count a
verified bearer that does not start with `noo-ak-` (log it, once per consumer per hour).

Your DB role cannot read that table, and should not — it holds every other
consumer's key. Read the view instead:

```sql
SELECT consumer FROM noo_addon_caller_keys WHERE key_hash = $1
```

`noo_addon_caller_keys` exposes the consumer, the hash and the creation time
for add-on-caller rows alone, and mesh migration `077_addon_caller_verify_view` grants
SELECT on it to each add-on role. Hash what you were presented, look it up,
and refuse the request when there is no row.

Cache the lookup briefly if you like; the gateway caches its own key
resolution for 60 seconds. Do not cache the ABSENCE of a row for long —
that is the revocation path (`noo security service-key revoke
addon-caller:gateway`), and a gateway restart is the rotation path.

If your add-on predates this, nothing breaks: the headers are additive and an
add-on that ignores them behaves exactly as it did. But an add-on reachable on
the mesh network that does not check is one that answers anything which can
reach its port.

## Step 2c — declare your worker handlers (NATS add-ons)

Claiming a subject prefix says which subjects are yours. It does not put a
handler behind them. Until recently the handler MODULE used to have to live in the
mesh repo and be named in `noomesh/workers/__init__.py`'s import list —
which meant an add-on could not move its own code without breaking a caller
in a repository it does not own.

Declare them instead. In your `pyproject.toml`:

```toml
[project.entry-points."noomesh.worker_surfaces"]
"ml-intel:graph" = "your_package.worker_surface"
```

The entry point resolves to a module whose import registers
`@worker_handler` subjects, or to a callable that registers them. Install
the package and the subjects are served; nothing in the mesh names you.

**The name carries the surface gate**, as `<surface>:<label>` — one of
`core`, `ml`, `ml-intel`, or `all`. This matters because several add-on
packages ship in the same image: a licensed surface must not register on the
core worker merely because its package is installed alongside. A name with
no prefix runs on every surface.

A declaration that fails to load **warns and is skipped**, and its subjects
go unserved rather than half-served. It does not take the worker down, and
it does not look like an absent add-on.

## Step 4 — prove you serve what your manifest declares

Add a test in **your** repo that reads your manifest and asserts your app
serves every route in it. This is the drift check, and it belongs in your CI
because that is where the fix belongs.

```python
# tests/test_gateway_route_contract.py
import json, pathlib

MANIFEST = pathlib.Path("src/yourthing/yourthing.routes.json")  # the file you ship

def test_we_serve_every_route_we_declare():
    declared = json.loads(MANIFEST.read_text())["routes"]
    served = {(r.methods, r.path) for r in create_app().routes if hasattr(r, "methods")}
    missing = [
        r for r in declared
        if not any(r["path"] == path and r["method"] in methods for methods, path in served)
    ]
    assert not missing, f"the manifest declares routes we do not serve: {missing}"
```

## Step 5 — document the routes

Your routes are documented in your repo, next to the manifest. The gateway's
public spec (`src/noomesh/gateway/static/openapi.json`) and the console's
contract carry core routes only; CI's `openapi-drift` job reads the gateway's
`.route(` calls and never sees an add-on's. Document the **503** shape your
callers get: for an add-on route, "the operator did not enable this" is a
normal answer, not an outage a UI should render as one.

`internal` routes are not part of any API.


## Console pieces — filling your slots in the console diagrams

The console's diagrams (the brain map and the workflow view) ship complete in
core, with a placeholder wherever an add-on owns a node. An installed add-on
serves its own description of those nodes — its *piece* — and the console fills
the slots at runtime. With no piece (add-on off, unreachable, or invalid) a slot
simply keeps its placeholder.

**Slot ids** are `<addon>:<name>`, where `<addon>` is the add-on's key in
`/health`'s `addons` map (`evolve`, `trellion_intel`). Every slot key in your
piece must start with your own `<addon>:`; the gateway refuses a piece that
names anyone else's.

**The piece** is JSON, version 1:

```json
{
  "version": 1,
  "addon": "<addon>",
  "slots": {
    "<addon>:<name>": { "title": "...", "description": "...", "steps": ["..."] }
  }
}
```

`title` and `description` are strings. `steps` is optional; when present it is
an array of strings (possibly empty). `slots` may be empty. The whole piece must
stay under 64 KB.

**Transport** follows the add-on's own:

- *HTTP add-ons* serve `GET /console-piece` and declare it in the manifest as an
  `internal` route named `console_piece` (`timeout_secs: 5`). It is never
  mounted on the public API; the gateway reaches it through
  `addon_proxy::call("<addon>", "console_piece", ...)`.
- *NATS add-ons* answer the request subject `worker.graph.console_piece`
  (empty or `{}` payload) with the piece as the reply. The subject sits inside
  the existing `worker.graph.*` family, so no new grant is needed.

**The gateway route** is `GET /api/addons/{addon_id}/console-piece`, readable by
any signed-in account. It validates the piece (version, `addon` match, key
prefix, types, size) and returns the validated copy:

| Status | Meaning |
|---|---|
| 200 | the validated piece |
| 404 `{"error":"unknown_addon"}` | `addon_id` is not an add-on that owns slots |
| 503 | the add-on is disabled or unlicensed; the body carries `addons::refusal_msg` |
| 502 | enabled, but no answer, a timeout, a non-200 upstream, or an invalid piece |

The route never answers 500.

## CLI pieces — bringing your own `noo` commands

The released `noo` is generic: it carries no add-on code. An enabled add-on
describes its own command groups in a *CLI piece*, and `noo` turns each command
into a request to the gateway's add-on proxy. This is how an add-on's commands
(a `widget` group, say) exist: the add-on provides them, not core.

**What the CLI does.** For `noo <group> <command> ...`, where `<group>` is not a
built-in command, it reads the enabled add-ons from `/health`'s `addons` map,
fetches each one's piece, and caches it per controller in the CLI's state
directory (ten minutes; a stale cache is used when the controller is
unreachable). It finds the group, builds the request from the command's `args`,
asks for confirmation when the command has a `confirm` (`-y`/`--yes` skips the
prompt; `--json` never prompts and so needs `-y`), sends it, and renders the
`output`. `--json` prints the raw response. A response that is HTTP 2xx but says
`{"status":"error"}` (or has an `error` string) is shown as an error and exits
non-zero. `noo --help` lists the add-on groups, marked as coming from the
add-on; `noo <group> --help` lists the commands. A group whose add-on is off
says so (exit 5). A group that collides with a built-in command is ignored with
a warning, so an add-on can never shadow a core command.

**The piece** is JSON, version 1:

```json
{
  "version": 1,
  "addon": "<addon>",
  "groups": [{"name": "widget", "summary": "Manage widgets"}],
  "commands": [{
    "group": "widget", "name": "rollback",
    "summary": "Restore a previous widget state",
    "method": "POST", "path": "/api/widget/rollback",
    "args": [{"name": "to", "flag": "--to", "kind": "int", "required": false,
              "into": "body:version", "help": "version to restore"}],
    "confirm": "Restore the previous widget state?",
    "output": {"title": "widget rollback",
               "fields": [{"key": "/restored", "label": "restored"}],
               "hint": "noo widget resume"}
  }]
}
```

The gateway validates the whole piece and refuses it (502) if any rule fails:

- `version` is 1 and `addon` is yours. Group and command names match
  `^[a-z][a-z0-9-]{0,23}$`, and every command's group is declared.
- **Every command's `method` and `path` must match a mounted, non-internal
  route in your add-on's manifest.** Path parameters are written the manifest's
  way, `{cycle_id}`. This is the security property: an add-on can only make the
  CLI call routes the gateway already exposes for it. Declare the routes your
  commands need in the manifest first (`internal` routes cannot be named).
- `args[].kind` is `string`, `int`, `uuid` or `bool`. `args[].into` is
  `path:<param>`, `query:<name>` or `body:<name>`. Every `{param}` in the path
  needs exactly one required `path:` arg. Positional args have no `flag`;
  flagged args have a `flag` starting with `--`. `query:` needs a manifest
  route marked `query: true`; `body:` is for `POST` only.
- `confirm` is an optional string, shown verbatim. `output.fields[].key` are JSON
  pointers; `output.list` is an optional pointer to an array, rendered as a table
  with `output.columns: [{key, label}]`; `output.hint` is an optional command to
  suggest next. Arrays render comma-joined, booleans as yes/no, null as a dash.
- The whole piece stays under 64 KB.

**Transport.** An HTTP add-on serves `GET /cli-piece` and declares it in its
manifest as an `internal` route named `cli_piece` (`timeout_secs: 5`); the
gateway reaches it through `addon_proxy::call`, as it does for `console_piece`.
There is no per-command timeout in the piece: the manifest route's
`timeout_secs` governs, and the CLI waits at least that long (310 s).

**The gateway route** is `GET /api/addons/{addon_id}/cli-piece`, readable by any
signed-in account:

| Status | Meaning |
|---|---|
| 200 | the validated piece |
| 404 `{"error":"unknown_addon"}` | `addon_id` is not an add-on |
| 404 `{"error":"no_cli_piece"}` | the add-on declares no `cli_piece` route (NATS add-ons such as `trellion_intel` have none) |
| 503 | the add-on is disabled or unlicensed; the body carries `addons::refusal_msg` |
| 502 | enabled, but no answer, a timeout, a non-2xx upstream, or an invalid piece |

The route never answers 500.

## Roles — how the Python host asks an add-on for a capability

The host never imports an add-on by name. It asks for a role
(`src/noomesh/addon_roles.py`) and the add-on declares what fills it:

* **Provider roles** (graph ranking, graph metrics, the temporal graph store, the
  conversation extractor, the retrieval tracker, audience scope, saved walks, query
  classification): the add-on trellion discovers declares `TRELLION_PROVIDERS` at its
  package root, role name to `"module:attribute"`; the host calls
  `addon_provider(role)`. No add-on, no declaration, or a declaration that does not
  resolve all read as "this tier is not available" to the caller; the last two are
  logged at WARNING.
* **Extensions** (`cli_groups`, `mcp_tool_defs`): a package declares
  `NOOMESH_EXTENSIONS = {kind: {name: "module:attr"}}` and registers with the
  `noomesh.addons` entry point (value: the package name), or is named in
  `NOOMESH_ADDON_PACKAGES` where it is mounted rather than installed. A CLI group is
  a Typer app added under `name`; an `mcp_tool_defs` entry is a module whose import
  registers its tools. A package that is not installed is skipped silently; one that
  is installed but whose declaration does not resolve is skipped with a WARNING.

## Can an add-on extend the dashboard?

Partly today, and the part that works is worth knowing before you ask for
more.

**What works now, with no dashboard change:**

- **Presence.** `/health` carries `addons.<name>`, and the console renders it
  as a tri-state badge — `enabled` (solid green), `disabled` (dashed, muted,
  *not* a fault), `unhealthy` (red, is a fault), anything else `unknown`.
  Declaring your add-on in `addons.rs` is all it takes to appear there. That
  distinction is a rendering contract the console tests pin, so do not
  collapse it into a boolean anywhere.
- **Your data, through your routes.** Anything you serve and the gateway
  proxies is reachable by the console like any other endpoint, and appears in
  the OpenAPI spec the console builds against.

**What does not exist: a way for an add-on to contribute UI.** The console is
a built SPA (`ui/`, shipped as the `mesh-ui-web` artifact and unpacked at
`/var/www`). Panels are written there, hardcoded in the console, which is why a
panel exists for a built-in add-on and would not exist for yours.

**If you need panels today**, the honest answer is a PR touching `ui/`,
coordinated with the console's contract changelog.

**The extension point, if it gets built,** should be declarative — panels
described as DATA (which endpoint, which fields, which shape), rendered by a
generic component in the console. Not a JavaScript bundle the console loads
from the add-on at runtime. The reasoning is the same one that put the route
manifest in the gateway rather than in the add-on, only sharper: a mounted
file that adds *routes* lets a sidecar publish a path; a loaded bundle that
adds *code* runs it on the operator's authenticated dashboard origin, with
their session. The console must decide what it renders, the same way the
gateway decides what it exposes.

## What you get for free

- **Presence** — `/health` reports `addons.<name>` as `enabled` /
  `disabled` / `unlicensed`.
- **Honest refusals** — every mounted route answers a 503 that says which of
  those three it is, with the add-on's own message. Never a silent 404.
- **Entitlement checks** — offline ed25519 against a key baked into the
  binary (`entitlement.rs`). No licence server, nothing leaves the box.
- **Auth** — the global middleware gates mutating routes on write/admin scope
  before your handler is reached.
- **Param validation, query passthrough, timeouts** — from the manifest.

## Deployment

Ship a compose overlay — `docker-compose.<addon>.yml` — with an **explicit env allowlist**. A variable absent from that
block reaches nothing, which is deliberate: it makes the container's
configuration a list someone can read rather than whatever happened to be
exported. Put no `profiles:` inside it: composing the file is the switch, and
a profile inside an overlay is a second switch a launcher can forget.

The overlay lives in **your** repository and ships in your signed bundle (see
[the signed add-on lock](#the-signed-add-on-lock)): core carries no add-on's
overlay. `noo addons enable|upgrade` materialises it at
`<install root>/addons/<name>/docker-compose.yml`, and the launcher composes
it when `addons.<name>` is declared on — the file list has one home,
`scripts/lib-compose.sh` (`lib-addons.sh` `addon_overlay`). Two things follow
from where it sits:

- Ordinary relative paths resolve against the **project directory** (the
  install root, where `docker-compose.cluster.yml` is), as for every `-f` file.
- So does `extends.file` when several `-f` files are composed (Compose v2):
  an overlay that extends trellion says `file: docker-compose.trellion.yml`,
  not `../../docker-compose.trellion.yml`.

A development checkout of your add-on wins over the bundle:
`${NOO_<NAME>_PATH:-../noo-<name>}/docker-compose.<name>.yml`. Guard your
overlay's env allowlist, secrets and mounts in your own repository's CI. `pull_policy` in your overlay
should follow `${NOO_PULL_POLICY:-build}`, which `--dist` installs set to
`missing`.

### Where an add-on's release image is built

The stack release is **core-only**. The signed stack lock
(`stack-<tag>.lock`) lists core images and nothing else: the stack release
workflow has no add-on job, reads no add-on repository, and records no
add-on image or `source:` row.

A licensed add-on's image is built, pushed and released by the add-on's
**own** repository, with its **own signed lock**. The controller pins each
licensed add-on by that lock, never by tag.

### The signed add-on lock

The lock is `addon-lock.json`: compact canonical JSON in the format
`noo-addon-lock/1`, written and signed by
`noo security addon-lock sign --out addon-lock.json`, which also writes
`addon-lock.json.sig` (a `noo-sig1` signature over the exact bytes). Its fields
are `format`, `addon` (the `addons:` key), `version` (semver), `source_commit`,
`supports_stack` (exact stack tags), `images` (`name` → `ref@sha256:…`) and,
for an add-on built `FROM` a stack image, `base` (`{image, digest}`, checked
against that image's row in the stack's own signed lock). Never re-serialise
the file: non-canonical bytes are refused.

**Trust anchor.** The licence names whom to trust. The entitlement token
carries, per add-on,
`"addons": {"<name>": {"keys": ["<hex ed25519 pubkey>", …], "registry": "<root>"}}`,
with the current key first, and is issued with
`--addon <name>=<root>:<key>[,<key>]`. The public tree names no add-on key and
no add-on registry.

**The bundle.** A release also signs a second lock, `addon-bundle.json`, in
the format `noo-addon-lock/2`: the same fields plus `files`, each file the
add-on ships beside its images (its compose overlay, `docker-compose.yml`, at
least; `system.json` and `workloads.json` when it declares them) by name and
`sha256:…`. One signature therefore covers the overlay and the declarations.
Sign it with the same command and one `--file <name>=<path>` per file, then
check it with `verify … --files-dir <dir>`. File names are one plain component
(`[A-Za-z0-9._-]`).

**Where the lock is published.** It is an OCI artifact in the add-on's
**own registry package**: the `registry` root from the licence (for example
`ghcr.io/<owner>/<image>`), which is the same package as the image. One
`read:packages` credential therefore reads both, and it cannot read source.

| | |
|---|---|
| Reference | `<root>:stack-<stack tag>`, for example `…:stack-v0.6.0` or `…:stack-v0.6.0-rc.1`; push one tag per entry in `supports_stack` |
| Manifest | OCI image manifest (`application/vnd.oci.image.manifest.v1+json`) with `artifactType: application/vnd.noomesh.addon-lock.v1` and the empty config (`application/vnd.oci.empty.v1+json`) |
| Layer 1 | `mediaType: application/vnd.noomesh.addon-lock.v1+json`, annotation `org.opencontainers.image.title: addon-lock.json` |
| Layer 2 | `mediaType: application/vnd.noomesh.addon-lock.sig.v1`, annotation `org.opencontainers.image.title: addon-lock.json.sig` |
| Bundle lock | `mediaType: application/vnd.noomesh.addon-bundle.v1+json`, title `addon-bundle.json` |
| Bundle signature | `mediaType: application/vnd.noomesh.addon-lock.sig.v1`, title `addon-bundle.json.sig` |
| Bundle files | one layer per entry in `files`: `mediaType: application/vnd.noomesh.addon-file.v1`, title = the file name |
| Limits | each layer at most 1 MiB; each blob's sha256 is checked against the manifest |

A release publishes it with oras (1.2 or later), run from the directory
that holds the two files:

```sh
oras push <root>:stack-v0.6.0 \
  --artifact-type application/vnd.noomesh.addon-lock.v1 \
  addon-lock.json:application/vnd.noomesh.addon-lock.v1+json \
  addon-lock.json.sig:application/vnd.noomesh.addon-lock.sig.v1 \
  addon-bundle.json:application/vnd.noomesh.addon-bundle.v1+json \
  addon-bundle.json.sig:application/vnd.noomesh.addon-lock.sig.v1 \
  docker-compose.yml:application/vnd.noomesh.addon-file.v1
```

Publish **both** locks. A CLI from before the bundle (0.6.3 and earlier)
reads only the `addon-lock.json` pair and ignores the other layers; it would
refuse the bundle lock's unknown field. A current CLI takes the bundle when
the artifact carries one: it verifies the signature, then that the file
layers are exactly the files the lock lists, each hashing to its entry.

The signed content is the authority. The tag is only a lookup, and a newer
build for the same stack moves it.

**On the controller.** `noo addons enable <name>`, `noo addons upgrade` and
`noo upgrade --stack` (for the target tag, before anything else moves) run
the same steps:

1. fetch the artifact over TLS;
2. verify the signature against the licence's keys;
3. check that the add-on name matches, that every image is under the root,
   that the stack tag is listed, that `base` matches the stack lock, and that
   the version is not a downgrade (allowed only with `--allow-downgrade`);
4. pull every image by digest through a throwaway docker config (the
   credential depends on the path, below);
5. cache the lock under `addon-locks/` and write the pin to `addons.lock`,
   beside `stack.lock`;
6. materialise the bundle files under `addons/<name>/`, replacing the
   directory whole (a lock without files removes it).

A refusal at any step changes nothing. An add-on with no lock for the target
stack holds the stack roll, and `noo upgrade --check --stack` says which
add-on holds it.

**Where the lock and images come from** (`lock_fetch::Route`, one selector, no
fallback between paths; the chosen path is printed by every verb that pulls):

1. `NOO_ADDON_REGISTRY_TOKEN` is in the store: **Direct** to the anchor's
   `registry` (GHCR) with that token. This is the vendor-fleet override; the
   entitlement's `pull` is ignored and the add-on registry proxy is never
   contacted.
2. Otherwise the anchor names `pull` (`addons.noomesh.ai/<same path as
   registry>`): **Proxy**. The lock is fetched from `pull`, and the token realm
   gets Basic `<entitlement id>:<entitlement token>` (never a GHCR token). When
   the entitlement carries `cnf.ed25519` the proxy answers `401` with
   `WWW-Authenticate: Noo-PoP realm=…,nonce=…`; the controller signs
   `noo-addon-pop/1\n<service>\n<entitlement id>\n<nonce>` and retries once
   with `Noo-PoP-Nonce` and `Noo-PoP-Signature`. Images are pulled as
   `addons.noomesh.ai/<path>@sha256:…` (the signed digest, another host) with a
   fresh short proxy token per image as docker's password; the entitlement and
   the controller key never reach docker. The pin records `pulled_from`, and
   `launch-pins` and `noo addons verify` use the pulled refs.
3. Otherwise: Direct to `registry`, anonymous.

Trust never moves with the location: the lock is verified against `registry`
and every image ref in it must sit under `registry`. A `pull` that is not
`registry`'s path on another host refuses the whole entitlement.

The controller key is ed25519, derived one way from the cluster CA private key
(`addons::pop`): stable for the cluster's life, nothing new stored. `noo
security entitlement pubkey` prints its public half for the vendor's `issue
--bind-key`; a re-created CA changes it and the entitlement is reissued.

**At start.** The launcher never pulls an add-on and holds no registry
credential. `scripts/lib-dist.sh` `require_addon_pins` asks
`noo addons launch-pins` to re-verify each cached lock offline. It then
requires each image to be present locally by its digest, and exports
`NOO_ADDON_IMAGE_<NAME>`: the lock's image name upper-cased, with `-` as `_`.
Your overlay's `image:` line must read that variable first:

```yaml
image: ${NOO_ADDON_IMAGE_<NAME>:-${NOO_IMAGE_PREFIX:-noomesh}/<name>:${NOO_IMAGE_TAG:-latest}}
```

The fallback is the development build's name and is never used by a dist start.
`noo addons verify` and `noo cluster verify` (row `add-on pins`) re-check
four things: the pins, the materialised bundle files (each must still hash to
the signed lock; an edited overlay is refused like an edited lock), the local
images, and what runs.

**Locks without a bundle (refused).** A `noo-addon-lock/1` lock carries no
overlay, so there is nothing to compose. Through 0.6.5 the launcher still
composed the `docker-compose.<name>.yml` an earlier CLI left in the install
root; 0.6.6 removed that path. `noo addons enable|upgrade|verify` and the
launcher's pins now refuse such a lock ("this add-on lock predates signed
bundles; the vendor must re-sign it for <tag>"; check with `noo addons
upgrade <name> --check`), and the upgrade that installs 0.6.6 removes any
leftover root overlay (`docker-compose.evolve.yml`,
`docker-compose.trellion-intel.yml`), moving it aside as `.retired-<version>`
if it was edited. Every add-on lock published for stack v0.6.2 and later is a
bundle.

## Declaring a database

An add-on that owns tables declares its database system in its signed bundle,
as a file named `system.json` listed in `files` like the overlay. It is never
written in `noomesh.yaml`. The gateway's systems broker provisions it exactly
like a `systems:` entry (see
[the `systems` reference](../reference/config.md#systems--the-per-system-database-manifest-gateway-broker)):
the schema owned by the migration role, a runtime role with no `CREATE`, the
default privileges, and the extensions.

```json
{
  "schema": "example_addon",
  "role": "noo_example_addon",
  "ddl_role": "noo_example_addon_ddl",
  "extensions": ["pg_trgm"]
}
```

| Field | Rule |
|---|---|
| `schema` | exactly `<id>`, the add-on name with `-` as `_` (`example-addon` → `example_addon`) |
| `role` | exactly `noo_<id>`: the runtime role (DML, no `CREATE`) |
| `ddl_role` | exactly `noo_<id>_ddl`: owns the schema; run your migrations as it |
| `extensions` | optional; each one of `vector`, `pg_trgm`, `pgcrypto`, `citext`, `btree_gin`, `btree_gist`, `hstore`, `unaccent`, `fuzzystrmatch` (the broker installs them as superuser, so the list is closed) |

Any other value, any other field, or an add-on whose `<id>` would be a core
name (`app`, `worker`, `gateway`, `admin`, `public`, `mesh`, `noo`, … or a
`pg_` prefix) refuses the bundle. `noo addons enable | upgrade` refuses it
before anything is pinned, and the gateway refuses the whole add-on (no routes)
if one reaches it anyway.

**Passwords are derived, never declared:** `NOO_<ID>_DB_PASSWORD` (runtime)
and `NOO_<ID>_DDL_PASSWORD` (migrations). `noo addons enable <name>` mints
both into the encrypted store when absent (never rotates), and `noo upgrade
--stack` does the same for every add-on switched on. The launcher delivers
them to the gateway in its one systems-secrets file. Your overlay delivers
them to your own containers the usual way (`file: ${NOO_SECRET_RUNDIR}/<name>`
with `x-noo-source: NOO_<ID>_DB_PASSWORD`).

**When it is provisioned.** Only while the add-on is registered: switched on
(`addons.<name>: true`), its signed lock verified by the launcher for this
stack, and its manifest and declarations valid. On every `noo stack start |
restart` the launcher copies `system.json` from the verified bundle to
`.noo-addon-systems/<name>/system.json` in the install root, which the gateway
mounts read-only at `/opt/noo/addon-systems/<name>/system.json`. A file the
signed lock does not list is never copied. Switching the add-on off stops
the declaration on the next start; like `noo systems disable`, that drops no
role, schema or row.

A `systems:` entry in `noomesh.yaml` with the same name wins, with a warning
in the gateway log. A missing password skips the system (ERROR in the log,
`dependencies.systems` on `/health`), and the gateway keeps booting.

Your data-owning service runs on the controller, on the private database
network, and connects as `noo_<id>` (migrations as `noo_<id>_ddl`) to the
`noomesh` database with the cluster CA. Nodes never connect to Postgres.

### Provisioning the database without starting the add-on

While you develop, you need your schema and roles before any service of yours
may run (a connected-database acceptance test from a private runner, say).
`--provision-only` does exactly that and nothing else:

```bash
noo addons trust-key your-addon <pubkey> --registry <root> --dev --expires 14d
noo addons enable your-addon --lock ./lock.json --provision-only      # add --json for the receipt as JSON
```

It verifies the signed lock and bundle exactly as a plain `enable` does (it
refuses `--force`, a development checkout that pins no stack tag, and a bundle
without `system.json`), mints the two role passwords when absent, and has the
gateway's own broker create the schema and the two roles for that one system.
The broker is not reimplemented: `docker exec -i noo-gateway noo-gateway
provision-system` runs the function the gateway runs at boot, over the system
read from the verified bundle, with the passwords on stdin. Nothing is
composed or started, no gateway key is issued, no NATS principal is rendered,
and the gateway is not restarted.

The add-on's switch (`addons.<name>`) is never written, so a later `noo stack
restart --force` composes none of its services; the state is recorded beside
the pins (`addon-provisioned/<name>.json`, names and a lock hash only) and
`noo addons show`, `noo addons list` and `noo cluster verify` word it
**provisioned (services not started)**. A plain `noo addons enable <name>`
afterwards finds the credentials, roles and pin waiting and turns it fully on.
Running the command again changes nothing that exists.

The receipt (names and paths only; no value is ever printed) gives the
database (`noomesh` on `postgres:5432`), the schema and both roles, the
private Docker network to attach a runner to (the `noo-db` network of this
stack), and the read-only credential files under
`/run/noo/provision/<name>/` (`/dev/shm/noo-provision-<uid>/<name>/` when not
root, or `$NOO_PROVISION_RUNDIR`; tmpfs only, gone at reboot, rewritten by a
re-run): `ca.crt`, `client.crt` / `client.key` (the add-on's own service leaf),
and one libpq `pgpass.<role>` per role. Run a runner as your own uid, on that
network only, with nothing published:

```bash
docker run --rm -i --network <network> --user "$(id -u):$(id -g)" \
  --read-only --tmpfs /tmp --cap-drop ALL --security-opt no-new-privileges \
  -v /run/noo/provision/<name>:/run/noo-db:ro \
  -e PGHOST=postgres -e PGPORT=5432 -e PGDATABASE=noomesh -e PGUSER=noo_<id> \
  -e PGSSLMODE=verify-full -e PGSSLROOTCERT=/run/noo-db/ca.crt \
  -e PGSSLCERT=/run/noo-db/client.crt -e PGSSLKEY=/run/noo-db/client.key \
  -e PGPASSFILE=/run/noo-db/pgpass.noo_<id> <image> <command>
```

Use `PGUSER=noo_<id>_ddl` with `pgpass.noo_<id>_ddl` for migrations.

## Declaring workloads

An add-on whose containers continuously consume a piece of the mesh (a voice,
image or video worker with its model loaded on a GPU) declares them in its
signed bundle as `workloads.json`. The gateway's add-on workload registry
(`addon_workloads`) and the node agent's actuator consume it, and a
reservation names a workload as `<addon>/<name>` (noomesh-internal i163 part B
and the reservations layer).

```json
{
  "workloads": [
    {
      "name": "worker",
      "container": "noo-example-addon-worker",
      "gpu": true,
      "need_mb": 11264,
      "drain": { "route": "drain", "timeout_secs": 120 }
    }
  ]
}
```

| Field | Rule |
|---|---|
| `name` | lowercase letters, digits and `-`, starting with a letter, at most 32; unique in the file; a reservation names it `<addon>/<name>` |
| `container` | `noo-<addon>-<suffix>` (suffix: lowercase letters, digits, `-`; at most 63 characters in all); unique. The container must also carry the labels `noo.addon=<addon>` and `noo.workload=<name>` in your overlay |
| `gpu` | `true` when the workload needs a GPU |
| `need_mb` | memory it needs on that device, MiB, 1 to 262144 |
| `drain.route` | the `name` of an `internal` route in your `routes.json`; noomesh calls it through the add-on proxy before stopping the workload |
| `drain.timeout_secs` | 1 to 600 |

Every field is required, unknown fields are refused, and at most 16 workloads
may be declared. Nothing in the file names an image, a command or a mount: the
node agent starts only the container your verified overlay already defines.

The launcher copies the file from the verified bundle to
`.noo-addon-workloads/<name>/workloads.json` in the install root (mounted
read-only in the gateway at `/opt/noo/addon-workloads/<name>/workloads.json`),
under the same rule as `system.json`: switched on, lock verified this start,
and the file listed in the signed lock. `noo addons enable | upgrade` refuses a
bundle whose `workloads.json` breaks a rule above (and checks `drain.route`
when the bundle also ships `routes.json`); the gateway checks `drain.route`
against the manifest it loaded. Nodes receive the registered add-ons'
workloads in `desired-config` (`addon_workloads`) and act on nothing else.

**Shipping it.** Add the files to the bundle when you sign it:

```sh
noo security addon-lock sign --out addon-bundle.json … \
  --file docker-compose.yml=docker-compose.example-addon.yml \
  --file system.json=deploy/system.json \
  --file workloads.json=deploy/workloads.json
```

and push each as an `application/vnd.noomesh.addon-file.v1` layer next to the
overlay. A CLI from before these files materialises them and ignores them; a
gateway from before them never reads them. Ship them with a `supports_stack`
that starts at the release that reads them. In a development checkout, put
`system.json` and `workloads.json` beside your `docker-compose.<name>.yml`; a
dev start copies them from there.

`noo addons show <name>` prints what an add-on's bundle declares; `noo addons
list` lists the add-ons that declare anything.
