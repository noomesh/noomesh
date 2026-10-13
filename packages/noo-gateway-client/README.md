# noo-gateway-client

The one way an add-on talks to the noomesh gateway. Import name `noo_gateway`;
depends on `httpx` and nothing else; Apache-2.0-licensed on its own (`LICENSE`), so
the proprietary add-ons may import it whatever the core's licence is (the core is AGPL-3.0).

It does three things, and every add-on used to do all three its own way:

1. **Authenticate.** Exchange the add-on's service key at `POST /api/addon/token`
   for a ten-minute token, refresh it 60 s before it expires, and choose the
   right credential per route when the exchange is not available.
2. **Stop asking.** A refusal circuit: three consecutive refusals on a lane
   open it for 300 s, the gateway sees no more traffic for it, and one log
   line names the consumer. This is what the 2026-09-22 storm (17,000 403s an
   hour from one container) lacked.
3. **Count.** `Counters` batches increments and gauges to
   `POST /api/metrics/increment` and `POST /api/metrics/gauge`, with a circuit
   of its own so a missing `metrics` scope silences metrics and nothing else.

## Usage

The async shape (evolve, trellion's workers):

```python
from noo_gateway import AsyncGatewayClient, Counters, GatewaySettings

settings = GatewaySettings.from_env(consumer="svc:evolve")

async with AsyncGatewayClient(settings) as gw:
    body = await gw.post_json("/api/temporal/adaptations", {"edges": edges})
    cfg = await gw.get_json("/api/config/self_identity")

counters = Counters(settings)
counters.inc("hofstadter_rollback_events_total", 1, engine="ga")
counters.gauge("embedding_backlog", 42)
await counters.aclose()   # flushes; or `counters.close()` from sync code
```

The sync shape, and a client someone else builds (an OpenAI SDK's `http_client`):

```python
import httpx
from openai import OpenAI
from noo_gateway import GatewayAuth, GatewayClient, GatewaySettings

settings = GatewaySettings.from_env(consumer="svc:trellion")

with GatewayClient(settings) as gw:
    gw.post_json("/api/external/embeddings", {"input": texts, "model": "harrier"})

llm = OpenAI(
    base_url=settings.url + "/v1",
    api_key="unused",   # the credential is on the http_client
    http_client=httpx.Client(auth=GatewayAuth(settings), verify=settings.verify, cert=settings.cert),
)
```

`AsyncGatewayClient` / `GatewayClient` are `httpx.AsyncClient` / `httpx.Client`
with `base_url`, `verify`, `cert`, `auth` and `timeout` filled from the
settings; any httpx keyword overrides them. The `get_json` / `post_json` /
`put_json` helpers raise `GatewayRefused` (401/403, with the body's reason),
`GatewayThrottled` (429, with `retry_after`) or `GatewayResponseError`
(any other non-2xx). Plain `.get()` / `.post()` return the response as httpx does.

## Environment

| Variable | Meaning | Default |
|---|---|---|
| `NOO_GATEWAY_URL` | base URL | `https://gateway:8080` |
| `NOO_GATEWAY_KEY` | the add-on's own service key (the overlay delivers `NOO_SVC_KEY_<X>` under this name); blank = absent | — |
| `NOO_TLS_CA` | CA file to verify the gateway against; else `/tls/ca.crt` or `/app/pki/ca.crt` if present; else the **system trust store**. Never `verify=False` by omission | — |
| `NOO_TLS_CERT` + `NOO_TLS_KEY` | client certificate (mTLS), used only when both files exist | — |

The client authenticates only with the add-on's own key. It never reads
`NOO_CONTROLLER_SECRET`, `NOO_CLUSTER_SECRET` or `NODE_ID` (a container may
hold them for other reasons); an add-on with no `NOO_GATEWAY_KEY` sends
nothing.

`from_env(consumer, *, env=None, **overrides)`: `overrides`
win, which is how an add-on maps its own aliases
(`GatewaySettings.from_env("svc:evolve", url=os.environ["NOO_EVOLVE_GATEWAY_URL"])`).

## The ladder, chosen per request

The gateway accepts a raw service key only on the inference surface (`/v1/*`,
`/api/external/*`) and at the exchange door. A control route (`/api/temporal/…`,
`/api/metrics/…`, `PUT /api/config/…`) opens only to an exchanged token. So what a failed exchange leaves depends on the route:

```
key configured?
 ├─ yes ─ token cached & fresh & not cooling down ─→ Bearer <token>
 │        else exchange (single-flight) ─ ok → Bearer <token>
 │                                     └ fail → 300 s cooldown, then:
 │          inference route                       → Bearer <raw key>
 │          control route                         → GatewayAuthUnavailable, nothing sent
 └─ no ── GatewayAuthUnavailable ("no NOO_GATEWAY_KEY configured"), nothing sent
```

What an answer means while a **token** is presented:

- **401** — the token is dead (key revoked, JWT secret rotated). Drop it, cool
  down, retry this one request once on the next lane.
- **403 on the inference surface** — the door minted a token its own surface
  refuses (noomesh PR 421). Retry once with the key; it carries the same grant.
- **403 on a control route** — the token is valid and the grant lacks the word.
  Surfaced, never hidden behind another credential, and logged once per window
  with the hint: check `x-noo-addon` in the overlay, then
  `noo security service-key provision <addon>`.

The exchange door's answers: 404 (older gateway; INFO once), 401 (key unknown
or revoked; ERROR), 403 `addon_key_has_no_scopes` (ERROR with the provision
hint), 503 `no_jwt_secret` (WARN), transport error (WARN). Every one starts
the 300 s cooldown.

Logging goes to the stdlib logger `noo_gateway`; every line carries the
fields in its message (`consumer=… lane=… status=… method=… path=…`) and in
`extra=` for a structured handler. Events: `gateway_auth_refused`,
`gateway_auth_unavailable`,
`gateway_auth_circuit_open` / `_closed`, `addon_token_exchange_*`,
`gateway_metrics_circuit_open`, `gateway_metrics_refused`,
`gateway_settings_refused`. No key, token or secret is ever logged.

## What it refuses to do

- **Return a header dict.** `GatewayAuth` is the only interface; an add-on's
  tests can then hold "no call site builds an `Authorization` header by hand".
- **Turn TLS verification off, or skip the hostname check.** There is no
  switch. The retired toggles `NOO_GATEWAY_TLS_VERIFY`,
  `NOO_GATEWAY_TLS_CHECK_HOSTNAME` and `NOO_GATEWAY_SHARED_SECRET_FALLBACK`,
  still set to an off value, make `from_env` raise `ValueError` naming them.
- **Present any shared secret**, on any route, keyed or not. There is no HMAC
  lane; a missing key is `GatewayAuthUnavailable`, locally.
- **Fall back on a scope refusal.** That would hide a
  missing grant, and the operator would never learn the overlay asked for too
  little.
- **Keep asking.** An open circuit sends nothing until it closes.
- **Send the raw key anywhere but the inference surface and the door.**
- **Let metrics break the caller.** `Counters` never raises, and its own
  circuit never touches the auth lanes.

## Tests

```
python3 -m pytest packages/noo-gateway-client -q
```

Every test drives the real `httpx.Client` / `httpx.AsyncClient` under an
`httpx.MockTransport`-style fake gateway (`tests/_fake_gateway.py`) passed as
`GatewaySettings(transport=...)`. Never monkeypatch `httpx.post`.
