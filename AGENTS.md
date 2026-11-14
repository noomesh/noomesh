# Agents working in this repository

noomesh turns the machines you own into one local-first AI cluster: a Rust
gateway (`gateway-rust/`), a Go node agent (`node-agent-go/`), the `noo` CLI
(`noo-cli/`) and the console (`ui/`).

## Hard rules

- Core code never names an add-on, not even in comments or tests
  (`tests/test_core_names_no_addon.py`).
- Never commit `.env`, anything under `secrets/`, or a key.
- Register a gateway route as `.route("/literal", …)`. A route change then
  needs all four generated artifacts in the same change: the gateway spec
  (`python3 scripts/gen-openapi.py`), the console contract
  (`python3 scripts/export-openapi.py`), a dated `ui/contracts/CHANGELOG.md`
  entry, and the console's types (`cd ui && npm ci && npm run gen:api`).
  Check with `gen-openapi.py --check`, `export-openapi.py --check` and
  `cd ui && npm run check:api`; the `ui` CI job is not a required check, so
  read it yourself.
- A change to a command, a config key or an endpoint updates its doc in the
  same change, kept short: edit or delete before adding.
- Nothing that deletes data uses force (`-f`) or bypasses a refusal.

## Where to read, by topic

Each page has a `## For people` part and a `## For agents` part; read the
second.

| topic | page |
|---|---|
| disk use, old images, reclaim | [docs/operating/disk-and-images.md](docs/operating/disk-and-images.md#for-agents) |

## Where truth lives

The code is the truth; generated references (`docs/cli/`, the OpenAPI spec)
are rebuilt from it. A running install's state is what
`noo --json cluster verify --controller` reports; its config is
`noomesh.yaml` in the install root.

## How to verify a change

The commands in [CONTRIBUTING.md](CONTRIBUTING.md#tests), at minimum
`python3 scripts/docs-check.py` for any doc change.
