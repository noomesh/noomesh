# Multiple instances on one host

> **Development.** Instances are checkout-scoped (`scripts/lib-instance.sh`:
> one instance = one checkout); this is a dev/test feature, not part of
> the standalone controller setup.

One machine can run several independent noomesh stacks side by side —
each with its own containers, network, volumes, ports, data root and
credentials. An instance is **one checkout (or standalone home) plus one
`NOO_INSTANCE` name**. The command that proves it: `noo --instance galaxy
stack status` showing `noo-galaxy-*` containers next to the default
`noo-*` ones.

## Create a second instance

Clone (or materialise) a second install, then onboard it with a name:

```bash
git clone https://github.com/noomesh/noomesh.git ~/noomesh-galaxy
cd ~/noomesh-galaxy
noo onboard
```

The Environment step asks for an **instance name** (default `noomesh`,
which — like `mesh` or blank — means the default instance) and, once you
name one, a **port offset** (also asked when `:8080` is already bound).
They land in `.env` as the two bootstrap flags:

```sh
NOO_INSTANCE=galaxy
NOO_PORT_OFFSET=1000
```

They live in `.env` because the launcher reads them before any config
file is chosen. The Storage step scopes the data root automatically to
`<root>/instances/galaxy` — see the refusal rule below for why.

**The default instance is the absence of configuration.** No
`NOO_INSTANCE` means the directory-derived compose project, `noo-*`
container names, the `noo-cluster` network and stock ports. Existing
installs are never renamed.

## What the name and offset derive

`scripts/lib-instance.sh` turns the pair into everything else and every
lifecycle script sources it; the `noo` binary mirrors the same rules.

| Surface | Default instance | Instance `galaxy` |
|---|---|---|
| Compose project | directory-derived (`noomesh` for a `~/noomesh` checkout) | `noo-galaxy` |
| Container names | `noo-gateway`, `noo-postgres`, … | `noo-galaxy-gateway`, … |
| Docker network | `noo-cluster` | `noo-galaxy-cluster` |
| Data volume | `<project>_noo-data` | `noo-galaxy_noo-data` |
| Data root | `NOO_DATA_ROOT` | `NOO_DATA_ROOT/instances/galaxy` |
| Gateway | `:8080` | `:8080 + offset` (`:9080`) |
| NATS client / monitor / cluster | `:4222` / `:8222` / `:6222` | each `+ offset` |
| Node agent, Prometheus, Alertmanager, Grafana, exporters | `:8081`, `:9090`, `:9093`, `:3000`, `:9100`, `:9400` | each `+ offset` |
| CLI credentials | `~/.config/mesh/credentials.json` | `~/.config/mesh/galaxy/credentials.json` |

Two ports keep their own knobs, which win over the offset when set
explicitly: `POSTGRES_PORT` (5433) and `NOO_MODEL_CACHE_TLS_PORT` (8443).
(The
MCP door has no port of its own since stack-v0.2.41; it is a path on the
gateway port.)

Credentials are per instance because two stacks have two JWT secrets;
`noo auth login` inside the galaxy checkout writes the galaxy file.

## Data-root refusal

Every stateful volume is bind-mounted under `NOO_DATA_ROOT`, so two
instances sharing one root would open the same Postgres, Redis and NATS
files — the production stack's. The launcher therefore **refuses** to
start a named instance whose data root does not end in
`/instances/<name>`, with a message that says so. The wizard scopes the
root for you; if you assembled `.env` by hand, fix `NOO_DATA_ROOT`. The
escape hatch for stopping or cleaning a misconfigured instance is
`NOO_INSTANCE_UNSAFE_DATA_ROOT=1`; never start with it. The default
instance is not guarded.

## Port guard

`noo stack start` (controller path only) refuses to launch when one of the
instance's host ports — gateway, Postgres, NATS client and monitor, the
MCP door, the model cache — is already bound by anything that is not a
running container of this instance. The error names the ports; fix by
stopping the other service or giving this instance a different
`NOO_PORT_OFFSET`. `:8081` is deliberately not checked (the host-native
node agent owns it). `stop`, `status` and `logs` never refuse.

## Drive an instance from anywhere

`noo` resolves the instance from the `.env` of the checkout it runs in.
From elsewhere:

```sh
noo --instance galaxy cluster status
noo --instance galaxy stack logs gateway
```

`--instance` sets `NOO_INSTANCE` for the process, so one rule serves the
credential file, container names and the gateway URL's port offset. Every
docker-boundary command (`exec`, `inspect`, `logs`, `restart`) remaps
container names through the prefix, so `noo logs` in the galaxy checkout
reads `noo-galaxy-gateway`, never the default stack.

## Tailscale serve: one MagicDNS name, many instances

A host has one MagicDNS name, so instances share it by path:

- **Default instance**: `/` → gateway, `/mcp` → the MCP external door.
- **Named instance**: `/<instance>` → its gateway port, `/<instance>/mcp`
  → its MCP door. The wizard writes these mounts and prints the URLs,
  e.g. `https://<controller>/galaxy`.

`tailscale serve` strips the path prefix before proxying, so the gateway
receives the same request shape either way. API, MCP and CLI access work
fully under the subpath; the browser dashboard of a named instance uses
absolute asset paths, so reach it directly at `https://<controller-ip>:<port>`.

## What is not namespaced

- **Images** — shared on purpose: same binaries, different instances.
- **The tailnet node identity** — per host, not per instance.
- **Worker and edge nodes** — a node belongs to whichever gateway URL it
  registers with; point it at `:9080` and it serves the galaxy instance.

## Retire an instance

`noo stack stop` in its checkout, then remove its volumes
(`docker volume rm noo-<name>_noo-data`, and the rest `docker volume ls`
shows under the `noo-<name>_` prefix), its `<root>/instances/<name>`
directory, and `~/.config/mesh/<name>/`.
