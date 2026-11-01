# Standalone controller

A standalone controller runs on a machine that has only the `noo` binary
and Docker — no git checkout. The deploy slice (compose files, config
templates, the launch scripts, prompts and skills, monitoring configs) is
embedded in the binary and written out at onboard time. The command that
proves it: `noo onboard` on a box with no checkout, followed by
`noo health`. [install.md](install.md) is the primary path; this page is
its no-checkout variant.

## Prerequisites

- Docker with the compose plugin
- no registry login for the core images (they are public). Licensed add-ons
  (`trellion-intel`, `evolve`) are published to a private registry: run
  `docker login ghcr.io` once registry access is granted with the entitlement
- Tailscale, optionally: the wizard offers to install it. Declining keeps a
  LAN-only box — the dashboard is reachable only on this machine's own
  addresses, and adding nodes later needs a tailnet.

## Bring one up

`noo onboard` auto-detects standalone: with no checkout in the working
directory or above it, and `NOO_REPO_ROOT` unset, a bare `noo onboard`
prints *no repo checkout found — onboarding in STANDALONE mode* and
continues. Standing inside a checkout keeps the repo-based install — but
an already-materialised standalone home (`~/.noo`) outranks the checkout
you are standing in; set `NOO_REPO_ROOT` to the checkout when you mean
that one. `--standalone` is the explicit override either way.

```bash
# the release installer (install.md §1):
curl -fsSL https://github.com/noomesh/noomesh/releases/download/<noo-cli-tag>/install.sh | sh
noo onboard --standalone                     # the control plane, monitoring included
```

`--bundle` applies whenever onboarding ends up standalone, whether that's
this explicit `--standalone` or the auto-detect above — `--standalone`
isn't required alongside it. It is refused on a repo/controller install.
(`--with-monitoring` is accepted and does nothing: since 2026-09-28 the
monitoring set is in the `standalone` profile itself.)

What `--standalone` does before the normal steps run:

- materialises the embedded deploy slice under **`~/.noo`** (override with
  `NOO_HOME`) and writes a `.noo-standalone` marker there, so later bare
  runs recognise the install
- points the wizard at it (`NOO_REPO_ROOT`) and neutralises the dev-only
  source overlays
- **forces dist mode**: seeds `.env` with `NOO_INSTALL_MODE=dist`,
  `NOO_DEFAULT_PROFILE=standalone`, the image registry prefix, and the
  stack tag paired with this binary release when one is baked in

Secrets, the age key and the PKI are generated live in the wizard; nothing
sensitive is embedded. From there the eleven wizard steps run unchanged.

### What runs

The `standalone` compose profile: `gateway`, `worker`, `trellion`,
`sandbox`, `postgres`, `redis`, `nats`, `model-cache`, `ollama-embed`
(the embedding server the knowledge routes use on a standalone box) and
the monitoring set — `loki`, `tempo`, `prometheus`, `alertmanager`, `grafana`, `node-exporter` and, on a GPU
host, `nvidia-exporter` — **not** `node-agent`: the agent runs as a host
process installed by the pull rail (`noo enroll` + `noo cluster
provision`), not a compose service. That is the `controller` profile with
the local embedder in place of the containerised agent, and it is enough
to enroll nodes, run the mesh and federate. The monitoring set needs
`GRAFANA_PASSWORD` (onboard mints it) and the `loki`, `tempo`, `alertmanager`, `prometheus`, `grafana` and exporter service leaves
(onboard issues them; `noo onboard --only enrollment` on an older install).

A fresh standalone controller starts with an empty inventory; the PKI
step issues only the CA and the gateway and service certificates.

## Update it

Because the deploy slice rides the binary, updating the controller's
config means updating the binary:

```bash
noo upgrade --check          # current vs latest, no changes
noo upgrade                  # the binary only: pull, verify, swap in place
noo upgrade --stack          # + move the stack to this release's paired images
noo upgrade --nodes          # + restage a signed provision bundle for every pull-capable node
noo upgrade --all            # binary + stack + nodes
noo upgrade --stack --tag vX.Y.Z   # override the paired stack tag
noo stack sync-assets        # refresh the deploy slice from the binary without upgrading
```

Every CLI release records the stack tag it was released alongside, so
`--stack` needs no version bookkeeping. After the binary swap the process
re-executes the new binary before touching the stack, so the assets and
pairing used are the new release's. Re-running the materialisation is
safe: it refreshes compose files, scripts and templates and never touches
`noomesh.yaml`, `secrets/` or `pki/`.

`noo upgrade --check` reports current vs latest without changing anything. This
is the single, self-contained update path — see [setup-and-host.md](../cli/setup-and-host.md#upgrade).

## Take the deploy slice from a bundle instead

By default the config is locked to the binary version. To unpin it, feed
the wizard a versioned bundle:

```bash
noo bundle export noo-stack-bundle.tar.gz     # any binary exports its own slice, plus a .sha256 sidecar
noo onboard --standalone --bundle ./noo-stack-bundle.tar.gz
noo onboard --standalone --bundle https://…/releases/download/noo-cli-vX.Y.Z/noo-stack-bundle.tar.gz
```

Every CLI release attaches `noo-stack-bundle.tar.gz`. `http://` URLs are
refused; `https://` fetches require the `.sha256` sidecar (a local path
only warns without one); the archive is checksum-verified and every entry
is rejected if it is absolute or contains `..` before extraction.

| | Embedded (default) | Bundle |
|---|---|---|
| Config source | the `noo` binary | a fetched, versioned artifact |
| Network at onboard | images only | images + the bundle |
| Update config | `noo upgrade` | re-fetch a newer bundle |
| CLI and config | locked together | independent |

## Add nodes

Which machines to use, and how to check one before enrolling it, is in
[supported-hardware.md](supported-hardware.md). Node birth needs no checkout or
Go toolchain on either side:

```bash
noo cluster bootstrap-token create --node worker1   # → paste the blob on the node
noo cluster provision worker1 --wait                # certs + env + agent binary + unit, staged at the gateway
noo cluster status
```

`provision` resolves everything from the node's enrollment record, issues
its certificate, renders the agent env, extracts the arch-matched agent
binary from the released node-agent image, signs the bundle with the
cluster CA, encrypts it to the node's birth certificate and stages it at
the gateway. The node's fetch timer pulls and applies it — the controller
never opens a connection to the node, so nodes behind NAT work. Re-run
`provision` to re-provision. A node that predates the pull rail (no birth
cert on record) must be re-enrolled rather than reached over SSH, which is
retired.

## A second controller on the same tailnet

Two controllers can share one tailnet. Mesh isolation does not come from
the tailnet; it comes from each controller's **CA**: a node's trust anchor
lands at birth and the node refuses bundles signed by any other CA.

- Give the second controller its own tailnet hostname (the wizard asks;
  the default `noo-controller` would collide and be auto-suffixed).
  `noo cluster provision` renders node envs with the controller's actual
  MagicDNS name, so nodes phone the right gateway.
- `noo enroll` refuses a node that already belongs to a different mesh
  (exit 78) before burning the token. Move a node deliberately:
  `noo cluster teardown-node <n> --factory` on its own controller, then
  enroll it on the new one.
- Warm-standby failover between two controllers uses the stable role
  name: `noo controller promote` / `demote` — see
  [../cli/setup-and-host.md](../cli/setup-and-host.md).
