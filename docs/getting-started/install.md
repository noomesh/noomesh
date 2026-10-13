# Install

noomesh is a self-hosted AI agent cluster that runs on your own hardware.
This page takes an empty Linux box to a running controller: install the
`noo` binary, pick an install shape, run the setup wizard, check health.
The command that proves it worked at the end is `noo health` exiting 0.
This is the primary path; [standalone-controller.md](standalone-controller.md)
is the no-checkout variant of the same step, and
`noo --help` lists every command.

Requirements: Linux (or WSL2), Docker with the Compose v2 plugin (v2.40 or
newer; `docker compose version` must work — Ubuntu's `docker.io` ships without
it, add `docker-compose-v2` from Ubuntu, or `docker-compose-plugin` from Docker's
own apt repository, which is newer and preferred), and optionally an NVIDIA GPU. The services run from Docker
images; nothing Python is needed on the host for the launcher itself — the
`noo` binary you just installed reads `noomesh.yaml` for it (compose_env,
the add-on map, and the watched-folder/workspace mounts regenerated on
every start). A host `python3` with PyYAML is only used as a fallback in a
contributor checkout running the scripts directly without `noo` on PATH;
with neither, the launcher prints one line naming what it skipped and keeps
the previous mounts (harmless on a fresh install, stale after you add
folders). `git` only for a contributor checkout.

Minimums, for one box running the controller and its first model (the
numbers are approximate and grow with the models you pull):

| | Minimum | Why |
|---|---|---|
| Disk | ~40 GB free on the data root | the core images (~10 GB incl. trellion), the default model (`gemma4:e2b`, 7.2 GB), Postgres and logs |
| RAM | 16 GB | the stack idles at ~6 GB; a CPU-only box also holds the model in RAM |
| GPU | optional; 4 GB+ VRAM to run a model on it | under ~10 GB the wizard offers a model verified to fit; with none, Ollama runs on CPU (slow, but it works) |
| Network | outbound HTTPS to `ghcr.io` and `ollama.com` at install | pulling images and the first model; nothing inbound |

## 1. Install the `noo` binary

`noo` is a single static binary published on every `noo-cli-v*` GitHub
release, for `x86_64` and `aarch64` Linux (musl) and Apple-silicon macOS.
The installer resolves the newest release, downloads the asset for your
platform plus the release's signed `sha256sums.txt`, checks that manifest's
signature against a release key pinned in the script, refuses to install on
a signature or checksum mismatch, and puts the binary in `~/.local/bin/noo`.

```bash
# The installer script is attached to every noo-cli release; "latest" always
# resolves to one (stack releases are never marked Latest), so no tag is needed:
curl -fsSL https://github.com/noomesh/noomesh/releases/latest/download/install.sh | sh

# From a checkout (never pipes into sh; runs the repo-local script):
scripts/install-noo.sh
```

The installer fetches the binary and its signed checksums, and tells you when it cannot resolve a release. Knobs the installer reads:

| Variable | Effect |
|---|---|
| `NOO_CLI_VERSION` | pin a release (`0.2.16`, `v0.2.16` and `noo-cli-v0.2.16` all work) instead of the newest |
| `NOO_INSTALL_DIR` | install somewhere other than `~/.local/bin` |
| `NOO_CLI_REPO` | fetch from a different `owner/repo` |

Then:

```bash
noo --version
noo whoami        # "client-only" on a fresh host — expected
```

`noo whoami` reports what the box is: `controller`, `node`, `both`, or
`client-only`. On a node-only box it also lists which verbs run there.

Updating later is `noo upgrade` (binary only), `noo upgrade --stack` (also
move the Docker stack to the images paired with that release), or
`noo upgrade --all` (plus the fleet's nodes). `noo upgrade --check` only
reports.

## 2. Where it lives

The default, and the only shape a machine without this source tree can
take, is **standalone**: `noo onboard` run outside any checkout writes the
compose files, scripts and templates embedded in the binary to `~/.noo`,
pulls the released images (`stack-v*` tags) and persists dist mode. Nothing
to clone, nothing to keep in sync. Details, including the `--bundle` variant
and updating: [standalone-controller.md](standalone-controller.md).

Standalone auto-detects: a bare `noo onboard` run outside any checkout (and
with `NOO_REPO_ROOT` unset) prints *no repo checkout found — onboarding in
STANDALONE mode* and continues. `--standalone` is the explicit override.

The core images are public at `ghcr.io/noomesh`, so a standard install needs
**no registry login**. Licensed add-ons (`trellion-intel`, `evolve`) are
separate private packages: GHCR access is granted with the entitlement, and
only then do you need `docker login ghcr.io` (a personal access token with
`read:packages`; a `gh auth` OAuth token is refused with `denied`).

### Contributors: run from a checkout

Standing inside a git checkout keeps the repo-based install. It differs only
in where the compose files come from and whether images are built or
pulled; the wizard, the CLI and the running stack are the same.

| Shape | You need | Images |
|---|---|---|
| **dist** | a git checkout | pulled from the release registry (`stack-v*` tags) |
| **dev** | a git checkout and `docker login dhi.io` (hardened base images) | built from this source tree — for changing the code |

```bash
git clone https://github.com/noomesh/noomesh.git ~/noomesh
cd ~/noomesh
```

The shape is persisted as the `NOO_INSTALL_MODE` bootstrap flag in `.env`
(`dev` or `dist`). The wizard asks once in the Services step — the default
is `dist`; answer `dev` to build — and every later `noo stack start`
honours the persisted answer. `noo stack start --dev` forces a one-off build
from source; `--dist [--tag <stack-vX.Y.Z>]` forces the released images.
Passing both is an error. A dev build that fails stops the wizard there;
nothing is started from a missing image.

In dist mode the image tag comes from `--tag`, else `NOO_IMAGE_TAG` (env,
then `.env`), else the newest local `stack-v*` git tag. No registry
login is needed for the core images; the launcher notes it when none is present
and pulls anonymously (a licensed add-on image that is denied is reported by
compose). A repo install runs `noo stack`
verbs from inside the checkout (or with `NOO_REPO_ROOT` pointing at it).

## 3. Run the setup wizard

```bash
noo onboard            # plain terminal; or --tui, or --web (http://127.0.0.1:7080)
noo onboard --ci       # non-interactive: accept defaults; the admin password is generated and never shown — set your own with `noo security admin-password reset`
```

The wizard runs eleven steps — prerequisites, environment, secrets and
admin account, Tailscale, PKI and cluster enrollment, storage, services,
first model, channels, add-ons, summary — and prints `step N/11` as it goes.
Run `noo onboard --help` for every flag; the
add-ons it offers (knowledge, voice, licensed tiers) are in
[add-ons.md](add-ons.md).

When it finishes and services were started, the summary prints the
endpoints: the dashboard on `localhost:8080` (and on your tailnet name if
Tailscale was configured) and Grafana. Without Tailscale the
dashboard is served with a certificate from the cluster's own CA, so a browser
warns until you trust it: see [trust-the-cluster-ca.md](trust-the-cluster-ca.md).
Open Grafana from the console's **Open Grafana** button: your noomesh account
signs you in, and Grafana has no password of its own to type. On a tailnet
controller Grafana answers on your tailnet name, port 3000, with the same
trusted certificate as the console (`tailscale serve` fronts it); the button
takes you there. On a `local`, `all` or LAN-bound controller Grafana is on the
controller's loopback only: from another machine, run
`ssh -L 3000:127.0.0.1:3000 <you>@<controller>` first (see
[monitoring.md](../operating/monitoring.md)).

Before `noo onboard` has issued certificates, the CLI's default gateway URL
is `http://localhost:8080`. That is the **only** cleartext the CLI will
speak: `http://` to a loopback address, for local development. Point it at
a non-loopback `http://` URL and it refuses (exit 3, `tls_untrusted`)
rather than putting your credential on the wire.
Once onboarding writes `NOO_TLS_CERT` the default becomes `https://`.

## 4. Start, stop, and inspect the stack

Service control on **this host** goes through `noo stack` (the fleet of
nodes is `noo cluster` — see the [CLI overview](../cli/README.md) for the
naming rule).

```bash
noo stack start                 # honours NOO_INSTALL_MODE; controller profile, GPU tier auto-detected
noo stack start --profile vllm  # add a compose profile
noo stack status
noo stack logs gateway --follow
noo stack restart --force       # recreate containers so new env and secrets are read
noo stack stop
noo stack rebuild               # dev mode: rebuild images and restart
```

`noo stack start` wraps `scripts/noomesh-start.sh`, which layers the
compose files (`docker-compose.cluster.yml`, the GPU embed overlay when
`nvidia-smi` succeeds, an auto-generated `docker-compose.override.yml`,
the dist overlay last), picks the `controller` profile unless the install
persisted another default, appends `gpu-tier1`/`gpu-tier2` from the
detected VRAM, and adds each enabled add-on's compose overlay file
(`docker-compose.<addon>.yml`, from the `addons:` map in `noomesh.yaml` —
add-ons are overlays, not compose profiles). Drive `docker compose` by hand
only when you know why. More on day-to-day operation:
[../operating/operator-manual.md](../operating/operator-manual.md).

## 5. The triage trio

Three commands answer "what is this box, is it up, and is Docker sane":

```bash
noo whoami           # controller / node / both / client-only
noo health           # GET /health; per-dependency table; exit 0 healthy, 5 degraded, 3 unreachable
noo doctor docker    # read-only: detects unclean-shutdown damage and prints the recovery recipe
```

`noo health` prints each dependency as ok / down / not reported and, when
something is down, the exact `noo stack logs <dep>` to run next. `--json`
prints the gateway's raw body, which includes an `addons` object
(`trellion`, `evolve`, `identity`, `trellion_intel` → `enabled` / `disabled` /
`unlicensed`). `voice` is launcher-only and does not appear here.

`noo doctor docker` counts ghost container records, empty names and
`Exited (255)` containers — the signature of a host that rebooted under
Docker. It never repairs by itself: a damaged host gets a four-step
runbook (remove what Docker can remove, stop Docker and clear
`/var/lib/docker/containers`, prune the builder, `noo stack start`). Exit
code is 1 when damaged, 0 when clean.

The exit-code contract every `noo` command follows is in the
[CLI overview](../cli/README.md#contracts).

## Next

- [first-chat.md](first-chat.md) — talk to what you built, ingest a document, find the dashboard
- [add-ons.md](add-ons.md) — switch on knowledge, voice, the licensed tiers
- [standalone-controller.md](standalone-controller.md) — a controller from the binary alone
- [multi-instance.md](multi-instance.md) — several stacks on one host
- [../cli/README.md](../cli/README.md) — how the `noo` CLI is organised
