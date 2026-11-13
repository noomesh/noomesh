# Add-on developer guide

> **DRAFT — not yet verified end to end. Steps marked UNVERIFIED have not been seen working on a live install.**

This guide walks one path: build an add-on, sign it, publish it, and have an
operator trust and enable it. It is written for someone outside the core team.

It does not replace the contract. The contract is
[development/addons.md](../development/addons.md) (routes, databases,
workloads, runtime inputs, the signed lock). The operator's half is
[getting-started/add-ons.md](../getting-started/add-ons.md). The node-workload
and model-set formats are in
[reference/node-workloads.md](../reference/node-workloads.md). This page links
to them instead of repeating them.

How to read the tags:

- **UNVERIFIED** means the step exists in code and is described from reading
  the code, but nobody has seen it work on a live install. Treat it as a claim
  to test, not a recipe.
- No tag means the step has been seen working live. That is limited to: the
  public and private-registry pull paths, `noo addons trust-key`,
  `noo addons registry-login`, and enabling a signed third-party add-on.
- Every command below is an exact command line. Secrets never appear on the
  command line; tokens and seeds go through stdin or a file.

Contents:

1. [What an add-on is](#1-what-an-add-on-is)
2. [The manifest and the signed bundle](#2-the-manifest-and-the-signed-bundle)
3. [Signing keys](#3-signing-keys)
4. [The release workflow](#4-the-release-workflow)
5. [The operator side](#5-the-operator-side)
6. [Node workloads](#6-node-workloads)
7. [Model sets](#7-model-sets)
8. [What core refuses, and why](#8-what-core-refuses-and-why)
9. [Pain points from the first add-on author](#9-pain-points-from-the-first-add-on-author)
10. [Worked example](#10-worked-example)

---

## 1. What an add-on is

An add-on is a set of containers (and optionally node-side workloads) that run
beside the core stack. The core stays free and self-hosted. An add-on is
switched on by the `addons:` map in `noomesh.yaml`, and it reaches the core
through the same seams anyone can use: HTTP routes the gateway proxies, a
gateway service key, a NATS subject prefix, a database schema of its own.

### First-party and third-party

The CLI ships a fixed table of **five** first-party add-ons: `trellion`,
`voice`, `trellion_intel`, `identity` and `evolve`
(`ADDON_ROWS` in `noo-cli/src/commands/addons.rs`). A name is first-party when
it normalises (`-` to `_`) to one of those rows. Two of the five are licensed
(`trellion_intel`, `evolve`) and take their trust anchor from the operator's
entitlement. The other three are free and ship with the stack.

**Every other name is third-party**, including add-ons that PersonifAI builds
itself. For a third-party add-on:

- the operator trusts your signing key by hand (`noo addons trust-key`);
- your overlay is checked under stricter rules than a first-party one (section 2);
- nothing in noomesh vouches for you. The operator is trusting a key you gave
  them out of band.

`noo addons trust-key` refuses the five first-party names: their keys come from
the entitlement, and `trust-key` cannot give them others.

### Three ways the controller pulls an add-on

| Path | How the controller pulls | What it needs | State |
|---|---|---|---|
| Public (community) | Anonymously, from the trusted registry root | A public OCI package; your release key given to the operator out of band; `noo addons trust-key` | Works |
| Private (in-house) | With a per-add-on read-only token, sent to that registry root only | The public path's needs, plus `noo addons registry-login` on each controller | Works |
| Commercial, through the add-on registry proxy | With the operator's entitlement as the pull credential | A deployed proxy and an entitlement anchor | **UNVERIFIED**, and closed to third parties today (see the note below) |

> **Note: the commercial path does not serve third-party add-ons.** For any
> name outside the five rows, the CLI reads only the operator's `addon_trust`
> entry (`resolve::installed_anchor`). An entitlement's per-add-on anchor is
> never consulted for a third-party name, so the proxy route is unreachable for
> it. If you need to be paid-for-and-licensed through noomesh, that is not
> available yet.

Rules that hold on every path:

- The vendor's own registry token is only ever sent to `ghcr.io`. On a
  third-party route it is not sent at all.
- Trust does not move with location. The lock is verified against the registry
  root the operator trusted, and every image reference in it must sit under
  that root.
- The launcher never pulls and holds no registry credential. `noo addons
  enable`, `noo addons upgrade` and `noo upgrade --stack` pull; `noo stack
  start` and `noo stack restart` re-verify offline.

---

## 2. The manifest and the signed bundle

There is no single "manifest" file. An add-on is a **bundle**: a set of
declaration files, all listed (by name and hash) in one signed lock. Core
refuses anything the lock does not list and anything that does not hash to the
lock.

### The add-on name

- Lowercase letters, digits, `-` and `_`; starts with a letter; at most 32
  characters (`trust::name_ok`).
- The gateway side also reserves core service names (today `worker`).
- At enable, core refuses a name, or any name derived from it, that core
  already uses: the compose service and container `noo-<x>`, certificate
  names, database roles `noo_<id>` and `noo_<id>_ddl`, and core environment
  variables. `<id>` is the name upper-cased with `-` as `_`.
- Do not choose a name that normalises to a first-party row. `trellion-intel`
  is `trellion_intel`.
- `foo-bar` and `foo_bar` are both legal names and map to the same `<id>`.
  Whether enable catches that collision has not been tested (**UNVERIFIED**).
  Pick one spelling and do not publish the other.
- Node workloads are stricter: both the add-on name and the workload name must
  be lowercase letters, digits and `-` only (no `_`) when used in a node
  workload (section 6).

> **Note.** `trust-key` accepts `worker` as a name; the manifest rules refuse
> it later. Do not use core service names.

### The bundle's files

Each file is listed under `files` in the signed `noo-addon-lock/2` lock and
published as one OCI layer. A file name is one plain component of
`[A-Za-z0-9._-]`, at most 128 bytes. A declaration file is at most 64 KiB. A
lock holds at most 32 files, each at most 1 MiB.

| File | Required | What it declares |
|---|---|---|
| `docker-compose.yml` (the overlay) | Yes. A v2 lock without it is refused (`NoOverlay`) | Your services. See the overlay rules below. |
| `x-noo-addon` (a block inside the overlay) | If you call the gateway | `addon` (= your name), `consumer` (`svc:<kebab>`), `key` (`NOO_SVC_KEY_<ID>`, which must be your own), `containers` (`noo-*`), `scopes` (never `addon`, `kiosk`, `mcp:operator` or `identity`), optional `why` and `nats_principal`. |
| `routes.json` | For an HTTP surface | `version: 1`, `addon`, `base_url_env` (`NOO_<ID>_URL`), the routes, scopes (`<name>:<word>`), optional `features`, `ui`, delegation. Unknown fields are refused. |
| `system.json` | If you own database tables | `schema` = `<id>`, `role` = `noo_<id>`, `ddl_role` = `noo_<id>_ddl`, `extensions` from a closed list. |
| `workloads.json` | For controller-side containers noomesh may start, stop or drain | At most 16 entries; `drain.route` names an `internal` route in `routes.json`; `drain.timeout_secs` at most 600. |
| `node-workloads.json` | For workloads placed on nodes | See section 6. |
| `resources.json` | For runtime inputs (gateway URL, TLS leaf, keys, shared secrets, networks) | Schema: [`addon-resources.schema.json`](../reference/addon-resources.schema.json). |

The field-by-field rules for routes, databases, workloads and resources are in
[development/addons.md](../development/addons.md). Public paths must sit under
`/api/` and outside the reserved prefixes (`/api/addons/`, `/api/auth`,
`/api/security/`, `/api/config`, `/api/users`, `/api/v1/settings/`,
`/api/cluster/`, `/api/logs/`, `/api/metrics/`, `/api/grafana-ds/`,
`/api/tasks`).

### Overlay rules for a third-party add-on

Core checks your overlay (`guards::check_overlay`, `check_runtime`,
`check_bundle_files`) and refuses, with nothing changed:

- an image line that is not `${NOO_ADDON_IMAGE_<NAME>:-...}` (the launcher
  exports the pin there);
- a secret that is not your own (`NOO_SVC_KEY_<ID>`, `NOO_BUS_KEY_<ID>`,
  `NOO_<ID>_DB_PASSWORD`, `NOO_<ID>_DDL_PASSWORD`, `NOO_PGPASS_<ID>`,
  `NATS_<ID>_PASSWORD`, `NOO_ADDON_SECRET_<ID>__<NAME>`);
- `extends:`, a service named like a core service, `env_file`, `volumes_from`,
  a core volume, `devices:`, `cap_add:`, host namespaces, an unconfined
  security profile, host `configs:`, or a bind mount that is not a declared
  mount directory.

Use an explicit `environment:` allowlist and no `profiles:`.

### Images

- Every image is pinned by digest: `<repo>@sha256:<64 hex>`. `repo:tag@digest`
  is refused (`NotDigestRef`).
- Every image must sit under the registry root you sign (`OutsideRegistry`).
- If you build `FROM` a stack image, sign `--base <image>=<digest>`. It is
  checked against the stack's own signed lock.

### Console surfaces

An add-on reaches the console in two ways: a `ui` on its own origin
(`upstream_path`, `min_role`, `title`, `feature`, `timeout_secs`), or a console
piece served from an `internal` route named `console_piece` (slot keys start
`<name>:`, at most 64 KB). The gateway-side checks for the console piece were
not re-read for this guide (**UNVERIFIED**). The term "console paths" appears
in older notes; no field or validator by that name was found.

### Check before you sign

```sh
noo addons check ./bundle
noo addons check ./bundle --name example-addon
```

**UNVERIFIED** (not yet run by the guide's author). It runs the same file
checks as `noo addons enable`, and runs `routes.json` and `node-workloads.json`
through their validators. Without `--name` the directory name is the add-on
name. A pass is **not** "enable will accept it": it does not check the lock's
signature or file hashes, the operator's trusted key, the stack's base-image
row, the pull, or node-workload image names against the lock. It checks against
the compose files embedded in your `noo`, not a live install's. Run it in your
CI with the `noo` of each stack you support.

### Develop before you release

The operator can trust a temporary key on their own mesh, then you hand them
the lock directly:

```sh
noo addons trust-key example-addon <dev-pubkey> --registry ghcr.io/vendor/example-addon --dev --expires 14d
noo addons enable example-addon --lock ./addon-bundle.json
noo addons enable example-addon --lock ./addon-bundle.json --provision-only
noo addons untrust-key example-addon --dev
```

`--expires` is required with `--dev` and is at most 30 days. A development key
is never a release key and the reverse. `noo security addon-lock verify`
refuses a lock signed only by a development key. `--provision-only` creates the
database schema and roles and does not start the add-on. With `--lock` the
signature must sit beside the lock as `<lock>.sig` and every bundle file in the
same directory.

---

## 3. Signing keys

Keys are ed25519. Signatures use the scheme `noo-sig1`. A seed is 64 hex
characters.

### Generating

There is **no `noo` verb that generates an add-on signing key or prints its
public half.** Generate a seed yourself and derive the public key without
printing the seed. **UNVERIFIED** (from reading the code and an internal
check script; not run for this guide):

```sh
umask 077
openssl rand -hex 32 > addon.seed
printf '302e020100300506032b657004220420%s' "$(cat addon.seed)" | xxd -r -p > addon.der
openssl pkey -inform DER -in addon.der -pubout -outform DER | tail -c 32 | od -An -tx1 | tr -d ' \n'; echo
shred -u addon.der
```

The 16-byte prefix is the fixed PKCS#8 header for an ed25519 seed. The output
is the 64-hex public key the operator trusts. As a cross-check,
`noo --json security addon-lock sign ...` prints `"pubkey"`. The seed is never
printed and never read from an environment variable.

### Holding

- Keep the seed only in your CI's protected secret store, available to the
  release job and nothing else. Restrict that environment to your release
  branch and release tags.
- Give it to `sign` on stdin (`--seed-file -`) or from a 0600 file. Never put it
  on a command line.
- Keep a second copy offline. Losing the seed means every operator must
  `trust-key` a new key.

### Rotating

There is no rotation protocol and no revocation feed. Rotating is manual:

1. Generate a new seed and public key.
2. Tell operators the new public key through the same channel as the first.
3. Each operator runs `noo addons trust-key example-addon <new-pubkey>`. The
   registry root is reused from the first key.
4. Sign new locks with the new seed.
5. After operators have moved, each runs `noo addons untrust-key example-addon <old-pubkey>`.

Locks already signed with the old key stay valid while the old key is trusted.
The rotation steps themselves are **UNVERIFIED**.

### What the operator trusts

By running `trust-key`, the operator records `addon_trust.<name>` in
`noomesh.yaml`: your registry root and your key(s). From then on they accept a
lock for that name only if it verifies against the key, lists their stack tag,
has files that match their signed hashes, and has images under that root. They
are trusting whoever holds the seed. The key comes from you through a channel
the operator trusts; noomesh keeps no directory of developer keys.

---

## 4. The release workflow

The shape, generically. Your own CI will differ.

### Build the images

1. Build each image and push it to your registry root. Record each image's
   digest.
2. If you build `FROM` a stack image, record the stack image digest for
   `--base`.
3. Never take `latest`. Always sign the digest you built.

### Write the lock

The lock format is `noo-addon-lock/2`: the add-on name, a semver `version`, a
40-hex `source_commit`, the stack tags it supports, the images by digest, the
base rows, and the bundle files with hashes. It is signed with your seed.
Validation rules:

- `--supports` takes `vX.Y.Z` or `vX.Y.Z-rc.N`, with no `stack-` prefix. An empty
  list is refused.
- `--version` is semver; `--source-commit` is 40 hex.
- `--registry` is `host/path` with no scheme, no `:`, no `@`, no trailing `/`.
  A registry with a port (`host:5000/x`) is therefore refused.
- Never re-serialise a lock. Non-canonical bytes are refused (`NotCanonical`).

### Sign and verify

```sh
noo security addon-lock sign --addon example-addon --version 1.2.0 --source-commit <40-hex> \
  --supports v0.6.20,v0.6.21-rc.1 \
  --image app=ghcr.io/vendor/example-addon@sha256:<digest> \
  --base app=sha256:<stack-image-digest> \
  --file docker-compose.yml=./docker-compose.yml --file routes.json=./routes.json \
  --registry ghcr.io/vendor/example-addon --seed-file - --out addon-bundle.json < addon.seed
```

This writes `addon-bundle.json` and `addon-bundle.json.sig`. Run the same
command without any `--file` and with `--out addon-lock.json` to write the v1
lock that CLIs from 0.6.3 and earlier read. Publish both.

```sh
noo security addon-lock verify addon-bundle.json --key <release-pubkey> --addon example-addon \
  --registry ghcr.io/vendor/example-addon --stack v0.6.20 --files-dir .
```

`verify` refuses a `--key` that is a development key. Verify against a public
key pinned in your reviewed source, not one read from the artifact.

### Publish to an OCI registry

The lock is an OCI artifact in **the same package as the image**, tagged
`<registry-root>:stack-<stack tag>`. Push one tag per stack tag in `--supports`.

| Item | Value |
|---|---|
| `artifactType` | `application/vnd.noomesh.addon-lock.v1` |
| `addon-lock.json` and its `.sig` | `application/vnd.noomesh.addon-lock.v1+json`, `application/vnd.noomesh.addon-lock.sig.v1` |
| `addon-bundle.json` and its `.sig` | `application/vnd.noomesh.addon-bundle.v1+json`, `application/vnd.noomesh.addon-lock.sig.v1` |
| Each bundle file | `application/vnd.noomesh.addon-file.v1`, titled with the file name |

The exact `oras push` line is in
[development/addons.md](../development/addons.md#the-signed-add-on-lock). After
you push, read the artifact back and check the manifest, every layer and a
fresh pull.

### Re-sign for every stack release

A lock lists exact stack tags. **Every new stack release needs a new signed
lock from you before an operator can roll to it.** A release pipeline should:

- run when a new `stack-v*` tag appears;
- recover the exact image digest of your existing release rather than rebuild;
- run `noo addons check` with that stack's `noo`;
- sign, verify against the pinned public key, publish, and read back;
- refuse a downgrade, and refuse a different digest for the same version.

The noomesh release notifies add-on repositories that it names itself. A
third-party developer gets no notification and must watch `noomesh/noomesh`
releases for new `stack-v*` tags.

---

## 5. The operator side

### Trust the developer's key

```sh
noo addons trust-key example-addon <64-hex-pubkey> --registry ghcr.io/vendor/example-addon
noo addons untrust-key example-addon <pubkey>
```

The first key for a name needs `--registry`; later keys reuse it. It writes
`addon_trust.example-addon` into `noomesh.yaml` (admin-only through the config
API). The key comes from the developer through a channel the operator trusts.

### A private registry

```sh
noo addons registry-login example-addon --registry ghcr.io/vendor/example-addon < token.txt
noo addons registry-login example-addon --registry ghcr.io/vendor/example-addon --from-file token.txt
noo addons registry-login example-addon --clear
```

`--registry` must be exactly the root the key was trusted for. The token is
read from stdin or a file, never argv, and is refused if stdin is a terminal.
It needs the sops secret store. It is stored as
`NOO_ADDON_REGISTRY_CRED_<NAME>`, sent to that root only, and `noo addons list`
shows whether one is set, never its value. Create it read-only (`read:packages`
on GHCR). `untrust-key` removes it with the last key.

**Limit: the registry needs a publicly trusted certificate.** noomesh fetches
a lock only over HTTPS, and it trusts only the public certificate authorities
built into `noo` (Mozilla's set), not the machine's own trust store. A
registry with a certificate from your own CA, or a plain-HTTP registry (a
local `registry:2` on a laptop), cannot serve your lock to noomesh. Use
ghcr.io, Docker Hub, or a registry with a certificate from a public CA. For
local work, `noo addons enable <name> --lock ./addon-bundle.json` installs
from the file and fetches nothing, but then `noo upgrade` cannot follow the
add-on to a new stack release.

### Enable

```sh
noo addons enable example-addon
noo addons enable example-addon --lock ./addon-bundle.json
noo stack restart --force
noo addons list
noo addons show example-addon
noo addons verify
```

`enable` fetches `<root>:stack-<NOO_IMAGE_TAG>` unless `--lock` is given. Its
steps run in order, and any refusal leaves `noomesh.yaml` unchanged:

1. Verify the signed lock, pull the images by digest, write the pin.
2. Plan and mint the gateway key from `x-noo-addon`.
3. Mint database credentials.
4. Declare `addons.example-addon` on, last.

Options: `--accept-suggested` or `--no-grants` decide feature grants.
`noo addons set example-addon --delegate tasks` is the operator's half of task
delegation (**UNVERIFIED**). Node-workload leaves reach nodes only with
`noo upgrade --nodes`.

> **Note.** `getting-started/add-ons.md` still says a third-party add-on's
> gateway key and database credentials are not minted and that the lock and
> images are fetched only anonymously. The code mints them for every pinned
> third-party add-on and supports `registry-login`. Follow the code.

### What `noo upgrade --stack` refuses

**UNVERIFIED** (read from `upgrade.rs`, not run against a live third-party
add-on). Before a roll, `noo upgrade --stack` resolves, verifies and pulls,
for the target tag, every add-on that is trusted and declared on. One that
cannot is a **hold**: "refusing to roll to `<tag>` ... Nothing was changed."

| Cause | What is printed | Remedy |
|---|---|---|
| Registry 404 for `stack-<tag>` | no signed lock published yet | `noo addons upgrade example-addon --check`, retry later |
| Registry 401 or 403 | the registry refused access | `noo addons registry-login example-addon --registry <root>` |
| Lock signed by an untrusted key | bad signature | `noo addons trust-key ...` |
| Lock does not list the target | not for this stack | `noo addons disable example-addon`, or roll to an older tag |
| Older version than pinned | downgrade | `noo upgrade --stack --allow-downgrade` |
| A v1 lock | unbundled | the developer must re-sign |

`noo upgrade --check --stack` reports holds without pulling. A declared-on
third-party add-on with **no** trust entry does not hold the roll; the launcher
refuses it at start instead and starts the rest.

**The confusing "access refused".** Any 401 or 403 is reported as a credential
problem and sends the operator to `registry-login`. On a private package, a
missing `stack-<tag>` may look the same as a bad token, so "the developer has
not re-signed yet" can be reported as "your credential is wrong". Whether GHCR
answers 401/403 rather than 404 for a missing tag was inferred from one
incident and not reproduced (**UNVERIFIED**). If a stored token is refused,
check that the developer has published the tag before replacing the token.

---

## 6. Node workloads

A node workload is a container that core builds from a closed declaration and
places on a capable node: typically a GPU worker, with no network and no
credentials. The full contract is
[reference/node-workloads.md](../reference/node-workloads.md) with its schema
[`noo-addon-node-workloads-1.schema.json`](../reference/noo-addon-node-workloads-1.schema.json).

**The whole node-workload path is UNVERIFIED.** The pieces exist on `dev` and
each has tests, but no end-to-end run (consent, placement, reserve, the door,
drain) has been seen on a live install.

### `node-workloads.json`

Format `noo-addon-node-workloads/1`. At most 16 workloads per file. Per
workload (every field is checked by the CLI, the gateway and the node agent
against shared fixtures):

- `name`, `image` (a **name** in the lock's `images` map, never a ref), `uid`
  (at least 1; not the agent's own), `command?`, `port` (1024-65535),
  `protocols` (`http`, `ws`);
- `health {ready, live, start_secs}`;
- `drain {path, done_path, timeout_secs}` — the worker's own drain endpoints;
- `service_drain {route, timeout_secs}` — required; names an `internal` route
  in your `routes.json` that drains your CPU-side service;
- `accel {gpu, slots_env?, realtime}`;
- `models[]` — the model slots (section 7);
- `env` — see below;
- `scratch[]` — see below;
- `limits {ram_mb, cpus, pids}` — required.

Env keys must start with `<ADDON_UPPER>_`. These prefixes are refused whatever
the add-on is called: `NOO_`, `NVIDIA_`, `CUDA_`, `LD_`, `PYTHON`, `HF_`,
`TRANSFORMERS_`. Values are strings; each key carries a bound (`min`/`max` for
an integer, or `one_of`).

### The door name

The node's door container is called `noo-stunnel-<addon>-<workload>`, which
must be one DNS label of at most 63 characters. So
`len(addon) + 1 + len(workload)` is at most **51**
(`door_name_too_long`), and both names are lowercase letters, digits and `-`,
starting and ending with a letter or digit (`door_name_invalid`). `_` is not
mapped to `-`.

### Scratch, including exec scratch and the no-nesting rule

`scratch[]` is at most 4 entries. Each is `{target, max_mb}` (a size-capped
volume) or `{target, tmpfs_mb}`, with exactly one size. Both are held in
memory, so they count against `limits.ram_mb`. They are thrown away at release.

- The target is not `/`, `/proc`, `/sys` or `/dev` (or below them) and does not
  overlap a model slot's target.
- **Scratch targets must not nest.** A target that repeats, sits inside, or
  contains another scratch target is `scratch_invalid`. Declare siblings, for
  example `/cache` and `/exec-cache`, not `/cache` and `/cache/exec`.
- Every scratch is mounted `nosuid,nodev,noexec`, **except** one entry that may
  set `"exec": true`. At most one entry may; its size is at most **1024 MiB**
  (512 MiB is the recommendation; the size is required). It is for a worker that
  compiles and loads native code, such as a GPU kernel compiler that writes a
  shared library into its cache and loads it. The exec entry is tmpfs-backed,
  owned by the worker's uid with mode 0700, empty at every container start, and
  charged to the worker's memory limit.
- The `exec` flag is in the signed file, so it is part of what the operator
  approves, and `noo addons check` names it.

> **Note.** Earlier design notes say a scratch nested inside another is
> accepted. From 0.6.21 it is refused. Follow the current rule.

### Consent

A node runs an add-on's workload only if its owner consented. The node's policy
is `NOO_ADDON_WORKLOADS` = `none` | `approve` | `auto`, default `approve`
(before 0.6.19 the default was `none`). With `approve` and nothing approved,
nothing runs. `none` is the owner's kill switch and refuses even an approved
add-on. The owner approves one add-on at one image digest, on the node, as
root:

```sh
sudo "$(command -v noo)" node workloads approve example-addon <digest>
sudo "$(command -v noo)" node workloads revoke example-addon <digest>
sudo "$(command -v noo)" node workloads list
```

The digest is the one the placement's `consent_unapproved` refusal names. The
controller cannot approve on its own. An owner can opt a node in to
controller-signed approvals:

```sh
sudo "$(command -v noo)" node workloads controller allow
sudo "$(command -v noo)" node workloads controller deny
noo node workloads controller status
```

All of this is **UNVERIFIED**. A node that hosts the controller refuses
workloads (`controller_host`) unless `NOO_ADDON_WORKLOADS_ON_CONTROLLER=1`.

### Placement

The operator places a workload on one node. The node is explicit; the add-on
does not choose it.

```sh
noo cluster workloads
noo cluster workloads place gpu-node-1 example-addon/worker --profile int8 --set main=example-set@rev1 --env EXAMPLE_ADDON_SLOTS=1
noo cluster workloads show gpu-node-1 example-addon/worker
noo cluster workloads unplace gpu-node-1 example-addon/worker
```

**UNVERIFIED.** Placement checks the node before it writes the row. A node can
be refused for: not Linux (`door_unreachable`), the wrong CPU architecture
(`arch_mismatch`), no NVIDIA runtime (`nvidia_runtime_missing`), the driver
cannot grant `compute,utility` (`driver_caps_missing`), GPU compute capability
below the set's `min_compute` (`compute_cap_low`), not enough disk (`disk`),
consent (`consent_none`, `consent_unapproved`), or being the controller host
(`controller_host`). The gateway and the agent use the same codes.

At enable and upgrade, the CLI pulls each workload image by digest and saves it
to the rail as a tar plus an image-id sidecar. Nodes fetch the tar and refuse it
unless it loads as exactly one image with the recorded id
(`image_digest_mismatch`). In this phase the controller is the root of trust
for that id; the node cannot check it against your signed lock.

### Reserve, run and release

**UNVERIFIED.** A reservation sets the row to `running` and starts the worker.
The add-on may reserve and release its own placed workload for a person (with
the task-delegation token and `noo addons set example-addon --delegate tasks`).
Release order: the gateway calls your `service_drain` route and waits, the row
returns to `provisioned`, then the agent drains the worker (POST `drain.path`,
poll `drain.done_path` every 2 s, all within `drain.timeout_secs`), stops it,
and recreates it fresh and stopped. A drain that times out leaves the worker
running as `needs_attention` (`drain_timeout`); a live session is never cut.
While a row is `draining`, the gateway answers 409 to a new session. Your
`drain.path` must be idempotent, and `drain.done_path` must answer 200 only when
it is safe to stop.

### The door

**UNVERIFIED.** The worker has no network of its own and no egress. Each
workload gets one internal Docker bridge, `noo-wl-<addon>-<workload>`, with a
door container (stunnel) on it. The worker joins the door's network namespace
and listens on `127.0.0.1:<port>`. Only the node agent talks to the door: it
presents its own node certificate and the door admits exactly that one name. The
agent relays the gateway's calls to the worker. It forwards exactly three
headers (`X-Noo-Reservation`, `X-Noo-Requester-Sub`, `X-Noo-Requester-Role`),
strips client copies of them, and strips `Origin`, `Authorization` and `Cookie`.
The worker holds no credential and no user token. The door certificate is issued
per node and per enabled add-on at provision time, so after enabling an
add-on with node workloads run `noo upgrade --nodes`; until then the agent
reports `door_leaf_missing`.

> **Note.** Earlier design notes describe the door as published on loopback.
> The code uses an internal bridge, because Docker cannot publish a port from an
> internal network. The door is reachable by processes on the node's host that
> hold a certificate for the agent's name, not only by loopback.

### The worker container

**UNVERIFIED.** The agent creates the worker from the recorded image id with:
a read-only root filesystem; all capabilities dropped and `no-new-privileges`;
no host namespaces, no privileged mode; only the verified model sets (read-only)
and the declared scratch mounted; memory, CPU and pid limits from `limits`;
`HF_HUB_OFFLINE=1` and `TRANSFORMERS_OFFLINE=1`; restart policy `no`. If your
worker loads pickled tensors, load them with `weights_only=True`; core verifies
bytes, not what a pickle does.

### The GPU

`accel.gpu` is the number of GPUs (0-8). With `gpu > 0` the agent adds an NVIDIA
device request with `compute,utility` driver capabilities. Until per-GPU leases
exist, a workload gets GPU indices `0..gpu-1`, and the reservation holds the
node's GPUs while it runs (**UNVERIFIED**). `accel.realtime` says the workload
needs a profile that is realtime-capable. `accel.slots_env` optionally names one
of your own integer-bounded env keys; placement sizes VRAM as the profile's
`vram_mb` plus `per_slot_vram_mb` times the placed value.

---

## 7. Model sets

A model set is a named, versioned directory of weight and notice files with a
signed manifest (`model-set.json`, format `noo-model-set/1`). Your workload
declares model **slots**; the operator chooses a set for each slot at
placement. The controller stages and signs sets. Nodes fetch and verify them.
The schema is
[`noo-model-set-1.schema.json`](../reference/noo-model-set-1.schema.json).

**All of this section is UNVERIFIED on a live install.**

### Slots in your declaration

`models[]` entries are `{slot, target, accepts {kind, runtime?}, many?,
optional?}`. A `many: false` slot mounts its one set read-only at `target`; a
`many: true` slot mounts each set at `<target>/<set id>`. `kind` is `voice` or
`voice-pack`; a `voice-pack` set declares `fits` (a model, a model and
revision, or a runtime).

### Stage

```sh
noo security secrets rotate HF_TOKEN --prompt
noo models stage hf:example-org/example-model@<40-hex-commit> --kind voice --id example-set --modality speech-to-speech --runtime example-runtime --needs ./needs.json --license <spdx-id> --license-url https://example.org/license
```

- The only source is an **authenticated Hugging Face fetch of a pinned
  40-hex commit**, using the controller's `HF_TOKEN` (stored with `noo security
  secrets rotate HF_TOKEN --prompt`; the token is read, never put on a command
  line, never written to the manifest or output). Gated repos redact file
  digests from anonymous callers, which is why the fetch is authenticated.
  There is no local-directory source.
- `--needs` is a JSON file holding `profiles`, `cpu_fallback` and `arch`.
- `--file <path>` chooses files (up to 64 in a set); otherwise every file of the
  commit is taken.
- `--extract <archive>[:<glob>]` extracts members from one archive of the same
  repo and commit, on the controller. Each member becomes an ordinary file with
  its own hash. Regular files only, with size caps enforced while streaming;
  nothing is renamed, and nothing is left behind on refusal. Nodes never see the
  archive.
- `--license-additional <id>=<url>[,<notice path>]` records a second attribution
  the upstream requires. `--fits-model`, `--fits-revision` and `--fits-runtime`
  set `fits` for a `voice-pack`.
- The manifest is validated, then signed with the fleet signing key (ECDSA
  P-384 over SHA-256, detached `model-set.json.sig`, written last). A set with
  no signature does not exist to `noo models list --kind`.

### Licence acceptance

If the licence needs the operator's acceptance, stage refuses until it is
recorded. Accept on the Hugging Face account behind `HF_TOKEN` first, then:

```sh
noo models accept example-set
noo models accept hf:example-org/example-model@<40-hex-commit>
```

The first form accepts one staged set; the second accepts every set staged from
that gated repo at that commit. `--accept-license` on `stage` records it in the
same step. The acceptance (who, when) is written into the signed manifest.

### List and remove

```sh
noo models list --kind voice
noo models rm example-set@<revision> --force
```

`rm` refuses without `--force` because it cannot yet check whether a node still
places the set.

### Place

A set is placed by naming it in a workload placement, not by a separate verb:

```sh
noo cluster workloads place gpu-node-1 example-addon/worker --profile int8 --set main=example-set@<revision>
```

`--profile` must name a profile in the main set's `needs.profiles`, and is
required when the main slot has a set (`profile_invalid` otherwise). A
non-optional slot needs at least one set; a `many: false` slot takes at most one.

### What a node fetches and verifies

A staged set lives on the controller at `<MODELS_DIR>/sets/<id>/<revision>/`.
For a set named in its desired config, a node:

1. Fetches the signed manifest over the mTLS rail
   (`GET /api/artifacts/manifest/modelset/<id>@<revision>`).
2. Verifies the signature with `/etc/noo/pki/signing.pub` **before parsing**.
   A node without that key reports `set_unverified`.
3. Validates the manifest, then fetches each file (resumable) and checks its
   byte count and sha256 against the manifest. The signature covers the files.
4. Marks the set verified. Only verified sets are mounted, read-only, into the
   worker. A set still being fetched leaves the row pending, not refused.

The node needs free disk for the set plus scratch (`disk`). A node keeps the
retired signing keys it has seen, so a key rotation does not strand a set.

---

## 8. What core refuses, and why

Codes below are taken from the validators in `dev`. Refusals from the overlay
guards are sentences, not codes, so they are summarised by cause. A refusal at
enable changes nothing.

### Add-on lock and enable

| Code or message | Cause | Fix |
|---|---|---|
| `NoOverlay` | A v2 lock lists no `docker-compose.yml` | Sign the overlay with `--file docker-compose.yml=...` |
| `NotCanonical` | The lock bytes were re-serialised | Use the file `sign` wrote, unchanged |
| `BadSignature` | Not signed by a trusted key | Operator: `noo addons trust-key`. Author: sign with the published key |
| `DevKeyExpired` | Only a development key signed it, and it has expired | Re-trust a new dev key, or sign with the release key |
| `EmptySupports`, `BadStackTag` | `--supports` empty or not `vX.Y.Z[-rc.N]` | Fix `--supports`; no `stack-` prefix |
| `BadVersion`, `BadSourceCommit` | Version not semver, commit not 40 hex | Fix the flag |
| `NotDigestRef`, `BadDigest` | An image is not `repo@sha256:<64 hex>` | Pin by digest, no tag |
| `OutsideRegistry` | An image is not under the trusted root | Publish the image under the root you sign |
| `BaseMismatch`, `NoStackLock`, `BaseRowMissing` | The `--base` digest does not match the stack's signed lock | Rebuild on the stack's image; check the stack lock |
| `FilesFormat`, `BadFileName`, `FileMismatch` | A v1 lock carrying files, a bad file name, or a file that is missing, extra or does not hash to the lock | Re-sign with exactly the files you publish |
| `AddonMismatch` | The lock is for another name | Sign with `--addon` equal to the name |
| `NotForStack` | The lock does not list the operator's stack | Re-sign with that stack in `--supports` |
| `Downgrade` | Older version than the pin | `--allow-downgrade`, or publish a newer version |
| `Unbundled` | A v1 lock with no bundle | Re-sign as a v2 bundle |
| `Untrusted` | No key trusted for this name | `noo addons trust-key` |
| `Fetch` (access refused) | 401/403 from the registry (see section 5) | `registry-login`, or check the tag exists |
| Name collision (sentence) | The name, or a derived name, is core's | Choose another name |
| Secret not your own (sentence) | The overlay uses a secret that is not one of yours | Use only your own secrets |
| Host access (sentence) | The overlay bind-mounts the host, adds devices or capabilities, uses `extends:` or core volumes | Remove it; use declared mounts and your own volumes |

### `node-workloads.json`

`bad_json`, `duplicate_key` (at any depth), `unknown_field`, `field_type` (a JSON
null is refused except where listed nullable), `field_missing`, `bad_format`,
`workloads_invalid`, `name_duplicate`, `image_not_in_lock`, `uid_invalid`,
`command_invalid`, `port_invalid`, `protocols_invalid`, `health_invalid`,
`drain_invalid`, `limits_invalid`, `model_slot_invalid` and `env_bound_invalid`
mean the file or field is not the shape in the schema; fix it there. The rest:

| Code | Cause | Fix |
|---|---|---|
| `door_name_invalid` | Add-on or workload name has `_`, upper case, or a leading or trailing `-` | Lowercase letters, digits and `-` only |
| `door_name_too_long` | `len(addon) + 1 + len(workload)` is over 51 | Shorten a name |
| `service_drain_invalid` | `service_drain.route` is missing, not a route name, not in `routes.json`, or not `internal` | Declare an internal drain route and name it |
| `accel_invalid` | `slots_env` names an undeclared key, or one without an integer bound | Declare the env key with `min`/`max` |
| `env_key_outside_prefix` | An env key does not start with `<ADDON_UPPER>_` | Add the prefix |
| `env_key_refused_prefix` | An env key starts with `NOO_`, `NVIDIA_`, `CUDA_`, `LD_`, `PYTHON`, `HF_` or `TRANSFORMERS_` | Rename it |
| `scratch_target_refused` | A scratch target is `/`, `/proc`, `/sys`, `/dev` or below them | Use another path |
| `scratch_invalid` | More than 4 entries; bad size; targets repeat or nest; more than one `exec`; `exec` over 1024 MiB | Declare sibling targets; one exec entry at most 1024 MiB |
| `scratch_in_model_slot` | A scratch target overlaps a model slot target | Move one |

### `model-set.json`

`bad_json`, `unknown_field`, `field_type`, `field_missing`, `bad_format`,
`id_invalid`, `revision_invalid`, `kind_invalid`, `modality_invalid`,
`runtime_invalid`, `path_invalid`, `sha256_invalid`, `files_invalid` and
`arch_invalid` are shape errors. The rest:

| Code | Cause | Fix |
|---|---|---|
| `source_invalid`, `license_invalid` | Source or licence block malformed | Fix at `noo models stage` |
| `notice_not_in_files` | A `notice_files` or `notice_path` is not a `role: notice` file of the set | Include the notice file |
| `profile_invalid` | A needs profile is malformed | Fix `--needs` |
| `fits_required`, `fits_forbidden`, `fits_invalid` | A `voice-pack` lacks `fits`, a `voice` has it, or it is malformed | Fix the `--fits-*` flags |
| `trust_required`, `trust_invalid` | Digests were not authenticated and no `trust` was recorded | Use the authenticated fetch |
| `from_archive_invalid` | A `from_archive` entry is malformed | Fix `--extract` |

### Node and placement reasons (what the agent reports)

| Reason | Cause | Fix |
|---|---|---|
| `consent_none` | The node's policy is `none` | Only the node's owner can change it |
| `consent_unapproved` | Policy `approve`, this add-on and digest not approved | `sudo "$(command -v noo)" node workloads approve example-addon <digest>` on the node |
| `door_leaf_missing` | The door certificate is not on the node yet | `noo upgrade --nodes` |
| `door_unreachable` | The node is not Linux | Place on a Linux node |
| `image_missing`, `image_digest_mismatch` | The image tar is missing or malformed, or does not load as exactly the recorded image | Re-enable or upgrade the add-on; re-stage |
| `set_missing`, `set_slot_invalid`, `set_unverified`, `profile_invalid` | Slot has no set, wrong slot, signature or hash failed, or the profile is not valid for the set | Fix the placement; re-stage the set; check `signing.pub` |
| `disk` | Not enough free space | Free space on the node |
| `nvidia_runtime_missing`, `driver_caps_missing`, `compute_cap_low`, `arch_mismatch` | The node cannot run the workload | Install the toolkit or place elsewhere |
| `controller_host` | The node hosts the controller | Opt in with `NOO_ADDON_WORKLOADS_ON_CONTROLLER=1`, or place elsewhere |
| `env_out_of_bounds` | An env key is undeclared or out of its bound | Fix the placement's `--env` |
| `container_conflict` | A container with the workload's name was not made by the agent | Remove it by hand |
| `start_timeout`, `crashed`, `drain_timeout` | Not ready in `start_secs`; exited; drain did not finish | Read the worker's logs; raise `start_secs`; wait |

The reasons list also has `decl_invalid`, `desired_invalid` and `admit_invalid`;
the last two indicate version skew between controller and node.

---

## 9. Pain points from the first add-on author

TODO: this section is a placeholder. Input is being collected from the first
add-on author and has not been added yet. Do not treat the absence of an entry
as meaning the path is smooth.

---

## 10. Worked example

A complete worked example add-on lives in that add-on's own repository, not in
core: core never names a real add-on. Look for the worked example linked from
the add-on registry listing. TODO: link it here, by a generic description, when
the example's document merges in its own repository.

Everything about running a third-party add-on that has not yet been seen
working on a live install is marked **UNVERIFIED** in sections 6 and 7. When the
first end-to-end run happens, those tags are what get finalised.
