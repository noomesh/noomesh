# Node workloads and model sets: the contract

This is the contract for an add-on's **node workload** (a container core builds
from a closed declaration and places on a capable node) and for the **model
set** it mounts. It is the F1 piece of i300; nothing here starts a container.
The CLI, the gateway and the node agent each validate against the same
fixtures, and the agent does not trust the other two.

| Artifact | Format | Schema | Fixtures |
|---|---|---|---|
| A model set's manifest, `model-set.json` | `noo-model-set/1` | [`noo-model-set-1.schema.json`](noo-model-set-1.schema.json) | `tests/fixtures/i300/model-sets/` |
| An add-on's `node-workloads.json` | `noo-addon-node-workloads/1` | [`noo-addon-node-workloads-1.schema.json`](noo-addon-node-workloads-1.schema.json) | `tests/fixtures/i300/node-workloads/` |
| The `node_workloads` key of desired-config | (this document) | none | `tests/fixtures/i300/desired/`, `desired-node-workloads.json` |
| The new heartbeat keys | (this document) | none | `heartbeat-i300.json` |

Each fixture directory has a `cases.json`: `[{file, valid, code}]`, plus an
optional `addon` (the add-on name the validator is told; default `rhaddon`).
`code` is the stable refusal code a file must produce, and `""` for a valid
file. A schema states the shape; the rules it cannot state (anything needing
the lock, the add-on's name, or two values compared) are in its `x-noo-rules`.
An unknown field is refused everywhere.

Every validator refuses duplicate object keys, at any depth (code `duplicate_key`): Go keeps the last value and `serde_json` refuses the repeat, so a document must not be readable two ways. The CLI and gateway validators must match this.

JSON null is refused on every field except those named nullable (today: `reservation`); every validator must match. The code is `field_type`, also in desired-config (where a type error elsewhere is `desired_invalid`). Go's decoder reads a null on a non-pointer field as a no-op that keeps the zero value (`"accel": {"gpu": null}` reads as 0), while `serde` refuses it, so the null must be refused on the raw tokens before any typed decode. The list is the table under "Nullable fields".

Core never names a real add-on. The fixture add-on is `rhaddon`, and its
declaration is `tests/fixtures/addons/rhaddon/node-workloads.json`.

## Signing a model set

A model set is signed by the **fleet bundle signing key**, the same key that
signs noo-apply bundles. No new key is designed.

- **Algorithm.** ECDSA on curve P-384. The key is generated as
  `PKCS_ECDSA_P384_SHA384` (`noo-cli/src/pki.rs:232`; the comment at
  `noo-cli/src/pki.rs:283` says the same: "the CA and fleet signing keys are
  P-384"). Signatures are made with `openssl dgst -sha256 -sign`
  (`scripts/sign-bundle.sh:85`) and checked with `openssl dgst -sha256 -verify`
  (`scripts/noo-apply.sh:181`), so the signature is **ECDSA over the SHA-256
  digest, DER (ASN.1) encoded**. In Go that is
  `ecdsa.VerifyASN1(pub, sha256.Sum256(bytes), sig)`.
- **The signature is detached**: a file `model-set.json.sig` beside the
  manifest, over the exact bytes of `model-set.json` as stored. It is checked
  before the manifest is parsed. Re-serialising the JSON invalidates it.
- **Where the controller keeps it.** `signing.key` (PKCS#8 PEM, 0600) and
  `signing.pub` (SPKI PEM, 0644) in the controller's PKI directory
  (`noo-cli/src/pki.rs:190` and `:197`).
- **Where a node keeps the public half.** The `signing-pub` bundle kind is
  installed as `signing.pub` in the node's PKI directory,
  `/etc/noo/pki/signing.pub` (`scripts/noo-apply.sh:64` for the directory,
  `:173` where the verifier reads it, `:833` where the bundle installs it,
  mode 644, `root:noo-agent`). A node that holds no `signing.pub` cannot verify
  a set and reports `set_unverified`. Key rotation is the existing
  `noo security pki rotate-signing-key` path; a set signed under a retired key
  is re-signed by the controller, and the node accepts any key it retains.

## The model set (`noo-model-set/1`)

Fields: `id`, `revision`, `kind` (`voice` | `voice-pack`), `modality`
(`speech-to-speech` | `stt` | `tts`), `runtime[]`, `source`, `license`,
`files`, `needs`, and `fits` (voice-pack only). See the schema for each bound.

- **`source`** is `{"hf": {repo, ref, digests}}` or `{"local": {verified}}`.
  `ref` is a 40-hex commit. `digests` records whether upstream digests were
  authenticated: `authenticated`, or `operator-trusted-local` (HF redacts LFS
  digests on gated repos for anonymous callers, so the operator supplied or
  accepted them). `trust: {by, at, reason}` is **required** when `digests` is
  `operator-trusted-local` or `local.verified` is false.
- **`license`** is `{id, url, accept: none|operator, accepted?: {by, at},
  notice_files?, additional?}`. `notice_files` are paths that must appear in
  `files`; `additional` is `[{id, url}]` for a second attribution upstream
  requires.
- **`files`** are `{path, bytes, sha256, role?}`. `role` is `weights` (the
  default), `notice` or `config`; notice and config files are staged and
  verified like any file but are not what the worker loads. `sha256` is 64
  lower-case hex.
- **File path rule**: relative, no `.` or `..` component, **at most one
  directory level**, charset `[A-Za-z0-9._-]`. The rail's path check, the
  node's fetch and the mount check all use this one rule
  (`nodewl.ValidSetPath`).
- **`needs`** is `{profiles[{name, accel, min_compute?, vram_mb?, ram_mb?,
  per_slot_vram_mb?, realtime?}], cpu_fallback, arch[]}`.
- **`fits`** is `{model}`, `{model, revision}` (a pack pinned to one revision of
  one model) or `{runtime}`. It is required for `voice-pack` and forbidden for
  `voice`.

### Archive members and license notices

- A `files[]` entry may carry `from_archive: {path, sha256, bytes}`: the file
  was extracted by the **controller, at staging**, from an archive. `path`
  follows the set path rule; `sha256` is 64 lower-case hex; `bytes` is at
  least 1. The archive must come from the **same upstream repo and revision**
  as the set (the CLI enforces it). A file may not carry both `from_archive`
  and `role: notice`. A shape error is `from_archive_invalid`. Nodes only ever
  see flat, verified files, never the archive.
- `license.additional` entries are `{id, url, notice_path?}`. A `notice_path`
  must name a file of `files` whose `role` is `notice`
  (`notice_not_in_files` otherwise).

Extraction rules, for the CLI side (the controller extracts; a node never
does):

- Caps are enforced **while decompressing** (streaming), per member and in
  total, as named constants, not after the fact.
- Only regular files are extracted. No links, devices, FIFOs, sparse entries
  or long-link entries.
- A directory entry is skipped: nothing is created for it, and its mode and
  owner are never applied. It still counts toward the entry cap and passes the
  same name checks (a trailing `/` aside). A directory entry with a non-zero
  size is refused.
- A member the glob does not select is not extracted, but it still counts
  toward the entry and byte caps and passes the same type and name checks.
- Member names are kept as the archive spells them (`voices/NATF0.pt` stays
  `voices/NATF0.pt`), so every selected name must itself be a valid set path.
  Nothing is renamed, so two members can never collide after a rename.
- No duplicate member names, and no name changed by normalisation.
- Extract to a temp directory, and rename into the set only after **every**
  member has passed.

The worker, not core, must load pickled tensors safely
(`weights_only=True`); core verifies bytes, not what a pickle does.

### Rail delivery

A staged set lives at `<MODELS_DIR>/sets/<id>/<revision>/` on the controller
(files, then `model-set.json`, then `model-set.json.sig` last). A set without
its signature does not exist to the rail. A node gets a set in two steps, both
over the mTLS rail.

1. **The signed manifest**, from the gateway (same auth as every artifact
   manifest, a node's cluster bearer):

   `GET /api/artifacts/manifest/modelset/<id>@<revision>`

   ```json
   {
     "kind": "modelset",
     "name": "<id>@<revision>",
     "id": "<id>",
     "revision": "<revision>",
     "manifest_b64": "<standard base64 of the exact bytes of model-set.json>",
     "sig_b64": "<standard base64 of the exact bytes of model-set.json.sig>",
     "key": "fleet-signing",
     "data_path": "/sets/<id>/<revision>"
   }
   ```

   The manifest travels as base64, never as embedded JSON, because the
   signature is over the stored bytes and re-serialising would break it. The
   node decodes both, verifies the signature (see "Signing a model set")
   **before parsing**, then validates the manifest. `<id>` and `<revision>` are
   checked against the schema's patterns (400 on a miss). 404: no such set, or
   no signature. The gateway checks only the shape: the manifest parses as
   JSON and its `id` and `revision` equal the request's (a mismatch is a 500,
   a staging fault). It does not verify the signature and does not run the full
   contract validator; the node does both.

2. **The files**, from the model cache: each `files[].path` of the verified
   manifest at `GET <data_path>/<path>` (`/sets/<id>/<revision>/<path>`),
   resumable with `Range`. The node checks each file's byte count and sha256
   against the manifest. There is no per-file hashing route: unlike a `gguf`,
   whose digest only the gateway states, every set file's digest is already
   inside the signed manifest, so the signature covers the files.

   The model cache serves only `/sets/<id>/<revision>/<file>` and
   `/sets/<id>/<revision>/<dir>/<file>`. It refuses (404) a `.` or `..`
   component, any other depth, a name outside the schema charset, a `.part`
   file, and `model-set.json` and `model-set.json.sig` themselves: the manifest
   has one source, the gateway route. Directory listing is off.

## The declaration (`noo-addon-node-workloads/1`)

One file, listed in the signed bundle lock beside `resources.json`. Per
workload: `name`, `image`, `uid` (at least 1), `command?`, `port`
(1024-65535), `protocols` (a subset of `http`, `ws`), `health {ready, live,
start_secs 1-600}`, `drain {path, done_path, timeout_secs 1-3600}`, `service_drain
{route, timeout_secs 1-3600}` (required), `accel {gpu 0-8, slots_env?,
realtime}`, `models[]`, `env`, `scratch[]` and `limits {ram_mb, cpus, pids}`
(required).

- `image` is a **name** in the lock's `images` map (`noo-addon-lock/2`), never a
  ref. The digest comes from the lock. The cross-file rule is in `x-noo-rules`.
- `models[]` declares slots: `{slot, target, accepts {kind, runtime?}, many?,
  optional?}`. The operator or a class picks the set for each slot. A
  `many: false` slot mounts its one set read-only at `target`; a `many: true`
  slot mounts each set at `<target>/<set id>`.
- `env` is `{KEY: {min?, max?} | {one_of: [...]}}`. Keys start with
  `<ADDON_UPPER>_` (the add-on name upper-cased, `-` as `_`). These prefixes
  are refused whatever the add-on is called: `NOO_`, `NVIDIA_`, `CUDA_`, `LD_`,
  `PYTHON`, `HF_`, `TRANSFORMERS_`. Values are **strings** in desired-config;
  an integer bound takes a base-10 integer string (no sign but `-`), an enum
  takes one of its members, and a fixed boolean is `{"one_of": ["false"]}`.
- `scratch[]` is `{target, max_mb}` (a size-capped volume the agent owns) or
  `{target, tmpfs_mb}`. The target is not `/`, `/proc`, `/sys` or `/dev` (or
  below them), and not equal to, inside or around a model slot target.
- A scratch entry may add `exec` (boolean, default `false`). **At most one**
  entry may be `exec: true`, and its size (`max_mb` or `tmpfs_mb`) is at most
  **1024 MiB** (512 MiB is the recommendation; the size is required as for any
  scratch, there is no default). It is for a worker that compiles and loads
  native code (Triton writes a `.so` into its cache dir and dlopens it). The
  exec entry is mounted `nosuid,nodev` WITHOUT `noexec`, owned by the worker's
  uid with mode 0700, and is tmpfs-backed (for both kinds), so it is empty at
  every container start and is charged to the worker's memory limit. Every
  other scratch keeps `nosuid,nodev,noexec`; the read-only rootfs, read-only
  model mounts, dropped capabilities and no network are unchanged. The flag is
  in the signed file, so it is part of what the operator approves, and
  `noo addons check` names the exec scratch. Two exec entries, or one over the
  cap, are `scratch_invalid`; a non-boolean `exec` is `field_type`.

### The door name

The door's DNS SAN is `noo-stunnel-<addon>-<workload>`, which must be one DNS
label of at most 63 characters. So **a node workload is refused when
`len(addon) + 1 + len(workload) > 51`** (`door_name_too_long`), and both the
workload name and the add-on name must be lower-case letters, digits and `-`,
starting and ending with a letter or digit (the `name` pattern in the
node-workloads schema; `door_name_invalid`): `_`, upper case and a leading or
trailing `-` are
refused. `_` is **not** mapped to `-`: a per-file validator cannot see a
collision between two add-ons. The fixtures pin 51 (valid) and 52 (refused),
by workload name and by add-on name.

## The desired-config entry (`node_workloads`)

Separate from the existing `addon_workloads` key. One row per
(add-on, workload) the node must hold:

```json
{"addon": "rhaddon", "name": "worker",
 "decl": { "...": "the validated workload object, verbatim" },
 "image": {"name": "addon-worker", "digest": "sha256:<64 hex>",
           "id": "sha256:<64 hex>",
           "artifact": "noo-addon-wl_rhaddon_addon-worker_<64 hex>_amd64.tar"},
 "sets": {"main": [{"id": "...", "revision": "..."}]},
 "profile": "int8",
 "env": {"RHADDON_SLOTS": "1"},
 "door": {"leaf": "svc-addon-rhaddon-worker", "admit": ["<this node's agent CN>"]},
 "start_secs": 300,
 "drain": {"path": "/v1/lifecycle/drain", "timeout_secs": 420},
 "reservation": "<canonical lower-case UUID>" ,
 "state": "provisioned"}
```

`profile` names the load profile of the **main slot's** set (the first declared
model slot): it is required when that slot has a set, and it must name one of
that set's `needs.profiles`. `ParseDesired` cannot see the set manifest, so it
checks the shape only (a non-empty lower-case word); `nodewl.CheckProfile(entry,
mainSet)` then refuses (`profile_invalid`) a profile that is missing or not
listed by the set, or one with `realtime: false` when the decl's
`accel.realtime` is true (a profile that does not state `realtime` counts as
realtime-capable). An entry whose decl has no model slot carries no profile.

`reservation` is a canonical **lower-case** UUID string or `null` (the gateway
mints ids with `Uuid::new_v4().to_string()`,
`gateway-rust/src/routes/reservations.rs:345`, which is lower-case canonical;
an upper-case or non-UUID id is `desired_invalid`). `start_secs` and
`drain` equal the decl's. `image.name` equals `decl.image`. `door.leaf` is
`svc-addon-<addon>-<name>`. `sets` keys are declared slots, a non-optional slot
has at least one set, and a `many: false` slot has at most one (not checked for
`absent`). The agent re-checks `env` against the decl's bounds; a key the decl
does not declare is out of bounds.

### The image: digest, id and artifact

The lock digest is the **registry manifest digest**; a docker image ID is the
**config digest**, and a classic `docker save` drops RepoDigests, so a node
cannot check a loaded tar against the lock digest. `image` is therefore
`{name, digest, id, artifact}`:

- `digest`: `sha256:` and 64 lower-case hex, from the verified lock. **Record
  only** on the node.
- `id`: `sha256:` and 64 lower-case hex, the image ID the CLI recorded after
  its digest-verified pull (the `.imageid` sidecar).
- `artifact`: the rail name of the staged tar,
  `noo-addon-wl_<addon>_<image name>_<64 hex>_<arch>.tar`, where the 64 hex
  equal the hex of `digest`, `<addon>` and `<image name>` equal the entry's
  `addon` and `image.name`, and `<arch>` is `amd64` or `arm64`.

`ParseDesired` refuses any violation, and a malformed `digest`, with
`image_missing`. Matching `<arch>` against the node's own arch is a runtime
check, F5's job, reported as `arch_mismatch`.

Node rules (enforced in F5):

- The worker is created from `image.id`, never from a tag or a repo name.
- Loading the tar must yield **exactly one** image, and its ID must equal
  `image.id`. Anything else is `image_digest_mismatch`.
- Only the CLI writes the `.imageid` sidecar, at staging. The gateway only
  reads it, when it builds the entry, and never caches it across a restage. A
  changed ID changes the entry, so the agent reprovisions.

**Trust boundary.** In phase 2 the controller is the root of trust for the
image, the same as it is for the tar's rail sha256: the node trusts the
`id` the controller names and checks the tar against it, but cannot check the
id against the add-on's signed lock. Phase 3's node-side lock-signature check
closes that gap.

### Door and amendments

- **A1.** The door leaf `svc-addon-<addon>-<workload>` is CLI-issued per (node,
  enabled add-on node workload) in the provision bundle. If it is missing the
  agent refuses with `door_leaf_missing`.
- **A2.** The node agent is the **only** door client. It dials the door with
  its own node leaf. The door is on the workload's private, internal network
  (see "Door network": it is not published, because Docker cannot publish from
  such a network) and pins exactly this node's agent CN. `door.admit` must be
  exactly `[<own agent CN>]`; anything else is `admit_invalid`. The agent picks
  `door_port` (today the fixed `8443`, inside the door's own namespace) and
  reports it.
- **A3.** The entry above, with the state machine below.
- **A4.** The heartbeat keys below.

### Door network

A workload gets **no egress**, and its door must still be reachable by the
agent, a host process. Docker cannot publish a port from a container that is
attached only to an `internal: true` network (the publish is accepted and
ignored: `docker port` lists nothing), so publishing on `127.0.0.1` and
blocking egress separately would need a firewall rule, which is a new
privilege. The design that needs none:

- **One internal bridge network per workload**, `noo-wl-<addon>-<workload>`,
  created with `internal: true` and the label `noo.managed-by=agent`. Docker
  installs no route and no NAT out of it.
- The **door sidecar** `noo-stunnel-<addon>-<workload>` is attached to it and
  to nothing else. The **worker** has no network of its own: it joins the
  sidecar's network namespace (`network_mode: container:noo-stunnel-...`) and
  listens on `127.0.0.1:<decl.port>`. The worker therefore has exactly the
  sidecar's reach: its private network and nothing beyond.
- The door **accepts on the sidecar's address on that network** (port
  `door_port`) and connects to `127.0.0.1:<decl.port>` inside the shared
  namespace. The agent dials that address. The host holds the bridge's
  gateway address on an internal network (Docker 29.2.1 checked), so a host
  process reaches the sidecar and nothing outside the host or the network can.
- The address is **per container and changes on recreate**: the agent reads it
  from the daemon on every dial (`DoorAddr`) and never caches it.

Evidence (Docker 29.2.1, Linux, a throwaway `--internal` network and an
Ubuntu container): a host TCP connect to the container's address on the
network succeeded; a connect from inside the container to `1.1.1.1:443` failed
with "Network is unreachable"; a container on the default bridge timed out
connecting to it; `-p 127.0.0.1::9000` on the internal network published
nothing.

Limits, stated: the door is reachable by the **host** (any local process that
holds a cluster-CA client cert with the agent's CN can complete the handshake;
without one, stunnel refuses it), not by "loopback only". The contract's
earlier wording, "published on loopback", described the macOS Docker Desktop
shape, where a VM's bridge addresses are not routable from the host and an
internal network cannot be published: on a non-Linux host the agent refuses to
provision with `door_unreachable` rather than weaken the no-egress rule. Each
workload takes one address pool slot (Docker's default pools allow about 30
networks); the bound on how many workloads one node holds is the placement's.

### The worker container

The agent creates the worker with exactly this and nothing more.

| Property | Value |
|---|---|
| Image | `image.id`, never a tag |
| User | `decl.uid`; uid 0 and the agent's own uid are refused (`decl_invalid`, inner `uid_is_agent`) |
| Root filesystem | read-only |
| Capabilities | `CapDrop: [ALL]`, no `CapAdd`, `no-new-privileges` |
| Namespaces | no host pid, ipc, uts or user namespace; not privileged; no `Devices` beyond the GPU request |
| Mounts | the verified sets, read-only, at each slot's `target` (`<target>/<set id>` for a `many` slot); the declared scratch. No host binds besides the sets, no docker socket, no PKI, no data root, no `/etc/noo` |
| Scratch | `tmpfs_mb`: a tmpfs of that size. `max_mb`: a per-workload named volume of the local driver backed by a tmpfs of that size (`size=<max_mb>m`, owned by `decl.uid`). Both `nosuid,nodev,noexec` |
| GPU | `accel.gpu > 0`: a `nvidia` device request, `NVIDIA_DRIVER_CAPABILITIES=compute,utility`, `NVIDIA_VISIBLE_DEVICES` pinned (below) |
| Env | the entry's declared keys; `<ADDON_UPPER>_MODEL_<SLOT_UPPER>_ID` and `_REVISION` per placed slot (comma-separated for a `many` slot); `HF_HUB_OFFLINE=1`; `TRANSFORMERS_OFFLINE=1`. Nothing else. A declared key that collides with one the agent sets is `env_out_of_bounds` |
| Limits | memory `limits.ram_mb` (swap equal to memory, so none), `limits.cpus`, `limits.pids` |
| Restart | `no` |
| Labels | `noo.addon`, `noo.workload`, `noo.managed-by=agent`, `noo.role`, `noo.spec.hash`, and `noo.reservation` when set |

Only `.verified` sets are bound (a set the agent has not verified is
`set_unverified`, one it does not hold is `set_missing`, one still being
fetched is not a refusal: the row stays pending).

- **Scratch size.** Docker's local volume driver cannot cap a volume's size
  (the `size` option needs an xfs project quota the agent cannot assume), so a
  `max_mb` volume is a tmpfs-backed volume with `size=<max_mb>m`. The cap is
  real; the gap is that the space is **memory**, charged to the worker's own
  cgroup, so a workload that declares more scratch than `limits.ram_mb` is
  bounded by the RAM limit instead. A disk-backed cap needs xfs quotas and is
  not built. Scratch is thrown away at release and at recreate.
- **GPU pinning.** Until the lease (F5b) names a device, the workload is
  pinned to GPU indices `0..gpu-1`: the request is `Count: gpu` and
  `NVIDIA_VISIBLE_DEVICES` states the same indices. When the lease supplies
  devices (an index or a UUID) the request carries those `DeviceIDs` and the
  same value goes in `NVIDIA_VISIBLE_DEVICES`. Docker refuses `Count` and
  `DeviceIDs` together, so it is one or the other. Setting
  `NVIDIA_VISIBLE_DEVICES` from a placement is refused by the env-prefix rule.
- **The door sidecar** is root with `CapDrop: [ALL]` and `DAC_OVERRIDE` only
  (to read the 0600 leaf key), a read-only root, `no-new-privileges`, 128 MiB
  and 64 pids. It is the only container the leaf is mounted into
  (`svc-addon-<addon>-<workload>.{crt,key}` from the node PKI directory, plus
  `ca.crt`). Its stunnel config requires a client certificate from the cluster
  CA (`verify = 2`) and carries exactly one `checkHost`, the entry's
  `door.admit[0]`, so a certificate from the same CA with any other name is
  refused at the handshake.
- **Recreate.** One spec hash (the image, the door image and conf, the leaf's
  fingerprint, the sets, the env, the limits, the labels) is stored on both
  containers. A matching pair is left alone; any change removes both (and the
  scratch volumes) and recreates them stopped. A running worker is never
  recreated by a provision: it returns `ErrWorkerRunning` and the caller
  drains first.
- A container, volume or network with the workload's name that lacks
  `noo.managed-by=agent` is never adopted, changed or removed:
  `container_conflict`.

### Relay rule (the agent is the proxy)

Because the agent is the only door client, it relays the gateway's calls to the
worker. It forwards **exactly three** gateway-set headers, `X-Noo-Reservation`
(a lower-case UUID), `X-Noo-Requester-Sub` and `X-Noo-Requester-Role`, taken
from the gateway's authenticated call. The gateway's constants
(`gateway-rust/src/routes/reservations.rs:569-571`, on origin/dev) are
`PEER_RESERVATION_HEADER = "x-noo-reservation"`,
`PEER_SUB_HEADER = "x-noo-requester-sub"` and
`PEER_ROLE_HEADER = "x-noo-requester-role"`; the agent's list is exactly
those three. It **strips any client-supplied copy** of those
three, and strips `Origin`, `Authorization` and `Cookie`, before the request
reaches the worker. The worker holds no credential and no user token.

The outbound allowlist is exactly: `Content-Type`, `Accept`,
`Sec-WebSocket-Key`, `Sec-WebSocket-Version` and `Sec-WebSocket-Protocol` (the
proxy restores `Connection` and `Upgrade` itself, for a websocket only), plus
the three `x-noo` headers above. Each is present **exactly once**: a duplicate
is a 400. Nothing else is forwarded.

### The worker's drain (`drain`)

`drain` is `{path, done_path, timeout_secs}`; `path` and `done_path` are
absolute paths with the same rules (a missing or invalid one is
`drain_invalid`). The agent drains the worker through the door:

- **POST `path`**: a 2xx means the drain was accepted. The endpoint must be
  idempotent.
- It then **polls GET `done_path` every 2 s**: `200` means drained. Anything
  else means not yet: a non-200 status, a connection error, an unreachable
  door.
- `timeout_secs` bounds the **whole** drain, the POST plus the polling.
- If the worker **exits during the drain**, the agent reports `crashed` and
  recreates the worker fresh and stopped.
- Only a **timeout** leaves the worker running, reported as `needs_attention`
  with reason `drain_timeout`; no live session is cut.

### Slots and `accel.slots_env`

`accel.slots_env` is optional. It names one of the decl's **own** declared env
keys, and that key must have an integer `min` and/or `max` bound, not a
`one_of`; otherwise `accel_invalid`. Placement sizes VRAM as the profile's
`vram_mb` plus `per_slot_vram_mb` times the **placed value** of that key; with
no `slots_env`, slots = 1. The heartbeat row therefore carries no `slots`
(phase 2).

### `service_drain` and the release order

`service_drain` is `{route, timeout_secs}`, required on every workload. `route`
is a route **name** (the route-name rule of `routes.json`, lower-case letters,
digits and `_`, starting with a letter, at most 64) of the add-on's CPU-side
drain endpoint. It is never a path and is never inferred. Cross-file rule: the
route must exist in the add-on's `routes.json` and be marked `internal`;
`timeout_secs` is 1-3600. Any violation is `service_drain_invalid`.

Release order (the i163 order): the gateway first POSTs
`{reservation, workload: "<addon>/<name>", timeout_secs}` through the existing
internal add-on call to the `service_drain` route and waits up to
`timeout_secs + 30` seconds; it then sets the row to `provisioned`, and the
agent then drains the worker (`drain.path`, below).

The agent does not use `service_drain`: it has no `routes.json`, so its
re-check of the decl (inside a desired-config entry) is **shape only**
(present, a route name, `timeout_secs` 1-3600); `ParseDecl` takes the routes
as an input and a nil input skips only the existence and internal check. It is
carried in desired-config only as part of the verbatim `decl`.

## State machine

| State | Meaning |
|---|---|
| `absent` | Nothing of this workload on the node: worker, sidecar and network removed. |
| `provisioned` | Image loaded and its ID equals `image.id`, sets verified, sidecar and worker created **stopped**, on an `internal: true` network. The resting state. |
| `running` | Started. Ready when `health.ready` answers through the door within `start_secs`. |

- `absent` to `provisioned`: load the image tar from the rail, check it yields
  exactly one image whose ID equals `image.id`, verify the sets, create the sidecar and the worker stopped.
- `provisioned` to `running`: start. A worker not ready within `start_secs`
  reports `start_timeout`.
- **Release returns the row to `provisioned`**: drain the worker as described
  under "The worker's drain" (POST `drain.path`, poll `drain.done_path`, all
  within `drain.timeout_secs`), stop, remove the worker and its scratch,
  recreate it fresh and stopped. A drain that does not finish reports
  `drain_timeout` with state `needs_attention` and **never cuts a live
  session**; the worker keeps running. A worker that exits during the drain is
  `crashed` and is recreated fresh and stopped.
- any state to `absent`: remove the worker, sidecar and network.

**Reported states.** The desired states are only `absent`, `provisioned` and
`running`. A heartbeat row may also report two states that never appear in
desired-config (`ParseDesired` refuses `draining` and `needs_attention` with
`desired_invalid`):

| Reported state | Meaning |
|---|---|
| `draining` | From the accepted drain POST until the done poll answers 200 or the drain times out. The gateway proxy answers **409** to a NEW session while the row says `draining` (H4). |
| `needs_attention` | A drain timeout (`drain_timeout`); the worker is left running. |
- A refusal never changes the container: the row reports its last good state
  with a `reason`.

## Nullable fields

The one list every validator copies (the agent's is
`node-agent-go/internal/nodewl/nullable.go`; a test holds the two equal). A
pattern is a JSON pointer relative to the root of that document kind, with `*`
standing for any one array index. A JSON null at any other path is refused with
`field_type`.

| Document | Nullable pointer | Why |
|---|---|---|
| desired-config fragment | `/node_workloads/*/reservation` | a provisioned entry holds no reservation |
| `node-workloads.json` | (none) | |
| `model-set.json` | (none) | |

The heartbeat example never sends a null: an unknown value is omitted.

## Heartbeat keys (A4)

Absent or unknown values are **omitted**, never defaulted: an error must not
become a fact (the i495 rule). A `null` is never sent.

| Key | Type | Notes |
|---|---|---|
| `os` | string | `runtime.GOOS` (`linux`, `darwin`, `windows`); always reported |
| `gpu_compute_cap` | string, `"8.6"` | omitted when unknown. Compared with a set's `min_compute` **numerically as (major, minor)**, never as strings (`"10.0"` is above `"8.0"`, `"8.10"` above `"8.9"`): `nodewl.ComputeCapAtLeast`. A value that does not parse is an error the caller treats as **unknown**, never as low |
| `nvidia_runtime` | bool | the nvidia container runtime is registered |
| `nvidia_driver_caps_ok` | bool | `compute,utility` driver capabilities are usable |
| `controller_host` | bool | this node is the controller's host: the agent's `NOO_SELF_NODE` marker. A workload is refused (`controller_host`) unless `NOO_ADDON_WORKLOADS_ON_CONTROLLER=1` (default off) |
| `data_root_free_gb` | number | omitted when unknown |
| `addon_workloads_policy` | `"none"` / `"approve"` / `"auto"` | the node's consent setting |
| `addon_workloads_approvals` | `[{addon, digest}]` | per add-on and image digest |
| `model_sets` | `[{id, revision, state, reason?}]` | `state` is `verified`, `fetching` or `refused`; `reason` rides `refused` |
| `node_workloads` | `[{addon, name, state, ready, model?, door_port, reservation?, reason?}]` | `state` is a desired state or a reported one (`draining`, `needs_attention`). `model`, `reservation` and `reason` are omitted when unknown or none. There is no `slots` in phase 2 (placement sizes it from `accel.slots_env`) |

`heartbeat-i300.json` is the example.

## Reasons

The agent's fixed vocabulary for the `reason` of a `node_workloads` or
`model_sets` row. A reason is a code, never free text. The same list is in
`node-agent-go/internal/nodewl/reasons.go`, and a test holds the two equal.

| Reason | When | Remedy |
|---|---|---|
| `decl_invalid` | the decl fails the node-workloads rules (the inner refusal code is logged) | fix the add-on's `node-workloads.json` |
| `desired_invalid` | the entry is malformed: unknown field, wrong type, bad state, reservation not a UUID, name or `start_secs`/`drain` differing from the decl, wrong `door.leaf` | a gateway bug or version skew: upgrade the controller |
| `door_leaf_missing` | the door leaf is not available: it is not in the provision bundle yet, or this node's applier predates the `svc-addon-*` leaf kind | re-provision (`noo upgrade --nodes`) |
| `image_missing` | `image` is not `{name, digest, id, artifact}` as above (name, digest, id or artifact absent, malformed or inconsistent), or the tar is not on the rail | re-enable or upgrade the add-on on the controller |
| `image_digest_mismatch` | the tar did not load as exactly one image, or that image's ID differs from `image.id` | re-stage the image; investigate the rail |
| `set_missing` | a required slot has no set | choose a model for the slot |
| `set_slot_invalid` | `sets` names an undeclared slot, several sets for a `many: false` slot, or a malformed id or revision | fix the placement |
| `set_unverified` | a set's signature, hashes or `.verified` marker did not check out | re-stage the set; check the node holds `signing.pub` |
| `profile_invalid` | the entry's `profile` is missing, not one of the main set's profiles, or not realtime-capable for a realtime workload | fix the placement's profile |
| `disk` | the data root lacks space for the set or the scratch plus the margin | free space on the node |
| `consent_none` | the node's `addon_workloads_policy` is `none` | the node's owner sets `approve` or `auto` |
| `consent_unapproved` | policy is `approve` and this add-on and digest are not approved | approve the add-on and digest on the node |
| `nvidia_runtime_missing` | `accel.gpu` > 0 and the nvidia runtime is not registered | install the NVIDIA container toolkit |
| `driver_caps_missing` | the driver cannot grant `compute,utility` | fix the driver or toolkit |
| `compute_cap_low` | the GPU's compute capability is below the set's `min_compute` | place on a newer GPU |
| `arch_mismatch` | the node's arch is not in the set's `needs.arch`, or differs from the `<arch>` of `image.artifact` | place on another node |
| `controller_host` | the node is the controller's host and has not opted in (D4) | opt in for a single-box install, or place elsewhere |
| `admit_invalid` | `door.admit` is not exactly `[<own agent CN>]` | a gateway bug or version skew |
| `env_out_of_bounds` | an env key is undeclared or its value is outside the decl's bound | fix the placement's env |
| `container_conflict` | a container with the workload's name exists and was not created by the agent | remove it by hand |
| `start_timeout` | the worker was not ready within `start_secs` | read the worker's logs; raise `start_secs` in the add-on |
| `crashed` | the worker exited while it should run, or during a drain (it is then recreated fresh and stopped) | read the worker's logs |
| `drain_timeout` | the drain did not finish in `drain.timeout_secs`; reported as `needs_attention` | wait; the session is never cut |
| `door_unreachable` | the host cannot route the agent to an internal Docker network (not Linux, e.g. macOS Docker Desktop) and the no-egress rule does not bend | place on a Linux node |

The placement facts (`consent_none`, `consent_unapproved`, `nvidia_runtime_missing`, `driver_caps_missing`, `compute_cap_low`, `arch_mismatch`, `controller_host`, `disk`) are also the gateway's placement refusal codes, spelled identically: the gateway refuses a placement with the code the agent would report.

### Consent, and the controller host

- The node's consent is `NOO_ADDON_WORKLOADS` = `none` | `approve` | `auto`
  (default `none`); it is reported as `addon_workloads_policy`.
- Approvals live in `addon-workload-approvals.json` in the agent state
  directory (mode 0600, written atomically). A corrupt file is an **error**,
  never read as empty (an empty list would silently drop every approval).
- A node that is the controller's host (the agent's `NOO_SELF_NODE` marker) is
  refused with `controller_host` unless `NOO_ADDON_WORKLOADS_ON_CONTROLLER=1`
  (default off).

`image_missing` also covers a malformed digest, id or artifact at parse time. A refusal of the
decl inside an entry is reported as `decl_invalid` and carries the inner code.

## Refusal codes

The stable codes a validator returns for a file. The fixtures pin each.

Every file kind also has `duplicate_key` (see above); in desired-config it is returned as itself, not as `desired_invalid`.

**`node-workloads.json`:** `bad_json`, `duplicate_key`, `unknown_field`, `field_type`,
`field_missing`, `bad_format`, `workloads_invalid`, `door_name_invalid`,
`door_name_too_long`, `name_duplicate`, `image_not_in_lock`, `uid_invalid`,
`command_invalid`, `port_invalid`, `protocols_invalid`, `health_invalid`,
`drain_invalid`, `service_drain_invalid`, `accel_invalid`, `model_slot_invalid`,
`env_key_outside_prefix`, `env_key_refused_prefix`, `env_bound_invalid`,
`scratch_target_refused`, `scratch_invalid`, `scratch_in_model_slot`,
`limits_invalid`.

**`model-set.json`:** `bad_json`, `unknown_field`, `field_type`,
`field_missing`, `bad_format`, `id_invalid`, `revision_invalid`, `kind_invalid`,
`modality_invalid`, `runtime_invalid`, `source_invalid`, `license_invalid`,
`path_invalid`, `sha256_invalid`, `files_invalid`, `notice_not_in_files`,
`profile_invalid`, `arch_invalid`, `fits_required`, `fits_forbidden`,
`fits_invalid`, `trust_required`, `trust_invalid`, `from_archive_invalid`.

**desired-config:** the codes are reasons: `desired_invalid`, `decl_invalid`,
`image_missing`, `door_leaf_missing`, `admit_invalid`, `env_out_of_bounds`,
`set_missing`, `set_slot_invalid`, `profile_invalid` (from `CheckProfile`, run
with the paired set manifest).

The first failing rule wins; the fixtures each carry one defect, so order does
not matter to them. Precedence worth knowing: a refused env prefix wins over
the add-on prefix; `scratch_target_refused` wins over `scratch_invalid`. The
`exec` scratch checks (more than one entry, over 1024 MiB) come after the size
range check.

## Images on the rail

The gateway has no docker, so the CLI stages the images (F2c). At
`noo addons enable` and `noo addons upgrade`, after the add-on's images are
pulled by digest, each image **named by a workload's `image`** (the lock's
`images` entry, with the lock's digest) is written with `docker save` into the
rail's image directory, as an `image`-kind artifact. Name:

```text
noo-addon-wl_<addon>_<image name>_<64 hex of the lock digest>_<arch>.tar
```

That is `image_tar_name` of the synthetic ref
`noo-addon-wl/<addon>/<image name>:<64 hex>`; a `<tar>.imageid` sidecar beside
it names the image id it loads as. Written as `<tar>.part`, then renamed; a tar
whose sidecar names the image that is local now is not exported again. The
`noo-addon-wl_` prefix marks the add-on's files: `noo addons upgrade` removes
the add-on's tars that the new lock no longer names, and `noo addons disable`
removes all of them. Nothing else on the rail is touched.

## Who validates what

| Validator | Reads | Against |
|---|---|---|
| CLI, `noo-cli/src/addons/decls.rs` (F2) | `node-workloads.json` at `enable`, `upgrade --check`, `verify` and launch; the lock's images map and the bundle's `routes.json` (`service_drain.route` must be an internal route) | `tests/fixtures/i300/node-workloads/` |
| Gateway, `gateway-rust/src/addon_workloads.rs` (harness) | the same file at every start; env values at placement; builds the desired-config entry | the same fixtures; `desired/` for the entry it emits |
| Node agent, `node-agent-go/internal/nodewl` | the decl inside every desired-config entry (re-checked, not trusted); the entry; env values; the signed model-set manifest | all three fixture directories |
| The staging side (CLI), model sets | `model-set.json` at staging, before it is written (i300 F2b) | `tests/fixtures/i300/model-sets/` |

`tests/test_i300_fixture_parity.py` holds the agent's copy of the fixtures
byte-identical to the canonical set, checks the gateway and CLI copies
(`gateway-rust/src/testdata/i300/`, `noo-cli/src/addons/testdata/i300/`) the
moment they exist, and checks both schemas against every case.
