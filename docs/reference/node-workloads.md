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

## The declaration (`noo-addon-node-workloads/1`)

One file, listed in the signed bundle lock beside `resources.json`. Per
workload: `name`, `image`, `uid` (at least 1), `command?`, `port`
(1024-65535), `protocols` (a subset of `http`, `ws`), `health {ready, live,
start_secs 1-600}`, `drain {path, timeout_secs 1-3600}`, `accel {gpu 0-8,
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

### The door name

The door's DNS SAN is `noo-stunnel-<addon>-<workload>`, which must be one DNS
label of at most 63 characters. So **a node workload is refused when
`len(addon) + 1 + len(workload) > 51`** (`door_name_too_long`), and both the
workload name and the add-on name must match `^[a-z0-9]([a-z0-9-]*[a-z0-9])?$`
(`door_name_invalid`): `_`, upper case and a leading or trailing `-` are
refused. `_` is **not** mapped to `-`: a per-file validator cannot see a
collision between two add-ons. The fixtures pin 51 (valid) and 52 (refused),
by workload name and by add-on name.

## The desired-config entry (`node_workloads`)

Separate from the existing `addon_workloads` key. One row per
(add-on, workload) the node must hold:

```json
{"addon": "rhaddon", "name": "worker",
 "decl": { "...": "the validated workload object, verbatim" },
 "image": {"name": "addon-worker", "digest": "sha256:<64 hex>"},
 "sets": {"main": [{"id": "...", "revision": "..."}]},
 "env": {"RHADDON_SLOTS": "1"},
 "door": {"leaf": "svc-addon-rhaddon-worker", "admit": ["<this node's agent CN>"]},
 "start_secs": 300,
 "drain": {"path": "/v1/lifecycle/drain", "timeout_secs": 420},
 "reservation": "<canonical lower-case UUID>" ,
 "state": "provisioned"}
```

`reservation` is a canonical lower-case UUID string or `null`. `start_secs` and
`drain` equal the decl's. `image.name` equals `decl.image`. `door.leaf` is
`svc-addon-<addon>-<name>`. `sets` keys are declared slots, a non-optional slot
has at least one set, and a `many: false` slot has at most one (not checked for
`absent`). The agent re-checks `env` against the decl's bounds; a key the decl
does not declare is out of bounds.

### Door and amendments

- **A1.** The door leaf `svc-addon-<addon>-<workload>` is CLI-issued per (node,
  enabled add-on node workload) in the provision bundle. If it is missing the
  agent refuses with `door_leaf_missing`.
- **A2.** The node agent is the **only** door client. It dials
  `127.0.0.1:<door_port>` with its own node leaf. The door is published on
  loopback only and pins exactly this node's agent CN. `door.admit` must be
  exactly `[<own agent CN>]`; anything else is `admit_invalid`. The agent picks
  `door_port` and reports it.
- **A3.** The entry above, with the state machine below.
- **A4.** The heartbeat keys below.

### Relay rule (the agent is the proxy)

Because the agent is the only door client, it relays the gateway's calls to the
worker. It forwards **exactly three** gateway-set headers, `X-Noo-Reservation`
(a UUID), `X-Noo-Requester-Sub` and `X-Noo-Requester-Role`, taken from the
gateway's authenticated call. It **strips any client-supplied copy** of those
three, and strips `Origin` and `Authorization`, before the request reaches the
worker. The worker holds no credential and no user token.

## State machine

| State | Meaning |
|---|---|
| `absent` | Nothing of this workload on the node: worker, sidecar and network removed. |
| `provisioned` | Image loaded and matches the digest, sets verified, sidecar and worker created **stopped**, on an `internal: true` network. The resting state. |
| `running` | Started. Ready when `health.ready` answers through the door within `start_secs`. |

- `absent` to `provisioned`: load the image from the rail, check its ID equals
  `image.digest`, verify the sets, create the sidecar and the worker stopped.
- `provisioned` to `running`: start. A worker not ready within `start_secs`
  reports `start_timeout`.
- **Release returns the row to `provisioned`**: call `drain.path` (POST) through
  the door, wait up to `drain.timeout_secs`, stop, remove the worker and its
  scratch, recreate it fresh and stopped. A drain that does not finish reports
  `drain_timeout` with state `needs_attention` and **never cuts a live
  session**; the worker keeps running until it drains.
- any state to `absent`: remove the worker, sidecar and network.
- A refusal never changes the container: the row reports its last good state
  with a `reason`.

## Heartbeat keys (A4)

Absent or unknown values are **omitted**, never defaulted: an error must not
become a fact (the i495 rule). A `null` is never sent.

| Key | Type | Notes |
|---|---|---|
| `gpu_compute_cap` | string, `"8.6"` | omitted when unknown |
| `nvidia_runtime` | bool | the nvidia container runtime is registered |
| `nvidia_driver_caps_ok` | bool | `compute,utility` driver capabilities are usable |
| `controller_host` | bool | this node is the controller's host |
| `data_root_free_gb` | number | omitted when unknown |
| `addon_workloads_policy` | `"none"` / `"approve"` / `"auto"` | the node's consent setting |
| `addon_workloads_approvals` | `[{addon, digest}]` | per add-on and image digest |
| `model_sets` | `[{id, revision, state, reason?}]` | `state` is `verified`, `fetching` or `refused`; `reason` rides `refused` |
| `node_workloads` | `[{addon, name, state, ready, model?, slots?, door_port, reservation?, reason?}]` | `model`, `slots`, `reservation` and `reason` are omitted when unknown or none |

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
| `image_missing` | the image name or digest is absent or malformed, or the image is not on the rail | re-enable or upgrade the add-on on the controller |
| `image_digest_mismatch` | the loaded image's ID differs from `image.digest` | re-stage the image; investigate the rail |
| `set_missing` | a required slot has no set | choose a model for the slot |
| `set_slot_invalid` | `sets` names an undeclared slot, several sets for a `many: false` slot, or a malformed id or revision | fix the placement |
| `set_unverified` | a set's signature, hashes or `.verified` marker did not check out | re-stage the set; check the node holds `signing.pub` |
| `disk` | the data root lacks space for the set or the scratch plus the margin | free space on the node |
| `consent_none` | the node's `addon_workloads_policy` is `none` | the node's owner sets `approve` or `auto` |
| `consent_unapproved` | policy is `approve` and this add-on and digest are not approved | approve the add-on and digest on the node |
| `nvidia_runtime_missing` | `accel.gpu` > 0 and the nvidia runtime is not registered | install the NVIDIA container toolkit |
| `driver_caps_missing` | the driver cannot grant `compute,utility` | fix the driver or toolkit |
| `compute_cap_low` | the GPU's compute capability is below the set's `min_compute` | place on a newer GPU |
| `arch_mismatch` | the node's arch is not in the set's `needs.arch` | place on another node |
| `controller_host` | the node is the controller's host and has not opted in (D4) | opt in for a single-box install, or place elsewhere |
| `admit_invalid` | `door.admit` is not exactly `[<own agent CN>]` | a gateway bug or version skew |
| `env_out_of_bounds` | an env key is undeclared or its value is outside the decl's bound | fix the placement's env |
| `container_conflict` | a container with the workload's name exists and was not created by the agent | remove it by hand |
| `start_timeout` | the worker was not ready within `start_secs` | read the worker's logs; raise `start_secs` in the add-on |
| `crashed` | the worker exited while it should run | read the worker's logs |
| `drain_timeout` | the drain did not finish in `drain.timeout_secs`; reported as `needs_attention` | wait; the session is never cut |

`image_missing` also covers a malformed digest at parse time. A refusal of the
decl inside an entry is reported as `decl_invalid` and carries the inner code.

## Refusal codes

The stable codes a validator returns for a file. The fixtures pin each.

**`node-workloads.json`:** `bad_json`, `unknown_field`, `field_type`,
`field_missing`, `bad_format`, `workloads_invalid`, `door_name_invalid`,
`door_name_too_long`, `name_duplicate`, `image_not_in_lock`, `uid_invalid`,
`command_invalid`, `port_invalid`, `protocols_invalid`, `health_invalid`,
`drain_invalid`, `accel_invalid`, `model_slot_invalid`,
`env_key_outside_prefix`, `env_key_refused_prefix`, `env_bound_invalid`,
`scratch_target_refused`, `scratch_invalid`, `scratch_in_model_slot`,
`limits_invalid`.

**`model-set.json`:** `bad_json`, `unknown_field`, `field_type`,
`field_missing`, `bad_format`, `id_invalid`, `revision_invalid`, `kind_invalid`,
`modality_invalid`, `runtime_invalid`, `source_invalid`, `license_invalid`,
`path_invalid`, `sha256_invalid`, `files_invalid`, `notice_not_in_files`,
`profile_invalid`, `arch_invalid`, `fits_required`, `fits_forbidden`,
`fits_invalid`, `trust_required`, `trust_invalid`.

**desired-config:** the codes are reasons: `desired_invalid`, `decl_invalid`,
`image_missing`, `door_leaf_missing`, `admit_invalid`, `env_out_of_bounds`,
`set_missing`, `set_slot_invalid`.

The first failing rule wins; the fixtures each carry one defect, so order does
not matter to them. Precedence worth knowing: a refused env prefix wins over
the add-on prefix; `scratch_target_refused` wins over `scratch_invalid`.

## Who validates what

| Validator | Reads | Against |
|---|---|---|
| CLI, `noo-cli/src/addons/decls.rs` (F2) | `node-workloads.json` at `enable`, `upgrade --check`, `verify` and launch; the lock's images map | `tests/fixtures/i300/node-workloads/` |
| Gateway, `gateway-rust/src/addon_workloads.rs` (harness) | the same file at every start; env values at placement; builds the desired-config entry | the same fixtures; `desired/` for the entry it emits |
| Node agent, `node-agent-go/internal/nodewl` | the decl inside every desired-config entry (re-checked, not trusted); the entry; env values; the signed model-set manifest | all three fixture directories |
| The staging side (CLI), model sets | `model-set.json` at `noo models stage` | `tests/fixtures/i300/model-sets/` |

`tests/test_i300_fixture_parity.py` holds the agent's copy of the fixtures
byte-identical to the canonical set, checks the gateway and CLI copies
(`gateway-rust/src/testdata/i300/`, `noo-cli/src/addons/testdata/i300/`) the
moment they exist, and checks both schemas against every case.
