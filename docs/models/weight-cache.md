# LAN Model-Weight Cache

Model weights are the only genuinely large transfers in a cluster (4–70 GB
per model). The weight cache makes sure that after the controller has a
model on disk, every other node fetches it over the LAN (or your tailnet)
instead of from the internet. It is **storage, not a proxy**: the
controller serves the files it already has; a node copies them into its
own cache before the backend starts, then runs the backend offline.

Prove it works, from a node (the store requires the node's own certificate;
`/healthz` answers only on the container's loopback, so the probe is a
listing):

```bash
PKI=/etc/noo/pki
curl -s --cacert $PKI/ca.crt --cert $PKI/node.crt --key $PKI/node.key \
  https://<controller>:8443/hf/ | head  # JSON listing of the controller's HF cache
```

The second command is the one that catches a misconfigured cache. It must
list `models--<org>--<name>` entries:

```json
[
{ "name":"models--Qwen--Qwen3-8B-AWQ", "type":"directory", ... }
]
```

An empty list `[]` means the cache holds no models yet. A `404` means
`HF_CACHE_DIR` is not laid out the way the store expects — see below.

## What the cache serves

The `model-cache` compose service (`nginx:1.27-alpine`, profiles
`controller` and `standalone`) listens on port **8443** (mTLS) and serves
three read-only trees from the controller's data root:

| URL path | Host directory | Content |
|---|---|---|
| `/hf/` | the **`hub/` subtree of** `HF_CACHE_DIR` (default `<data root>/hf-cache`) | HuggingFace snapshots for vLLM, embedding and reranker backends; JSON directory listings |
| `/gguf/` | `MODELS_DIR` (default `<data root>/models`) | Bare `*.gguf` files for llama.cpp |
| `/images/` | `IMAGES_DIR` (default `<data root>/images`) | Container image tarballs — the only place a node gets an image from (see [Container images](#container-images)) |
| `/healthz` | — | `ok` — on the container's loopback (`127.0.0.1:8084`) only, for the compose healthcheck |

The service is **mTLS**: it presents the `model-cache` service certificate
(issued by `noo onboard`, carrying the controller's `noo-controller`, LAN
and tailnet names) and requires a cluster-CA client certificate whose
organisation is a node (`Mesh Cluster Node`) or the controller
(`Mesh Cluster Gateway`); any other leaf is refused with `403`. The node
agent presents its own `node.crt`. Image tarballs and weights are also
hashed on the node against the gateway's artifact manifest before use (an
authenticated answer over the same mTLS/cluster-HMAC channel; the gateway
stopped signing manifests with its TLS key any more). Confine
the port to your LAN or tailnet the same way you confine NATS.

There is no plaintext listener. Phase 1 of the mTLS move (stack-v0.2.77)
kept plain HTTP on 8083 for one release so an agent older than the
TLS-capable client could keep preseeding; phase 2 removed the listener
and its port. `noo cluster verify` fails its "model cache" row if a plain
listener or a second published port ever comes back, and names any node
whose agent refuses its `NOO_MODEL_CACHE_URL` (below).

The store fills itself: any model the controller runs lands in
`HF_CACHE_DIR` or `MODELS_DIR`, and so does anything you download there
by hand or with `noo models pull` (Ollama only — see below).

### `HF_CACHE_DIR` is an HF_HOME, not a hub directory

This is the one layout mistake that produces a silent empty cache, so it is
worth being exact. `HF_CACHE_DIR` is an **HF_HOME**: the directory
`huggingface_hub` treats as its root, which holds `hub/` (and `xet/`,
`token`, …) *inside* it. It is not the hub directory itself.

Both mounts depend on that. Compose binds `HF_CACHE_DIR` to
`/root/.cache/huggingface` for the vLLM-family backends — an HF_HOME, which
is where they look for `hub/` — and to `/hf-store` for the model cache,
whose nginx `location /hf/` aliases `/hf-store/hub/`.

```
$HF_CACHE_DIR/                     ← this is what HF_CACHE_DIR points at
├── hub/                           ← served as /hf/
│   ├── models--Qwen--Qwen3-8B-AWQ/
│   │   ├── blobs/
│   │   ├── refs/
│   │   └── snapshots/
│   └── .locks/
└── xet/
```

Point `HF_CACHE_DIR` at a bare hub archive — a directory whose `models--*`
entries sit at the top level, with no `hub/` — and everything still *starts*
cleanly: nginx has no directory to alias, so `/hf/` answers `404`, every
node's preseed fails its listing fetch, and the backends find no models
where they expect them. Nothing in that chain says "wrong layout".

Verify the layout, on the controller:

```bash
# Expect one or more models--<org>--<name> lines. Nothing = wrong level.
ls "${HF_CACHE_DIR:-${NOO_DATA_ROOT:-/var/lib/noo}/hf-cache}/hub" | grep '^models--'
```

and end to end, from any node that can reach the store:

```bash
# Expect {"name":"models--<org>--<name>","type":"directory",...}; a 404 means
# $HF_CACHE_DIR/hub does not exist. The node's own certificate is required.
PKI=/etc/noo/pki
CURL="curl -sS --cacert $PKI/ca.crt --cert $PKI/node.crt --key $PKI/node.key"
$CURL -o /dev/null -w '%{http_code}\n' https://<controller>:8443/hf/
$CURL https://<controller>:8443/hf/ | grep -o 'models--[^"]*' | head
```

To fix a bare-hub archive, give it the level it is missing rather than
re-downloading: `mkdir -p <hf-home>/hub && mv <archive>/models--* <hf-home>/hub/`,
then point `HF_CACHE_DIR` at `<hf-home>` and restart the stack.

## How a node uses it

A node preseeds when `NOO_MODEL_CACHE_URL` is set in its node-agent
environment. `noo cluster provision` sets it to
`https://<controller DNS name>:8443` for you; an empty value silently
disables both preseed paths and the image-pull rail, so check it first
when a node "always downloads from HuggingFace". A plaintext value
(`http://…`, whatever the port) is **refused**, not rewritten: the agent
logs an error naming the variable and the `https://<controller>:8443`
form, records a `model_cache_url` refusal that reaches the controller in
its heartbeat, and treats the store as absent — `noo cluster verify`
fails the "model cache" row naming the node, with
`noo cluster provision <node>` as the remedy (it re-renders the env file
and the node leaf). A node with no client certificate is refused the same
way. A TLS failure is logged as a preseed miss naming the cause, never
retried in plaintext.

A node provisioned before stack-v0.2.77 still carries
`http://<controller>:8083` in `/etc/noo-node-agent.env`; phase 1's agent
rewrote it silently, phase 2's refuses it. Re-provision those nodes after
the roll (the verify row is how you find them).

When the node-agent is asked to start a backend:

- **HuggingFace repos** (`vllm`, `embedding`, `reranker`): the agent mirrors
  `<cache-url>/hf/models--<org>--<name>/` into the node's HF cache itself,
  in-process against the host path (15-minute budget). It reads `refs/main`
  and mirrors **only that one** snapshot, so the backend can start with
  `HF_HUB_OFFLINE=1`. No helper container is involved: the agent is a host
  process. **A placed node never downloads weights from the internet.** With
  `NOO_MODEL_CACHE_URL` set, the backend always starts with
  `HF_HUB_OFFLINE=1` and **without** `HF_TOKEN` / `HUGGING_FACE_HUB_TOKEN`
  (a node needs no Hugging Face credential). A model the store does not hold
  (and the node's own HF cache has no snapshot of) is refused:
  the start fails with `model_cache_miss: <backend> needs <model>, which is
  not in the controller's model store`, the refusal reaches the controller in
  the node's heartbeat, and `noo cluster verify` shows it. The fix is on the
  controller: run the model once there, or
  `HF_HOME=$HF_CACHE_DIR huggingface-cli download <model>`, then re-run
  `noo cluster verify`. A permission error is logged with the directory the
  agent's user cannot write. A node with no store configured (the
  controller's own agent, a hand-run dev box) keeps the old behaviour:
  online on a miss, the token passed through.
- **Ollama registry tags** (`gemma4:12b`): the controller stages the tag
  (`noo models fetch ollama:gemma4:12b`, below) and a placed node imports
  it from the store: it fetches the staged pair by name, each file verified
  against the gateway's artifact manifest, checks the weight against the
  registry digest recorded in the Modelfile, and runs `ollama create`. It
  never contacts `registry.ollama.ai`. A tag the controller has **not**
  staged is **refused** (`ollama_registry_pull_refused`, naming the
  `noo models fetch ollama:<tag>` remedy): the controller store is the only
  source on a placed node. A node that must pull a tag anyway accepts that
  explicitly with `NOO_ALLOW_OLLAMA_REGISTRY_PULL=1` in its node-agent
  environment.

`noo models recommended` prefers models that are already in the cache
(`GET /api/models/cached`) precisely because they preseed over the LAN.

## Put a GGUF in the controller store

To get a ready-made GGUF from Hugging Face into the store, use
`noo models fetch` on the controller rather than `curl`:

```bash
noo models fetch unsloth/gemma-4-E2B-it-GGUF gemma-4-E2B-it-Q4_K_M.gguf
noo models fetch <org>/<repo> sub/dir/model.gguf --revision <branch|tag|commit>
```

What it does, in order:

- **Resolves the store** the same way `sync-model-files` does: `MODELS_DIR`,
  else `$NOO_DATA_ROOT/models`, else `/var/lib/noo/models`. The file is stored
  under its bare name (the last path segment), which is the name
  `sync-model-files -m` and `/gguf/` use.
- **Refuses if you cannot write the store**, before it downloads anything.
  The store usually belongs to a service account, and it is often an NFS
  mount (for example `/mnt/fleet/models/gguf`). NFS refuses `chown`, even
  under sudo, so the command never tries it and never escalates. The
  refusal names the owner, group and mode, and prints the remedy: make the
  directory group-writable (`chmod g+ws`) and join that group, or grant
  yourself an ACL (`setfacl -m u:<you>:rwx`). On NFS, apply either one on
  the server that exports the directory.
- **Authenticates with the controller's Hugging Face token**: `HF_TOKEN` (or
  `HUGGING_FACE_HUB_TOKEN`) from the process environment, else from the
  encrypted store `secrets/env.sops`. The token is sent only as an
  `Authorization` header to the Hugging Face origin (`HF_ENDPOINT` if set).
  It never goes on a command line or into a log, and it is not sent to the
  CDN the download redirects to, because that URL is pre-signed. Without a
  token, only public repos work. A gated repo answers 401/403; accept its
  licence with the token's account, then store the token with
  `noo security secrets rotate HF_TOKEN --prompt`.
- **Streams to `.<file>.part` in the store directory and resumes it.** An
  interrupted download continues from where it stopped when you re-run the
  same command (HTTP `Range`). If the server ignores `Range`, the download
  starts again from zero instead of appending to the partial file.
- **Verifies the sha256** against Hugging Face's LFS metadata (the
  `x-linked-etag` header, else the API's `lfs.sha256`). On a mismatch it
  deletes the partial file and installs nothing. A file with no published
  LFS digest is refused.
- **Renames the file into place with mode 0644**, so the model-cache nginx
  can read it.
- **Pre-warms the gateway's digest cache** (`GET
  /api/artifacts/manifest/gguf/<file>`), so the first `sync-model-files` does
  not have to wait for a multi-GB hash. This step is best effort. If the
  gateway's digest differs from the verified one, the command prints a loud
  warning. That usually means the gateway serves a different `MODELS_DIR`.

If the store already holds the same file (same sha256), the command does
nothing. If it holds a different file with that name, the command refuses
unless you pass `--force`. When it finishes, it prints the next two steps:

```
noo cluster sync-model-files <node> -m <file>
noo cluster place <node> llamacpp <file>
```

If you run `sync-model-files -m <file>` for a file that is not in the store,
the error names the resolved store path and points at `noo models fetch`.

## Stage an ollama registry model

An ollama tag is not a GGUF file, so the controller pulls it for the nodes:

```bash
noo models fetch ollama:gemma4:12b            # library/gemma4:12b
noo models fetch ollama:user/model:q4_K_M     # another namespace
noo models fetch ollama:gemma4:12b --force    # replace a store copy that differs
noo cluster place <node> ollama gemma4:12b    # then place the tag as usual
```

What it does, in order:

- **Resolves and checks the store** exactly like `noo models fetch <hf_repo>`
  (same writability refusal, same `MODELS_DIR`).
- **Reads the registry's manifest** (`registry.ollama.ai`, or the mirror in
  `NOO_OLLAMA_REGISTRY`) and downloads every layer and the config blob, each
  **checked against the `sha256:` digest and the size the manifest carries**.
  A mismatch installs nothing.
- **Refuses what a GGUF and a Modelfile cannot rebuild**: a vision projector,
  an adapter, any layer type it does not know, template or parameter text a
  Modelfile cannot quote. The refusal says so before the weight is
  downloaded. For such a model use a text-only tag, a GGUF from Hugging Face,
  or the per-node exception above.
- **Writes two files**, the weight first and the recipe last, 0644:
  `ollama+<namespace>+<name>+<tag>.gguf` (the model layer, byte for byte) and
  `ollama+<namespace>+<name>+<tag>.Modelfile` (`FROM` that file, plus the
  template, system prompt, parameters, licence and messages layers, and a
  header recording the registry digest). `library/` and `:latest` are implied
  and the name is lower-case, so `gemma4:12b` is
  `ollama+library+gemma4+12b.*`. The weight download resumes after an
  interruption (HTTP `Range`). These two names are served by the existing
  `/gguf/` tree and the existing `gguf` and `modelfile` artifact kinds; nothing
  new is mounted or exposed. `noo cluster sync-model-files` leaves them out of
  its default sweep (they ride a placement, not a push to every node).
- **Pre-warms the gateway's digest** for the weight, as `models fetch` does.

On the node, reconcile asks the store about a placed tag it does not hold; a
staged tag takes the same import path as `noo cluster import-model`, which
now accepts the tag itself: `noo cluster import-model <node> ollama:gemma4:12b
[--place --role chat]` (a bare `gemma4:12b`, or `gemma4` for `:latest`, works
when it is not also the name of a plain store model; if it is both, the verb
refuses and asks for the `ollama:` form). The CLI checks the controller store
for the complete `ollama+...` pair first and, when it is not staged, refuses
naming `noo models fetch ollama:<tag>`; a node older than this release has no
staged-tag import and answers with its own error. The node
holds a staged Modelfile to a stricter shape than a hand-made one: only the
directives `FROM`, `TEMPLATE`, `SYSTEM`, `PARAMETER`, `LICENSE`, `MESSAGE`,
`RENDERER` and `PARSER`; `FROM` must be exactly the staged weight; the weight
must start with the `GGUF` magic and hash to the digest in the Modelfile
header. Any of those failing is a refusal that names the restage command, and
`ollama create` is not run.

Failure cases: the registry unreachable or a 404 stops the command with the
store untouched; a controller that cannot be reached by a node leaves the
placement waiting (a timeout is never read as "not staged"); a node older than
this release has no staged-tag import and keeps refusing the registry pull.
An unplaced node (the controller's own agent, a dev box with no
`NOO_MODEL_CACHE_URL`) is unchanged: it still pulls from the registry itself.

## Container images

**A node never pulls one of our images from a registry.** The controller
pulls every image with its own registry login and stages it on this store;
the node pulls the tar over mTLS, verifies it, and `docker load`s it. No
registry credential is ever sent to a node, by design: a node without
the staged image fails with a clear refusal rather than an `unauthorized`
registry error.

Third-party backend images (vLLM, ollama, TEI) are pinned the same way. The
controller sends each node the digest-pinned ref from the release-signed
`stack.lock` (`vllm/vllm-openai:v0.25.0@sha256:...`) in its start request. A
node refuses `:latest` and untagged refs outright, and on a dist node
refuses a ref with no digest: a controller too old to send one leaves the
node on its versioned default, which a registry node refuses (with the
controller roll that fixes it) and a `rail` node (the default) runs only
if the controller staged that image (`noo cluster sync-images <node> -i
<image>`), since the rail verifies the tar against the gateway's manifest.
On a rail node the image never comes from a registry.

### What the controller stages

| When | What | How |
|---|---|---|
| `noo upgrade` (stack stage, after the roll; a stage with failures warns loudly, and blocks the `--nodes` roll unless `--force` while any online Linux node will run the rail after the roll: every one except a node that set `NOO_IMAGE_SOURCE=legacy` itself, and including an older agent that becomes rail on this roll) | every node-bound image in the release-signed `stack.lock` (not `gateway`, `worker`, `trellion*`, `postgres-pgvector`, `deps-*`) | pulled **by lock digest**, for every architecture in the fleet |
| `noo cluster sync-images --stage-only [--lock] [-i IMG]… [--arch a,b] [--all-images]` | the lock (default) and/or named images | same; `--all-images` stages the controller-only lock images too; stops after staging, no node pulls |
| `noo cluster sync-images <node> -i IMG` (or `--lock <node>` for the lock's node-bound images) | a named image, for that node's architecture | then asks the node's agent to pull it now |
| `noo cluster place …` refused with "not staged" | the placement's image | stages it, then places again |

**Multi-arch.** Architectures come from the nodes' reported
`capabilities.arch` (an older agent's `is_arm`/tier 4 counts as arm64) plus
the controller's own. An image published only for amd64 (most of the
release; llama.cpp on ARM uses the upstream image) is reported as *not
published for arm64* and skipped, not failed. On Docker's classic image
store a foreign-architecture pull under a shared reference would re-point
it, so the controller resolves the per-platform manifest digest from the
registry (`docker buildx imagetools inspect`, else `docker manifest
inspect -v`), pulls `repo@sha256:<that>` — a reference nothing else uses —
and saves **by ID** (the node tags it on load); there is no tag and no
restore pull. On the host's own architecture the pulled image's
architecture is checked before the release tag is moved. On the containerd
image store it uses `docker save --platform`.

**Files.** `<ref with / and : as _>_<arch>.tar` (the name *is* the
protocol: the node derives it from the ref and its own `GOARCH`), a
`<tar>.imageid` sidecar naming the image ID it holds, and
`staged-images.json` — one record per (ref, arch): `image_id`,
`lock_digest`, `source`, `release_tag`, plus the release `prefix`/`tag`
the gateway uses to name a node's default images. Lock-staged images of
releases older than the previous one are pruned at each stage. After
writing a tar the CLI asks the gateway for its manifest once, so the
multi-GB hash happens then and not inside a node's 15-second probe.

### What a node does

**Per-node switch: `NOO_IMAGE_SOURCE=legacy`** (node env,
`/etc/noo-node-agent.env`). The rail is the default: unset, empty or any
unrecognised value means `rail` (a typo fails closed toward the rule that
images come from the controller). Setting `legacy` opts one node out: a
local image is used and an absent one comes from its registry, the pre-rail
behaviour. The heartbeat reports `image_source_mode` and
`image_source_mode_source` (`env` when the variable is set to a recognised
value, `default` otherwise); `noo cluster verify` WARNs on a node that chose
legacy and says how to remove it. The steps below are what `rail` does.

*Rollout.* The release that made `rail` the default changes the start path
of every Linux backend: an image the node does not hold and the controller
has not staged for its architecture is refused instead of pulled. So
`noo upgrade` counts, before rolling nodes, every online Linux node that will
run the rail after the roll (all but those that chose `legacy`, and including
older agents that report no `image_source_mode_source`), and a failed stage of
the release images refuses the node roll unless `--force`. Darwin nodes start
no containers and are unaffected. After the roll, check awolf (largest image
set) and robopi (arm64) with `noo cluster verify`: `image sources` should
read all from the rail, with third-party `registry` entries accepted.

Every container start path in the agent — backends, the stunnel sidecar,
the containers API, MCP stdio servers, skills, the profile pull — resolves
its image through one function (`EnsureImage`):

1. **Local and vouched for** — the local image ID equals the manifest's
   `image_id`, or the ID this node itself loaded from that exact tar before
   (`/var/lib/noo-node-agent/rail/images.json`, directory 0700, believed
   only when the agent's uid owns it and nobody else can write it; the two
   IDs differ between the classic and containerd image stores) → used as is.
2. **Staged** → the tar is fetched and checked **before** `docker load`:
   its sha256 against the manifest, and its own `manifest.json`/`index.json`
   must hold exactly one image tagged as nothing or as the requested ref.
   After the load the ref is re-tagged to the loaded ID (always — a ref
   left on an older ID would loop) and must match the node's architecture.
   Any of those failing is a **refusal**. A local copy at a *different* ID
   than the staged one is replaced — unless the fetch fails in **transport**
   (cache unreachable, timeout, disk full): then the local copy runs, logged
   as `image.rail_transport_failed` and reported `local`, and the rail is
   not retried for 30 minutes.
3. **Local, nothing to compare** (not staged, an older gateway, controller
   unreachable) → used, and reported as `local`.
4. **Absent and not staged** → for our images (`$NOO_IMAGE_PREFIX/*`, the
   release namespaces, `noomesh/*`, `pai-assistant/*`, `noo-*`) a refusal:
   `image X not staged on the controller — run noo cluster sync-images
   <node> -i X or noo upgrade`. A **public third-party** image (upstream
   llama.cpp for ARM, ollama, the alpine sidecar fallback) may come from its
   registry only while `NOO_IMAGE_REGISTRY_FALLBACK=public` (the default),
   logged at WARN as `image.registry_fallback`; `off` makes the node
   rail-only. Prefer staging those too (`noo cluster sync-images <node> -i
   ollama/ollama:latest`) so a node needs no internet registry at all.

The agent's only registry pull is that fallback; a test
(`TestNoRegistryPullOutsideTheFallback`) fails on any other `ImagePull`.

### Seeing it

- The heartbeat carries `image_sources`: `[{image, source: rail|local|registry, image_id}]`.
- `noo cluster verify` adds **image sources** (WARN naming every image not
  from the rail) and **images staged** (WARN naming every running placement
  whose image is not staged for the node's architecture).
- The gateway refuses a running placement on a `rail` node whose image it
  can name and that is not staged (`409 image X for <arch> is not staged on
  the controller`), unless `--force`; on a node that chose `legacy` it is a warning.
  `noo cluster place` stages the image and places again on that refusal.

## Push GGUF weights to nodes by hand

For edge nodes that will run a GGUF you placed on the controller:

```bash
noo cluster sync-model-files                       # every *.gguf in the store, to every online node
noo cluster sync-model-files jetson-1 -m gemma-4-E2B-it-Q4_K_M.gguf --dry-run
```

This dispatches a `model_file` job per (node, file) over the artifact
rail, not the HTTP cache and not SSH — it replaced `scp` over SSH,
retired 2026-09-05. Each node's agent pulls the file from the
controller's model cache and verifies it against the gateway's manifest
digest; a file already present with the matching digest is a no-op
rather than a re-transfer. There is no login, no `--user`/SSH account
to select, and no destination path to type — the node agent places the
file under its own `MODELS_DIR`/`HF_CACHE_DIR`. Success prints
`model files synced` and the two commands to start using them:

```
noo cluster place <node> llamacpp <file>
```

## Pre-cache models on a schedule

The heartbeat action `model_cache_warm` takes a list of `{model,
node_id?, backend?}` entries, checks `/api/models/cached`, and asks the
node-agent to pull whatever is missing (`POST /api/models/pull`, which
starts the backend's own download on the node — Ollama by default).
Create it with `noo heartbeat` like any other task; see
[cli/stack-and-data.md](../cli/stack-and-data.md).

## Reference

| Setting | Where | Meaning |
|---|---|---|
| `NOO_MODEL_CACHE_TLS_PORT` | controller `compose_env` | Host port for the mTLS store (default `8443`; multi-instance installs offset it) |
| `NOO_MODEL_CACHE_URL` | node-agent env (set by `noo cluster provision`) | `https://<controller>:8443`; empty disables preseed and the image rail; an `http://` value is refused by the agent (re-run `noo cluster provision <node>`) |
| `HF_CACHE_DIR`, `MODELS_DIR`, `IMAGES_DIR` | controller `compose_env` | The three served directories (`BIN_DIR` and its `/bin/` tree were retired with the agent swap); each defaults to a subdirectory of `NOO_DATA_ROOT`. `HF_CACHE_DIR` is an **HF_HOME** — the store serves its `hub/` subtree, not the directory itself (above) |
| `HF_HUB_OFFLINE=1` | injected into the backend container | Set only after a successful HF preseed |
| `NOO_OLLAMA_REGISTRY` | the CLI's environment on the controller | Base URL `noo models fetch ollama:<tag>` reads manifests and blobs from (default `https://registry.ollama.ai`); for a mirror |
| `NOO_ALLOW_OLLAMA_REGISTRY_PULL` | node-agent env | `1` lets that node `ollama pull` a tag the controller has not staged (default: refused on a placed node) |
| `NOO_IMAGE_SOURCE` | node-agent env | `rail` (default; everything above) or `legacy` (per-node opt-out: the pre-rail behaviour) |
| `NOO_IMAGE_REGISTRY_FALLBACK` | node-agent env | `public` (default) or `off`: may a third-party image the controller has not staged come from its public registry. Our own images are rail-only under both |

Code: `docker/model-cache.nginx.conf`, `node-agent-go/internal/preseed/`,
`node-agent-go/internal/docker/backends.go` (`preseedModel`,
`preseedGGUF`), `noo-cli/src/commands/cluster.rs` (`sync-model-files`),
`noo-cli/src/commands/models_fetch.rs` (`models fetch`),
`noo-cli/src/commands/ollama_stage.rs` (`models fetch ollama:<tag>`),
`node-agent-go/internal/docker/ollama_stage.go` + `ollama_model.go` (the node's import),

`preseedGGUF`), `node-agent-go/internal/docker/image_source.go` (`EnsureImage`),
`noo-cli/src/commands/image_stage.rs` (staging), `noo-cli/src/commands/cluster.rs` (`sync-model-files`),
`gateway-rust/src/heartbeat_actions.rs` (`model_cache_warm`).

