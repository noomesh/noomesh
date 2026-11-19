# Disk and images

noomesh keeps its own disk use in check: after an upgrade it removes old
images of its own, and a disk past its watermark can reclaim space by
itself once you allow it. This page says what it removes, what it never
touches, and how to see what it did. The first part is for people; the
second is the exact contract for agents and scripts.

## For people

**What goes after an upgrade.** Once a roll is verified, `noo upgrade
--stack` removes the images it has superseded: noomesh's own, and each
pinned add-on image's own repository, when no current or previous release
names them and no container uses them.

**What never goes.** An image any container uses, running or stopped.
Images that are not noomesh's or a pinned add-on's (your own builds, other
projects). Docker Hub images by short name, such as `redis:7`, even when an
add-on pinned one: clean those yourself (below). The stack itself pins two
Hub images (`nats`, `nginx`); they are listed among what to keep too, which
changes nothing for them, since a Hub short name is never removed anyway.

This is the only thing a roll removes images with. Up to 0.6.24 a roll also
removed unused noomesh images by itself, ignoring the setting; 0.6.25 retired
that, so its first roll removes nothing and lists what the next one would.

**Preview first.** The first roll that carries this only lists what it
would remove; later rolls remove. To keep previewing, or to turn it off, set
`cluster.image_retention` in `noomesh.yaml` ([values](#for-agents)).

**When it did not clean.** The roll prints why, and `noo cluster verify
--controller` keeps saying it in its `image retention` row until a roll
cleans. Cleanup waits until the controller's stack images and add-ons are
proven current, so a half-finished roll never deletes what you might roll
back to. A failing row about something else (certificates, backups, another
node) never stops it.

**Docker Hub leftovers.** List them with `docker images`, check no container
uses one (`docker ps -a --filter ancestor=<image>`), then
`docker image rm <image>`. Never add `-f`.

**When the disk fills.** The `disk_watermark` rule watches the controller
and every node. In preview it only reports what it would reclaim:
`noo autonomy decisions -l disk_watermark`. `noo autonomy live
disk_watermark` lets it act, in this order, on the controller and on every
node: dangling images; Docker build cache older than a week; stopped
leftover containers from an interrupted compose rename; noomesh's own Rust
build-cache volumes (only the labelled ones a source build makes, only
unused, and only when their checkout is gone or they sat idle a week); then
superseded images of ours. `noo autonomy preview disk_watermark` puts it
back. Its report names every build-cache volume it kept, and why (a
checkout still there and used recently, a last use it could not read, a
label or volume it could not inspect), so a large cache it left alone is
never a mystery.

**Before a GPU llama.cpp is placed.** llama.cpp on a GPU runs a CUDA
image of about 2.6 GB to download and 4 GB on disk. `noo cluster place
<node> llamacpp <model>` checks that the node has room for it first, unless
the node already has the image. A node that is short and does not have the
image is refused, with its free space and the space the image needs. To make room, run noo's own
cleanup on that node: `noo autonomy decisions -l disk_watermark` shows what
it would free, and `noo autonomy live disk_watermark` lets it act (both
above). Or run the model on the CPU: add `--on cpu`. `--force` places it
anyway, and its start then waits on the node until there is room. When noo
cannot tell (an older node agent, which does not say whether it has the
image or how much room it has, or an image staged by an older noo), the
placement goes through with a warning instead.

**A WSL2 controller.** The distro's `.vhdx` file on Windows never shrinks by
itself; freeing space inside the distro does not free it on Windows.
`scripts/wsl-vhdx-compact.ps1` compacts it: it shuts WSL down, so schedule a
Windows-native copy of it (from an elevated PowerShell, copy it to
`%LOCALAPPDATA%\pai\` and register a weekly task that runs that copy). Named
volumes (`postgres-data`, `ollama-data`, `hf-cache`, …) hold your data and
model weights: no cleanup here touches them, and deleting from them is your
own decision. The one kind of volume the disk rule ever removes is the
labelled Rust build cache above, never one of these. `docker system df -v` shows what holds the space.

## For agents

Directive. Facts are exact; do not infer beyond them.

**Identity.** A lock names an image by digest under the release's short name
(`gateway@sha256:<d>`). Each row is resolved BY DIGEST against
`docker image inspect` (RepoTags and RepoDigests, as JSON lists) and kept by
the image ID holding it, whatever the name: `ghcr.io/noomesh/<n>`,
`ghcr.io/noomesh/dhi/<n>`, a Docker Hub short name, a mirror prefix. A row no
local image holds (a node-only image on a controller) stays in the keep file
under its own name, `why` ending `; not on this host`, and protects nothing.
Docker Hub images the lock pins are therefore kept by the keep file, although
hostd never treats a Hub short name as ours to delete: both hold.

**Setting.** `cluster.image_retention` in `<root>/noomesh.yaml`: `live` |
`preview` | `off`. Unset: `preview` until one roll has listed something,
then `live`. No environment variable controls it.

**Files, on the controller** (`<root>` is the install root):

| path | written by | meaning |
|---|---|---|
| `<root>/.noo-host-spool/image-keep.json` | the CLI after a roll whose gate passed | what must be kept (exact digests, image IDs), our namespaces, its sources' SHA-256 |
| `<root>/.noo-host-spool/image-retention-report.json` | noo-hostd | every image judged: `remove`, `why`, `result`; `dry_run`, `bytes` |
| `<root>/.noo-host-spool/image-retention-blocked.json` | the CLI when the gate blocked | `{at, tag, rows}`; removed by the next roll whose gate passes |
| `<root>/.noo-image-retention-previewed` | the CLI after the first non-empty preview | the tag; absent or unreadable means "not previewed" |

On a node: `/var/lib/noo-node-agent/spool/image-keep.json` (the agent,
each reconcile pass, `max_age_seconds` 3600) and the report beside it.

**The gate.** Read from `noo --json cluster verify --controller --wait`,
`controller.checks[]`. Cleanup runs only when all of these hold; the exit
code is not read:

| row `name` | required state |
|---|---|
| `stack images` | `ok` (always required) |
| `add-on pins` | `ok` (required when any add-on is enabled) |
| `add-on containers` | `ok` for each enabled add-on (detail starts `<addon>:`); a `warn` ending `declares no containers, so they aren't checked` does not block |

Missing, unreadable, `warn`, `starting` or `fail` on a row above blocks. No
other row blocks.

**Blocked.** The roll prints `images: superseded images were NOT cleaned up:
blocked by <row (detail)>; …` and writes the blocked file. Fix the named row;
the next roll cleans.

**Row `stack images`** judges a running container by image ID against the
lock row whose digest resolves to its image's repository. Running containers
of which it matches none is `fail` (`the check matched none of the …`): a
check fault, which blocks.

**Every deleter of images, and its gate.** Nothing else removes images.

| deleter | runs | gate |
|---|---|---|
| hostd rung 5, superseded images | after a verified roll | the setting, the gate above, a current keep file |
| hostd reclaim rungs 1–5: dangling images; build cache older than 7 days; stopped `<12hex>_noo-*` rename orphans; unused `noo.cargo-docker-src`-labelled build volumes whose checkout is gone or idle 7 days (the dry run lists each kept one with its reason); superseded images of ours | disk past watermark | `disk_watermark` live |
| node agent `POST /cleanup/images` | the disk_cleanup heartbeat | dangling only; sent with `dry_run: true` |
| node agent deep clean | `clean --deep` | opt-in |
| `noo offboard` | the operator | the command |
| `scripts/noomesh-clean.sh`, `scripts/noomesh-rebuild.sh` | by hand (dev) | none on a roll |

**Verify row `image retention`:**

| verdict | detail begins | means |
|---|---|---|
| `warn` | `superseded images not cleaned since the roll to` | the gate blocked; the rows follow |
| `ok` | `not judged yet` | no rung has run with a keep file |
| `ok` | `<n> superseded image(s) of ours, … reclaimable; report only` | a preview |
| `ok` | `removed <n> superseded image(s) of ours` | a live run |
| `ok` | `nothing superseded` | nothing to remove |
| `warn` | `<n> superseded image(s) Docker refused to remove` | in use since; not removed |
| `warn` | `the last report cannot be read` | the report file is unreadable |

**After a roll, check:** the `image retention` row and the report's entries
with `"remove": true`. Every one must be under a namespace in the keep file.
Report any other entry as a finding.

**Place-time image space check (i1036).** `PUT
/api/cluster/nodes/{node}/placements/llamacpp` with desired state `running`,
on a node where llamacpp runs on the GPU (the target is not `cpu` and the
node can use the CUDA build: `placement_fit::llamacpp_runs_on_gpu`, twin of
the agent's `llamacppOnGPU`), is checked against the staged image it pulls
(the release's `llamacpp-cuda`, or an image of ours the body names):

| input | from |
|---|---|
| `free` | the node's heartbeat `image_store_free_bytes`: the least free bytes over Docker's data root, `/var/lib/containerd` and the agent's staging dir; a path that does not exist is skipped |
| `tar` | the staged tar's size in the controller's store |
| `unpacked` | `unpacked_bytes` in `staged-images.json`, recorded at stage time from `docker image inspect --format '{{.Size}}'` |
| `need` | tar + max(unpacked, 2 × tar, tar + 2 GiB) + 512 MiB: the node agent's same-filesystem formula (`image_space.go`), with the real unpacked size when it is larger than the agent's estimate |
| held | the node's `held_images` maps the staged ref to `true`, or its `image_sources` has a row with the staged image ID, or (an ID unknown on either side) the same ref: no check |
| not held | `held_images` maps the staged ref to `false` (the agent inspected it; Docker does not have it) |
| unknown | neither: no `held_images`, or none for that ref (an older agent, or one on another release tag) |

| case | answer |
|---|---|
| held, llamacpp on cpu, another backend, nothing staged, the node's arch unknown | not judged |
| not held, `free` and `need` known, `free < need` | 409; the message starts `<node> has <free> in its image store and does not hold <image>, which needs <need>`, where free reads `<X> GB free` and need reads `about <Y> GB to pull and unpack (tar <A> + unpacked <B> + margin <C>; …`, Y being A + B + C (each rounded up to 0.1 GB; the unpacked part is the larger of the recorded size and the agent's estimate), then `noo autonomy decisions -l disk_watermark` / `noo autonomy live disk_watermark`, then `--on cpu` |
| unknown, `free < need` | placed; one warning in `warnings` with the same numbers, saying `whether the node already holds it is unknown` |
| the same with `force: true` | placed; the refusal is in `warnings`, prefixed `forced past a disk shortfall:` |
| `image_store_free_bytes` absent (an older agent, or a disk it could not read) | placed; one warning in `warnings` |
| `unpacked_bytes` absent (staged by an older noo) | placed; one warning naming `noo cluster sync-images <node> -i <image>`, which restages it and records the size |

No ratio stands in for a missing size. On a node whose staging dir and
Docker data root are separate filesystems, the agent checks each one
separately and this check is stricter than the agent's.

**Commands:** `noo --json cluster verify --controller`;
`noo autonomy decisions -l disk_watermark`; `noo autonomy live disk_watermark`
and `noo autonomy preview disk_watermark` (operator decisions: do not run
them without the operator's word).

**Never:**
- remove an image with `-f`;
- delete or hand-edit `image-keep.json`, or the previewed marker to force live;
- reap containerd leases to free image space;
- prune named volumes;
- set `cluster.image_retention` or take `disk_watermark` live without the
  operator.
