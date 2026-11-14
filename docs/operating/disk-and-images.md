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
add-on pinned one: clean those yourself (below).

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
disk_watermark` lets it act: dangling images and build cache first, then
superseded images of ours, on the controller and on every node.
`noo autonomy preview disk_watermark` puts it back.

**A WSL2 controller.** The distro's `.vhdx` file on Windows never shrinks by
itself; freeing space inside the distro does not free it on Windows.
`scripts/wsl-vhdx-compact.ps1` compacts it: it shuts WSL down, so schedule a
Windows-native copy of it (from an elevated PowerShell, copy it to
`%LOCALAPPDATA%\pai\` and register a weekly task that runs that copy). Named
volumes (`postgres-data`, `ollama-data`, `hf-cache`, …) hold your data and
model weights: no cleanup here touches them, and deleting from them is your
own decision. `docker system df -v` shows what holds the space.

## For agents

Directive. Facts are exact; do not infer beyond them.

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
