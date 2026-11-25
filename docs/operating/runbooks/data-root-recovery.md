# Data root recovery: the data disk is missing, unreadable or replaced

The stack records which filesystem its data root lives on (`.noo-data-root-id`
beside `.env`: the filesystem UUID, or the mount source and target when it has
none) and checks it at every launch, before compose starts anything, and again
when hostd restores the stack at boot. It refuses when the data root does not
exist, cannot be listed (an I/O error), or is on a different filesystem than
the one recorded, for example the root disk because the data disk did not
mount.

Why: postgres device-binds `<data root>/postgres`. With the disk absent, docker
makes the missing path on the root disk and postgres initialises a brand-new
EMPTY database there, and the gateway comes up on it (2026-10-24 near miss: the
data NVMe dropped off the bus; ext4 went read-only; postgres crash-looped).

## For people

### Symptoms

- `noo stack start|restart|rebuild` prints `REFUSED: not starting — the data
  root ... is not on its recorded filesystem` (or `does not exist`, `cannot be
  read`, `postgres was initialised ... but its data directory is empty`).
- hostd's boot restore logs `the data-root guard refused ... stateful
  containers stopped, nothing started`, and the install
  root holds `.noo-data-root-refused` with the reason and the containers it
  stopped.
- `noo cluster verify --controller` shows `data root filesystem` as FAIL.

Nothing was created: the data root is never made by the check.

### 1. Look

```bash
findmnt -T <data root>            # what is mounted there now
lsblk -f                          # is the data disk present, with its UUID?
cat .noo-data-root-id             # what was recorded (UUID, source, target)
dmesg | grep -i -E 'nvme|ext4|I/O error'
```

### 2. Bring the disk back

A disk that fell off the bus usually needs a cold power cycle (full power off,
not a reboot). Check `lsblk -f` shows it, then `sudo mount <target>` (or let
fstab do it) and `findmnt -T <data root>` shows the recorded UUID. Then
`noo stack start`. Do not create the directory by hand to "make it pass".

### Enrollment refused: the mount is not there

Enrolling a node never creates a data root that a boot-time mount would hide.
When the data root is under a mount the machine declares for boot (an
`/etc/fstab` entry without `noauto`, or an enabled systemd mount unit) and that
mount is not mounted, enroll stops with `<data root> is under the mount
<mount> declared in <fstab or unit>, which is not mounted` and creates
nothing: at its preflight (a `FAIL` line, before the token is spent), and again
in host prep (`FATAL`, exit 1). An automount is touched once first. Mount it
(`sudo mount <mount>`, check `findmnt <mount>`), then run the enroll line
again (after a `FATAL` the token is spent: mint a fresh one). If prep cannot
read the fstab, the unit directories or the mount table, it says so once and
goes on as before.

### No findmnt (Linux)

`REFUSED: not starting — findmnt is not installed` means the host has no
util-linux, so the check cannot see which filesystem holds the data root, and
a check that cannot look does not pass. Install it (`apt install util-linux`,
`apk add util-linux`), then `noo stack start`. `NOO_DATA_ROOT_RERECORD=1` does
not apply (there is nothing to record), and hostd's boot retries do not help
either. `noo cluster verify --controller` shows the row as FAIL with the same
fix. macOS has no findmnt and is never a controller: there the check is
skipped with a warning.

### 3. The disk was replaced, or the root moved on purpose

Only then, once the data is where it should be and the root lists cleanly:

```bash
NOO_DATA_ROOT_RERECORD=1 noo stack start
```

This re-records the identity once. It does not bypass the postgres check: an
empty postgres data directory on an install that has run before is always
refused.

### A network mount that stopped answering

A data root, model store or HF cache on NFS or SMB can stop answering when its
server goes away (a power cut at the storage host). A hard NFS mount does not
fail: every call that touches it waits, in D state, until the server is back.

- `noo upgrade --stack`, `--nodes` and `--all` check this first. A network
  mount under `NOO_DATA_ROOT`, `MODELS_DIR` or `HF_CACHE_DIR` that does not
  answer a `stat` in 5 s stops the upgrade with one line naming the mount, before
  anything is changed. If `docker inspect` of the gateway does not answer in
  30 s the upgrade stops the same way.
- `noo cluster verify --controller` shows the `network mount` row as FAIL
  with the same words; it is OK when there are no network mounts.
- **Bring the storage back** (power the storage host, restore its network). A
  hard NFS mount resumes by itself once its server answers; then rerun
  `noo upgrade`. **Do not force-unmount it** (`umount -f`, `umount -l`):
  that drops writes the clients still hold.
- To see whether a mount answers: `timeout 5 stat <mount>` (exit 124 means it
  did not).

### Upgrades

On the first launch of a version that has this check, an install with no
record and a healthy data root (it exists and lists) is recorded with a notice;
nothing breaks. If the disk is already missing on that first launch and the
mountpoint is an empty directory on the root disk, that is indistinguishable
from a fresh install: record it from a healthy boot, not a degraded one.

### Nodes: the agent's own check (0.6.30)

Each Linux node agent checks its own data roots (`NOO_DATA_ROOT`, plus
`HF_CACHE_DIR`, `MODELS_DIR` and `OLLAMA_DATA_DIR` when they are set
elsewhere) from the kernel's mount table. It keeps a record of each root's
filesystem in its state directory (`/var/lib/noo-node-agent/data-root-fs.json`).
On macOS the agent does not run this check; the rest of the data-root policy
still applies.

**Mount or plain directory.** There is no setting for this. The agent reads
what the machine already declares for boot. A root is a **mount** when a
boot-time mount covers it: an `/etc/fstab` line, or a systemd mount unit in
`/etc/systemd/system` or `/run/systemd/generator*`. A line or unit with
`noauto` does not count, unless it is also an automount
(`x-systemd.automount`). A unit counts only when it is enabled (a link to it
in a `*.wants/` or `*.requires/` directory, as `systemctl enable` and the fstab
generator make). A masked unit, or one that is present but not enabled, does
not count. Anything else is a **plain directory**. The `data root
policy` row in `noo cluster verify` shows which: `mount (fstab)`, `mount
(systemd unit)`, `mount (recorded)` (it was on its own disk at a good start,
with no boot-time mount declared) or `directory`.

An absent `/etc/fstab` or unit directory (a container, a host without
systemd) declares nothing: the agent reads it as no entries and checks what
the rest declares.

**"Cannot tell" never refuses.** Sometimes the agent cannot read or parse
`/proc/self/mountinfo` (missing included), or an `/etc/fstab` or unit
directory that is there (permission denied, not a file or directory,
garbage). Then the part of the check that needs it is **not checked**, and
nothing is refused for it. Verify's `data root policy`
row says `not checked: <why>`. Only a positive finding refuses: a covering
boot-time mount that is not mounted, or a filesystem that differs from the
record. When the mount table cannot be read, the agent makes no comparison,
even with a record, because a failed read is not evidence of a different
disk. A root on the root disk whose boot-time declarations cannot be read is
neither refused nor recorded.

**What the agent refuses, and when.** There are three cases:

- **Absent at start** (`mount_missing`): a boot-time mount covers the root and
  nothing is recorded yet, but the mount is not there. For an automount, the
  agent first touches the path once (bounded at 5 s) to trigger the mount,
  then looks again.
- **Not on its recorded filesystem** (`not_on_recorded_fs`): for example, the
  disk did not mount, so the root is now an empty directory on the root disk.
- **Not answering** (`not_answering`): a probe of the root, or the touch that
  triggers an automount, takes longer than 5 s. A hard NFS mount or a failing
  disk does this. The heartbeat still goes out.

While a root is refused, the agent does not do these things:

- start a backend;
- accept a host path from the controller under that root (the placement's
  models directory, bind sources);
- create a directory under that root for a model fetch or import (a GGUF
  pull, an HF weight preseed, a model set).

Warn mode refuses these too. `NOO_DATA_ROOT_POLICY=warn` relaxes only the
shape and ownership rules. The check gates starts and writes; it does not stop
a backend that is already running.

The refusal clears by itself. The agent checks again on every use: every
backend start, every fetch, every reconcile tick and every heartbeat. The
first check that passes logs `data root <path> is mounted now; the refusal is
cleared` once. A network mount that is late at boot (`_netdev`, NFS, CIFS)
clears the same way when it arrives. No command is needed.

**First start, including the 0.6.30 roll on an existing node.** Nothing is
recorded before 0.6.30, so the first start of a 0.6.30 agent is the first
look:

- A root under a boot-time mount that is mounted gets recorded.
- A root under a boot-time mount that is NOT mounted is refused
  (`mount_missing`), and nothing is recorded.
- Any other root is recorded where it is, as a plain directory, even when it
  is on the root disk.

**Which way the filesystem changed matters.**

- **Recorded on the root disk, now on its own disk:** the disk arrived, for
  example a disk mounted by hand or by the desktop that was absent at the
  first look. The agent accepts it and records the new disk, with one log
  line. No command is needed.
- **Recorded on its own disk, now on the root disk:** the mount is missing.
  The agent refuses (`not_on_recorded_fs`).
- **Recorded on one disk, now on a different one:** another disk is mounted
  there. The agent refuses (`not_on_recorded_fs`).

Files can end up hidden under the mount. At the first look the agent records
how many entries the root holds when it is on the root disk (one directory
listing, counted up to 10 000). If that count was not zero when the disk
arrives, whatever the node wrote there is now hidden beneath the mount. The
log line and the `data root policy` row in verify then say: "the disk is now
mounted at `<root>` since `<date>`: `<N>` files written before it was mounted
are hidden under the mount point on the root filesystem: unmount to recover
or remove them; this note clears by itself on `<date + 7 days>`" ("at least
`<N>`" past the cap). Verify shows the note for 7 days after the disk
arrived, then drops it; nothing on the node needs to be run to clear it.

**What noomesh creates or changes in a data root.**

- **The node agent** runs as its own unprivileged account. It never chmods a
  data root. It creates directories under a root only after the check above
  passes:
  - its own subdirectories (the models directory, HF cache repo folders,
    model-set folders);
  - the placement's models directory, under a root this node declared. The
    agent then tries to change that directory's owner to the backend's user.
    A change it is not permitted to make is logged once and skipped.

  A plain-directory root that is missing outright is not a filesystem
  refusal. Under the applier's systemd hold, the agent cannot create the root
  itself, because its parent is read-only to the agent. Verify's remedy for
  that case is `install -d`, which you run.
- **The node applier** (`noo-apply`, root, run for each bundle) never creates
  or chmods a data root. It does two narrower things:
  - grants the agent's account execute-only traverse (an ACL) on an existing
    parent directory that refuses it;
  - re-owns `hf-cache/hub` to the agent's account, but only when that
    directory is owned by root under an agent-owned `hf-cache`. It changes
    the owner only, never the mode.
- **The node's install script** (`prep-host`, which you run once with sudo
  when you enroll the node) does more:
  - creates the data root when it does not exist;
  - creates `hf-cache`, `models` and `ollama`, and re-owns `hf-cache` and
    `models` to the agent's account;
  - grants the installing user an ACL on `models`.

**The fix** is to mount the disk (`findmnt <data root>`, your fstab or mount
unit). Never create the directory: the mount would hide it, along with
anything written there. After a deliberate disk change, remove the record
file on the node, and the agent records the new disk at its next check.
This applies only when a different disk replaced the recorded one. A disk
that arrives over a root recorded on the root disk is recorded by itself.

## For agents

The refusal is the guard working: it stops postgres from starting an empty
database on the wrong disk. Never work around it.

- **Diagnose, read-only:** `noo --json cluster verify --controller` (the
  `data root filesystem` row), `findmnt -T <data root>`, `lsblk -f`, and the
  install root's `.noo-data-root-id`. Where the reason is depends on who
  refused: a refused `noo stack start` prints it on stderr; only hostd's
  boot restore writes it to `.noo-data-root-refused` in the install root
  (or `NOO_DATA_ROOT_REFUSED_FILE`), with the containers it stopped.
  Report what each shows.
- **The person's, never yours:** power-cycling the machine, mounting the
  disk (`sudo mount`), installing util-linux, and re-recording the identity
  with `NOO_DATA_ROOT_RERECORD=1 noo stack start` (only after a disk was
  replaced or the root moved on purpose, and only once the data is where
  it should be).
- **Never** create the data root directory by hand, and never set
  `NOO_DATA_ROOT_RERECORD=1` to get past a refusal: it records whatever
  disk is mounted now as the right one.
- **Enrollment refused** (`... which is not mounted`): mounting it is
  the person's; never create the directory or comment out the fstab entry
  to get past it. Once `findmnt <mount>` shows it, re-run the enroll line.
- **Once the disk is back** (the recorded UUID shows in `findmnt`),
  `noo stack start` is safe to run.
- **On a node** (`data root policy` FAIL with `not_on_recorded_fs`,
  `mount_missing` or `not answering`): the agent refuses on its own and
  clears when the mount answers. Diagnose read-only (`findmnt <root>`, `cat
  /var/lib/noo-node-agent/data-root-fs.json`, `dmesg`). Mounting the disk,
  and removing the record after a deliberate disk change, are the person's.
  Never `install -d` the root while its mount is missing.
