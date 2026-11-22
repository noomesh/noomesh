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
