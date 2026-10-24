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

## Symptoms

- `noo stack start|restart|rebuild` prints `REFUSED: not starting — the data
  root ... is not on its recorded filesystem` (or `does not exist`, `cannot be
  read`, `postgres was initialised ... but its data directory is empty`).
- hostd's boot restore logs `the data root is not on its recorded filesystem —
  stateful containers stopped, nothing started`, and the install
  root holds `.noo-data-root-refused` with the reason and the containers it
  stopped.
- `noo cluster verify --controller` shows `data root filesystem` as FAIL.

Nothing was created: the data root is never made by the check.

## 1. Look

```bash
findmnt -T <data root>            # what is mounted there now
lsblk -f                          # is the data disk present, with its UUID?
cat .noo-data-root-id             # what was recorded (UUID, source, target)
dmesg | grep -i -E 'nvme|ext4|I/O error'
```

## 2. Bring the disk back

A disk that fell off the bus usually needs a cold power cycle (full power off,
not a reboot). Check `lsblk -f` shows it, then `sudo mount <target>` (or let
fstab do it) and `findmnt -T <data root>` shows the recorded UUID. Then
`noo stack start`. Do not create the directory by hand to "make it pass".

## 3. The disk was replaced, or the root moved on purpose

Only then, once the data is where it should be and the root lists cleanly:

```bash
NOO_DATA_ROOT_RERECORD=1 noo stack start
```

This re-records the identity once. It does not bypass the postgres check: an
empty postgres data directory on an install that has run before is always
refused.

## Upgrades

On the first launch of a version that has this check, an install with no
record and a healthy data root (it exists and lists) is recorded with a notice;
nothing breaks. If the disk is already missing on that first launch and the
mountpoint is an empty directory on the root disk, that is indistinguishable
from a fresh install: record it from a healthy boot, not a degraded one.
