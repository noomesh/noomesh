# At-rest recovery: the encrypted state volume did not open

A controller that said yes to encryption at rest (i10a) keeps its sensitive
state (postgres, redis, nats, prometheus, grafana, loki, noo-data, the PKI
and an escrow copy of the age key) on a LUKS2 volume backed by the file
`<data root>/state.luks2` and mounted at `<data root>/state`
(`NOO_STATE_ROOT`). At boot, `/etc/crypttab` opens it as
`/dev/mapper/noo-state` with this machine's TPM, with no person present, and
`/etc/fstab` mounts it. The record of what was made is `/etc/noo/at-rest.json`
(no secrets).

This protects against a stolen or lost disk or machine. It does not protect
against someone with admin access to the running machine.

## Symptoms

- `noo stack start` (or restart, rebuild) refuses: `REFUSED: not starting —
  the encrypted state volume is not open`.
- `noo cluster verify --controller` shows `at-rest volume` as FAIL.
- hostd's boot restore logs `the encrypted state volume is not open — not
  starting the stack`.

Nothing was started and nothing was changed: the launchers refuse rather than
run the services on the empty mountpoint (which is `chattr +i`, so nothing
can be written there while the volume is closed).

## 1. Look

```bash
systemctl status 'systemd-cryptsetup@noo\x2dstate.service'
journalctl -b -u 'systemd-cryptsetup@noo\x2dstate.service'
findmnt /var/lib/noo/state          # your data root + /state
sudo cat /etc/noo/at-rest.json      # volume_file, volume_pcrs, volume_mountpoint
```

The usual cause is a TPM that will not release the key: a firmware (BIOS/UEFI)
update or a Secure Boot change on a volume bound to PCR 7, a cleared TPM, or
the disk moved to another machine.

## 2. Open it with the recovery key (over ssh)

The recovery key was shown once when the volume was made (or when you last ran
`noo security at-rest recovery-key`). It works as a passphrase. With the
machine up but the stack refusing to start:

```bash
sudo cryptsetup open /var/lib/noo/state.luks2 noo-state   # type the recovery key
sudo mount /var/lib/noo/state                             # the fstab entry
```

Use your own data root in place of `/var/lib/noo`. Never paste the recovery
key into a chat, a ticket or a shell history. The volume is now open, but the
TPM still does not unlock it: fix that next, or the next reboot lands here
again.

## 3. Make the TPM unlock again

Once the machine is in the state you want it to boot in (the firmware update
done, Secure Boot as you want it):

```bash
noo security at-rest reenroll
noo stack start
```

`reenroll` runs `systemd-cryptenroll --wipe-slot=tpm2 --tpm2-device=auto
--tpm2-pcrs=<7|"">` on the device `cryptsetup status noo-state` names (you
are asked for the recovery key), and:

- binds PCR 7 when Secure Boot is on, and nothing (TPM-only, an explicit empty
  list) when it is off. The firmware PCRs 0 and 2 are never bound, so a BIOS
  update does not lock the machine out again; `--pcrs 0` or `2` is refused;
- reseals the age key when it was sealed (`noo-unseal.service`), from the
  escrow copy inside the volume. If this build has no seal verb yet, or the
  escrow is missing, it prints the exact `sudo noo-hostd at-rest seal-age-key
  …` line to run;
- updates `/etc/noo/at-rest.json` (PCR policy, Secure Boot state).

The recovery key is untouched. Reboot once to prove the unattended unlock, then
run `noo cluster verify --controller` (the `at-rest volume binding` and
`at-rest pcr binding` rows).

`reenroll` refuses when the volume is not open and says how to open it (step
2). It cannot help a volume you cannot open at all: see "Lost recovery key".

## A TPM that was cleared

A cleared TPM (BIOS "clear TPM", an fTPM reset after a BIOS update, a changed
owner) voids every TPM keyslot. The recovery key still works: follow steps 2
and 3. The stale slot is replaced by `reenroll`.

## Moving the drive to another board

A new board has a new TPM, so the volume will not unlock there by design.
Boot the new machine from a live system or the moved install, then follow
steps 2 and 3 on it. On a moved install the volume file path in
`/etc/noo/at-rest.json` must still be right (`sudo cat /etc/noo/at-rest.json`);
the `/etc/crypttab` and `/etc/fstab` lines come with the system disk, not the
data disk. If only the data disk moved, open the file by hand
(`sudo cryptsetup open <file> noo-state`, then mount it where `NOO_STATE_ROOT`
points) and restore the manifest and crypttab lines from a backup of `/etc`.

## Recovery keys

```bash
noo security at-rest recovery-key
```

Run it at a terminal while the TPM still unlocks the volume. It enrolls a NEW
recovery key, shows it once (you retype its first and last groups), and only
then removes the old one, so you are never left with none. If you do not
confirm the new key, the old one is kept and verify warns. This is also how a
volume made with `--defer-recovery-key` (unattended onboarding) gets its first
recovery key: until then `at-rest recovery key` warns "deferred" and a TPM
failure loses the data. If the TPM no longer unlocks the volume, run
`reenroll` first (with the old key), then this.

## Lost recovery key

A key that was lost cannot be recovered from the machine. While the TPM still
unlocks the volume, make a new one (above) and store it off the machine. If the
TPM no longer unlocks the volume and there is no recovery key, the data on the
volume cannot be read: restore from the encrypted backups
(`docs/operating/runbooks/backup-restore-secrets.md`), onto a new volume
(`noo security at-rest create-volume`).

## Before and after a firmware update

Before a BIOS/UEFI update, a fwupd run, or any Secure Boot change:

```bash
noo security at-rest preflight-firmware
```

It checks that the recovery key exists and was acknowledged, that a backup
newer than 24 hours exists, that the volume's binding matches Secure Boot now,
and warns about the two things no check can see: an AMD fTPM (or Intel PTT)
that a BIOS update can reset, and a fwupd dbx (Secure Boot database) update,
which changes PCR 7. Fix any FAIL first (`noo security at-rest recovery-key`,
`scripts/backup-controller.sh`).

After the update: reboot. If `noo cluster verify --controller` is green, you
are done. If the stack refuses to start, open the volume with the recovery key
(step 2), then `noo security at-rest reenroll` (step 3), then
`noo stack start`.
