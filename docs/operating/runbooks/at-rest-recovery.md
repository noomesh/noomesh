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

## 2. Open it with the recovery key

The recovery key was shown once when the volume was made. It works as a
passphrase:

```bash
sudo cryptsetup open /var/lib/noo/state.luks2 noo-state   # type the recovery key
sudo mount /var/lib/noo/state                             # the fstab entry
noo stack start
```

Use your own data root in place of `/var/lib/noo`. Never paste the recovery
key into a chat, a ticket or a shell history.

## 3. Make the TPM unlock again

Once the machine is in the state you want it to boot in (the firmware update
done, Secure Boot as you want it), enroll the TPM again and remove the stale
enrollment. You are asked for the recovery key:

```bash
# Secure Boot on: bind PCR 7
sudo systemd-cryptenroll --wipe-slot=tpm2 --tpm2-device=auto --tpm2-pcrs=7 /var/lib/noo/state.luks2
# Secure Boot off: TPM-only (an explicit empty list)
sudo systemd-cryptenroll --wipe-slot=tpm2 --tpm2-device=auto --tpm2-pcrs= /var/lib/noo/state.luks2
```

Never bind the firmware PCRs (0 or 2): a BIOS update would lock the machine
out again. Reboot once to prove the unattended unlock, then run
`noo cluster verify --controller`.

## No recovery key

A volume made without a terminal has none yet (`at-rest recovery key` warns
"deferred"), and a key that was lost cannot be recovered from the machine.
While the TPM still unlocks the volume, make a new one and store it offline
(the recovery-key verb, a later 0.6.11 step). If the TPM no longer unlocks it
and there is no recovery key, the data on the volume cannot be read: restore
from the encrypted backups (`docs/operating/runbooks/backup-restore-secrets.md`).
