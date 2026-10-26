# Moving an existing controller onto the encrypted state volume

`noo security at-rest migrate` moves the sensitive state of a controller that
is already running (postgres, redis, nats, prometheus, grafana, loki, noo-data,
the PKI, and the `claude-config` and `alertmanager-data` volumes) onto the
TPM-unlocked LUKS2 volume that `noo security at-rest create-volume` makes. It
is built to be stopped at any point and to be undone.

This protects against a stolen or lost disk or machine. It does not protect
against someone with admin access to the running machine.

## What it will and will not do

- It takes a FRESH backup first, restores it into a throwaway Postgres
  (`scripts/restore-drill.sh`) and records the sha256 of every artifact in the
  journal `<install root>/.noo-at-rest-migrate.json`.
- It wants proof a copy left this machine: the backup script's `offsite:
  copied` line, or you typing `backup is only on this machine` (or passing it
  to `--confirm-offbox`). A backup that lives on the disk being migrated is
  not a backup of the disk being migrated.
- It copies the plaintext directories (read only) with `rsync -aHAXS
  --numeric-ids` as root through `sudo noo-hostd at-rest copy`, first while the
  stack runs, then again with the stack stopped (`--delete`), then runs a
  `--checksum` dry-run that must show zero differences.
- It changes `.env` only after that (`NOO_STATE_ROOT`, `NOO_PKI_DIR`,
  `NOO_PG_DATA` if it was set, the TLS paths under the old PKI directory,
  `NOO_CLAUDE_CONFIG_VOLUME`, `NOO_ALERTMANAGER_VOLUME`). The original `.env`
  is saved byte for byte as `.noo-at-rest-migrate.env.orig`.
- It never deletes the old plaintext. That is a separate verb.

The size is measured as root (`sudo noo-hostd at-rest measure`), because the
database directory is not readable by the operator. The volume is twice the
measured state, at least 50 GiB. If the measurement fails or is partial, the
migration refuses; it never falls back to the minimum. It also refuses when the
data disk cannot hold the volume plus a 5 GiB margin.

## Steps

```bash
noo security at-rest migrate --dry-run      # prints every step, touches nothing
noo security at-rest migrate                # asks once, then runs
```

Run it at a terminal. If the volume does not exist yet it is created (the
recovery key is shown once: store it off the machine). The stack is stopped
for the final copy only: plan for roughly the time it takes to copy the state
again.

If anything fails, nothing past that step has run. Fix the cause and run the
same command again: it resumes at the first step the journal does not show as
done. The journal is the record; do not delete it.

## Go back

```bash
noo security at-rest migrate --rollback
```

Stops the stack, puts the original `.env` back (the switched one is kept as
`.env.pre-rollback-<time>`), starts it. The plaintext directories were only
ever read, so the old install is exactly as it was. The volume stays, so a
later `migrate` starts from a copy that only needs topping up.

Rollback stops working once the plaintext is wiped. After that, recovery is
from the backup (`docs/operating/runbooks/backup-restore-secrets.md`).

## Delete the old plaintext

```bash
noo security at-rest wipe-plaintext --dry-run
noo security at-rest wipe-plaintext
```

Refused unless the migration completed, the backup taken FROM the encrypted
state still matches its journaled sha256, the stack has been healthy on the
encrypted state for the required time (24 hours; `--hours` changes it), the
stack is healthy right now, and you type `delete the plaintext state` (or pass
it to `--confirm`). It removes the old directories, removes the plaintext
`claude-config` and `alertmanager-data` docker volumes, and runs `fstrim`.

An SSD does not erase deleted blocks: until the keys are rotated, assume the
old plaintext could still be read off a stolen drive. Rotate keys next (the
age key, the CA and leaf keys, the DB and app secrets): that is part of the
i10a decision, not an extra.

## Test seam

`NOO_AT_REST_VOLUME=dir NOO_AT_REST_VOLUME_DIR=<dir>` makes a plain directory
stand in for the volume (no TPM, no sudo, rsync run directly). It exists for
the unit tests and the rehearsal; never set it on a real controller.
