# Backup, restore and secrets

Everything needed to keep a controller recoverable: what is backed up, how
to prove it, how to restore it, and how to rotate the keys that protect
it. Prove the backups are real:

```sh
cd ~/.noo                     # the install root on a standalone controller (the scripts ship in its deploy slice); your checkout on a dev box
scripts/restore-drill.sh      # restores the newest dump into a throwaway container and decrypts env.sops from the age-key backup; exit 0 = both paths work
```

Read [Recovery model](#recovery-model) before an incident. Under pressure
the tempting move is to restore the newest thing you can find; the
ordering below exists because the database is worthless without the
secrets that run it.

## Recovery model

Two independent artifacts. **You need both.** Losing either one alone is
a total loss of the system as it exists today.

| Artifact | What it is | If lost |
|---|---|---|
| `pg_<ts>.sql.gz.enc` | the system of record — conversations, knowledge base, graph, node registry, config | everything since the last good dump |
| `pgroles_<ts>.sql.enc` | the `noo_*` login roles the dump refers to (names and attributes, **no passwords**), as an idempotent script; same timestamp as its dump | the dump still loads, but only after you pre-create the roles by hand (see [Restoring an old backup by hand](#restoring-an-old-backup-by-hand)) |
| `age-key_<ts>.txt.enc` | the age private key that decrypts `secrets/env.sops` | **every secret is unrecoverable, permanently** — no passwords, no JWT secret, no cluster secret; the stack cannot start |

Both are written to `$NOO_BACKUP_DIR` (default `~/noo-backups` in the home of
the user that runs the script, owner-only; it does not follow the data root). Postgres is the system of record; Redis is deliberately not
backed up — it holds reconstructible state (queues, cache, rate limits,
autonomy counters).

### The two passphrases

| Variable | Protects | Must be |
|---|---|---|
| `NOO_BACKUP_PASSPHRASE` | the Postgres dumps | stored off-machine |
| `NOO_AGE_BACKUP_PASSPHRASE` | the age-key backup | **independent** of the first, stored off-machine |

They must differ. `NOO_BACKUP_PASSPHRASE` may live in `env.sops`; if the
age-key backup were protected by that same value, recovery would be
circular — you would need the age key to read the passphrase that
decrypts the age key. Both go in a password manager *before* you need
them; `.env` is on the machine you just lost. Each also accepts a
`_FILE` variant naming a file that holds it.

## Where backups should live

1. **Off the machine.** A backup of the controller's key stored on the
   controller protects you from nothing.
2. **Separate the file from its passphrase.** Same drive, same folder,
   same cloud account means the encryption is decoration.
3. **Prove it.** `restore-drill.sh` is the only evidence any of this works.

A concrete arrangement: the age key itself → password manager (secure
note); `age-key_*.txt.enc` → a second location (USB key, or a cloud
account distinct from the passphrase's); `pg_*.sql.gz.enc` → bulk storage
(NAS, object store — a new one lands every day). On WSL2, `~` lives inside
the distro's `.vhdx`; a copy on the Windows drive survives a distro reset but is
the same physical machine — a waypoint, not a destination.

## Routine operations

The scripts read the passphrases from the environment. noo-hostd
loads them from `secrets/env.sops` before every scheduled run; for a
manual run, load them the same way:

```sh
cd ~/.noo    # install root on a standalone controller; your checkout otherwise
. scripts/lib-secrets.sh && load_secrets      # exports env.sops into this shell (needs sops + the age key)
```

### Take a backup now

```sh
scripts/backup-controller.sh
```

Writes `pg_<ts>.sql.gz.enc` (AES-256, openssl `-pbkdf2`), the matching
`pgroles_<ts>.sql.enc` (same passphrase; `pg_dump` is per-database and
Postgres roles are cluster-wide, so without this file the dump's
`OWNER TO noo_trellion_ddl` / `GRANT ... TO noo_app` statements fail on a clean
server), and, when
`NOO_SECRETS_BACKEND=sops`, `age-key_<ts>.txt.enc`.

**Encryption is not optional.** Without a passphrase the script refuses,
before it dumps anything, and exits non-zero — so noo-hostd records
`ok:false`, and the gateway's completion hook fails the `database_backup` run
and raises an operator alert (see [Scheduling](#scheduling-and-how-it-runs)).
It refuses in three cases:

| Condition | Why |
|---|---|
| no `NOO_BACKUP_PASSPHRASE` | there is no unencrypted dump to fall back to |
| an age key exists and no `NOO_AGE_BACKUP_PASSPHRASE` | it used to copy the age **private key in plaintext** into `~/noo-backups` |
| the two passphrases are equal | recovery would be circular — see below |

There is no opt-out switch. There used to be one
(`NOO_BACKUP_ENCRYPT_REQUIRED`, an opt-in defaulting to off), and because nothing
ever set it the dangerous default was the only behaviour that ever ran.

noo-hostd also refuses to run the backup at all if `load_secrets` fails,
rather than running it with no passphrases in the environment.

**If your box has plaintext leftovers** from before 2026-09-11:

```sh
ls -l ~/noo-backups/age-key_*.txt      # plaintext private keys, if any
scripts/backup-controller.sh           # write a fresh .enc copy
scripts/restore-drill.sh               # prove it opens
shred -u ~/noo-backups/age-key_*.txt   # then destroy the plaintext
```

`restore-drill.sh` fails while any plaintext `age-key_*.txt` remains.

### The cold-storage archive is in the backup

Retention archives expired audit partitions and agent mail under
`/data/audit-archive` on the gateway's volume and then deletes them from
Postgres, so the dump above does not contain them. `backup-controller.sh`
therefore also writes `archive_<ts>.tar.enc` (the whole directory, AES-256 with
`NOO_BACKUP_PASSPHRASE`, a full snapshot each time; the newest three are always
kept and older ones age out with the dumps). It is copied offsite with the
dump and carried by `noo-backup-export.sh`. A run that cannot back it up fails.
Restore: `openssl enc -d -aes-256-cbc -pbkdf2 -in archive_<ts>.tar.enc | tar -x`
and copy the files back into `/data/audit-archive`. The agent-mail bodies in it
are sealed with `NOO_AGENT_REVIEW_KEY`; keep that key as safe as the age key.

### Getting a copy off the machine

Everything above — the dumps, the Postgres volume, the encrypted age key —
is on one disk. Losing it loses the data and the means to read it back,
together. `NOO_BACKUP_OFFSITE` says where a copy goes, and unset is a
third state: not "no", but "nobody has decided".

```sh
noo backups status                     # is a copy leaving this box?
noo backups setup                      # decide, once
noo backups setup --set dir:/mnt/usb   # or answer directly
```

| Answer | What happens |
|---|---|
| `ssh:user@host:/path` | each new artifact is `scp`'d to another machine |
| `dir:/mnt/disk` | copied to a mounted disk — external drive, NAS |
| `s3:s3://bucket/prefix` | handed to `aws s3 cp` or `rclone copyto` |
| `portable` | nothing automatic; run `scripts/noo-backup-export.sh` and carry the bundle |
| `none` | nothing leaves, recorded as a decision rather than an oversight |

`portable` is the honest answer for a box with no second host and no
network target. A failed copy never deletes or fails the local backup, but
it does exit non-zero, so noo-hostd records `ok:false` and the
completion hook fails the `database_backup` run and alerts — a copy that silently stopped
working is the same as no copy, found at the worst moment.

Retention: dumps keep `NOO_BACKUP_RETAIN_DAYS` (7) with a floor of
`NOO_BACKUP_KEEP_MIN` (3) newest regardless of age, and retention is
skipped entirely on any run that produced no new dump — a Postgres outage
can never delete your last backups. Age-key backups keep the newest three
and are never age-pruned.

### Verify backups are restorable

```sh
scripts/restore-drill.sh [backup-file]
```

Restores the newest dump (or the one named) into a uniquely named
throwaway Postgres container — never `noo-postgres` — applying the
`pgroles_<ts>.sql.enc` beside it first (a backup with no roles file gets the
known `noo_*` roles pre-created `NOLOGIN`, and the drill says so). Both steps
run with `ON_ERROR_STOP`: a failed restore stops at, and prints, the first
error rather than hundreds. The sanity checks look in the `mesh`, `public`,
`trellion` and `evolve` schemas and tell "restore failed" from "table missing"
from "restored but empty". Then decrypts `secrets/env.sops` using only a restored copy of
the newest age-key backup: the exact fresh-machine path. It **fails** if
SOPS is in use but no age-key backup exists; a drill that reports PASS
while your secrets are unrecoverable is worse than no drill. Run it after
any change to backups, and monthly.

### Where the passphrases come from

`noo onboard` generates both into the secret store (`NOO_BACKUP_PASSPHRASE`
and `NOO_AGE_BACKUP_PASSPHRASE` in `.env` → `secrets/env.sops`) and, on a
console with a real terminal, **shows you both once** and waits for you to
confirm you stored them. Under `--non-interactive`, `--tui` or `--web` it
shows nothing and prints the command to run later. An install from before
2026-09-11 has neither; mint them with
`noo security secrets rotate NOO_BACKUP_PASSPHRASE NOO_AGE_BACKUP_PASSPHRASE`.

### Read a passphrase back

```bash
noo security secrets reveal NOO_AGE_BACKUP_PASSPHRASE
noo security secrets reveal NOO_BACKUP_PASSPHRASE
```

Prints the value once on the terminal, offers the clipboard (cleared after
45 s where the platform supports it), and appends name + time + digest —
never the value — to `secrets/reveal-audit.log`. It **refuses** when stdout is
not a terminal, so `noo security secrets reveal ... | tee` cannot put a
passphrase in a log by accident; pass `--stdout` if capturing it is genuinely
what you want. `--no-clipboard` skips the clipboard entirely.

Only these two names work. The age private key itself is refused outright —
carry it off-box as the encrypted `age-key_*.txt.enc` backup, which this
passphrase opens. See
[security/secrets.md](../../security/secrets.md#secrets-a-human-must-hold).

### The plaintext file that used to linger

Before 2026-09-11 onboard also wrote `secrets/age_backup_passphrase.txt` and
`secrets/backup_passphrase.txt` in the clear, and nothing removed them. If
this controller is older than that:

```bash
noo security scan                                       # CRITICAL: names the file
noo security secrets reveal NOO_AGE_BACKUP_PASSPHRASE   # read it, store it off-box
                                                        # answer y when it offers to shred the file
noo security scan                                       # clean
```

`noo onboard` makes the same offer on its next run, and refuses to shred a
file whose value it cannot find anywhere else — shredding the only copy of a
passphrase is the one outcome worse than leaving it on disk.

`NOO_AGE_BACKUP_PASSPHRASE` **must also be kept off this machine.** It is the
key to the key: it protects the age private key that decrypts every other
secret, and it is itself stored in `env.sops`, which that same age key
decrypts. On a running box that circle is harmless. Once the box is gone it is
fatal — you would hold an encrypted age-key backup and the passphrase for it
only inside the thing the age key opens. Copy it into a password manager the
day it is generated, and keep the `age-key_*.txt.enc` files somewhere else
again.

### Rotate a passphrase

```sh
noo security secrets rotate NOO_AGE_BACKUP_PASSPHRASE                              # one
noo security secrets rotate NOO_BACKUP_PASSPHRASE NOO_AGE_BACKUP_PASSPHRASE        # both
noo security secrets rotate NOO_AGE_BACKUP_PASSPHRASE --dry-run                    # preview
```

One command does all four parts, in this order, and abandons the whole run on
any failure:

1. mints the new value in memory;
2. hands it to you on the terminal and waits for you to type `stored`;
3. prepares the replacement store (decrypt → edit ONLY that key → re-encrypt →
   **diff the key set and refuse on any loss** → round-trip verify) and
   re-encrypts every matching backup file old → new, verifying each, with no
   original touched yet;
4. installs the store by atomic rename, then installs the re-encrypted files.

`--dry-run` prints the file count and the store path and touches nothing.

The handover in step 2 is not optional and not skippable: these two secrets
have no consumer on the box — a *person* is the consumer — so a generated
value that does not reach you has not been rotated, it has been destroyed,
along with access to every file step 3 just re-encrypted. So it prints to a
terminal only, records the handover in `secrets/reveal-audit.log` (name, time,
who, digest — never the value), and refuses outright when stdout is a pipe or
`--json` is set. `--stdout` overrides the pipe case if a captured value is
genuinely what you want.

If you already hold the value (recovering a box, or matching a sibling), pass
it in instead of generating one:

```sh
<your password manager> | noo security secrets rotate NOO_BACKUP_PASSPHRASE --set-from-stdin --yes
```

The two are refused if they would end up **equal** — including the case where
you rotate one onto the value the other already holds, which is what copying
between two password-manager panes does by mistake.

**Never just edit the value.** Existing backups stay encrypted with the old
passphrase, so a hand edit silently makes every backup you hold unopenable the
moment the old value is forgotten. That is the whole reason rotation owns the
files as well as the value.

`scripts/noo-backup-rotate-passphrase.sh --age|--pg|--both` still works; it is
a thin wrapper that execs the verb. Before 2026-09-12 it was not a wrapper,
and what it implemented was an outage: it treated `.env` as the plaintext
source and re-encrypted `secrets/env.sops` **from** it, a full replace that on
a sops-first install would have reduced a ~30-secret store to `.env`'s two
bootstrap flags, and written both passphrases there in plaintext. It had never
been run; it was caught in `--dry-run` on the live controller (tracker R42).

### Rotate the age key itself

The age key is the root of trust for `secrets/env.sops`; rotating it
means re-encrypting the store to the new recipient
(`scripts/noo-secrets-sops-init.sh` sets one up from scratch). The
secrets model, key rotation and the `noo security secrets` verbs
(`audit`, `resync`, `rotate`, `absorb-files`) are in
[security/secrets.md](../../security/secrets.md). After rotating, **take a
fresh backup**: the old `age-key_*.txt.enc` files protect a key that no
longer opens `env.sops`.

## Restoring for real

### Restore the database

```sh
# 1. stop consumers so nothing writes mid-restore
noo stack stop

# 2. bring the stack up through the launcher (so Postgres gets its secrets), then stop the writers
noo stack start
docker stop noo-gateway noo-worker noo-trellion noo-trellion-intel 2>/dev/null

# 3a. roles first (skip if the stack already provisioned them; the script is idempotent).
#     No pgroles_<ts>.sql.enc for this backup? See "Restoring an old backup by hand".
BACKUP_PASS="$NOO_BACKUP_PASSPHRASE" openssl enc -d -aes-256-cbc -pbkdf2 \
    -pass env:BACKUP_PASS -in ~/noo-backups/pgroles_<ts>.sql.enc \
  | docker exec -i noo-postgres psql -q -v ON_ERROR_STOP=1 -U noo -d noomesh

# 3b. then the data (.enc; for a plain .sql.gz skip the openssl step)
BACKUP_PASS="$NOO_BACKUP_PASSPHRASE" openssl enc -d -aes-256-cbc -pbkdf2 \
    -pass env:BACKUP_PASS -in ~/noo-backups/pg_<ts>.sql.gz.enc \
  | gunzip -c \
  | docker exec -i noo-postgres psql -q -v ON_ERROR_STOP=1 -U noo -d noomesh

# 4. sanity-check (fresh installs keep the tables in schema `mesh`, older ones in `public`)
docker exec noo-postgres psql -tA -U noo -d noomesh \
  -c "SELECT table_schema, count(*) FROM information_schema.tables
      WHERE table_type='BASE TABLE' AND table_schema IN ('mesh','public','trellion','evolve') GROUP BY 1"

# 5. bring everything back
noo stack start
```

Every `psql`/`pg_dump` above runs **inside** the container over the unix
socket, which is the one path `pg_hba` still trusts. Postgres accepts no TCP
client without TLS **and** a cluster-CA client certificate (since 2026-09-28,
`docker/postgres/pg_hba.conf`), so a `psql -h 127.0.0.1 -p 5433` from the host
needs `sslmode=verify-ca sslrootcert=$NOO_PKI_DIR/ca.crt
sslcert=$NOO_PKI_DIR/gateway/pg/noo.crt sslkey=<a 0600 copy of gateway/pg/noo.key>`
on top of the password — libpq refuses the key as mounted. The certificate
must be the one issued for the role you log in as (its CN is the role:
`gateway/pg/noo.crt` for `noo`, `gateway/pg/noo_app.crt` for `noo_app`);
the gateway's own `gateway/gateway.crt` is refused for those roles. Prefer the
`docker exec` form.

(`noo` / `noomesh` are the defaults for `POSTGRES_USER` / `POSTGRES_DB`.)

### Restoring an old backup by hand

Every `pg_<ts>.sql.gz.enc` taken before `pgroles_<ts>.sql.enc` existed (stack
releases up to and including v0.2.105) has no roles file, and restoring it
into a server that does not already have the `noo_*` roles fails: the data
loads, but the ownership and grant statements error out with `role "noo_..."
does not exist`, and anything that checks only the `public` schema reports
zero tables. Pre-create the roles first, then restore with `ON_ERROR_STOP`:

```sql
-- run as the Postgres superuser (noo) before restoring the dump
CREATE ROLE noo_app          NOLOGIN;
CREATE ROLE noo_trellion     NOLOGIN;
CREATE ROLE noo_trellion_ddl NOLOGIN;
CREATE ROLE noo_evolve       NOLOGIN;
CREATE ROLE noo_evolve_ddl   NOLOGIN;
```

`noo_trellion*` and `noo_evolve*` are needed only if those add-ons were
enabled; creating an unused one is harmless. Skip any that already exist (the
gateway creates them on first boot against a live stack). After the data is in,
give them back their ability to log in and their passwords from the secret
store:

```sql
ALTER ROLE noo_app LOGIN;   -- and the others you created
```

```sh
noo security secrets resync --all   # re-applies the stored role passwords
```

`restore-drill.sh` does the `NOLOGIN` pre-creation for you when a backup has no
roles file, and says so.

### Restore onto a fresh machine

**Packaged form:** `noo migrate export` on the old controller seals the
age key, `secrets/env.sops` and `.sops.yaml`, `.env`, `noomesh.yaml`, the
full `pki/` tree (the CA unchanged, so enrolled workers reconnect), the
fleet inventory and a fresh `pg_dump` into one passphrase-encrypted
archive; `noo migrate import <archive>` on the new box restores it in the
right order — age key first, deploy slice at this binary's version, state
overlay, stack start, `psql` restore, and a certificate re-issue if the
hostname or IP changed. Models, caches and images are not carried; they
are pulled again. The manual steps below are the primitive it is built
from, and the path when all you have is a scheduled backup.

Order matters — secrets first, or nothing else can start.

```sh
# 1. install age + sops (or run scripts/noo-secrets-sops-init.sh)
# 2. restore the age key from your off-machine backup
BACKUP_PASS='<NOO_AGE_BACKUP_PASSPHRASE from your password manager>' \
  openssl enc -d -aes-256-cbc -pbkdf2 -pass env:BACKUP_PASS \
    -in age-key_<ts>.txt.enc -out ~/.config/sops/age/keys.txt
chmod 600 ~/.config/sops/age/keys.txt

# 3. install noo (release installer) and materialise ~/.noo (noo onboard --standalone),
#    restore secrets/env.sops into it, cd ~/.noo, verify it decrypts
sops -d --input-type dotenv --output-type dotenv secrets/env.sops | head

# 4. restore the database (above), then: noo stack start
```

Both `--input-type` and `--output-type` are required: the file is dotenv
but named `.sops`, so a bare `sops -d` guesses JSON and fails — and a
broken decrypt returns zero keys, which reads exactly like "the key is
missing".

## Scheduling and how it runs

`database_backup` is a default heartbeat task, enabled, **daily at 03:30**
in the controller's heartbeat timezone (`NOO_HEARTBEAT_TZ`, else the
`heartbeat.tz` setting; default `America/New_York`). It was every 6 hours until the dump outgrew the 120 s the
gateway used to wait for it. An existing install keeps the schedule it already
has; to move it to the quiet hour (this changes only the schedule, so the
task's channels, recipients and config stay as they are; the next tick also
fires one run right away, because a changed schedule clears the task's next run):

```bash
noo heartbeat set-schedule database_backup "30 3 * * *"
```

Do not use `noo heartbeat add` for this: it replaces the whole task row, and
anything you did not repeat on the command line (channels, recipients, config)
is cleared.

The path is:

```
gateway heartbeat → writes a `backup` command to ~/.noo/.noo-host-spool/
                  → noo-hostd (controller mode, systemd user unit; installed by noo onboard) claims it
                  → loads secrets from env.sops (refuses if it cannot), runs scripts/backup-controller.sh on the host
                  → writes <name>.result.json (ok, stderr, and the dump's path, size and duration)
gateway completion hook (every 30 s) → finishes the SAME heartbeat run from that file
```

The heartbeat run is **queued, not finished**, when the task fires: it shows
`running` with the result file it waits on. The gateway's completion hook
(`database_backup_completion` on `/api/agent/loops`) records success (dump
path, size, duration; the file is checked when the gateway can see the backup
dir) or failure (hostd's stderr) on that run. No result within 2 hours is a
failure. A slow but successful dump never alerts.

Consequences:

- **Backups only run while the gateway and noo-hostd are up.** There
  is no host crontab entry, so a stopped stack means zero backups. For
  unattended sites add a host cron line that loads secrets first
  (`30 3 * * * cd ~/.noo && . scripts/lib-secrets.sh && load_secrets && scripts/backup-controller.sh`)
  so backups survive a gateway outage.
- noo-hostd is a **user** unit on the controller:
  `systemctl --user status noo-hostd`; its log (every `EXEC`, `OK`,
  `FAIL` and `REJECT` line) is `journalctl --user -u noo-hostd`.
  Missing or stopped: `noo onboard --only services` installs it (from a
  terminal, with sudo: it installs the binary system-wide, and skips itself
  under `--non-interactive`).
- A failed dump, or no result within 2 hours, raises an operator alert
  (`database_backup.failed`, 6 h cooldown) — a backup is never reported
  successful until hostd's result says so.

## Troubleshooting

### `REJECT … not valid JSON` in the noo-hostd log

Usually a **permission** problem, not a malformed payload. The gateway
runs as uid 65532; the spool directory and noo-hostd run as you. If the
gateway cannot write, or hostd cannot read what it wrote, you see
this.

```sh
docker exec noo-gateway id            # expect groups=…,1000 (NOO_HOST_GID)
ls -ld ~/.noo/.noo-host-spool         # expect drwxrwsr-x (2775)
```

The compose file gives the gateway `group_add: ["${NOO_HOST_GID:-1000}"]`;
the spool must be `2775` and command files `0640`.

### Scheduled backups fail while manual runs succeed

The noo-hostd unit pins `PATH=~/.local/bin:/usr/local/bin:/usr/bin:/bin`.
If `sops` lives somewhere else, `load_secrets` fails under the unit
while it works in your shell, and hostd refuses the backup ("could not
load secrets") rather than run it without passphrases. Check where
`sops` is installed, then verify the real path rather than trusting a
manual run:

```sh
noo heartbeat run database_backup                         # queues the backup through the spool and returns at once (run shows `running`)
journalctl --user -u noo-hostd -n 5 --no-pager            # expect EXEC … op=backup then OK, not REJECT/FAIL
ls -t ~/noo-backups | head -2                             # expect .enc
noo heartbeat history database_backup --limit 1           # within about 30 s of hostd finishing: success, with path and size
```

### The task reports success but no backup appears

```sh
noo heartbeat history --task-id database_backup --limit 5
docker exec noo-postgres psql -U noo -d noomesh -c \
  "SELECT started_at, status, left(error,120) FROM noo_heartbeat_runs \
   WHERE task_id='database_backup' ORDER BY started_at DESC LIMIT 5"
```

A run still `running` is waiting on hostd's result file (2 hours at most; the
file's path is in its result text). Then the noo-hostd log
(`journalctl --user -u noo-hostd`). A run marked `success` with no file means
hostd answered with a result the gateway accepted — read what the result said.

## Related

- [security/secrets.md](../../security/secrets.md) — the SOPS/age model, `noo security secrets`, key rotation
- [../operator-manual.md](../operator-manual.md) — stack start/stop/rebuild, noo-hostd
- `noo migrate export` / `import` — [cli/setup-and-host.md](../../cli/setup-and-host.md)
