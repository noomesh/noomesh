---
title: "Security Release Upgrade"
domain: "security"
architecture: "polyglot"
tools_referenced: []
---

# Security Release Upgrade

What an operator on a current release still does from the September 2026
security rollout: link chat identities, keep the backup passphrases, set
posture, roll node agents and the fleet signing key, and prove each control
refuses. The step-by-step record of those rolls (`stack-v0.2.39`, `v0.2.40`)
is kept in the project's records; nothing in it applies to a current
install.

## 1. Link every person's channel identity

Chat ingress is default-deny against `noo_user_channel_links`.
`TELEGRAM_ALLOWED_USERS` is retired and admits nobody: drop it from `.env`.

```sh
noo security user link <you> telegram <your numeric id>
noo security user link <you> google_chat users/<id>     # if Chat is in use
noo security user links <you>
```

Do this for every person who talks to the bot, on a new install too:
onboard mints the admin account but does not know your channel id. An
unlinked sender is refused with the exact `link` command in the reply.

## 2. Backup passphrases

Backups never run unencrypted. Check both passphrases are set, and mint any
that is missing:

```sh
cd ~/.noo                     # install root on a standalone controller; your checkout otherwise
. scripts/lib-secrets.sh && load_secrets
printenv NOO_BACKUP_PASSPHRASE     >/dev/null || echo "pg: MISSING"
printenv NOO_AGE_BACKUP_PASSPHRASE >/dev/null || echo "age: MISSING"
noo security secrets rotate NOO_BACKUP_PASSPHRASE NOO_AGE_BACKUP_PASSPHRASE   # --dry-run first
```

Run `rotate` from the box's terminal, never piped: it prints each generated
value once, re-encrypts every existing backup file, and refuses (changing
nothing) when its output is not a terminal. Store both values off this
machine. The age passphrase protects the key that decrypts the store it
lives in, so a copy kept only inside that store is not a backup.

`noo security secrets reveal <NAME>` reads a stored value back, on a
terminal only, and is audited. A leftover plaintext passphrase file is a
CRITICAL "Backup Passphrase Plaintext" in `noo security scan`; `reveal`
offers to shred it.

Then prove it:

```sh
env -u NOO_AGE_BACKUP_PASSPHRASE scripts/backup-controller.sh   # expect: REFUSING, exit 1
scripts/backup-controller.sh                                    # expect: both .enc files
scripts/restore-drill.sh                                        # expect: PASSED
```

`restore-drill.sh` fails while a plaintext `~/noo-backups/age-key_*.txt`
exists: `shred -u` it.

## 3. Posture

```sh
noo security posture apply-profile hardened
noo security posture set NOO_EXEC_APPROVAL_MODE <auto|approval|strict>   # if you want other than approval
noo security posture list
noo stack restart --force gateway
```

`hardened` sets `NOO_EXEC_APPROVAL_MODE=approval`; with nothing configured
the gate is `strict`. It also closes the external MCP door
(`NOO_MCP_EXTERNAL_ENABLED=0`): re-open it with `posture set … 1` only if
you serve that door. Read the before/after diff `apply-profile` prints.
Posture applies on restart, and `--force` is needed: a plain restart keeps
the old container environment.

## 4. Roll the node agents

Agent binaries reach a node only in a provision bundle signed by the fleet
signing key, over the pull rail. Do one GPU node first:

```sh
noo cluster provision <gpu-node> --wait     # restage, wait for the node's apply verdict
noo cluster show <gpu-node>                 # the agent version moved
noo cluster place <gpu-node> vllm <model>   # confirm the backends still serve
noo cluster place <gpu-node> llamacpp <model>
noo upgrade --nodes                         # then every pull-capable node; the controller's own agent last
noo cluster provision <mac> --wait          # each Mac, one at a time
```

Backend containers run with `CapDrop ALL` and `no-new-privileges`. If an
image needs a capability, add `NOO_BACKEND_CAP_ADD=<CAP>` to that node's
`/etc/noo-node-agent.env` and restart the agent.

A `models_dir` outside the node's declared roots (`MODELS_DIR`,
`NOO_DATA_ROOT`, `HF_CACHE_DIR`, `NOO_HOST_ROOTS`, …) is refused, not
warned about: `journalctl -u noo-node-agent | grep -E 'models_dir_refused|start_failed'`.
Fix the node's env or its `node_config` row.

On a node, the controller-only routes answer 503 until `NOO_TLS_CA`,
`NOO_TLS_CERT` and `NOO_TLS_KEY` are set. Node-local MCP servers come only
from the node's root-owned `/etc/noo/mcp-servers.json`, and each entry needs
an `image` (it runs contained); `noo mcp server add --transport stdio`
prints an entry to paste.

## 5. Roll the fleet signing key

`ca.key` issues identities; `signing.key` signs the node bundles that carry
the agent, the applier and fleet secrets.

```sh
noo security pki rotate-signing-key --deliver-only -y    # deliver the existing key
noo security pki rotate-signing-key -y                   # or mint a new one and roll it
noo security pki rotate-signing-key --json --deliver-only -y \
  | jq '{ok, complete, adopted, no_report, failed, orphaned_material}'
```

| In the summary | Meaning | Do |
|---|---|---|
| `adopted` | the node applied the bundle (exit 0) and recorded the key | nothing |
| `no_report` | it collected the bundle but cannot report an apply | check by hand (V10) |
| `failed` | it can report and did not adopt, or never collected the bundle | re-run; this alone makes the exit non-zero and `ok` false |
| `orphaned_material` | key material for a node the registry does not know | remove it |

`complete` is false while anything is unproven. Each adopted node has
`$NOO_PKI_DIR/nodes/<node>/signing-adopted` on the controller, holding the
fingerprint it accepted. A node that never adopts is recovered by
re-enrolling it.

## Verification checklist

Each row proves a control by making it refuse. Check exit codes, not text.

| # | Control | Probe | Expected |
|---|---|---|---|
| V1 | Chat ingress is default-deny | DM the bot from an unlinked account | A reply quoting your channel id, `channel_ingress_denied` in `docker logs noo-gateway`, and a matching `noo_security_audit` row |
| V2 | Approvals bind to who asked | As a linked operator, trigger a HIGH-risk call, then `noo approval list` | The row names you and the conversation; a bare `y` there decides it |
| V3 | A person is not an agent | Open `/ws/agent` with a user token | Refused: "/ws/agent takes a peer token, not a user token" |
| V4 | Operator ≠ admin | As an operator, `noo security user set-scopes <user> admin` | 403: "admin role required to change roles/scopes" |
| V5 | No unverified TLS lane | `NOO_TLS_INSECURE=1 noo health` | Exit 3, `tls_untrusted` |
| V5b | The trust anchor is named | `noo auth status` | A named anchor, never "unverified" |
| V6 | Per-principal bus credentials | `/connz?auth=1` on `:8222` (https, the gateway leaf as client certificate) | One user per principal (`gateway`, `worker`, `node-<id>`); no shared `noo` |
| V7 | A node refuses a path outside its roots | A `models_dir` outside the declared roots, then reconcile | `reconcile.models_dir_refused` in the node journal and a `models_dir` refusal on the heartbeat |
| V8 | Backups refuse without a passphrase | `env -u NOO_AGE_BACKUP_PASSPHRASE scripts/backup-controller.sh` | `REFUSING`, exit 1 |
| V9 | The scanner can gate | Plant a CRITICAL, then `noo security scan` | Exit 1; restore the value, exit 0 |
| V10 | Signing key adopted | `ls $NOO_PKI_DIR/nodes/*/signing-adopted`; for a `no_report` node, `noo cluster logs <node>` | A marker per node; `verified-by: signing-key` in the node's own log |
| V11 | Monitoring holds no gateway key | `docker exec noo-prometheus ls /app/pki/gateway` | No such file or directory |
| V12 | Node work routes are controller-only | `/gpu` on a node agent with another node's leaf | Refused; the controller's own call succeeds |
| V13 | `fetched_at` is evidence | `POST /bootstrap/bundle/<node>/fetched` without the node's proof | 403; `GET /api/cluster/provision-bundle/<node>/status` still shows the real `fetched_at` |
| V14 | A node-local MCP server is contained | Remove an entry's `image` in `/etc/noo/mcp-servers.json`, restart the agent | It does not start; `noo cluster show <node>` names `image` |

NATS reports a denied publish asynchronously (the client sees success), so
for V6 read `docker logs noo-nats`. For V5, do not probe by unsetting
`NOO_TLS_CA`: the CLI then verifies through the system trust store, which is
a verified lane working, not a hole.

## When the gateway is already down

These are host-level fixes (root or the operator account on the controller);
prefer the `noo` verbs whenever the gateway is up.

**On the retired YAML gate.** Remove `security.exec_approval_mode` from
`noomesh.yaml` and restart; the refusal names the key and its replacement.

**On a retired bridge held open.** A gateway refuses to start while
`NOO_CLUSTER_LEGACY_FULL_ACCESS`, `NOO_BOOTSTRAP_ACCEPT_UNSIGNED_FETCH` or
`NOO_BUS_PRINCIPAL=optional` is open, and names the key. `posture set` needs
a running gateway, so write the closed value (`0`, `0`, `required`)
directly, then restart:

```sh
docker exec noo-postgres psql -U noo -d noomesh -c \
  "UPDATE mesh.noo_security_posture SET value = 'required', updated_by = 'host-sql', updated_at = NOW()
   WHERE key = 'NOO_BUS_PRINCIPAL';"
noo stack restart --force gateway
```

The table is in schema `mesh`. Remove any `.env` line that still names the
key.

## Related

- [backup-restore-secrets.md](backup-restore-secrets.md): the recovery artifacts, the restore drill, passphrase rotation
- [nats-isolation.md](nats-isolation.md): per-principal bus credentials
- [../operator-manual.md](../operator-manual.md): stack lifecycle
