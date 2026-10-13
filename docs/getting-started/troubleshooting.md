# Troubleshooting the first run

The failures below are the ones a fresh install runs into. Start with the
triage trio, which answers "what is this box, is it up, and is Docker sane":

```bash
noo whoami           # controller / node / both / client-only
noo health           # per-dependency table; exit 0 healthy, 5 degraded, 3 unreachable
noo doctor docker    # read-only; exit 1 when Docker is damaged, with the recovery steps
```

When `noo health` shows something down it prints the `noo stack logs <dep>`
command to run next.

## Docker

| Symptom | Fix |
|---|---|
| `docker compose version` fails, or the wizard's prerequisites step stops on Compose | Compose v2.40 or newer is required. Ubuntu's `docker.io` ships without it: add `docker-compose-v2` from Ubuntu, or `docker-compose-plugin` from Docker's own apt repository (newer, preferred). |
| Every container is `Exited (255)` after a reboot, usually on WSL2 | `noo doctor docker`, follow the recovery recipe it prints, then `noo stack start`. It never repairs on its own. |

## Ports

| Symptom | Fix |
|---|---|
| `noo stack start` refuses because a port is in use | `ss -ltnp \| grep 8080` finds what holds it. It is usually another noomesh instance or a stray container: `noo stack status`. To run a second stack on purpose, see [multi-instance.md](multi-instance.md). |
| Dashboard unreachable | It is `https://localhost:8080`. Grafana is `https://localhost:3000`. The browser wizard (`noo onboard --web`) listens on `http://127.0.0.1:7080` only while it runs. |

## The browser warns about the certificate

The dashboard is served with a certificate from your install's own CA, so a
browser warns until it trusts that CA. This is expected and is not a fault.
Either open the `ts.net` URL (it carries a public certificate and needs
nothing installed) or trust the CA:
[trust-the-cluster-ca.md](trust-the-cluster-ca.md).

The `noo` CLI itself refuses a non-loopback `http://` gateway URL (exit 3,
`tls_untrusted`) rather than send your credential in the clear.

## The stack starts but chat does not work

- **The model is still loading.** After the first start the backend can take
  minutes to load, longer on CPU. Chat says the backend is not ready. Wait,
  then retry; `noo stack logs <dep>` shows progress.
- **"No backend available".** Nothing is placed, or a backend is cooling down:
  `noo cluster status`.
- **Knowledge commands answer 503.** The knowledge add-on is off
  (`addons.trellion: false` in `noomesh.yaml`) or its container crashed:
  `noo health --json` shows the add-on state, `docker logs noo-trellion` the
  crash. See [add-ons.md](add-ons.md).
- **An environment change had no effect.** A plain restart keeps the old
  environment: `noo stack restart --force <service>`.

## Start-up refusals

`noo stack start` checks before it launches and tells you the fix:

| Message | Fix |
|---|---|
| a required secret is empty | `noo security secrets audit`, then `noo onboard --only secrets` |
| bind-mount sources are missing or the wrong type | run each `fix:` line it prints; for a directory sitting where a file belongs, `sudo rmdir` it first |
| the gateway restarts in a loop | `docker logs noo-gateway --tail 200`: a drifted database password (`noo security secrets resync --all`), a missing certificate (`noo security pki status`) or a failed migration (`noo db status`) |

## Locked out

Reset the admin password on the controller:

```bash
noo security admin-password reset
```

`noo onboard --ci` generates the admin password and never shows it, so this
is the normal route after a non-interactive install.

More: [operator-manual.md](../operating/operator-manual.md) has the
day-to-day troubleshooting table, and `noo --help` lists every command.
