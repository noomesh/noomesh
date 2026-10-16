# Kiosk displays: set up, enrol as a seat, keep current

A kiosk is a screen with no keyboard that shows the dashboard's `/kiosk.html`
from the controller: a Linux box running `cage` + Chromium under systemd, a
local proxy that holds the display's short-lived credential, and a watchdog.
`noo kiosk setup` installs that on the box. Enrolling the box as a **seat**
then lets the controller keep its `noo` CLI and kiosk scripts current, so
`noo upgrade --all` reaches the display as well as the nodes.

A seat is **not a node**. It never runs workloads, never appears in
`noo cluster status`, and can never obtain anything a node holds: no fleet
secret, no NATS bus credential, no backend door certificate, no node-agent
control API, no harness. Its one credential is a birth key it generates for
itself, which proves it is the seat it enrolled as and nothing more.

## 1. Set up the display

On the display box, as the account that runs `noo` (the controller's
`noo kiosk invite <display-name>` prints the tailnet steps first):

```bash
noo kiosk setup --mode dedicated --url https://<controller>.<tailnet>.ts.net
noo kiosk status
```

`--mode dedicated` hands the box to the display (tty1, no desktop login);
`--mode shared` leaves a laptop usable and puts the display on its own VT.

## 2. Enrol it as a seat

On the **controller**, mint a one-time seat token:

```bash
noo kiosk seat-token lobby
```

It prints one line, `noo kiosk enroll noo-seat1.<blob>`. The blob carries the
controller URL, the single-use token (default lifetime one hour, `--ttl` to
change it, at most 24h), the cluster CA fingerprint and the fleet signing
public key. A seat token cannot enrol a node, and a node's enrolment paste
cannot enrol a seat: `noo enroll` refuses a `noo-seat1.` blob and
`noo kiosk enroll` refuses a `noo1.` one.

On the **display box**, as the same account that ran `noo kiosk setup` (not
root), paste it:

```bash
noo kiosk enroll noo-seat1.<blob>
```

This:

1. fetches the cluster CA and checks it against the fingerprint in the paste;
2. generates the seat's birth key pair (RSA-4096);
3. redeems the token at the controller (it burns on first use);
4. asks for `sudo` **once**, printing the exact script first, to install:
   - `/etc/noo-seat/` (root): `birth.key` (0600), `birth.crt`, `ca.crt`,
     `signing.pub`, `seat.json` (seat name, controller URL, the seat user and
     home);
   - `/var/lib/noo-seat/` (root, 0700): the sync timer's state;
   - `/usr/local/libexec/noo-seat/noo`: a root-owned copy of this `noo`, which
     the timer runs, so a binary the seat user can write is never run as root;
   - `noo-seat-sync.service` and `noo-seat-sync.timer`, enabled now.

Nothing after this step needs `sudo`. Add `--controller <url>` when the seat
reaches the controller by a different address than the one the controller
advertises. `--dry-run` prints the root script without redeeming the token.

## 3. Keep it current

On the controller:

```bash
noo upgrade --all        # CLI, stack, nodes, then seats
noo upgrade --nodes      # nodes, then seats
noo upgrade --seats      # seats only
noo upgrade --nodes --no-seats
```

After the nodes have been staged and have reported, the seats stage builds
one bundle per enrolled seat: the `noo` CLI for the seat's platform, the four
`noo-kiosk-*` scripts, the kiosk units rendered for that seat's user, mode
and VT, the signing public key, and the controller's console build. It is
signed with the fleet signing key, gzipped and encrypted to the seat's birth
certificate, as node bundles are. The gateway only ever holds ciphertext.
With no seat enrolled, nothing is staged and the stage prints one line.

Every seat's `noo-seat-sync.timer` runs once a minute. Each run sends a signed
heartbeat, then fetches the bundle (also signed), decrypts and verifies it,
and applies it. The applier writes only:

| path | written as |
|---|---|
| `~/.local/bin/noo` of the seat user | that user (via `runuser`) |
| `/usr/local/libexec/noo-seat/noo` | root |
| `/usr/local/bin/noo-kiosk-{launch,cdp,watchdog,serve}` | root |
| `/etc/systemd/system/{kiosk,kiosk-serve,kiosk-watchdog}.service`, `kiosk-watchdog.timer` | root |
| `/etc/noo-seat/signing.pub` | root |

A bundle that names any other file, or a kind outside that list, is refused
whole, before anything is written. A node bundle is never accepted by a seat,
and a seat bundle is never accepted by a node, because the manifest headers
differ.

After applying, the seat restarts `kiosk-serve` when the proxy or its unit
changed. It restarts the display session when the launcher, the CDP helper or
the display unit changed. Otherwise it reloads the page only when the
controller's console build moved. Then it reports the outcome and sends a
second heartbeat. The install keeps a `BROWSER=` line that `noo kiosk setup`
wrote for a non-Chromium browser.

`noo upgrade` waits for every seat together, up to 10 minutes, and prints a
verify block per seat:

- **seat online**: heard from in the last 3 minutes;
- **seat cli**: the seat's `noo` is the controller's version, and the user's
  `~/.local/bin/noo` matches it;
- **kiosk-serve**: the local proxy is active;
- **display**: the console build on the screen is the controller's, and what
  the last apply did (`reloaded`, `restarted` or `unchanged`);
- **seat bundle**: the staged bundle applied with exit 0.

`noo cluster verify` shows the same rows in its **Seats** section.

A seat that is off during an upgrade picks up its bundle on the next boot.

## Troubleshooting

| symptom | check |
|---|---|
| "never heard from since it enrolled" | on the seat: `systemctl status noo-seat-sync.timer`, `journalctl -u noo-seat-sync -n 30` |
| `decrypt failed` in the apply report | the seat's birth key changed (re-enrolled elsewhere?); mint a new token and run `noo kiosk enroll` again |
| `signature does not verify` | the seat's `signing.pub` is older than every key the controller still holds; re-enrol |
| `seat cli` warns that `~/.local/bin/noo` differs | the seat user runs `noo` from another path; put `~/.local/bin` first on `PATH` |
| `display` FAIL, console build behind | on the seat: `noo kiosk reload` |

Revoke an unused seat token from the controller with
`POST /api/cluster/seat-tokens/<id>/revoke` (the id is printed with the
token). Removing an enrolled seat and rotating a seat's key are not commands
yet; re-enrolling the same seat name replaces its birth certificate and drops
any bundle staged for the old one.
