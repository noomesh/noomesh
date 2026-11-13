# example-addon

The reference add-on of [Building an add-on](../../docs/development/addons.md).
It is the smallest add-on that connects to its runtime both ways:

- **in**: the gateway calls `GET /api/example-addon/status` with its own
  bearer. The add-on verifies that bearer against the `noo_addon_caller_keys`
  view before answering ("Verifying the bearer").
- **out**: the add-on exchanges **its own key, delivered as a file**, at
  `POST /api/addon/token` for a short-lived token ("Step 3a — connect to your
  runtime").

Everything it needs is in this folder; nothing here names a path outside it.

| File | What |
|---|---|
| `docker-compose.yml` | the overlay: `x-noo-addon` (key, scopes), one service, no pass-through env |
| `routes.json` | the route manifest the gateway registers |
| `resources.json` | gateway URL + CA, TLS leaf, the add-on key, the DB parts, the networks: secrets as files |
| `system.json` | its database roles, and `verify_callers` (read the caller-key view) |
| `app/server.py` | the service (standard library + psycopg; no shell needed in the image) |
| `Dockerfile` | the image; `USER 1000` matches `resources.json`'s `uid` |
| `tests/test_contract.py` | routes == served paths; no key or pass-through in env; secrets as files |

## From source to running

**Proof status.** Only steps 1 and 2 have been run as written here, on a
0.6.23 CLI, for this folder. Steps 3–7 use the commands the release rehearsal
runs for its own fixture add-on. The token exchange that step 6 relies on (key
file → `POST /api/addon/token` → token accepted on the add-on's own route,
refused on another's) was run in the release rehearsal on 0.6.24-rc.3, with
that fixture add-on, not this folder. The end-to-end pass that takes **this**
folder from build to an upgrade with it enabled is the definition of done.
Until it lands, read steps 3–7 as checked against the code, not copied from a
run of this example.

1. **Test the contract** (no stack needed):

   ```sh
   python3 -m unittest discover -s tests
   ```

2. **Check the bundle with enable's own guards** (offline: no signature,
   image or network):

   ```sh
   noo addons check . --name example-addon
   ```

3. **Build and push the image** to your registry, and note its digest
   (`<root>/example-addon@sha256:…`).

4. **Sign a lock** for the stack you target. The seed is your signing key;
   keep it private.

   ```sh
   ( umask 077; openssl rand -hex 32 > seed )
   noo --json security addon-lock sign --addon example-addon --version 0.1.0 \
     --source-commit "$(git rev-parse HEAD)" --supports stack-v0.6.24 \
     --image example-addon=<root>/example-addon@sha256:<digest> --registry <root> \
     --file docker-compose.yml=docker-compose.yml --file routes.json=routes.json \
     --file resources.json=resources.json --file system.json=system.json \
     --seed-file seed --out addon-lock.json
   ```

   The JSON it prints carries your `pubkey`.

5. **Trust and enable** on the controller:

   ```sh
   noo addons trust-key example-addon <pubkey> --registry <root> --dev --expires 14d
   noo addons enable example-addon --lock ./addon-lock.json
   ```

   Enable mints `NOO_SVC_KEY_EXAMPLE_ADDON` with `metrics` (plus `addon`),
   provisions the database roles, and starts the service.

6. **Connect**: call the add-on's route through the gateway as an operator. It
   answers with who the call was for and whether its own token exchange
   succeeded (`"outbound": {"exchanged": true, "consumer": "svc:example-addon",
   …}`).

7. **The next stack upgrade**: see "your add-on and the next stack upgrade" in
   the guide. A lock names exact stack tags, so sign one for each stack you
   support.
