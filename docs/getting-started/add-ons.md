# Add-ons

noomesh is a free, self-hosted core plus **add-ons**: extras that run as
their own containers beside the core stack. They are switched by the
`addons:` map in `noomesh.yaml`; there is no per-add-on environment
variable. Some are free, some need a licence.

| Add-on | What it adds | Kind | `addons:` key (default) |
|---|---|---|---|
| Trellion knowledge pack | RAG over ingested documents, conversation-memory search, the knowledge graph, episodic recall (`noo rag`, `noo memory`, `noo graph`, `noo recall`) | free | `addons.trellion` (on) |
| Identity | short-lived per-agent connection tokens | free | `addons.identity` (on) |
| Voice | local speech-to-text and text-to-speech; the voice channel and `noo voice` | free | `addons.voice` (off) |
| Intelligent tier | graph-guided retrieval on top of the knowledge pack | licensed | `addons.trellion_intel` (off) |
| Evolve | self-tuning of the agent from its own runs; provides `noo loop` and `noo ga` | licensed | `addons.evolve` (off) |

## Turn one on or off

Edit the map in `noomesh.yaml`, then restart the stack:

```yaml
addons:
  trellion: true
  voice: true
```

```bash
noo stack restart --force
noo health --json          # the "addons" object reads enabled, disabled or unlicensed
```

Or use the wizard step on its own:

```bash
noo onboard --only addons
```

A name left out of the map takes its default from the table. For a licensed
add-on the flag is not enough: it also needs an entitlement (below).

From the command line, `noo addons enable <name>` mints what the add-on needs
and declares it on; `noo addons list` shows the state of each.

## Voice models are staged by the controller

The voice containers never download anything. The controller fetches the
models, verifies them and stores them in its model store (`MODELS_DIR`,
default `<data root>/models`):

| What | Default | Stored in | Mounted read-only at |
|---|---|---|---|
| faster-whisper model (`WHISPER_MODEL`) | `base`, from `Systran/faster-whisper-base` | `<models>/voice/whisper/base/` | `noo-whisper:/models` |
| piper voice (`PIPER_VOICE`) | `en_US-lessac-medium`, from `rhasspy/piper-voices` (`.onnx` + `.onnx.json`) | `<models>/voice/piper/` | `noo-piper:/voices` |

Both containers run as `nonroot` (uid 65532) with `HF_HUB_OFFLINE=1`, have
no Hugging Face token, and have no writable model volume.
`noo addons enable voice` stages the configured pair and prints each file
and its size. `noo upgrade --stack` and `noo onboard --only addons` stage it
too while voice is on. To stage another size or voice by name:

```bash
noo models pull whisper:small          # tiny, base, small, medium, large-v3, *.en, turbo, or <org>/<ct2-repo>
noo models pull piper:en_GB-alba-medium
```

Downloads use the controller's `HF_TOKEN` when one is stored, and each file
is checked against Hugging Face's digest before it goes in place. A request
for a model or voice that is not staged gets a 404 that names the
`noo models pull` line to run, and no download is attempted.
`noo cluster verify --controller` reports this in two rows:

- **`voice models`**: the configured pair is staged and both containers run
  offline.
- **`voice images`**: both containers run as uid 65532.

**Upgrading an install whose voice containers downloaded their own models.** Older images downloaded into the
`hf-cache` and `piper-voices` volumes as root. The new containers ignore
both. `noo upgrade --stack` stages the configured pair before the restart,
so the default model and voice download once more. A controller with no
internet keeps a working voice only once you copy the files into
`<models>/voice/` with the layout above. After that you may delete the old
`noomesh_piper-voices` volume (`docker volume rm noomesh_piper-voices`) and the
`<data root>/hf-cache/hub/models--Systran--faster-whisper-*` directories.

## What a disabled add-on does

Nothing else breaks. The gateway keeps serving; only the add-on's own surface
answers **HTTP 503** with `{"error": "<why>", "addon": "<name>"}`, and the
`noo` commands that hit it exit 5 and print the reason. `/health` stays 200
and reports each add-on as `enabled`, `disabled` or `unlicensed` (flag on,
no valid entitlement).

## Who can use an add-on's routes

An add-on's HTTP routes are scoped by role like the core's. Each route in the
add-on's manifest names the lowest role that may call it; a route that names
none is Operator-only, so a User-tier login reads nothing an add-on did not
vouch for. The evolve add-on's loop, GA, RL-policy and meta-loop reads
describe the whole installation and are Operator and Admin only. Add-on authors:
[development/addons.md](../development/addons.md#who-may-call-a-route).

## Licensed add-ons

A licensed add-on needs an entitlement token from PersonifAI. Register at
<https://noomesh.ai/add-ons>; the terms are at
<https://noomesh.ai/add-ons/terms>.

```bash
noo security entitlement install <token>   # prints the terms, asks you to type accept
noo security entitlement show              # subject, expiry, what it unlocks
noo addons enable trellion-intel
noo stack restart --force
```

In a non-interactive run, pass `--accept-terms <version>` naming the terms
version the install prints. If `install` refuses a token,
`noo security entitlement verify <token>` says why.

## Enable a third-party add-on

An add-on you did not get with the stack (a voice assistant from another
vendor, say) is switched on the same way as a built-in one, with one extra
decision that is yours: **which signing key you trust for it.** The add-on's
release is a signed lock (its images by digest, the stack versions it runs on,
its compose overlay). noomesh will pin and run it only if the lock verifies
against a key you trusted and lists your stack.

```bash
noo addons trust-key yourthing <pubkey> --registry ghcr.io/vendor/yourthing
noo addons enable yourthing                  # fetches <registry>:stack-<your tag>
noo addons enable yourthing --lock ./yourthing-lock.json    # or hand it the lock
noo stack restart --force                    # the launcher re-verifies it, then starts it
noo health --json                            # "addons" reads enabled for it
```

- `trust-key` writes the key and the registry root its images come from to
  `addon_trust` in `noomesh.yaml`. The ed25519 public key (64 hex characters)
  comes from the vendor, through a channel you trust. `noo addons untrust-key
  <name> <pubkey>` removes it. The section is admin-only to change through the
  API. The CLI ships no default key for third parties; the built-in add-ons
  (evolve, trellion-intel) are trusted through your entitlement and cannot be
  given other keys.
- `--lock` takes a file path or an `https://` URL for the lock JSON. The
  signature must sit beside it as `<name>.sig`, and every bundle file the lock
  names (at least `docker-compose.yml`) in the same directory. Without
  `--lock` the lock is fetched from the registry you named.
- A lock signed by a key you did not trust is refused, and the message names
  `noo addons trust-key`. A lock that does not list your stack, whose files do
  not match their signed hashes, or whose images sit outside the trusted
  registry root is refused too, with nothing changed.
- Images are pulled by digest into the same pins as a built-in add-on's
  (`noo addons verify` checks them), and the launcher re-verifies the lock on
  every start and tells the gateway, which registers the add-on's routes. If
  you enable it without a verified lock, nothing loads quietly: `noo health`
  reads `unhealthy`, and the gateway log says "has no verified lock for this
  stack ... Run `noo addons upgrade yourthing`".
- To try an add-on before it ships, trust its developer's temporary key with
  `noo addons trust-key yourthing <pubkey> --registry <root> --dev --expires 14d`
  (30 days at most). It works on this mesh until it expires, `noo addons list`
  marks it DEV with the expiry, and `noo addons untrust-key yourthing --dev`
  removes it. See "Development keys" in docs/development/addons.md.

A private registry takes one credential per add-on. Create a read-only token
for the add-on's package (`read:packages` on GHCR) and register it:

```bash
noo addons registry-login yourthing --registry <root> < token.txt   # or --from-file token.txt
```

`<root>` must be exactly the root you trusted the add-on's key for. The token is
read from stdin or the file, never the command line; it is kept in the encrypted
secret store (`NOO_ADDON_REGISTRY_CRED_YOURTHING`), `noo addons list` shows
whether one is set (never its value), and it is sent to that registry root and
nowhere else. The vendor's `NOO_ADDON_REGISTRY_TOKEN` is never sent to it.
`noo addons registry-login yourthing --clear` removes it, and so does
`noo addons untrust-key` when it removes the add-on's last key.

Limits of the third-party path today: without that credential the lock and the
images are fetched **anonymously** from the registry you named, and
there is no proxy or entitlement-mediated pull. The add-on's own gateway key and
database credentials are not minted for it: its overlay's key declaration is
read only for the add-ons the CLI ships, so provision a key with `noo security
service-key provision` if it needs one.

An add-on that wants to create and steer a person's tasks for them (a voice
assistant that starts work while you talk) must declare that in its manifest
**and** be allowed by you. It is off until you allow it, and the gateway reads
it at startup:

```bash
noo addons set yourthing --delegate tasks     # --delegate off turns it off again
noo stack restart --force
```

That writes `addon_delegation.yourthing.tasks: true`. Setting it for an add-on
that does not declare delegation does nothing, and the gateway log says so. The
key is admin-only to change through the API. Upgrading noomesh keeps the
add-ons you already run working on the first start.

## Build your own

An add-on is anything that speaks one of the core's extension seams (an MCP
server, a plugin shim, a model backend, a worker container). The author guide
is [development/addons.md](../development/addons.md); the Apache-2.0 client
for calling the gateway is `packages/noo-gateway-client`.

## Licensing

The core is AGPL-3.0-only (see `LICENSE`). Trellion is AGPL-3.0-only with a
commercial licence available from PersonifAI LLC. The licensed add-ons are
proprietary, live in separate repositories and talk to the core over the same
network seams you can use.
