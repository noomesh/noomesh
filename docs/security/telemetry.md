# Telemetry and outbound traffic

noomesh sends no telemetry. No component it ships or launches reports
usage, analytics or crashes to a vendor, and none checks for updates on
its own. Some of the third-party software noomesh runs *does* phone home
by default, so this page lists every component, what it would send, the
switch that turns it off, and how to check the switch yourself. That covers
the host software noomesh installs or lives beside (Tailscale, Homebrew, the
Ubuntu reporters, Docker) as well as the containers: see
[Host software](#host-software), kiosk displays
([Kiosk displays](#kiosk-displays)) and phones
([Phones and other client devices](#phones-and-other-client-devices)).

"No telemetry" does not mean "no network traffic". Downloading a model,
pulling an image, joining the tailnet and using a cloud model or web search
all reach the internet when you ask for them.
[Outbound traffic that is not telemetry](#outbound-traffic-that-is-not-telemetry)
lists that traffic.

## Components

| Component | What it does by default | How noomesh turns it off | Where the switch is set |
|---|---|---|---|
| **vLLM** (`vllm/vllm-openai`) | Posts a usage report to `stats.vllm.ai` when the engine starts and every 10 minutes after. The report holds a stable UUID, GPU type, count and memory, CPU model, total RAM, OS, a cloud-provider guess, the model architecture and part of the engine config. It also keeps a copy in `/root/.config/vllm/usage_stats.json`. | `VLLM_NO_USAGE_STATS=1`, `VLLM_DO_NOT_TRACK=1`, `DO_NOT_TRACK=1`. Any one of them is enough (vLLM's `is_usage_stats_enabled`); all three are set. `HF_HUB_DISABLE_TELEMETRY=1` covers its Hugging Face downloads. | compose `vllm`, `vllm-secondary`; node agent `vllm` backend spec |
| **Hugging Face libraries** (`huggingface_hub`, `transformers`, `tokenizers`, `faster-whisper`) | `huggingface_hub` can send usage pings for the libraries built on it, and tags every download with a user-agent describing the library. | `HF_HUB_DISABLE_TELEMETRY=1`, `DO_NOT_TRACK=1` | compose `worker`, `worker-extra`, `trellion`, `trellion-intel`, `noo-evolve`, `whisper`, `piper`, `sandbox`, `sandbox-extra`, `browser`, `airllm`. Also baked into the `deps-core` (worker, sandbox, trellion), whisper, piper, airllm and browser images, so a container started outside compose carries them too. |
| **text-embeddings-inference** (TEI 1.6: `tei`, `tei-gpu`, `reranker`, node `embedding`) | No usage reporting. Its only exporter is OpenTelemetry, and that sends only to an `--otlp-endpoint` you configure; noomesh configures none. It downloads models from the Hugging Face Hub. | `HF_HUB_DISABLE_TELEMETRY=1`, `DO_NOT_TRACK=1`, set as a precaution | compose `tei`, `tei-gpu`, `reranker`; node agent `embedding` spec and TEI `reranker` spec |
| **Ollama** | No usage telemetry. It does have cloud features: a `*-cloud` model is run on ollama.com, and the server offers a web-search tool. Both send your prompt off the machine. | `OLLAMA_NO_CLOUD=1` (Ollama: "Disable Ollama cloud features (remote inference and web search)") | compose `ollama`, `ollama-embed`, `ollama-embed-cpu`; node agent `ollama` spec; on a Mac the brew ollama's launchd plist, `~/Library/LaunchAgents/homebrew.mxcl.ollama.plist`, key `EnvironmentVariables:OLLAMA_NO_CLOUD` (set by `noo enroll`, re-applied by the node agent) |
| **llama.cpp server** (`llamacpp`, llama.cpp reranker) | None. | Nothing to switch off. | — |
| **AirLLM** | Built on `transformers` and `huggingface_hub`. | `HF_HUB_DISABLE_TELEMETRY=1`, `DO_NOT_TRACK=1` | compose `airllm`; node agent `airllm` spec; image `ENV` |
| **Headless browser** (Playwright Chromium, `browser`) | Chromium's background services: component and variations updates, Safe Browsing list fetches, crash reports, domain-reliability reports, metrics upload. | `--disable-background-networking`, `--disable-component-update`, `--disable-domain-reliability`, `--disable-breakpad`, `--disable-client-side-phishing-detection`, `--disable-sync`, `--metrics-recording-only`, `--no-pings` | `src/noomesh/tools/browser/server.py`. Playwright passes most of these by default; they are written out so the claim does not depend on a library default. |
| **Kiosk display** (Chromium on a kiosk host) | Same Chromium background services. | The same flag group. The host's own tailscaled and OS reporters are covered in [Kiosk displays](#kiosk-displays). | `noo-kiosk-launch`; `noo kiosk setup` |
| **Loki** | Sends anonymous usage statistics to `stats.grafana.org`. | `analytics: reporting_enabled: false` | `monitoring/loki/*.yml` |
| **Grafana** | Usage reporting, version and plugin-update checks, the news feed, gravatar, plugin signing-key fetches, preinstalled plugins and external snapshots all reach grafana.com or Google storage. | `[analytics] reporting_enabled = false`, `check_for_updates = false`, `check_for_plugin_updates = false`, `feedback_links_enabled = false`; `[news] news_feed_enabled = false`; `[snapshots] external_enabled = false`; `[security] disable_gravatar = true`; `[plugins] plugin_admin_enabled = false`, `public_key_retrieval_disabled = true`, `preinstall_disabled = true`, `preinstall_auto_update = false`; `[cloud_migration] enabled = false`; and `[grafana_com] api_url = http://127.0.0.1:9/api` as a fallback, so any grafana.com call a setting above does not cover goes to a closed local port | `configs/grafana/grafana.ini`. `noo cluster verify --controller` FAILs its `grafana door` row if any of these is back on. |
| **Agent harnesses: `noo`** (`noo-gateway harness`, kind `noo`) | noomesh's own binary; no phone-home code. | Nothing to switch off. | n/a |
| **Agent harnesses: Claude Code** (kind `claude-code`) | Anthropic's CLI. Usage metrics to Anthropic and third-party logging, error reports to a third-party error tracker, `/feedback` transcripts, session-quality surveys, background auto-updates and, on a first interactive launch, automatic registration of the official plugin marketplace. Its own docs: "Claude Code sends two kinds of operational telemetry: usage metrics and error reports." | `CLAUDE_CODE_DISABLE_NONESSENTIAL_TRAFFIC=1` (auto-updates, telemetry, error reporting, `/feedback`, release notes), plus `DISABLE_TELEMETRY=1`, `DISABLE_ERROR_REPORTING=1`, `DISABLE_FEEDBACK_COMMAND=1`, `CLAUDE_CODE_DISABLE_FEEDBACK_SURVEY=1`, `DISABLE_UPDATES=1`, `DO_NOT_TRACK=1`, plus `CLAUDE_CODE_DISABLE_OFFICIAL_MARKETPLACE_AUTOINSTALL=1`, which the first variable does not cover. See [Agent harnesses](#agent-harnesses). | `telemetry_off` of kind `claude-code` in `config/harness-kinds.json` |
| **Agent harnesses: Copilot CLI** (kind `copilot`) | GitHub's CLI. Talks to GitHub's servers and sends telemetry unless offline. | `COPILOT_OFFLINE=true` ("prevent Copilot CLI from contacting GitHub's servers"; "In offline mode, all telemetry is disabled and the CLI only communicates with your configured provider"). See [Agent harnesses](#agent-harnesses). | `telemetry_off` of kind `copilot` in `config/harness-kinds.json` |
| **Agent harnesses: Codex CLI** (kind `codex`) | OpenAI's CLI. No switches are declared for it yet, and no runner ships for it. | None declared yet. See [Agent harnesses](#agent-harnesses). | `telemetry_off` of kind `codex` in `config/harness-kinds.json` (empty) |
| **Prometheus, Alertmanager, node-exporter** | None. | — | — |
| **NATS server** | None. It does not check for updates. | — | — |
| **PostgreSQL** (pgvector), **Redis**, **nginx** (model cache), **stunnel** sidecars | None. | — | — |
| **nvidia-exporter** | noomesh's own script around `nvidia-smi`. None. | — | — |
| **evolve route-manifest one-shot** (`noo-evolve-routes`) | Copies the route manifest out of the evolve image into a volume and exits. Runs with `network_mode: none`. None. | — | — |
| **noomesh gateway** (Rust), **node agent** and **noo-hostd** (Go), **`noo` CLI** (Rust), **worker** (Python) | No analytics, no crash reporting, no automatic update check. `noo upgrade` contacts GitHub's releases API only when you run it. | — | — |
| **Web console** | Loads no third-party scripts, fonts or analytics. Every asset is served by the gateway. | — | — |

### Python dependencies

The ML image (trellion) was audited package by package. Of its packages,
only `huggingface_hub` has telemetry, and it is switched off as shown above.
`opentelemetry-api` is present without an SDK or exporter, so it does
nothing. These clients connect out only when you use the feature they serve:
`ddgs` (web search), `youtube-transcript-api`, `openai`, the Azure
document-intelligence clients pulled in by `markitdown[all]`, and `edge-tts`
(the legacy Python voice CLI's fallback; the served voice path uses local
Piper).

None of the usual phone-home packages is a dependency: `chromadb`, `posthog`,
`gradio`, `litellm`, `langchain`/`langsmith`, `sentry-sdk`, `wandb`, `mlflow`,
`streamlit`, `datasets`. If one is ever added, a guard test fails until its
switch and a row on this page are added with it.

### Agent harnesses

A node can be placed with a harness of kind `noo`, `claude-code`, `copilot`
or `codex` (`noo cluster place <node> harness <model> --kind ...`). The kinds
are declared once, in `config/harness-kinds.json`, which the gateway and the
node agent both embed. Which kinds run today and which chat backends each can
use are in
[../getting-started/supported-agent-harnesses.md](../getting-started/supported-agent-harnesses.md). `noo` is noomesh's
own loop. The other three are third-party CLIs with their own reporting.

**Status: the foreign runners are not shipped.** The node agent accepts a
`claude-code`, `copilot` or `codex` placement, checks that the node's chat
backend speaks the CLI's wire format, and then refuses to start it ("its
runner is not shipped yet"). No noomesh image or installer provides
any of these CLIs. So today nothing launches them and nothing leaves the network
because of them. The switches are declared now so the runner cannot ship
without them: each kind's `telemetry_off` entry in `config/harness-kinds.json`
holds them, and whatever launches a CLI must merge that entry
into the CLI's environment after any placement value, so a placement cannot
turn reporting back on. A guard test fails if a kind has no entry, if a
switch below goes missing, or if a foreign kind with no switches declared
gets a runner.

Codex CLI's switches are not declared yet: its `telemetry_off` entry is
empty, so this page lists none for it, and the guard keeps it runner-less
until they are.

| Kind | Switch | What the vendor's documentation says |
|---|---|---|
| `claude-code` | `CLAUDE_CODE_DISABLE_NONESSENTIAL_TRAFFIC=1` | "Set to any non-empty value, such as `1`, to disable nonessential network traffic: auto-updates, telemetry, error reporting, the `/feedback` command, ... release notes" ([env-vars](https://code.claude.com/docs/en/env-vars)) |
| `claude-code` | `DISABLE_TELEMETRY=1` | "Set to any non-empty value, such as `1`, to opt out of telemetry." ([env-vars](https://code.claude.com/docs/en/env-vars)) |
| `claude-code` | `DISABLE_ERROR_REPORTING=1` | "Set to any non-empty value, such as `1`, to opt out of error reporting." ([env-vars](https://code.claude.com/docs/en/env-vars)) |
| `claude-code` | `DISABLE_FEEDBACK_COMMAND=1` | "Set to `1` to disable the `/feedback` command ... Also disables `/bug` and `/share` ... The older name `DISABLE_BUG_COMMAND` is also accepted" ([env-vars](https://code.claude.com/docs/en/env-vars)) |
| `claude-code` | `CLAUDE_CODE_DISABLE_FEEDBACK_SURVEY=1` | "Set to `1` to disable the 'How is Claude doing?' session quality surveys." ([env-vars](https://code.claude.com/docs/en/env-vars)) |
| `claude-code` | `DISABLE_UPDATES=1` | "Set to `1` to block all updates including manual `claude update` and `claude install`. Stricter than `DISABLE_AUTOUPDATER`." ([env-vars](https://code.claude.com/docs/en/env-vars)) |
| `claude-code` | `DO_NOT_TRACK=1` | "Set to `1` to opt out of telemetry, with the same effect as `DISABLE_TELEMETRY`" ([env-vars](https://code.claude.com/docs/en/env-vars)) |
| `claude-code` | `CLAUDE_CODE_DISABLE_OFFICIAL_MARKETPLACE_AUTOINSTALL=1` | "Set to `1` to disable automatic registration of the official plugin marketplace. Claude Code reads the variable when it is about to register the marketplace, usually during a machine's first interactive launch." Anthropic's `CLAUDE_CODE_DISABLE_NONESSENTIAL_TRAFFIC` row says the official plugin marketplace auto-install "isn't covered" by it ([env-vars](https://code.claude.com/docs/en/env-vars)) |
| `copilot` | `COPILOT_OFFLINE=true` | "Set `COPILOT_OFFLINE=true` to prevent Copilot CLI from contacting GitHub's servers." "In offline mode, all telemetry is disabled and the CLI only communicates with your configured provider." ([GitHub changelog, 2026-04-07](https://github.blog/changelog/2026-04-07-copilot-cli-now-supports-byok-and-local-models/); [BYOK guide](https://docs.github.com/en/copilot/how-tos/copilot-cli/customize-copilot/use-byok-models)) |

What the switches do not cover, stated plainly:

- **Claude Code's WebFetch hostname check.** Before a WebFetch the CLI sends
  the requested hostname (only the hostname) to `api.anthropic.com`. Anthropic
  says this "is not affected by `CLAUDE_CODE_DISABLE_NONESSENTIAL_TRAFFIC`";
  its opt-out is the settings key `skipWebFetchPreflight`, not an environment
  variable ([data usage](https://code.claude.com/docs/en/data-usage)). The
  runner must write that setting too, or leave the WebFetch tool off.
- **Copilot CLI has no separate telemetry switch.** GitHub documents none;
  offline mode is the only documented way. Offline mode also removes the
  features that need GitHub (`/delegate`, the GitHub MCP server, code
  search), and it needs a bring-your-own-model provider
  (`COPILOT_PROVIDER_BASE_URL`, here the node's own model endpoint). Without
  offline mode Copilot would use GitHub's service and GitHub sign-in, which
  would be chosen outbound traffic, not something noomesh does for you.
  noomesh's copilot harness is offline-only.
- **A harness pointed at a cloud model** sends its prompts to that vendor.
  That is the chosen cloud-model traffic in
  [the table below](#outbound-traffic-that-is-not-telemetry), not telemetry.
  The node harness is pointed at the node's own agent over loopback, so by
  default this does not arise.
- **`noo cluster verify`.** The `vendor telemetry` row is built from the node
  agent's report on running backend containers. A harness is a host service
  and reports no environment today, so the row does not cover it; with no
  runner there is nothing to check yet. Reporting the harness's switches into
  that row is open work to land with the runner.

### Paid add-ons

The Intelligent tier (graph-guided retrieval, enrichment, temporal graph) and
the self-tuning engines (genetic search, reflection loop, reinforcement
learning) were audited for outbound network use: every call site, every
dependency list and each image's environment. They send nothing to
PersonifAI or to any vendor.

- Their traffic goes to services of your own deployment: the gateway, the
  message bus, Postgres and the model endpoints you configured for the
  worker. The self-tuning engines reach the gateway over TLS with the
  cluster's own certificates.
- A model call goes to whatever endpoint your configuration names. If that is
  a cloud model, the prompt goes there, as in the cloud-models row below; the
  add-ons do not choose a cloud model on their own.
- Neither package downloads models or data at runtime, contains an analytics,
  crash-reporting or experiment-tracking client, or checks a licence or
  version online.
- Pulling an add-on is the only contact with the vendor: when the licence names
  a pull location, `noo addons enable|upgrade` and `noo upgrade --stack` fetch
  the add-on's signed lock and images from the vendor's add-on registry
  (`addons.noomesh.ai`) with the licence as the credential (row below). A
  running add-on never checks its licence online.
- The Intelligent tier image is built on the open ML image and inherits its
  Hugging Face switches. The self-tuning engines image has no Hugging Face
  library; its compose service sets the same two switches anyway.
- Installing them (building an image) reaches the package registries, like
  any build.

## Host software

noomesh installs `tailscaled` on every node, runs `brew` on a Mac, and runs on
an OS that has reporters of its own. Their defaults are not noomesh's, so each
is listed here with what it sends and what noomesh does about it. The rule
is the one above: no vendor phone-home. Fleet-internal observability
(Prometheus, Loki, Grafana, gateway counters, `noo cluster verify`) stays on.

| Component | What it sends by default | The switch | Where noomesh sets it | How to check |
|---|---|---|---|---|
| **Tailscale** (`tailscaled`, Linux and the Mac brew formula) | Client operational logs, uploaded continuously to Tailscale's log server (`log.tailscale.com`, `log.tailscale.io` in older clients). | `tailscaled --no-logs-no-support`, or the same switch as the environment variable `TS_NO_LOGS_NO_SUPPORT=true` (Tailscale: "disable log uploads; this also disables any technical support"). **It opts you out of Tailscale technical support**, because support reads those logs; that is the whole price. It does not touch the tailnet, node keys or policy. Tailscale documents it for Linux and for the open-source `tailscaled` on macOS, **not** for the Standalone or App Store Mac apps. | **New Linux node:** `noo enroll` appends `TS_NO_LOGS_NO_SUPPORT=true` to `/etc/default/tailscaled` (the unit loads it as an EnvironmentFile) and restarts tailscaled, before `tailscale up`, only when the file does not already carry it. The controller's `noo onboard` does the same, only when it has just installed Tailscale. **New Mac node:** `noo enroll` adds the key to the brew service's launchd plist (`/Library/LaunchDaemons/homebrew.mxcl.tailscale.plist`, `EnvironmentVariables:TS_NO_LOGS_NO_SUPPORT`) and restarts the job with `launchctl` (never `brew services`, which regenerates the plist). **Existing nodes:** noo-hostd reports it, and the operator applies it with one command from the controller, `noo cluster host-telemetry apply` (below). Restarting tailscaled drops the node's tailnet link for a few seconds and on the controller every node's path to it, so nothing restarts it unattended: not an upgrade, not noo-hostd. | `noo cluster verify` row `host telemetry` (FAIL while the running tailscaled uploads). By hand: `tr '\0' '\n' < /proc/$(pidof tailscaled)/environ \| grep TS_NO_LOGS` (root), or `grep -r no-logs /etc/default/tailscaled`. |
| **Homebrew** (Mac) | Install analytics (package names, options, OS and CPU, Homebrew version) on by default. | `HOMEBREW_NO_ANALYTICS=1`, or `brew analytics off` (persistent, kept in brew's git config). | Every `brew` command `noo enroll` runs carries `HOMEBREW_NO_ANALYTICS=1`, and enroll runs `brew analytics off` once. `scripts/setup-dev.sh` exports it. | `brew analytics state` |
| **Ubuntu reporters** (Linux nodes) | `motd-news`: fetches from `motd.ubuntu.com` at login and on a timer. `popularity-contest`: weekly package report to `popcon.ubuntu.com`. `whoopsie` (with `apport`): uploads crash reports to `daisy.ubuntu.com`. | motd-news: `ENABLED=0` in `/etc/default/motd-news` and `systemctl disable --now motd-news.timer`. popularity-contest: `PARTICIPATE="no"` in `/etc/popularity-contest.conf`. whoopsie: `systemctl disable --now whoopsie`. | **Not set.** They belong to the operating system and the operator, so noo-hostd reports each enabled one and `noo cluster verify` WARNs with the exact command. `ubuntu-report` and `ubuntu-insights` ask per user and are not checked. | `noo cluster verify` row `host telemetry`. |
| **Docker Engine** (Linux) | Nothing. | None needed. | n/a | n/a |
| **Docker Desktop** (Mac) | Diagnostics, crash reports and usage data unless "Send usage statistics" is off (Settings, General; stored in `~/Library/Group Containers/group.com.docker/settings-store.json`). | Turn the setting off. | **Not set, not checked.** The JSON key was not confirmed against Docker's documentation, so noomesh does not guess it. | Settings, General. |
| **NVIDIA driver, `nvidia-container-toolkit`** | Nothing known: the driver and the container runtime hook make no network calls of their own; the apt repository is contacted only when you install or update. Not packet-captured. | None. | n/a | n/a |
| **snapd, `apt`, `unattended-upgrades`** | Package and snap store contacts for updates. This is the OS updating, not a report about you; it is not switched off. | n/a | n/a | n/a |

`noo cluster verify` judges the `host telemetry` row from what noo-hostd reads
as root: the running tailscaled's command line and environment (not just the
file, since a file edited without a restart changes nothing), the
`/etc/default` files above, and `systemctl is-active whoopsie`. The row is a
sibling of `vendor telemetry`, not part of it: that row is built from the node
agent's report on backend containers and is fixed by `noo cluster provision`,
while this one is about the host and is fixed by a command on the node. A
node whose hostd is too old to report shows WARN, never a pass. A Mac reports
only its brew tailscaled.

### Tailscale logs: what you give up, what you keep

With the switch on, **Tailscale cannot see this node's logs.** Tailscale
support, and anything built on those logs such as `tailscale bugreport`, has
nothing to look at, and Tailscale's own docs say it "may not be able to
provide technical support". What you keep: tailscaled still logs locally. The
switch only replaces its upload transport with a no-op (Tailscale's
`logpolicy`: local output to stderr continues unchanged). On Linux that is
the journal (`journalctl -u tailscaled`); on a Mac it is the brew service's
log file (`/opt/homebrew/var/log/tailscaled.log`). The node agent ships both
to Loki on every node, so they are in Grafana as `{name="tailscaled"}`
(noo-hostd's journal allowlist carries `tailscaled`; the Mac agent tails the
brew log). They go through the same secret-redaction as every other shipped
log.

**Opting in when you need Tailscale support.** It is a per-node choice, off by
default, and reversible:

```sh
# Linux: let this node upload again (undo with the line in the next block)
sudo mkdir -p /etc/noo && sudo touch /etc/noo/allow-tailscale-log-upload
sudo sed -i '/TS_NO_LOGS_NO_SUPPORT/d' /etc/default/tailscaled   # and drop --no-logs-no-support from FLAGS if you put it there
sudo systemctl restart tailscaled
```

On a Mac, create the same marker file, then
`sudo /usr/libexec/PlistBuddy -c 'Delete :EnvironmentVariables:TS_NO_LOGS_NO_SUPPORT' /Library/LaunchDaemons/sh.brew.tailscale.plist`
(`homebrew.mxcl.tailscale.plist` under older Homebrew)
and the `launchctl bootout` / `bootstrap` pair from above. While the marker
exists, `noo enroll` leaves the switch off, and `noo cluster verify` shows
`host telemetry` as WARN "uploads ... by operator choice" instead of FAIL,
with the way back (`sudo rm /etc/noo/allow-tailscale-log-upload` and the switch
command). There is no fleet-wide setting yet; the choice is per node.

**Applying it to nodes enrolled before the switch existed.** From the
controller, one command, over the signed pull rail (no SSH):

```sh
noo cluster host-telemetry apply --all            # every online remote node, one at a time
noo cluster host-telemetry apply node-2 node-1     # or just these
noo cluster host-telemetry apply --all --include-controller   # also the controller's own node, LAST
```

It asks first (`-y` skips). It delivers a signed `host-telemetry` bundle to one
node, waits for the node's `noo-apply` to report success and then for the
node's next heartbeat, and only then moves to the next; a node that does not
come back stops the roll and the rest are reported "not attempted". The
controller's own node is left out unless you pass `--include-controller`, and
then goes last, after a warning: restarting its tailscaled drops every node's
path to the controller for a few seconds, so run it at the controller's
console if you can.

What the bundle can do is fixed. It carries only the node's own name
(`NODE=<name>`); `noo-apply` refuses any other content. On the node it sets
`TS_NO_LOGS_NO_SUPPORT=true` in `/etc/default/tailscaled` (Linux) or the brew
tailscale LaunchDaemon plist (Mac), restarts `tailscaled` (Mac: `launchctl
bootout`/`bootstrap`, never `brew services`) only if something changed or the
running process lacks the switch, and on a Mac runs `brew analytics off`. It
does nothing on a node with `/etc/noo/allow-tailscale-log-upload`, and a rerun
is a no-op. It touches no other file, key or service. A node whose
`noo-apply` predates the kind refuses the bundle (exit 76); update it with
`noo cluster upgrade-applier <node>` or use the by-hand commands:

```sh
# Linux node (on the controller: at the console, because the tailnet drops for a few seconds)
echo 'TS_NO_LOGS_NO_SUPPORT=true' | sudo tee -a /etc/default/tailscaled && sudo systemctl restart tailscaled

# Mac node (brew tailscale) (on the controller: at the console, because the tailnet drops for a few seconds)
echo 'TS_NO_LOGS_NO_SUPPORT=true' | sudo tee -a /etc/default/tailscaled && sudo systemctl restart tailscaled

# Mac node (brew tailscale)
P=/Library/LaunchDaemons/sh.brew.tailscale.plist; [ -f $P ] || P=/Library/LaunchDaemons/homebrew.mxcl.tailscale.plist
sudo /usr/libexec/PlistBuddy -c 'Add :EnvironmentVariables dict' $P
sudo /usr/libexec/PlistBuddy -c 'Delete :EnvironmentVariables:TS_NO_LOGS_NO_SUPPORT' $P
sudo /usr/libexec/PlistBuddy -c 'Add :EnvironmentVariables:TS_NO_LOGS_NO_SUPPORT string true' $P
sudo launchctl bootout system $P; sudo launchctl bootstrap system $P
```

### Kiosk displays

A kiosk display is **not an enrolled node**. `noo kiosk setup` turns a Linux
box with a screen into a viewer: a `kiosk` user, `cage` and Chromium under
systemd, a launcher and a watchdog. No node agent and no noo-hostd run there
(the design is in `noo-cli/src/commands/kiosk.rs`), so nothing on the display
reports to `noo cluster verify`, and the rail does not reach it. Its
operator-installed tailscaled (the display joins the tailnet as `tag:kiosk`)
and its OS therefore need their own coverage:

| On the display | Default | What `noo kiosk` does |
|---|---|---|
| Chromium | background services | `noo-kiosk-launch` carries the quiet-flag group (see Components). |
| `tailscaled` | uploads client logs | `noo kiosk setup` runs the same step as `noo enroll`: `TS_NO_LOGS_NO_SUPPORT=true` in `/etc/default/tailscaled`, restart only if it was added, nothing where `/etc/noo/allow-tailscale-log-upload` exists or tailscaled is not installed. |
| Ubuntu `motd-news`, `popularity-contest`, `whoopsie` | on, on Ubuntu | **Not set** (the OS's), reported by `noo kiosk status` with the same command as in the table above. |
| Raspberry Pi OS | The three above are Ubuntu's, not Raspberry Pi OS's | Nothing to switch. Raspberry Pi Connect is installed on the Desktop and Full images but off until someone turns it on (`rpi-connect off` makes sure); Raspberry Pi's documentation does not say whether it sends anything while off. It is a per-user service, so noomesh does not check it. |
| Google Chrome (the `.deb` some Ubuntu displays use) | has its own usage-statistics and crash-report settings | The launcher's flags (`--no-first-run`, `--disable-breakpad`, `--metrics-recording-only`) are the only control noomesh applies; it sets no Chrome policy. Debian's `chromium` has no such vendor account to reason about. |

`noo kiosk status` has two rows for this, read without privilege:
`tailscale logs` and `os reporters`. A file-configured switch is judged by
whether tailscaled started after the file was written (a root process's
environment is unreadable to the operator), so the row says "predates it"
rather than claiming a pass when a restart is still owed. `noo kiosk teardown` leaves the tailscaled switch in place (it is
not the seat's to undo; the opt-in marker is the way back).

### Phones and other client devices

noomesh ships **no phone app**. A phone reaches it two ways: the web console
in a browser, and the official Tailscale app that puts the phone on the
tailnet.

- **What noomesh controls on a phone: nothing but the console.** The console
  is served by the gateway and loads no third-party scripts, fonts or
  analytics; it registers no service worker and has no web-app manifest, so
  nothing runs in the background after the tab closes (checked in
  `ui/apps/web`: `index.html`, `kiosk.html` and `src` contain no external
  `src`/`href`, no `serviceWorker`, no analytics package; a test fails if one
  appears).
- **`noo_device_*` tools (camera, location, clipboard, screenshot, audio,
  battery) are not fed by a phone client.** They call `POST /api/v1/device/<action>`
  on the gateway, which proxies to a **companion node's node agent** (tier 5, a
  host that runs the agent: a Pi with a webcam, a laptop). Their data comes from that host's
  hardware, so a companion is a node, and the Host software rules above apply
  to it. Nothing runs on a phone for them.
- **What you can do about Tailscale's log upload on a phone.** Tailscale
  documents `--no-logs-no-support` / `TS_NO_LOGS_NO_SUPPORT` for Linux, for
  Windows (`tailscaled-env.txt`) and for the open-source `tailscaled` on macOS.
  Its [logging page](https://tailscale.com/docs/features/logging) documents **no
  opt-out for the iOS or Android apps**, and none for the Standalone and App
  Store Mac apps. So the honest answer is: it cannot be switched off, from
  noomesh or by the operator, short of not putting that phone on the tailnet.
  A phone that must not upload Tailscale logs should not run the Tailscale app;
  that also means it cannot reach a tailnet-only console. Tailscale support
  access and logging are Tailscale's, set by Tailscale's app, and are outside
  what noomesh can promise.
- **What the operator can do.** Keep phones off the tailnet that carries
  sensitive nodes (an ACL, or a separate tailnet), treat a phone as an
  untrusted viewer of the console, and sign it out of the console when done.
  Neither of these removes the app's own log upload.

## Checking a Mac

A Mac node runs ollama natively (brew + launchd), not in a container. Check
the switch in its plist — `sh.brew.ollama` under current Homebrew,
`homebrew.mxcl.ollama` under older releases — and in the job launchd runs
(`gui/<uid>` at the Mac's screen, `user/<uid>` on a headless Mac over SSH):

```sh
L=sh.brew.ollama; [ -f ~/Library/LaunchAgents/$L.plist ] || L=homebrew.mxcl.ollama
plutil -p ~/Library/LaunchAgents/$L.plist | grep -A6 EnvironmentVariables
launchctl print gui/$(id -u)/$L 2>/dev/null || launchctl print user/$(id -u)/$L
```

`OLLAMA_NO_CLOUD = 1` must be listed. `noo cluster verify <node>` reports the
same in its `vendor telemetry` row, judged from the plist and the running
`ollama serve` process's environment.

noomesh manages the native ollama only when it runs as the Homebrew launchd
service (that plist, loaded at login). If you run Ollama.app, or an
`ollama serve` you started by hand, noomesh does not touch it, but the node
agent still reads the running process's environment, so the switch is proven
rather than guessed: the row passes when the process has `OLLAMA_NO_CLOUD=1`,
fails when it does not, and names the launcher (`brew-service`, `ollama-app`,
`manual`) so the remedy fits. Only when the process cannot be read does the row
say "not managed by noomesh" and stay unproven. The fix for a failing
Ollama.app or hand-run ollama is to quit it and run `HOMEBREW_NO_ANALYTICS=1 brew services start
ollama`; the agent then sets the switch within a minute. Turn off Ollama.app's
own login item as well, or it and the brew service will both try to serve on
port 11434. Note that `brew services restart ollama` regenerates the plist
without the key; the node agent puts it back and restarts ollama once, within
a minute.

## How the switches stay on

- **Compose.** Every service in `docker-compose.cluster.yml` and the add-on
  overlays carries its switches as literal values. They are not
  `${VAR:-1}`, so no `.env` can turn them off.
- **Node agent.** The backends the agent starts on every node (vLLM, TEI,
  Ollama, AirLLM) carry the same switches in their backend specs. After
  placement and node-local overrides are applied, the agent sets the
  switches again, so a placement's `env` cannot turn them back on.
- **Mac node.** The native brew ollama is not a container. `noo enroll` writes
  the switch into its launchd plist and restarts the job with `launchctl`
  (never `brew services`, which regenerates the plist from the formula). The
  agent re-checks every minute, restarts ollama once if it had to add the
  key, and reports it as `backend_containers.ollama.telemetry_missing`.
- **Recreate on upgrade.** The agent's env generation is part of each
  placement's spec hash. The first reconcile after an agent upgrade
  therefore recreates each backend once, and an existing container without
  the switches does not keep running.
- **Images.** The Python images set `HF_HUB_DISABLE_TELEMETRY` and
  `DO_NOT_TRACK` with `ENV`.
- **Guard test.** `tests/test_no_vendor_telemetry.py` holds the list. It
  fails if:
  - a compose service is not classified, or lacks a switch;
  - a node-agent backend spec lacks a switch;
  - the agent's switch table and the test's table disagree;
  - an image or Chromium launch drops a switch;
  - Loki's reporting is turned back on;
  - a known phone-home package becomes a dependency;
  - the kiosk seat stops switching off tailscaled's upload, or `noo kiosk
    status` loses its telemetry rows;
  - the web console gains a service worker, a manifest or an external script;
  - the `host-telemetry` bundle gains any capability beyond its one key.

## Verify it yourself

```bash
noo cluster verify            # node row `vendor telemetry`: FAILs on any running backend missing a switch
noo cluster verify --controller   # `grafana door` row covers Grafana's settings
```

For each node, the agent reports which switches each running backend
container is missing. It sends only the names, never the values. The row
FAILs on any missing switch. If the agent is too old to report, the row
shows WARN, never a pass.

On the controller's self-node the stack's `ollama-embed` is ADOPTED as the node's `ollama`: the agent never recreates it, and an old agent-created `noo-ollama` (plus `noo-stunnel-ollama`) left from before the adoption is an orphan nobody manages. The agent reports it (`backend_containers.ollama.orphan`, with `container` and `sidecars`), and the `vendor telemetry` row still FAILs, naming the orphan, with `docker rm -f noo-ollama noo-stunnel-ollama` as the remedy — `noo cluster provision` cannot fix it. The agent removes nothing itself.

By hand, on a node:

```bash
docker inspect noo-vllm --format '{{range .Config.Env}}{{println .}}{{end}}' \
  | grep -E '^(VLLM_NO_USAGE_STATS|VLLM_DO_NOT_TRACK|DO_NOT_TRACK|HF_HUB_DISABLE_TELEMETRY)='
docker exec noo-vllm ls /root/.config/vllm/   # no usage_stats.json in a container started with the switches
```

To check the network itself, capture DNS on the host for a few minutes
after the stack starts, for example with
`tcpdump -i any -n port 53`. None of these names should appear:
`stats.vllm.ai`, `stats.grafana.org`, `grafana.com`, `huggingface.co/api/telemetry`
or `ollama.com`. The exception is a model download or cloud call you
started yourself.

## Outbound traffic that is not telemetry

Each item below runs only when you start it, either directly or through a
setting you chose. None of it is a report about you or your machines.

| Traffic | Destination | When |
|---|---|---|
| Model downloads | Hugging Face Hub (`huggingface.co`, its CDN) | A vLLM, TEI, AirLLM or `noo models` pull of a model that is not already cached. Whisper and Piper fetch their model or voice on first use. A model preseeded from the controller's model store (`HF_HUB_OFFLINE=1`) does not reach the Hub. |
| Ollama model pulls | `registry.ollama.ai`, `ollama.com` | An Ollama placement or pull of a model that is not cached |
| Model catalog browsing | `huggingface.co` API, `ollama.com`, `registry.ollama.ai` | `noo models search`; `noo models list` / `recommended` / `ollama` with `--refresh` or an expired catalog cache |
| Image pulls | `ghcr.io`, `dhi.io`, Docker Hub, `mcr.microsoft.com`, NVIDIA | `noo stack start`, `noo upgrade`, provisioning, building images |
| Releases and install | `api.github.com`, `github.com`, `raw.githubusercontent.com` | `noo upgrade`, the installer, node bootstrap |
| Add-on pulls | `addons.noomesh.ai` (the vendor's add-on registry) and `pkg-containers.githubusercontent.com` (large layers it redirects to) | `noo addons enable|upgrade`, and `noo upgrade --stack` with a licensed add-on on, when the licence names a pull location. The vendor sees the licence id, add-on, digest, bytes and status for 30 days, never an IP address. With `NOO_ADDON_REGISTRY_TOKEN` in the store the controller pulls from `ghcr.io` instead and never contacts it. |
| Tailnet | Tailscale coordination (`controlplane.tailscale.com`) and DERP relays; `api.tailscale.com` | Always while `tailscaled` runs on a host: this is how the node reaches the controller, so it is function, not telemetry, and is not switched off. Tailscale's client *log upload* is a different thing and is switched off (see [Host software](#host-software)). noomesh calls `api.tailscale.com` itself only when it provisions or removes a node with your Tailscale OAuth credentials. |
| Channels | Google Chat, Google Pub/Sub, Telegram APIs; Meta's WhatsApp Cloud API (`graph.facebook.com`, outbound sends only) | Only for a channel you have configured |
| Cloud models | Anthropic, OpenAI, Google Gemini APIs | Only when `CLOUD_PROVIDERS_ENABLED` is on, a `claude-*`, `gpt-*` or `gemini-*` model is selected and its key is configured. The model runs the full agent loop, so each request carries the whole turn: the system prompt with retrieved context and memory, the conversation, the tool definitions and the tool results |
| Agent harness on a cloud model | The model vendor (Anthropic for Claude Code, the provider you set for Copilot CLI, OpenAI for Codex CLI) | Only if a third-party harness is pointed at a cloud model instead of the node's own endpoint. The prompts go to that vendor: this is the cloud-model traffic above, not telemetry. Not reachable today: the foreign runners are not shipped. |
| Web search | DuckDuckGo's HTML endpoint, or the provider set in `search.provider` (SearXNG, Brave, Tavily) | When an agent, a chat or a scheduled task uses `web_search` |
| Browser tool | Whatever page it is sent to | When an agent uses the browser tool. `BROWSER_URL_ALLOWLIST` limits it. |
| Build-time package installs | PyPI, the PyTorch wheel index, Go and crates.io registries, Debian/Alpine mirrors | Building images, not running them |

These are out of scope here:

- The host operating system beyond what [Host software](#host-software)
  lists, including NTP, DNS and package updates. noomesh reports the Ubuntu
  reporters but does not change them. Docker Desktop's usage data is yours
  to turn off in its settings. Docker Engine sends none.
- Images you add yourself, such as MCP servers and skill containers.

The `sandbox` service has no route out at all: its network is
`internal: true`.
