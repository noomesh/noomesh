# Developer Guide

How to build, test and extend noomesh. The repository holds four
codebases — the Rust `noo` CLI, the Rust gateway, the Go node-agent and the
Python worker package — and each has its own toolchain. This page tells you
which command to run for which tree, what the tests look like, and where the
sanctioned extension points are. What each component *is* and how they talk
is in the source tree's module docs.

The whole suite in one line, from the repo root:

```bash
pytest tests/ && scripts/cargo-docker.sh check --tests && (cd node-agent-go && go test ./...)
```

## Repository layout

```
noo-cli/                 Rust — the `noo` binary (NATIVE registry in src/main.rs, usage lines in src/usage.rs,
                         one file per command group in src/commands/, the onboard wizard in src/onboard/)
gateway-rust/            Rust — the gateway (src/main.rs, src/routes/ one file per domain, src/coordinator/,
                         scheduler_*.rs, autonomy_*.rs, heartbeat_*.rs, channels/, mcp_local.rs, mcp_external.rs,
                         mesh_migrate.rs; .sqlx/ is the committed offline query cache)
node-agent-go/           Go — noo-node-agent and noo-hostd (cmd/, internal/, deploy/ templates, Makefile)
src/noomesh/             Python — the worker package: workers/ (NATS handlers), mcp/tool_defs/ (tool
                         definitions), memory/, cluster/ (placement + job CRUD), channels/ (outbound only),
                         config.py, settings.py, posture.py, the reference *_cli.py modules
scripts/                 host-side shell: noomesh-start.sh and the lib-*.sh it sources, cargo-docker.sh,
                         prep-host.sh / noo-apply.sh / noo-fetch.sh (the node pull rail), setup-dev.sh, docs-check.py,
                         gen-cli-docs.py, build-mcp-manifest.py, wsl-vhdx-compact.ps1
docker/                  every Dockerfile (deps-core, deps-base, gateway-rust, worker, trellion, node-agent-go,
                         sandbox, postgres, whisper, piper, nvidia-exporter, …) and sidecar configs
docker-compose.cluster.yml   the one compose file; docker-compose.dist.yml is the pull-only overlay
skills/                  builtins/ and examples/ containerised skills (manifest.yml + run.py)
config/tools.json        the exported tool registry the gateway reads (regenerate with `noo tools export`)
prompts/                 the live coordinator system prompt (coordinator.md) + skills/{core,evolved}
                         (loaded by gateway-rust/src/prompt_skills.rs)
plugins/weather          a sample plugin only; the live plugin dir is NOO_PLUGIN_DIR or ~/.noo/plugins
tests/                   pytest suite (unit) and tests/integration/ (needs a running gateway)
docs/                    this documentation; internal/ never ships
```

## Set up a dev environment

On a Linux, WSL2 or macOS box, one script installs or verifies everything
below and is safe to re-run:

```bash
git clone <your-fork> && cd noomesh
scripts/setup-dev.sh --dry-run   # print the plan, change nothing
scripts/setup-dev.sh
```

It installs Docker Engine + Compose v2 (on WSL2 it leaves Docker Desktop
alone if that serves `docker`; on macOS it checks for Docker Desktop or
colima), the NVIDIA container toolkit when `nvidia-smi` works, Rust via
rustup, Go at the `node-agent-go/go.mod` version, Python from
`.python-version` with `./venv` and the extras below, Node 22 with `npm ci`
in `ui/`, the repo's git hooks and pre-commit's hook environments, and the
`noo` binary. On WSL2 it first checks that systemd is on in
`/etc/wsl.conf` and prints the fix if it is not; after a WSL rebuild, bind
mounts under `/mnt` need `sudo mount --make-rshared /` (see
[wsl-disk.md](wsl-disk.md) for keeping the distro's disk in check).

To do it by hand instead — prerequisites: Python 3.12, Docker with Compose
v2, Go (see `node-agent-go/go.mod` for the version), and no Rust toolchain —
Rust builds run in a container.

That 3.12 is not a minimum, it is *the* version: the images install exactly
one interpreter and CI tests exactly that one. `.python-version` at the repo
root is where it is declared, and `tests/test_python_version_single_source.py`
holds every other place in the tree to it.

```bash
git clone <your-fork> && cd noomesh
python3.12 -m venv venv && source venv/bin/activate
pip install -e ".[dev,web,cache]"
pre-commit install           # git hooks that run the checks on each commit
python3 -m pytest -q         # post-install smoke test (unit suite)
```

To run the checks by hand instead, before you push:
`pre-commit run --from-ref origin/dev --to-ref HEAD`.

The editable install also leaves a legacy Python CLI on your venv's PATH as
`noo-py`. The `noo` you operate with is the Rust binary, and it never runs
that script: an unknown command or subcommand prints a usage error and
exits 2 rather than falling through to Python. Install the Rust binary from the release
one-liner in the [README](../../README.md#quick-start) or build it from
`noo-cli/` (below).

Once a stack is running, `noo health` (GET `/health`, per-dependency table)
is the live reachability check — see
[docs/getting-started/install.md](../getting-started/install.md).

Run the stack from local source:

```bash
noo stack start            # builds from this tree (NOO_INSTALL_MODE=dev or absent)
noo stack rebuild gateway  # rebuild one image after a change
noo health
```

`--dev` forces a one-off source run on an install whose persisted mode is
`dist`. Never `docker compose up` by hand — the launcher exports secrets,
`compose_env` and the profile set first.

## Build and check each tree

### Rust (gateway and CLI) — always through `scripts/cargo-docker.sh`

There is no host Rust toolchain. The script runs cargo in a `rust:1-bookworm`
container with `--user` set, mounts your cargo registry from `$HOME` so
repeat runs take ~35 s instead of ~10 min, and resolves the crate from the
directory you are standing in (so a worktree builds the worktree, not the
main clone).

```bash
scripts/cargo-docker.sh check                       # gateway-rust
scripts/cargo-docker.sh check --tests               # also compiles #[cfg(test)]
scripts/cargo-docker.sh test --locked
scripts/cargo-docker.sh clippy -- -D warnings
CARGO_DOCKER_CRATE="$PWD/noo-cli" scripts/cargo-docker.sh test          # the CLI crate
CARGO_DOCKER_CRATE="$PWD/noo-cli" CARGO_DOCKER_COMPONENTS=clippy \
  scripts/cargo-docker.sh clippy --all-targets -- -D warnings
```

Why not a hand-rolled `docker run … cargo`: without `--user`, cargo writes
`target/` as root and the first thing that breaks is `git worktree remove`.

`sqlx::query!` needs a schema at compile time and the build has no
database, so `gateway-rust/.sqlx/` is committed and `SQLX_OFFLINE=true` is
set in the builder and in CI. After touching any SQL, regenerate it with
`scripts/sqlx-prepare.sh`; `cargo check` fails closed on a query with no
cached entry.

### Go (node-agent, hostd)

```bash
cd node-agent-go
go vet ./... && go test ./...
make build-all          # linux amd64 + arm64 binaries into bin/
make build-mac          # darwin arm64, on request only
```

`make` produces both `noo-node-agent-*` and `noo-hostd-*` per platform.
Integration tests that need Docker are guarded (`NOO_DOCKER_SMOKE`).

### Python

```bash
ruff check src tests
mypy src
pytest tests/
python3 scripts/build-mcp-manifest.py --check    # the MCP manifest the gateway serves must match tool_defs/
noo tools export --check                          # config/tools.json must match the registry
```

### Docs

```bash
python3 scripts/docs-check.py            # index, links, forbidden strings, no internal/ citations
python3 scripts/gen-cli-docs.py --check  # generated CLI tables are fresh
```

CI runs all of the above (`.github/workflows/ci.yml`: `preflight`, `test`
on a Python matrix, `go-node-agent`, `rust-gateway`, `noo-cli`).

## Tests

### Proving a guard works

A test for a bug you just fixed is worth nothing until you have **seen it
fail**. Break the fix — revert the condition, stub the check out — run the
test, read the failure message, then restore. If it still passes, it is not
testing what you think.

The trap is in the restore-and-re-run, which is the one step nobody checks:

- **Verify the plant landed by reading the file back, at an ABSOLUTE path,
  before the run.** Never infer it from the run's result. "The test passed,
  so the guard holds" and "the test passed, so my plant did not compile" are
  indistinguishable from the output.
- `scripts/cargo-docker.sh` and any `docker run` mount a **path**, and
  compile whatever is on disk there. A `cd` inside a shell function, a
  relative `cp` after that `cd`, a stray file created one directory up —
  each silently leaves the previous source in place. On 2026-09-12 a restore
  written to the wrong relative path meant the container kept compiling the
  *previous* plant, and the test under examination "passed"; the plant it
  was supposed to be failing had never been applied.
- Plant from **both** directions when a rule has two sides. A window that
  never opens and a window always open should each fail a *different*,
  named subset of the tests. If the same tests fail both ways, one of the
  conditions is not being exercised.
- Assert your **fixtures**, not just your subject: that the migration added
  the column, that the backdating `UPDATE` moved exactly one row, that the
  parse found something. A fixture that quietly did nothing turns every
  assertion below it into a pass for the wrong reason.

This is the same failure shape as the `pythonpath` note below — a green run
against code you did not actually compile — and it is why that note exists
too.

### A skip in CI must be explained

A guard that skips in CI guards nothing, and nobody notices: PR #551 added
an 18-case parity test gated on a `noo-cli/target/debug/noo` binary that the
CI pytest job never builds, so all 18 cases skipped — the PR's evidence
never ran where it counts. `tests/_ci_skip_guard.py` (wired up from
`tests/conftest.py`) makes that a build failure instead of a silent log
line: in CI, every skipped test must match an entry in
`tests/ci_skip_allowlist.txt`, or the session fails with one line per
unexplained skip.

Allow-list format, one entry per line:

```
<glob on nodeid> | <regex on skip reason> | <why this skip is acceptable in CI>
```

`#` comments and blank lines are ignored; all three fields are required — a
line missing the justification fails the session, naming the line. The glob
matches the pytest nodeid (`fnmatch`); the regex is searched (`re.search`)
against the reason pytest recorded for the skip.

An entry that matches nothing on a *full* `pytest tests` run (no `-k`, no
`-m`, no narrowed path) is stale — a rule that excuses nothing today will one
day excuse a skip nobody meant to allow. In CI a stale entry is printed as a
warning, not a failure: what skips depends on the runner's tools and on the
base commit, so an entry can be right on one run and unused on the next. A
local `NOO_STRICT_SKIPS=1` run fails on it; use that when auditing the list.

To run the check locally: `NOO_STRICT_SKIPS=1 python3 -m pytest tests -q`
(it fires automatically in CI, where `GITHUB_ACTIONS=true`).
`NOO_STRICT_SKIPS=0` disables it even in CI. When you hit an unexplained
skip, the fix is either to make the test run in CI (build the binary it
needs, set the env var it's gated on) or to add an allow-list entry that
says, honestly, why skipping there is fine.

### Python

`pyproject.toml` pins the important settings:

```toml
[tool.pytest.ini_options]
asyncio_mode = "auto"      # async tests run without @pytest.mark.asyncio
pythonpath = ["src"]       # import THIS tree, not the venv's editable install
testpaths = ["tests"]
markers = ["integration: requires a running gateway (deselect with '-m not integration')"]
```

`pythonpath = ["src"]` matters in worktrees: the editable install resolves
to the main clone, so without it a green run from `.worktrees/<name>`
verifies code the branch does not contain.

```bash
pytest tests/ -v                          # unit suite
pytest tests/test_config.py -k default    # one file, one pattern
pytest tests/ --cov=noomesh --cov-report=term-missing
noo test run [-k pattern] [--integration] # the same, through the CLI
noo test coverage [--html]
```

Integration tests live in `tests/integration/` and skip themselves unless
`NOO_GATEWAY_URL` is set:

```bash
noo stack start
NOO_GATEWAY_URL=https://localhost:8080 pytest tests/integration/
```

They cover the external MCP door, the MCP filesystem server, the node-agent,
the persona flow and autonomy smoke checks.

Shared fixtures in `tests/conftest.py`: `test_config` (an `AppConfig` with
memory off and two tool loops), `temp_config_file`, `tool_result_ok` /
`tool_result_fail`, `mock_tool_registry`,
`sample_channel_message`, `sample_telegram_update`.

A large share of the suite is **parity and guard tests** rather than unit
tests of one function — they pin two declarations of the same fact to each
other so drift is a red build, not an outage. Examples worth copying:
`test_posture_key_parity.py` (Rust and Python posture allow-lists),
`test_job_type_declarations.py` (Rust job types vs the Go executor),
`test_worker_surfaces.py`, `test_standalone_asset_parity.py`,
`test_gateway_image_is_shell_less.py`, `test_launcher_trellion_parity.py`.
When you add a second copy of a fact, add the test that ties them together.

Two reusable guard helpers live under `tests/`, not beside any one suite:
`tests/_compose_projection.py` runs `docker compose config --no-interpolate`
(with every profile/overlay selected) so env-allowlist and secret guards
check the composed projection rather than parsing the raw YAML — use it
whenever a guard needs to know what a compose invocation actually resolves
to. `tests/source_scan.py` strips comments before scanning source, so a
guard that greps for a retired name does not false-negative on a comment
that mentions it. Use the composed-projection helper for compose-file
guards and the source-scan helper for source-tree string guards.

Writing one:

```python
# tests/test_my_feature.py
import pytest
from noomesh.tool_spec import ToolSpec


def test_spec_roundtrip():
    spec = ToolSpec(name="t", description="", parameters={"type": "object", "properties": {}},
                    handler=lambda args: "ok")
    assert spec.handler({}) == "ok"


async def test_async_path():            # picked up automatically (asyncio_mode = auto)
    ...
```

Integration tests take the `gateway_url` fixture and are marked
`pytestmark = pytest.mark.integration`.

### Rust and Go

Rust unit tests sit beside the code (`#[cfg(test)] mod tests`); the CLI
crate also has `noo-cli/tests/` (registry integrity, `resolve()` dispatch,
migrate, secrets store, onboard TUI). The CLI's usage table is pinned to
the command registry by test, so adding a command means adding a usage row.
Go tests are `_test.go` files next to each package; run them with `go test
./...` from `node-agent-go/`.

## Extension points

### Add an MCP tool

Tools are declared once, in Python, and served from both MCP doors by the
gateway. A tool is a `ToolDef` subclass in `src/noomesh/mcp/tool_defs/`
(one module per area: `cluster.py`, `rag.py`, `memory.py`, `heartbeat.py`,
`skills.py`, `devices.py`, …). The base class is in
`src/noomesh/mcp/tool_models.py`:

```python
from typing import ClassVar
from pydantic import Field
from ..tool_models import ToolDef, HttpMethod, AuthLevel, RiskLevel, register


@register
class NooRagQuery(ToolDef):
    name: ClassVar[str] = "noo_rag_query"
    description: ClassVar[str] = "Answer questions from the knowledge base."
    method: ClassVar[HttpMethod] = HttpMethod.POST
    path: ClassVar[str] = "/api/v1/rag/query"
    auth: ClassVar[AuthLevel] = AuthLevel.CLUSTER      # default
    risk_level: ClassVar[RiskLevel] = RiskLevel.LOW    # feeds the exec-approval gate
    question: str = Field(description="The question to answer")
    strategy: str = Field(default="hybrid", description="Search strategy")
```

The fields become the tool's JSON schema; the generic dispatcher turns a
call into the HTTP request against the gateway (`method` + `path`, body
from the fields). Then:

1. `python3 scripts/build-mcp-manifest.py` — regenerates the manifest the
   external door serves (CI runs `--check`).
2. `noo tools export` — rewrites `config/tools.json`, which the gateway's
   tool registry reads.
3. Restart the gateway. `noo tools list` and `noo mcp tools` show the new
   tool; the coordinator can call it on its next turn.

A tool that needs Python at call time (rather than an HTTP round-trip) is
answered on `worker.tool.generic` by `src/noomesh/workers/tools.py`; keep
heavy imports inside the handler body so the worker package stays cheap
to import.

### Add a skill

Skills are sandboxed programs with a manifest: `manifest.yml` declares
inputs, outputs, the container (image, command, timeout, memory limit,
network) and permissions; `run.py` reads `SKILL_INPUT` and prints JSON.
Builtins live in `skills/builtins/`, a worked example in
`skills/examples/hello_greeter/`.

```bash
noo skills scaffold my_skill          # writes manifest.yml + run.py under $NOO_SKILLS_DIR (default ~/.noo/skills)
noo skills list                       # local registry scan, no gateway
noo skills run my_skill '{"name": "x"}'          # through the gateway
```

`noo skills run` posts to the gateway (`POST /api/skills/{name}/run`),
which builds the container spec from the manifest and sends it to a node
agent's `POST /api/skills/run` with the controller's certificate; the agent
runs it in its own container with the manifest's limits.
`POST /api/skills/rescan` makes the gateway re-read the registry dirs.
The gateway runs skills from ITS registry: `skills/` as mounted into the
gateway container, and its own `NOO_SKILLS_DIR`. A skill scaffolded only in
your user dir is listed by `noo skills list` but is not runnable until it is
in one of those. The CLI never calls a node agent itself.

### Add a worker handler

Write the function in the right domain module under `src/noomesh/workers/`
and decorate it:

```python
from .registry import worker_handler

@worker_handler("worker.rag.my_verb")
async def _my_verb(request: dict) -> dict:
    params = request.get("params") or {}
    ...
    return {"ok": True}
```

Importing the package registers it; the dispatch shell subscribes one NATS
subscription per subject. A new *module* must be added to the surface lists
in `src/noomesh/workers/__init__.py` (`_CORE_MODULES`, `_ML_MODULES`,
`_ML_INTEL_MODULES`) so `NOO_WORKER_SURFACES` places it in the right
container. Call it from Rust with `worker_client::request(subject, params)`.

### Add an inference backend

Backend knowledge is split across the three languages on purpose — the
container spec is Go, the port and health path are Rust, the hardware-fit
decision is Python.

### Add a CLI command

Register the words in `NATIVE` in `noo-cli/src/main.rs`, add the usage row
in `noo-cli/src/usage.rs` (a test pins the two tables to each other), put
the handler in the group's `src/commands/<group>.rs`, and regenerate the
docs tables with `python3 scripts/gen-cli-docs.py`. Contract rules (exit
codes, `--json`, destructive confirmation) are in
[cli/README.md](../cli/README.md).

### Add a gateway route

Routes are axum handlers, one file per domain in `gateway-rust/src/routes/`,
merged in `routes/mod.rs`. Every route is behind `require_any_auth` unless
you add it to the public allow-list in `auth.rs` — do not. Use the shared
HTTP clients from `tls.rs` for anything outbound
and `sqlx::query!` (then `scripts/sqlx-prepare.sh`) for SQL.

### Pin a vendor CLI

The controller stages each foreign harness kind's vendor CLI (Claude Code,
Copilot CLI, Codex CLI) to the nodes; a node never downloads it. What it
stages is pinned in `config/harness-kinds.json`: each kind's `distribution`
carries a version and a
sha256 for every platform the fleet has (`linux-x86_64`, `linux-aarch64`,
`macos-aarch64`), or one `any` digest for a platform-independent artefact.
`scripts/vendor-pin.py` writes those blocks; nobody edits a digest by hand.

**When to bump:** a vendor ships a fix or a flag the harness driver needs, a
security advisory names the pinned version.
Pick the vendor's stable channel (Claude Code's `stable`, not `latest`), and
never a prerelease.

**How:**

```bash
python3 -I scripts/vendor-pin.py copilot 1.0.98   # a kind
python3 -I scripts/vendor-pin.py --check          # re-verify every pin, writes nothing
```

It fills the block's `source` template for each platform, downloads every
artefact (hash only: it never unpacks or runs one), cross-checks the digest
against what the vendor publishes (the GitHub
release `SHA256SUMS` file, Claude Code's release `manifest.json`), and rewrites both `config/harness-kinds.json`
and its byte-equal copy `node-agent-go/internal/reconcile/harness_kinds.json`.
It refuses an unknown kind, a missing artefact, and a cross-check mismatch,
printing both digests. `--dl-dir DIR` keeps the downloads. If a vendor
renames its assets, edit the block's `source`/`names`/`entry`/`unpack` in
the file and re-run; the script's seed recipes only apply to a block that
does not exist yet. `--check` needs the internet and is not part of CI;
`tests/test_vendor_pins.py` holds only the shape.

**What to review in the diff:** only `version` and the `sha256` values
should move on a bump; a changed `source`, `entry` or `format` is a layout
change and needs the applier checked against it. Confirm the run printed a
cross-check source for every platform (a `WARNING … trust-on-first-use`
line means the vendor published nothing to check against). Both JSON files
change identically, or the parity tests fail.

## Conventions

- **Python:** `from __future__ import annotations`; Pydantic `BaseModel` for
  config and API bodies, `@dataclass` for internal structures; `structlog`
  in gateway/worker code; optional imports guarded with `try/except
  ImportError` and a module-level `*_AVAILABLE` flag; `init_*()` /
  `get_*()` singletons.
- **Rust:** one file per domain; no ad-hoc `reqwest::Client`; env reads go
  through `config::env_or_yaml` when a YAML key exists (`.env` → YAML →
  default); posture gates are read once at startup.
- **Go:** config is env-only (`internal/config`), every network client
  fails loudly on unreadable TLS material, ops tables are checked against
  their producers by parity tests.
- **Declare a fact once.** A value that the system already knows (the
  embedding model of a placement, the vector dimension of a column, a
  channel identity) must not be restated in config — the restatement
  becomes a stale override that silently wins.
- **Git:** work in a worktree off `origin/dev`, PR into `dev`, linear
  history. See [CONTRIBUTING.md](../../CONTRIBUTING.md).
- **Where a setting goes** (secrets, config, posture, bootstrap): see
  [reference/config.md](../reference/config.md#where-does-a-value-go).
- **Public docs:** current behaviour a contributor can act on goes in
  `docs/`; `internal/` never ships and must not be cited from `docs/`.
