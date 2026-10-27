# Contributing to noomesh

Thanks for helping. This page is the short version: set up, the branch
and PR flow, tests, and the conventions reviewers hold you to. The longer
guides it points at are the source of truth.

## Set up

Three languages, three toolchains — pick the ones your change touches, or
let `scripts/setup-dev.sh` install and check all of them (Linux, WSL2 or
macOS; `--dry-run` prints the plan first).

**Stack (any change you want to see running):** install the `noo` binary
and onboard a dev-mode install as in
[docs/getting-started/install.md](docs/getting-started/install.md); `noo
stack start` then builds the images from your tree and `noo stack rebuild`
picks up changes.

**Python worker (`src/noomesh/`):**

```bash
python3 -m venv venv && source venv/bin/activate
pip install -e ".[dev,web,cache]"
pre-commit install         # run the checks on every commit; or by hand: `pre-commit run --all-files`
python3 -m pytest -q
```

Contributors keep the unpinned `pip install -e ".[dev,web,cache]"` above. The
shipped image (`docker/Dockerfile.deps-core`) does not: it installs from the
hash-locked `docker/core-lock/requirements.txt` with `--require-hashes`. After you
change a dependency in `pyproject.toml`, regenerate that file with the command
in its header and commit both together; `tests/test_python_lock_guard.py`
fails when the lock and the Dockerfile's extras drift apart. The project is
built `--no-build-isolation`, so the build backend from `[build-system]` is
locked too: it is named in `docker/core-lock/build-backends.in`, which is part
of the regenerate command (change a backend range in both places).

The ML tier (`docker/Dockerfile.deps-base`) is locked the same way, in
`docker/ml-lock/requirements.txt`; regenerate it with
`scripts/regen-ml-lock.sh` (it resolves trellion's dependencies too, so run it
against the trellion checkout the release builds).

There is no Python CLI: `noo` is the Rust binary (`noo-cli/`) and the only
command-line front door. The editable install ships the `noo-mcp-*` servers,
not a `noo-py`.

**Rust (`gateway-rust/`, `noo-cli/`):** there is no host toolchain
requirement — `scripts/cargo-docker.sh` runs cargo in a container with the
registry cached, e.g. `scripts/cargo-docker.sh check --tests` (set
`CARGO_DOCKER_CRATE` to the crate directory).

**Go (`node-agent-go/`):** the Go version in `node-agent-go/go.mod`;
`cd node-agent-go && go build ./... && go test ./...`.

Project layout, extension points and conventions:
[docs/development/developer-guide.md](docs/development/developer-guide.md).

## Branch and PR flow

`dev` is the integration branch and only changes by pull request with
linear history. Fork the repository, then work on a branch off `dev`:

```bash
git clone <your-fork> && cd noomesh
git remote add upstream https://github.com/noomesh/noomesh.git
git fetch upstream
git switch -c <type>/<slug> upstream/dev
# … commit …
git push -u origin <type>/<slug>
gh pr create --repo noomesh/noomesh --base dev
```

Before opening the PR, `git fetch upstream` and check
`git log HEAD..upstream/dev`: if `dev` moved onto files you touched,
rebase and let CI re-run.

Commit messages use a `type: summary` first line (`feat:`, `fix:`,
`docs:`, `refactor:`, `test:`). Keep PRs to one change; include tests for
new behaviour; update the docs when you change a command, a config key or
an endpoint. Never commit `.env`, anything under `secrets/`, or a key.

## Tests

```bash
pytest tests/ -v --ignore=tests/integration                 # Python unit tests, no services needed
NOO_GATEWAY_URL=http://localhost:8080 pytest tests/integration/ -v   # against a running gateway
CARGO_DOCKER_CRATE="$PWD/gateway-rust" scripts/cargo-docker.sh test --locked
CARGO_DOCKER_CRATE="$PWD/noo-cli" scripts/cargo-docker.sh test --locked
python3 scripts/docs-check.py                               # docs index, links, forbidden strings
python3 scripts/gen-cli-docs.py --check                     # generated CLI reference is fresh
```

CI runs ruff, mypy, the Python suite on **one** interpreter — the one in
`.python-version` at the repo root, which is also the one the images
install — plus the Rust checks and tests for both crates (clippy on
`noo-cli`), the Go agent build, the docs checks, and a migration
replay. Writing tests:
[docs/development/developer-guide.md](docs/development/developer-guide.md) — `tests/`
mirrors the source layout, `asyncio_mode` is `auto`, integration tests are
gated on `NOO_GATEWAY_URL`, and a guard for a fixed bug is watched to fail
before it is trusted (§ Proving a guard works — including why the plant is
verified by reading the file back rather than inferred from the run).

## Code standards

```bash
ruff check src/ && ruff format --check src/
mypy src/noomesh/ --ignore-missing-imports
```

### The Python version

There is one, and it is the one that ships. `.python-version` at the repo
root is the single source of truth: `uv` honours it, `actions/setup-python`
reads it via `python-version-file`, and the two Dockerfile `PYTHON_VERSION`
ARGs, `requires-python`, the Python classifier, `ruff`'s `target-version`
and `mypy`'s `python_version` are all pinned to the same value.
`tests/test_python_version_single_source.py` fails if any of them disagree,
so bumping the interpreter means editing `.python-version` **and** the
literals that test names, in one commit.

- **One home per value.** Secrets in `secrets/env.sops`, config in
  `noomesh.yaml`, only bootstrap flags in `.env`; never declare a fact the
  system already knows. [docs/reference/config.md](docs/reference/config.md)
  has the rules.
- **The CLI usage table is pinned.** A new `noo` command needs a row in
  `noo-cli/src/usage.rs` and its `NATIVE` entry in `noo-cli/src/main.rs`;
  a test fails otherwise, and `scripts/gen-cli-docs.py` regenerates the
  docs from that table.
- **Python:** optional imports behind `try/except ImportError` with an
  `X_AVAILABLE` flag; `structlog`, never bare `print()` in library code;
  type hints on public signatures; Pydantic models for config.
- **Docs:** current behaviour a contributor can act on goes in `docs/`;
  a doc that names a file that no longer exists gets fixed or removed.
  `python3 scripts/docs-check.py` enforces the index and the links.

## Where to go

- **Questions and ideas:** [GitHub Discussions](https://github.com/noomesh/noomesh/discussions).
  Start there for "how do I", design ideas and anything you are not sure
  is a bug.
- **Bugs:** open an [issue](https://github.com/noomesh/noomesh/issues/new/choose)
  with the [bug report](.github/ISSUE_TEMPLATE/bug_report.md) template;
  feature requests have their own
  [template](.github/ISSUE_TEMPLATE/feature_request.md).
- **Security disclosures:** never a public issue or discussion. Follow
  [SECURITY.md](SECURITY.md) and email **contact@noomesh.ai**.
- **Pull requests:** target `dev`; they are rebase-merged (linear history),
  and CI must be green before review. On your first pull request the CLA
  bot comments and asks you to sign (see below).

## Licensing and the CLA

Noomesh is licensed under the **AGPL-3.0**. Contributions are accepted under
the **Contributor License Agreement** in [`CLA.md`](CLA.md): on your first
pull request a bot will ask you to sign it by replying with one sentence. It
takes a minute and you do it once.

Why a CLA: the code is AGPL for everyone, and PersonifAI also offers a
commercial licence for it. The CLA is what lets PersonifAI do that over code
that includes your contribution.
Your own rights to your contribution are not affected — you can do anything
you like with it elsewhere.

Source files carry an SPDX header (`SPDX-License-Identifier:
AGPL-3.0-only`). New files need one too.
