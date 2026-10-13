# SPDX-License-Identifier: AGPL-3.0-only
# Copyright 2026 PersonifAI LLC

"""The launchers refuse to start an install whose secrets sit in plaintext
`.env`.

#594 made `noo onboard` sops-only and made `cluster verify --controller`,
`security scan` and `upgrade --stack` judge a plaintext install; the launcher
was the last lane that still started one. The criterion lives in the `noo`
binary (`noo config launch-check secrets-at-rest`,
noo-cli/src/commands/plaintext_env.rs — unit-tested there in the noo-cli CI
job, including host8's exact `.env` key set); scripts/lib-secrets.sh
`check_secrets_at_rest` only runs it and maps its exit code.

Three layers here:

  1. GUARD (no tools): every launcher calls `check_secrets_at_rest || exit 1`
     after `load_secrets` and before its first `docker compose` command.
  2. GLUE (bash only; fake `noo`): exit 3 refuses and noo's lines reach
     stderr; 0 passes; an older noo (exit 2) or no noo at all WARNS and lets
     the start continue; the install root handed over is the launcher's cwd.
  3. END TO END (needs the debug `noo`): a planted secret in `.env` is
     refused naming the key (never the value) and the remedy; a non-sops
     backend is refused; host8's key set passes.
"""

from __future__ import annotations

import re
import stat
import subprocess
import textwrap
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parent.parent
SCRIPTS = REPO_ROOT / "scripts"
LIB_CONFIG = SCRIPTS / "lib-config.sh"
LIB_SECRETS = SCRIPTS / "lib-secrets.sh"
NOO_DEBUG = REPO_ROOT / "noo-cli" / "target" / "debug" / "noo"

# Every script that starts or recreates the stack (the same three that
# tests/test_launcher_bind_sources.py holds to the bind-source check).
LAUNCHERS = ("noomesh-start.sh", "noomesh-restart.sh", "noomesh-rebuild.sh")

REMEDY_ONBOARD = "noo onboard --reconfigure --only secrets --secrets-backend sops"
REMEDY_TIDY = "noo security secrets tidy"

CALL_LINE = re.compile(r"^\s*check_secrets_at_rest\s*\|\|\s*exit 1\s*$")
LOAD_LINE = re.compile(r"^\s*load_secrets\b")
COMPOSE_LINE = re.compile(r"\bdocker compose\b")


def _statements(path: Path) -> list[str]:
    out = []
    for line in path.read_text().splitlines():
        s = line.strip()
        if not s or s.startswith("#"):
            continue
        out.append(line)
    return out


# ── 1. guard ─────────────────────────────────────────────────────────────


@pytest.mark.parametrize("name", LAUNCHERS)
def test_every_launcher_refuses_a_plaintext_install_before_compose(name):
    stmts = _statements(SCRIPTS / name)
    calls = [i for i, s in enumerate(stmts) if CALL_LINE.match(s)]
    assert calls, (
        f"{name} never calls `check_secrets_at_rest || exit 1` — it would start an "
        "install whose secrets sit in plaintext .env"
    )
    call = calls[0]
    loads = [i for i, s in enumerate(stmts) if LOAD_LINE.match(s)]
    assert loads and loads[0] < call, f"{name}: the check must follow load_secrets"
    composes = [i for i, s in enumerate(stmts) if COMPOSE_LINE.search(s)]
    assert composes, f"{name}: found no `docker compose` line — the pattern broke"
    assert call < composes[0], (
        f"{name}: `{stmts[composes[0]].strip()}` runs before the secrets-at-rest check"
    )


def test_the_lib_does_not_restate_the_criterion():
    """The shell never judges a key itself: it asks noo."""
    body = LIB_SECRETS.read_text()
    fn = body[body.index("check_secrets_at_rest() {"):]
    fn = fn[: fn.index("\n}\n")]
    assert "config launch-check secrets-at-rest" in fn
    for word in ("PASSWORD", "SECRET=", "TOKEN", "grep"):
        assert word not in fn, f"check_secrets_at_rest restates the classifier ({word})"


# ── 2. glue ──────────────────────────────────────────────────────────────


def _exe(path: Path, body: str) -> None:
    path.write_text(textwrap.dedent(body))
    path.chmod(path.stat().st_mode | stat.S_IEXEC | stat.S_IXGRP | stat.S_IXOTH)


@pytest.fixture
def glue(tmp_path):
    work = tmp_path / "work"
    work.mkdir()
    record = tmp_path / "record"
    _exe(tmp_path / "noo", """\
        #!/usr/bin/env bash
        printf '%s\\n' "$*" > "$FAKE_NOO_RECORD.argv"
        pwd > "$FAKE_NOO_RECORD.cwd"
        [ -n "${FAKE_NOO_STDERR:-}" ] && echo "$FAKE_NOO_STDERR" >&2
        exit "${FAKE_NOO_RC:-0}"
        """)
    env = {
        "PATH": "/usr/bin:/bin",
        "HOME": str(tmp_path),
        "TERM": "dumb",
        "FAKE_NOO_RECORD": str(record),
    }
    return {"env": env, "work": work, "record": record, "noo": tmp_path / "noo"}


def _run_check(g, noo: Path | None, extra: dict | None = None):
    env = dict(g["env"])
    if noo is not None:
        env["NOO_CLI_BIN"] = str(noo)
    env.update(extra or {})
    script = f"""
set -e
source {LIB_CONFIG}
source {LIB_SECRETS}
rc=0; check_secrets_at_rest || rc=$?
echo "RC=$rc"
"""
    return subprocess.run(["bash", "-c", script], cwd=g["work"], env=env,
                          capture_output=True, text=True, timeout=30)


def test_noo_refusal_refuses_and_its_lines_reach_stderr(glue):
    out = _run_check(glue, glue["noo"], {"FAKE_NOO_RC": "3", "FAKE_NOO_STDERR": "REFUSED: not starting"})
    assert "RC=1" in out.stdout, out.stdout + out.stderr
    assert "REFUSED: not starting" in out.stderr


def test_clean_check_passes_and_names_the_launcher_cwd(glue):
    out = _run_check(glue, glue["noo"])
    assert "RC=0" in out.stdout, out.stdout + out.stderr
    argv = Path(str(glue["record"]) + ".argv").read_text().split()
    assert argv == ["config", "launch-check", "secrets-at-rest", "."], argv
    assert Path(str(glue["record"]) + ".cwd").read_text().strip() == str(glue["work"])
    assert "WARNING" not in out.stderr


def test_older_noo_warns_and_does_not_block_the_start(glue):
    out = _run_check(glue, glue["noo"], {"FAKE_NOO_RC": "2"})
    assert "RC=0" in out.stdout, out.stdout + out.stderr
    assert "secrets at rest NOT checked" in out.stderr and "exit 2" in out.stderr, out.stderr


def test_no_noo_warns_and_does_not_block_the_start(glue):
    out = _run_check(glue, None)
    assert "RC=0" in out.stdout, out.stdout + out.stderr
    assert "no noo binary found" in out.stderr


# ── 3. end to end ────────────────────────────────────────────────────────

needs_real = pytest.mark.skipif(
    not NOO_DEBUG.is_file(), reason="needs the debug noo (cargo build in noo-cli)",
)

# host8's `.env` as of 2026-09-30: every key that holds a value.
HOST8_ENV_KEYS = (
    "CLUSTER_MODE EMBEDDING_DIM GPU_MODEL LLAMACPP_MODEL NATS_GATEWAY_USER NATS_URL NATS_USER "
    "NATS_WORKER_USER N_CTX N_GPU_LAYERS NODE_ID NODE_IP NODE_TIER NOO_ADMIN_USER NOO_BASE_REGISTRY "
    "NOO_BIND_MODE NOO_DATA_ROOT NOO_DEFAULT_PROFILE NOO_IMAGE_PREFIX NOO_IMAGE_TAG NOO_INSTALL_MODE "
    "NOO_LOKI_TLS NOO_MODEL_ORIGINS NOO_MTLS_GATEWAY NOO_MTLS_NODES NOO_NATS_CONFIG NOO_NATS_TLS "
    "NOO_PG_DATA NOO_PG_SSLMODE NOO_PG_TLS NOO_PKI_DIR NOO_REDIS_TLS NOO_SECRETS_BACKEND NOO_TLS_CA "
    "NOO_TLS_CERT NOO_VLLM_TLS N_THREADS OLLAMA_MODEL OLLAMA_URL PAGEINDEX_EMBEDDING_BACKEND "
    "PAGEINDEX_EMBEDDING_MODEL PAGEINDEX_EMBEDDING_URL PAGEINDEX_LLM_URL REDIS_URL "
    "TELEGRAM_ALLOWED_USERS VRAM_GB"
).split()


def _host8_env() -> str:
    return "".join(
        f"{k}={'sops' if k == 'NOO_SECRETS_BACKEND' else 'value-of-' + k}\n" for k in HOST8_ENV_KEYS
    )


@pytest.fixture
def install(glue):
    work = glue["work"]
    (work / "secrets").mkdir()
    (work / "secrets" / "env.sops").write_text("ciphertext")
    (work / ".env").write_text(_host8_env())
    return glue


def _real(g):
    # The process env overrides .env (as the launcher's own precedence does):
    # never let the runner's NOO_SECRETS_BACKEND leak in.
    return _run_check(g, NOO_DEBUG, {"NOO_SECRETS_BACKEND": ""})


@needs_real
def test_e2e_host8_key_set_passes(install):
    assert len(HOST8_ENV_KEYS) == 46
    out = _real(install)
    assert "RC=0" in out.stdout, out.stdout + out.stderr
    assert "REFUSED" not in out.stderr and "WARNING" not in out.stderr, out.stderr


@needs_real
def test_e2e_planted_secret_is_refused_naming_the_key_not_the_value(install):
    env = install["work"] / ".env"
    env.write_text(env.read_text() + "POSTGRES_PASSWORD=SENTINEL-planted\n")
    out = _real(install)
    assert "RC=1" in out.stdout, out.stdout + out.stderr
    assert "POSTGRES_PASSWORD" in out.stderr, out.stderr
    assert "SENTINEL" not in out.stderr + out.stdout
    assert REMEDY_ONBOARD in out.stderr and REMEDY_TIDY in out.stderr, out.stderr


@needs_real
@pytest.mark.parametrize("backend", ["env", ""])
def test_e2e_non_sops_backend_is_refused(install, backend):
    env = install["work"] / ".env"
    env.write_text(env.read_text().replace("NOO_SECRETS_BACKEND=sops", f"NOO_SECRETS_BACKEND={backend}"))
    out = _real(install)
    assert "RC=1" in out.stdout, out.stdout + out.stderr
    assert "NOO_SECRETS_BACKEND" in out.stderr and REMEDY_ONBOARD in out.stderr, out.stderr

