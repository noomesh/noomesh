# SPDX-License-Identifier: AGPL-3.0-only
# Copyright 2026 PersonifAI LLC

"""Rotating a backup passphrase must not empty the secret store.

`scripts/noo-backup-rotate-passphrase.sh` treated `.env` as the plaintext
source of truth and re-encrypted `secrets/env.sops` FROM it:

    sops -e --filename-override secrets/env.sops --input-type dotenv \
         --output-type dotenv .env > secrets/env.sops

That is a full REPLACE, not a merge. On a sops-first install — the default
since 2026-08-02 — `.env` holds a couple of bootstrap flags and the store
holds ~30 secrets, so one run would have reduced the store to those flags and
taken the whole cluster down, while `env_set` also wrote both passphrases into
`.env` in plaintext. Caught in dry-run on the live controller on 2026-09-12
before it ever ran; tracker R42. CLAUDE.md's "Never re-encrypt `env.sops` from
`.env`" rule was written about this file.

These tests build a REAL sops+age store (both binaries are on this host; the
tests skip if they are not), run the rotation, and assert the two things that
would have been destroyed: the key set survives, and no passphrase lands in
`.env`.

The rotation now lives in `noo security secrets rotate`; this exercises the
store-write contract that the verb and the wrapper share, in the shape the
operator's own manual recipe used.
"""

from __future__ import annotations

import os
import shutil
import subprocess
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parents[1]

# The thirty-odd real store plus the two passphrases: the shape that made the
# defect catastrophic rather than merely wrong.
STORE_KEYS = [f"NOO_SECRET_{i:02d}" for i in range(28)] + [
    "POSTGRES_PASSWORD",
    "NOO_JWT_SECRET",
]
# What `.env` actually holds on a sops-first install: bootstrap flags only.
ENV_ONLY = {"NOO_SECRETS_BACKEND": "sops", "NOO_IMAGE_TAG": "v0.2.40"}


def _tools() -> None:
    for exe in ("sops", "age-keygen"):
        if not shutil.which(exe):
            pytest.skip(f"{exe} not installed on this host")


@pytest.fixture
def store(tmp_path: Path):
    """A sops-backed install: age key, .sops.yaml, secrets/env.sops, .env."""
    _tools()
    root = tmp_path / "install"
    (root / "secrets").mkdir(parents=True)
    os.chmod(root / "secrets", 0o700)

    key = tmp_path / "age-key.txt"
    gen = subprocess.run(
        ["age-keygen", "-o", str(key)], capture_output=True, text=True, timeout=60
    )
    assert gen.returncode == 0, gen.stderr
    pub = next(
        line.split(": ", 1)[1].strip()
        for line in (gen.stderr + key.read_text()).splitlines()
        if "public key:" in line
    )
    (root / ".sops.yaml").write_text(
        "creation_rules:\n  - path_regex: secrets/.*\\.sops$\n    age: %s\n" % pub
    )

    plain = "\n".join(f"{k}=value-of-{k}" for k in STORE_KEYS) + "\n"
    enc = root / "secrets/env.sops"
    res = subprocess.run(
        [
            "sops", "-e", "--filename-override", str(enc),
            "--input-type", "dotenv", "--output-type", "dotenv", "/dev/stdin",
        ],
        input=plain, capture_output=True, text=True, cwd=root,
        env={**os.environ, "SOPS_AGE_KEY_FILE": str(key)}, timeout=60,
    )
    assert res.returncode == 0, res.stderr
    enc.write_text(res.stdout)

    (root / ".env").write_text("".join(f"{k}={v}\n" for k, v in ENV_ONLY.items()))
    return {"root": root, "key": key, "enc": enc}


def _decrypt_keys(store) -> set[str]:
    res = subprocess.run(
        ["sops", "-d", "--input-type", "dotenv", "--output-type", "dotenv", str(store["enc"])],
        capture_output=True, text=True, cwd=store["root"],
        env={**os.environ, "SOPS_AGE_KEY_FILE": str(store["key"])}, timeout=60,
    )
    assert res.returncode == 0, res.stderr
    keys = {ln.split("=", 1)[0] for ln in res.stdout.splitlines() if "=" in ln and not ln.startswith("#")}
    # CLAUDE.md: a broken decrypt returns ZERO keys, which reads exactly like
    # "the key is missing". Never conclude anything from an empty set.
    assert keys, "decrypt produced no keys — the assertion below would be vacuous"
    return keys


def test_the_fixture_store_really_holds_thirty_keys(store) -> None:
    """Guard the guard: if the fixture were empty, every test here passes."""
    assert _decrypt_keys(store) == set(STORE_KEYS)
    assert len(STORE_KEYS) == 30


def _run_rotation(store, *keys: str) -> subprocess.CompletedProcess:
    """The store write, exactly as the operator's working manual recipe did it.

    Decrypt to a 0600 temp inside secrets/, edit ONLY the named keys,
    re-encrypt in place under a rule-matching name, diff the key sets, install.
    This is the contract `noo security secrets rotate` implements in Rust
    (`prepare_store`); running it as shell here keeps the test honest about the
    sops invocations without needing a built binary.
    """
    script = r"""
set -euo pipefail
cd "$ROOT"
TMP="$(mktemp -d secrets/.rotate.XXXXXX)"; chmod 700 "$TMP"
trap 'shred -u "$TMP"/* 2>/dev/null || true; rm -rf "$TMP"' EXIT
( umask 077; sops -d --input-type dotenv --output-type dotenv secrets/env.sops > "$TMP/plain" )
before="$(grep -oE '^[A-Z_0-9]+=' "$TMP/plain" | sort)"
cp "$TMP/plain" "$TMP/next"
for k in $KEYS; do
    grep -v "^$k=" "$TMP/next" > "$TMP/n2" || true
    printf '%s=%s\n' "$k" "rotated-$k" >> "$TMP/n2"
    mv "$TMP/n2" "$TMP/next"
done
install -m 600 "$TMP/next" secrets/env.new.sops
sops -e -i --input-type dotenv --output-type dotenv secrets/env.new.sops
after="$(sops -d --input-type dotenv --output-type dotenv secrets/env.new.sops | grep -oE '^[A-Z_0-9]+=' | sort)"
# The refusal. A re-encrypt that DROPS keys is the documented failure mode of
# this file, and a dropped credential is invisible until some later restart.
lost="$(comm -23 <(printf '%s\n' "$before") <(printf '%s\n' "$after"))"
if [ -n "$lost" ]; then
    echo "REFUSING: the re-encrypted store would LOSE keys:" >&2
    printf '%s\n' "$lost" >&2
    rm -f secrets/env.new.sops
    exit 1
fi
mv secrets/env.new.sops secrets/env.sops
chmod 600 secrets/env.sops
"""
    return subprocess.run(
        ["bash", "-c", script],
        capture_output=True, text=True, timeout=120,
        env={
            **os.environ,
            "ROOT": str(store["root"]),
            "KEYS": " ".join(keys),
            "SOPS_AGE_KEY_FILE": str(store["key"]),
        },
    )


def test_rotation_keeps_every_key_and_adds_the_two(store) -> None:
    """30 keys in, 32 out, identical sets bar the two added.

    This is the operator's own verification, mechanised: "key-set diff 30→32
    identical sets".
    """
    before = _decrypt_keys(store)
    res = _run_rotation(store, "NOO_BACKUP_PASSPHRASE", "NOO_AGE_BACKUP_PASSPHRASE")
    assert res.returncode == 0, res.stderr
    after = _decrypt_keys(store)
    assert len(before) == 30 and len(after) == 32, (len(before), len(after))
    assert before < after
    assert after - before == {"NOO_BACKUP_PASSPHRASE", "NOO_AGE_BACKUP_PASSPHRASE"}


def test_no_passphrase_is_written_to_dot_env(store) -> None:
    """`.env` is configuration and bootstrap flags. Never a credential.

    The old script's `env_set` wrote both values there in plaintext, and
    nothing removed them.
    """
    _run_rotation(store, "NOO_BACKUP_PASSPHRASE", "NOO_AGE_BACKUP_PASSPHRASE")
    env_text = (store["root"] / ".env").read_text()
    assert "PASSPHRASE" not in env_text, env_text
    assert {ln.split("=", 1)[0] for ln in env_text.splitlines() if "=" in ln} == set(ENV_ONLY)


def test_the_key_set_guard_actually_refuses(store) -> None:
    """Watch the guard fail.

    A guard nobody has seen refuse is a guard that might not be wired up. This
    re-encrypts from a source that is MISSING keys — which is precisely what
    encrypting `.env` did — and asserts the refusal fires and the store is
    left alone.
    """
    before = _decrypt_keys(store)
    script = r"""
set -euo pipefail
cd "$ROOT"
before="$(sops -d --input-type dotenv --output-type dotenv secrets/env.sops | grep -oE '^[A-Z_0-9]+=' | sort)"
# The defect, reproduced exactly: encrypt .env over the store.
install -m 600 .env secrets/env.new.sops
sops -e -i --input-type dotenv --output-type dotenv secrets/env.new.sops
after="$(sops -d --input-type dotenv --output-type dotenv secrets/env.new.sops | grep -oE '^[A-Z_0-9]+=' | sort)"
lost="$(comm -23 <(printf '%s\n' "$before") <(printf '%s\n' "$after"))"
if [ -n "$lost" ]; then
    echo "REFUSING: would LOSE $(printf '%s\n' "$lost" | grep -c .) keys" >&2
    rm -f secrets/env.new.sops
    exit 1
fi
mv secrets/env.new.sops secrets/env.sops
"""
    res = subprocess.run(
        ["bash", "-c", script], capture_output=True, text=True, timeout=120,
        env={**os.environ, "ROOT": str(store["root"]), "SOPS_AGE_KEY_FILE": str(store["key"])},
    )
    assert res.returncode != 0, "the guard did not refuse an obviously lossy re-encrypt"
    assert "REFUSING" in res.stderr and "LOSE 30 keys" in res.stderr, res.stderr
    assert _decrypt_keys(store) == before, "the store changed despite the refusal"


def test_the_script_no_longer_re_encrypts_the_store_from_dot_env() -> None:
    """The shell must not carry the pattern any more, in any sibling.

    `sops -e … .env` (or `$ENV_FILE`) writing to the store is the shape; it is
    allowed in exactly one place, `noo-secrets-sops-init.sh`, which CREATES the
    store from `.env` the first time and refuses when one already exists.
    """
    allowed = {"scripts/noo-secrets-sops-init.sh"}
    offenders = []
    for path in sorted((REPO / "scripts").glob("*.sh")):
        rel = f"scripts/{path.name}"
        if rel in allowed:
            continue
        for n, line in enumerate(path.read_text().splitlines(), 1):
            s = line.strip()
            if s.startswith("#"):
                continue  # the history is allowed to be written down
            if "sops -e" in s and ("$ENV_FILE" in s or " .env" in s or '"$ENV_FILE"' in s):
                offenders.append(f"{rel}:{n}: {s}")
    assert not offenders, (
        "a script re-encrypts the store from .env — a full replace that drops "
        "every key .env lacks (tracker R42):\n" + "\n".join(offenders)
    )


def test_the_wrapper_delegates_to_the_verb() -> None:
    """One implementation. The script must not have grown a second one back."""
    body = (REPO / "scripts/noo-backup-rotate-passphrase.sh").read_text()
    code = [ln for ln in body.splitlines() if not ln.lstrip().startswith("#")]
    joined = "\n".join(code)
    assert "exec noo security secrets rotate" in joined
    for forbidden in ("sops -e", "openssl enc", "env_set"):
        assert forbidden not in joined, f"the wrapper implements {forbidden!r} again"
