# SPDX-License-Identifier: AGPL-3.0-only
# Copyright 2026 PersonifAI LLC

"""The small §3f R30 defaults, each of which was wrong in the same direction:
the safe choice was documented and the unsafe one was shipped.

Every assertion here is against the artefact an operator or a build actually
consumes, not against prose describing it.
"""

from __future__ import annotations

import re
import subprocess
from pathlib import Path

REPO = Path(__file__).resolve().parents[1]


# ── the spool the stack actually writes ────────────────────────────────────

def test_the_live_host_spool_is_gitignored():
    """`.gitignore` covered the pai-era name; compose writes the noo-era one.

    An unignored runtime spool sits in `git status` as untracked, one
    `git add -A` away from committing whatever a command payload held.
    """
    compose = (REPO / "docker-compose.cluster.yml").read_text()
    written = set(re.findall(r"\./(\.[a-z-]*host-spool)[:/]", compose))
    assert written, "no host-spool bind mount found in docker-compose.cluster.yml"
    ignored = (REPO / ".gitignore").read_text()
    for path in sorted(written):
        assert f"{path}/*" in ignored, (
            f"docker-compose.cluster.yml bind-mounts ./{path} but .gitignore does "
            f"not cover it"
        )


def test_git_does_not_see_the_spool_as_untracked():
    """The end state, checked through git rather than through the file."""
    out = subprocess.run(
        ["git", "status", "--porcelain", "--untracked-files=all"],
        capture_output=True, text=True, cwd=REPO, check=True,
    ).stdout
    offenders = [ln for ln in out.splitlines() if "host-spool" in ln]
    assert not offenders, f"host spool files are visible to git: {offenders}"


# ── the secrets backend ────────────────────────────────────────────────────

def test_env_example_defaults_to_the_encrypted_backend():
    """`.env.example` said `env` while docs/operating/secrets.md said sops.

    A new install took the plaintext path unless the operator noticed, which
    is the wrong direction for a default to fail in.
    """
    text = (REPO / ".env.example").read_text()
    m = re.search(r"^NOO_SECRETS_BACKEND=(\S*)$", text, re.M)
    assert m, ".env.example no longer sets NOO_SECRETS_BACKEND"
    assert m.group(1) == "sops", (
        f".env.example ships NOO_SECRETS_BACKEND={m.group(1)} — plaintext secrets "
        "at rest by default"
    )
    assert "DOWNGRADE" in text, (
        "the `env` backend is no longer documented as an explicit downgrade "
        "beside the setting"
    )


def test_the_env_backend_is_still_supported_not_removed():
    """Naming it a downgrade is a documentation change, not a removal."""
    lib = (REPO / "scripts/lib-secrets.sh").read_text()
    assert re.search(r"^\s*env\|\"\"\)", lib, re.M), (
        "scripts/lib-secrets.sh stopped accepting NOO_SECRETS_BACKEND=env"
    )


# ── the llama.cpp build ref ────────────────────────────────────────────────

MOVING = {"master", "main", "HEAD", ""}


def test_the_llamacpp_ref_is_an_immutable_tag():
    """It defaulted to `master`, and the release workflow passes no override.

    Two published images with the same stack tag could therefore contain
    different upstream code, with nothing recording which.
    """
    df = (REPO / "docker/Dockerfile.llamacpp").read_text()
    m = re.search(r"^ARG LLAMACPP_REF=(\S*)$", df, re.M)
    assert m, "Dockerfile.llamacpp no longer declares ARG LLAMACPP_REF"
    assert m.group(1) not in MOVING, (
        f"Dockerfile.llamacpp defaults LLAMACPP_REF to the moving ref "
        f"'{m.group(1)}'"
    )


def test_the_dockerfile_refuses_a_moving_ref_rather_than_trusting_the_default():
    """A default is a default; the refusal is what survives a --build-arg."""
    df = (REPO / "docker/Dockerfile.llamacpp").read_text()
    assert "LLAMACPP_ALLOW_MOVING_REF" in df
    assert "master|main|HEAD|" in df, "no moving-ref guard in the build"
    # The silent-error fallback that defeated the pin must stay gone.
    assert "git clone https://github.com/ggml-org/llama.cpp.git . &&" not in df, (
        "the unshallow-clone fallback is back; a typo'd tag becomes a master "
        "build again"
    )
    assert "LLAMACPP_COMMIT" in df, (
        "the image no longer records which upstream commit it contains"
    )


def test_the_local_builder_agrees_with_the_dockerfile_default():
    """Drift here means `pai stack rebuild` and CI ship different code."""
    df = (REPO / "docker/Dockerfile.llamacpp").read_text()
    sh = (REPO / "scripts/build-hardened-llamacpp.sh").read_text()
    a = re.search(r"^ARG LLAMACPP_REF=(\S+)$", df, re.M).group(1)
    b = re.search(r'^LLAMACPP_REF="\$\{LLAMACPP_REF:-(\S+?)\}"$', sh, re.M).group(1)
    assert a == b, f"Dockerfile pins {a}, build-hardened-llamacpp.sh pins {b}"


# ── the admin-JWT fallback ─────────────────────────────────────────────────

def test_no_admin_token_is_minted_in_worker_code():
    """`parallel_collab._internal_token` minted an admin-scoped JWT from
    NOO_JWT_SECRET (once with the shipped example secret as a fallback). It
    is gone with its dead peer lane: the worker holds no
    signing secret, so there must be no mint left to fall back from."""
    src = (REPO / "src/noomesh/agents/parallel_collab.py").read_text()
    for needle in ("def _internal_token(", '"scopes": ["admin"]', "NOO_JWT_SECRET\")", "dev-secret-change-in-production"):
        assert needle not in src, f"parallel_collab mints a token again ({needle})"
