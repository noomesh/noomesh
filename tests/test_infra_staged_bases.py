# SPDX-License-Identifier: AGPL-3.0-only
# Copyright 2026 PersonifAI LLC

"""The daily infra build takes TODAY'S base images (noomesh-internal i604).

Every infra FROM is pinned by digest in git, so before this a daily rebuild
could never take a distro security fix. Now infra-staged.yml resolves each
pinned FROM tag at its source registry to the digest it points at now, builds
on it, fingerprints the Dockerfile as built, and records the digests in the
`org.noomesh.base-digests` label. The release recomputes that fingerprint
from git plus the label and re-tags the exact staged digest. These pin it:

  * resolution reads each FROM's own tag at its source registry;
  * a base that moved backwards (older than the git pin, or than the base the
    current :staged used) is refused;
  * a changed base changes the fingerprint, and the git pins leave it as it was;
  * the plan re-tags only when the label's bases are pinned FROMs at the
    release commit, reads a staged copy without the label as built on the
    pins, and builds when the platforms disagree;
  * the bases reach the signed lock as a row no lock reader takes for an image.
"""
from __future__ import annotations

import importlib.util
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest
import yaml

ROOT = Path(__file__).resolve().parents[1]


def _load(name: str, path: str):
    spec = importlib.util.spec_from_file_location(name, ROOT / path)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


S = _load("infra_staged", "scripts/infra-staged.py")
P = _load("release_retag_plan", "scripts/release-retag-plan.py")

PIN_UV = "sha256:" + "1" * 64
PIN_PY = "sha256:" + "2" * 64
NEW_UV = "sha256:" + "a" * 64
NEW_PY = "sha256:" + "b" * 64
DOCKERFILE = f"""ARG DHI_REGISTRY=dhi.io
ARG HUB_MIRROR=ghcr.io/example/mirror
FROM ${{DHI_REGISTRY}}/uv:0-debian13-dev@{PIN_UV} AS builder
RUN echo uv:0-debian13-dev@{PIN_UV} stays in a RUN line
FROM ${{HUB_MIRROR}}/library/python:3.12-slim-bookworm@{PIN_PY}
COPY --from=builder /x /x
"""
T0 = datetime(2026, 11, 1, tzinfo=timezone.utc)


def _registry(published: dict[str, tuple[str, datetime]], created: dict[str, datetime]):
    """A fake `inspect(ref) -> (digest, created)`: tags resolve through
    `published`, digest refs through `created`. Records every ref asked."""
    asked: list[str] = []

    def inspect(ref: str):
        asked.append(ref)
        if "@" in ref:
            d = ref.split("@", 1)[1]
            return d, created[d]
        return published[ref]
    return inspect, asked


def test_each_from_tag_is_resolved_at_its_own_source_registry():
    inspect, asked = _registry(
        {"dhi.io/uv:0-debian13-dev": (NEW_UV, T0 + timedelta(days=5)),
         "docker.io/library/python:3.12-slim-bookworm": (NEW_PY, T0 + timedelta(days=4))},
        {PIN_UV: T0, PIN_PY: T0})
    got = S.resolve_bases(DOCKERFILE, inspect, None)
    assert got == {"uv:0-debian13-dev": NEW_UV, "library/python:3.12-slim-bookworm": NEW_PY}
    assert "dhi.io/uv:0-debian13-dev" in asked and "docker.io/library/python:3.12-slim-bookworm" in asked
    assert f"dhi.io/uv@{PIN_UV}" in asked, "the git pin's age must be read to refuse a downgrade"


def test_a_base_older_than_the_git_pin_or_the_current_staged_base_is_refused():
    older = {"dhi.io/uv:0-debian13-dev": (NEW_UV, T0 - timedelta(days=1)),
             "docker.io/library/python:3.12-slim-bookworm": (PIN_PY, T0)}
    inspect, _ = _registry(older, {PIN_UV: T0, PIN_PY: T0, NEW_UV: T0 - timedelta(days=1)})
    with pytest.raises(ValueError, match="moved backwards"):
        S.resolve_bases(DOCKERFILE, inspect, None)
    # Newer than the pin, but older than what the current :staged was built on.
    staged_uv = "sha256:" + "c" * 64
    newer_than_pin = {"dhi.io/uv:0-debian13-dev": (NEW_UV, T0 + timedelta(days=2)),
                      "docker.io/library/python:3.12-slim-bookworm": (PIN_PY, T0)}
    inspect, _ = _registry(newer_than_pin, {PIN_UV: T0, PIN_PY: T0, NEW_UV: T0 + timedelta(days=2),
                                            staged_uv: T0 + timedelta(days=3)})
    with pytest.raises(ValueError, match="current :staged"):
        S.resolve_bases(DOCKERFILE, inspect, S.format_bases({"uv:0-debian13-dev": staged_uv}))


def test_a_changed_base_changes_the_fingerprint_and_the_pins_do_not():
    pins = S.repo_fingerprint("llamacpp")
    [base] = S.pinned_bases((ROOT / "docker/Dockerfile.llamacpp").read_text())
    assert S.repo_fingerprint("llamacpp", bases={base["key"]: base["digest"]}) == pins
    moved = S.repo_fingerprint("llamacpp", bases={base["key"]: NEW_UV})
    assert moved != pins and moved.startswith("sha256:")


def test_rebasing_moves_only_the_named_from_lines():
    out = S.rebase_text(DOCKERFILE, {"uv:0-debian13-dev": NEW_UV})
    assert f"FROM ${{DHI_REGISTRY}}/uv:0-debian13-dev@{NEW_UV} AS builder" in out
    assert f"RUN echo uv:0-debian13-dev@{PIN_UV} stays" in out, "only FROM lines move"
    assert f"python:3.12-slim-bookworm@{PIN_PY}" in out
    with pytest.raises(S.NoFingerprint, match="not pinned FROMs"):
        S.rebase_text(DOCKERFILE, {"uv:1-debian13-dev": NEW_UV})


def test_the_label_round_trips_and_refuses_malformed_values():
    bases = {"uv:0-debian13-dev": NEW_UV, "library/python:3.12-slim-bookworm": NEW_PY}
    label = S.format_bases(bases)
    assert "@" not in label and S.parse_bases(label) == bases
    for bad in ("", "uv:0=sha256:xyz", f"uv:0={NEW_UV};uv:0={NEW_UV}", f"uv={NEW_UV}"):
        with pytest.raises(ValueError):
            S.parse_bases(bad)


# ── the release plan ─────────────────────────────────────────────────────

NOW = datetime(2026, 11, 20, 12, 0, tzinfo=timezone.utc)
SDIG = "sha256:" + "5" * 64


def _apply(labels_by_plat: dict[str, dict], fingerprint_of):
    result = {"retag": {"llamacpp": False}, "why": {}, "rc_digests": {}, "source_tags": {}}
    return P.apply_staged(result, lambda img: (SDIG, labels_by_plat), fingerprint_of, NOW, ("llamacpp",))


def _lab(fp, bases=None):
    lab = {"org.noomesh.build-fingerprint": fp, "org.opencontainers.image.created": "2026-11-20T03:17:00Z"}
    if bases is not None:
        lab[S.BASES_LABEL] = bases
    return lab


def test_the_plan_retags_a_copy_built_on_todays_bases_and_records_them():
    [base] = S.pinned_bases((ROOT / "docker/Dockerfile.llamacpp").read_text())
    label = S.format_bases({base["key"]: NEW_UV})
    fp = S.repo_fingerprint("llamacpp", bases={base["key"]: NEW_UV})
    fpof = lambda img, bases: S.repo_fingerprint(img, bases=bases)  # noqa: E731
    r = _apply({"linux/amd64": _lab(fp, label), "linux/arm64": _lab(fp, label)}, fpof)
    assert r["retag"]["llamacpp"] is True, r["why"]
    assert r["staged_bases"] == {"llamacpp": label}
    # The same label at a commit where that FROM is no longer pinned: build.
    stale = S.format_bases({"uv:1-debian13-dev": NEW_UV})
    r = _apply({"linux/amd64": _lab(fp, stale), "linux/arm64": _lab(fp, stale)}, fpof)
    assert r["retag"]["llamacpp"] is False and "staged bases" in r["why"]["llamacpp"], r["why"]


def test_a_copy_without_the_label_is_read_as_built_on_the_git_pins():
    fp = S.repo_fingerprint("llamacpp")
    fpof = lambda img, bases: S.repo_fingerprint(img, bases=bases)  # noqa: E731
    r = _apply({"linux/amd64": _lab(fp), "linux/arm64": _lab(fp)}, fpof)
    assert r["retag"]["llamacpp"] is True, r["why"]
    assert r["staged_bases"] == {}


def test_platforms_that_disagree_on_their_bases_build():
    [base] = S.pinned_bases((ROOT / "docker/Dockerfile.llamacpp").read_text())
    label = S.format_bases({base["key"]: NEW_UV})
    fp = S.repo_fingerprint("llamacpp", bases={base["key"]: NEW_UV})
    fpof = lambda img, bases: S.repo_fingerprint(img, bases=bases)  # noqa: E731
    r = _apply({"linux/amd64": _lab(fp, label), "linux/arm64": _lab(fp)}, fpof)
    assert r["retag"]["llamacpp"] is False and "differs between platforms" in r["why"]["llamacpp"], r["why"]


def test_the_bases_reach_the_signed_lock_as_no_image_row():
    wf = yaml.safe_load((ROOT / ".github/workflows/images-release.yml").read_text())
    assert wf["jobs"]["release-line"]["outputs"]["staged_bases"] == "${{ steps.plan.outputs.staged_bases }}"
    steps = wf["jobs"]["lock"]["steps"]
    rec = next(s for s in steps if s.get("name") == "Record the staged infra images a release reuses")
    assert 'f"staged-base:{img}={bases}"' in rec["run"] and "digests/staged-base-" in rec["run"]
    sign = next(i for i, s in enumerate(steps) if "release-sign" in str(s.get("run", "")))
    assert steps.index(rec) < sign, "the base provenance must be inside the signed lock"
    row = "staged-base:llamacpp=" + S.format_bases({"uv:0-debian13-dev": NEW_UV})
    images, _ = P.parse_lock(f"{row}\nllamacpp@{SDIG}\n")
    assert images == {"llamacpp": SDIG}, "a staged-base row must never read as an image"


def test_the_launchers_lock_reader_skips_the_staged_base_row():
    """The REAL shell loop (lib-dist.sh dist_load_stack_lock) feeds the
    gateway's NOO_IMAGE_DIGEST_* and so every node's pinned refs; the Go
    agent never reads lock text. An unknown row must not stop a start."""
    reader = _load("stack_lock_reader", "tests/test_stack_lock_reader.py")
    row = "staged-base:llamacpp=" + S.format_bases({"uv:0-debian13-dev": NEW_UV})
    got = reader._exported_for(f"# tag v1.3.0\n{row}\nllamacpp@{SDIG}\n")
    assert got == {"NOO_IMAGE_DIGEST_LLAMACPP": "@" + SDIG}, got


def test_the_daily_job_resolves_rebases_and_fingerprints_before_it_builds():
    wf = yaml.safe_load((ROOT / ".github/workflows/infra-staged.yml").read_text())
    steps = wf["jobs"]["stage"]["steps"]
    names = [s.get("name", "") for s in steps]
    resolve = next(i for i, n in enumerate(names) if n.startswith("Resolve today's base digests"))
    build = next(i for i, n in enumerate(names) if n.startswith("Build + push"))
    login = next(i for i, n in enumerate(names) if n.startswith("Registry logins"))
    assert login < resolve < build
    run = steps[resolve]["run"]
    order = [run.index(x) for x in ("infra-staged.py resolve-bases", "infra-staged.py rebase-dockerfile",
                                    'infra-staged.py fingerprint "${{ matrix.image }}" --bases "$bases"')]
    assert order == sorted(order), "resolve, then rebase the Dockerfile, then fingerprint what is built"
    assert '--staged-label "$old"' in run, "the current :staged base is the downgrade floor"
