# SPDX-License-Identifier: AGPL-3.0-only
# Copyright 2026 PersonifAI LLC

"""Compose `user:` is a NAME from the image's /etc/passwd, never a number.

i64 pinned redis and grafana (DHI -dev images, image USER 0) to
`user: "65532:65532"`. The 0.6.4-rc.1 rehearsal on Docker 27.5.1 (compose
v2.33) then failed onboard with

    Error response from daemon: getent unable to find entry "65532:65532"
    in passwd database

because that daemon resolves the `user:` string BY NAME when compose copies
the service's `secrets:` (environment-sourced) into the container. A bare
`65532` and `nonroot:nonroot` fail the same way; only a bare name present
in the image's passwd works. Docker 29 accepts every form, so a box on a
newer engine never sees it: the guard is here so it cannot come back.
"""

from __future__ import annotations

import re
import subprocess

from tests._compose_projection import ROOT, load_raw, untag
from tests.test_compose_secret_files import OWNED_UIDS

# The name each pinned image gives uid 65532, read from the image's
# /etc/passwd (`docker run --rm --entrypoint /bin/sh <image> -c 'grep 65532
# /etc/passwd'`, 2026-10-15). Static on purpose: tests never pull images.
#   ghcr.io/noomesh/dhi/redis:8.6-debian13-dev   nonroot:x:65532:65532
#   ghcr.io/noomesh/dhi/grafana:12-debian13-dev  grafana:x:65532:65532
# (The UPSTREAM grafana image also has a `grafana`, at 472: the name is only
# 65532 in the DHI family, which is why `noo cluster verify` judges the live
# uid, not this string.)
NAMED_USERS: dict[str, tuple[str, str, int]] = {
    # service: (image name:tag under the base registry, user, uid)
    "redis": ("redis:8.6-debian13-dev", "nonroot", 65532),
    "grafana": ("grafana:12-debian13-dev", "grafana", 65532),
}

NUMERIC_USER = re.compile(r"^\s*user:\s*[\"']?\d")


def _shipped_compose_files() -> list[str]:
    out = subprocess.run(["git", "ls-files"], cwd=ROOT, capture_output=True, text=True, check=True).stdout
    files = [f for f in out.splitlines() if re.search(r"(^|/)[^/]*compose[^/]*\.ya?ml$", f)]
    assert "docker-compose.cluster.yml" in files, files  # the scan found the files it is for
    return files


def test_no_shipped_compose_service_uses_a_numeric_user() -> None:
    bad = []
    for f in _shipped_compose_files():
        for n, line in enumerate((ROOT / f).read_text().splitlines(), 1):
            if NUMERIC_USER.match(line):
                bad.append(f"{f}:{n}: {line.strip()}")
        for svc, spec in (untag(load_raw(ROOT / f)).get("services") or {}).items():
            user = str((spec or {}).get("user", ""))
            if user and user.split(":")[0].strip().isdigit():
                bad.append(f"{f}: {svc} user {user!r}")
    assert not bad, (
        "a numeric compose `user:` fails onboard on Docker 27 (`getent unable to find entry` "
        f"when compose copies secrets in); use the image's passwd NAME: {bad}")


def test_the_pattern_catches_what_it_is_for() -> None:
    for line in ['    user: "65532:65532"', "    user: 65532", "  user: '0'"]:
        assert NUMERIC_USER.match(line), line
    for line in ["    user: nonroot", "    user: grafana", '    # user: "65532:65532"']:
        assert not NUMERIC_USER.match(line), line


def test_redis_and_grafana_run_as_the_images_name_for_their_reader_uid() -> None:
    services = untag(load_raw(ROOT / "docker-compose.cluster.yml"))["services"]
    for svc, (image, user, uid) in NAMED_USERS.items():
        spec = services[svc]
        assert spec.get("user") == user, f"{svc}: user {spec.get('user')!r}, want {user!r}"
        assert re.sub(r"\$\{NOO_IMAGE_DIGEST_[A-Z_]+:-(?:@sha256:[0-9a-f]{64})?\}$", "", spec["image"]).endswith(f"/{image}"), (
            f"{svc} image is {spec['image']}: re-measure the passwd name for uid {uid} before changing NAMED_USERS")
        # The name's uid is the uid the secrets (and keys, data) are handed to.
        assert str(uid) == OWNED_UIDS[svc], (svc, uid, OWNED_UIDS[svc])
        secrets = spec.get("secrets") or []
        assert secrets, f"{svc} has no secrets: the getent path this guards is not exercised"
        for s in secrets:
            assert str(s.get("x-noo-uid")) == str(uid), (svc, s)
