# SPDX-License-Identifier: AGPL-3.0-only
# Copyright 2026 PersonifAI LLC

"""The image store serves ``.tar.gz`` exports as plain bytes.

The controller compresses ``docker save`` output; a node fetches the file
and checks its sha256 against the gateway's manifest (the hash of the file
ON DISK). If the model-cache nginx ever answered with
``Content-Encoding: gzip`` (``gzip_static``, ``gzip on`` with a type that
covers ``.gz``, or an ``add_header``), the node's Go http client would
transparently inflate the body and every digest check would fail.
"""

import re
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
CONFS = [REPO_ROOT / "docker" / "model-cache.nginx.conf", REPO_ROOT / "docker" / "model-cache.locations.conf"]


def _code(path: Path) -> str:
    return "\n".join(re.sub(r"#.*", "", ln) for ln in path.read_text().splitlines())


def test_no_gzip_directive_or_content_encoding_in_the_model_cache_conf():
    for conf in CONFS:
        code = _code(conf)
        assert not re.search(r"^\s*gzip\w*\s", code, re.M), f"{conf.name}: a gzip directive would re-encode /images/"
        assert not re.search(r"content-encoding", code, re.I), f"{conf.name}: Content-Encoding breaks the digest check"


def test_the_images_location_exists():
    assert "location /images/" in _code(CONFS[1])
