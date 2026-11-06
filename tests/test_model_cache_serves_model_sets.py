# SPDX-License-Identifier: AGPL-3.0-only
# Copyright 2026 PersonifAI LLC

"""The model cache serves a model set's files, and only those (i300 F3).

``/sets/<id>/<revision>/<file>`` or ``.../<dir>/<file>`` is served read-only
from ``<MODELS_DIR>/sets/``. The manifest and its signature are NOT served
here (the gateway's ``modelset`` route is their one source), ``.part`` temp
files are not, and nothing outside the schema's path shape is. The deny rules
are regex locations in ``docker/model-cache.locations.conf``; this test reads
them from the file and runs them (PCRE and Python ``re`` agree on this
syntax), in nginx's order: regex locations first-match-wins, then the prefix.
"""

import re
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
LOCATIONS = REPO_ROOT / "docker" / "model-cache.locations.conf"


def _conf() -> str:
    return "\n".join(re.sub(r"#.*$", "", ln) for ln in LOCATIONS.read_text().splitlines())


def _sets_regex_denies() -> list:
    """The compiled ``location ~ ^/sets/...`` patterns, in file order."""
    out = []
    for m in re.finditer(r"location\s+~\s+(\^/sets/\S+)\s*\{(.*?)\n\}", _conf(), re.S):
        assert re.search(r"return\s+404;", m.group(2)), f"{m.group(1)}: a /sets/ regex block must deny"
        out.append(re.compile(m.group(1)))
    return out


def _served(uri: str) -> bool:
    """Would nginx hand this URI to the /sets/ alias?"""
    for rx in _sets_regex_denies():
        if rx.search(uri):
            return False
    return uri.startswith("/sets/")


def test_the_sets_prefix_is_a_read_only_alias_with_no_listing():
    locs = dict(
        (m.group(1).strip(), m.group(2))
        for m in re.finditer(r"location\s+([^\{]+?)\s*\{(.*?)\n\}", _conf(), re.S)
    )
    body = locs.get("/sets/")
    assert body is not None, "location /sets/ is gone"
    assert re.search(r"alias\s+/models/sets/;", body), "/sets/ must alias <MODELS_DIR>/sets/"
    assert "autoindex on" not in body
    assert len(_sets_regex_denies()) >= 3, "the /sets/ deny blocks are gone"


def test_set_files_are_served():
    sha = "0123456789abcdef0123456789abcdef01234567"
    for uri in [
        "/sets/kokoro-82m/abc123/weights.safetensors",
        f"/sets/kokoro-82m/{sha}/voices/af_heart.pt",
        "/sets/a.b_c-d/R1.0/config.json",
        "/sets/x/y/model-set.jsonl",
        "/sets/x/y/dir/NOTICE.txt",
    ]:
        assert _served(uri), f"{uri} must be served"


def test_the_manifest_and_signature_are_not_served_here():
    for uri in [
        "/sets/kokoro/rev1/model-set.json",
        "/sets/kokoro/rev1/model-set.json.sig",
        "/sets/kokoro/rev1/sub/model-set.json",
    ]:
        assert not _served(uri), f"{uri} must be 404: the gateway route is its only source"


def test_part_files_are_not_served():
    for uri in ["/sets/kokoro/rev1/w.bin.part", "/sets/kokoro/rev1/d/.w.bin.part"]:
        assert not _served(uri), f"{uri} is a stager temp file"


def test_only_the_schema_path_shape_is_served():
    for uri in [
        "/sets/",
        "/sets/kokoro",
        "/sets/kokoro/",
        "/sets/kokoro/rev1",
        "/sets/kokoro/rev1/",
        "/sets/kokoro/license-accepted.json",  # two segments: not a revision
        "/sets/kokoro/rev1/a/b/c.bin",  # two directory levels
        "/sets/kokoro/rev1/a/b/",
        "/sets/Kokoro/rev1/w.bin",  # id is lowercase
        "/sets/kokoro/-rev/w.bin",  # revision starts alphanumeric
        "/sets/kokoro/rev1/w bin",
        "/sets/kokoro/rev1/w%2Fbin",
    ]:
        assert not _served(uri), f"{uri} must not be served"


def test_dot_components_are_not_served():
    for uri in [
        "/sets/../etc/passwd",
        "/sets/kokoro/../x/w.bin",
        "/sets/kokoro/rev1/../w.bin",
        "/sets/kokoro/rev1/./w.bin",
        "/sets/kokoro/rev1/d/..",
        "/sets/kokoro/rev1/d/.",
    ]:
        assert not _served(uri), f"{uri} must not be served"
    # A dot inside a name is fine: only a whole component is refused.
    assert _served("/sets/kokoro/a..b/w..bin")
