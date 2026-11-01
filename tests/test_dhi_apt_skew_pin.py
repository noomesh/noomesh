# SPDX-License-Identifier: AGPL-3.0-only
# Copyright 2026 PersonifAI LLC

"""The llama.cpp builder's DHI apt-skew preference must actually apply.

dhi.io/deb rebuilds packages as ``+deb13u0+dhiN`` that depend by exact
version on ``+deb13u0+`` builds of their libraries, which sort below the base's
``+dhiN`` builds (noomesh-internal 17a). The builder prefers every
``+deb13u0+`` build. Two apt rules make that easy to get silently wrong, and
each one has broken a release lane:

- the version must be a regex (``/\\+deb13u0\\+/``): the glob ``*+deb13u0+*``
  never matches these versions (0.6.15-rc.1);
- the package must be a regex (``/./``), not ``*``: ``Package: *`` is apt's
  general form, which honours only release/origin pins and ignores a version
  pin; and a fixed list of packages goes stale as DHI rebuilds more
  (gcc-14 and openblas, 0.6.16-rc.1).

Verified by apt itself (``apt-cache policy`` and a full install on the pinned
base) when this was written; this test keeps the form from regressing.
"""
from __future__ import annotations

import re
from pathlib import Path

DOCKERFILE = Path(__file__).resolve().parents[1] / "docker" / "Dockerfile.llamacpp"


def _pref_lines() -> list[str]:
    text = DOCKERFILE.read_text()
    m = re.search(r"RUN printf '([^']*)'\s*\\\s*\n\s*>\s*/etc/apt/preferences\.d/dhi-deb13u0-skew", text)
    assert m, "the dhi-deb13u0-skew preference is no longer written where this test looks"
    return m.group(1).replace("\\\\", "\\").split("\\n")


def test_the_preference_covers_every_package_by_regex_with_a_version_regex():
    lines = _pref_lines()
    assert "Package: /./" in lines, f"Package must be the regex /./ (not *, not a list): {lines}"
    assert "Pin: version /\\+deb13u0\\+/" in lines, f"the version pin must be a regex: {lines}"
    assert "Pin-Priority: 1001" in lines, "priority > 1000 is what permits the downgrade"


def test_the_install_allows_the_downgrade_the_preference_asks_for():
    text = DOCKERFILE.read_text()
    install = re.search(r"apt-get install[^\n]*", text)
    assert install and "--allow-downgrades" in install.group(0)
