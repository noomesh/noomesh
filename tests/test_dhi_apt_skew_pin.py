# SPDX-License-Identifier: AGPL-3.0-only
# Copyright 2026 PersonifAI LLC

"""Every apt stage on the DHI uv:0-debian13-dev base prefers the +deb13u0+ builds.

dhi.io/deb rebuilds packages as ``+deb13u0+dhiN`` that depend by exact
version on ``+deb13u0+`` builds of their libraries, which sort below the base's
``+dhiN`` builds (noomesh-internal 17a). Each stage that installs with apt on
that base writes a preference for every ``+deb13u0+`` build and installs with
``--allow-downgrades``. The form has broken a release lane three times:

- the version must be a regex (``/\\+deb13u0\\+/``): the glob ``*+deb13u0+*``
  never matches these versions (0.6.15-rc.1);
- the package must be the regex ``/./``, not ``*`` (apt's general form ignores
  a version pin) and not a list (it goes stale as DHI rebuilds more:
  gcc-14 and openblas, 0.6.16-rc.1);
- it must be in EVERY apt stage, the runtime ones too: 0.6.16-rc.1's release
  failed in the llama.cpp and ollama runtime stages after the builder was
  fixed (libgomp1 needs gcc-14-base at its +deb13u0+ version). A PR's image
  lane can pass on a CACHED runtime layer, so only this test sees a stage
  that lacks it.

Verified by apt on the pinned base when written; this keeps the form.
"""
from __future__ import annotations

import re
from pathlib import Path

DOCKER = Path(__file__).resolve().parents[1] / "docker"
BASE = re.compile(r"^FROM\s.*\$\{DHI_REGISTRY\}/uv:0-debian13-dev@", re.M)
PREF = re.compile(r"RUN printf '([^']*)'\s*\\\s*\n\s*>\s*/etc/apt/preferences\.d/dhi-deb13u0-skew")


def _stages(text: str) -> list[str]:
    """The Dockerfile split at each FROM, each piece starting with its FROM line."""
    starts = [m.start() for m in re.finditer(r"^FROM\s", text, re.M)]
    return [text[a:b] for a, b in zip(starts, starts[1:] + [len(text)])]


def _apt_stages_on_the_dhi_uv_base() -> list[tuple[str, int, str]]:
    out = []
    for df in sorted(DOCKER.glob("Dockerfile*")):
        for i, st in enumerate(_stages(df.read_text())):
            if BASE.match(st) and "apt-get install" in st:
                out.append((df.name, i, st))
    return out


def test_the_scan_finds_the_stages_it_was_written_for():
    found = {(name, i) for name, i, _ in _apt_stages_on_the_dhi_uv_base()}
    # llama.cpp builder + runtime, ollama fetch + runtime.
    assert len(found) >= 4, f"only {found}: the scan is not reading the Dockerfiles it should"
    assert {"Dockerfile.llamacpp", "Dockerfile.ollama"} <= {n for n, _ in found}


def test_every_apt_stage_prefers_every_deb13u0_build_and_allows_the_downgrade():
    bad = []
    for name, i, st in _apt_stages_on_the_dhi_uv_base():
        m = PREF.search(st)
        lines = m.group(1).replace("\\\\", "\\").split("\\n") if m else []
        if not ("Package: /./" in lines and "Pin: version /\\+deb13u0\\+/" in lines and "Pin-Priority: 1001" in lines):
            bad.append(f"{name} stage {i}: no `Package: /./` + version-regex preference at 1001 ({lines})")
        for inst in re.findall(r"apt-get install[^\n]*", st):
            if "--allow-downgrades" not in inst:
                bad.append(f"{name} stage {i}: `{inst.strip()}` lacks --allow-downgrades")
        if m and st.find("apt-get install") < m.start():
            bad.append(f"{name} stage {i}: the preference is written after the install")
    assert not bad, "\n".join(bad)
