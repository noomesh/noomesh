# SPDX-License-Identifier: AGPL-3.0-only
# Copyright 2026 PersonifAI LLC

"""The gateway runtime image must stay Python-free and shell-free.

an earlier change moved the mesh Alembic chain into the binary
(mesh_migrate.rs), which removed the last reason this image carried a Python
interpreter, and with it the last reason it needed a shell. The runtime stage
is now FROM a non-dev hardened base: no /bin/sh, no apt, no pip.

That property is easy to lose and expensive to lose silently. Adding a `RUN`
line, or a shell-form CMD, produces an image that either fails to BUILD (RUN)
or builds fine and then never runs the instruction (shell-form HEALTHCHECK,
which Docker cannot evaluate without /bin/sh and which therefore marks a
perfectly healthy gateway unhealthy — and Docker restarts unhealthy
containers).

These assertions are on the RUNTIME stage only. The builder and any earlier
stages are `-dev` images and may use RUN freely.
"""

from __future__ import annotations

import re
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parents[1]
DOCKERFILE = REPO / "docker" / "Dockerfile.gateway-rust"


def _runtime_stage() -> str:
    """Text from the LAST FROM to end of file."""
    text = DOCKERFILE.read_text()
    starts = [m.start() for m in re.finditer(r"^FROM ", text, re.MULTILINE)]
    assert starts, "no FROM instruction found"
    return text[starts[-1] :]


def _instructions(stage: str) -> list[str]:
    """Logical instructions, with line continuations joined and comments dropped."""
    out: list[str] = []
    buf = ""
    for raw in stage.splitlines():
        line = raw.strip()
        if line.startswith("#") or not line:
            continue
        buf += line
        if buf.endswith("\\"):
            buf = buf[:-1].rstrip() + " "
            continue
        out.append(buf)
        buf = ""
    if buf:
        out.append(buf)
    return out


def test_runtime_base_is_the_non_dev_hardened_image() -> None:
    stage = _runtime_stage()
    first = stage.splitlines()[0]
    # ${DHI_REGISTRY} defaults to dhi.io; the release workflow points it at
    # our ghcr MIRRORS of the same hardened images (build-from-mirrors,
    # 2026-08-20 — dhi TLS flakes). Either spelling is the hardened base;
    # what this test guards is the -dev/-shell distinction below.
    assert "dhi.io/" in first or "${DHI_REGISTRY}/" in first, (
        f"runtime base is not a hardened dhi image (direct or mirrored): {first}"
    )
    assert "-dev@" not in first and not first.rstrip().endswith("-dev"), (
        f"runtime base is a -dev variant: {first}\n"
        "The -dev images carry apt and a shell. The runtime stage must use the "
        "non-dev variant — that is the whole point of dropping Python."
    )
    assert "debian13" in first, (
        "runtime base must track the BUILDER's Debian release. The binary needs "
        "GLIBC_2.38/2.39; a bookworm (Debian 12, glibc 2.36) runtime builds "
        "clean and then dies at exec."
    )
    assert "@sha256:" in first, "runtime base must be digest-pinned"


def test_runtime_stage_has_no_run_instruction() -> None:
    offenders = [i for i in _instructions(_runtime_stage()) if i.startswith("RUN ")]
    assert not offenders, (
        "RUN in the runtime stage, which has no shell:\n  "
        + "\n  ".join(offenders)
        + "\nUse COPY (with --chmod= if a mode is needed), or do the work in an "
        "earlier -dev stage and COPY --from it."
    )


@pytest.mark.parametrize("instruction", ["ENTRYPOINT", "CMD", "HEALTHCHECK"])
def test_exec_form_only(instruction: str) -> None:
    """Shell form is unrunnable here; Docker gives no build-time warning."""
    for line in _instructions(_runtime_stage()):
        if not line.startswith(instruction + " "):
            continue
        body = line[len(instruction) :].strip()
        if instruction == "HEALTHCHECK":
            m = re.search(r"\bCMD\b(.*)", body)
            if not m:
                continue  # HEALTHCHECK NONE
            body = m.group(1).strip()
        assert body.startswith("["), (
            f"{instruction} uses shell form:\n  {line}\n"
            "There is no /bin/sh in this image. Use JSON exec form."
        )


def test_no_python_interpreter_is_invoked() -> None:
    for line in _instructions(_runtime_stage()):
        if line.startswith(("ENTRYPOINT", "CMD", "HEALTHCHECK")):
            assert '"python"' not in line and '"python3"' not in line, (
                f"runtime stage still invokes Python:\n  {line}\n"
                "The mesh chain is applied by mesh_migrate.rs now; nothing "
                "Python-shaped should start in this container."
            )


def test_entrypoint_is_the_binary() -> None:
    entry = [i for i in _instructions(_runtime_stage()) if i.startswith("ENTRYPOINT")]
    assert len(entry) == 1, f"expected exactly one ENTRYPOINT, got {entry}"
    assert "/usr/local/bin/noo-gateway" in entry[0], (
        f"ENTRYPOINT should exec the gateway binary directly: {entry[0]}"
    )


def test_healthcheck_uses_the_binarys_own_probe() -> None:
    hc = [i for i in _instructions(_runtime_stage()) if i.startswith("HEALTHCHECK")]
    assert len(hc) == 1, f"expected exactly one HEALTHCHECK, got {hc}"
    assert "--health" in hc[0] and "/usr/local/bin/noo-gateway" in hc[0], (
        f"HEALTHCHECK must use the binary's --health probe: {hc[0]}\n"
        "There is no curl, wget or python in this image."
    )


def test_dashboard_html_is_copied() -> None:
    """The pages live at GATEWAY_HTML_DIR, which is under /app/src.

    Dropping `COPY src ./src` nearly took the dashboard with it. index.html is
    NOT in static/, so routes/ui.rs's fallback to STATIC_DIR does not cover
    it, and dev cannot notice: compose bind-mounts the file over that exact
    path. It would have surfaced only on a --dist install, as
    "Page not found: index.html".
    """
    stage = _runtime_stage()
    copies = [i for i in _instructions(stage) if i.startswith("COPY ")]
    assert any("src/noomesh/gateway/" in c and ".html" in c for c in copies), (
        "no COPY for the dashboard HTML. routes/ui.rs reads them from "
        "paths::GATEWAY_HTML_DIR (/app/src/noomesh/gateway); without a COPY "
        "the dashboard 404s on any install that does not bind-mount them."
    )
    assert any("/app/static" in c for c in copies), "static assets are not copied"


def test_gateway_html_dir_matches_the_copy_destination() -> None:
    """paths.rs and the Dockerfile must agree on where the pages land."""
    paths_rs = (REPO / "gateway-rust" / "src" / "paths.rs").read_text()
    m = re.search(r'GATEWAY_HTML_DIR:\s*&str\s*=\s*"([^"]+)"', paths_rs)
    assert m, "GATEWAY_HTML_DIR not found in paths.rs"
    dest = m.group(1).rstrip("/")
    copies = [i for i in _instructions(_runtime_stage()) if i.startswith("COPY ")]
    assert any(dest in c for c in copies), (
        f"GATEWAY_HTML_DIR is {dest!r} but no COPY targets it:\n  "
        + "\n  ".join(copies)
    )


def test_python_source_tree_is_not_copied() -> None:
    """`COPY src ./src` shipped the Python package purely for entrypoint.py."""
    for line in _instructions(_runtime_stage()):
        if not line.startswith("COPY "):
            continue
        parts = [p for p in line.split()[1:] if not p.startswith("--")]
        if len(parts) < 2:
            continue
        src = parts[0]
        # The dashboard's static assets live under the Python tree but are not
        # Python; that one COPY is expected and named explicitly.
        if src == "src/noomesh/gateway/static":
            continue
        assert src != "src" and not src.startswith("src/noomesh/db"), (
            f"runtime stage copies the Python source tree:\n  {line}\n"
            "Nothing in this image imports it any more."
        )
    # Instructions, not raw text: the stage's comments legitimately explain
    # why PYTHONPATH is gone, and matching those would make the check
    # unfixable-by-construction.
    env_pythonpath = [
        i
        for i in _instructions(_runtime_stage())
        if i.startswith("ENV ") and "PYTHONPATH" in i
    ]
    assert not env_pythonpath, (
        f"PYTHONPATH is set in the runtime stage: {env_pythonpath}\n"
        "There is no interpreter and no source tree for it to point at."
    )
