# SPDX-License-Identifier: AGPL-3.0-only
# Copyright 2026 PersonifAI LLC

"""Files the Rust gateway embeds at compile time must be in the Docker context.

`include_str!` / `include_bytes!` create a build dependency that lives only in
the source — nothing in Cargo.toml mentions it. If the file sits outside
`gateway-rust/src/` it also has to appear in a `COPY` in
`docker/Dockerfile.gateway-rust`, or the image build dies with:

    error: couldn't read `src/../mcp-tools.json`: No such file or directory

Nothing else catches this. `cargo check`, `cargo test`, and CI's `rust-gateway`
job all build from a full checkout where the file is simply present; CI's
`build` job builds the ROOT Dockerfile, not the gateway one. So the gateway
image — the main artifact — is never built in CI, and a missing COPY reaches
the operator as a failed `noo stack rebuild`. It did, on 2026-08-02.

Static parse: no docker, no cargo, no network.
"""
from __future__ import annotations

import re
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
RUST_SRC = ROOT / "gateway-rust/src"
DOCKERFILE = ROOT / "docker/Dockerfile.gateway-rust"

# include_str!("…") / include_bytes!("…") — the path is relative to the FILE.
INCLUDE = re.compile(r'include_(?:str|bytes)!\s*\(\s*"([^"]+)"\s*\)')


def _copied_paths() -> list[str]:
    """Repo-relative sources named by COPY lines in the gateway Dockerfile."""
    out: list[str] = []
    for line in DOCKERFILE.read_text().splitlines():
        line = line.strip()
        if not line.upper().startswith("COPY "):
            continue
        if "--from=" in line:  # inter-stage copy, not from the build context
            continue
        parts = line.split()[1:]
        if len(parts) < 2:
            continue
        out.extend(parts[:-1])  # everything but the destination
    return out


def _embedded_outside_src() -> list[tuple[Path, Path]]:
    """(rust file, repo-relative embedded path) for embeds that escape src/.

    Includes inside a `#[cfg(test)]` module are skipped: they are compiled by
    `cargo test`, never by the release build the image runs, so they have no
    business in the Docker context. `stt_client.rs` embeds a .wav fixture that
    way and correctly is not COPY'd.

    Heuristic — anything after the file's FIRST `#[cfg(test)]` is treated as
    test-only, which matches this codebase's convention of a single test module
    at the end. A production embed placed below a test module would be missed;
    that is the trade for a static check with no cargo dependency.
    """
    found = []
    for rs in RUST_SRC.rglob("*.rs"):
        text = rs.read_text()
        test_at = text.find("#[cfg(test)]")
        cutoff = test_at if test_at >= 0 else len(text)
        for m in INCLUDE.finditer(text):
            if m.start() >= cutoff:
                continue
            rel = m.group(1)
            target = (rs.parent / rel).resolve()
            try:
                repo_rel = target.relative_to(ROOT)
            except ValueError:
                continue  # outside the repo entirely — not our concern here
            if RUST_SRC.resolve() in target.parents:
                continue  # under src/, already covered by `COPY gateway-rust/src`
            found.append((rs.relative_to(ROOT), repo_rel))
    return found


def test_embedded_files_exist() -> None:
    for rs, target in _embedded_outside_src():
        assert (ROOT / target).exists(), (
            f"{rs} embeds {target}, which does not exist — the build would fail "
            "at compile time"
        )


def test_embedded_files_are_in_the_docker_build_context() -> None:
    copied = _copied_paths()
    for rs, target in _embedded_outside_src():
        posix = target.as_posix()
        covered = any(
            posix == c or posix.startswith(c.rstrip("/") + "/") for c in copied
        )
        assert covered, (
            f"{rs} embeds {posix}, but no COPY in {DOCKERFILE.relative_to(ROOT)} "
            f"brings it into the build context.\n"
            f"  COPY sources present: {sorted(set(copied))}\n"
            "  `noo stack rebuild` will fail with "
            '"couldn\'t read … No such file or directory".'
        )
