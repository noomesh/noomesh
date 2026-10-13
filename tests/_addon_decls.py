# SPDX-License-Identifier: AGPL-3.0-only
# Copyright 2026 PersonifAI LLC

"""Each add-on overlay's `x-noo-addon` block, read file by file.

an earlier change: the overlay declares the grant its key asks for, and
noo-cli's build script derives the registry rows and default scopes from it.
The Python guards read the same bytes with their own parser — two parsers of
one source, not two sources.

READ PER FILE, RAW. Compose merges top-level `x-` keys across `-f` files, so
`docker compose config` (`_compose_projection.full_projection()`) shows one
merged block — the last overlay's — and a reader of the projection would see
one add-on and silently lose the others. Never read declarations from the
projection.
"""

from __future__ import annotations

from dataclasses import dataclass

from tests._compose_projection import ADDON_OVERLAYS, ROOT, load_raw, untag

BLOCK = "x-noo-addon"


@dataclass(frozen=True)
class Decl:
    overlay: str
    addon: str
    consumer: str
    key: str
    containers: tuple[str, ...]
    scopes: tuple[str, ...]
    why: str | None


def block_of(overlay: str) -> dict | None:
    """The raw block in one overlay, or None when the file declares none."""
    return untag(load_raw(ROOT / overlay)).get(BLOCK)


def decls() -> list[Decl]:
    out: list[Decl] = []
    for overlay in ADDON_OVERLAYS:
        b = block_of(overlay)
        if b is None:
            continue
        assert isinstance(b, dict), f"{overlay}: {BLOCK} must be a mapping, got {b!r}"
        out.append(
            Decl(
                overlay=overlay,
                addon=str(b.get("addon") or ""),
                consumer=str(b.get("consumer") or ""),
                key=str(b.get("key") or ""),
                containers=tuple(b.get("containers") or ()),
                scopes=tuple(b.get("scopes") or ()),
                why=b.get("why"),
            )
        )
    # A parse miss (a renamed block, a list moved) must not make every guard
    # that iterates this pass vacuously.
    assert len(out) >= 3, (
        f"found only {len(out)} {BLOCK} block(s) across {ADDON_OVERLAYS} — trellion, "
        "trellion-intel and evolve each declare one; the read broke"
    )
    return out
