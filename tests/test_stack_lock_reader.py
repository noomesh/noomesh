# SPDX-License-Identifier: AGPL-3.0-only
# Copyright 2026 PersonifAI LLC

"""The launcher's stack.lock reader must take IMAGE rows only.

#1108 added provenance rows to the signed lock (`source:trellion@<git
sha>`) so a stack tag records which source an image was built from. The
launcher's digest loop treated every non-comment line as `<image>@<digest>`,
derived `NOO_IMAGE_DIGEST_SOURCE:PAI_TRELLION` from it, and `export` refused
that as an invalid identifier — under `set -e` the whole start died.

Effect: stack v0.2.22 could not boot anywhere. The two changes were correct
alone and fatal together, and nothing compared them, so it surfaced on the
operator's controller rather than in CI.

These tests run the REAL loop out of the REAL script, because the bug was in
the shell, not in a reimplementation of it.
"""

import pathlib
import subprocess
import tempfile

ROOT = pathlib.Path(__file__).resolve().parents[1]
# The one reader (dist_load_stack_lock), shared by start and restart.
SCRIPT = ROOT / "scripts" / "lib-dist.sh"


def _digest_loop() -> str:
    """The launcher's `while … done < stack.lock` block, verbatim.

    Anchored on the `done < stack.lock` and searched BACKWARDS for its
    `while`, so a `while IFS= read` added earlier in the script cannot be
    picked up instead. The regression test below asserts an ABSENCE, and an
    absence passes vacuously against the wrong block — so the extraction
    also asserts it found the loop that does the exporting.
    """
    src = SCRIPT.read_text()
    end = src.index("done < stack.lock") + len("done < stack.lock")
    start = src.rindex("    while IFS= read -r line; do", 0, end)
    block = src[start:end]
    assert "NOO_IMAGE_DIGEST_" in block, "extracted the wrong block from the launcher"
    return block


def _exported_for(lock_text: str) -> dict[str, str]:
    with tempfile.TemporaryDirectory() as tmp:
        (pathlib.Path(tmp) / "stack.lock").write_text(lock_text)
        script = f"set -eu\n{_digest_loop()}\nenv | grep '^NOO_IMAGE_DIGEST_' || true\n"
        out = subprocess.run(
            ["bash", "-c", script], capture_output=True, text=True, cwd=tmp
        )
    assert out.returncode == 0, f"the loop exited {out.returncode}: {out.stderr.strip()}"
    return dict(
        line.split("=", 1)
        for line in out.stdout.splitlines()
        if line.startswith("NOO_IMAGE_DIGEST_")
    )


# Shaped like the published stack-v0.2.22.lock, provenance row included.
LOCK = """# tag v0.2.22
gateway@sha256:f680ae1d2517ac508d370181090b3d502c7f170b96e9c7a85a11b907778f653e
node-agent@sha256:7f9090c103dabb6480b6ed96ee734d8b15b2d10994e4cd00d61ac666849fc9a7
postgres-pgvector@sha256:c8b6aa0e68df8b9a82bd321478f25e47eb4ecc777920cdc62f80c4399aeca52d
source:trellion@1b1a75025145ef42ed95c3940aaa4f1e5193480f
trellion@sha256:e29bd08279570650290eef16b96dcd0cbc6fc6be33854fb3a36648220bc4fd4e
"""


def test_a_provenance_row_does_not_break_the_start():
    """The regression: `source:…` must be skipped, not exported."""
    got = _exported_for(LOCK)
    assert not any("SOURCE" in k for k in got), (
        "a provenance row was turned into an env var — that name is not a valid "
        f"shell identifier and `export` kills the launcher: {got}"
    )


def test_image_rows_still_pin():
    got = _exported_for(LOCK)
    assert got["NOO_IMAGE_DIGEST_GATEWAY"].startswith("@sha256:")
    # Hyphens become underscores so the name is a valid identifier.
    assert "NOO_IMAGE_DIGEST_NODE_AGENT" in got
    assert "NOO_IMAGE_DIGEST_POSTGRES_PGVECTOR" in got
    assert len(got) == 4, f"expected the four image rows, got {sorted(got)}"


def test_any_future_provenance_row_is_skipped_too():
    """The check is on the DIGEST, not on a `source:` name.

    Testing the value rather than the key is what makes this durable: a later
    provenance row under a different name is skipped automatically, because
    only an image row carries a sha256 digest.
    """
    lock = LOCK + "builder:buildkit@v0.16.0\nsbom:cyclonedx@1.6\n"
    got = _exported_for(lock)
    assert len(got) == 4, f"non-image rows leaked into the env: {sorted(got)}"


def test_a_row_whose_name_is_not_an_identifier_does_not_kill_the_start():
    """The failure mode, not just the one row that triggered it.

    `export` dies on any name that is not a shell identifier, and the `tr`
    only folds case and hyphens — a colon, a dot or a slash survives it. The
    digest test alone does not catch these, because they ARE digest-bearing
    rows. Each of them reproduced v0.2.22 exactly before the name guard.
    """
    for row in (
        "attestation:sbom@sha256:bbb",          # a future non-image row
        "ghcr.io/personifai/gateway@sha256:cc",  # a registry-qualified image
        "sha256:orphan",                         # no `@`: img and dig are equal
    ):
        got = _exported_for(LOCK + row + "\n")
        assert len(got) == 4, f"{row!r} leaked into the env: {sorted(got)}"


def test_the_four_image_rows_survive_a_row_we_skip():
    """Skipping is not the same as bailing out.

    A row the launcher cannot use must not cost the rows it can — the point
    is to keep booting with the pins we understand.
    """
    got = _exported_for(LOCK + "attestation:sbom@sha256:bbb\n")
    assert got["NOO_IMAGE_DIGEST_GATEWAY"].startswith("@sha256:")
    assert len(got) == 4, sorted(got)
