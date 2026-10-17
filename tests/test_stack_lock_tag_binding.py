# SPDX-License-Identifier: AGPL-3.0-only
# Copyright 2026 PersonifAI LLC

"""The signed stack lock binds the stack tag (`# stack <tag>` inside the signed bytes).

Before, the tag binding was a `# tag <tag>` line the CLI wrote UNSIGNED after
verifying, so a validly signed lock of an older release served under a newer
tag was accepted and pinned. The release workflow now signs `# stack $TAG` as
the first line; `noo upgrade --stack` refuses a lock that names another tag
(noo-cli upgrade.rs lock_tag_binding, tested there), and the launcher reads
only that signed line when it is present.
"""

import pathlib
import subprocess
import tempfile

ROOT = pathlib.Path(__file__).resolve().parents[1]
D = "sha256:" + "a" * 64


def _fn(name):
    src = (ROOT / "scripts/lib-dist.sh").read_text()
    start = src.index(f"{name}() {{")
    return src[start:src.index("\n}\n", start) + 3]


def _state(lock_text: str, tag: str):
    with tempfile.TemporaryDirectory() as tmp:
        (pathlib.Path(tmp) / "stack.lock").write_text(lock_text)
        script = f"set -u\n_DIST_PINS=()\n{_fn('dist_load_stack_lock')}\ndist_load_stack_lock {tag}\necho \"$_DIST_LOCK_STATE\"\n"
        r = subprocess.run(["bash", "-c", script], capture_output=True, text=True, cwd=tmp, timeout=30)
    assert r.returncode == 0, r.stderr
    return r.stdout.strip().splitlines()[-1]


ROW = f"gateway@{D}\n"


def test_signed_line_for_this_tag_loads():
    assert _state(f"# tag v0.6.6\n# stack v0.6.6\n{ROW}", "v0.6.6") == "loaded"


def test_signed_line_for_another_tag_is_never_applied_even_with_a_forged_tag_header():
    # the unsigned `# tag` header says v0.6.7; the signed line says v0.6.5
    assert _state(f"# tag v0.6.7\n# stack v0.6.5\n{ROW}", "v0.6.7") == "other"


def test_two_signed_lines_must_all_match():
    assert _state(f"# stack v0.6.7\n# stack v0.6.5\n{ROW}", "v0.6.7") == "other"


def test_rc_signed_lock_is_not_the_final():
    assert _state(f"# stack v0.6.7-rc.1\n{ROW}", "v0.6.7") == "other"


def test_legacy_lock_without_the_signed_line_still_loads_by_its_tag_header():
    assert _state(f"# tag v0.6.5\n{ROW}", "v0.6.5") == "loaded"
    assert _state(f"# tag v0.6.4\n{ROW}", "v0.6.5") == "other"


def test_release_workflow_signs_the_tag_line_and_the_cli_verifies_it():
    wf = (ROOT / ".github/workflows/images-release.yml").read_text()
    assert 'echo "# stack $TAG"' in wf
    up = (ROOT / "noo-cli/src/commands/upgrade.rs").read_text()
    assert "lock_tag_binding(tag, &text)" in up and "stack_lock_tag_mismatch" in up
