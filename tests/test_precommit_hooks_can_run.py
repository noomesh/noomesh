# SPDX-License-Identifier: AGPL-3.0-only
# Copyright 2026 PersonifAI LLC

"""A hook that cannot run is not a check, and nothing says so out loud.

The `detect-secrets` hook in this file pointed at `--baseline
.secrets.baseline` for as long as the file has existed. That baseline has
never been in the tree. detect-secrets does not scan-and-warn when its
baseline is missing; it errors. So the hook was not a weak check, it was a
guaranteed failure for the first person to run `pre-commit install` — and
nobody found out, because `pre-commit` is not installed here and CI does not
invoke it.

That is the shape this file guards: a hook whose own configuration names
something that is not there. It cannot verify that a hook CATCHES anything —
only that it can start.

It also pins the one hook we care about being identical in both places. The
leak gate is the tier-1 control (`scripts/leak-check.sh`), and the point of
running it locally is that a commit is judged by the rule it will be judged
by in CI. Two gates that drift apart are worse than one gate, because the
local one teaches you the wrong rule.
"""
from __future__ import annotations

import os
from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parents[1]
CONFIG = ROOT / ".pre-commit-config.yaml"
CI = ROOT / ".github" / "workflows" / "ci.yml"

# Args that name a path in this tree. A hook may legitimately pass a flag
# value that is not a file (`--severity=warning`, `E,F,W,I,S`), so this is
# the set of flags whose VALUE is known to be a path.
PATH_BEARING_FLAGS = {"--baseline", "-c", "--config"}


def hooks():
    doc = yaml.safe_load(CONFIG.read_text())
    for repo in doc["repos"]:
        for hook in repo["hooks"]:
            yield repo["repo"], hook


def test_every_path_a_hook_names_exists():
    """The exact failure that shipped: `--baseline .secrets.baseline`, and no
    such file. A hook whose config names a missing file does not degrade — it
    stops."""
    missing = []
    for repo, hook in hooks():
        args = hook.get("args") or []
        for flag, value in zip(args, args[1:]):
            if flag in PATH_BEARING_FLAGS and not (ROOT / value).exists():
                missing.append(f"{hook['id']} ({repo}): {flag} {value}")
    assert not missing, (
        "these hooks name a path that is not in the tree, so they error "
        f"instead of checking: {missing}"
    )


def test_a_local_hook_points_at_a_runnable_script():
    """A `language: script` hook runs its entry directly. A path that is
    missing, or present but not executable, fails the same way a missing
    baseline did."""
    problems = []
    for repo, hook in hooks():
        if repo != "local" or hook.get("language") != "script":
            continue
        entry = ROOT / hook["entry"].split()[0]
        if not entry.exists():
            problems.append(f"{hook['id']}: {entry} does not exist")
        elif not os.access(entry, os.X_OK):
            problems.append(f"{hook['id']}: {entry} is not executable")
    assert not problems, problems


def _skip_when_leak_check_is_not_shipped() -> None:
    """leak-check.sh is a migration tool the OSS sync does not ship, and the
    sync cuts its hook out of .pre-commit-config.yaml. Missing is not failed."""
    if not (ROOT / "scripts" / "leak-check.sh").exists():
        pytest.skip("scripts/leak-check.sh is not present in this tree (not shipped)")


def test_the_leak_gate_is_the_same_script_locally_and_in_ci():
    """Two gates that drift apart are worse than one, because the local one
    teaches the wrong rule. Both must invoke the same script."""
    _skip_when_leak_check_is_not_shipped()
    ids = {hook["id"] for _, hook in hooks()}
    assert "leak-check" in ids, (
        "the local leak gate is gone from pre-commit; a commit is then judged "
        "by a rule the author never sees until CI"
    )

    entry = next(h["entry"] for _, h in hooks() if h["id"] == "leak-check")
    script = entry.split()[0]
    assert script == "scripts/leak-check.sh", entry
    assert script in CI.read_text(), (
        f"CI no longer runs {script}, so the local hook enforces a rule the "
        "pipeline does not"
    )


def test_the_leak_gate_takes_no_filenames_and_always_runs():
    """`leak-check.sh` scans a TREE, not a file list. Left with pre-commit's
    default `pass_filenames: true` it would be handed the staged paths as
    `$1` — which the script reads as "the tree to scan", so staging a single
    file would scan that file as if it were the repo root and pass. A gate
    that passes for the wrong reason is the failure this whole file is
    about."""
    _skip_when_leak_check_is_not_shipped()
    hook = next(h for _, h in hooks() if h["id"] == "leak-check")
    assert hook.get("pass_filenames") is False, (
        "leak-check.sh takes a tree as $1; passing staged filenames makes it "
        "scan one file and report the repo clean"
    )
    assert hook.get("always_run") is True, (
        "without always_run the gate is skipped on any commit that touches no "
        "file pre-commit matched — i.e. it runs least when the diff is unusual"
    )


def test_detect_secrets_is_not_reintroduced_without_a_baseline():
    """If someone brings the hook back, the baseline has to come with it."""
    for repo, hook in hooks():
        if "detect-secrets" not in hook["id"]:
            continue
        args = hook.get("args") or []
        assert "--baseline" in args, f"{hook['id']} has no baseline"
        value = args[args.index("--baseline") + 1]
        assert (ROOT / value).exists(), (
            f"{hook['id']} names {value}, which is not in the tree — the hook "
            "will error rather than scan"
        )
