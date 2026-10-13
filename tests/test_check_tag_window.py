# SPDX-License-Identifier: AGPL-3.0-only
# Copyright 2026 PersonifAI LLC

"""scripts/check-tag-window.py: stack code merged between the stack tag and
the CLI tag ships in neither artifact. Throwaway git repo,
no network."""
import importlib.util
import pathlib
import subprocess

import pytest

SCRIPT = pathlib.Path(__file__).resolve().parent.parent / "scripts" / "check-tag-window.py"
spec = importlib.util.spec_from_file_location("check_tag_window", SCRIPT)
ctw = importlib.util.module_from_spec(spec)
spec.loader.exec_module(ctw)


def git(repo, *args):
    subprocess.run(["git", "-C", str(repo), "-c", "user.name=t", "-c", "user.email=t@t",
                    *args], check=True, capture_output=True)


def commit(repo, path, msg):
    f = repo / path
    f.parent.mkdir(parents=True, exist_ok=True)
    f.write_text(msg)
    git(repo, "add", "-A")
    git(repo, "commit", "-m", msg)
    return subprocess.run(["git", "-C", str(repo), "rev-parse", "HEAD"], check=True,
                          capture_output=True, text=True).stdout.strip()


@pytest.fixture
def repo(tmp_path):
    git(tmp_path, "init", "-q")
    commit(tmp_path, "gateway-rust/a.rs", "base")
    git(tmp_path, "tag", "stack-v0.2.9")
    git(tmp_path, "tag", "stack-v0.2.10")  # numeric order: 10 > 9
    return tmp_path


def run(repo, *args):
    return ctw.main(["--repo", str(repo), *args])


def test_cli_only_window_is_clean(repo, capsys):
    commit(repo, "noo-cli/src/x.rs", "cli change")
    commit(repo, "docker-compose.dist.yml", "compose rides the CLI")
    assert run(repo) == 0


def test_stack_code_in_window_fails_and_names_commit(repo, capsys):
    commit(repo, "noo-cli/src/x.rs", "cli change")
    sha = commit(repo, "ui/apps/web/src/kiosk/q.ts", "kiosk backoff")
    assert run(repo) == 1
    err = capsys.readouterr().err
    assert sha[:10] in err and "kiosk backoff" in err and "ui/apps/web" in err
    assert "cli change" not in err


def test_defaults_to_numerically_newest_stack_tag(repo):
    # stack-v0.2.9 sorts after stack-v0.2.10 lexically; the window must start
    # at 0.2.10, so a commit before it is not reported.
    assert ctw.newest_stack_tag(str(repo)) == "stack-v0.2.10"


def test_a_release_candidate_tag_is_never_the_pairing(repo):
    # Promotion model: `stack-vX.Y.Z-rc.N` is cut on staging and its numeric
    # key ([0, 2, 11, 1]) outranks every final tag; the window must still
    # start at the newest FINAL tag.
    commit(repo, "gateway-rust/b.rs", "rc candidate")
    git(repo, "tag", "stack-v0.2.11-rc.1")
    assert ctw.newest_stack_tag(str(repo)) == "stack-v0.2.10"


def test_a_candidate_cli_measures_against_its_candidate_stack(repo, capsys):
    # A CLI candidate (noo-cli-vA.B.C-rc.N) is tagged on the same staging
    # commit as its stack candidate; the release workflow passes that rc tag
    # explicitly, so the window is empty even though stack code landed after
    # the last FINAL tag.
    commit(repo, "gateway-rust/b.rs", "promoted gateway change")
    git(repo, "tag", "stack-v0.2.11-rc.1")
    assert run(repo, "--stack-tag", "stack-v0.2.11-rc.1") == 0
    # Measured from the newest final instead, the same commit is in neither.
    assert run(repo) == 1
    assert "promoted gateway change" in capsys.readouterr().err


def test_ack_clears_and_stale_ack_errors(repo, capsys):
    sha = commit(repo, "gateway-rust/b.rs", "gw change")
    assert run(repo, "--ack", sha[:8]) == 0
    assert run(repo, "--ack", "deadbeef") == 2
    # The release workflow passes acks from a repo variable, never --ack by
    # hand, so a stale ack must name the variable or a forgotten one silently
    # blocks the next CLI release with advice the operator cannot act on.
    assert "TAG_WINDOW_ACK" in capsys.readouterr().err


def test_reverse_direction_loses_nothing(repo):
    commit(repo, "ui/z.ts", "after stack tag")
    git(repo, "tag", "noo-cli-v1")
    # stack tag cut AFTER the cli ref: nothing in stack..cli.
    git(repo, "tag", "stack-v0.2.11")
    assert run(repo, "--cli-ref", "noo-cli-v1") == 0


def test_cannot_answer_is_not_clean(repo):
    assert run(repo, "--cli-ref", "no-such-ref") == 2
    assert run(repo, "--stack-tag", "stack-v9.9.9") == 2


def test_no_stack_tag_means_nothing_to_compare(tmp_path):
    git(tmp_path, "init", "-q")
    commit(tmp_path, "ui/a.ts", "x")
    assert run(tmp_path) == 0
