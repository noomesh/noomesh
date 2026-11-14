# SPDX-License-Identifier: AGPL-3.0-only
# Copyright 2026 PersonifAI LLC
"""scripts/install-cell/onboard_pty.py drives `noo onboard` like a stranger
(i677). Its decisions are pure functions; the end-to-end tests run the real
driver against a fake wizard that has the shapes the read of steps.rs found:
a password with no default, a revealed secret, the default-No passphrase
loop, the Tailscale questions."""
import importlib.util
import os
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
DRIVER = ROOT / "scripts" / "install-cell" / "onboard_pty.py"
spec = importlib.util.spec_from_file_location("onboard_pty", DRIVER)
op = importlib.util.module_from_spec(spec)
spec.loader.exec_module(op)

SECRET = "zQ8vT2mWfX9kLp3RtY6uN1aB"


def test_prompt_shapes():
    for p in ["Install it now? [Y/n] ", "Admin password: ", "Node ID (unique name) [host1]: ",
              "Continue anyway (you can re-read them later) (y/N) ", "Select backend [1]"]:
        assert op.looks_like_prompt(p), p
    for p in ["Pulling gemma4:e2b via Ollama (this may take several minutes)...", "", "   "]:
        assert not op.looks_like_prompt(p), p


def test_answers_per_pass():
    pw = "Aa9-xxxxxxxxxxxxxxxxxxxx"
    for prompt in ["Admin password: ", "Confirm password: ", "Stored both in a password manager OFF this machine [y/N] ",
                   "Tailscale is not installed. Install it now? [Y/n] ", "Node ID [x]: "]:
        assert op.answer(prompt, "literal", pw) == ("", "enter"), "literal is Enter, always"
    assert op.answer("Admin password: ", "attentive", pw) == (pw, "typed <password>")
    assert op.answer("Stored both in a password manager OFF this machine [y/N] ", "attentive", pw) == ("y", "typed y")
    assert op.answer("Tailscale is not installed. Install it now? [Y/n] ", "attentive", pw) == ("n", "typed n")
    assert op.answer("Join your tailnet now? (runs `sudo tailscale up`) [Y/n] ", "attentive", pw) == ("n", "typed n")
    assert op.answer("Continue as a LAN-only install? [Y/n] ", "attentive", pw) == ("", "enter")
    assert op.answer("Node ID [x]: ", "attentive", pw) == ("", "enter")


def test_the_masker_hides_the_typed_password_and_a_revealed_value():
    m = op.Masker("Aa9-secretsecretsecret00")
    assert m.line("echo Aa9-secretsecretsecret00 back") == "echo [REDACTED] back"
    assert m.line("  NOO_AGE_BACKUP_PASSPHRASE") == "  NOO_AGE_BACKUP_PASSPHRASE"
    assert m.line("") == ""
    assert m.line(f"    {SECRET}") == op.MASK, "the value line after a lone secret name"
    assert m.line("next ordinary line") == "next ordinary line"


FAKE = r"""#!/usr/bin/env bash
read -r -p "Node ID (unique name) [box]: " a
pw=""
while [ -z "$pw" ]; do
  read -r -s -p "Admin password: " pw; echo
  [ -n "$pw" ] || echo "A password is required."
done
echo; echo "  NOO_AGE_BACKUP_PASSPHRASE"; echo "    SECRETVALUE"; echo
while true; do
  read -r -p "Stored both in a password manager OFF this machine [y/N] " s
  [ "$s" = y ] && break
  echo "Without them, an encrypted backup is an opaque blob."
  read -r -p "Continue anyway (you can re-read them later) [y/N] " c
  [ "$c" = y ] && break
done
read -r -p "Tailscale is not installed. Install it now? [Y/n] " t
[ "$t" = n ] || { echo "would open a login link"; sleep 30; }
read -r -p "Continue as a LAN-only install? [Y/n] " l
echo "You're all set. Welcome to Noomesh!"
""".replace("SECRETVALUE", SECRET)


def _drive(tmp_path, mode):
    fake = tmp_path / "fake-onboard"
    fake.write_text(FAKE)
    fake.chmod(0o755)
    return subprocess.run(
        [sys.executable, str(DRIVER), "--pass", mode, "--silence", "8", "--max-repeat", "3", "--", str(fake)],
        capture_output=True, text=True, timeout=120, env={**os.environ, "TERM": "dumb"},
    )


def test_literal_enter_never_finishes_and_is_stopped_as_a_loop(tmp_path):
    """Enter at a prompt with no default (the admin password) is re-asked
    forever, exactly as the wizard re-asks: the literal pass is stopped as a
    LOOP (exit 2), it never hangs and never reaches the end."""
    r = _drive(tmp_path, "literal")
    out = r.stdout
    assert r.returncode == 2, out[-800:]
    assert "DRIVER: LOOP: the same prompt answered 4 times in a row with 'enter'" in out
    assert "PROMPT: Admin password:" in out
    assert "Welcome to Noomesh" not in out
    assert SECRET not in out


def test_attentive_finishes_types_only_what_is_forced_and_leaks_nothing(tmp_path):
    r = _drive(tmp_path, "attentive")
    out = r.stdout
    assert r.returncode == 0, out[-1200:]
    assert "Welcome to Noomesh" in out
    assert SECRET not in out and "Aa9-" not in out, "neither the revealed value nor the typed password is printed"
    answers = [line.split("ANSWER: ", 1)[1] for line in out.splitlines() if line.startswith("ANSWER: ")]
    assert answers == ["enter", "typed <password>", "typed y", "typed n", "enter"], answers
    assert out.count("PROMPT: ") == 5
