#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-only
# Copyright 2026 PersonifAI LLC
"""Drive `noo onboard` through a pty the way a stranger would (i677).

    onboard_pty.py --pass literal|attentive [--silence S] [--max-prompts N] -- noo onboard

Two passes, because a read of the wizard shows Enter alone cannot finish it:

* literal:   Enter at every prompt, nothing else. Where it stops, and after
             how long, is the result.
* attentive: Enter wherever a default moves forward. Type only what a prompt
             forces (an admin password; "y" once the backup passphrases are
             "stored"; "n" to installing or joining Tailscale, which leads to
             the LAN-only install). Every typed answer is printed as a finding.

Prints the redacted transcript, plus one `PROMPT: <text>` and one
`ANSWER: <enter | typed y | typed n | typed <password>>` line per prompt
answered. lib.sh's redactor runs after this, but secrets are masked here
FIRST: the password this driver types, and any value printed on the line after
a lone secret name (the console reveals backup passphrases that way:
prompt.rs reveal_secret prints the name, then the value on its own line,
which no key=value pattern can see).

Exit codes: onboard's own on a normal exit. 2: the same prompt was answered
too many times in a row (a loop). 3: more than --max-prompts answers.
124: no output for --silence seconds (stuck, e.g. a login link waiting).
"""
from __future__ import annotations

import argparse
import os
import pty
import re
import secrets
import select
import signal
import string
import sys
import time

ANSI = re.compile(r"\x1b\[[0-9;?]*[ -/]*[@-~]|\x1b[()][A-Za-z0-9]|\r")
# Prompt-shaped endings: "[Y/n] ", "[y/N] ", "(y/N) ", "[default]: ", "? ", ": ".
PROMPT_END = re.compile(r"(\[[YyNn]/[YyNn]\]|\([YyNn]/[YyNn]\)|\[[^\]\n]{0,80}\]:?|\?|:)\s*$")
SECRET_NAME = re.compile(r"^\s*[A-Z][A-Z0-9_]*(PASSPHRASE|PASSWORD|TOKEN|SECRET|KEY)[A-Z0-9_]*\s*$")
MASK = "[REDACTED]"


def clean(text: str) -> str:
    return ANSI.sub("", text)


def looks_like_prompt(tail: str) -> bool:
    """The last unfinished line of output, once the program went quiet."""
    line = clean(tail).rsplit("\n", 1)[-1]
    return bool(line.strip()) and len(line) < 400 and bool(PROMPT_END.search(line))


def is_password_prompt(p: str) -> bool:
    return bool(re.search(r"(?i)\b(admin )?password\b", p)) and not re.search(r"(?i)password manager", p)


def answer(prompt: str, mode: str, password: str) -> tuple[str, str]:
    """(bytes to type, how to report it). Enter is "".

    attentive answers only what a prompt FORCES or what the stranger would
    decline on a single machine; everything else is the default (Enter)."""
    p = prompt.lower()
    if mode == "attentive":
        if is_password_prompt(prompt):
            return password, "typed <password>"
        if "stored both in a password manager" in p:
            return "y", "typed y"
        if "tailscale is not installed" in p or "join your tailnet now" in p:
            return "n", "typed n"
    return "", "enter"


class Masker:
    """Masks what must never reach a public log: the typed password, and the
    value line that follows a lone SECRET_NAME line."""

    def __init__(self, password: str):
        self.password = password
        self.after_name = False

    def line(self, raw: str) -> str:
        text = clean(raw)
        if self.password and self.password in text:
            text = text.replace(self.password, MASK)
        if self.after_name and text.strip():
            self.after_name = False
            return MASK
        if SECRET_NAME.match(text):
            self.after_name = True
        return text


def gen_password() -> str:
    # Mixed classes, 24 chars: passes any reasonable strength rule.
    alphabet = string.ascii_letters + string.digits
    core = "".join(secrets.choice(alphabet) for _ in range(20))
    return "Aa9-" + core


def drive(argv: list[str], mode: str, silence: float, max_prompts: int, max_repeat: int) -> int:
    password = gen_password()
    masker = Masker(password)
    pid, fd = pty.fork()
    if pid == 0:
        os.execvp(argv[0], argv)
    buf = ""            # current unfinished line (raw)
    answered = 0
    last_prompt, repeat = None, 0
    last_out = time.monotonic()
    out = sys.stdout

    def emit(s: str) -> None:
        out.write(s + "\n")
        out.flush()

    def stop(code: int, why: str) -> int:
        emit(f"DRIVER: {why}")
        try:
            os.kill(pid, signal.SIGTERM)
            time.sleep(2)
            os.kill(pid, signal.SIGKILL)
        except ProcessLookupError:
            pass
        return code

    while True:
        r, _, _ = select.select([fd], [], [], 1.0)
        if r:
            try:
                data = os.read(fd, 4096)
            except OSError:
                data = b""
            if not data:
                break
            last_out = time.monotonic()
            buf += data.decode("utf-8", "replace")
            while "\n" in buf:
                line, buf = buf.split("\n", 1)
                emit(masker.line(line))
            continue
        quiet = time.monotonic() - last_out
        if buf and quiet >= 1.5 and looks_like_prompt(buf):
            prompt = clean(buf).strip()
            emit(masker.line(buf))
            buf = ""
            text, how = answer(prompt, mode, password)
            emit(f"PROMPT: {masker.line(prompt)}")
            emit(f"ANSWER: {how}")
            answered += 1
            repeat = repeat + 1 if prompt == last_prompt else 1
            last_prompt = prompt
            if repeat > max_repeat:
                return stop(2, f"LOOP: the same prompt answered {repeat} times in a row with '{how}'")
            if answered > max_prompts:
                return stop(3, f"more than {max_prompts} prompts answered")
            os.write(fd, (text + "\r").encode())
            last_out = time.monotonic()
            continue
        if quiet >= silence:
            tail = masker.line(buf) if buf else "(nothing pending)"
            return stop(124, f"STUCK: no output for {int(quiet)}s; last: {tail[-200:]}")
    if buf:
        emit(masker.line(buf))
    _, status = os.waitpid(pid, 0)
    rc = os.waitstatus_to_exitcode(status)
    emit(f"DRIVER: onboard exited {rc} after {answered} prompt(s)")
    return rc


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--pass", dest="mode", choices=["literal", "attentive"], required=True)
    ap.add_argument("--silence", type=float, default=900.0)
    ap.add_argument("--max-prompts", type=int, default=60)
    ap.add_argument("--max-repeat", type=int, default=5)
    ap.add_argument("argv", nargs=argparse.REMAINDER)
    a = ap.parse_args()
    argv = a.argv[1:] if a.argv[:1] == ["--"] else a.argv
    if not argv:
        ap.error("no command")
    return drive(argv, a.mode, a.silence, a.max_prompts, a.max_repeat)


if __name__ == "__main__":
    sys.exit(main())
