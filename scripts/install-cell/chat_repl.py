#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-only
# Copyright 2026 PersonifAI LLC
"""Drive the interactive `noo chat` REPL through a pty, as first-chat.md's
first command asks a stranger to (2026-11-18 launch audit: the matrix ran
only `noo chat --message`). One prompt in, an answer out, `/exit`, a clean
exit. Prints one line: `CHAT-REPL PASS: …` or `CHAT-REPL FAIL: …`; exit 0
on PASS, 1 on FAIL.

    chat_repl.py [--prompt TEXT] [--timeout SECS] [-- noo chat]
"""
import argparse
import os
import pty
import re
import select
import sys
import time

ANSI = re.compile(r"\x1b\[[0-9;?]*[A-Za-z]")


def read_until(fd, marker, deadline, buf, count=1):
    """Read until `marker` appears `count` times in the de-coloured text."""
    while ANSI.sub("", buf).count(marker) < count:
        left = deadline - time.time()
        if left <= 0:
            return buf, False
        r, _, _ = select.select([fd], [], [], min(left, 1.0))
        if fd in r:
            try:
                chunk = os.read(fd, 4096).decode(errors="replace")
            except OSError:
                return buf, False
            if not chunk:
                return buf, False
            buf += chunk
    return buf, True


def main(argv):
    ap = argparse.ArgumentParser()
    ap.add_argument("--prompt", default="Say hello in five words.")
    ap.add_argument("--timeout", type=int, default=900)
    ap.add_argument("cmd", nargs="*", default=["noo", "chat"])
    a = ap.parse_args(argv)
    cmd = [c for c in a.cmd if c != "--"] or ["noo", "chat"]
    pid, fd = pty.fork()
    if pid == 0:
        os.execvp(cmd[0], cmd)
    start = time.time()
    buf, ok = read_until(fd, "you> ", start + 120, "")
    if not ok:
        print(f"CHAT-REPL FAIL: no `you> ` prompt within 120 s; got: {ANSI.sub('', buf)[-300:]!r}")
        return 1
    os.write(fd, (a.prompt + "\n").encode())
    seen = len(ANSI.sub("", buf))
    buf, ok = read_until(fd, "noo> ", time.time() + 60, buf)
    if not ok:
        print(f"CHAT-REPL FAIL: the prompt was not taken (no `noo> `); got: {ANSI.sub('', buf)[seen:][-300:]!r}")
        return 1
    clean = ANSI.sub("", buf)
    after = clean.index("noo> ", seen) + len("noo> ")
    # the answer runs until the next `you> ` prompt (the second one)
    buf, ok = read_until(fd, "you> ", time.time() + a.timeout, buf, count=2)
    clean = ANSI.sub("", buf)
    end = clean.find("you> ", after)
    answer = clean[after:end if end >= 0 else None].strip()
    if end < 0:
        print(f"CHAT-REPL FAIL: no answer ended within {a.timeout} s; got: {answer[-300:]!r}")
        return 1
    if not re.search(r"[A-Za-z0-9]", answer) or re.search(r"(?i)\b(failed|error)\b", answer.splitlines()[0] if answer else ""):
        print(f"CHAT-REPL FAIL: the answer is empty or an error: {answer[:300]!r}")
        return 1
    os.write(fd, b"/exit\n")
    deadline = time.time() + 30
    status = None
    while time.time() < deadline:
        done, status = os.waitpid(pid, os.WNOHANG)
        if done:
            break
        try:
            select.select([fd], [], [], 0.5) and os.read(fd, 4096)
        except OSError:
            pass
    if status is None or not os.WIFEXITED(status) or os.WEXITSTATUS(status) != 0:
        print(f"CHAT-REPL FAIL: `/exit` did not end the REPL cleanly (status {status})")
        return 1
    secs = int(time.time() - start)
    print(f"CHAT-REPL PASS: one prompt, an answer ({len(answer)} chars), a clean /exit in {secs} s: {answer[:120]!r}")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
