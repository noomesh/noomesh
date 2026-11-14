#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-only
# Copyright 2026 PersonifAI LLC

"""Helpers for one install-matrix cell (lib.sh calls these; stdlib only, so
it runs on a bare runner before anything is installed).

    cell.py run TIMEOUT -- CMD...    run CMD in its own process group, kill the
                                     group at TIMEOUT seconds (exit 124);
                                     macOS has no GNU `timeout`
    cell.py redact                   stdin -> stdout with secrets masked
    cell.py scan PATH...             exit 3 if any file still holds a
                                     secret-shaped string (the last gate
                                     before upload: this repo is PUBLIC)
    cell.py record NAME RC SECS LOG  print the step's JSON line
    cell.py summary DIR              steps.jsonl + meta -> summary.md/.json

The logs and the artifact of this workflow are public, and onboard prints an
admin password, join material and tokens. Every line passes `redact` before
it reaches the job log, a step record or the artifact; `scan` then refuses
the upload if anything secret-shaped is left.
"""

from __future__ import annotations

import json
import os
import re
import signal
import subprocess
import sys
from pathlib import Path

MASK = "[REDACTED]"

# Shapes, most specific first. Each is replaced, never the whole line.
SECRET_SHAPES = [
    # PEM blocks are handled line by line below (BEGIN ... END).
    re.compile(r"noo1\.[A-Za-z0-9_\-.=]+"),                                   # join / bootstrap blobs
    re.compile(r"eyJ[A-Za-z0-9_\-]{8,}\.[A-Za-z0-9_\-]{8,}\.[A-Za-z0-9_\-]{8,}"),  # JWT
    re.compile(r"(?i)\b(gh[pousr]_[A-Za-z0-9]{20,})"),                        # GitHub tokens
    re.compile(r"(?i)((?:password|passwd|passphrase|token|secret|api[_-]?key|private[_-]?key|key)"
               r"\s*[:=]\s*)(\"?)([^\s\"']{4,})"),                             # key: value / key=value
]
LONG_B64 = re.compile(r"(?<![A-Za-z0-9+/=_\-])[A-Za-z0-9+/_\-]{40,}={0,2}(?![A-Za-z0-9+/=_\-])")
SHA_LIKE = re.compile(r"^(?:sha256:)?[0-9a-f]{40,64}$")


def looks_random(run: str) -> bool:
    """A long run worth masking: random base64 of 40+ characters mixes upper
    case, lower case and digits; a URL path or a digest does not (run 3,
    2026-11-12: the README's install URL read as a 'long base64 run')."""
    return (not SHA_LIKE.match(run) and bool(re.search(r"[A-Z]", run))
            and bool(re.search(r"[a-z]", run)) and bool(re.search(r"[0-9]", run)))


ANSI = re.compile(r"\x1b\[[0-9;?]*[A-Za-z]")
# A secret revealed on its own line under its name (onboard's reveal_secret,
# prompt.rs: "  NOO_AGE_BACKUP_PASSPHRASE" then the value alone): the name
# line arms a mask for the next non-blank line, whatever that value looks like.
SECRET_NAME = re.compile(r"^[A-Z][A-Z0-9_]*(PASSPHRASE|PASSWORD|TOKEN|SECRET|KEY)[A-Z0-9_]*:?$")


def redact_line(line: str, state: dict) -> str:
    nl = "\n" if line.endswith("\n") else ""
    line = ANSI.sub("", line.rstrip("\n")) + nl
    bare = line.strip()
    if state.get("mask_next") and bare:
        state["mask_next"] = False
        return MASK + nl
    if SECRET_NAME.match(bare):
        state["mask_next"] = True
        return line
    if state.get("pem"):
        if re.search(r"-----END [A-Z ]+-----", line):
            state["pem"] = False
        return MASK + "\n" if line.endswith("\n") else MASK
    if re.search(r"-----BEGIN [A-Z ]+-----", line):
        state["pem"] = not re.search(r"-----END [A-Z ]+-----", line)
        return MASK + "\n" if line.endswith("\n") else MASK
    out = SECRET_SHAPES[0].sub(MASK, line)
    out = SECRET_SHAPES[1].sub(MASK, out)
    out = SECRET_SHAPES[2].sub(MASK, out)
    out = SECRET_SHAPES[3].sub(lambda m: m.group(1) + m.group(2) + MASK, out)
    # Long base64-ish runs; digests (hex, sha256:) stay readable on purpose.
    out = LONG_B64.sub(lambda m: MASK if looks_random(m.group(0)) else m.group(0), out)
    return out


def secret_hits(text: str) -> list[str]:
    hits = []
    lines = text.splitlines()
    for i, line in enumerate(lines, 1):
        if SECRET_NAME.match(ANSI.sub("", line).strip()):
            nxt = next((l.strip() for l in lines[i:] if l.strip()), None)
            if nxt is not None and nxt != MASK:
                hits.append(f"{i + 1}: value under {line.strip()[:40]}")
        probe = line.replace(MASK, "")
        if re.search(r"-----BEGIN [A-Z ]*PRIVATE KEY-----", probe):
            hits.append(f"{i}: PEM private key")
        for rx in SECRET_SHAPES[:3]:
            if rx.search(probe):
                hits.append(f"{i}: {rx.pattern[:24]}")
        m = SECRET_SHAPES[3].search(probe)
        if m and m.group(3) != MASK:
            hits.append(f"{i}: {m.group(1).strip()} value")
        for b in LONG_B64.findall(probe):
            if looks_random(b):
                hits.append(f"{i}: long base64 run")
    return hits


def cmd_run(argv: list[str]) -> int:
    timeout = int(argv[0])
    cmd = argv[2:] if argv[1:2] == ["--"] else argv[1:]
    p = subprocess.Popen(cmd, start_new_session=True)
    try:
        return p.wait(timeout=timeout)
    except subprocess.TimeoutExpired:
        os.killpg(p.pid, signal.SIGTERM)
        try:
            p.wait(timeout=20)
        except subprocess.TimeoutExpired:
            os.killpg(p.pid, signal.SIGKILL)
            p.wait()
        print(f"[install-cell] TIMEOUT after {timeout}s: {' '.join(cmd)[:200]}", flush=True)
        return 124


def cmd_redact() -> int:
    state: dict = {}
    for line in sys.stdin:
        sys.stdout.write(redact_line(line, state))
        sys.stdout.flush()
    return 0


def cmd_scan(paths: list[str]) -> int:
    bad = []
    for root in paths:
        for f in sorted(Path(root).rglob("*")) if Path(root).is_dir() else [Path(root)]:
            if f.is_file():
                for h in secret_hits(f.read_text(errors="replace")):
                    bad.append(f"{f}:{h}")
    if bad:
        print("install-cell: secret-shaped text left in the files to upload; refusing:", file=sys.stderr)
        for b in bad[:40]:
            print("  " + b, file=sys.stderr)
        return 3
    return 0


# A line that SAYS something failed, not one that merely contains the word
# ("13 created, 0 failed" read as the error in run 1, 2026-11-12).
ERROR_RX = re.compile(r"^\s*(x |✗|error\b|ERROR\b|Error:|fatal\b|FATAL\b|panicked)|did NOT complete|"
                      r"^DRIVER: LOOP|\[install-cell\] TIMEOUT after|^curl: \(\d+\)|^Traceback|Error: |\bno matching manifest\b")
NOT_ERROR = re.compile(r"\b0 failed\b|\bno errors?\b")
PROMPT_RX = re.compile(r"^PROMPT: |\[[yY]/[nN]\]|\([yY]/[nN]\)|\?\s*(\[[^\]]*\])?\s*$")
WARN_RX = re.compile(r"^\s*(!|⚠)|\bWARN(ING)?\b|operator alert|TargetDown")


def record(name: str, rc: int, secs: int, log: str) -> dict:
    lines = Path(log).read_text(errors="replace").splitlines() if Path(log).exists() else []
    first_error = ""
    if rc != 0:
        # The DECISIVE line: the last one that says something failed, with the
        # two lines after it (the reason usually follows the verdict).
        hits = [i for i, l in enumerate(lines) if ERROR_RX.search(l) and not NOT_ERROR.search(l)]
        if hits:
            i = hits[-1]
            first_error = " | ".join(l.strip() for l in lines[i:i + 3] if l.strip())
        elif lines:
            first_error = lines[-1]
    return {
        "step": name, "rc": rc, "seconds": secs,
        "first_error": first_error[:500],
        "prompts": [l[:300] for l in lines if PROMPT_RX.search(l)][:80],
        "warnings": [l.strip()[:300] for l in lines if WARN_RX.search(l)][:80],
        "tail": lines[-50:],
    }


def first_answer_times(steps: list[dict], wall) -> tuple:
    """(install-to-first-answer seconds, seconds of probe steps that ran before
    first-answer). `wall` is run.sh's first_answer_s (cell start to the end of
    first-answer); a probe is a step named probe-* or the idle judge."""
    if wall in (None, "", "?"):
        return None, 0
    before = []
    for s in steps:
        if s["step"] == "first-answer":
            break
        before.append(s)
    else:
        return int(wall), 0
    wait = sum(int(s["seconds"]) for s in before
               if s["step"].startswith(("probe-", "idle-")))
    return int(wall) - wait, wait


def summarize(d: Path) -> dict:
    steps = [json.loads(l) for l in (d / "steps.jsonl").read_text().splitlines() if l.strip()] \
        if (d / "steps.jsonl").exists() else []
    meta = json.loads((d / "meta.json").read_text()) if (d / "meta.json").exists() else {}
    failed = next((s for s in steps if s["rc"] != 0 and not s["step"].startswith(("leftover", "probe-", "agent-state-after-"))
                   and s["step"] != "verify"), None)
    probes = [s for s in steps if s["step"].startswith("probe-")]
    verify = next((s for s in steps if s["step"] == "verify"), None)
    warnings = [w for s in steps for w in s["warnings"]]
    prompts = [p for s in steps for p in s["prompts"]]
    # The number a stranger feels is install to first answer. Probes that run
    # BEFORE first-answer on purpose (the memory baseline and the 40-minute
    # idle series must see a stack nobody has chatted to) are waits we add,
    # not the product's time, so they are reported apart (general, rc.1 run
    # 43642041751: 2,792 s on the wall, 327 s without the 2,465 s of probes).
    first_answer, probe_wait = first_answer_times(steps, meta.get("first_answer_s"))
    out = {**meta, "first_answer_s": first_answer, "first_answer_wall_s": meta.get("first_answer_s"),
           "probe_wait_before_first_answer_s": probe_wait,
           "result": ("not run" if meta.get("not_run") or not steps
                      else "pass" if failed is None else "fail"),
           "failed_step": failed["step"] if failed else None,
           "first_error": failed["first_error"] if failed else None,
           "steps": [{k: s[k] for k in ("step", "rc", "seconds")} for s in steps],
           "verify": None if verify is None else ("green" if verify["rc"] == 0 else verify["first_error"]),
           "probes": {s["step"]: ("pass" if s["rc"] == 0 else s["first_error"]) for s in probes},
           "warning_count": len(warnings), "warnings": warnings[:40],
           "prompt_count": len(prompts), "prompts": prompts[:60]}
    md = [f"### {meta.get('cell', '?')}: {out['result'].upper()}"
          + (f" at `{out['failed_step']}`" if failed else ""),
          f"runner `{meta.get('runner', '?')}` · installed `{meta.get('installed_version', '?')}` · "
          f"peak disk used {meta.get('peak_disk_used_gb', '?')} GB · first answer {'?' if first_answer is None else first_answer} s "
          f"after the cell started" + (f" (not counting {probe_wait} s of probes before it; {meta.get('first_answer_s')} s on the wall clock)"
                                         if probe_wait else ""),
          "", "| step | rc | seconds |", "|---|---|---|"]
    md += [f"| {s['step']} | {s['rc']} | {s['seconds']} |" for s in steps]
    if failed:
        md += ["", f"**First error** ({failed['step']}): `{failed['first_error']}`"]
    if verify is not None and verify["rc"] != 0:
        md += ["", f"**cluster verify is RED** (recorded, not fatal): `{verify['first_error']}`"]
    for s in probes:
        md += ["", f"**Probe `{s['step']}`: {'PASS' if s['rc'] == 0 else 'FAIL'}**"
               + ("" if s["rc"] == 0 else f" `{s['first_error']}`")]
    md += ["", f"**Warnings a stranger sees: {len(warnings)}**"] + [f"- `{w}`" for w in warnings[:20]]
    md += ["", f"**Prompts: {len(prompts)}**"] + [f"- `{p}`" for p in prompts[:20]]
    if meta.get("limits"):
        md += ["", "**Not covered here:** " + "; ".join(meta["limits"])]
    (d / "summary.json").write_text(json.dumps(out, indent=1, ensure_ascii=False), encoding="utf-8")
    (d / "summary.md").write_text("\n".join(md) + "\n")
    return out


def main(argv: list[str]) -> int:
    if not argv:
        print(__doc__, file=sys.stderr)
        return 2
    cmd, rest = argv[0], argv[1:]
    if cmd == "run":
        return cmd_run(rest)
    if cmd == "redact":
        return cmd_redact()
    if cmd == "scan":
        return cmd_scan(rest)
    if cmd == "record":
        # ensure_ascii=False: an escaped "\u2014" next to a masked value read
        # as a key's value to the upload scan (rc.3, "age key: [REDACTED] —").
        sys.stdout.reconfigure(encoding="utf-8")
        print(json.dumps(record(rest[0], int(rest[1]), int(rest[2]), rest[3]), ensure_ascii=False))
        return 0
    if cmd == "summary":
        summarize(Path(rest[0]))
        return 0
    print(f"cell.py: unknown command {cmd}", file=sys.stderr)
    return 2


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
