#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-only
# Copyright 2026 PersonifAI LLC
"""The install matrix's REBOOT cell judge (scripts/install-cell/reboot.sh).

After a reboot the stack comes back with NO command (noo-hostd's BootRestore,
node-agent-go/internal/hostd/boot.go); `noo stack start` is only the remedy
when it did not. reboot.sh polls with read-only commands only and records one
row per assert; this file reads what the polls fetched and writes the verdict.

  reboot_judge.py verify FILE [--onboard-log PATH]...
      the verify JSON in FILE, judged by ratchet.py's FAIL-row rule (the same
      fail_allowed list and the same default_chat registry-outage exemption the
      fresh cells use). Prints VERIFY OK / VERIFY FAIL: ... / VERIFY NOT READ.
      exit 0 only on OK.
  reboot_judge.py agent FILE GUEST_T0 [--journal FILE]
      the node agent re-registered after the reboot. Source 1: `noo --json
      cluster show <node>`'s last_heartbeat is later than GUEST_T0 (the guest's
      epoch seconds just before the reboot command). Source 2, only when that
      field is absent or unreadable: the agent's "registered with controller"
      line in `journalctl -u noo-node-agent -b`. Prints which source decided.
  reboot_judge.py units FILE        the units' states (units.txt)
  reboot_judge.py bootrestore FILE  noo-hostd's boot journal
  reboot_judge.py chat FILE         the chat answer is an answer
  reboot_judge.py judge ROWS OUTDIR
      ROWS is reboot.sh's tab-separated rows (id status seconds detail).
      Writes OUTDIR/reboot.txt (`REBOOT <id> PASS|FAIL|SKIP <seconds> <detail>`,
      one per row), OUTDIR/reboot.md (the summary), prints both. exit 1 when
      any judged row is FAIL (the extra `remedy-stack-start` row is evidence
      and never fails the cell). A SKIP is never a FAIL and never a PASS.
"""
from __future__ import annotations

import json
import re
import sys
from datetime import datetime, timezone
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
import ratchet  # noqa: E402  (the verify FAIL-row rule is shared, not copied)

STATUSES = ("PASS", "FAIL", "SKIP", "INFO")
DIAGNOSTIC_PREFIX = "nolinger-"   # the second pass: what a stranger without linger gets; its FAILs are evidence
UNITS_MUST_BE_ACTIVE = ("noo-hostd", "noo-node-agent")


def read(path: str) -> str:
    try:
        return Path(path).read_text(errors="replace")
    except OSError:
        return ""


# ── verify ──────────────────────────────────────────────────────────────────

def judge_verify(text: str, onboard: str = "", ceiling: dict | None = None,
                 names: dict[str, str] | None = None) -> tuple[bool, str]:
    v = ratchet.verify_json(text)
    if v is None:
        return False, "VERIFY NOT READ: no verify JSON in the output"
    ceiling = ratchet.load_ceiling(ratchet.CEILING) if ceiling is None else ceiling
    names = ratchet.registry() if names is None else names
    notes, fails = ratchet.verify_fail_lines(v, ceiling, names, onboard)
    if fails:
        return False, " ".join(fails)
    rows = sum(len(((n or {}).get("checks") or [])) for n in (v.get("nodes") or []))
    rows += len((v.get("controller") or {}).get("checks") or [])
    return True, "VERIFY OK: no FAIL rows" + (f" ({rows} node and controller rows)" if rows else "") \
        + ("; " + "; ".join(notes) if notes else "")


# ── the agent ───────────────────────────────────────────────────────────────

def find_key(obj, key: str):
    """The first value stored under `key`, at any depth (cluster show prints
    the node object bare or inside a wrapper)."""
    if isinstance(obj, dict):
        if key in obj:
            return obj[key]
        for v in obj.values():
            r = find_key(v, key)
            if r is not None:
                return r
    elif isinstance(obj, list):
        for v in obj:
            r = find_key(v, key)
            if r is not None:
                return r
    return None


def to_epoch(value) -> float | None:
    """Epoch seconds from an epoch number (seconds or milliseconds) or an
    ISO-8601 / RFC 3339 string; None when it is neither."""
    if isinstance(value, bool) or value is None:
        return None
    if isinstance(value, (int, float)):
        v = float(value)
        return v / 1000 if v > 1e11 else v
    s = str(value).strip()
    if not s:
        return None
    if re.fullmatch(r"\d+(\.\d+)?", s):
        return to_epoch(float(s))
    s = re.sub(r"Z$", "+00:00", s)
    s = re.sub(r"(\.\d{6})\d+", r"\1", s)        # nanoseconds: fromisoformat takes six digits
    try:
        d = datetime.fromisoformat(s)
    except ValueError:
        return None
    if d.tzinfo is None:
        d = d.replace(tzinfo=timezone.utc)
    return d.timestamp()


def json_object(text: str):
    dec = json.JSONDecoder()
    for i, ch in enumerate(text):
        if ch == "{" and (i == 0 or text[i - 1] == "\n"):
            try:
                return dec.raw_decode(text, i)[0]
            except ValueError:
                continue
    return None


def judge_agent(show_text: str, guest_t0: float, journal: str = "") -> tuple[bool, str]:
    obj = json_object(show_text)
    beat = find_key(obj, "last_heartbeat") if obj is not None else None
    epoch = to_epoch(beat)
    if epoch is not None:
        status = find_key(obj, "status")
        late = epoch - guest_t0
        if late > 0:
            return True, (f"source=cluster-show.last_heartbeat: {beat} is {late:.0f}s after the reboot command"
                          f" (node status {status})")
        return False, (f"source=cluster-show.last_heartbeat: {beat} is not after the reboot command"
                       f" ({-late:.0f}s before it; node status {status})")
    line = next((l.strip() for l in journal.splitlines() if "registered with controller" in l), "")
    if line:
        return True, ("source=journal (cluster show printed no readable last_heartbeat: "
                      f"{beat!r}): {line[:160]}")
    return False, (f"no evidence: cluster show has no readable last_heartbeat ({beat!r}) "
                   "and the journal has no \"registered with controller\" line this boot")


# ── units, boot-restore, chat ───────────────────────────────────────────────

def parse_units(text: str) -> dict[str, dict[str, str]]:
    """`<unit> system=<state> user=<state>` per line."""
    out = {}
    for line in text.splitlines():
        m = re.match(r"^(\S+)\s+system=(\S*)\s+user=(\S*)", line)
        if m:
            out[m.group(1)] = {"system": m.group(2), "user": m.group(3)}
    return out


def judge_units(text: str) -> tuple[bool, str]:
    units = parse_units(text)
    if not units:
        return False, "no unit states were read"
    parts = [f"{u}={s['system']}" for u, s in units.items()]
    # noo-hostd is a systemd USER unit in controller mode (onboard): active in either manager counts.
    bad = [u for u in UNITS_MUST_BE_ACTIVE
           if "active" not in (units.get(u, {}).get("system"), units.get(u, {}).get("user"))]
    parts = [f"{u}=system:{s['system']}/user:{s['user']}" for u, s in units.items()]
    detail = " ".join(parts)
    if bad:
        return False, f"not active (system or user manager): {', '.join(bad)} ({detail})"
    return True, detail


def judge_bootrestore(text: str) -> tuple[str, str]:
    """(status, detail) for noo-hostd's journal of this boot. BootRestore logs
    `boot-restore: done` (plus the script's own line), or `BOOT-RESTORE WARN`
    (a core service still down), `BOOT-RESTORE attempt N failed` and `BOOT-RESTORE
    gave up`. No such line is a SKIP: the stack rows decide, not a missing log."""
    lines = [l.strip() for l in text.splitlines() if re.search(r"boot-restore", l, re.I)]
    if not lines:
        return "SKIP", "no boot-restore line in noo-hostd's journal this boot"
    bad = [l for l in lines if re.search(r"BOOT-RESTORE (WARN|gave up)", l)]
    if bad:
        return "FAIL", bad[-1][:300]
    done = [l for l in lines if re.search(r"boot-restore: (done|started|populated)", l, re.I)]
    last = (done or lines)[-1]
    retried = [l for l in lines if re.search(r"BOOT-RESTORE attempt \d+ failed", l)]
    return "PASS", last[:200] + (f" ({len(retried)} retried attempt(s) first)" if retried else "")


def judge_linger(kind: str, linger: str, user: str) -> tuple[str, str]:
    """linger-at-install: (PASS|FAIL|INFO, detail). A system unit starts at boot
    whatever Linger says (INFO); a user unit starts at boot only with Linger=yes."""
    kind, linger = kind.strip(), linger.strip()
    if kind == "system":
        return "INFO", f"noo-hostd is a system unit: linger does not matter (Linger={linger or '?'})"
    if kind != "user":
        return "FAIL", "noo-hostd is neither an enabled user unit nor an enabled system unit: nothing restores the stack at boot"
    if linger == "yes":
        return "PASS", "noo-hostd is a systemd user unit and Linger=yes: it starts at boot without a login"
    return "FAIL", (f"noo-hostd is a systemd user unit and Linger={linger or '?'}: without linger the user manager, "
                    f"and hostd, start only at a login, so nothing restores the stack after a reboot; "
                    f"remedy: sudo loginctl enable-linger {user}")


def judge_chat(text: str) -> tuple[bool, str]:
    answer = " ".join(text.split())
    if not answer:
        return False, "the chat printed nothing"
    return True, f"answered: {answer[:80]}"


# ── the verdict ─────────────────────────────────────────────────────────────

def read_rows(text: str) -> list[tuple[str, str, str, str]]:
    rows = []
    for line in text.splitlines():
        if not line.strip():
            continue
        parts = line.split("\t", 3)
        parts += [""] * (4 - len(parts))
        rid, status, secs, detail = parts
        if status not in STATUSES:
            raise ValueError(f"row {rid!r}: status {status!r} is not PASS, FAIL or SKIP")
        rows.append((rid, status, secs, " ".join(detail.split())))
    return rows


def render(rows: list[tuple[str, str, str, str]]) -> tuple[str, str]:
    txt = "".join(f"REBOOT {rid} {status} {secs or '-'} {detail}\n" for rid, status, secs, detail in rows)
    fails = [r for r in rows if r[1] == "FAIL" and not r[0].startswith(DIAGNOSTIC_PREFIX)]
    diag = [r for r in rows if r[1] == "FAIL" and r[0].startswith(DIAGNOSTIC_PREFIX)]
    skips = [r for r in rows if r[1] == "SKIP"]
    head = ("FAIL: " + ", ".join(r[0] for r in fails)) if fails else \
        ("PASS" if any(r[1] == "PASS" for r in rows) and not skips else
         "NOT FULLY JUDGED (SKIP rows)" if any(r[1] == "PASS" for r in rows) else "SKIP")
    md = [f"### reboot cell: {head}", "",
          "The stack must come back after a reboot with NO command (noo-hostd's BootRestore); "
          "`noo stack start` is only the remedy. Seconds are on the host clock since the guest stopped answering ssh.",
          "", "| assert | result | seconds | detail |", "|---|---|---|---|"]
    if any(r[0].startswith(DIAGNOSTIC_PREFIX) for r in rows):
        md[3:3] = ["", f"The `{DIAGNOSTIC_PREFIX}*` rows are a DIAGNOSTIC second pass (Linger switched off, then rebooted again): "
                   "what a stranger who skipped `loginctl enable-linger` gets"
                   + (f"; {len(diag)} of them FAIL, which is the finding, not a cell failure" if diag else "") + "."]
    md += [f"| {rid} | {status} | {secs or '-'} | {detail.replace('|', '/')} |" for rid, status, secs, detail in rows]
    return txt, "\n".join(md) + "\n"


def cmd_judge(args: list[str]) -> int:
    rows = read_rows(read(args[0]))
    out = Path(args[1])
    out.mkdir(parents=True, exist_ok=True)
    txt, md = render(rows)
    (out / "reboot.txt").write_text(txt)
    (out / "reboot.md").write_text(md)
    sys.stdout.write(txt)
    # The remedy line and the nolinger- pass are evidence, not verdicts.
    return 1 if any(r[1] == "FAIL" and r[0] != "remedy-stack-start" and not r[0].startswith(DIAGNOSTIC_PREFIX)
                    for r in rows) else 0


def main(argv: list[str]) -> int:
    if not argv:
        print(__doc__, file=sys.stderr)
        return 2
    cmd, a = argv[0], argv[1:]
    if cmd == "verify" and a:
        onboard = "".join(read(a[i + 1]) + "\n" for i, x in enumerate(a[:-1]) if x == "--onboard-log")
        ok, msg = judge_verify(read(a[0]), onboard)
        print(msg)
        return 0 if ok else 1
    if cmd == "agent" and len(a) >= 2:
        journal = read(a[a.index("--journal") + 1]) if "--journal" in a else ""
        ok, msg = judge_agent(read(a[0]), float(a[1]), journal)
        print(("AGENT OK: " if ok else "AGENT FAIL: ") + msg)
        return 0 if ok else 1
    if cmd == "units" and a:
        ok, msg = judge_units(read(a[0]))
        print(msg)
        return 0 if ok else 1
    if cmd == "bootrestore" and a:
        status, msg = judge_bootrestore(read(a[0]))
        print(f"{status}\t{msg}")
        return 0
    if cmd == "linger" and len(a) >= 3:
        status, msg = judge_linger(a[0], a[1], a[2])
        print(f"{status}\t{msg}")
        return 0
    if cmd == "chat" and a:
        ok, msg = judge_chat(read(a[0]))
        print(msg)
        return 0 if ok else 1
    if cmd == "judge" and len(a) >= 2:
        return cmd_judge(a)
    print(__doc__, file=sys.stderr)
    return 2


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
