# SPDX-License-Identifier: AGPL-3.0-only
# Copyright 2026 PersonifAI LLC

"""A first-contact fetch of the cluster CA is never unpinned.

The one moment a node cannot verify the controller's TLS is before it holds
the cluster CA. `scripts/prep-host.sh` fetches that anchor with `-k` — and
refuses to do so unless `PREP_CA_SHA256` (the CA's DER-sha256, carried by
the enrollment paste) is set, then checks the downloaded bytes against it.
The pin is what turns blind trust-on-first-use into a verified handoff.

Until 2026-09-29 `noo cluster provision` for the controller's OWN node
called prep-host with `PREP_INSECURE=1` and no pin (so prep refused, or —
on an older prep — fetched blind), and `scripts/bootstrap-enroll.sh`
printed `curl -fsSk …/bootstrap/deenroll` and `curl -fsSL …/prep | sudo
bash` as advice: an operator following it would fetch a root-executed
script with no pin at all.

What this pins:

  1. every `PREP_INSECURE=1` in the scripts and the noo-cli source is in a
     command that also carries `PREP_CA_SHA256=` (or `NOO_CA_SHA256`);
  2. every insecure curl (`-k`, `--insecure`, `-fsSk`, `-sk`, `-sSk`) in
     the scripts — as a command OR as advice printed for an operator — is
     guarded by a fingerprint check in the same command or the enclosing
     shell block (the GUARD_WINDOW lines above it name the pin variable).
     A `-k` aimed at the host's own loopback (`localhost`, `127.0.0.1`) is
     a liveness probe, not a fetch of anything trusted, and is out of
     scope;
  3. the guard catches a plant (each rule, fed a bad snippet, fails).
"""

from __future__ import annotations

import re
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SCRIPTS = sorted((ROOT / "scripts").glob("*.sh"))
RUST = sorted((ROOT / "noo-cli" / "src").rglob("*.rs"))
PIN_VARS = ("PREP_CA_SHA256", "NOO_CA_SHA256")
INSECURE_CURL = re.compile(r"\bcurl\b[^|\n]*?(\s-(?:[a-zA-Z]*k[a-zA-Z]*)\b|--insecure)")
INSECURE_OPTS = re.compile(r'(?:CURL_OPTS|PREP_CURL)="-[a-zA-Z]*k[a-zA-Z]*"')
LOOPBACK = re.compile(r"https?://(localhost|127\.0\.0\.1|\[::1\])[:/]")
# The pin check and the -k it licenses sit in the same shell block; the
# widest such block in the tree (bootstrap-enroll.sh's NOO_BOOTSTRAP_INSECURE
# arm) is 14 lines.
GUARD_WINDOW = 16


def _shell_commands(text: str) -> list[tuple[int, str]]:
    """(first line number, joined command) with `\\` continuations folded."""
    out, buf, start = [], [], 0
    for i, line in enumerate(text.splitlines(), 1):
        if not buf:
            start = i
        stripped = line.rstrip()
        if stripped.endswith("\\"):
            buf.append(stripped[:-1])
            continue
        buf.append(stripped)
        out.append((start, " ".join(buf)))
        buf = []
    if buf:
        out.append((start, " ".join(buf)))
    return out


def _guarded(lines: list[str], idx: int) -> bool:
    """The command itself, or the GUARD_WINDOW lines above it, name a pin
    variable. ADVICE (an echo/printf the operator will paste) gets no window:
    the pasted command carries none of the enclosing block, so the pin —
    or a --cacert — must be on the printed line itself."""
    line = lines[idx]
    if re.match(r"\s*(echo|printf)\b", line):
        return any(v in line for v in PIN_VARS) or "--cacert" in line
    lo = max(0, idx - GUARD_WINDOW)
    window = "\n".join(lines[lo : idx + 1])
    return any(v in window for v in PIN_VARS)


def shell_violations(path_or_text, text: str | None = None) -> list[str]:
    text = text if text is not None else Path(path_or_text).read_text()
    name = str(path_or_text)
    lines = text.splitlines()
    problems = []
    for lineno, cmd in _shell_commands(text):
        code = cmd.split("#", 1)[0] if not cmd.lstrip().startswith("#") else ""
        if not code.strip():
            continue
        hit = None
        if "PREP_INSECURE=1" in code or 'PREP_INSECURE="1"' in code:
            hit = "PREP_INSECURE=1"
        elif (INSECURE_CURL.search(code) or INSECURE_OPTS.search(code)) and not LOOPBACK.search(code):
            hit = "insecure curl"
        if hit and not _guarded(lines, lineno - 1):
            problems.append(f"{name}:{lineno}: {hit} with no {'/'.join(PIN_VARS)} on the command or in the {GUARD_WINDOW} lines above: {cmd.strip()[:120]}")
    return problems


def rust_violations(path_or_text, text: str | None = None) -> list[str]:
    """Every `PREP_INSECURE=1` literal sits in a `Command::new(...)...;` chain that
    also passes a pin variable."""
    text = text if text is not None else Path(path_or_text).read_text()
    name = str(path_or_text)
    # Code only: a comment that names the literal is not a site.
    src = "\n".join(l for l in text.split("#[cfg(test)]")[0].splitlines() if not l.lstrip().startswith("//"))
    problems = []
    for m in re.finditer(r'"PREP_INSECURE=1"', src):
        start = src.rfind("Command::new(", 0, m.start())
        end = src.find(";", m.end())
        chain = src[start if start >= 0 else m.start() : end if end >= 0 else m.end()]
        if not any(v in chain for v in PIN_VARS):
            lineno = src.count("\n", 0, m.start()) + 1
            problems.append(f"{name}:{lineno}: PREP_INSECURE=1 in a command chain that passes no {'/'.join(PIN_VARS)}")
    return problems


def test_the_scripts_never_fetch_unpinned():
    assert SCRIPTS, "no scripts found — the parse is not looking at the tree"
    problems = []
    for p in SCRIPTS:
        problems += shell_violations(p)
    assert not problems, "\n".join(problems)


def test_noo_cli_never_sends_prep_insecure_without_the_pin():
    sites = [p for p in RUST if "PREP_INSECURE=1" in p.read_text().split("#[cfg(test)]")[0]]
    assert sites, "no PREP_INSECURE=1 site in noo-cli — did provision/enroll move?"
    problems = []
    for p in sites:
        problems += rust_violations(p)
    assert not problems, "\n".join(problems)


def test_the_two_enroll_sites_are_looked_at():
    """The parse found the sites this guard was written for (a guard that
    passes on an empty match set guards nothing)."""
    enroll = (ROOT / "scripts" / "bootstrap-enroll.sh").read_text()
    prep = (ROOT / "scripts" / "prep-host.sh").read_text()
    assert "bootstrap/deenroll" in enroll and "--cacert" in enroll
    assert "bootstrap/prep" in enroll
    assert 'PREP_CURL="-fsSk"' in prep and "PREP_CA_SHA256 is required" in prep
    prov = (ROOT / "noo-cli/src/commands/provision.rs").read_text()
    assert '"PREP_INSECURE=1"' in prov and "PREP_CA_SHA256=" in prov


def test_the_guard_catches_a_plant():
    bad_shell = 'echo x\ncurl -fsSk https://c/bootstrap/deenroll -o /tmp/x\n'
    assert shell_violations("plant.sh", bad_shell), "an unpinned -k curl passed"
    bad_print = 'echo "  curl -fsSk $NOO_URL/bootstrap/deenroll -o /tmp/noo-deenroll" >&2\n'
    assert shell_violations("plant.sh", bad_print), "unpinned advice printed for an operator passed"
    guarded_print = 'if [ -z "${NOO_CA_SHA256:-}" ]; then exit 1; fi\n' + bad_print
    assert shell_violations("plant.sh", guarded_print), "advice is pasted without its block; the window must not excuse it"
    bad_env = 'sudo env PREP_INSECURE=1 PREP_NOO_URL=$U \\\n    bash prep.sh\n'
    assert shell_violations("plant.sh", bad_env), "PREP_INSECURE=1 without the pin passed"
    ok_env = 'sudo env PREP_INSECURE=1 PREP_CA_SHA256="$PIN" \\\n    bash prep.sh\n'
    assert not shell_violations("ok.sh", ok_env)
    ok_guarded = 'if [ -z "${PREP_CA_SHA256:-}" ]; then\n  exit 1\nfi\nPREP_CURL="-fsSk"\n'
    assert not shell_violations("ok.sh", ok_guarded)
    comment_only = '# curl -fsSk is never allowed here\n'
    assert not shell_violations("ok.sh", comment_only)
    loopback_probe = 'curl -kfsS https://localhost:8080/health || true\n'
    assert not shell_violations("ok.sh", loopback_probe), "a loopback liveness probe is not a trust fetch"
    rust_comment = '// never PREP_INSECURE=1 alone\nlet _ = Command::new("x").arg("y").status();\n'
    assert not rust_violations("ok.rs", rust_comment), "a comment naming the literal is not a site"
    bad_rust = 'let _ = Command::new("sudo")\n    .arg("PREP_INSECURE=1")\n    .status();\n'
    assert rust_violations("plant.rs", bad_rust), "a Rust chain without the pin passed"
    ok_rust = 'let _ = Command::new("sudo")\n    .arg("PREP_INSECURE=1")\n    .arg(format!("PREP_CA_SHA256={pin}"))\n    .status();\n'
    assert not rust_violations("ok.rs", ok_rust)
