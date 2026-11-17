# SPDX-License-Identifier: AGPL-3.0-only
# Copyright 2026 PersonifAI LLC

"""The product never runs sudo to find out whether it could (i907).

`noo upgrade --all` ran `sudo -n true` (provision.rs `can_sudo_here`) and
onboard ran `sudo -n true` twice more (`passwordless_sudo`, the self-agent
step) to decide whether a root step could run without hanging. Each was a
refused attempt in auth.log on every box where sudo wants a password (and a
mail to root where `mail_badpass` is on); the rehearsal's B-nosudo `probe`
row failed on it ("sudo attempted: /bin/true"). The decision is now
isatty(stdin) plus the explicit `--root-ok` opt-in (`steps::root_step`).

This guard walks every function body in noo-cli/src (comments and
`#[cfg(test)]` items removed, `fn_body` brace matching) and refuses any sudo
command whose only work is `true`: `Command::new("sudo")` with `-n` + `true`,
`sudo_cmd(false)` / `ctx_sudo(ctx)` with `true`, or `root_shell("sudo",
"true")`.
"""

from __future__ import annotations

import re
from pathlib import Path

from tests import _rust_src as rs

ROOT = Path(__file__).resolve().parents[1]
SRC = ROOT / "noo-cli" / "src"

# A sudo command builder, then (chained directly) only `-n` and `true`.
_BUILDER = r'(?:Command::new\(\s*"sudo"\s*\)|sudo_cmd\(\s*\w*\s*\)|ctx_sudo\(\s*\w*\s*\))'
_ARG = r'\.args?\(\s*\[?\s*(?:"-n"\s*,\s*)?"(?:-n|true)"\s*(?:,\s*"true"\s*)?,?\s*\]?\s*\)'
_PROBE = re.compile(_BUILDER + r'(?:\s*' + _ARG + r')+')
_SHELL = re.compile(r'root_shell\(\s*"sudo"\s*,\s*"true"\s*\)')


def probes_in(body: str) -> list[str]:
    """Each sudo-runs-`true` call in `body`, normalized to one line."""
    out = []
    for m in _PROBE.finditer(body):
        text = " ".join(m.group(0).split())
        if '"true"' in text:
            out.append(text)
    out.extend(" ".join(m.group(0).split()) for m in _SHELL.finditer(body))
    return out


def fn_bodies(code: str):
    """(name, body) of every `fn` in already-own_code'd Rust source: from
    `fn name` through the brace matching the first code `{` after it, as
    `rs.fn_body` reads one, with the file classified once (a per-fn
    `rs.fn_body` re-reads the whole tail: minutes on steps.rs)."""
    b = code.encode()
    cls = rs._classify(b)
    for m in re.finditer(rb"\bfn\s+([A-Za-z_][A-Za-z0-9_]*)\s*[<(]", b):
        if cls[m.start()] != rs._CODE:
            continue
        i, open_, depth = m.end() - 1, None, 0
        while i < len(b):
            c = b[i] if cls[i] == rs._CODE else 0
            if c in (0x28, 0x5B):  # ( [ — a `;` inside is `[u8; 32]`
                depth += 1
            elif c in (0x29, 0x5D):
                depth -= 1
            elif c == 0x3B and depth == 0:  # `fn x();` — a declaration
                break
            elif c == 0x7B and depth == 0:
                open_ = i
                break
            i += 1
        if open_ is None:
            continue
        close = rs._matching_brace(b, cls, open_)
        if close is not None:
            yield m.group(1).decode(), b[m.start() : close + 1].decode()


def scan(src_root: Path) -> list[str]:
    hits = []
    for f in sorted(src_root.rglob("*.rs")):
        code = rs.own_code(f.read_text(encoding="utf-8"))
        for name, body in fn_bodies(code):
            for p in probes_in(body):
                hits.append(f"{f.relative_to(src_root)}: fn {name}: {p}")
    return hits


def test_the_detector_sees_every_shape_the_probe_had():
    """The three shapes dev carried before i907, each one caught; the real
    sudo calls beside them (a command that does work) are not."""
    old_provision = '''
pub(crate) fn can_sudo_here() -> bool {
    let quiet = Command::new("sudo").args(["-n", "true"])
        .stdout(std::process::Stdio::null()).stderr(std::process::Stdio::null())
        .status().map(|s| s.success()).unwrap_or(false);
    quiet || std::io::IsTerminal::is_terminal(&std::io::stdin())
}
'''
    old_self_agent = '''
fn ensure_self_agent(ctx: &mut Ctx) {
    let sudo_quiet = sudo_cmd(false).args(["true"])
        .stdout(std::process::Stdio::null()).stderr(std::process::Stdio::null())
        .status().map(|s| s.success()).unwrap_or(false);
}
'''
    old_passwordless = '''
pub(crate) fn passwordless_sudo() -> bool {
    sudo_cmd(false)
        .arg("true")
        .stdout(std::process::Stdio::null())
        .status()
        .map(|s| s.success())
        .unwrap_or(false)
}
'''
    for src, name in [(old_provision, "can_sudo_here"), (old_self_agent, "ensure_self_agent"),
                      (old_passwordless, "passwordless_sudo")]:
        found = [(n, p) for n, b in fn_bodies(rs.own_code(src)) for p in probes_in(b)]
        assert [n for n, _ in found] == [name], (name, found)
    assert probes_in('Command::new("sudo").arg("-n").arg("true").status()')
    assert probes_in('root_shell("sudo", "true").status()')
    assert probes_in('ctx_sudo(ctx).args(["true"]).status()')
    # Real work through sudo is not a probe.
    for ok in ['sudo_cmd(false).args(["cat", P]).output()',
               'ctx_sudo(ctx).args(["install", "-m", "0644", &src_s, INSTALLED])',
               'Command::new("sudo").args(["-n", "systemctl", "daemon-reload"])',
               'root_shell("sudo", &fix).status()']:
        assert probes_in(ok) == [], ok


def test_no_function_in_noo_cli_runs_sudo_to_learn_whether_it_could():
    hits = scan(SRC)
    assert hits == [], (
        "a sudo probe is back (i907: decide from isatty(stdin) and --root-ok, "
        "steps::root_step — never `sudo -n true`):\n" + "\n".join(hits))


def test_the_scan_reads_the_files_that_held_the_probe():
    """Not vacuous: the walk reaches the functions that carried the probe."""
    names = {}
    for rel in ["commands/provision.rs", "onboard/steps.rs", "commands/pki.rs"]:
        code = rs.own_code((SRC / rel).read_text(encoding="utf-8"))
        names[rel] = {n for n, _ in fn_bodies(code)}
    assert "converge_self_controller_url" in names["commands/provision.rs"]
    assert {"ensure_self_agent", "hostd_can_run_here", "root_step"} <= names["onboard/steps.rs"]
    assert "reconcile_key_modes" in names["commands/pki.rs"]


def test_onboards_root_ok_reaches_the_self_node_provision_child():
    """onboard's self-agent restage runs `cluster provision` in a child; its
    own root-step decision reads only the terminal and --root-ok, so the
    flag must be forwarded or `--ci --root-ok` would refuse there."""
    steps = rs.own_code((SRC / "onboard" / "steps.rs").read_text(encoding="utf-8"))
    body = rs.fn_body(steps, "fn ensure_self_agent(")
    assert 'if root_ok { &["--root-ok"] }' in body, body
    assert "provision_one(g, &node_id, extra)" in body, body
    prov = rs.own_code((SRC / "commands" / "provision.rs").read_text(encoding="utf-8"))
    parse = rs.fn_body(prov, "fn parse_provision_args(")
    assert '"--root-ok" => root_ok = true' in parse, parse
