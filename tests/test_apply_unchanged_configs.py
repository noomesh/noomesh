# SPDX-License-Identifier: AGPL-3.0-only
# Copyright 2026 PersonifAI LLC

"""A restage that carries config the node already holds restarts nothing.

The non-binary blocks of scripts/noo-apply.sh (certs, svc-* leaves, agent-env,
nats-creds, fleet-secrets, the two units, harness-env) used to install
unconditionally and set `need_restart` / `need_harness_restart` /
`need_daemon_reload`, so every `noo cluster provision` bounced the agent even
when the files were byte-identical. Each block now asks
`config_unchanged PAYLOAD INSTALLED MODE OWNER:GROUP`: true only when the
installed file exists, has the same bytes AND the mode and owner the install
would give it. Merged kinds are compared as the merged result.

Like test_apply_unchanged_binaries.py, the blocks are lifted out of the real
script and run under bash with `install` / `mv` / `stat` stubbed (the real
ones want root and a noo-agent group), the node's file tree redirected into a
temp dir that PERSISTS across applies, and the flags plus the `applied`
summary asserted. Not covered: a real node apply as root.
"""

from __future__ import annotations

import os
import re
import subprocess
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parents[1]
APPLIER = (REPO / "scripts" / "noo-apply.sh").read_text()
LINES = APPLIER.split("\n")
NODE = "node1"


@pytest.fixture(autouse=True)
def _nothing_lands_in_the_repo_cwd():
    """Every path handed to the applier must sit under the test's tmp dir: a
    stub that misreads an argument once wrote `1/NOO_CLUSTER_SECRET` into the
    working tree."""
    before = set(os.listdir(REPO)) | set(os.listdir(os.getcwd()))
    yield
    after = set(os.listdir(REPO)) | set(os.listdir(os.getcwd()))
    assert after == before, f"test left entries in the repo/cwd: {sorted(after - before)}"


def lift(start: str, end: str) -> str:
    idx = [i for i, l in enumerate(LINES) if l == start]
    assert len(idx) == 1, f"{start!r} matched {len(idx)} column-0 lines"
    for j in range(idx[0] + 1, len(LINES)):
        if LINES[j] == end:
            return "\n".join(LINES[idx[0]: j + 1]) + "\n"
    raise AssertionError(f"no {end!r} after {start!r}")


def delimited(name: str) -> str:
    m = re.search(rf"# BEGIN {name}\n(.*?)# END {name}", APPLIER, re.S)
    assert m, f"{name} is not delimited in noo-apply.sh"
    return m.group(1)


def kind_block(kind: str) -> str:
    return lift(f'if [ -f "$WORK/files/{kind}" ]; then', "fi")


BLOCKS = {
    "ca.crt": kind_block("ca.crt"),
    "node.crt": lift("for _nk in node.crt node.key; do", "done"),
    "node.key": lift("for _nk in node.crt node.key; do", "done"),
    "svc": lift("for _svc in vllm llamacpp ollama tei reranker; do", "done"),
    "agent-env": kind_block("agent-env"),
    "nats-creds": kind_block("nats-creds"),
    "fleet-secrets": kind_block("fleet-secrets"),
    "agent-unit": kind_block("agent-unit"),
    "harness-env": kind_block("harness-env"),
    "harness-unit": kind_block("harness-unit"),
}

PRELUDE = r'''set -u
R="$ROOT"
OWNERS="$R/owners"; touch "$OWNERS"
owner_of() { awk -v p="$1" '$1==p {o=$2} END {print o}' "$OWNERS"; }
install() {
    t_m=""; t_o=root; t_g=root; t_d=0
    while [ $# -gt 0 ]; do case "$1" in
        -m) t_m="$2"; shift 2 ;; -o) t_o="$2"; shift 2 ;; -g) t_g="$2"; shift 2 ;; -d) t_d=1; shift ;; *) break ;; esac; done
    if [ "$t_d" = 1 ]; then for t_p in "$@"; do mkdir -p "$t_p"; done; return 0; fi
    cp "$1" "$2" && chmod "$t_m" "$2" && echo "$2 $t_o:$t_g" >> "$OWNERS"
}
mv() {
    if [ "$#" -ge 2 ]; then eval "t_dst=\${$#}"; t_src=""; for t_a in "$@"; do case "$t_a" in -*) ;; *) [ "$t_a" = "$t_dst" ] || t_src="$t_a" ;; esac; done
        t_own="$(owner_of "$t_src")"; [ -z "$t_own" ] || echo "$t_dst $t_own" >> "$OWNERS"; fi
    command mv "$@"
}
stat() {
    if [ "$1" = -c ] && [ "$2" = '%a %U:%G' ]; then
        t_sm="$(command stat -c %a "$3")" || return 1
        t_so="$(owner_of "$3")"; [ -n "$t_so" ] || t_so="$(command stat -c %U:%G "$3")"
        echo "$t_sm $t_so"
    else command stat "$@"; fi
}
grant_traverse() { :; }
grant_traverse_flush_missing() { :; }
agent_env_secret() { sed -n "s/^$2=//p" "$1" | tail -1; }
getent() { return 0; }
id() { case "$*" in *-nG*) echo noo-agent ;; *-gn*) echo "${2}grp" ;; *-un*) echo root ;; *) return 0 ;; esac; }
chown() { echo "$2 $1" >> "$OWNERS"; }
useradd() { :; }
gpasswd() { :; }
'''


def run(root: Path, kind: str, files: dict[str, bytes], *, preload: dict[str, bytes] | None = None,
        tamper: str = "", asf: bool = False) -> dict[str, str]:
    """One apply of KIND against the node tree in ROOT (persistent across calls)."""
    work = root / "work"
    if work.exists():
        subprocess.run(["rm", "-rf", str(work)], check=True)
    (work / "files").mkdir(parents=True)
    for name, data in files.items():
        (work / "files" / name).write_bytes(data)
    for rel, data in (preload or {}).items():
        p = root / rel
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_bytes(data)
        p.chmod(0o600)
    pki = root / "pki"
    (pki / "nodes" / NODE).mkdir(parents=True, exist_ok=True)
    def paths(t: str) -> str:
        return t.replace("/etc/", f"{root}/etc/").replace("/usr/local/bin", f"{root}/usr/local/bin")
    body = paths(BLOCKS[kind])
    # what the end of a real apply does: agent_secret_files over the env just written
    tail = ""
    if asf:
        tail = paths('''ASF_OWNER="$(asf_owner)"
agent_secret_files /etc/noo-node-agent.env /etc/noo/agent-secrets /usr/local/bin/noo-node-agent "$ASF_OWNER" /etc/noo-node-agent.env.container-backup || exit $?
if [ "$ASF_CHANGED" = 1 ]; then need_restart=1; fi
echo "asf_changed=$ASF_CHANGED"
''')
    (root / "etc/systemd/system").mkdir(parents=True, exist_ok=True)
    (root / "etc/sudoers.d").mkdir(parents=True, exist_ok=True)
    script = f'''ROOT="{root}"
{PRELUDE}
WORK="{work}"; PKI="{pki}"; NODE_ID="{NODE}"
applied=""; need_restart=0; need_harness_restart=0; need_daemon_reload=0; fresh_unit=0
{delimited("agent_env_nats_carry")}
{delimited("config_unchanged")}
{paths(delimited("agent_secret_files"))}
{paths(delimited("asf_unchanged"))}
{tamper.replace("@ROOT@", str(root))}
{body}
{tail}
echo "applied=$applied"; echo "need_restart=$need_restart"
echo "need_harness_restart=$need_harness_restart"; echo "need_daemon_reload=$need_daemon_reload"
'''
    r = subprocess.run(["bash", "-c", script], capture_output=True, text=True)
    assert r.returncode == 0, r.stdout + r.stderr
    keys = ("applied", "asf_changed", "need_restart", "need_harness_restart", "need_daemon_reload")
    return dict(l.split("=", 1) for l in r.stdout.splitlines() if l.split("=")[0] in keys and "=" in l)


def flags(o: dict[str, str]) -> tuple[str, str, str]:
    return o["need_restart"], o["need_harness_restart"], o["need_daemon_reload"]


# kind -> (payload files, preloaded files, installed path relative to root, flags a real install sets)
PKI_NODE = f"pki/nodes/{NODE}"
CASES = {
    "ca.crt": ({"ca.crt": b"CA\n"}, {}, "pki/ca.crt", ("1", "0", "0"), ["ca.crt"]),
    "node.crt": ({"node.crt": b"CERT\n"}, {}, f"{PKI_NODE}/node.crt", ("1", "0", "0"), ["node.crt"]),
    "node.key": ({"node.key": b"KEY\n"}, {}, f"{PKI_NODE}/node.key", ("1", "0", "0"), ["node.key"]),
    "agent-env": ({"agent-env": f"NODE_ID={NODE}\nTIER=x\n".encode()}, {}, "etc/noo-node-agent.env",
                  ("1", "0", "0"), ["agent-env"]),
    "agent-unit": ({"agent-unit": b"[Unit]\n[Service]\nUser=noo-agent\n"}, {},
                   "etc/systemd/system/noo-node-agent.service", ("1", "0", "1"), ["agent-unit"]),
    "harness-unit": ({"harness-unit": b"[Service]\nUser=noo-harness\n"}, {},
                     "etc/systemd/system/noo-harness.service", ("0", "1", "1"), ["harness-unit"]),
    "harness-env": ({"harness-env": f"NODE_ID={NODE}\nNATS_NODE_USER=node-{NODE}\nNATS_NODE_PASSWORD=pw\n".encode()}, {},
                    "etc/noo-harness.env", ("0", "1", "0"), ["harness-env"]),
    "nats-creds": ({"nats-creds": f"NODE={NODE}\nNATS_NODE_USER=node-{NODE}\nNATS_NODE_PASSWORD=pw\n".encode()},
                   {"etc/noo-node-agent.env": f"NODE_ID={NODE}\n".encode()},
                   "etc/noo-node-agent.env", ("1", "0", "0"), ["nats-creds"]),
    "fleet-secrets": ({"fleet-secrets": f"NODE={NODE}\nNOO_CLUSTER_SECRET=s3cret\n".encode()},
                      {"etc/noo-node-agent.env": f"NODE_ID={NODE}\n".encode()},
                      "etc/noo-node-agent.env", ("1", "0", "0"), ["fleet-secrets"]),
}


@pytest.mark.parametrize("kind", list(CASES))
def test_first_apply_installs_and_flags_second_identical_apply_reports_unchanged(tmp_path: Path, kind: str) -> None:
    files, pre, _path, want, tokens = CASES[kind]
    first = run(tmp_path, kind, files, preload=pre)
    assert first["applied"].split() == tokens
    assert flags(first) == want
    second = run(tmp_path, kind, files)
    assert second["applied"].split() == [f"{t}=unchanged" for t in tokens]
    assert flags(second) == ("0", "0", "0")


@pytest.mark.parametrize("kind", list(CASES))
def test_changed_bytes_reinstall(tmp_path: Path, kind: str) -> None:
    files, pre, path, want, tokens = CASES[kind]
    run(tmp_path, kind, files, preload=pre)
    if kind in ("nats-creds", "fleet-secrets"):
        # a different credential in the fragment changes the MERGED result
        changed = {k: v.replace(b"pw", b"pw2").replace(b"s3cret", b"s3cret2") for k, v in files.items()}
    else:
        changed = {k: v + b"# more\n" for k, v in files.items()}
    again = run(tmp_path, kind, changed)
    assert again["applied"].split() == tokens
    assert flags(again) == want


@pytest.mark.parametrize("kind", list(CASES))
def test_changed_mode_reinstalls(tmp_path: Path, kind: str) -> None:
    files, pre, path, want, tokens = CASES[kind]
    run(tmp_path, kind, files, preload=pre)
    (tmp_path / path).chmod(0o666)
    again = run(tmp_path, kind, files)
    assert again["applied"].split() == tokens
    assert flags(again) == want


@pytest.mark.parametrize("kind", list(CASES))
def test_changed_owner_reinstalls(tmp_path: Path, kind: str) -> None:
    files, pre, path, want, tokens = CASES[kind]
    run(tmp_path, kind, files, preload=pre)
    with open(tmp_path / "owners", "a") as f:
        f.write(f"{tmp_path / path} nobody:nogroup\n")
    again = run(tmp_path, kind, files)
    assert again["applied"].split() == tokens
    assert flags(again) == want


def test_an_unreadable_or_empty_installed_file_is_installed_over(tmp_path: Path) -> None:
    files, pre, path, want, tokens = CASES["agent-unit"]
    run(tmp_path, "agent-unit", files)
    (tmp_path / path).write_bytes(b"")
    again = run(tmp_path, "agent-unit", files)
    assert again["applied"].split() == tokens and flags(again) == want


def test_first_install_of_the_agent_unit_is_fresh_never_unchanged(tmp_path: Path) -> None:
    files, *_ = CASES["agent-unit"]
    o = run(tmp_path, "agent-unit", files)
    assert o["applied"].split() == ["agent-unit"] and o["need_daemon_reload"] == "1"


def test_nats_creds_merged_into_both_envs_is_unchanged_only_when_neither_moved(tmp_path: Path) -> None:
    files, pre, *_ = CASES["nats-creds"]
    harness = {"etc/noo-harness.env": f"NODE_ID={NODE}\n".encode()}
    first = run(tmp_path, "nats-creds", files, preload={**pre, **harness})
    assert first["applied"].split() == ["nats-creds"] and flags(first) == ("1", "1", "0")
    second = run(tmp_path, "nats-creds", files)
    assert second["applied"].split() == ["nats-creds=unchanged"] and flags(second) == ("0", "0", "0")
    # the harness env alone drifts: the kind is installed, only the harness bounces
    (tmp_path / "etc/noo-harness.env").write_bytes(f"NODE_ID={NODE}\n".encode())
    third = run(tmp_path, "nats-creds", files)
    assert third["applied"].split() == ["nats-creds"] and flags(third) == ("0", "1", "0")


def test_harness_env_without_a_password_is_compared_after_the_pair_is_resolved(tmp_path: Path) -> None:
    payload = {"harness-env": f"NODE_ID={NODE}\n".encode(),
               "nats-creds": f"NODE={NODE}\nNATS_NODE_USER=node-{NODE}\nNATS_NODE_PASSWORD=pw\n".encode()}
    first = run(tmp_path, "harness-env", payload)
    assert first["applied"].split() == ["harness-env"] and first["need_harness_restart"] == "1"
    second = run(tmp_path, "harness-env", payload)
    assert second["applied"].split() == ["harness-env=unchanged"] and second["need_harness_restart"] == "0"


def test_agent_env_carried_pair_counts_in_the_comparison(tmp_path: Path) -> None:
    env = f"NODE_ID={NODE}\nTIER=x\n".encode()
    installed = env + f"NATS_NODE_USER=node-{NODE}\nNATS_NODE_PASSWORD=pw\n".encode()
    # no nats-creds in the bundle: the installed pair is carried into the new
    # env, so the final content equals the installed file
    run(tmp_path, "agent-env", {"agent-env": env}, preload={"etc/noo-node-agent.env": installed})
    (tmp_path / "etc/noo-node-agent.env").chmod(0o600)
    with open(tmp_path / "owners", "a") as f:
        f.write(f"{tmp_path}/etc/noo-node-agent.env root:root\n")
    again = run(tmp_path, "agent-env", {"agent-env": env})
    assert again["applied"].split() == ["agent-env=unchanged"] and flags(again) == ("0", "0", "0")


def _leaf(tmp: Path) -> tuple[bytes, bytes, bytes]:
    d = tmp / "ssl"
    d.mkdir(exist_ok=True)

    def sh(*a: str) -> None:
        subprocess.run(a, cwd=d, check=True, capture_output=True)
    sh("openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes", "-keyout", "ca.key", "-out", "ca.crt",
       "-subj", "/CN=testca", "-days", "2")
    sh("openssl", "req", "-newkey", "rsa:2048", "-nodes", "-keyout", "s.key", "-out", "s.csr", "-subj", "/CN=svc")
    sh("openssl", "x509", "-req", "-in", "s.csr", "-CA", "ca.crt", "-CAkey", "ca.key", "-CAcreateserial",
       "-out", "s.crt", "-days", "2")
    return (d / "ca.crt").read_bytes(), (d / "s.crt").read_bytes(), (d / "s.key").read_bytes()


def test_svc_leaf_is_skipped_when_identical_and_reinstalled_on_any_difference(tmp_path: Path) -> None:
    ca, crt, key = _leaf(tmp_path)
    (tmp_path / "pki").mkdir()
    (tmp_path / "pki/ca.crt").write_bytes(ca)
    files = {"svc-vllm.crt": crt, "svc-vllm.key": key}
    first = run(tmp_path, "svc", files)
    assert first["applied"].split() == ["svc-vllm"]
    second = run(tmp_path, "svc", files)
    assert second["applied"].split() == ["svc-vllm=unchanged"] and flags(second) == ("0", "0", "0")
    # key mode drifted: reinstall
    (tmp_path / "pki/services/vllm/service.key").chmod(0o644)
    assert run(tmp_path, "svc", files)["applied"].split() == ["svc-vllm"]
    # cert owner drifted: reinstall
    with open(tmp_path / "owners", "a") as f:
        f.write(f"{tmp_path}/pki/services/vllm/service.crt nobody:nogroup\n")
    assert run(tmp_path, "svc", files)["applied"].split() == ["svc-vllm"]
    # a leaf that differs AND does not verify against the CA is still refused
    (tmp_path / "pki/ca.crt").write_bytes(crt)  # wrong anchor
    (tmp_path / "pki/services/vllm/service.crt").write_bytes(b"old")
    with pytest.raises(AssertionError, match="does not verify"):
        run(tmp_path, "svc", files)


def test_every_kind_block_consults_the_helper_and_the_old_unconditional_installs_are_gone() -> None:
    for tok in ("ca.crt", "agent-unit", "harness-unit", "harness-env", "fleet-secrets", "nats-creds", "agent-env"):
        assert f"{tok}=unchanged" in APPLIER or tok == "nats-creds", tok
    assert 'applied="$applied $_nk=unchanged"' in APPLIER
    assert 'applied="$applied svc-$_svc=unchanged"' in APPLIER
    assert "nats-creds=unchanged" in APPLIER
    assert "$ae_state" in APPLIER
    # the signing-pub kind never restarts anything and stays unconditional
    assert 'applied="$applied signing-pub"' in APPLIER
    sign = next(l for l in LINES if 'applied="$applied signing-pub"' in l)
    assert "need_restart" not in sign and "config_unchanged" not in sign


def test_the_refusal_still_fires_on_an_empty_bundle_but_not_when_every_kind_was_unchanged() -> None:
    line = next(l for l in LINES if l.startswith('[ -n "$applied" ] ||'))
    assert "contained nothing to apply" in line and "exit 65" in line

    def verdict(applied: str) -> int:
        return subprocess.run(["bash", "-c", f'applied="{applied}"\n{line}\nexit 0'], capture_output=True).returncode
    assert verdict("") == 65
    assert verdict(" ca.crt=unchanged agent-env=unchanged svc-vllm=unchanged") == 0


def test_all_unchanged_bundle_succeeds_end_to_end(tmp_path: Path) -> None:
    """Every config kind applied twice: the second pass is all `=unchanged`, sets no flag, and passes the refusal."""
    line = next(l for l in LINES if l.startswith('[ -n "$applied" ] ||'))
    summary: list[str] = []
    for kind in ("ca.crt", "node.crt", "node.key", "agent-unit", "harness-unit", "harness-env"):
        files, pre, *_ = CASES[kind]
        run(tmp_path, kind, files, preload=pre)
    for kind in ("ca.crt", "node.crt", "node.key", "agent-unit", "harness-unit", "harness-env"):
        files, *_ = CASES[kind]
        o = run(tmp_path, kind, files)
        assert flags(o) == ("0", "0", "0")
        summary += o["applied"].split()
    assert summary and all(t.endswith("=unchanged") for t in summary)
    r = subprocess.run(["bash", "-c", f'applied=" {" ".join(summary)}"\n{line}\nexit 0'], capture_output=True)
    assert r.returncode == 0


def test_secret_file_conversion_is_seen_through_two_secrets_applied_twice(tmp_path: Path) -> None:
    """The env kinds survive agent_secret_files: with a capable agent binary the
    installed env holds KEY_FILE pointers and the values live in files. A second
    identical apply must compare the NORMALISED payload against that, report
    `=unchanged`, set no flag, and leave the env and both secret files alone."""
    binary = tmp_path / "usr/local/bin/noo-node-agent"
    binary.parent.mkdir(parents=True)
    binary.write_bytes(b"\x7fELF noo-agent-reads-secret-files/1 \n")
    payload = {"agent-env": (f"NODE_ID={NODE}\nTIER=x\nNOO_NODE_AGENT_TOKEN=tok-1\n"
                             "NOO_CLUSTER_SECRET=sec-1\n").encode()}
    first = run(tmp_path, "agent-env", payload, asf=True)
    assert first["applied"].split() == ["agent-env"] and first["need_restart"] == "1"
    assert first["asf_changed"] == "1"
    env = tmp_path / "etc/noo-node-agent.env"
    sdir = tmp_path / "etc/noo/agent-secrets"
    assert f"NOO_NODE_AGENT_TOKEN_FILE={sdir}/NOO_NODE_AGENT_TOKEN" in env.read_text()
    assert "tok-1" not in env.read_text()
    assert (sdir / "NOO_CLUSTER_SECRET").read_text() == "sec-1"
    marks = {p: p.stat().st_mtime_ns for p in (env, sdir / "NOO_NODE_AGENT_TOKEN", sdir / "NOO_CLUSTER_SECRET")}
    second = run(tmp_path, "agent-env", payload, asf=True)
    assert second["applied"].split() == ["agent-env=unchanged"]
    assert flags(second) == ("0", "0", "0") and second["asf_changed"] == "0"
    assert {p: p.stat().st_mtime_ns for p in marks} == marks
    # a changed secret value is NOT unchanged, even though the env pointers are identical
    changed = {"agent-env": payload["agent-env"].replace(b"sec-1", b"sec-2")}
    third = run(tmp_path, "agent-env", changed, asf=True)
    assert third["applied"].split() == ["agent-env"] and third["need_restart"] == "1"
    assert (sdir / "NOO_CLUSTER_SECRET").read_text() == "sec-2"
    # a missing secret file is not unchanged either
    (sdir / "NOO_NODE_AGENT_TOKEN").unlink()
    fourth = run(tmp_path, "agent-env", changed, asf=True)
    assert fourth["applied"].split() == ["agent-env"] and fourth["need_restart"] == "1"
    assert (sdir / "NOO_NODE_AGENT_TOKEN").read_text() == "tok-1"


def test_merged_kinds_see_through_the_conversion_too(tmp_path: Path) -> None:
    binary = tmp_path / "usr/local/bin/noo-node-agent"
    binary.parent.mkdir(parents=True)
    binary.write_bytes(b"noo-agent-reads-secret-files/1\n")
    pre = {"etc/noo-node-agent.env": f"NODE_ID={NODE}\n".encode()}
    nats = {"nats-creds": f"NODE={NODE}\nNATS_NODE_USER=node-{NODE}\nNATS_NODE_PASSWORD=pw\n".encode()}
    fleet = {"fleet-secrets": f"NODE={NODE}\nNOO_CLUSTER_SECRET=s3cret\nNOO_NODE_AGENT_TOKEN=t\n".encode()}
    for kind, files in (("nats-creds", nats), ("fleet-secrets", fleet)):
        first = run(tmp_path, kind, files, preload=pre if kind == "nats-creds" else None, asf=True)
        assert first["applied"].split() == [kind] and first["need_restart"] == "1"
        second = run(tmp_path, kind, files, asf=True)
        assert second["applied"].split() == [f"{kind}=unchanged"], kind
        assert flags(second) == ("0", "0", "0") and second["asf_changed"] == "0"


def test_asf_unchanged_runs_the_real_agent_secret_files_so_they_cannot_drift() -> None:
    wrapper = delimited("asf_unchanged")
    assert 'agent_secret_files "$_au_root/env"' in wrapper
    # provision --local lifts only this block; the comparison lives outside it
    assert "asf_unchanged" not in delimited("agent_secret_files")
    assert 'ASF_OWNER="$(asf_owner)"' in APPLIER
