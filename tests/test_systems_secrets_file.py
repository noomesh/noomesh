# SPDX-License-Identifier: AGPL-3.0-only
# Copyright 2026 PersonifAI LLC

"""A declared system core does not name still gets its flag and passwords.

The gateway has no `env_file`: only variables compose names one by one reach
it. trellion and evolve have their own `_FILE` lines; a system declared at
runtime (an operator's `systems:` entry, later an add-on bundle's fragment)
never can, because core never names add-ons. So the launcher writes ONE file,
`noo_systems_secrets` (`KEY=VALUE` lines), from the declared systems
(`lib-secrets.sh` `_declared_systems` → `_systems_secrets_body`), and the
broker reads a name from its env first, then from that file
(`gateway-rust/src/system_provision.rs` `SYSTEMS_SECRETS`).

What this holds:
  * the file carries each declared system's `enabled_when` flag (from .env,
    where `noo systems enable` writes it) and its two passwords (from the
    store), is 0400 and handed to the gateway's uid;
  * a variable a compose secret already delivers by name (trellion's) is not
    repeated; a variable with no value is left out;
  * a bad variable name or a multi-line value is refused with a warning that
    names the variable, never the value; no value reaches stdout/stderr;
  * an older `noo` that cannot list the systems warns (only when `systems:` is
    declared) and the launch goes on;
  * compose mounts the one file on the gateway with one pointer.

Old code: no `noo_systems_secrets` compose secret and no `_systems_secrets_body`
— every test below fails on it (the file is absent, the function undefined).

`noo config launch-render systems` is faked here (NOO_CLI_BIN): its own output
shape is pinned by the Rust test `systems_renders_the_variable_names_never_values`.
"""

from __future__ import annotations

import stat
import subprocess
from pathlib import Path

import pytest

from tests._compose_projection import ROOT, env_of, full_projection
from tests.test_secret_rundir import SECRET_MARK, Box, needs_shm

LIB = ROOT / "scripts" / "lib-secrets.sh"

MANIFEST = """\
systems:
  example_addon:
    role: noo_example_addon
    ddl_role: noo_example_addon_ddl
    schema: example_addon
    enabled_when: NOO_EXAMPLE_ADDON_ENABLED
    password_env: NOO_EXAMPLE_ADDON_DB_PASSWORD
    ddl_password_env: NOO_EXAMPLE_ADDON_DDL_PASSWORD
  trellion:
    role: noo_trellion
    ddl_role: noo_trellion_ddl
    schema: trellion
    password_env: NOO_TRELLION_DB_PASSWORD
    ddl_password_env: NOO_TRELLION_DDL_PASSWORD
"""

# What `noo config launch-render systems noomesh.yaml` prints for MANIFEST.
RENDERED = (
    "example_addon NOO_EXAMPLE_ADDON_ENABLED NOO_EXAMPLE_ADDON_DB_PASSWORD NOO_EXAMPLE_ADDON_DDL_PASSWORD -\n"
    "trellion - NOO_TRELLION_DB_PASSWORD NOO_TRELLION_DDL_PASSWORD on\n"
)

STORE = "\n".join(
    [
        f"NOO_JWT_SECRET={SECRET_MARK}jwt",
        f"POSTGRES_PASSWORD={SECRET_MARK}pg",
        f"NOO_APP_DB_PASSWORD={SECRET_MARK}app",
        f"NOO_TRELLION_DB_PASSWORD={SECRET_MARK}trellion",
        f"NOO_TRELLION_DDL_PASSWORD={SECRET_MARK}trellion-ddl",
        # `=` and quotes inside a value travel verbatim.
        f"NOO_EXAMPLE_ADDON_DB_PASSWORD={SECRET_MARK}ex=a'b",
        f"NOO_EXAMPLE_ADDON_DDL_PASSWORD={SECRET_MARK}ex-ddl",
    ]
)

WANT_BODY = (
    "NOO_EXAMPLE_ADDON_ENABLED=1\n"
    f"NOO_EXAMPLE_ADDON_DB_PASSWORD={SECRET_MARK}ex=a'b\n"
    f"NOO_EXAMPLE_ADDON_DDL_PASSWORD={SECRET_MARK}ex-ddl"
)


def _fake_noo(tmp: Path, rendered: str, rc: int = 0) -> Path:
    noo = tmp / "fake-noo"
    noo.write_text(
        "#!/bin/sh\n"
        '[ "$1 $2 $3 $4" = "config launch-render systems noomesh.yaml" ] || { echo "unexpected: $*" >&2; exit 64; }\n'
        f"cat <<'EOF'\n{rendered}EOF\nexit {rc}\n"
    )
    noo.chmod(noo.stat().st_mode | stat.S_IEXEC)
    return noo


@pytest.fixture
def box(tmp_path: Path):
    b = Box(tmp_path)
    (b.bin / "sops").write_text(f"#!/bin/sh\ncat <<'EOF'\n{STORE}\nEOF\n")
    (tmp_path / ".env").write_text("NOO_SECRETS_BACKEND=sops\nNOO_EXAMPLE_ADDON_ENABLED=1\n")
    (tmp_path / "noomesh.yaml").write_text(MANIFEST)
    yield b
    b.cleanup()


def _no_value_in(out: subprocess.CompletedProcess) -> None:
    assert SECRET_MARK not in out.stdout + out.stderr, "a secret value reached the launcher's output"


@needs_shm
def test_the_launcher_writes_one_0400_file_for_the_gateway_with_the_declared_systems(box: Box) -> None:
    r = box.run("load_secrets >/dev/null", extra={"NOO_CLI_BIN": str(_fake_noo(box.tmp, RENDERED))})
    assert r.returncode == 0, r.stderr
    _no_value_in(r)
    f = box.rundir / "noo_systems_secrets"
    assert f.is_file(), "no systems-secrets file: a system core does not name gets nothing"
    assert stat.S_IMODE(f.stat().st_mode) == 0o400
    # flag from .env, passwords from the store; trellion's are delivered by
    # their own compose secrets and are not repeated here
    assert f.read_text() == WANT_BODY
    handed = {name: uid for uid, name in (line.split() for line in box.log.read_text().splitlines())}
    owner = next(uid for name, uid in handed.items() if name.endswith(".noo_systems_secrets"))
    assert owner == "65532", "the gateway's uid owns the file"


def _body(tmp: Path, rendered: str, env_file: str, rc: int = 0, extra: dict[str, str] | None = None) -> subprocess.CompletedProcess:
    (tmp / "docker-compose.cluster.yml").write_text((ROOT / "docker-compose.cluster.yml").read_text())
    (tmp / ".env").write_text(env_file)
    env = {"PATH": "/usr/bin:/bin", "HOME": str(tmp), "NOO_CLI_BIN": str(_fake_noo(tmp, rendered, rc))}
    env.update(extra or {})
    return subprocess.run(
        ["bash", "-c", f'cd {tmp} && . {LIB} && _systems_secrets_body; printf "\\0%s" "$(derive_file_secrets; printf "%s" "${{NOO_SYSTEMS_SECRETS-UNSET}}")"'],
        env=env, capture_output=True, text=True, timeout=30,
    )


def test_derive_exports_the_body_and_skips_what_has_no_value(tmp_path: Path) -> None:
    (tmp_path / "noomesh.yaml").write_text(MANIFEST)
    r = _body(
        tmp_path, RENDERED, "NOO_EXAMPLE_ADDON_ENABLED=true\n",
        extra={"NOO_EXAMPLE_ADDON_DB_PASSWORD": f"{SECRET_MARK}p", "NOO_TRELLION_DB_PASSWORD": f"{SECRET_MARK}t"},
    )
    assert r.returncode == 0, r.stderr
    assert SECRET_MARK not in r.stderr, "a secret value reached a warning"
    body, exported = r.stdout.split("\0")
    assert body == f"NOO_EXAMPLE_ADDON_ENABLED=true\nNOO_EXAMPLE_ADDON_DB_PASSWORD={SECRET_MARK}p\n"
    assert exported == body.rstrip("\n"), "derive_file_secrets exports it for write_secret_files"


def test_a_bad_name_or_a_multi_line_value_is_refused_naming_the_variable_only(tmp_path: Path) -> None:
    (tmp_path / "noomesh.yaml").write_text(MANIFEST)
    rendered = "evil - NOO_EX_PW NOO_EX_DDL -\nbadflag a[$(touch${IFS}pwned)] NOO_EX_X NOO_EX_Y -\n"
    r = _body(tmp_path, rendered, "", extra={
        "NOO_EX_PW": f"{SECRET_MARK}one\n{SECRET_MARK}two", "NOO_EX_DDL": f"{SECRET_MARK}d", "NOO_EX_X": f"{SECRET_MARK}x",
    })
    assert r.returncode == 0, r.stderr
    assert not (tmp_path / "pwned").exists(), "a variable name reached an indirect expansion"
    assert "not an environment variable name" in r.stderr
    assert "NOO_EX_PW (system evil) holds a multi-line value" in r.stderr
    assert SECRET_MARK not in r.stderr, "a secret value reached a warning"
    body, _ = r.stdout.split("\0")
    assert body == f"NOO_EX_DDL={SECRET_MARK}d\n"


def test_an_older_noo_warns_when_systems_are_declared_and_the_launch_goes_on(tmp_path: Path) -> None:
    (tmp_path / "noomesh.yaml").write_text(MANIFEST)
    r = _body(tmp_path, "", "", rc=64)
    assert r.returncode == 0, r.stderr
    assert "could not list the declared systems" in r.stderr
    assert r.stdout.split("\0") == ["", ""]


def test_no_manifest_means_no_file_and_no_noise(tmp_path: Path) -> None:
    (tmp_path / "noomesh.yaml").write_text("addons: {}\n")
    r = _body(tmp_path, "", "", rc=64)
    assert r.returncode == 0 and r.stderr == "", r.stderr
    (tmp_path / "noomesh.yaml").unlink()
    r = _body(tmp_path, RENDERED, "")
    assert r.returncode == 0 and r.stderr == "", r.stderr
    assert r.stdout.split("\0") == ["", ""]


def test_compose_mounts_the_one_file_on_the_gateway_with_one_pointer() -> None:
    p = full_projection()
    assert p["secrets"]["noo_systems_secrets"]["x-noo-source"] == "NOO_SYSTEMS_SECRETS"
    gw = p["services"]["gateway"]
    entries = [s for s in gw["secrets"] if isinstance(s, dict) and s["source"] == "noo_systems_secrets"]
    assert entries and entries[0]["target"] == "noo_systems_secrets"
    assert env_of(gw)["NOO_SYSTEMS_SECRETS_FILE"] == "${NOO_SYSTEMS_SECRETS:+/run/secrets/noo_systems_secrets}"
    others = [n for n, s in p["services"].items() if n != "gateway" and any(
        (e.get("source") if isinstance(e, dict) else e) == "noo_systems_secrets" for e in s.get("secrets") or []
    )]
    assert not others, f"only the gateway (the broker) takes the systems file: {others}"


def test_a_disabled_system_gets_its_flag_but_never_its_passwords(tmp_path: Path) -> None:
    """Least privilege: only a system that is ON has its passwords delivered.
    Its flag is delivered either way, so the broker logs "disabled" rather
    than "never told". On old code (4 columns, no gating) every declared
    system's passwords reached the gateway."""
    (tmp_path / "noomesh.yaml").write_text(MANIFEST)
    rendered = (
        "flagged_off NOO_OFF_FLAG NOO_OFF_PW NOO_OFF_DDL -\n"
        "flagged_on NOO_ON_FLAG NOO_ON_PW NOO_ON_DDL -\n"
        "always - NOO_ALWAYS_PW NOO_ALWAYS_DDL -\n"
        "addon_off - NOO_ADDOFF_PW NOO_ADDOFF_DDL off\n"
        "addon_on NOO_STALE_FLAG NOO_ADDON_PW NOO_ADDON_DDL on\n"
    )
    values = {k: f"{SECRET_MARK}{k.lower()}" for k in (
        "NOO_OFF_PW", "NOO_OFF_DDL", "NOO_ON_PW", "NOO_ON_DDL", "NOO_ALWAYS_PW", "NOO_ALWAYS_DDL",
        "NOO_ADDOFF_PW", "NOO_ADDOFF_DDL", "NOO_ADDON_PW", "NOO_ADDON_DDL",
    )}
    r = _body(tmp_path, rendered, "NOO_OFF_FLAG=0\nNOO_ON_FLAG=Yes\nNOO_STALE_FLAG=0\n", extra=values)
    assert r.returncode == 0, r.stderr
    got = dict(line.split("=", 1) for line in r.stdout.split("\0")[0].splitlines())
    assert got == {
        "NOO_OFF_FLAG": "0",
        "NOO_ON_FLAG": "Yes",
        "NOO_ON_PW": values["NOO_ON_PW"],
        "NOO_ON_DDL": values["NOO_ON_DDL"],
        "NOO_ALWAYS_PW": values["NOO_ALWAYS_PW"],
        "NOO_ALWAYS_DDL": values["NOO_ALWAYS_DDL"],
        # an add-on's switch is addons.<name>; a stale flag neither enables
        # nor disables it (the broker ignores it the same way)
        "NOO_STALE_FLAG": "0",
        "NOO_ADDON_PW": values["NOO_ADDON_PW"],
        "NOO_ADDON_DDL": values["NOO_ADDON_DDL"],
    }, got
