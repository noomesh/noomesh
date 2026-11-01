# SPDX-License-Identifier: AGPL-3.0-only
# Copyright 2026 PersonifAI LLC

"""The launcher's secrets loader never exports CLI-only secrets.

`NOO_ADDON_REGISTRY_TOKEN` (the controller's read token for the licensed add-on
packages) is read by the noo CLI from the encrypted store itself; no container
holds it. `scripts/lib-secrets.sh::_load_secrets_sops` exports every other
store key into the launcher's environment, which compose and every child
inherit, so it must skip this one. Exercised for real with a fake `sops`."""

from __future__ import annotations

import os
import re
import stat
import subprocess
from pathlib import Path

REPO = Path(__file__).resolve().parents[1]


def test_cli_only_secrets_are_not_exported(tmp_path):
    bindir = tmp_path / "bin"
    bindir.mkdir()
    sops = bindir / "sops"
    sops.write_text(
        "#!/bin/sh\n"
        "printf 'POSTGRES_PASSWORD=pg\\nNOO_ADDON_REGISTRY_TOKEN=ghp_secret\\n"
        "NOO_ADDON_REGISTRY_USER=bot\\nNOO_IMAGE_TAG=v0.0.1\\n"
        "NOO_ADDON_REGISTRY_CRED_RHADDON=tp\\n'\n"
    )
    sops.chmod(sops.stat().st_mode | stat.S_IEXEC)
    (tmp_path / "secrets").mkdir()
    (tmp_path / "secrets" / "env.sops").write_text("x")
    script = f"""
cd {tmp_path}
. {REPO}/scripts/lib-secrets.sh
_load_secrets_sops >/dev/null
env | grep -E '^(POSTGRES_PASSWORD|NOO_ADDON_REGISTRY_TOKEN|NOO_ADDON_REGISTRY_USER|NOO_IMAGE_TAG|NOO_ADDON_REGISTRY_CRED_[A-Z_]*)=' | sort
"""
    env = {"PATH": f"{bindir}:{os.environ['PATH']}", "HOME": str(tmp_path)}
    r = subprocess.run(["bash", "-c", script], env=env, capture_output=True, text=True)
    assert r.returncode == 0, r.stderr
    assert r.stdout.split() == ["POSTGRES_PASSWORD=pg"], r.stdout


def test_the_skip_list_covers_every_cli_only_registry_row():
    rs = (REPO / "noo-cli/src/commands/secrets.rs").read_text()
    m = re.search(r"CLI_ONLY_SECRETS: &\[&str\] = &\[([^\]]*)\]", rs)
    assert m, "CLI_ONLY_SECRETS not found"
    cli_only = re.findall(r'"([A-Z0-9_]+)"', m.group(1))
    assert cli_only, "parsed no CLI_ONLY_SECRETS"
    sh = (REPO / "scripts/lib-secrets.sh").read_text()
    m = re.search(r'^_SECRETS_NOT_EXPORTED="([^"]*)"', sh, re.M)
    assert m, "_SECRETS_NOT_EXPORTED not found"
    skipped = m.group(1).split()
    for k in cli_only:
        assert k in skipped, f"{k} is CLI-only but lib-secrets.sh exports it"
