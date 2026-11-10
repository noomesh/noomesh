# SPDX-License-Identifier: AGPL-3.0-only
# Copyright 2026 PersonifAI LLC

"""The Linux harness reads its CA and pair as systemd credentials (finding 116).

On pop-os (0.6.20) the harness restart-looped with NATS "CertificateRequired":
it runs as noo-harness, in no group but its own (i119), and /etc/noo/pki is
0750 root:noo-agent, so it could reach neither the CA nor its own pair. The
operator refused to loosen those modes. Instead:

  * noo-harness.service loads three credentials (`LoadCredential=`): the CA
    and the harness's own copy of the node pair. systemd reads them as root
    at START and exposes them only to that service, in
    /run/credentials/noo-harness.service.
  * provision renders NOO_TLS_CA/CERT/KEY into that directory on Linux. The
    env file must carry them: EnvironmentFile= overrides Environment=, so the
    unit cannot set them with %d.
  * the applier restarts the harness when the CA or its pair changes, because
    credentials are read only at start.
  * the unit and the env ship in the SAME bundle (provision's attach_harness,
    both from this CLI's embedded assets), and the applier daemon-reloads
    BEFORE it restarts the harness: never a new env under the old unit.

SECURITY and reliability tests; each has a mutant that turns it red.
"""

from __future__ import annotations

import re
from pathlib import Path

REPO = Path(__file__).resolve().parents[1]
UNIT = (REPO / "node-agent-go/deploy/noo-harness.service").read_text()
ENV_TMPL = (REPO / "node-agent-go/deploy/noo-harness.env.tmpl").read_text()
APPLY = (REPO / "scripts/noo-apply.sh").read_text()
PROVISION = (REPO / "noo-cli/src/commands/provision.rs").read_text()
BUILD_RS = (REPO / "noo-cli/build.rs").read_text()
CRED_DIR = "/run/credentials/noo-harness.service"


def _lines(text: str) -> list[str]:
    return [l.strip() for l in text.splitlines() if l.strip() and not l.strip().startswith("#")]


def _const(name: str) -> str:
    m = re.search(rf'pub\(crate\) const {name}: &str = "([^"]*)";', PROVISION)
    assert m, f"provision.rs has no {name}"
    return m.group(1)


def test_the_unit_loads_exactly_the_ca_and_the_harness_pair() -> None:
    creds = [l for l in _lines(UNIT) if l.startswith("LoadCredential")]
    assert creds == [
        "LoadCredential=ca.crt:/etc/noo/pki/ca.crt",
        "LoadCredential=node.crt:/etc/noo/pki/harness/node.crt",
        "LoadCredential=node.key:/etc/noo/pki/harness/node.key",
    ], creds
    assert not any(l.startswith(("SetCredential", "ImportCredential")) for l in _lines(UNIT))
    assert "/etc/noo/pki/nodes" not in " ".join(creds), "never the agent's pair"


def test_the_env_points_into_the_units_credentials_directory() -> None:
    """The env's paths are the files the unit loads, by name, in this unit's
    credentials directory; and the template names them through the harness
    vars, never the agent's."""
    assert _const("HARNESS_TLS_CA") == f"{CRED_DIR}/ca.crt"
    assert _const("HARNESS_TLS_CERT") == f"{CRED_DIR}/node.crt"
    assert _const("HARNESS_TLS_KEY") == f"{CRED_DIR}/node.key"
    loaded = {l.split("=", 1)[1].split(":", 1)[0] for l in _lines(UNIT) if l.startswith("LoadCredential=")}
    for c in ("HARNESS_TLS_CA", "HARNESS_TLS_CERT", "HARNESS_TLS_KEY"):
        assert _const(c).rsplit("/", 1)[1] in loaded, f"{c} names a credential the unit does not load"
    body = [l for l in ENV_TMPL.splitlines() if l.startswith("NOO_TLS_")]
    assert body == ["NOO_TLS_CA={{ harness_tls_ca }}", "NOO_TLS_CERT={{ harness_tls_cert }}", "NOO_TLS_KEY={{ harness_tls_key }}"], body
    assert 'hvars.insert("harness_tls_ca", harness_tls_ca(darwin, vars));' in PROVISION


def test_nothing_in_the_change_widens_the_pki_path() -> None:
    """The operator's condition: /etc/noo and /etc/noo/pki keep their modes.
    No chmod in the unit, the template or provision's harness code; the
    applier's one existing chmod (on a CA change) is not joined by another."""
    for name, text in (("unit", UNIT), ("env template", ENV_TMPL)):
        assert "chmod" not in text, f"the harness {name} changes a mode"
    # Every chmod whose target is /etc/noo or $PKI ITSELF (not a file or
    # directory below them): only the one that predates this change.
    own = [l.strip() for l in APPLY.splitlines()
           if re.search(r'chmod\b[^\n;]*\s(?:/etc/noo|"?\$PKI"?|/etc/noo/pki)(?=[\s;]|$)', l) and not l.lstrip().startswith("#")]
    assert len(own) == 1 and 'chmod 755 /etc/noo "$PKI"' in own[0], f"a chmod of the PKI path was added: {own}"
    assert not re.search(r"chmod -R[^\n]*(/etc/noo|\$PKI)", APPLY), "a recursive chmod of the PKI path"
    harness_fns = PROVISION[PROVISION.index("fn harness_tls_paths"):]
    harness_fns = harness_fns[: harness_fns.index("#[cfg(test)]")]
    assert "chmod" not in harness_fns


def test_the_applier_restarts_the_harness_when_its_ca_or_pair_changes() -> None:
    """Credentials are copied at START: a renewed CA or leaf reaches the
    harness only through a restart."""
    ca_line = next(l for l in APPLY.splitlines() if 'install -m 644 -o root -g noo-agent "$WORK/files/ca.crt"' in l)
    assert "need_harness_restart=1" in ca_line, ca_line
    pair = APPLY[APPLY.index("# harness-pair"):]
    pair = pair[: pair.index("# vendor-cli")]
    assert re.search(r'install -m 640 -o root -g noo-harness "\$PKI/nodes/\$NODE_ID/\$_nk" "\$PKI/harness/\$_nk"\n\s+applied="\$applied harness-\$_nk"; need_harness_restart=1', pair), pair


def test_the_unit_and_its_env_arrive_together_and_reload_precedes_the_restart() -> None:
    """No skew: the Linux branch of attach_harness stages harness-env and
    harness-unit together, both from this CLI's embedded assets (the unit is
    the file that carries LoadCredential=); the applier daemon-reloads before
    it restarts the harness, and a changed unit asks for both."""
    m = re.search(r'files\.push\(\("harness-env", henv\.into_bytes\(\)\)\);\n\s+if darwin \{.*?\} else \{\n\s+files\.push\(\("harness-unit", super::enroll::asset_harness_unit\(\)', PROVISION, re.S)
    assert m, "harness-env and harness-unit are no longer staged together on Linux"
    assert '("ASSET_HARNESS_UNIT", "node-agent-go/deploy/noo-harness.service")' in BUILD_RS
    reload = APPLY.index('[ "$need_daemon_reload" = 1 ] && systemctl daemon-reload')
    restart = APPLY.index("    systemctl restart noo-harness\n")
    assert reload < restart, "the harness would restart under the old unit"
    unit_block = APPLY[APPLY.index('if [ -f "$WORK/files/harness-unit" ]'):]
    unit_block = unit_block[: unit_block.index("# harness-pair")]
    assert 'applied="$applied harness-unit"; need_daemon_reload=1; need_harness_restart=1' in unit_block


def test_the_harness_joins_no_other_group() -> None:
    lines = _lines(UNIT)
    assert "User=noo-harness" in lines and "Group=noo-harness" in lines
    assert not any(l.startswith("SupplementaryGroups") for l in lines), "the harness was added to another group"
    assert not any(l.startswith(("DynamicUser", "PrivilegedMode")) for l in lines)


def test_a_node_whose_applier_predates_the_unit_still_takes_it_whole() -> None:
    """The skew case: the applier pins the harness unit by sha256, so an OLD
    applier would refuse the new unit. Every Linux bundle carries the applier,
    and the applier updates itself FIRST (§1b) and re-runs the bundle, so the
    unit, its env and the applier that accepts the unit arrive and apply
    together. The pin is the shipped unit's sum (test_apply_env_unit_shape)."""
    m = re.search(r"fn attach_applier_and_fetcher\(.*?\n\}\n", PROVISION, re.S)
    assert m, "attach_applier_and_fetcher is gone"
    body = m.group(0)
    assert "if !darwin {" in body and 'files.push(("applier", apply.as_bytes().to_vec()));' in body
    assert APPLY.index("# ── 1b. Applier self-update comes FIRST") < APPLY.index("unit_payload_ok() {")
    first_use = min(m.start() for m in re.finditer(r"unit_payload_ok \"", APPLY))
    assert APPLY.index("# ── 1b. Applier self-update comes FIRST") < first_use
