# SPDX-License-Identifier: AGPL-3.0-only
# Copyright 2026 PersonifAI LLC

"""Each add-on's NATS principal is granted exactly the subjects it serves (i70 residue).

Three sources say which add-on owns a `worker.*` subject, in three places and
two languages:

- the gateway routes on `addons::is_trellion_subject` /
  `is_trellion_intel_subject` (and picks the reply prefix from them);
- noo-cli renders each add-on principal's subscribe grant from
  `ADDON_PRINCIPALS` (and denies the same subjects to the worker);
- the Python surfaces register the handlers (`@worker_handler`) that a
  container actually serves (`NOO_WORKER_SURFACES=ml` / `ml-intel`).

If they drift, a subject is served by a container whose principal may not
subscribe it — silently: a denied subscription is an asynchronous error the
pool never surfaces, and the gateway reads "no responders".
"""

import re
from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parent.parent
GRANTS = ROOT / "noo-cli/src/commands/nats_users.rs"
ADDONS_RS = ROOT / "gateway-rust/src/addons.rs"
WORKERS = ROOT / "src/noomesh/workers"
TRELLION_COMPOSE = ROOT / "docker-compose.trellion.yml"

#: The trellion-intel package's own surfaces, registered through its
#: `noomesh.worker_surfaces` entry points (personifAI/trellion-intel
#: pyproject.toml: `ml-intel:console-piece`, `ml-intel:retrieval`).
INTEL_ENTRY_POINT_SUBJECTS = ("worker.graph.console_piece", "worker.retrieval.feedback")


def _grants() -> dict[str, list[str]]:
    out = {}
    for m in re.finditer(r'AddonPrincipal \{\s*name: "([a-z_]+)",.*?subjects: &\[(.*?)\],', GRANTS.read_text(), re.S):
        out[m.group(1)] = re.findall(r'"([^"]+)"', m.group(2))
    assert set(out) == {"trellion", "trellion_intel"}, out
    return out


def _matches(pattern: str, subject: str) -> bool:
    """NATS wildcard semantics: `*` one token, `>` one or more trailing tokens."""
    p, s = pattern.split("."), subject.split(".")
    for i, tok in enumerate(p):
        if tok == ">":
            return len(s) > i
        if i >= len(s) or (tok != "*" and tok != s[i]):
            return False
    return len(p) == len(s)


def _handlers(modules) -> list[str]:
    out = []
    for m in modules:
        for f in [WORKERS / f"{m}.py", *sorted((WORKERS / m).glob("*.py"))]:
            if f.is_file():
                out += re.findall(r'^@worker_handler\("([^"]+)"\)', f.read_text(), re.M)
    return out


def _surface(name: str) -> tuple[str, ...]:
    text = (WORKERS / "__init__.py").read_text()
    m = re.search(rf"^{name} = \((.*?)\)", text, re.M | re.S)
    assert m, name
    return tuple(re.findall(r'"([a-z_]+)"', m.group(1)))


def _owner(grants, subject):
    owners = [a for a, pats in grants.items() if any(_matches(p, subject) for p in pats)]
    assert len(owners) <= 1, f"{subject} is granted to two add-ons: {owners}"
    return owners[0] if owners else None


def test_wildcards_mean_what_nats_means():
    assert _matches("worker.rag.>", "worker.rag.query")
    assert _matches("worker.rag.>", "worker.rag.a.b")
    assert not _matches("worker.rag.>", "worker.rag")
    assert not _matches("worker.autonomy.check_rag", "worker.autonomy.check")
    assert _matches("agent.peer.*.task.*", "agent.peer.x.task.y")


def test_every_subject_a_surface_serves_is_its_principals():
    grants = _grants()
    trellion = _handlers(_surface("_ML_MODULES"))
    intel = _handlers(_surface("_ML_INTEL_MODULES")) + list(INTEL_ENTRY_POINT_SUBJECTS)
    core = _handlers(_surface("_CORE_MODULES"))
    assert len(trellion) >= 20 and len(intel) >= 10 and core, (len(trellion), len(intel), len(core))
    for s in trellion:
        assert _owner(grants, s) == "trellion", f"noo-trellion serves {s} but its principal may not subscribe it"
    for s in intel:
        assert _owner(grants, s) == "trellion_intel", f"noo-trellion-intel serves {s} but its principal may not subscribe it"
    for s in core:
        assert _owner(grants, s) is None, f"the core worker serves {s}, which an add-on grant claims"


def test_the_grants_are_the_gateways_ownership_predicates():
    # The gateway decides which prefix a reply goes to by these predicates;
    # the grant is the same set as NATS wildcards, family for family.
    text = ADDONS_RS.read_text()
    t = re.search(r"pub fn is_trellion_subject.*?\n}\n", text, re.S).group(0)
    i = re.search(r"pub fn is_trellion_intel_subject.*?\n}\n", text, re.S).group(0)

    def as_grants(body):
        prefixes = re.findall(r'"(worker\.[a-z_.]+\.)"', body)
        exact = re.findall(r'subject == "([^"]+)"', body)
        return sorted([p + ">" for p in prefixes] + exact)

    grants = _grants()
    assert as_grants(t) == sorted(grants["trellion"]), (as_grants(t), grants["trellion"])
    assert as_grants(i) == sorted(grants["trellion_intel"]), (as_grants(i), grants["trellion_intel"])


def test_names_agree_across_the_cli_gateway_and_python():
    grants = _grants()
    addons = re.findall(r'name: "([a-z_]+)"', re.search(r"pub const ADDONS.*?\n\];", ADDONS_RS.read_text(), re.S).group(0))
    for name in grants:
        assert name in addons, f"{name} is not an add-on key the gateway knows"
    py = (ROOT / "src/noomesh/cluster/messaging.py").read_text()
    m = re.search(r"^ADDON_PRINCIPALS = \((.*?)\)", py, re.M)
    assert m and tuple(re.findall(r'"([a-z_]+)"', m.group(1))) == tuple(grants), "messaging.ADDON_PRINCIPALS"
    rs = GRANTS.read_text()
    for name in grants:
        assert f'secret_key: "NATS_{name.upper()}_PASSWORD"' in rs, name


def test_the_trellion_overlay_delivers_its_own_principal_by_file():
    text = TRELLION_COMPOSE.read_text()
    doc = yaml.safe_load(text)
    assert doc["x-noo-addon"]["nats_principal"] == "trellion"
    src = doc["secrets"]["nats_trellion_password"]
    assert src["x-noo-source"] == "NATS_TRELLION_PASSWORD"
    assert src["file"].endswith("}/nats_trellion_password"), "a file: secret under the launcher's NOO_SECRET_RUNDIR (the service is read_only)"
    svc = doc["services"]["trellion"]
    env = svc["environment"]
    # A literal: an env value may name a secret only as a `_FILE` pointer.
    assert env["NATS_ADDON_USER"] == "trellion"
    assert env["NATS_ADDON_PASSWORD_FILE"] == "${NATS_TRELLION_PASSWORD:+/run/secrets/nats_addon_password}"
    assert "NATS_ADDON_PASSWORD" not in env, "a password is a FILE, never env"
    secrets = {s["target"]: s["source"] for s in svc["secrets"]}
    assert secrets["nats_addon_password"] == "nats_trellion_password"
    # On the SERVICE, not the shared anchor trellion-intel also extends: an
    # add-on's own principal is overridden per add-on, like its bus key.
    anchor = doc["x-trellion-env"]
    assert anchor and not [k for k in anchor if k.startswith("NATS_ADDON_")], "NATS_ADDON_* belongs on the service"
