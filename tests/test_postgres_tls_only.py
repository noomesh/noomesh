# SPDX-License-Identifier: AGPL-3.0-only
# Copyright 2026 PersonifAI LLC

"""Postgres accepts only TLS connections that present a cluster-CA client
certificate, and every client is shaped to make one (2026-09-28, "ensure
full TLS coverage, anything plaintext").

Before this: `ssl=on` hung on `NOO_PG_TLS` being set, the pg_hba initdb
wrote accepted non-SSL `host` lines and trusted loopback, and every client
connected with `verify-ca` and no client certificate. Four things now hold,
each pinned here with a planted negative so the checker itself is known to
bite:

1. The shipped policy `docker/postgres/pg_hba.conf`: no TCP rule accepts a
   client without TLS; every `hostssl` rule requires `clientcert=verify-ca`
   AND a password; plaintext is `hostnossl … reject`ed explicitly; only the
   unix socket (docker exec) is `trust`.
2. The postgres service runs with that file (`-c hba_file=`), `ssl=on`
   unconditionally, and no `NOO_PG_TLS` switch — nor does any other
   service receive one.
3. Every Postgres DSN a container receives (the composed projection, every
   overlay) carries `sslmode=verify-full` (or `verify-ca`), `sslrootcert`,
   `sslcert` and `sslkey`, and the certificate it names is one that
   service actually mounts — the controller leaf for the controller's own
   process (the gateway), `services/evolve` for evolve, `services/worker`
   for noo-worker and worker-extra, and `services/trellion` /
   `services/trellion-intel` for the trellion add-ons.
4. The policy file is in noo-cli's standalone manifest, so an install that
   has no checkout still ships it (the service refuses to start without it).

The Rust half — `noo cluster verify --controller` reads the same file and
probes the live server — is `postgres_hba_check` / `postgres_client_cert_check`
in noo-cli/src/commands/cluster_verify.rs.
"""

from __future__ import annotations

import re
from pathlib import Path
from urllib.parse import parse_qs, urlsplit

import pytest

from tests._compose_projection import env_of, full_projection, load_raw, untag

ROOT = Path(__file__).resolve().parents[1]
HBA = ROOT / "docker" / "postgres" / "pg_hba.conf"
COMPOSE = ROOT / "docker-compose.cluster.yml"
COMPOSE_FILES = sorted(ROOT.glob("docker-compose*.yml"))

SECURE_SSLMODES = {"verify-ca", "verify-full"}
CLIENT_CERT_REQUIRED = {"clientcert=verify-ca", "clientcert=verify-full"}


# ── 1. the shipped pg_hba ────────────────────────────────────────────────


def hba_rules(text: str) -> list[list[str]]:
    rules = []
    for line in text.splitlines():
        code = line.split("#", 1)[0].strip()
        if code:
            rules.append(code.split())
    return rules


def hba_problems(text: str) -> list[str]:
    """Every way the policy could accept a client it must not."""
    rules = hba_rules(text)
    problems = []
    if not rules:
        return ["no rules at all"]
    for r in rules:
        kind = r[0]
        if kind in ("host", "hostgssenc"):
            problems.append(f"accepts a TCP client without TLS: {' '.join(r)}")
        elif kind == "hostnossl":
            if len(r) < 5 or r[4] != "reject":
                problems.append(f"a plaintext rule that is not reject: {' '.join(r)}")
        elif kind == "hostssl":
            method = r[4] if len(r) > 4 else ""
            if method == "trust" or not method:
                problems.append(f"a TLS rule without a password: {' '.join(r)}")
            if not any(f in CLIENT_CERT_REQUIRED for f in r):
                problems.append(f"a TLS rule that does not require a cluster-CA client certificate: {' '.join(r)}")
        elif kind == "local":
            continue
        else:
            problems.append(f"unknown rule type: {' '.join(r)}")
    if not any(r[0] == "hostssl" and r[1] == "all" and r[2] == "all" for r in rules):
        problems.append("no `hostssl all all …` rule — no client could connect")
    if not any(r[0] == "hostnossl" and r[1] == "all" and r[2] == "all" and r[-1] == "reject" for r in rules):
        problems.append("plaintext is not rejected explicitly (`hostnossl all all all reject`)")
    return problems


def test_the_shipped_pg_hba_is_tls_and_client_cert_only():
    text = HBA.read_text()
    assert len(hba_rules(text)) >= 4, "the parser found almost nothing — is the file empty?"
    assert hba_problems(text) == []


def test_the_hba_checker_catches_each_weakening():
    text = HBA.read_text()
    # what initdb writes: loopback trust over plain TCP
    assert any("without TLS" in p for p in hba_problems(text + "\nhost all all 127.0.0.1/32 trust\n"))
    # TLS but no certificate required
    assert any("client certificate" in p for p in hba_problems(text.replace("clientcert=verify-ca", "")))
    # certificate but no password
    weak = text.replace("scram-sha-256   clientcert=verify-ca", "trust clientcert=verify-ca")
    assert any("without a password" in p for p in hba_problems(weak))
    # plaintext merely unmatched instead of rejected
    no_reject = "\n".join(l for l in text.splitlines() if not l.startswith("hostnossl all"))
    assert any("not rejected explicitly" in p for p in hba_problems(no_reject))
    # a plaintext rule that accepts
    assert any("not reject" in p for p in hba_problems(text + "\nhostnossl all all all scram-sha-256\n"))
    assert hba_problems("") == ["no rules at all"]


# ── 2. the postgres service runs with it, unconditionally ───────────────


def _code_lines(script: str) -> list[str]:
    return [l for l in script.splitlines() if l.split("#", 1)[0].strip()]


def postgres_service_problems(svc: dict) -> list[str]:
    problems = []
    vols = [v if isinstance(v, str) else f"{v.get('source')}:{v.get('target')}" for v in svc.get("volumes") or []]
    if not any(v.startswith("./docker/postgres/pg_hba.conf:/etc/noo/pg_hba.conf") or v.endswith("/docker/postgres/pg_hba.conf:/etc/noo/pg_hba.conf") or "/docker/postgres/pg_hba.conf:/etc/noo/pg_hba.conf:" in v for v in vols):
        problems.append("docker/postgres/pg_hba.conf is not mounted at /etc/noo/pg_hba.conf")
    cmd = svc.get("command") or []
    script = "\n".join(cmd if isinstance(cmd, list) else [cmd])
    code = "\n".join(_code_lines(script))
    if "hba_file=/etc/noo/pg_hba.conf" not in code:
        problems.append("the command does not select the shipped file (-c hba_file=/etc/noo/pg_hba.conf)")
    if "-c ssl=on" not in code:
        problems.append("the command does not turn ssl on")
    if "NOO_PG_TLS" in code:
        problems.append("ssl=on is conditional on NOO_PG_TLS")
    # ssl=on must not sit inside an `if` on anything: the only conditionals
    # allowed are the fail-closed refusals (exit 1).
    for line in _code_lines(script):
        if "ssl=on" in line and line.strip().startswith(("if ", "elif ")):
            problems.append(f"ssl=on is conditional: {line.strip()}")
    if "NOO_PG_TLS" in {k for k in (svc.get("environment") or {})} if isinstance(svc.get("environment"), dict) else any(str(e).startswith("NOO_PG_TLS") for e in (svc.get("environment") or [])):
        problems.append("the service still receives NOO_PG_TLS")
    return problems


def test_the_postgres_service_runs_the_shipped_policy_with_tls_always_on():
    raw = untag(load_raw(COMPOSE))["services"]["postgres"]
    assert postgres_service_problems(raw) == []
    projected = full_projection()["services"]["postgres"]
    assert postgres_service_problems(projected) == []


def test_the_service_checker_catches_each_weakening():
    raw = untag(load_raw(COMPOSE))["services"]["postgres"]
    good = "\n".join(raw["command"])
    assert "hba_file" in good and "ssl=on" in good, "the parser did not find the command it checks"

    def with_command(script: str) -> dict:
        return {**raw, "command": [script]}

    assert any("hba_file" in p for p in postgres_service_problems(with_command(good.replace("-c hba_file=/etc/noo/pg_hba.conf", ""))))
    conditional = good.replace('ARGS="$$ARGS -c ssl=on', 'if [ -n "$$NOO_PG_TLS" ]; then ARGS="$$ARGS -c ssl=on')
    assert any("NOO_PG_TLS" in p or "conditional" in p for p in postgres_service_problems(with_command(conditional)))
    assert any("ssl on" in p for p in postgres_service_problems(with_command(good.replace("-c ssl=on", ""))))
    no_mount = {**raw, "volumes": [v for v in raw["volumes"] if "pg_hba" not in v]}
    assert any("not mounted" in p for p in postgres_service_problems(no_mount))
    with_switch = {**raw, "environment": {**raw["environment"], "NOO_PG_TLS": "${NOO_PG_TLS:-}"}}
    assert any("receives NOO_PG_TLS" in p for p in postgres_service_problems(with_switch))


def test_no_service_receives_a_pg_tls_switch():
    services = full_projection()["services"]
    assert len(services) > 10, "the projection is suspiciously small"
    holders = sorted(name for name, svc in services.items() if "NOO_PG_TLS" in env_of(svc))
    assert holders == [], f"NOO_PG_TLS is an opt-out that no longer exists; drop it from: {holders}"


_SWITCH = re.compile(r"\$\{?NOO_PG_TLS\b|^\s*NOO_PG_TLS\s*[=:]|\(\"NOO_PG_TLS\",", re.M)
# The detectors themselves, and their planted negatives, name the switch on
# purpose. Nothing else may.
_DETECTORS = {"noo-cli/src/commands/cluster_verify.rs"}


def test_no_pg_tls_opt_out_is_declared_anywhere():
    """Not in compose, not written by onboard, not offered by an example
    file. A comment may still name it as history; a declaration may not."""
    files = [*COMPOSE_FILES, ROOT / ".env.example", ROOT / "noomesh.yaml.example",
             *sorted((ROOT / "noo-cli" / "src").rglob("*.rs")),
             *sorted((ROOT / "scripts").glob("*.sh")),
             *sorted((ROOT / "src" / "noomesh").rglob("*.py"))]
    assert len(files) > 50, "the sweep found almost nothing"
    hits = []
    for f in files:
        if str(f.relative_to(ROOT)) in _DETECTORS:
            continue
        for i, line in enumerate(f.read_text(errors="replace").splitlines(), 1):
            code = line.split("#", 1)[0] if f.suffix in (".yml", ".sh", ".py", ".example") else line.split("//", 1)[0]
            if _SWITCH.search(code):
                hits.append(f"{f.relative_to(ROOT)}:{i}: {line.strip()}")
    assert hits == [], "\n".join(hits)
    # the pattern itself, planted
    assert _SWITCH.search('      - NOO_PG_TLS=${NOO_PG_TLS:-}')
    assert _SWITCH.search('        ("NOO_PG_TLS", "true".into()),')
    assert _SWITCH.search('if [ -n "$$NOO_PG_TLS" ]')
    assert not _SWITCH.search("# Until 2026-09-28 ssl=on hung on NOO_PG_TLS")


# ── 3. every DSN presents a certificate the service holds ───────────────


def _mount_targets(svc: dict) -> set[str]:
    out = set()
    for v in svc.get("volumes") or []:
        if isinstance(v, str):
            # `${NOO_PKI_DIR:-./.pki-placeholder}/ca.crt:/app/pki/ca.crt:ro`
            # — the source may hold `:`; the target never does.
            spec = re.sub(r":(ro|rw|z|Z)$", "", v)
            if ":" in spec:
                out.add(spec.rsplit(":", 1)[1])
        elif isinstance(v, dict) and v.get("target"):
            out.add(v["target"])
    return out


def dsn_problems(name: str, svc: dict) -> tuple[list[str], int]:
    """(problems, dsns seen) for one service's environment."""
    problems, seen = [], 0
    targets = _mount_targets(svc)
    for key, value in env_of(svc).items():
        if not re.match(r"postgres(ql)?(\+\w+)?://", value or ""):
            continue
        seen += 1
        q = {k: v[-1] for k, v in parse_qs(urlsplit(value).query).items()}
        mode = q.get("sslmode", "")
        if mode not in SECURE_SSLMODES:
            problems.append(f"{name}: {key} sslmode={mode or '(none → libpq prefer, downgradeable)'}")
        for param in ("sslrootcert", "sslcert", "sslkey"):
            if not q.get(param):
                problems.append(f"{name}: {key} carries no {param}")
        cert, root = q.get("sslcert", ""), q.get("sslrootcert", "")
        if cert and not any(cert == t or cert.startswith(t.rstrip("/") + "/") for t in targets):
            problems.append(f"{name}: {key} names sslcert={cert}, which this service does not mount (targets: {sorted(targets)})")
        if root and not any(root == t or root.startswith(t.rstrip("/") + "/") for t in targets):
            problems.append(f"{name}: {key} names sslrootcert={root}, which this service does not mount")
        if cert and q.get("sslkey", "") and Path(q["sslkey"]).parent != Path(cert).parent:
            problems.append(f"{name}: {key} cert and key are from different leaves: {cert} / {q['sslkey']}")
    return problems, seen


def test_every_dsn_in_the_composed_stack_presents_a_mounted_certificate():
    services = full_projection()["services"]
    problems, seen = [], 0
    for name, svc in sorted(services.items()):
        p, n = dsn_problems(name, svc)
        problems += p
        seen += n
    # gateway 3, worker 2 (+ worker-extra 2), trellion 5
    assert seen >= 12, f"only {seen} DSNs found — the sweep is broken"
    assert problems == [], "\n".join(problems)


def test_every_compose_file_as_written_carries_the_transport():
    # The overlay text itself, not only the projection: a site copy of an
    # overlay is read on its own, and a DSN in an `x-` anchor is still a DSN.
    seen = 0
    for path in COMPOSE_FILES:
        for m in re.finditer(r"postgres(?:ql)?://[^\s'\"]+", path.read_text()):
            seen += 1
            q = {k: v[-1] for k, v in parse_qs(urlsplit(m.group(0)).query).items()}
            assert q.get("sslmode") in SECURE_SSLMODES, f"{path.name}: {m.group(0)[:60]}…"
            for param in ("sslrootcert", "sslcert", "sslkey"):
                assert q.get(param), f"{path.name}: no {param} in {m.group(0)[:60]}…"
    # cluster 5 + trellion 5 (the licensed add-ons' overlays left core, N6)
    assert seen >= 10, f"only {seen} DSN literals across the compose files"


def test_the_dsn_checker_catches_each_gap():
    svc = {
        "environment": {},
        "volumes": ["${NOO_PKI_DIR:-./.pki-placeholder}/ca.crt:/app/pki/ca.crt:ro",
                    "${NOO_PKI_DIR:-./.pki-placeholder}/gateway:/app/pki/gateway:ro"],
    }
    full = ("postgresql://u:p@postgres:5432/db?options=-c%20search_path%3Dmesh&sslmode=verify-full"
            "&sslrootcert=/app/pki/ca.crt&sslcert=/app/pki/gateway/gateway.crt&sslkey=/app/pki/gateway/gateway.key")
    assert dsn_problems("s", {**svc, "environment": {"DATABASE_URL": full}}) == ([], 1)
    cases = {
        "no sslmode": full.replace("&sslmode=verify-full", ""),
        "require only": full.replace("verify-full", "require"),
        "no sslcert": full.replace("&sslcert=/app/pki/gateway/gateway.crt", ""),
        "no sslkey": full.replace("&sslkey=/app/pki/gateway/gateway.key", ""),
        "no sslrootcert": full.replace("&sslrootcert=/app/pki/ca.crt", ""),
        "a leaf the service does not mount": full.replace("/app/pki/gateway/", "/tls/services/evolve/"),
        "cert and key from different leaves": full.replace("sslkey=/app/pki/gateway/gateway.key", "sslkey=/tls/services/postgres/service.key"),
    }
    for why, dsn in cases.items():
        problems, n = dsn_problems("s", {**svc, "environment": {"DATABASE_URL": dsn}})
        assert n == 1 and problems, f"{why}: not caught"
    # a value that is not a DSN is not counted
    assert dsn_problems("s", {**svc, "environment": {"X": "sslkey=nothing"}}) == ([], 0)


# ── 4. the standalone install ships the file ────────────────────────────


def test_the_policy_is_in_the_standalone_manifest():
    build = (ROOT / "noo-cli" / "build.rs").read_text()
    assert '"docker/postgres/pg_hba.conf",' in build, (
        "a standalone controller has no checkout; the postgres service refuses to start without this file")
    assert '"docker/redis-entrypoint.sh",' in build, "the manifest the assertion above reads is not where I think it is"


# ── evolve stages the key it presents ───────────────────────────────────
# test_evolve_stages_its_key_and_rewrites_both_dsns: moved with the overlay to
# the add-on repo (N6).


# ── 5. the warm standby streams with its own leaf ──

STANDBY = ROOT / "scripts" / "bootstrap-standby.sh"
STEPS = ROOT / "noo-cli" / "src" / "onboard" / "steps.rs"
PKI_RS = ROOT / "noo-cli" / "src" / "pki.rs"


def _libpq_conninfos(script: str) -> list[str]:
    """Every single-quoted libpq conninfo the script passes (`host=… `)."""
    return re.findall(r"'(host=[^']*)'", script)


def standby_problems(script: str) -> list[str]:
    # Code only: the comments explain what used to be there, by name.
    script = "\n".join(line for line in script.splitlines() if not line.lstrip().startswith("#"))
    problems = []
    infos = _libpq_conninfos(script)
    if not infos:
        return ["no pg_basebackup conninfo found — the checker would pass anything"]
    for info in infos:
        params = dict(kv.split("=", 1) for kv in info.split() if "=" in kv)
        if params.get("sslmode") != "verify-full":
            problems.append(f"conninfo sslmode is {params.get('sslmode')!r}, not verify-full: {info}")
        for k in ("sslrootcert", "sslcert", "sslkey"):
            if k not in params:
                problems.append(f"conninfo has no {k}: {info}")
    if "sslmode=prefer" in script:
        problems.append("sslmode=prefer is still spelled somewhere in the script")
    # primary_conninfo is what -R writes from the backup's conninfo; the
    # staged /tmp paths must be re-pointed into the data volume, and checked.
    if not re.search(r"sed -i 's#/tmp/standby-tls/#\$STANDBY_TLS_DIR/#g'.*postgresql\.auto\.conf", script):
        problems.append("primary_conninfo is not re-pointed at the leaf staged in the data volume")
    if "chmod 600 $STANDBY_TLS_DIR/client.key" not in script:
        problems.append("the staged client key is not 0600")
    # Never append a password-only replication rule again.
    if re.search(r">>\s*'?\$HBA_FILE", script) or re.search(r"\bhost replication\b", script):
        problems.append("the script still appends a password-only `host replication` rule to pg_hba")
    return problems


def test_the_standby_presents_its_own_leaf() -> None:
    problems = standby_problems(STANDBY.read_text())
    assert not problems, "\n".join(problems)


def test_the_standby_checker_bites() -> None:
    """PLANTED: the pre-1238 script shape must be refused on every count."""
    old = STANDBY.read_text().replace(
        "sslmode=verify-full sslrootcert=/tmp/standby-tls/ca.crt sslcert=/tmp/standby-tls/client.crt sslkey=/tmp/standby-tls/client.key",
        "sslmode=prefer",
    )
    old += "\ndocker exec \"$CONTAINER\" sh -c \"echo 'host replication replicator 100.64.0.0/10 scram-sha-256' >> '$HBA_FILE'\"\n"
    problems = standby_problems(old)
    assert any("not verify-full" in p for p in problems), problems
    assert any("no sslcert" in p for p in problems), problems
    assert any("password-only" in p for p in problems), problems


def test_onboard_issues_the_standby_leaf_and_only_the_cli_reads_it() -> None:
    steps = STEPS.read_text()
    svc_list = steps[steps.index("pub(crate) const SVC_LIST") :]
    svc_list = svc_list[: svc_list.index("];")]
    code = "\n".join(line.split("//", 1)[0] for line in svc_list.splitlines())
    assert '"postgres-standby"' in code, "onboard / upgrade never issue services/postgres-standby"
    assert re.search(r'\("postgres-standby",\s*KeyReader::Cli\)', PKI_RS.read_text()), (
        "services/postgres-standby has no Cli reader row: its key would not be 0600 on the primary"
    )
    assert 'STANDBY_LEAF="services/postgres-standby"' in STANDBY.read_text()
