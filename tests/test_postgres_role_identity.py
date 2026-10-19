# SPDX-License-Identifier: AGPL-3.0-only
# Copyright 2026 PersonifAI LLC

"""A Postgres role is reachable only with the client certificate issued for it (i132).

pg_hba used to ask for SOME cluster-CA leaf (`clientcert=verify-ca`) and then
the password, so any leaf on `noo-db` reached scram for any role and the
gateway's leaf logged in as `noo`, `noo_app`, anything. Now every role this
repo's containers connect as has its own leaf whose CN is the role
(`PG_LEAVES` in noo-cli/src/pki.rs, `gateway/pg/<role>.crt`,
`services/<owner>/pg/<role>.crt`), and pg_hba matches it with
`clientcert=verify-full` — the password is still required.

Four things are pinned here:

1. The shipped pg_hba.conf has one `verify-full` line per role in PG_LEAVES,
   ahead of the catch-all, and nothing weaker precedes them except the
   `samehost` probe line (a process inside the postgres container, which
   `noo security secrets rotate` uses to prove a rotated password).
2. Every DSN in the composed stack names, for its user, the leaf issued for
   that user and mounted in that container; a role with a `verify-full` rule
   never presents a service or gateway leaf.
3. The compose mounts and the PG_LEAVES owners agree (so the leaf exists
   where the DSN points).
4. The hba file against a REAL Postgres (skipped, loudly, when the image or
   docker is not present): a leaf for one role cannot log in as another, and
   the gateway's own leaf logs in as nothing. Point NOO_PG_PROOF_HBA at an
   older file to see it fail.
"""

from __future__ import annotations

import os
import re
import shutil
import subprocess
import uuid
from pathlib import Path

import pytest

from tests._compose_projection import env_of, full_projection

ROOT = Path(__file__).resolve().parents[1]
HBA = ROOT / "docker" / "postgres" / "pg_hba.conf"
PKI_RS = ROOT / "noo-cli" / "src" / "pki.rs"

# Roles whose clients live in OTHER repos (the evolve add-on) or are not a
# container here (the standby): they keep `clientcert=verify-ca` until their
# repos present a leaf named for the role. Listing them is a reviewed edit.
TIER3_ROLES = {"noo_evolve", "noo_evolve_ddl", "replicator"}

# compose service -> PG_LEAVES owner, and the in-container dir the leaf is read from.
OWNER_OF_SERVICE = {
    "gateway": ("gateway", "/app/pki/gateway"),
    "worker": ("worker", "/app/pki/leaf"),
    "worker-extra": ("worker", "/app/pki/leaf"),
    "trellion": ("trellion", "/app/pki/leaf"),
}


def pg_leaves() -> list[tuple[str, str]]:
    """(owner, role) rows of PG_LEAVES, read from the source of truth."""
    table = PKI_RS.read_text().split("pub const PG_LEAVES", 1)[1].split("];", 1)[0]
    rows = re.findall(r'owner: "([a-z-]+)", role: "([a-z_]+)"', table)
    assert rows, "PG_LEAVES not found in pki.rs"
    return rows


def hba_rules(text: str) -> list[list[str]]:
    return [l.split() for l in (ln.split("#")[0].strip() for ln in text.splitlines()) if l]


def hba_problems(text: str, roles: set[str]) -> list[str]:
    """What is wrong with a pg_hba body for the per-role identity design."""
    rules = [r for r in hba_rules(text) if r[0] == "hostssl" and r[1] == "all"]
    out: list[str] = []
    full = {r[2]: i for i, r in enumerate(rules) if "clientcert=verify-full" in r and r[2] != "all"}
    catch_all = [i for i, r in enumerate(rules) if r[2] == "all" and r[3] == "all"]
    if not catch_all:
        return ["no `hostssl all all all` catch-all"]
    last = max(catch_all)
    for role in sorted(roles):
        if role not in full:
            out.append(f"role {role} has a leaf but no `clientcert=verify-full` line")
        elif full[role] > min(catch_all):
            out.append(f"role {role}'s verify-full line comes AFTER the catch-all, which already matched it")
    for role, i in full.items():
        if role not in roles:
            out.append(f"{role} has a verify-full line but no leaf is issued for it (PG_LEAVES): nobody could log in")
        r = rules[i]
        if r[3] != "all" or r[4] != "scram-sha-256":
            out.append(f"{role}: line must be `all scram-sha-256 clientcert=verify-full` (password kept): {' '.join(r)}")
    for i, r in enumerate(rules[: min(catch_all)]):
        if r[2] == "all" and r[3] != "samehost":
            out.append(f"a generic line precedes the per-role lines: {' '.join(r)}")
        if r[2] == "all" and r[3] == "samehost" and "clientcert=verify-ca" not in r:
            out.append("the samehost line must still require a cluster-CA certificate")
    if "clientcert=verify-ca" not in rules[last]:
        out.append("the catch-all must still require a cluster-CA client certificate")
    return out


def test_hba_has_one_verify_full_line_per_role_and_keeps_the_password():
    roles = {role for _, role in pg_leaves()}
    assert roles == {"noo", "noo_app", "noo_trellion", "noo_trellion_ddl"}, roles
    assert hba_problems(HBA.read_text(), roles) == []


def test_the_hba_checker_bites():
    roles = {"noo", "noo_app"}
    good = (
        "hostssl all all samehost scram-sha-256 clientcert=verify-ca\n"
        "hostssl all noo all scram-sha-256 clientcert=verify-full\n"
        "hostssl all noo_app all scram-sha-256 clientcert=verify-full\n"
        "hostssl all all all scram-sha-256 clientcert=verify-ca\n"
    )
    assert hba_problems(good, roles) == []
    cases = {
        "the old file (verify-ca only)": "hostssl all all all scram-sha-256 clientcert=verify-ca\n",
        "a role missing": good.replace("hostssl all noo_app all scram-sha-256 clientcert=verify-full\n", ""),
        "verify-full after the catch-all": good.replace(
            "hostssl all all all scram-sha-256 clientcert=verify-ca\n", "")
        + "hostssl all all all scram-sha-256 clientcert=verify-ca\nhostssl all noo_app all scram-sha-256 clientcert=verify-full\n",
        "password dropped": good.replace("noo all scram-sha-256 clientcert=verify-full", "noo all cert clientcert=verify-full"),
        "a generic line ahead": "hostssl all all 0.0.0.0/0 scram-sha-256 clientcert=verify-ca\n" + good,
        "an orphan verify-full": good.replace("hostssl all all all", "hostssl all ghost all scram-sha-256 clientcert=verify-full\nhostssl all all all"),
    }
    for name, text in cases.items():
        assert hba_problems(text, roles), f"not caught: {name}"


def _dsns(svc: dict) -> dict[str, str]:
    return {k: v for k, v in env_of(svc).items() if re.match(r"postgres(ql)?://", v or "")}


def dsn_problems(name: str, owner_dir: str, owner: str, dsns: dict[str, str], roles_by_owner: dict[str, set[str]]) -> list[str]:
    out: list[str] = []
    for key, dsn in dsns.items():
        user = re.match(r"postgres(?:ql)?://([^:@/]+)", dsn).group(1)
        q = dict(re.findall(r"[?&](ssl[a-z]+)=([^&]+)", dsn))
        if user in TIER3_ROLES:
            continue
        if user not in roles_by_owner.get(owner, set()):
            out.append(f"{name}: {key} connects as {user}, which has no role leaf for {owner} in PG_LEAVES")
            continue
        want_c, want_k = f"{owner_dir}/pg/{user}.crt", f"{owner_dir}/pg/{user}.key"
        if q.get("sslcert") != want_c or q.get("sslkey") != want_k:
            out.append(f"{name}: {key} (user {user}) presents {q.get('sslcert')} / {q.get('sslkey')}, not the role leaf {want_c} / {want_k}")
        if q.get("sslmode") != "verify-full":
            out.append(f"{name}: {key} sslmode is {q.get('sslmode')!r}, want verify-full")
    return out


def test_every_dsn_presents_the_leaf_issued_for_its_user():
    services = full_projection()["services"]
    by_owner: dict[str, set[str]] = {}
    for owner, role in pg_leaves():
        by_owner.setdefault(owner, set()).add(role)
    seen = 0
    for name, (owner, owner_dir) in OWNER_OF_SERVICE.items():
        dsns = _dsns(services[name])
        assert dsns, f"{name}: no Postgres DSN found — did the env change shape?"
        seen += len(dsns)
        assert dsn_problems(name, owner_dir, owner, dsns, by_owner) == [], name
    assert seen >= 10
    # trellion-intel `extends` trellion and swaps only the leaf mount, so it
    # presents ITS OWN role leaves through the same DSNs.
    assert "trellion-intel" in by_owner and by_owner["trellion-intel"] == by_owner["trellion"]


def test_a_dsn_on_the_wrong_leaf_is_caught():
    by_owner = {"worker": {"noo_app"}}
    ok = "postgresql://noo_app@postgres/db?sslmode=verify-full&sslcert=/app/pki/leaf/pg/noo_app.crt&sslkey=/app/pki/leaf/pg/noo_app.key"
    assert dsn_problems("worker", "/app/pki/leaf", "worker", {"DATABASE_URL": ok}, by_owner) == []
    for bad in (
        ok.replace("/pg/noo_app.crt", "/service.crt").replace("/pg/noo_app.key", "/service.key"),
        ok.replace("noo_app@", "noo@"),
        ok.replace("verify-full", "verify-ca"),
        ok.replace("pg/noo_app.key", "pg/noo.key"),
    ):
        assert dsn_problems("worker", "/app/pki/leaf", "worker", {"DATABASE_URL": bad}, by_owner), bad


def _target_of(vol) -> tuple[str, str]:
    if isinstance(vol, dict):
        return str(vol.get("source") or ""), str(vol.get("target") or "")
    parts = re.split(r":(?![^{]*\})", str(vol))
    return parts[0], parts[1] if len(parts) > 1 else ""


def test_every_role_leaf_owner_mounts_the_directory_it_lives_in():
    """gateway/pg/ lives inside the gateway/ mount, services/<owner>/pg/
    inside the owner's leaf mount: no new mount, no other container's key."""
    services = full_projection()["services"]
    expect = {
        "gateway": ("/gateway", "/app/pki/gateway"),
        "worker": ("/services/worker", "/app/pki/leaf"),
        "worker-extra": ("/services/worker", "/app/pki/leaf"),
        "trellion": ("/services/trellion", "/app/pki/leaf"),
    }
    for name, (src_end, target) in expect.items():
        mounts = [_target_of(v) for v in services[name].get("volumes") or []]
        assert any(s.endswith(src_end) and t == target for s, t in mounts), f"{name} does not mount …{src_end} at {target}: {mounts}"
    owners = {o for o, _ in pg_leaves()}
    assert owners == {"gateway", "worker", "trellion", "trellion-intel"}, owners


# ── the same property against a REAL Postgres ─────────────────────────────

IMAGE = os.environ.get("NOO_PG_PROOF_IMAGE", "pgvector/pgvector:pg18")
HBA_UNDER_TEST = Path(os.environ.get("NOO_PG_PROOF_HBA", str(HBA)))


def _docker_ready() -> str | None:
    if not shutil.which("docker") or not shutil.which("openssl"):
        return "docker or openssl is not installed"
    if subprocess.run(["docker", "image", "inspect", IMAGE], capture_output=True).returncode != 0:
        return f"image {IMAGE} is not present locally (set NOO_PG_PROOF_IMAGE)"
    return None


@pytest.fixture(scope="module")
def live(tmp_path_factory):
    why = _docker_ready()
    if why:
        pytest.skip(f"NOT CHECKED against a real Postgres: {why}")
    d = tmp_path_factory.mktemp("pgproof")
    pki = d / "pki"
    pki.mkdir()

    def sh(*a, **kw):
        return subprocess.run(a, check=True, capture_output=True, text=True, cwd=pki, **kw)

    sh("openssl", "ecparam", "-name", "secp384r1", "-genkey", "-noout", "-out", "ca.key")
    sh("openssl", "req", "-x509", "-new", "-key", "ca.key", "-subj", "/CN=Mesh Cluster CA", "-days", "2", "-out", "ca.crt")

    def leaf(name, cn, san):
        sh("openssl", "ecparam", "-name", "secp384r1", "-genkey", "-noout", "-out", f"{name}.key")
        sh("openssl", "req", "-new", "-key", f"{name}.key", "-subj", f"/CN={cn}", "-out", f"{name}.csr")
        (pki / f"{name}.ext").write_text(f"subjectAltName={san}\nextendedKeyUsage=clientAuth,serverAuth\n")
        sh("openssl", "x509", "-req", "-in", f"{name}.csr", "-CA", "ca.crt", "-CAkey", "ca.key", "-CAcreateserial",
           "-days", "2", "-extfile", f"{name}.ext", "-out", f"{name}.crt")
        (pki / f"{name}.key").chmod(0o644)

    host = f"pgproof-{uuid.uuid4().hex[:8]}"
    leaf("server", "postgres", f"DNS:{host},DNS:localhost,IP:127.0.0.1")
    for role in ("noo", "noo_app", "noo_evolve"):
        leaf(role, role, f"DNS:pg-{role}")
    leaf("gwhost", "gw-host", "DNS:gateway,DNS:gw-host")
    net = f"net-{host}"
    subprocess.run(["docker", "network", "create", net], check=True, capture_output=True)
    subprocess.run(
        ["docker", "run", "-d", "--name", host, "--network", net, "--network-alias", host,
         "--memory", "512m", "--cpus", "0.5",
         "-e", "POSTGRES_USER=noo", "-e", "POSTGRES_PASSWORD=superpw", "-e", "POSTGRES_DB=noomesh",
         "-v", f"{pki}:/tls:ro", "-v", f"{HBA_UNDER_TEST}:/etc/noo/pg_hba.conf:ro", "--entrypoint", "sh", IMAGE, "-c",
         "cp /tls/server.key /tmp/s.key; chown postgres /tmp/s.key; chmod 600 /tmp/s.key; "
         "exec docker-entrypoint.sh postgres -c ssl=on -c ssl_cert_file=/tls/server.crt -c ssl_key_file=/tmp/s.key "
         "-c ssl_ca_file=/tls/ca.crt -c hba_file=/etc/noo/pg_hba.conf -c listen_addresses=*"],
        check=True, capture_output=True,
    )
    try:
        import time
        for _ in range(60):
            # Over TCP: the entrypoint's temporary init server listens on the
            # socket only, so this is true only for the real server.
            if subprocess.run(["docker", "exec", host, "pg_isready", "-h", "127.0.0.1", "-U", "noo", "-d", "noomesh"], capture_output=True).returncode == 0:
                break
            time.sleep(1)
        else:
            pytest.fail("the proof Postgres did not come up")
        subprocess.run(
            ["docker", "exec", host, "psql", "-U", "noo", "-d", "noomesh", "-qc",
             "CREATE ROLE noo_app LOGIN PASSWORD 'appw'; CREATE ROLE noo_evolve LOGIN PASSWORD 'evw';"],
            check=True, capture_output=True,
        )
        yield {"host": host, "net": net, "pki": pki}
    finally:
        subprocess.run(["docker", "rm", "-f", host], capture_output=True)
        subprocess.run(["docker", "network", "rm", net], capture_output=True)


def _login(live, cert: str | None, user: str, pw: str) -> bool:
    sslcert = f"sslcert=/tls/{cert}.crt sslkey=/tmp/k" if cert else ""
    cp = f"cp /tls/{cert}.key /tmp/k; chmod 600 /tmp/k; " if cert else ""
    cmd = (
        f"{cp}PGPASSWORD={pw} PGCONNECT_TIMEOUT=5 psql -w "
        f"'host={live['host']} user={user} dbname=noomesh sslmode=verify-full sslrootcert=/tls/ca.crt {sslcert}' -tAc 'select 1'"
    )
    r = subprocess.run(
        ["docker", "run", "--rm", "--network", live["net"], "-v", f"{live['pki']}:/tls:ro", "--entrypoint", "sh", IMAGE, "-c", cmd],
        capture_output=True, text=True,
    )
    return r.returncode == 0 and r.stdout.strip() == "1"


def test_live_a_role_leaf_logs_in_as_its_role_and_nothing_else(live):
    assert _login(live, "noo_app", "noo_app", "appw"), "the role's own leaf + password must log in"
    assert _login(live, "noo", "noo", "superpw")
    # The property: the certificate says WHICH role it may use.
    assert not _login(live, "gwhost", "noo_app", "appw"), "a cluster-CA leaf that is not noo_app's reached noo_app"
    assert not _login(live, "gwhost", "noo", "superpw"), "the gateway's own leaf logged in as the superuser"
    assert not _login(live, "noo_app", "noo", "superpw"), "noo_app's leaf logged in as the superuser"
    assert not _login(live, "noo", "noo_app", "appw"), "the superuser's leaf logged in as noo_app"
    # The password is still required, and a certificate is still required.
    assert not _login(live, "noo_app", "noo_app", "wrong")
    assert not _login(live, None, "noo_app", "appw")


def test_live_roles_without_a_leaf_here_keep_the_cluster_ca_rule(live):
    assert _login(live, "noo_evolve", "noo_evolve", "evw")
    assert _login(live, "gwhost", "noo_evolve", "evw"), "tier 3 (verify-ca) still accepts a cluster-CA leaf for the add-on roles"


def test_live_the_rotation_probe_inside_the_container_still_judges_the_password(live):
    """`noo security secrets rotate` logs in as the role from INSIDE the
    postgres container, presenting the server's leaf, to prove a password."""
    def probe(user, pw):
        cmd = (
            "cp /tls/server.key /tmp/pk; chown postgres /tmp/pk; chmod 600 /tmp/pk; "
            f"su postgres -c \"PGSSLMODE=verify-ca PGSSLROOTCERT=/tls/ca.crt PGSSLCERT=/tls/server.crt PGSSLKEY=/tmp/pk "
            f"PGPASSWORD={pw} PGCONNECT_TIMEOUT=5 psql -w -h {live['host']} -U {user} -d noomesh -tAc 'select 1'\""
        )
        r = subprocess.run(["docker", "exec", live["host"], "sh", "-c", cmd], capture_output=True, text=True)
        return r.returncode == 0 and r.stdout.strip() == "1", r.stderr
    ok, _ = probe("noo_app", "appw")
    assert ok, "the probe's correct password must be accepted"
    bad, err = probe("noo_app", "wrong")
    assert not bad and "password authentication failed" in err, "a wrong password must be Rejected (the probe's negative control)"
