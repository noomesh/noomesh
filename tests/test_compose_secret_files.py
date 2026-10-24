# SPDX-License-Identifier: AGPL-3.0-only
# Copyright 2026 PersonifAI LLC

"""Tier-1 secrets reach noomesh's own containers as FILES, and nothing else.

The operator's rule is "always sops, never plaintext", and the worry that goes
with it is "something just lying about". Since 2026-09-29 the base compose
file delivers every tier-1 secret to the gateway, the worker(s), redis,
postgres, grafana and the browser through a top-level `secrets:` entry whose
source is `file: ${NOO_SECRET_RUNDIR}/<name>` — a file the launcher writes to
a tmpfs directory (scripts/lib-secrets.sh `write_secret_files`; see
tests/test_secret_rundir.py), bind-mounted as `/run/secrets/<target>`. (It was
`environment: VAR` until the services went `read_only`: compose refuses that
form there.) Nothing on a disk, nothing in `Config.Env`, nothing in a
container's writable layer. What keeps that true:

G1  No file-backed NAME — tier-1, and since an earlier change the tier-2
    provider/channel keys (TAVILY_API_KEY, TELEGRAM_BOT_TOKEN, …; both
    readers' manifests carry them) — appears in a noomesh-owned service's
    `environment:` in the composed projection, and no env VALUE interpolates a secret source
    (`${POSTGRES_PASSWORD}` inside a DSN was exactly this) except as the
    pointer form `${NAME:+/run/secrets/<target>}` that yields only a path.
G2  Every top-level secret is referenced; every service-level secret has a
    pointer the container's reader actually reads (its language manifest,
    or a native consumer) and an `x-noo-uid` that is the image's user (the
    launcher hands the host file to it, 0400); every pointer names a file
    the service is given. No entry carries compose's own uid/gid/mode: they
    apply in Swarm only and Compose v5 warns three lines per secret per
    service on every start (960 lines in one `noo onboard`, 2026-10-24).
G4  The launcher writes no secret to disk: `lib-secrets.sh` and the three
    launchers have no redirection into `secrets/` and no `mkdir` of a
    runtime secrets directory. (The only writes are into the tmpfs-checked
    `$d` of `write_secret_files`; tests/test_secret_rundir.py.)
    Plus: the pgpass derivation has one declaration in two languages (the
    launcher and the onboard wizard's compose wrapper) and they produce the
    same bytes; the CLI's verify-row tier-1 list is the union of the two
    reader manifests; and the image floor is declared, enforced by the
    launcher and by `noo upgrade --stack`, and (once tagged) really is a
    stack whose gateway reads the JWT secret — and every name this file
    points the gateway and worker at — through `secret_env`.

Since an earlier change the add-on containers are IN: noo-trellion's image
reads `_FILE` (noomesh's `secret_env` plus trellion's own reader) since
stack-v0.2.80, and its overlay delivers files and a pgpass. The licensed
add-ons' overlays (trellion-intel, evolve) and their delivery guards moved
with the overlay to the add-on repos (N6). Only the Go
node agent reads `_FILE` too and nats has no secret env
since an earlier change, so nothing remains DEFERRED.
"""

from __future__ import annotations

import re
import subprocess
from pathlib import Path

import pytest

from tests._compose_projection import ROOT, env_of, full_projection, load_raw, untag
from tests.test_file_reader_parity import ADDON_MANIFESTS, addon_reader_manifest, go_manifest, python_manifest, rust_manifest

BASE = ROOT / "docker-compose.cluster.yml"

# The services whose images read `_FILE` today, with the uid their process
# runs as (the secret's owner — sqlx and libpq refuse a pgpass with group or
# other bits, and 0400 to the wrong uid is unreadable). Each uid is the
# image's own: gateway/worker are DHI `nonroot` (65532, measured on the
# gateway image's /etc/passwd); postgres is the alpine `postgres` user (70);
# the Playwright image runs as root. The DHI redis/grafana -dev images'
# USER is root, but compose pins both to the image's own name for 65532
# (`user: nonroot` / `user: grafana`; i64: they must not run as root; a name,
# not the number: Docker 27 getent, tests/test_compose_named_users.py), so
# their secrets are handed to 65532.
# The add-on, measured on the stack-v0.2.80 image: trellion is `USER nonroot`
# on the DHI deps-base (`os.getuid()` → 65532). (trellion-intel, noo-evolve:
# moved with the overlay to the add-on repo (N6).)
OWNED_UIDS: dict[str, str] = {
    "gateway": "65532",
    "worker": "65532",
    "worker-extra": "65532",
    "redis": "65532",
    "postgres": "70",
    "grafana": "65532",
    "browser": "0",
    "trellion": "65532",
    # The opt-in containerised Go agent (profiles node-agent-compose /
    # sensors): its image is `USER 0` (docker/Dockerfile.node-agent-go).
    # the design
    "node-agent": "0",
    "node-agent-sensors": "0",
}
# The add-on services core composes (the licensed ones: moved with the
# overlay to the add-on repo (N6)).
ADD_ONS = ("trellion",)

# Base-file services still handed secrets as env, and why. (The add-ons left
# this map with the design, the containerised node agent with §2.)
DEFERRED: dict[str, str] = {
    # (nats was here the earlier change retired the shared principal its
    # server expanded; the containerised node agent the earlier change
    # gave the Go agent a `_FILE` reader.)
}

# Pointers a native consumer reads, per service.
NATIVE_POINTERS: dict[str, set[str]] = {
    "postgres": {"POSTGRES_PASSWORD_FILE"},  # the image entrypoint's file_env
    "redis": {"REDIS_PASSWORD_FILE"},  # docker/redis-entrypoint.sh
    "grafana": {"GF_SECURITY_ADMIN_PASSWORD"},  # `$__file{…}` expansion
    "gateway": {"PGPASSFILE"},  # sqlx, natively
    "worker": {"PGPASSFILE"},  # libpq (psycopg), natively
    "worker-extra": {"PGPASSFILE"},
    "trellion": {"PGPASSFILE"},  # libpq (psycopg: noomesh's and trellion's engines)
}

POINTER = re.compile(r"^\$\{([A-Z_][A-Z0-9_]*):\+(?:\$\$__file\{)?/run/secrets/([a-z0-9_]+)\}?\}$")


def browser_manifest() -> list[str]:
    src = (ROOT / "src/noomesh/tools/browser/server.py").read_text()
    names = re.findall(r'_secret\("([A-Z0-9_]+)"\)', src)
    assert names, "the browser's inlined reader reads nothing — this guard is reading the wrong thing"
    return names


def reader_manifest(service: str) -> set[str]:
    if service in ADD_ONS:
        return addon_reader_manifest(service)
    return {
        "gateway": set(rust_manifest()),
        "worker": set(python_manifest()),
        "worker-extra": set(python_manifest()),
        "browser": set(browser_manifest()),
        "node-agent": set(go_manifest()),
        "node-agent-sensors": set(go_manifest()),
    }.get(service, set())


def top_level_secrets() -> dict[str, str]:
    """Top-level secret name → its source variable, across the base and every
    add-on overlay (compose merges top-level `secrets:` across `-f` files;
    the add-ons declare their own keys and pgpass bodies)."""
    raw = full_projection().get("secrets") or {}
    out = {k: v.get("x-noo-source") for k, v in raw.items()}
    assert all(out.values()), f"a top-level secret names no `x-noo-source:` variable (the launcher cannot write its file): {out}"
    # (`config --no-interpolate` prefixes the project directory to a path it
    # reads as relative, so the check is on the tail, not the start.)
    want = "${NOO_SECRET_RUNDIR:-/nonexistent/noo-secret-rundir-unset}/"
    bad = {k: v.get("file") for k, v in raw.items() if not str(v.get("file", "")).endswith(want + k)}
    assert not bad, (
        "a top-level secret is not sourced from `file: ${NOO_SECRET_RUNDIR:-...}/<name>` (an `environment:` source "
        f"is refused on a read-only service; any other file leaves a plaintext host file lying about): {bad}"
    )
    return out


def tier1_names() -> set[str]:
    return set(rust_manifest()) | set(python_manifest()) | set(go_manifest()) | {"POSTGRES_PASSWORD"}


def secret_sources() -> set[str]:
    return set(top_level_secrets().values())


def _svc_secrets(svc: dict) -> list[dict]:
    return [s if isinstance(s, dict) else {"source": s, "target": s} for s in (svc.get("secrets") or [])]


# ── G1 ────────────────────────────────────────────────────────────────────


def test_g1_no_tier1_name_in_an_owned_environment() -> None:
    p = full_projection()["services"]
    tier1 = tier1_names()
    assert len(tier1) >= 20, tier1
    checked = 0
    bad = []
    for name in OWNED_UIDS:
        if name not in p:
            continue
        checked += 1
        for key in env_of(p[name]):
            if key in tier1:
                bad.append(f"{name}: {key}")
    assert checked == len(OWNED_UIDS), f"only {checked} of {sorted(OWNED_UIDS)} are in the projection"
    assert not bad, (
        f"a tier-1 secret is a plain environment variable again: {bad} — deliver it as a file ONLY if every "
        "reader in that container reads `NAME_FILE` (see the gateway's `secrets:` block); a third-party server "
        "that expands `$VAR` from its own config needs the env var — add it to DEFERRED with the reason instead"
    )


def test_g1_no_env_value_interpolates_a_secret_except_as_a_pointer() -> None:
    p = full_projection()["services"]
    sources = secret_sources()
    assert len(sources) >= 20, sources
    bad = []
    pointers = 0
    for name, svc in p.items():
        if name not in OWNED_UIDS:
            continue
        for key, val in env_of(svc).items():
            for src in sources:
                # Boundary-matched: `${NOO_SVC_KEY_TRELLION_INTEL:+…}` must
                # not count as an interpolation of NOO_SVC_KEY_TRELLION.
                if not re.search(r"\$\{" + re.escape(src) + r"(?![A-Za-z0-9_])", val):
                    continue
                m = POINTER.match(val)
                if m and m.group(1) == src:
                    pointers += 1
                    continue
                bad.append(f"{name}: {key}={val[:80]}")
    assert pointers >= 30, f"only {pointers} pointer(s) found — is this reading the projection?"
    assert not bad, (
        "an environment VALUE interpolates a secret (a DSN with `:${…PASSWORD}` puts the password in Config.Env): "
        f"{bad}. Take the password out of the DSN (pgpass) or use the `${{NAME:+/run/secrets/…}}` pointer form — "
        "ONLY if every reader in that container reads `NAME_FILE`/PGPASSFILE; a third-party server that "
        "expands `$VAR` from its own config needs the env var (add the service to DEFERRED with the reason)."
    )


def test_g1_every_deferral_names_the_followup_that_ends_it() -> None:
    """A service is exempt from G1 only while its reason names the followup
    that ends the exemption. The add-ons are not exempt any more."""
    assert not set(ADD_ONS) & set(DEFERRED), "an add-on is deferred again — its image reads _FILE since stack-v0.2.80"
    assert "nats" not in DEFERRED, "nats is deferred again — an earlier change retired the reason"
    assert not {"node-agent", "node-agent-sensors"} & set(DEFERRED), "the Go agent is deferred again — it reads _FILE since an earlier change"
    for name, why in DEFERRED.items():
        assert "1252" in why, (name, why)


# ── G2 ────────────────────────────────────────────────────────────────────


def test_g2_every_top_level_secret_is_used_and_every_used_secret_declared() -> None:
    p = full_projection()["services"]
    declared = set(top_level_secrets())
    used = {s["source"] for svc in p.values() for s in _svc_secrets(svc)}
    assert len(declared) >= 20
    assert declared - used == set(), f"declared but no service takes it (a value exported for nothing): {declared - used}"
    assert used - declared == set(), f"used but not declared: {used - declared}"


def test_g2_each_delivery_is_owner_only_to_the_image_user() -> None:
    p = full_projection()["services"]
    seen = 0
    bad = []
    for name, svc in p.items():
        entries = _svc_secrets(svc)
        if not entries:
            continue
        assert name in OWNED_UIDS, f"{name} takes a compose secret but has no known image uid here — add it to OWNED_UIDS with the measured uid"
        for s in entries:
            seen += 1
            uid = str(s.get("x-noo-uid"))
            if uid != OWNED_UIDS[name]:
                bad.append(f"{name}/{s['target']}: x-noo-uid={uid}")
            swarm = {k for k in ("uid", "gid", "mode") if k in s}
            if swarm:
                bad.append(f"{name}/{s['target']}: carries {sorted(swarm)} (Swarm-only; Compose v5 warns on every start)")
    assert seen >= 30, seen
    assert not bad, f"a secret entry is not declared for its image's user, or carries Swarm-only keys: {bad}"


# One-release bridges: an OLD pointer name aimed at a NEW file, for an image
# from before the rename. Each names its removal.
BRIDGE_POINTERS: dict[str, dict[str, str]] = {
    "browser": {
        "NOO_CLUSTER_SECRET_FILE": "an earlier change: a pre-702 noo-browser image reads NOO_CLUSTER_SECRET; compose "
        "points that name at the BROWSER key's file for one release (remove after v0.2.103)",
    },
}


def test_g2_every_file_has_a_pointer_the_reader_reads_and_every_pointer_a_file() -> None:
    p = full_projection()["services"]
    bad = []
    checked = 0
    for name in OWNED_UIDS:
        svc = p[name]
        targets = {s["target"] for s in _svc_secrets(svc)}
        env = env_of(svc)
        pointed: dict[str, list[str]] = {}
        for key, val in env.items():
            m = POINTER.match(val)
            if m:
                pointed.setdefault(m.group(2), []).append(key)
        for t in targets:
            keys = pointed.get(t)
            if not keys:
                bad.append(f"{name}: /run/secrets/{t} is delivered but no env var points at it")
                continue
            checked += 1
            for key in keys:
                if key in NATIVE_POINTERS.get(name, set()) or key in BRIDGE_POINTERS.get(name, {}):
                    continue
                base = key.removesuffix("_FILE")
                if not key.endswith("_FILE") or base not in reader_manifest(name):
                    bad.append(f"{name}: {key} points at {t}, but {base} is not in this container's reader manifest")
        for t, keys in pointed.items():
            if t not in targets:
                bad.append(f"{name}: {', '.join(keys)} points at /run/secrets/{t}, which this service is not given")
    assert checked >= 30, checked
    assert not bad, bad


def test_g2_deferred_services_are_the_only_base_services_with_tier1_env() -> None:
    p = full_projection()["services"]
    base = set((untag(load_raw(BASE)).get("services") or {}))
    tier1 = tier1_names()
    holders = {n for n in base if n in p and tier1 & set(env_of(p[n]))}
    assert holders == set(DEFERRED), (
        f"base services with tier-1 env: {sorted(holders)}; expected only {sorted(DEFERRED)}. A new holder: "
        "deliver it as a file ONLY if every reader in that container reads `NAME_FILE`; a third-party server "
        "that expands `$VAR` from its own config needs the env var — add it to DEFERRED with the reason."
    )


# ── the add-ons' own gateway keys ──────────────────────


def _file_source_var(svc: dict, pointer: str) -> str | None:
    """The launcher variable whose value lands in the file `pointer` names:
    pointer value → /run/secrets/<target> → the service's secret with that
    target → its top-level source → `environment:`."""
    m = POINTER.match(env_of(svc).get(pointer, ""))
    if not m:
        return None
    target = m.group(2)
    entries = [e for e in _svc_secrets(svc) if e["target"] == target]
    assert len(entries) == 1, f"{len(entries)} secrets target /run/secrets/{target}"
    return top_level_secrets()[entries[0]["source"]]


def test_each_add_on_gateway_key_file_is_sourced_from_its_own_key() -> None:
    """An overlay that `extends` another's service inherits by merge both the
    environment map and the `secrets:` list (by target). Its pointer can
    name its own variable while the FILE behind it is still the parent's —
    then it presents the parent's key and nothing in the environment says
    so. Resolve pointer → target → source → variable in the projection and
    require each add-on's own declared key (x-noo-addon), and no plain
    NOO_GATEWAY_KEY beside the pointer (the readers refuse on both-set)."""
    from tests._addon_decls import decls

    p = full_projection()["services"]
    by_container = {("noo-" + n if not n.startswith("noo-") else n): n for n in p}
    checked = 0
    for d in decls():
        for c in d.containers:
            svc = p[by_container[c]]
            env = env_of(svc)
            assert "NOO_GATEWAY_KEY" not in env, f"{c} has a plain NOO_GATEWAY_KEY beside the file"
            src = _file_source_var(svc, "NOO_GATEWAY_KEY_FILE")
            assert src == d.key, (
                f"{c}'s NOO_GATEWAY_KEY_FILE resolves to a file sourced from {src}; {d.overlay} declares "
                f"its key as {d.key} — that container would present another consumer's key"
            )
            assert env["NOO_GATEWAY_KEY_FILE"].startswith("${" + d.key + ":+"), (c, env["NOO_GATEWAY_KEY_FILE"])
            checked += 1
    # trellion is core's one key holder; trellion-intel's distinct-file check
    # moved with the overlay to the add-on repo (N6).
    assert "noo-trellion" in {c for d in decls() for c in d.containers} and checked >= 1, checked


def test_add_on_secrets_reach_only_their_own_add_on() -> None:
    """The add-on-only sources (a key, a pgpass body) are declared in the
    add-on's own overlay and taken by no noomesh-owned container."""
    p = full_projection()["services"]
    # (NOO_SVC_KEY_TRELLION_INTEL, NOO_SVC_KEY_EVOLVE, NOO_PGPASS_EVOLVE: moved
    # with the overlay to the add-on repo (N6).)
    for var in ("NOO_SVC_KEY_TRELLION", "NOO_PGPASS_TRELLION"):
        names = [k for k, v in top_level_secrets().items() if v == var]
        assert len(names) == 1, (var, names)
        takers = sorted(n for n, svc in p.items() for e in _svc_secrets(svc) if e["source"] == names[0])
        assert takers and set(takers) <= set(ADD_ONS), (var, takers)
        assert var not in (untag(load_raw(BASE)).get("secrets") or {}).values(), f"{var} is declared in the base file"


def test_the_add_on_manifest_pins_name_the_images_readers() -> None:
    """The pinned sibling manifests (test_file_reader_parity.ADDON_MANIFESTS)
    are what G2 checks the add-on pointers against; each must at least cover
    the name the add-on's own gateway client reads — its key, the only one
    since an earlier change retired the shared-secret fallback."""
    for svc, (_repo, _path, names) in ADDON_MANIFESTS.items():
        assert "NOO_GATEWAY_KEY" in names, (svc, names)
        assert not names & {"NOO_CONTROLLER_SECRET", "NOO_CLUSTER_SECRET"}, (svc, names)


# ── G4 ────────────────────────────────────────────────────────────────────

LAUNCHERS = ("scripts/lib-secrets.sh", "scripts/noomesh-start.sh", "scripts/noomesh-restart.sh", "scripts/noomesh-rebuild.sh")
_REDIRECT_INTO_SECRETS = re.compile(r"(?:>>?|\btee\b(?:\s+-a)?)\s*[\"']?[^\s\"';|&]*secrets/")
_MKDIR_SECRETS = re.compile(r"\bmkdir\b[^\n#]*secrets(?:/|\b)")


def _code_lines(path: Path) -> list[tuple[int, str]]:
    out = []
    for i, line in enumerate(path.read_text().splitlines(), 1):
        stripped = line.lstrip()
        if stripped.startswith("#"):
            continue
        out.append((i, line))
    return out


def test_g4_the_launcher_writes_no_secret_to_disk() -> None:
    bad = []
    lines = 0
    for rel in LAUNCHERS:
        body = _code_lines(ROOT / rel)
        lines += len(body)
        for i, line in body:
            if _REDIRECT_INTO_SECRETS.search(line) or _MKDIR_SECRETS.search(line):
                bad.append(f"{rel}:{i}: {line.strip()}")
    assert lines > 800, f"read only {lines} code lines across the launchers"
    assert not bad, f"a launcher writes under secrets/ — the delivery is compose-from-env and needs no file: {bad}"


def test_g4_the_pattern_catches_what_it_is_for() -> None:
    for plant in ('printf "%s" "$x" > secrets/.runtime/pgpass', 'mkdir -p "$ROOT/secrets/.runtime"', "echo x | tee -a secrets/x"):
        assert _REDIRECT_INTO_SECRETS.search(plant) or _MKDIR_SECRETS.search(plant), plant
    assert not _REDIRECT_INTO_SECRETS.search('local enc="${NOO_SOPS_FILE:-secrets/env.sops}"')


# ── the pgpass derivation: one declaration, two languages, same bytes ─────


def _shell_roles() -> dict[str, tuple[str, list[tuple[str, str]]]]:
    """var → (driver, [(role, password var)]) from lib-secrets.sh."""
    src = (ROOT / "scripts/lib-secrets.sh").read_text()
    out = {}
    for var, body in re.findall(r'^NOO_PGPASS_ROLES_([A-Z]+)="([^"]*)"', src, re.M):
        driver, *pairs = body.split()
        out[f"NOO_PGPASS_{var}"] = (driver, [tuple(p.split(":", 1)) for p in pairs])
    assert len(out) == 4, out
    return out


def _rust_roles() -> dict[str, tuple[str, list[tuple[str, str]]]]:
    src = (ROOT / "noo-cli/src/onboard/sh.rs").read_text()
    m = re.search(r"pub\(crate\) const PGPASS_ROLES:.*?= &\[(.*?)\n\];", src, re.S)
    assert m, "PGPASS_ROLES not found in noo-cli/src/onboard/sh.rs"
    out = {}
    for var, driver, body in re.findall(r'\(\s*"(NOO_PGPASS_[A-Z]+)",\s*"([a-z]+)",\s*&\[(.*?)\],?\s*\)', m.group(1), re.S):
        out[var] = (driver, re.findall(r'\("([a-z_]+)", "([A-Z_]+)"\)', body))
    assert len(out) == 4, out
    return out


def test_pgpass_roles_are_declared_the_same_in_both_derivations() -> None:
    assert _shell_roles() == _rust_roles()


def test_the_pgpass_roles_match_the_dsn_users() -> None:
    """Each container's pgpass covers exactly the roles its DSNs log in as."""
    p = full_projection()["services"]
    roles = _shell_roles()
    for svc, var in (
        ("gateway", "NOO_PGPASS_GATEWAY"),
        ("worker", "NOO_PGPASS_WORKER"),
        ("trellion", "NOO_PGPASS_TRELLION"),
        # trellion-intel, noo-evolve: moved with the overlay to the add-on repo (N6)
    ):
        users = {m.group(1) for v in env_of(p[svc]).values() for m in [re.match(r"postgresql://([a-z_]+)@postgres:5432/", v)] if m}
        assert users == {r for r, _ in roles[var][1]}, (svc, users, roles[var])
        # and the pgpass that service is handed is THIS body
        srcs = top_level_secrets()
        pg = [s for s in _svc_secrets(p[svc]) if s["target"] == "pgpass"]
        assert len(pg) == 1 and srcs[pg[0]["source"]] == var, (svc, pg)
    # and each body is written for the driver that reads it
    assert roles["NOO_PGPASS_GATEWAY"][0] == "sqlx", "the gateway connects with sqlx"
    for var in ("NOO_PGPASS_WORKER", "NOO_PGPASS_TRELLION", "NOO_PGPASS_EVOLVE"):
        assert roles[var][0] == "libpq", f"{var}: that container connects with psycopg (libpq)"


def test_launcher_derives_pgpass_bodies(tmp_path: Path) -> None:
    """Same inputs and bytes as the Rust test
    `onboard::sh::file_secret_env_tests::pgpass_bodies_escape_per_driver_and_skip_empty`:
    the sqlx body carries the password verbatim, the libpq body escapes `\\`
    and `:` (libpq ends the password at an unescaped `:`)."""
    (tmp_path / "docker-compose.cluster.yml").write_text(BASE.read_text())
    (tmp_path / ".env").write_text('NOO_APP_DB_PASSWORD="app:pw\\x"\nREDIS_PASSWORD=r1\n')
    script = (
        f"source {ROOT}/scripts/lib-secrets.sh; derive_file_secrets; "
        'printf "%s" "$NOO_PGPASS_GATEWAY"; printf "\\0"; printf "%s" "$NOO_PGPASS_WORKER"; printf "\\0"; '
        'printf "%s" "$NOO_PGPASS_TRELLION"; printf "\\0"; printf "%s" "$NOO_PGPASS_EVOLVE"; printf "\\0"; '
        'printf "%s" "${NOO_JWT_SECRET-UNSET}"; printf "\\0"; printf "%s" "${REDIS_PASSWORD-UNSET}"'
    )
    out = subprocess.run(
        ["bash", "-c", script], cwd=tmp_path, capture_output=True, text=True, timeout=30,
        env={"PATH": "/usr/bin:/bin", "POSTGRES_PASSWORD": "superpw"},
    )
    assert out.returncode == 0, out.stderr
    gw, wk, tr, ev, jwt, redis = out.stdout.split("\0")
    assert gw == "postgres:5432:noomesh:noo:superpw\npostgres:5432:noomesh:noo_app:app:pw\\x"
    assert wk == "postgres:5432:noomesh:noo_app:app\\:pw\\\\x"
    # the add-ons: libpq bodies, only the roles whose password is set
    assert tr == "postgres:5432:noomesh:noo_app:app\\:pw\\\\x"
    assert ev == "", "no evolve password anywhere → an empty body (no file, no pointer)"
    assert jwt == "", "an unset source must be exported EMPTY so compose creates the service"
    assert redis == "UNSET", ".env assigns it — compose reads it from there; the launcher must not shadow it"


# ── the CLI's verify row knows the same tier-1 names ──────────────────────


def test_the_verify_row_tier1_list_is_the_union_of_the_readers() -> None:
    src = (ROOT / "noo-cli/src/commands/secrets_delivery.rs").read_text()
    m = re.search(r"pub\(crate\) const TIER1: &\[&str\] = &\[(.*?)\n\];", src, re.S)
    assert m, "TIER1 not found in secrets_delivery.rs"
    listed = set(re.findall(r'"([A-Z0-9_]+)"', m.group(1)))
    assert listed == tier1_names(), (sorted(listed - tier1_names()), sorted(tier1_names() - listed))


# ── the image floor ───────────────────────────────────────────────────────


def _floor() -> str:
    m = re.search(r"^x-noo-secrets-floor:\s*(\S+)\s*$", BASE.read_text(), re.M)
    assert m, "docker-compose.cluster.yml declares no x-noo-secrets-floor"
    return m.group(1)


def _bash_floor(tag: str) -> int:
    return subprocess.run(
        ["bash", "-c", f'source scripts/lib-dist.sh; require_secrets_floor . "{tag}"'],
        cwd=ROOT, capture_output=True, text=True, timeout=30,
    ).returncode


def test_the_floor_is_declared_and_the_launcher_refuses_below_it() -> None:
    floor = _floor()
    m = re.match(r"^stack-v(\d+)\.(\d+)\.(\d+)$", floor)
    assert m, floor
    major, minor, patch = map(int, m.groups())
    below = f"v{major}.{minor}.{patch - 1}" if patch else f"v{major}.{minor - 1}.999"
    assert _bash_floor(floor.removeprefix("stack-")) == 0
    assert _bash_floor(f"v{major}.{minor}.{patch + 1}") == 0
    assert _bash_floor(below) == 1, f"{below} is below {floor} and must be refused"
    assert _bash_floor("latest") == 1, "an unversioned tag cannot be shown to meet the floor"


def test_a_release_candidate_meets_the_floor_as_its_release() -> None:
    # Promotion model: `vX.Y.Z-rc.N` is cut on staging and rehearsed with
    # `noo stack start --dist --tag vX.Y.Z-rc.N`; it carries vX.Y.Z's code.
    floor = _floor()
    m = re.match(r"^stack-v(\d+)\.(\d+)\.(\d+)$", floor)
    assert m, floor
    major, minor, patch = map(int, m.groups())
    below = f"v{major}.{minor}.{patch - 1}" if patch else f"v{major}.{minor - 1}.999"
    assert _bash_floor(f"v{major}.{minor}.{patch + 1}-rc.1") == 0
    assert _bash_floor(f"{floor.removeprefix('stack-')}-rc.3") == 0
    assert _bash_floor(f"{below}-rc.1") == 1, "an rc below the floor is still below it"
    assert _bash_floor(f"v{major}.{minor}.{patch + 1}-beta") == 1, "only -rc.N is understood"


@pytest.mark.parametrize("script,needle", [
    ("scripts/noomesh-start.sh", 'require_secrets_floor "." "$DIST_TAG" || exit 1'),
    ("scripts/noomesh-restart.sh", 'require_secrets_floor "." "$NOO_IMAGE_TAG" || exit 1'),
    ("noo-cli/src/commands/upgrade.rs", "if !tag_meets_floor(&tag, &floor) {"),
])
def test_the_floor_is_enforced_where_images_are_chosen(script: str, needle: str) -> None:
    assert needle in (ROOT / script).read_text(), f"{script} no longer enforces the secrets floor"


def test_a_tagged_floor_really_reads_the_jwt_secret_from_a_file() -> None:
    """The floor must name a stack whose gateway reads NOO_JWT_SECRET through
    `secret_env` everywhere — stack-v0.2.78 carried the readers but three
    direct `std::env::var("NOO_JWT_SECRET")` sites were fixed after it. Until
    the floor tag exists locally there is nothing to check (said, not
    skipped silently)."""
    floor = _floor()
    have = subprocess.run(["git", "rev-parse", "-q", "--verify", f"refs/tags/{floor}"], cwd=ROOT, capture_output=True, text=True)
    if have.returncode != 0:
        print(f"{floor} is not tagged in this clone yet — nothing to verify")
        return
    for path in ("gateway-rust/src/mcp_external.rs", "gateway-rust/src/routes/addon_token.rs"):
        shown = subprocess.run(["git", "show", f"{floor}:{path}"], cwd=ROOT, capture_output=True, text=True)
        # A path the tag does not have is a FAIL, not an empty (passing) body.
        assert shown.returncode == 0 and shown.stdout.strip(), f"could not read {path} at {floor}: {shown.stderr.strip()}"
        body = shown.stdout
        assert 'std::env::var("NOO_JWT_SECRET")' not in body, (
            f"{floor}'s {path} still reads NOO_JWT_SECRET from the plain env — that image cannot run this compose file; "
            "raise x-noo-secrets-floor to the first stack tag that carries the fix"
        )


def _manifest_at(tag: str, path: str, pattern: str) -> set[str]:
    shown = subprocess.run(["git", "show", f"{tag}:{path}"], cwd=ROOT, capture_output=True, text=True)
    # A path the tag does not have is a FAIL, not an empty (passing) manifest.
    assert shown.returncode == 0 and shown.stdout.strip(), f"could not read {path} at {tag}: {shown.stderr.strip()}"
    m = re.search(pattern, shown.stdout, re.S)
    assert m, f"no FILE_BACKED_SECRETS in {path} at {tag}"
    names = set(re.findall(r'"([A-Z0-9_]+)"', m.group(1)))
    assert len(names) >= 10, (tag, path, names)
    return names


def test_a_tagged_floor_reads_every_name_this_file_points_at() -> None:
    """Every `<NAME>_FILE` pointer compose hands the gateway / the worker must
    name a secret the FLOOR's image reads through `secret_env` — else that
    image boots without it (a search key "unset", a channel "not
    configured": silent, not an outage, and loud is the rule). Checked
    against the floor tag's own manifests, so lowering the floor to a stack
    that predates a reader FAILS here once the tag exists. The tier-2 keys
 are what made stack-v0.2.79 too old."""
    floor = _floor()
    have = subprocess.run(["git", "rev-parse", "-q", "--verify", f"refs/tags/{floor}"], cwd=ROOT, capture_output=True, text=True)
    if have.returncode != 0:
        print(f"{floor} is not tagged in this clone yet — nothing to verify")
        return
    rust = _manifest_at(floor, "gateway-rust/src/secret_env.rs", r"pub const FILE_BACKED_SECRETS: &\[&str\] = &\[(.*?)\n\];")
    py = _manifest_at(floor, "src/noomesh/secret_env.py", r"FILE_BACKED_SECRETS: tuple\[str, \.\.\.\] = \((.*?)\n\)")
    p = full_projection()["services"]
    missing = []
    checked = 0
    # The add-on: trellion runs the FLOOR's noomesh Python plus trellion's
    # own reader, pinned (ADDON_MANIFESTS) to the sha the floor's signed lock
    # records (trellion 4d445003) for stack-v0.2.80 — verified by hand at the
    # flip. (trellion-intel, noo-evolve: moved with the overlay to the add-on
    # repo (N6).)
    trellion_side = py | set(ADDON_MANIFESTS["trellion"][2])
    for svc, manifest in (
        ("gateway", rust),
        ("worker", py),
        ("trellion", trellion_side),
    ):
        for key, val in env_of(p[svc]).items():
            if not POINTER.match(val) or not key.endswith("_FILE"):
                continue
            checked += 1
            name = key.removesuffix("_FILE")
            if name not in manifest:
                missing.append(f"{svc}: {name}")
    assert checked >= 30, checked
    assert not missing, (
        f"{floor}'s images do not read these through secret_env, yet this compose file delivers them only as files: "
        f"{missing} — raise x-noo-secrets-floor to the first stack tag that carries the readers"
    )
