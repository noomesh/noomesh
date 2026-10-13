# SPDX-License-Identifier: AGPL-3.0-only
# Copyright 2026 PersonifAI LLC

"""_usable_client_key: libpq refuses client keys that fail its permission rule
(0600 or less; 0640 or less only when ROOT owns the key — fe-secure-openssl.c).
Regression for the exec-context footgun (0644 mount path) from the
2026-07-12 fire drill — and, since 2026-09-28, the contract that a too-open
key is STAGED (a 0600 copy under /tmp/pki) rather than dropped: Postgres now
requires a client certificate from every TCP client, so "fall back to a
password" is a connection that does not work."""
import importlib.util
import os
from pathlib import Path

import pytest

from noomesh.db import engine
from noomesh.db.engine import _stage_dsn_client_key, _staged_key_path, _usable_client_key

REPO = Path(__file__).resolve().parents[1]


def _load_entrypoint():
    spec = importlib.util.spec_from_file_location("_noo_entrypoint_under_test", REPO / "docker" / "entrypoint.py")
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


ENTRYPOINT = _load_entrypoint()
# Both copies of _usable_client_key, run against the same files.
IMPLS = [pytest.param(engine, id="engine"), pytest.param(ENTRYPOINT, id="entrypoint")]


def _key(tmp_path, name, mode, body="k"):
    p = tmp_path / name
    p.write_text(body)
    os.chmod(p, mode)
    return str(p)


def test_0600_key_accepted(tmp_path):
    k = _key(tmp_path, "a.key", 0o600)
    assert _usable_client_key(k) == k


def test_0640_key_owned_by_a_non_root_uid_is_staged(tmp_path, monkeypatch):
    # The 2026-09-30 host8 crash loop: fix-modes left gateway.key 0640 + an
    # ACL for uid 65532, owned by uid 1000. libpq allows 0640 ONLY when root
    # owns the key, so this must be staged, never used as is.
    k = _key(tmp_path, "b.key", 0o640)
    _chown_or_fake(monkeypatch, k, 1000)
    staged = _usable_client_key(k)
    assert staged == _staged_key_path(k) and staged != k
    os.remove(staged)


def test_0644_key_is_staged_to_a_0600_copy(tmp_path):
    # World-readable -> a private copy under /tmp/pki at the same relative
    # path, 0600, same bytes; the copy is what libpq gets.
    k = _key(tmp_path, "c.key", 0o644, body="secret")
    staged = _usable_client_key(k)
    assert staged == _staged_key_path(k) and staged != k
    assert staged.startswith("/tmp/pki/")
    assert os.stat(staged).st_mode & 0o777 == 0o600
    assert open(staged).read() == "secret"
    # a second call reuses the clean copy
    assert _usable_client_key(k) == staged
    os.remove(staged)


def test_the_mount_roots_map_under_tmp_pki():
    assert _staged_key_path("/app/pki/gateway/gateway.key") == "/tmp/pki/gateway/gateway.key"
    assert _staged_key_path("/tls/services/evolve/service.key") == "/tmp/pki/services/evolve/service.key"
    assert _staged_key_path("/x/y.key") == "/tmp/pki/x/y.key"


def test_a_dsn_naming_a_0644_key_gets_the_staged_path(tmp_path):
    k = _key(tmp_path, "d.key", 0o644)
    dsn = f"postgresql://u:p@postgres:5432/db?options=-c%20x&sslcert=/c.crt&sslkey={k}&sslmode=verify-full"
    out = _stage_dsn_client_key(dsn)
    staged = _staged_key_path(k)
    assert out == dsn.replace(f"sslkey={k}", f"sslkey={staged}")
    os.remove(staged)
    # a clean key, or no key, leaves the DSN alone
    ok = _key(tmp_path, "e.key", 0o600)
    assert _stage_dsn_client_key(f"postgresql://u@h/db?sslkey={ok}") == f"postgresql://u@h/db?sslkey={ok}"
    assert _stage_dsn_client_key("postgresql://u@h/db") == "postgresql://u@h/db"


def test_unreadable_key_is_dropped_not_guessed(tmp_path, monkeypatch):
    # Only when no copy can be made does the cert get dropped — the server
    # then refuses with a message that names the certificate.
    k = _key(tmp_path, "f.key", 0o644)
    monkeypatch.setattr("noomesh.db.engine._staged_key_path", lambda p: "/proc/nope/" + os.path.basename(p))
    assert _usable_client_key(k) == ""


def test_missing_path_passthrough(tmp_path):
    assert _usable_client_key("") == ""
    missing = str(tmp_path / "nope.key")
    assert _usable_client_key(missing) == missing


# ---- libpq's exact rule (fe-secure-openssl.c, libpq 18.6 in the images) ----

def _libpq_refuses(mode: int, st_uid: int) -> bool:
    """Transcribed from libpq: st_uid == 0 ? mode & (S_IWGRP|S_IXGRP|S_IRWXO)
    : mode & (S_IRWXG|S_IRWXO)."""
    import stat as s
    if st_uid == 0:
        return bool(mode & (s.S_IWGRP | s.S_IXGRP | s.S_IRWXO))
    return bool(mode & (s.S_IRWXG | s.S_IRWXO))


@pytest.mark.parametrize("impl", IMPLS)
def test_predicate_is_libpqs_rule_for_every_mode_and_owner(impl):
    for uid in (0, 1, 1000, 65532, os.geteuid()):
        for mode in range(0o10000):
            assert impl._libpq_accepts_key(mode, uid) == (not _libpq_refuses(mode, uid)), (oct(mode), uid)


def test_entrypoint_and_engine_predicates_agree():
    for uid in (0, 1000, 65532):
        for mode in range(0o10000):
            assert ENTRYPOINT._libpq_accepts_key(mode, uid) == engine._libpq_accepts_key(mode, uid), (oct(mode), uid)


@pytest.mark.parametrize("mode,uid,accepted", [
    (0o640, 0, True),       # root-owned 0640: the stopgap shape, used as is
    (0o440, 0, True),
    (0o660, 0, False),      # g+w refused even for root
    (0o644, 0, False),
    (0o640, 1000, False),   # the crash-loop shape: 0640 + ACL, operator-owned
    (0o640, 65532, False),
    (0o600, 1000, True),    # libpq does not compare owner to euid
    (0o600, 65532, True),
    (0o400, 1000, True),
    (0o644, 1000, False),
    (0o604, 1000, False),
])
def test_named_cases(mode, uid, accepted):
    assert engine._libpq_accepts_key(mode, uid) is accepted
    assert ENTRYPOINT._libpq_accepts_key(mode, uid) is accepted


# ---- the real _usable_client_key against real files, owner injected ----

def _fake_owner(monkeypatch, path, uid):
    """Make os.stat report `uid` as the owner of `path` (only), so the real
    _usable_client_key sees a root- or other-owned key without chown."""
    real = os.stat

    def fake(p, *a, **kw):
        r = real(p, *a, **kw)
        if os.fspath(p) == path:
            t = list(r)
            t[4] = uid
            return os.stat_result(t)
        return r
    monkeypatch.setattr(os, "stat", fake)


def _chown_or_fake(monkeypatch, path, uid):
    """chown when we can (root in CI containers), else inject stat."""
    if os.geteuid() == 0:
        os.chown(path, uid, -1)
    else:
        _fake_owner(monkeypatch, path, uid)


@pytest.fixture
def staged_cleanup():
    made = []
    yield made
    for p in made:
        try:
            os.remove(p)
        except OSError:
            pass


@pytest.mark.parametrize("impl", IMPLS)
@pytest.mark.parametrize("mode,uid,used_as_is", [
    (0o640, 0, True),        # root-owned 0640: used as is
    (0o640, 4242, False),    # 0640 owned by a non-root other uid: staged
    (0o600, 4242, True),     # 0600 owned by another non-root uid: libpq accepts it
    (0o644, 0, False),       # 0644: staged
    (0o644, 4242, False),
])
def test_usable_client_key_on_owned_files(impl, mode, uid, used_as_is, tmp_path, monkeypatch, staged_cleanup):
    k = _key(tmp_path, f"k{mode:o}-{uid}.key", mode, body="secret")
    _chown_or_fake(monkeypatch, k, uid)
    got = impl._usable_client_key(k)
    if used_as_is:
        assert got == k
        return
    staged_cleanup.append(got)
    assert got == impl._staged_key_path(k) and got.startswith("/tmp/pki/")
    st = os.stat(got)
    assert st.st_mode & 0o777 == 0o600 and st.st_uid == os.geteuid()
    with open(got) as f:
        assert f.read() == "secret"


@pytest.mark.parametrize("impl", IMPLS)
def test_0600_owned_by_euid_used_as_is(impl, tmp_path):
    k = _key(tmp_path, "mine.key", 0o600)
    assert os.stat(k).st_uid == os.geteuid()
    assert impl._usable_client_key(k) == k


@pytest.mark.parametrize("impl", IMPLS)
def test_crash_loop_shape_through_the_dsn_rewrite(impl, tmp_path, monkeypatch, staged_cleanup):
    # gateway.key 0640 owned by uid 1000, read by uid 65532 via an ACL: the
    # sslkey in every DSN must come out pointing at the staged copy.
    k = _key(tmp_path, "gateway.key", 0o640)
    _chown_or_fake(monkeypatch, k, 1000 if os.geteuid() != 1000 else 1001)
    dsn = f"postgresql://u@postgres:5432/db?sslcert=/c.crt&sslkey={k}&sslmode=verify-full"
    staged = impl._staged_key_path(k)
    staged_cleanup.append(staged)
    if impl is engine:
        out = engine._stage_dsn_client_key(dsn)
    else:
        env = {"PAGEINDEX_DSN": dsn}
        assert ENTRYPOINT.stage_pg_client_keys(env) == ["PAGEINDEX_DSN"]
        out = env["PAGEINDEX_DSN"]
    assert out == dsn.replace(f"sslkey={k}", f"sslkey={staged}")


@pytest.mark.parametrize("impl", IMPLS)
def test_a_stale_staged_copy_is_restaged(impl, tmp_path, staged_cleanup):
    # A rotated key must not keep serving the old copy from /tmp/pki.
    k = _key(tmp_path, "rot.key", 0o644, body="old")
    first = impl._usable_client_key(k)
    staged_cleanup.append(first)
    with open(k, "w") as f:
        f.write("new")
    assert impl._usable_client_key(k) == first
    with open(first) as f:
        assert f.read() == "new"


def test_leaf_mount_path_is_staged_under_tmp_pki():
    # #606: trellion/intel present their own leaf at /app/pki/leaf/service.key.
    for impl in (engine, ENTRYPOINT):
        assert impl._staged_key_path("/app/pki/leaf/service.key") == "/tmp/pki/leaf/service.key"


def test_every_engine_dsn_helper_stages_the_key(tmp_path, monkeypatch, staged_cleanup):
    # noo-worker has no entrypoint env rewrite: its audit sink, HeartbeatStore
    # and migration runner build engines from raw env DSNs via _sync_dsn /
    # _async_dsn, so those helpers must stage too.
    k = _key(tmp_path, "w.key", 0o640)
    _chown_or_fake(monkeypatch, k, 1000 if os.geteuid() != 1000 else 1001)
    staged = engine._staged_key_path(k)
    staged_cleanup.append(staged)
    dsn = f"postgresql://u@postgres:5432/db?sslcert=/c.crt&sslkey={k}"
    for helper in (engine._sync_dsn, engine._async_dsn):
        assert helper(dsn) == f"postgresql+psycopg://u@postgres:5432/db?sslcert=/c.crt&sslkey={staged}"
