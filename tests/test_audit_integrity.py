# SPDX-License-Identifier: AGPL-3.0-only
# Copyright 2026 PersonifAI LLC

"""CRIT-6 audit tamper-evidence — hash determinism + cross-language vector."""
import os

os.environ["NOO_AUDIT_HMAC_KEY"] = "test-audit-key-123"

from noomesh.gateway.audit_log import audit_row_hash  # noqa: E402


def test_hash_is_deterministic():
    a = audit_row_hash("auth_failure", "warning", "alice", "gateway", "bad_password", "req1")
    b = audit_row_hash("auth_failure", "warning", "alice", "gateway", "bad_password", "req1")
    assert a == b
    assert len(a) == 64  # sha256 hex


def test_any_field_change_changes_hash():
    base = audit_row_hash("auth_failure", "warning", "alice", "gateway", "bad_password", "req1")
    assert audit_row_hash("auth_success", "warning", "alice", "gateway", "bad_password", "req1") != base
    assert audit_row_hash("auth_failure", "critical", "alice", "gateway", "bad_password", "req1") != base
    assert audit_row_hash("auth_failure", "warning", "mallory", "gateway", "bad_password", "req1") != base
    assert audit_row_hash("auth_failure", "warning", "alice", "gateway", "ok", "req1") != base


def test_known_vector_matches_rust():
    # Frozen vector — the Rust `audit_row_hash` unit test asserts this SAME hex
    # for the SAME inputs + key, proving both writers agree (CRIT-6).
    h = audit_row_hash("auth_failure", "warning", "alice", "gateway", "bad_password", "")
    assert h == "d7d4771f53f878b27d37dc4a0ee58e018e967d3d5de689eaa26c15fd1b2712e1"


def _without_key(monkeypatch):
    for v in ("NOO_AUDIT_HMAC_KEY", "NOO_AUDIT_HMAC_KEY_FILE", "NOO_SECRET_NOO_AUDIT_HMAC_KEY"):
        monkeypatch.delenv(v, raising=False)
    # The login secret is present, as it is in every worker container today:
    # the writer must NOT derive a key from it.
    monkeypatch.setenv("NOO_JWT_SECRET", "a-login-secret-that-must-not-sign-audit-rows")


def test_no_key_means_no_hash_not_a_derived_one(monkeypatch):
    import pytest

    from noomesh.gateway.audit_log import AuditKeyMissing

    _without_key(monkeypatch)
    with pytest.raises(AuditKeyMissing):
        audit_row_hash("auth_failure", "warning", "alice", "gateway", "bad_password", "")


class _Result:
    def __init__(self, value):
        self._value = value

    def scalar_one(self):
        return self._value

    def first(self):
        return self._value


class _RecordingEngine:
    """Stands in for a sync SQLAlchemy engine: records every statement.

    `jsonb_text` plays Postgres for the writer's `CAST(:d AS jsonb)::text`
    question: given the writer's JSON, the text Postgres would store. The
    default hands it back unchanged."""

    def __init__(self, jsonb_text=lambda d: d):
        self.executed = []
        self.jsonb_text = jsonb_text

    @property
    def inserts(self):
        return [p for sql, p in self.executed if sql.lstrip().upper().startswith("INSERT")]

    def connect(self):
        engine = self

        class _Conn:
            def __enter__(self):
                return self

            def __exit__(self, *a):
                return False

            def execute(self, stmt, params=None):
                engine.executed.append((str(stmt), params))
                if "AS jsonb)::text" in str(stmt):
                    return _Result(engine.jsonb_text(params["d"]))
                return _Result(None)

            def commit(self):
                pass

        return _Conn()


def test_missing_key_refuses_the_row_and_says_so(monkeypatch):
    from noomesh.gateway import audit_log

    _without_key(monkeypatch)
    errors = []
    monkeypatch.setattr(audit_log.logger, "error",
                        lambda event, **kw: errors.append((event, kw)))
    engine = _RecordingEngine()
    audit_log.AuditLogger(db_engine=engine).log(
        audit_log.AuditEvent(event_type="exec_denied", actor="alice", outcome="denied"))
    assert engine.executed == [], "a row was written without NOO_AUDIT_HMAC_KEY"
    assert [e for e, _ in errors] == ["audit_write_refused_no_key"]


def test_with_the_key_the_row_is_written_signed_v2(monkeypatch):
    from noomesh.gateway import audit_log

    monkeypatch.setenv("NOO_AUDIT_HMAC_KEY", "test-audit-key-123")
    engine = _RecordingEngine()
    audit_log.AuditLogger(db_engine=engine).log(
        audit_log.AuditEvent(event_type="exec_denied", actor="alice", outcome="denied",
                             request_id="r1"))
    assert len(engine.inserts) == 1
    p = engine.inserts[0]
    assert p["eh"].startswith("v2:")
    # Recomputed from exactly what was bound — the stored values.
    assert p["eh"] == audit_log.audit_row_hash_v2(
        id=p["id"], timestamp_us=audit_log.stored_micros(p["ts"]), event_type="exec_denied",
        severity="info", actor="alice", resource="", outcome="denied", request_id="r1",
        details=p["details"], prev_hash=None)


# ---------------------------------------------------------------------------
# Hash v2: the shared vectors, the real writer, the time.
# ---------------------------------------------------------------------------

def _vectors():
    import json
    import pathlib

    path = pathlib.Path(__file__).resolve().parent / "fixtures" / "audit_hash_v2_vectors.json"
    doc = json.loads(path.read_text())
    assert len(doc["vectors"]) >= 3, "the fixture lost its vectors"
    return doc


def test_v2_vectors_match_the_rust_verifier():
    # gateway-rust/src/audit_integrity.rs::the_shared_v2_vectors_match_the_python_writer
    # asserts the SAME canonical text and digest for the SAME rows.
    from noomesh.gateway.audit_log import audit_row_hash_v2, canonical_v2

    doc = _vectors()
    key = doc["key"].encode()
    for v in doc["vectors"]:
        assert canonical_v2(**v["row"]).decode("utf-8") == v["canonical"], v["name"]
        assert audit_row_hash_v2(key=key, **v["row"]) == v["entry_hash"], v["name"]


def test_the_real_python_writer_signs_the_vector_row(monkeypatch):
    """The writer itself — not just the helper — produces the vector's digest:
    `_write_db` with the vector row's id, time, fields and Postgres's jsonb
    text for its details binds exactly `entry_hash`."""
    import uuid as uuidmod

    from noomesh.gateway import audit_log

    doc = _vectors()
    v = next(x for x in doc["vectors"] if x["name"] == "python_worker_row")
    row = v["row"]
    monkeypatch.setenv("NOO_AUDIT_HMAC_KEY", doc["key"])
    monkeypatch.setattr(audit_log.uuid, "uuid4", lambda: uuidmod.UUID(row["id"]))
    # The writer's own JSON (key order and spacing of json.dumps) is NOT what
    # Postgres stores; the fake answers with Postgres's text, as Postgres would.
    asked = []
    engine = _RecordingEngine(jsonb_text=lambda d: asked.append(d) or row["details"])
    event = audit_log.AuditEvent(
        event_type=row["event_type"], severity=row["severity"], actor=row["actor"],
        resource=row["resource"], outcome=row["outcome"],
        details={"source_ip": "10.0.0.7", "path": "/api/x"},
        timestamp=row["timestamp_us"] / 1_000_000, request_id=row["request_id"])
    audit_log.AuditLogger(db_engine=engine).log(event)
    assert asked == ['{"source_ip": "10.0.0.7", "path": "/api/x"}']
    [p] = engine.inserts
    assert audit_log.stored_micros(p["ts"]) == row["timestamp_us"]
    assert p["details"] == row["details"], "the writer must store the text it hashed"
    assert p["eh"] == v["entry_hash"]


def test_the_hashed_time_is_the_stored_microseconds():
    """`AuditEvent.timestamp` is a float; what is stored — and hashed — is the
    microsecond datetime bound to the column, exactly, with no float in it."""
    from datetime import datetime, timezone

    from noomesh.gateway import audit_log

    for us in (1790000000123456, 1790000000999999, 1790000000000001, 0, 1):
        ts = datetime.fromtimestamp(us / 1_000_000, tz=timezone.utc)
        assert audit_log.stored_micros(ts) == us, us
    # A float with sub-microsecond noise: the hashed value is the bound one.
    p = audit_log._signed_params(
        audit_log.AuditEvent(event_type="x", timestamp=1790000000.1234567891),
        b"k", "{}")
    assert p["ts"].microsecond == audit_log.stored_micros(p["ts"]) % 1_000_000
    assert p["eh"] == audit_log.audit_row_hash_v2(
        key=b"k", id=p["id"], timestamp_us=audit_log.stored_micros(p["ts"]), event_type="x",
        severity="info", actor="", resource="", outcome="", request_id=p["rid"],
        details="{}", prev_hash=None)


def test_the_v2_form_is_length_prefixed():
    # v1 joined on \x1f: a value carrying one shifted a field boundary.
    from noomesh.gateway.audit_log import canonical_v2

    base = dict(id="i", timestamp_us=1, event_type="e", severity="s", resource="r",
                outcome="o", request_id=None, details=None, prev_hash=None)
    assert canonical_v2(actor="a\x1fb", **base) != canonical_v2(actor="a", **{**base, "event_type": "e\x1fb"})
    # NULL is not "".
    assert canonical_v2(actor="a", **base) != canonical_v2(actor="a", **{**base, "request_id": ""})


def test_the_writer_holds_no_derivation_of_the_login_secret():
    # The retired derivation lives only in the gateway's verifier now
    # (audit_integrity.rs::retired_key_from). A copy here would be a second
    # signing source someone could wire back in.
    import pathlib

    src = (pathlib.Path(__file__).resolve().parents[1]
           / "src/noomesh/gateway/audit_log.py").read_text()
    code = "\n".join(line for line in src.splitlines() if not line.lstrip().startswith("#"))
    assert "audit-integrity-fallback" not in code
    assert "audit-hmac:" not in code
    assert 'secret_or_empty("NOO_JWT_SECRET")' not in code


def test_every_audit_writer_is_given_the_key_and_the_registry_says_so():
    """Every process that writes audit rows — the gateway, and each service
    running `worker_pool` (it sets NOO_WORKER_SURFACES) — receives
    NOO_AUDIT_HMAC_KEY as a file, sourced from that variable; and the
    registry row's `consumers` names exactly those containers, so a rotation
    recreates every writer. A writer left without the key refuses every row,
    silently from the operator's point of view until someone reads the log."""
    import re
    from pathlib import Path

    from tests._compose_projection import env_of, full_projection
    from tests.test_compose_secret_files import _file_source_var

    services = full_projection()["services"]
    writers = sorted(
        n for n, svc in services.items()
        if n == "gateway" or "NOO_WORKER_SURFACES" in env_of(svc)
    )
    # trellion-intel's row: moved with the overlay to the add-on repo (N6)
    assert {"gateway", "worker", "trellion"} <= set(writers), writers
    for n in writers:
        assert _file_source_var(services[n], "NOO_AUDIT_HMAC_KEY_FILE") == "NOO_AUDIT_HMAC_KEY", (
            f"{n} writes security audit rows but is not given NOO_AUDIT_HMAC_KEY as a file"
        )

    src = (Path(__file__).resolve().parents[1] / "noo-cli/src/commands/secrets.rs").read_text()
    block = src[src.index('key: "NOO_AUDIT_HMAC_KEY"'):]
    block = block[:block.index("required_when")]
    consumers = set(re.findall(r'"(noo-[a-z-]+)"', block[block.index("consumers"):]))
    assert consumers, "parsed no consumers from the NOO_AUDIT_HMAC_KEY registry row"
    # A licensed add-on's container (its overlay arrives in its signed bundle,
    # N6) is a writer core cannot compose, so the row may name it beyond the
    # composed writers — but only as `noo-<add-on>` for an ADDON_ROWS row with
    # `licensed: Some(..)`, and never a container core composes as a non-writer.
    rows = (Path(__file__).resolve().parents[1] / "noo-cli/src/commands/addons.rs").read_text()
    licensed = {
        "noo-" + k.replace("_", "-")
        for k in re.findall(r'key:\s*"([a-z_]+)",[^}]*?licensed:\s*Some\(', rows, re.S)
    }
    assert licensed, "parsed no licensed add-on from ADDON_ROWS — the parse broke"
    composed = {"noo-" + n for n in services}
    extra = consumers - {"noo-" + n for n in writers}
    assert extra <= licensed - composed, (
        f"the NOO_AUDIT_HMAC_KEY row names {sorted(extra - (licensed - composed))}, which is "
        "neither a composed audit writer nor a licensed add-on's container"
    )
    assert {"noo-" + n for n in writers} <= consumers, (consumers, writers)


if __name__ == "__main__":
    test_hash_is_deterministic()
    test_any_field_change_changes_hash()
    print("cross-lang vector (empty request_id):",
          audit_row_hash("auth_failure", "warning", "alice", "gateway", "bad_password", ""))
    print("all Python audit-integrity tests passed")


# ---------------------------------------------------------------------------
# The hash chain: shared vectors, the writer's link, the lock, retention.
# ---------------------------------------------------------------------------

def test_chain_vectors_match_the_rust_verifier():
    # gateway-rust/src/audit_chain.rs::chain_hash_matches_the_shared_vectors
    # asserts the SAME hex for the SAME inputs.
    import json
    import pathlib

    from noomesh.gateway.audit_log import chain_hash

    doc = json.loads((pathlib.Path(__file__).resolve().parent / "fixtures" / "audit_chain_vectors.json").read_text())
    assert len(doc["cases"]) >= 3
    for c in doc["cases"]:
        assert chain_hash(key=doc["key"].encode(), seq=c["seq"], prev=c["prev"],
                          entry_hash=c["entry_hash"]) == c["chain_hash"], c


class _ChainEngine(_RecordingEngine):
    """A recording engine whose chain tail is `tail` ((seq, hash, ts) or None)."""

    def __init__(self, tail):
        super().__init__()
        self.tail = tail

    def connect(self):
        engine = self
        inner = super().connect()

        class _Conn:
            def __enter__(self):
                return self

            def __exit__(self, *a):
                return False

            def execute(self, stmt, params=None):
                if "chain_seq, chain_hash, timestamp" in str(stmt):
                    engine.executed.append((str(stmt), params))
                    return _Result(engine.tail)
                return inner.execute(stmt, params)

            def commit(self):
                pass

            def rollback(self):
                engine.rolled_back = True

        return _Conn()


def _log(engine, monkeypatch, ts=None):
    from noomesh.gateway import audit_log

    monkeypatch.setenv("NOO_AUDIT_HMAC_KEY", "test-audit-key-123")
    kw = {} if ts is None else {"timestamp": ts}
    audit_log.AuditLogger(db_engine=engine).log(
        audit_log.AuditEvent(event_type="exec_denied", actor="alice", outcome="denied", **kw))


def test_a_row_is_linked_after_the_newest_chained_row(monkeypatch):
    from datetime import datetime, timezone

    from noomesh.gateway import audit_log

    tail_ts = datetime(2026, 10, 1, tzinfo=timezone.utc)
    engine = _ChainEngine((41, "ab" * 32, tail_ts))
    _log(engine, monkeypatch, ts=tail_ts.timestamp() + 5)
    [p] = engine.inserts
    assert p["seq"] == 42
    assert p["ch"] == audit_log.chain_hash(key=b"test-audit-key-123", seq=42, prev="ab" * 32, entry_hash=p["eh"])
    # The lock is taken before the tail is read, in the same connection.
    sqls = [s for s, _ in engine.executed]
    lock = next(i for i, s in enumerate(sqls) if "pg_advisory_xact_lock" in s)
    tail = next(i for i, s in enumerate(sqls) if "chain_seq, chain_hash, timestamp" in s)
    ins = next(i for i, s in enumerate(sqls) if s.lstrip().upper().startswith("INSERT"))
    assert lock < tail < ins
    assert engine.executed[lock][1] == {"k": audit_log.CHAIN_LOCK_KEY}


def test_a_row_is_never_timed_before_its_predecessor(monkeypatch):
    from datetime import datetime, timezone

    from noomesh.gateway import audit_log

    tail_ts = datetime(2026, 10, 1, 12, tzinfo=timezone.utc)
    engine = _ChainEngine((7, "cd" * 32, tail_ts))
    _log(engine, monkeypatch, ts=tail_ts.timestamp() - 3600)  # the event is older than the tail
    [p] = engine.inserts
    assert p["ts"] == tail_ts
    assert p["eh"] == audit_log.audit_row_hash_v2(
        id=p["id"], timestamp_us=audit_log.stored_micros(p["ts"]), event_type="exec_denied",
        severity="info", actor="alice", resource="", outcome="denied", request_id=p["rid"],
        details=p["details"], prev_hash=None)


def test_before_the_chain_starts_the_row_is_written_unchained(monkeypatch):
    engine = _ChainEngine(None)
    _log(engine, monkeypatch)
    [p] = engine.inserts
    assert p["seq"] is None and p["ch"] is None


def test_a_database_without_the_chain_columns_still_records_the_row(monkeypatch):
    """A worker that starts before the gateway has run migration 092 must not
    lose the audit row."""
    from noomesh.gateway import audit_log

    class _Old(_RecordingEngine):
        def connect(self):
            engine = self
            inner = super().connect()

            class _Conn:
                def __enter__(self):
                    return self

                def __exit__(self, *a):
                    return False

                def execute(self, stmt, params=None):
                    if "chain_seq, chain_hash, timestamp" in str(stmt):
                        raise RuntimeError('column "chain_seq" does not exist')
                    return inner.execute(stmt, params)

                def commit(self):
                    pass

                def rollback(self):
                    pass

            return _Conn()

    engine = _Old()
    monkeypatch.setenv("NOO_AUDIT_HMAC_KEY", "test-audit-key-123")
    audit_log.AuditLogger(db_engine=engine).log(
        audit_log.AuditEvent(event_type="exec_denied", actor="alice", outcome="denied"))
    [p] = engine.inserts
    assert "seq" not in p and "ch" not in p
    assert any("chain_seq" not in s for s, _ in engine.executed if s.lstrip().upper().startswith("INSERT"))


def test_retention_checkpoint_names_the_range_and_blocks_the_drop_without_a_key(monkeypatch):
    import asyncio
    from datetime import datetime, timezone

    import pytest

    from noomesh.gateway import audit_archive as aa
    from noomesh.gateway import audit_log

    ts = datetime(2026, 10, 1, tzinfo=timezone.utc)
    executed = []

    class _R:
        def __init__(self, v):
            self.v = v

        def first(self):
            return self.v

        def scalar_one(self):
            return self.v

    class _Conn:
        async def __aenter__(self):
            return self

        async def __aexit__(self, *a):
            return False

        async def execute(self, stmt, params=None):
            sql = str(stmt)
            executed.append((sql, params))
            if "min(chain_seq)" in sql:
                return _R((10, 20))
            if "WHERE chain_seq = :h" in sql:
                return _R(("ee" * 32,))
            if "LIMIT 1" in sql and "event_type = :et" in sql:
                return _R(None)
            if "chain_seq, chain_hash, timestamp" in sql:
                return _R((99, "ff" * 32, ts))
            if "AS jsonb)::text" in sql:
                return _R(params["d"])
            return _R(None)

        async def commit(self):
            pass

        async def rollback(self):
            pass

    class _Eng:
        def connect(self):
            return _Conn()

    monkeypatch.setenv("NOO_AUDIT_HMAC_KEY", "test-audit-key-123")
    assert asyncio.run(aa.record_retention_checkpoint(_Eng(), 2026, 9)) is True
    [ins] = [p for s, p in executed if s.lstrip().upper().startswith("INSERT")]
    assert ins["et"] == "audit_retention_checkpoint"
    assert ins["resource"] == "audit-retention:from:10;through:20;chain:" + "ee" * 32
    assert ins["seq"] == 100 and ins["ch"]
    assert ins["ch"] == audit_log.chain_hash(key=b"test-audit-key-123", seq=100, prev="ff" * 32, entry_hash=ins["eh"])

    # No key: it raises, so drop_partition never reaches the drop.
    for v in ("NOO_AUDIT_HMAC_KEY", "NOO_AUDIT_HMAC_KEY_FILE", "NOO_SECRET_NOO_AUDIT_HMAC_KEY"):
        monkeypatch.delenv(v, raising=False)
    dropped = []

    class _DropEng(_Eng):
        def begin(self):
            dropped.append(1)
            raise AssertionError("must not reach the drop")

    with pytest.raises(audit_log.AuditKeyMissing):
        asyncio.run(aa.drop_partition(_DropEng(), 2026, 9))
    assert dropped == []
