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
    assert {"gateway", "worker", "trellion", "trellion-intel"} <= set(writers), writers
    for n in writers:
        assert _file_source_var(services[n], "NOO_AUDIT_HMAC_KEY_FILE") == "NOO_AUDIT_HMAC_KEY", (
            f"{n} writes security audit rows but is not given NOO_AUDIT_HMAC_KEY as a file"
        )

    src = (Path(__file__).resolve().parents[1] / "noo-cli/src/commands/secrets.rs").read_text()
    block = src[src.index('key: "NOO_AUDIT_HMAC_KEY"'):]
    block = block[:block.index("required_when")]
    consumers = set(re.findall(r'"(noo-[a-z-]+)"', block[block.index("consumers"):]))
    assert consumers, "parsed no consumers from the NOO_AUDIT_HMAC_KEY registry row"
    assert consumers == {"noo-" + n for n in writers}, (consumers, writers)


if __name__ == "__main__":
    test_hash_is_deterministic()
    test_any_field_change_changes_hash()
    print("cross-lang vector (empty request_id):",
          audit_row_hash("auth_failure", "warning", "alice", "gateway", "bad_password", ""))
    print("all Python audit-integrity tests passed")
