# SPDX-License-Identifier: AGPL-3.0-only
# Copyright 2026 PersonifAI LLC

"""redis-py 8 against the TLS-only, mTLS, password-protected Redis the stack runs.

The lock moved redis 4.6.0 -> 8.1.0. Every other Python test fakes the client,
so none of them would notice what the move changes for us:

* ``ssl_check_hostname`` defaulted to False in redis-py 4 and defaults to True
  in 8. The client verifies the CA either way; from 5 on it ALSO checks that the
  server certificate names the host in ``REDIS_URL``. The cluster issues the
  ``redis`` service certificate with SANs ``redis`` / ``localhost`` /
  ``127.0.0.1`` (``ClusterCA.issue_service_cert``), and ``REDIS_URL`` is
  ``rediss://redis:6379``, so the stack connects; a URL naming a host the
  certificate does not (an IP or DNS name nobody put in the SANs) now fails
  closed. Pinned both ways below.
* ``redis.from_url`` / ``redis.asyncio.from_url`` kwargs we pass
  (``decode_responses``, ``encoding``, ``ssl_ca_certs``, ``ssl_certfile``,
  ``ssl_keyfile``) and the commands the scheduler and the heartbeat use
  (``hset(mapping=)``, ``zadd({member: score})``, MULTI/EXEC pipelines, ``set(ex=)``)
  are exercised here over a REAL TLS socket with a client certificate required,
  signed by the repo's own ``ClusterCA``.

The server is a small RESP2 implementation (no redis-server binary on the CI
runner); it is only as faithful as the commands above, which is all this code
base sends.
"""

from __future__ import annotations

import asyncio
import socket
import ssl
import threading

import pytest

import redis
import redis.asyncio as aioredis

from noomesh.cache import _redis_ssl_kwargs
from noomesh.cluster.scheduler import JobScheduler, JobStatus
from noomesh.pki.ca import ClusterCA

PASSWORD = "s3cret-redis-pw"


class _FakeRedisServer:
    """A threaded RESP2 server speaking TLS with a required client certificate."""

    def __init__(self, ctx: ssl.SSLContext) -> None:
        self.ctx = ctx
        self.lsock = socket.socket()
        self.lsock.bind(("127.0.0.1", 0))
        self.lsock.listen(8)
        self.port = self.lsock.getsockname()[1]
        self.kv: dict[str, str] = {}
        self.hashes: dict[str, dict[str, str]] = {}
        self.zsets: dict[str, dict[str, float]] = {}
        self.sets: dict[str, set[str]] = {}
        self.client_cert_seen = False
        self.hello_protocols: list[str] = []
        self._stop = False
        self._t = threading.Thread(target=self._accept, daemon=True)
        self._t.start()

    def close(self) -> None:
        self._stop = True
        try:
            self.lsock.close()
        except OSError:
            pass

    def _accept(self) -> None:
        while not self._stop:
            try:
                raw, _ = self.lsock.accept()
            except OSError:
                return
            threading.Thread(target=self._serve, args=(raw,), daemon=True).start()

    # -- RESP -------------------------------------------------------------

    @staticmethod
    def _readline(f) -> bytes:
        return f.readline().rstrip(b"\r\n")

    def _read_command(self, f) -> list[str] | None:
        head = self._readline(f)
        if not head:
            return None
        assert head[:1] == b"*", head
        out = []
        for _ in range(int(head[1:])):
            ln = int(self._readline(f)[1:])
            out.append(f.read(ln + 2)[:-2].decode())
        return out

    class _Map(dict):
        """Encoded as a RESP3 map (`%`)."""

    class _Set(set):
        """Encoded as a RESP3 set (`~`)."""

    @staticmethod
    def _enc(v, p3: bool = False) -> bytes:
        enc = _FakeRedisServer._enc
        if v is None:
            return b"_\r\n" if p3 else b"$-1\r\n"
        if p3 and isinstance(v, _FakeRedisServer._Map):
            return b"%%%d\r\n" % len(v) + b"".join(enc(k, p3) + enc(x, p3) for k, x in v.items())
        if p3 and isinstance(v, _FakeRedisServer._Set):
            return b"~%d\r\n" % len(v) + b"".join(enc(x, p3) for x in sorted(v))
        if isinstance(v, bool):
            return b":1\r\n" if v else b":0\r\n"
        if isinstance(v, int):
            return b":%d\r\n" % v
        if isinstance(v, bytes):  # a raw simple-string / error line
            return v
        if isinstance(v, (list, tuple, set)):
            return b"*%d\r\n" % len(v) + b"".join(enc(x, p3) for x in v)
        s = str(v).encode()
        return b"$%d\r\n%s\r\n" % (len(s), s)

    def _exec(self, c: list[str]):
        cmd = c[0].upper()
        a = c[1:]
        if cmd == "PING":
            return b"+PONG\r\n"
        if cmd == "SET":
            if "NX" in [x.upper() for x in a[2:]] and a[0] in self.kv:
                return None
            self.kv[a[0]] = a[1]
            return b"+OK\r\n"
        if cmd == "GET":
            return self.kv.get(a[0])
        if cmd == "DEL":
            n = sum(1 for k in a if self.kv.pop(k, None) is not None)
            return n
        if cmd == "HSET":
            h = self.hashes.setdefault(a[0], {})
            new = 0
            for k, v in zip(a[1::2], a[2::2]):
                new += k not in h
                h[k] = v
            return new
        if cmd == "HGETALL":
            return self._Map(self.hashes.get(a[0], {}))
        if cmd == "ZADD":
            z = self.zsets.setdefault(a[0], {})
            new = 0
            for score, member in zip(a[1::2], a[2::2]):
                new += member not in z
                z[member] = float(score)
            return new
        if cmd == "ZRANGE":
            z = self.zsets.get(a[0], {})
            return [m for m, _ in sorted(z.items(), key=lambda kv: kv[1])]
        if cmd == "ZREM":
            z = self.zsets.get(a[0], {})
            return sum(1 for m in a[1:] if z.pop(m, None) is not None)
        if cmd == "ZCARD":
            return len(self.zsets.get(a[0], {}))
        if cmd == "SADD":
            s = self.sets.setdefault(a[0], set())
            n = len(set(a[1:]) - s)
            s.update(a[1:])
            return n
        if cmd == "SREM":
            s = self.sets.setdefault(a[0], set())
            n = len(set(a[1:]) & s)
            s.difference_update(a[1:])
            return n
        if cmd == "SMEMBERS":
            return self._Set(self.sets.get(a[0], set()))
        if cmd == "SISMEMBER":
            return int(a[1] in self.sets.get(a[0], set()))
        if cmd == "SCARD":
            return len(self.sets.get(a[0], set()))
        return b"-ERR unknown command '%s'\r\n" % cmd.encode()

    def _serve(self, raw: socket.socket) -> None:
        try:
            conn = self.ctx.wrap_socket(raw, server_side=True)
        except (ssl.SSLError, OSError):
            raw.close()
            return
        if conn.getpeercert():
            self.client_cert_seen = True
        f = conn.makefile("rwb", buffering=0)
        authed = False
        p3 = False
        queued: list[list[str]] | None = None
        try:
            while True:
                c = self._read_command(f)
                if c is None:
                    return
                cmd = c[0].upper()
                if cmd == "HELLO":
                    # redis-py 8 opens with `HELLO 3 AUTH <user> <password>`.
                    # Keep the AUTH decision in one place.
                    if "AUTH" in [x.upper() for x in c]:
                        i = [x.upper() for x in c].index("AUTH")
                        if c[i + 2] != PASSWORD:
                            f.write(b"-WRONGPASS invalid username-password pair\r\n")
                            continue
                        authed = True
                    p3 = c[1] == "3"
                    self.hello_protocols.append(c[1])
                    info = self._Map({"server": "redis", "version": "8.6.0", "proto": int(c[1]), "id": 1})
                    f.write(self._enc(info, p3) if p3 else self._enc([x for kv in info.items() for x in kv]))
                    continue
                if cmd == "AUTH":
                    ok = c[-1] == PASSWORD
                    authed = authed or ok
                    f.write(b"+OK\r\n" if ok else b"-WRONGPASS invalid password\r\n")
                    continue
                if not authed:
                    f.write(b"-NOAUTH Authentication required.\r\n")
                    continue
                if cmd in ("CLIENT", "SELECT"):
                    f.write(b"+OK\r\n")
                elif cmd == "MULTI":
                    queued = []
                    f.write(b"+OK\r\n")
                elif cmd == "EXEC":
                    results = [self._exec(q) for q in (queued or [])]
                    queued = None
                    f.write(b"*%d\r\n" % len(results) + b"".join(self._enc(r, p3) for r in results))
                elif queued is not None:
                    queued.append(c)
                    f.write(b"+QUEUED\r\n")
                else:
                    f.write(self._enc(self._exec(c), p3))
        except (OSError, ssl.SSLError):
            return
        finally:
            conn.close()


@pytest.fixture()
def pki(tmp_path):
    ca = ClusterCA(pki_dir=tmp_path / "pki")
    ca.generate_ca()
    return ca


def _server_ctx(pki: ClusterCA, cert: str, key: str) -> ssl.SSLContext:
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.load_cert_chain(cert, key)
    ctx.load_verify_locations(str(pki.ca_cert_path))
    ctx.verify_mode = ssl.CERT_REQUIRED  # mTLS, as docker/redis-entrypoint.sh
    return ctx


@pytest.fixture()
def redis_tls(pki, tmp_path, monkeypatch):
    """The stack's Redis, in miniature: cluster-CA service cert, mTLS, password."""
    cert, key = pki.issue_service_cert("redis")
    gcert, gkey = pki.issue_gateway_cert()
    srv = _FakeRedisServer(_server_ctx(pki, cert, key))
    monkeypatch.setenv("NOO_TLS_CA", str(pki.ca_cert_path))
    monkeypatch.setenv("NOO_TLS_CERT", gcert)
    monkeypatch.setenv("NOO_TLS_KEY", gkey)
    try:
        yield srv
    finally:
        srv.close()


def _url(srv: _FakeRedisServer, host: str = "localhost") -> str:
    return f"rediss://:{PASSWORD}@{host}:{srv.port}"


def test_redis_py_is_the_8_series() -> None:
    """The contract below is written for 8.x; a downgrade must be deliberate."""
    major = int(redis.__version__.split(".")[0])
    assert major >= 8, redis.__version__


def test_the_job_scheduler_round_trips_over_mtls(redis_tls) -> None:
    sched = JobScheduler(redis_url=_url(redis_tls))

    job_id = sched.submit_job("inference", {"prompt": "hi"}, priority=7)

    job = sched.get_job(job_id)
    assert job is not None
    assert job["status"] == JobStatus.QUEUED.value
    assert job["payload"] == {"prompt": "hi"}  # decode_responses=True -> str, then json
    assert job["priority"] == "7"
    # The pipeline (MULTI/EXEC) landed all three writes.
    assert sched.get_queue_depth() == 1
    assert [j["id"] for j in sched.list_jobs()] == [job_id]

    assert sched.cancel_job(job_id) is True
    assert sched.get_job(job_id)["status"] == JobStatus.CANCELLED.value
    assert sched.get_queue_depth() == 0
    assert sched.list_jobs() == []

    sched.drain_node("n1")
    assert sched.is_node_drained("n1")  # an int 1, as in 4.x
    sched.undrain_node("n1")
    assert not sched.is_node_drained("n1")

    # The server really asked for, and got, a client certificate.
    assert redis_tls.client_cert_seen is True


def test_the_async_client_the_heartbeat_builds_works(redis_tls) -> None:
    """Same construction as HeartbeatScheduler._get_redis / ProactiveAgent._get_redis."""

    async def go() -> str | None:
        r = aioredis.from_url(
            _url(redis_tls), encoding="utf-8", decode_responses=True, **_redis_ssl_kwargs()
        )
        try:
            await r.set("noo:proactive:status", "running", ex=30)
            got = await r.get("noo:proactive:status")
            # The thought-experiment dedup (heartbeat.py): SET NX EX is truthy
            # the first time and falsy once the key exists.
            assert await r.set("noo:te:pair:a:b", "1", nx=True, ex=60)
            assert not await r.set("noo:te:pair:a:b", "1", nx=True, ex=60)
            await r.delete("noo:proactive:status")
            assert await r.get("noo:proactive:status") is None
            return got
        finally:
            await r.aclose()

    assert asyncio.run(go()) == "running"


def test_a_wrong_password_is_refused(redis_tls) -> None:
    sched = JobScheduler(redis_url=_url(redis_tls).replace(PASSWORD, "wrong"))
    with pytest.raises(redis.exceptions.AuthenticationError):
        sched.get_queue_depth()


def test_a_url_naming_a_host_the_certificate_does_not_is_refused(pki, monkeypatch) -> None:
    """redis-py 8 verifies the hostname (4.x did not). Fail closed, loudly."""
    # A service certificate that names `redis` only: connecting by `localhost`
    # reaches the right socket, with a CA-valid cert for the wrong name.
    cert, key = pki.pki_dir / "services" / "x" / "service.crt", pki.pki_dir / "services" / "x" / "service.key"
    pki._issue_leaf(
        cn="x", org="Mesh Cluster Service", cert_path=cert, key_path=key,
        dns_sans=["redis"], ip_sans=[], days=1,
    )
    gcert, gkey = pki.issue_gateway_cert()
    srv = _FakeRedisServer(_server_ctx(pki, str(cert), str(key)))
    monkeypatch.setenv("NOO_TLS_CA", str(pki.ca_cert_path))
    monkeypatch.setenv("NOO_TLS_CERT", gcert)
    monkeypatch.setenv("NOO_TLS_KEY", gkey)
    try:
        sched = JobScheduler(redis_url=_url(srv, "localhost"))
        with pytest.raises(redis.exceptions.ConnectionError) as exc:
            sched.get_queue_depth()
        assert "hostname" in str(exc.value).lower() or "certificate" in str(exc.value).lower()
    finally:
        srv.close()


def test_a_client_without_the_cluster_ca_does_not_connect(redis_tls, monkeypatch) -> None:
    """With no NOO_TLS_CA the client verifies against the system store, which
    does not contain the cluster CA: the connection must not be made."""
    monkeypatch.delenv("NOO_TLS_CA")
    sched = JobScheduler(redis_url=_url(redis_tls))
    with pytest.raises(redis.exceptions.ConnectionError):
        sched.get_queue_depth()


def test_resp3_on_the_wire_but_the_replies_keep_the_shapes_the_code_reads(redis_tls) -> None:
    """redis-py 8 opens with `HELLO 3` (4.x spoke RESP2). `legacy_responses`
    (default True) keeps the reply SHAPES the code was written against:
    hgetall -> dict[str, str], zrange -> list[str], smembers -> set[str],
    zcard/sadd -> int. scheduler.py indexes into exactly these."""
    r = redis.from_url(_url(redis_tls), decode_responses=True, **_redis_ssl_kwargs())
    r.hset("h", mapping={"a": "1", "b": "2"})
    r.zadd("z", {"j2": -1, "j1": -5})
    r.sadd("s", "x", "y")

    assert redis_tls.hello_protocols == ["3"]
    assert r.hgetall("h") == {"a": "1", "b": "2"}
    assert r.zrange("z", 0, -1) == ["j1", "j2"]
    got = r.smembers("s")
    assert got == {"x", "y"} and isinstance(got, set)
    assert r.zcard("z") == 2 and r.scard("s") == 2
    # `active_ids | set(queued_ids)` in list_jobs() needs a real set on the left.
    assert (got | set(r.zrange("z", 0, -1))) == {"x", "y", "j1", "j2"}
    assert r.get("missing") is None
