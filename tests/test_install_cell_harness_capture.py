"""The harness-e2e window capture (scripts/install-cell/run.sh, secret_check.py,
stamps.py): every captured file is uploaded only when the upload scan AND the
node's own credentials check pass on that exact file; otherwise only its
lines' timestamps and levels are kept. These artifacts are public."""
from __future__ import annotations

import hashlib
import pathlib
import subprocess
import sys

ROOT = pathlib.Path(__file__).resolve().parents[1]
HERE = ROOT / "scripts" / "install-cell"
sys.path.insert(0, str(HERE))
import secret_check as sc  # noqa: E402

TOKEN = "tok-0123456789abcdef"
SECRET = "sec-fedcba9876543210"
GW_NATS = "Ab3dE5gH7jK9mN1pQ3sT5vW7yZ9bC1dF"  # 32 chars: under the shape scan's 40-character floor
GW_JWT = "jwt-secret-from-a-mounted-file-42"


def _envs(monkeypatch, files: dict[str, bytes | None], gateway=([], [])):
    read = lambda p: files.get(p)  # noqa: E731
    monkeypatch.setattr(sc, "root_read", read)
    monkeypatch.setattr(sc, "gateway_env", lambda: gateway)


def test_node_credentials_by_name_a_file_pointer_and_a_hash_are_refused(tmp_path, monkeypatch, capsys):
    env = f"NODE_ID=n1\nNOO_NODE_AGENT_TOKEN={TOKEN}\nNOO_CLUSTER_SECRET_FILE=/run/s\n".encode()
    _envs(monkeypatch, {"/etc/noo-node-agent.env": env, "/run/s": SECRET.encode() + b"\n"})
    clean, raw, hashed, viafile = (tmp_path / n for n in ("clean.log", "raw.log", "hashed.log", "viafile.log"))
    clean.write_text("2026-11-24T16:38:51Z INFO harness_dispatched\n")
    raw.write_text(f"Authorization: Bearer {TOKEN}\n")
    hashed.write_text("token sha " + hashlib.sha256(TOKEN.encode()).hexdigest() + "\n")
    viafile.write_text(f"secret={SECRET}\n")
    assert sc.main([str(clean)]) == 0
    for f in (raw, hashed, viafile):
        assert sc.main([str(f)]) == 3, f.name
    out = capsys.readouterr().out
    assert TOKEN not in out and SECRET not in out, "the check never prints a value"


def test_a_gateway_only_credential_is_refused_and_a_gateway_file_is_followed_through_its_mount(tmp_path, monkeypatch, capsys):
    gw = ([f"NATS_GATEWAY_PASSWORD={GW_NATS}", "NOO_JWT_SECRET_FILE=/run/secrets/jwt", "NOO_TLS_KEY=/app/pki/gateway/key.pem", "PATH=/usr/bin"],
          [{"Destination": "/run/secrets", "Source": "/srv/noo/secrets"}])
    _envs(monkeypatch, {"/etc/noo-node-agent.env": b"NODE_ID=n1\n", "/srv/noo/secrets/jwt": GW_JWT.encode()}, gw)
    nats, jwt, path = (tmp_path / n for n in ("nats.log", "jwt.log", "path.log"))
    nats.write_text(f"nats connect failed: tls://gateway:{GW_NATS}@localhost:4222\n")
    jwt.write_text(f"signing with {GW_JWT}\n")
    path.write_text("TLS key loaded from /app/pki/gateway/key.pem\n")
    assert sc.main([str(nats)]) == 3 and sc.main([str(jwt)]) == 3
    assert sc.main([str(path)]) == 0, "a path is not a credential"
    out = capsys.readouterr().out
    assert GW_NATS not in out and GW_JWT not in out and "nats.log" in out


def test_a_password_delivered_only_inside_a_url_value_is_refused(tmp_path, monkeypatch, capsys):
    pw = "Zx8Qw2Er4Ty6Ui8Op0As2Df4Gh6Jk8Lm"  # 32 alphanumerics: the shape scan does not see it
    enc = "p%40ss%2Fword-with-escapes-1234"   # URL-encoded: both forms are known
    gw = ([f"PGVECTOR_URL=postgresql://noo:{pw}@postgres:5432/noo", f"DATABASE_URL=postgresql://noo_app:{enc}@postgres:5432/noomesh"], [])
    _envs(monkeypatch, {"/etc/noo-node-agent.env": b"NODE_ID=n1\n"}, gw)
    a, b2, c = (tmp_path / n for n in ("pg.log", "dec.log", "clean.log"))
    a.write_text(f"connecting as noo with {pw}\n")
    b2.write_text("password p@ss/word-with-escapes-1234 rejected\n")
    c.write_text("postgres ready\n")
    assert sc.main([str(a)]) == 3 and sc.main([str(b2)]) == 3 and sc.main([str(c)]) == 0
    out = capsys.readouterr().out
    assert pw not in out and "p@ss" not in out and "pg.log" in out


def test_unreadable_credentials_are_not_a_pass(tmp_path, monkeypatch):
    f = tmp_path / "x.log"
    f.write_text("anything\n")
    _envs(monkeypatch, {})
    assert sc.main([str(f)]) == 2, "no node env: not checked"
    _envs(monkeypatch, {"/etc/noo-node-agent.env": b"NODE_ID=n1\n"}, None)
    assert sc.main([str(f)]) == 2, "no gateway env: not checked, so the gateway window is withheld"


def test_stamps_keep_only_a_real_timestamp_and_a_level_word():
    lines = ('2026-11-24T16:38:51+0000 host noo-harness[1]: {"level":"WARN","fields":{"message":"x","token":"abc"}}\n'
             "2026-11-24T16:38:52.123456789Z time=t level=INFO msg=\"load\" secret=xyz\n"
             "2026-11-24T16:38:53+0000 host x: plain text\n"
             f"{GW_NATS} a line with no timestamp, its first word a credential\n"
             f"    {TOKEN} an indented continuation line\n"
             "2026-11-24T16:38:54Z level=hunter2secret not a level word\n")
    out = subprocess.run([sys.executable, "-I", str(HERE / "stamps.py")], input=lines, capture_output=True, text=True).stdout
    assert out.splitlines() == ["2026-11-24T16:38:51+0000 WARN", "2026-11-24T16:38:52.123456789Z INFO", "2026-11-24T16:38:53+0000 -",
                                "- -", "- -", "2026-11-24T16:38:54Z -"], out
    assert GW_NATS not in out and TOKEN not in out and "hunter2" not in out


def test_the_capture_follows_harness_e2e_and_keeps_a_file_only_on_both_checks():
    run = (HERE / "run.sh").read_text()
    he = run.index('step harness-e2e 1500 -- env NOO_BIN="$NOO_BIN" python3 -I "$HERE/harness_e2e.py"')
    cap = run.index("step harness-e2e-capture 300 -- env")
    assert he < cap < run.index("\nfi\n", cap), "the capture runs right after the judge, inside its block"
    block = run[cap:run.index("        done' || true\n", cap)]
    assert block.count('python3 "$CELL_PY" scan') == 2 and block.count('secret_check.py"') == 2, "both files paths: scan AND secret check"
    for kept in ('mv "$tmp" "$OUT/logs/gateway-window.log"', 'mv "$t2" "$OUT/logs/$1"'):
        guard = block.rindex("if python3", 0, block.index(kept))
        assert "&& python3 -I" in block[guard:block.index(kept)], kept
    assert "abandon" not in run, "no abandoned-turn step in the real matrix"
    assert block.count("logs --timestamps --since") == 2, "docker logs lines carry real timestamps (the stamps keep only those)"
