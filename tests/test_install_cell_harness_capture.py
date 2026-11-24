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


def _envs(monkeypatch, files: dict[str, bytes | None]):
    import harness_e2e
    read = lambda p: files.get(p)  # noqa: E731
    monkeypatch.setattr(sc, "root_read", read)
    monkeypatch.setattr(harness_e2e, "root_read", read)  # agent_secret follows a KEY_FILE pointer with it


def test_a_log_with_a_credential_or_its_hash_is_refused_and_a_clean_one_passes(tmp_path, monkeypatch, capsys):
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


def test_unreadable_credentials_are_not_a_pass(tmp_path, monkeypatch):
    _envs(monkeypatch, {})
    f = tmp_path / "x.log"
    f.write_text("anything\n")
    assert sc.main([str(f)]) == 2, "not checked is not clean: the caller keeps only the stamps"


def test_stamps_keep_only_the_time_and_the_level():
    lines = ('2026-11-24T16:38:51+0000 host noo-harness[1]: {"level":"WARN","fields":{"message":"x","token":"abc"}}\n'
             "2026-11-24T16:38:52+0000 host ollama[2]: time=t level=INFO msg=\"load\" secret=xyz\n"
             "2026-11-24T16:38:53+0000 host x: plain text with a secret\n")
    out = subprocess.run([sys.executable, "-I", str(HERE / "stamps.py")], input=lines, capture_output=True, text=True).stdout
    assert out.splitlines() == ["2026-11-24T16:38:51+0000 WARN", "2026-11-24T16:38:52+0000 INFO", "2026-11-24T16:38:53+0000 -"]


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
