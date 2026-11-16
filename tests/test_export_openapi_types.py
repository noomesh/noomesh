"""scripts/export-openapi.py `_types`: the console's schema.d.ts is the fourth
artifact behind a route change. Without npm or the console's dependencies it
names the exact command and passes (the Python-only drift job stays green);
with them, a failing `npm run` fails the run."""

from __future__ import annotations

import importlib.util
import subprocess
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def _load():
    spec = importlib.util.spec_from_file_location("export_openapi", ROOT / "scripts/export-openapi.py")
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def test_without_npm_it_names_the_command_and_passes(tmp_path, monkeypatch, capsys):
    mod = _load()
    import shutil
    monkeypatch.setattr(shutil, "which", lambda _: None)
    assert mod._types(tmp_path, check=True) == 0
    assert "npm ci && npm run check:api" in capsys.readouterr().out
    assert mod._types(tmp_path, check=False) == 0
    assert "npm ci && npm run gen:api" in capsys.readouterr().out


def test_a_failing_npm_run_fails_and_says_the_fix(tmp_path, monkeypatch, capsys):
    mod = _load()
    import shutil
    (tmp_path / "node_modules").mkdir()
    monkeypatch.setattr(shutil, "which", lambda _: "/usr/bin/npm")
    seen = []

    def fake_run(argv, **kw):
        seen.append(argv)
        return subprocess.CompletedProcess(argv, 1, stdout="", stderr="schema.d.ts is stale")

    monkeypatch.setattr(subprocess, "run", fake_run)
    assert mod._types(tmp_path, check=True) == 1
    assert seen == [["npm", "run", "--silent", "check:api"]]
    assert "npm run gen:api" in capsys.readouterr().err
    monkeypatch.setattr(subprocess, "run", lambda argv, **kw: subprocess.CompletedProcess(argv, 0, "", ""))
    assert mod._types(tmp_path, check=False) == 0
