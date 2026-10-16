# SPDX-License-Identifier: AGPL-3.0-only
# Copyright 2026 PersonifAI LLC

"""`noo_rag_ingest` cannot read arbitrary files out of the service container.

Drives the real `_rag_ingest` with a trellion double that records what it
was handed, so the assertions are about what reached the storage boundary:
a refused source must produce a ValueError AND zero calls into trellion.
"""
from __future__ import annotations

from pathlib import Path

import pytest

from noomesh.workers import ingest_confine as ic
from noomesh.workers import rag as rag_worker
from noomesh.gateway import kb_roles


class _Ingestor:
    def __init__(self):
        self.files: list = []
        self.texts: list = []

    async def ingest_file(self, path, title=None, source_uri=None, metadata=None):
        self.files.append(Path(path))
        return "doc-file"

    async def ingest_text(self, text, title, source_uri="", metadata=None):
        self.texts.append(text)
        return "doc-text"


class _Rag:
    """Like PageIndexRAG: `ingest` would open any existing path (never used)."""

    def __init__(self):
        self.ingestor = _Ingestor()
        self.ingest_calls = 0

    async def ingest(self, *a, **k):  # pragma: no cover - must not be reached
        self.ingest_calls += 1
        raise AssertionError("the worker must use the explicit entry points")


@pytest.fixture
def env(monkeypatch, tmp_path):
    rag = _Rag()
    root = tmp_path / "user-dirs"
    root.mkdir()
    monkeypatch.setattr(rag_worker, "_get_rag", lambda: rag)

    async def _empty():
        return []

    async def _grants():
        return {}

    monkeypatch.setattr(rag_worker, "_kb_source_rules", _empty)
    monkeypatch.setattr(rag_worker, "_kb_grants_map", _grants)
    monkeypatch.setattr(kb_roles, "_load_kb_config", lambda: None)
    monkeypatch.setitem(kb_roles._cache, "rules", [])
    monkeypatch.setitem(kb_roles._cache, "default_roles", [])
    monkeypatch.setattr(ic, "declared_roots", lambda: [root.resolve()])
    # The worker's roots come from classify() -> declared_roots().
    return rag, root


async def _ingest(**params):
    return await rag_worker._rag_ingest({"title": "t", **params})


# ── allowed ────────────────────────────────────────────────────────────

async def test_file_under_a_declared_root_is_ingested(env):
    rag, root = env
    f = root / "a.md"
    f.write_text("hello")
    out = await _ingest(source=str(f))
    assert out["doc_id"] == "doc-file"
    assert rag.ingestor.files == [f.resolve()]


async def test_staged_file_under_the_staging_dir_is_ingested(env, tmp_path, monkeypatch):
    """Watched-folder and Drive ingests pass the staged copy as `source`."""
    rag, _ = env
    staging = tmp_path / "working"
    staging.mkdir()
    monkeypatch.setattr(ic, "declared_roots", lambda: [staging.resolve()])
    f = staging / "folder_ab12cd34_report.md"
    f.write_text("x")
    await _ingest(source=str(f), source_uri="/mnt/nas/report.md")
    assert rag.ingestor.files == [f.resolve()]


def test_staging_dir_is_always_a_root():
    assert Path(ic.STAGING_DIR).resolve() in ic.declared_roots()


async def test_upload_text_with_a_source_label_stores_the_text(env):
    """The dashboard upload sends text + source="upload"; the label is not the content."""
    rag, _ = env
    await _ingest(text="body of the upload", source="upload", source_uri="upload://a.md")
    assert rag.ingestor.texts == ["body of the upload"]
    assert rag.ingestor.files == []


async def test_plain_text_in_source_is_stored_as_text(env):
    rag, _ = env
    await _ingest(source="remember that the deploy window is Tuesday")
    assert rag.ingestor.texts == ["remember that the deploy window is Tuesday"]


# ── denied ─────────────────────────────────────────────────────────────

def _no_side_effect(rag):
    assert rag.ingestor.files == [] and rag.ingestor.texts == [] and rag.ingest_calls == 0


@pytest.mark.parametrize(
    "secret",
    [
        "/run/secrets/db-password",
        "/app/pki/leaf/service.key",
        "/app/noomesh.yaml",
        "/proc/self/environ",
        "/etc/passwd",
        "/tls/ca.crt",
    ],
)
async def test_paths_outside_the_roots_are_refused(env, secret):
    rag, _ = env
    with pytest.raises(ValueError) as e:
        await _ingest(source=secret)
    assert "allowed roots" in str(e.value) and "tools.allowed_paths" in str(e.value)
    _no_side_effect(rag)


@pytest.mark.parametrize(
    "secret",
    ["/run/secrets/db-password", "/app/pki/leaf/service.key", "/proc/self/environ", "/etc/passwd"],
)
async def test_denylist_holds_even_if_a_root_is_misdeclared(env, monkeypatch, secret):
    rag, _ = env
    monkeypatch.setattr(ic, "declared_roots", lambda: [Path("/")])
    with pytest.raises(ValueError):
        await _ingest(source=secret)
    _no_side_effect(rag)


async def test_symlink_from_a_root_to_a_secret_is_refused(env, tmp_path):
    rag, root = env
    target = tmp_path / "fake-run" / "secrets"
    target.mkdir(parents=True)
    (target / "db").write_text("hunter2")
    link = root / "innocent.md"
    link.symlink_to("/proc/self/environ")
    with pytest.raises(ValueError):
        await _ingest(source=str(link))
    outside = tmp_path / "outside.md"
    outside.write_text("private")
    link2 = root / "link2.md"
    link2.symlink_to(outside)
    with pytest.raises(ValueError):
        await _ingest(source=str(link2))
    _no_side_effect(rag)


async def test_dotdot_out_of_the_root_is_refused(env, tmp_path):
    rag, root = env
    (tmp_path / "elsewhere.md").write_text("x")
    with pytest.raises(ValueError):
        await _ingest(source=str(root / ".." / "elsewhere.md"))
    _no_side_effect(rag)


async def test_glob_escaping_the_root_is_refused(env):
    rag, root = env
    for pattern in (str(root / ".." / "*"), "/run/secrets/*", "/app/*.yaml"):
        with pytest.raises(ValueError) as e:
            await _ingest(source=pattern)
        assert "allowed roots" in str(e.value), pattern
    _no_side_effect(rag)


async def test_glob_and_directory_inside_the_root_are_refused_with_the_reason(env):
    rag, root = env
    (root / "a.md").write_text("x")
    for src, word in ((str(root / "*.md"), "glob"), (str(root), "directory")):
        with pytest.raises(ValueError) as e:
            await _ingest(source=src)
        assert word in str(e.value) and "one file" in str(e.value)
    _no_side_effect(rag)


async def test_urls_are_refused_not_stored_as_text(env):
    rag, _ = env
    for url in ("https://example.com/x", "http://169.254.169.254/latest/meta-data/", "file:///etc/passwd"):
        with pytest.raises(ValueError) as e:
            await _ingest(source=url)
        assert "does not fetch URLs" in str(e.value)
    _no_side_effect(rag)


async def test_text_that_spells_a_secret_path_is_stored_not_read(env, tmp_path):
    """`text="/some/existing/file"` must not be reinterpreted as a path."""
    rag, _ = env
    secret = tmp_path / "secret.key"
    secret.write_text("PRIVATE KEY BYTES")
    await _ingest(text=str(secret))
    assert rag.ingestor.texts == [str(secret)]
    assert rag.ingestor.files == []


async def test_backend_without_explicit_entry_points_never_opens_text_as_path(monkeypatch, tmp_path):
    """A rag object that only has `ingest` (a double) is not handed a path-shaped text."""
    secret = tmp_path / "s.key"
    secret.write_text("k")

    class _OnlyIngest:
        calls = []

        async def ingest(self, content, **kw):
            self.calls.append(content)
            return "d"

    rag = _OnlyIngest()
    monkeypatch.setattr(rag_worker, "_get_rag", lambda: rag)

    async def _rules():
        return []

    async def _grants():
        return {}

    monkeypatch.setattr(rag_worker, "_kb_source_rules", _rules)
    monkeypatch.setattr(rag_worker, "_kb_grants_map", _grants)
    with pytest.raises(ValueError):
        await rag_worker._rag_ingest({"text": str(secret), "title": "t"})
    assert rag.calls == []
