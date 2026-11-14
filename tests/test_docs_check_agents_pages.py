"""scripts/docs-check.py `check_agents_pages`: a page AGENTS.md points agents
at has exactly the two H2s `## For people` then `## For agents`."""

from __future__ import annotations

import importlib.util
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def _load():
    spec = importlib.util.spec_from_file_location("docs_check", ROOT / "scripts/docs-check.py")
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def _run(tmp_path: Path, page: str) -> list[str]:
    dc = _load()
    (tmp_path / "docs").mkdir()
    (tmp_path / "docs/p.md").write_text(page, encoding="utf-8")
    (tmp_path / "AGENTS.md").write_text("| t | [docs/p.md](docs/p.md#for-agents) |\n", encoding="utf-8")
    dc.REPO = tmp_path
    errors: list[str] = []
    dc.check_agents_pages(errors)
    return errors


def test_a_two_part_page_passes(tmp_path):
    assert _run(tmp_path, "# P\n\nintro\n\n## For people\n\na\n\n## For agents\n\nb\n") == []


def test_a_missing_part_an_extra_h2_or_the_wrong_order_fails(tmp_path):
    for page in [
        "# P\n\n## For people\n\na\n",
        "# P\n\n## For people\n\n## For agents\n\n## More\n",
        "# P\n\n## For agents\n\n## For people\n",
        "# P\n\nno parts at all\n",
    ]:
        sub = tmp_path / str(abs(hash(page)))
        sub.mkdir()
        assert _run(sub, page), f"believed: {page!r}"


def test_the_repo_agents_md_lists_the_disk_page_first_and_it_passes():
    text = (ROOT / "AGENTS.md").read_text(encoding="utf-8")
    rows = [line for line in text.splitlines() if line.startswith("| ") and "docs/" in line]
    assert rows and "docs/operating/disk-and-images.md#for-agents" in rows[0]
    dc = _load()
    errors: list[str] = []
    dc.check_agents_pages(errors)
    assert errors == []
