# SPDX-License-Identifier: AGPL-3.0-only
# Copyright 2026 PersonifAI LLC

"""SPDX headers: the tool must not break a file, and the tree must carry them.

`internal/noomesh/licensing/spdx.py` stamps every source file with a licence
header. A header is a comment, but "just a comment" is exactly where it goes
wrong: above a shebang the script stops executing, above a PEP 263 cookie the
file stops decoding, fused to a Go package line it becomes the package doc,
above a CSS `@charset` it silently disables the charset.

So the tool's placement rules are pinned here, and the last test runs the
tool's own `--check` over this repository so a new file without a header
fails the suite as well as the CI preflight step.
"""

import importlib.util
import pathlib
import subprocess
import sys

import pytest

ROOT = pathlib.Path(__file__).resolve().parents[1]
TOOL = ROOT / "internal" / "noomesh" / "licensing" / "spdx.py"
ID = "AGPL-3.0-only"

if not TOOL.is_file():
    # The checker lives under internal/, which the public sync excludes.
    pytest.skip(f"SPDX checker not in this tree ({TOOL.relative_to(ROOT)})", allow_module_level=True)

_spec = importlib.util.spec_from_file_location("spdx_tool", TOOL)
spdx = importlib.util.module_from_spec(_spec)
sys.modules["spdx_tool"] = spdx
_spec.loader.exec_module(spdx)

H_HASH = f"# SPDX-License-Identifier: {ID}\n# Copyright 2026 PersonifAI LLC\n\n"
H_SLASH = f"// SPDX-License-Identifier: {ID}\n// Copyright 2026 PersonifAI LLC\n\n"


def _write(root, rel, content, mode="w"):
    p = root / rel
    p.parent.mkdir(parents=True, exist_ok=True)
    if isinstance(content, bytes):
        p.write_bytes(content)
    else:
        p.write_bytes(content.encode("utf-8"))
    return p


def _run(root, *extra):
    return spdx.main([str(root), ID, *extra])


def test_shebang_stays_first_and_script_still_runs(tmp_path):
    p = _write(tmp_path, "run.sh", "#!/bin/sh\necho hi\n")
    assert _run(tmp_path) == 0
    text = p.read_text()
    assert text == "#!/bin/sh\n" + H_HASH + "echo hi\n"


def test_rust_inner_attribute_is_not_a_shebang(tmp_path):
    p = _write(tmp_path, "lib.rs", "#![deny(warnings)]\n//! crate docs\nfn main() {}\n")
    _run(tmp_path)
    # The header goes ABOVE `#![...]`: it is an attribute, not a shebang.
    assert p.read_text() == H_SLASH + "#![deny(warnings)]\n//! crate docs\nfn main() {}\n"


def test_python_encoding_cookie_stays_in_first_two_lines(tmp_path):
    a = _write(tmp_path, "a.py", "# -*- coding: latin-1 -*-\nx = 1\n")
    b = _write(tmp_path, "b.py", "#!/usr/bin/env python3\n# vim: set fileencoding=utf-8 :\nx = 1\n")
    c = _write(tmp_path, "c.py", "# one\n# coding: utf-8\nx = 1\n")
    _run(tmp_path)
    for p in (a, b, c):
        lines = p.read_text().splitlines()
        assert any("coding" in ln for ln in lines[:2]), p.name
        assert "SPDX-License-Identifier" in p.read_text()
        compile(p.read_text(), p.name, "exec")
    assert b.read_text().startswith("#!/usr/bin/env python3\n")


def test_python_future_import_and_docstring_still_valid(tmp_path):
    p = _write(tmp_path, "m.py", '"""Doc."""\nfrom __future__ import annotations\nx = 1\n')
    _run(tmp_path)
    ns = {}
    exec(compile(p.read_text(), "m.py", "exec"), ns)
    assert ns["__doc__"] == "Doc."


def test_go_build_constraint_still_valid_and_not_fused_to_package_doc(tmp_path):
    p = _write(tmp_path, "x.go", "//go:build linux\n\npackage x\n")
    q = _write(tmp_path, "y.go", "// Package y does y.\npackage y\n")
    _run(tmp_path)
    t = p.read_text()
    # Constraint may be preceded only by blank lines and // comments, and the
    # header must be followed by a blank line (so it is not a doc comment).
    assert t == H_SLASH + "//go:build linux\n\npackage x\n"
    assert q.read_text() == H_SLASH + "// Package y does y.\npackage y\n"


def test_css_charset_and_html_doctype_stay_first(tmp_path):
    c = _write(tmp_path, "a.css", '@charset "utf-8";\nbody{}\n')
    h = _write(tmp_path, "a.html", "<!DOCTYPE html>\n<html></html>\n")
    _run(tmp_path)
    assert c.read_text().startswith('@charset "utf-8";\n/* SPDX-License-Identifier')
    assert h.read_text().startswith("<!DOCTYPE html>\n<!-- SPDX-License-Identifier")


def test_bom_and_crlf_are_preserved(tmp_path):
    b = _write(tmp_path, "b.ts", b"\xef\xbb\xbfconst a = 1;\n")
    r = _write(tmp_path, "r.py", b"x = 1\r\ny = 2\r\n")
    _run(tmp_path)
    assert b.read_bytes().startswith(b"\xef\xbb\xbf// SPDX-License-Identifier")
    assert _run(tmp_path, "--check") == 0  # a BOM does not hide the header
    data = r.read_bytes()
    assert b"\r\n" in data and b"\n" not in data.replace(b"\r\n", b"")


def test_idempotent_and_check_mode(tmp_path):
    p = _write(tmp_path, "a.py", "x = 1\n")
    assert _run(tmp_path, "--check") == 1
    assert p.read_text() == "x = 1\n"  # --check never writes
    assert _run(tmp_path) == 0
    once = p.read_bytes()
    assert _run(tmp_path) == 0 and p.read_bytes() == once
    assert _run(tmp_path, "--check") == 0


def test_no_comment_formats_data_and_empty_files_are_untouched(tmp_path):
    files = {
        "a.json": '{"a": 1}\n',
        "README.md": "# hi\n",
        "q.sql": "select 1;\n",
        "Dockerfile": "FROM scratch\n",
        "Cargo.lock": "# lock\n",
        "__init__.py": "",
        "blank.py": "\n\n",
    }
    for rel, content in files.items():
        _write(tmp_path, rel, content)
    assert _run(tmp_path, "--check") == 0
    _run(tmp_path)
    for rel, content in files.items():
        assert (tmp_path / rel).read_text() == content


def test_generated_vendored_and_fixture_files_are_skipped(tmp_path):
    keep = {
        "gen.ts": "// @generated by tool\nexport {}\n",
        "api.d.ts": "export {}\n",
        "pb.go": "// Code generated by protoc. DO NOT EDIT.\npackage x\n",
        "node_modules/x/i.js": "1\n",
        "vendor/v.go": "package v\n",
        "tests/fixtures/f.py": "x = 1\n",
        "testdata/t.go": "package t\n",
        "db/migrations/001.sql": "select 1;\n",
        "web/routeTree.gen.ts": "export {}\n",
    }
    for rel, content in keep.items():
        _write(tmp_path, rel, content)
    assert _run(tmp_path, "--check") == 0
    _run(tmp_path)
    for rel, content in keep.items():
        assert (tmp_path / rel).read_text() == content, rel


def test_mirrored_addon_overlays_are_never_stamped(tmp_path):
    names = ("docker-compose.trellion-intel.yml", "docker-compose.evolve.yml")
    for n in names:
        _write(tmp_path, n, "services: {}\n")
    assert _run(tmp_path, "--check") == 0
    _run(tmp_path)
    for n in names:
        assert (tmp_path / n).read_text() == "services: {}\n"
    # ...the real ones carry a header that is maintained by hand, in step with
    # the add-on repos' copies (the tool never writes it).


def test_subtree_with_its_own_licence_is_not_stamped(tmp_path):
    sdk = _write(tmp_path, "packages/sdk/src/pkg/a.py", "x = 1\n")
    deep = _write(tmp_path, "packages/sdk/tests/t.py", "y = 1\n")
    _write(tmp_path, "packages/sdk/LICENSE", "Apache-2.0 text\n")
    mine = _write(tmp_path, "src/m.py", "z = 1\n")
    _write(tmp_path, "LICENSE", "AGPL text\n")  # the root licence does not exempt the root
    _run(tmp_path)
    assert sdk.read_text() == "x = 1\n" and deep.read_text() == "y = 1\n"
    assert "SPDX" in mine.read_text()


def test_apache_subtree_is_stamped_and_checked_as_apache(tmp_path, capsys):
    apache = (tmp_path / "packages/sdk")
    _write(tmp_path, "packages/sdk/LICENSE", "                                 Apache License\n                           Version 2.0, January 2004\n")
    a = _write(tmp_path, "packages/sdk/src/a.py", "x = 1\n")
    _write(tmp_path, "LICENSE", "AGPL text\n")
    assert _run(tmp_path, "--check") == 1
    _run(tmp_path)
    assert a.read_text().startswith("# SPDX-License-Identifier: Apache-2.0\n# Copyright 2026 PersonifAI LLC\n\n")
    assert _run(tmp_path, "--check") == 0
    # An AGPL header inside the Apache subtree is a wrong id, not a pass.
    a.write_text(H_HASH + "x = 1\n")
    assert _run(tmp_path, "--check") == 1
    assert "expected Apache-2.0" in capsys.readouterr().out


def test_a_different_existing_id_is_reported_never_rewritten(tmp_path, capsys):
    other = "# SPDX-License-Identifier: MIT\nx = 1\n"
    p = _write(tmp_path, "a.py", other)
    assert _run(tmp_path, "--check") == 1
    assert "wrong SPDX id" in capsys.readouterr().out
    _run(tmp_path)
    assert p.read_text() == other


def test_a_tracked_build_dir_is_source_in_git_but_output_outside_it(tmp_path):
    """trellion keeps real code in src/trellion/build/; a bare tree cannot tell."""
    plain = tmp_path / "plain"
    _write(plain, "src/build/x.py", "x = 1\n")
    _run(plain)
    assert (plain / "src/build/x.py").read_text() == "x = 1\n"
    repo = tmp_path / "repo"
    subprocess.run(["git", "init", "-q", str(repo)], check=True)
    _write(repo, "src/build/x.py", "x = 1\n")
    _write(repo, "snapshots/s.py", "y = 1\n")
    _run(repo)
    assert "SPDX" in (repo / "src/build/x.py").read_text()
    assert "SPDX" in (repo / "snapshots/s.py").read_text()


def test_git_checkout_only_stamps_files_git_knows(tmp_path):
    subprocess.run(["git", "init", "-q", str(tmp_path)], check=True)
    (tmp_path / ".gitignore").write_text("out/\n")
    _write(tmp_path, "out/built.py", "x = 1\n")
    _write(tmp_path, "src.py", "x = 1\n")
    _run(tmp_path)
    assert (tmp_path / "out/built.py").read_text() == "x = 1\n"
    assert "SPDX" in (tmp_path / "src.py").read_text()


def test_this_repository_carries_its_headers():
    """The tool's own --check over the real tree (CI preflight runs the same)."""
    r = subprocess.run([sys.executable, str(TOOL), str(ROOT), ID, "--check"],
                       capture_output=True, text=True)
    assert r.returncode == 0, r.stdout[-2000:]
