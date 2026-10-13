#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-only
# Copyright 2026 PersonifAI LLC

"""Generate the CLI reference blocks in docs/cli/ from the noo-cli source tables.

This is the docs counterpart of `usage_table_matches_registry_exactly` in
noo-cli/src/main.rs: that test pins the per-command usage table (usage.rs) to
the dispatch registry (NATIVE) 1:1, so a native command cannot ship without an
argument syntax and a one-line description. This script extends the same
mechanism one hop — it parses those literal tables (no Rust toolchain needed)
and writes one reference block per CLI section into the six section pages
under docs/cli/, plus the section/tagline list into docs/cli/README.md.
A CI step (scripts/docs-check.py) re-runs it with --check and fails when a
page is stale, which is what keeps the docs from drifting away from the
binary.

Sources (all simple tuple tables, parsed with regexes):
  noo-cli/src/usage.rs  pub const USAGE: &[(&[&str], &str, &str)]
                        rows: (&["group", "sub"], "<syntax>", "description")
  noo-cli/src/main.rs   const GROUP_SECTIONS: &[(&str, &[&str])]  (ordered)
                        const GROUP_DESC: &[(&str, &str)]         (taglines)
                        const NATIVE: &[(&[&str], Handler)]       (cross-check)

Modes:
  (default)            write the blocks into the section pages and README
  --check              regenerate to a temp copy; exit 1 with a diff if stale
  --stdout <section>   print one section's block (title or page slug)

The generated block is idempotent: running twice yields no diff.
"""

from __future__ import annotations

import argparse
import difflib
import re
import sys
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
USAGE_RS = REPO / "noo-cli" / "src" / "usage.rs"
MAIN_RS = REPO / "noo-cli" / "src" / "main.rs"
CLI_DOCS = REPO / "docs" / "cli"

# Section title → page slug. Titles are the shipped GROUP_SECTIONS titles;
# the slug is the page name under docs/cli/.
SECTION_PAGES = {
    "Setup & host": "setup-and-host.md",
    "Fleet": "fleet.md",
    "Stack & data": "stack-and-data.md",
    "Memory & knowledge": "memory-and-knowledge.md",
    "Agents & channels": "agents-and-channels.md",
    "Security": "security.md",
}

REGEN_HINT = "do not edit; regenerate with scripts/gen-cli-docs.py"


def begin_marker(kind: str, **attrs: str) -> str:
    extra = "".join(f' {k}="{v}"' for k, v in attrs.items())
    return f"<!-- BEGIN GENERATED: {kind}{extra} — {REGEN_HINT} -->"


END_MARKER = "<!-- END GENERATED -->"


# ── Rust literal parsing ─────────────────────────────────────────────────

_RUST_STR = r'"((?:[^"\\]|\\.)*)"'


def _unescape(s: str) -> str:
    return s.replace('\\"', '"').replace("\\\\", "\\")


def _const_block(src: str, name: str) -> str:
    """The text between `const NAME ... = &[` and the closing `];`."""
    m = re.search(rf"^(?:pub )?const {name}\b[^\n]*=\s*&\[\n(.*?)^\];", src, re.S | re.M)
    if not m:
        sys.exit(f"gen-cli-docs: could not find `const {name}` in the source")
    return m.group(1)


def _str_list(inner: str) -> list[str]:
    return [_unescape(s) for s in re.findall(_RUST_STR, inner)]


def parse_usage(src: str) -> list[tuple[tuple[str, ...], str, str]]:
    rows = []
    row_re = re.compile(rf"^\s*\(&\[(.*?)\],\s*{_RUST_STR},\s*{_RUST_STR}\),\s*(?://.*)?$", re.M)
    for m in row_re.finditer(_const_block(src, "USAGE")):
        words = tuple(_str_list(m.group(1)))
        rows.append((words, _unescape(m.group(2)), _unescape(m.group(3))))
    return rows


def parse_native(src: str) -> list[tuple[str, ...]]:
    # Rows may carry a trailing `// alias …` comment.
    row_re = re.compile(r"^\s*\(&\[(.*?)\],\s*[\w:]+\),\s*(?://.*)?$", re.M)
    return [tuple(_str_list(m.group(1))) for m in row_re.finditer(_const_block(src, "NATIVE"))]


def parse_hidden_no_usage(src: str) -> set[tuple[str, ...]]:
    """Commands that dispatch but are deliberately absent from USAGE/help."""
    row_re = re.compile(r"^\s*&\[(.*?)\],\s*$", re.M)
    return {tuple(_str_list(m.group(1))) for m in row_re.finditer(_const_block(src, "HIDDEN_NO_USAGE"))}


def parse_group_sections(src: str) -> list[tuple[str, list[str]]]:
    row_re = re.compile(rf"^\s*\({_RUST_STR},\s*&\[(.*?)\]\),\s*$", re.M)
    return [
        (_unescape(m.group(1)), _str_list(m.group(2)))
        for m in row_re.finditer(_const_block(src, "GROUP_SECTIONS"))
    ]


def parse_group_desc(src: str) -> dict[str, str]:
    row_re = re.compile(rf"^\s*\({_RUST_STR},\s*{_RUST_STR}\),\s*$", re.M)
    return {
        _unescape(m.group(1)): _unescape(m.group(2))
        for m in row_re.finditer(_const_block(src, "GROUP_DESC"))
    }


# ── Model ────────────────────────────────────────────────────────────────


class Cli:
    def __init__(self) -> None:
        usage_src = USAGE_RS.read_text(encoding="utf-8")
        main_src = MAIN_RS.read_text(encoding="utf-8")
        self.usage = parse_usage(usage_src)
        self.native = parse_native(main_src)
        self.hidden = parse_hidden_no_usage(main_src)
        self.sections = parse_group_sections(main_src)
        self.desc = parse_group_desc(main_src)
        self._validate()

    def _validate(self) -> None:
        errors: list[str] = []
        usage_words = [w for w, _, _ in self.usage]
        usage_set = set(usage_words)
        native_set = set(self.native)
        if len(usage_words) != len(usage_set):
            errors.append("duplicate rows in USAGE")
        for w in sorted(usage_set - native_set):
            errors.append(f"USAGE row {list(w)} has no NATIVE registry entry")
        for w in sorted(native_set - usage_set - self.hidden):
            errors.append(f"NATIVE entry {list(w)} has no USAGE row")
        groups = self.groups()
        placed: dict[str, str] = {}
        for title, members in self.sections:
            for g in members:
                if g in placed:
                    errors.append(f"group `{g}` appears in two sections ({placed[g]}, {title})")
                placed[g] = title
                if g not in groups:
                    errors.append(f"GROUP_SECTIONS names `{g}`, which is not a registry group")
        for g in groups:
            if g not in placed:
                errors.append(f"group `{g}` is in no GROUP_SECTIONS entry")
            if not self.desc.get(g):
                errors.append(f"group `{g}` has no GROUP_DESC tagline")
        for title in self.section_titles():
            if title not in SECTION_PAGES:
                errors.append(f"section `{title}` has no page slug in SECTION_PAGES")
        if errors:
            sys.exit("gen-cli-docs: source tables are inconsistent:\n  " + "\n  ".join(errors))

    def groups(self) -> list[str]:
        out: list[str] = []
        for w, _, _ in self.usage:
            if w and w[0] not in out:
                out.append(w[0])
        return out

    def section_titles(self) -> list[str]:
        return [t for t, _ in self.sections]

    def rows_for_group(self, group: str) -> list[tuple[tuple[str, ...], str, str]]:
        return [r for r in self.usage if r[0] and r[0][0] == group]


# ── Rendering ────────────────────────────────────────────────────────────


def md_cell(s: str) -> str:
    return s.replace("|", "\\|")


def render_section_block(cli: Cli, title: str) -> str:
    members = dict(cli.sections)[title]
    lines = [begin_marker("cli-reference", section=title)]
    for g in members:
        lines.append(f"### `noo {g}` — {md_cell(cli.desc[g])}")
        lines.append("| Command | Arguments | What it does |")
        lines.append("|---|---|---|")
        for words, syntax, about in cli.rows_for_group(g):
            cmd = "`noo " + " ".join(words) + "`"
            args = f"`{md_cell(syntax)}`" if syntax else "—"
            lines.append(f"| {cmd} | {args} | {md_cell(about)} |")
        lines.append("")
    if lines[-1] == "":
        lines.pop()
    lines.append(END_MARKER)
    return "\n".join(lines) + "\n"


def render_sections_block(cli: Cli) -> str:
    """The section/tagline list for docs/cli/README.md."""
    lines = [begin_marker("cli-sections")]
    lines.append("| Section | Groups |")
    lines.append("|---|---|")
    for title, members in cli.sections:
        page = SECTION_PAGES[title]
        groups = ", ".join(f"`{g}`" for g in members)
        lines.append(f"| [{title}]({page}) | {groups} |")
    lines.append("")
    for title, members in cli.sections:
        lines.append(f"**{title}** — [{SECTION_PAGES[title]}]({SECTION_PAGES[title]})")
        lines.append("")
        for g in members:
            lines.append(f"- `noo {g}` — {cli.desc[g]}")
        lines.append("")
    lines.pop()
    lines.append(END_MARKER)
    return "\n".join(lines) + "\n"


def splice(page_text: str, kind: str, block: str) -> str:
    """Replace the marked block of `kind` in the page, or append it."""
    begin_re = re.compile(rf"^<!-- BEGIN GENERATED: {re.escape(kind)}\b[^\n]*-->\n", re.M)
    m = begin_re.search(page_text)
    if m:
        end = page_text.find(END_MARKER + "\n", m.end())
        if end < 0:
            end = page_text.find(END_MARKER, m.end())
            if end < 0:
                sys.exit(f"gen-cli-docs: BEGIN marker without END marker for {kind}")
            return page_text[: m.start()] + block + page_text[end + len(END_MARKER):]
        return page_text[: m.start()] + block + page_text[end + len(END_MARKER) + 1 :]
    if page_text and not page_text.endswith("\n"):
        page_text += "\n"
    if page_text and not page_text.endswith("\n\n"):
        page_text += "\n"
    return page_text + block


def targets(cli: Cli) -> list[tuple[Path, str, str]]:
    """(page, kind, block) for every generated block."""
    out = [(CLI_DOCS / "README.md", "cli-sections", render_sections_block(cli))]
    for title in cli.section_titles():
        out.append((CLI_DOCS / SECTION_PAGES[title], "cli-reference", render_section_block(cli, title)))
    return out


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--check", action="store_true", help="exit 1 with a diff if any page is stale")
    ap.add_argument("--stdout", metavar="SECTION", help="print one section's block (title or page slug)")
    args = ap.parse_args()

    cli = Cli()

    if args.stdout:
        want = args.stdout
        for title, page in SECTION_PAGES.items():
            if want in (title, page, page.removesuffix(".md")):
                sys.stdout.write(render_section_block(cli, title))
                return 0
        if want in ("README", "README.md", "sections"):
            sys.stdout.write(render_sections_block(cli))
            return 0
        sys.exit(f"gen-cli-docs: unknown section {want!r}; want one of {list(SECTION_PAGES)}")

    stale = 0
    for page, kind, block in targets(cli):
        current = page.read_text(encoding="utf-8") if page.exists() else ""
        updated = splice(current, kind, block)
        if updated == current:
            continue
        if args.check:
            stale += 1
            rel = page.relative_to(REPO)
            print(f"gen-cli-docs: {rel} is stale", file=sys.stderr)
            sys.stderr.writelines(
                difflib.unified_diff(
                    current.splitlines(keepends=True),
                    updated.splitlines(keepends=True),
                    fromfile=f"a/{rel}",
                    tofile=f"b/{rel}",
                )
            )
        else:
            page.parent.mkdir(parents=True, exist_ok=True)
            page.write_text(updated, encoding="utf-8")
            print(f"gen-cli-docs: wrote {page.relative_to(REPO)}")

    n_cmd = len(cli.usage)
    n_grp = len(cli.groups())
    n_sec = len(cli.sections)
    if args.check:
        if stale:
            print(f"gen-cli-docs: {stale} page(s) stale — run scripts/gen-cli-docs.py", file=sys.stderr)
            return 1
        print(f"gen-cli-docs: up to date ({n_cmd} commands, {n_grp} groups, {n_sec} sections)")
    else:
        print(f"gen-cli-docs: {n_cmd} commands, {n_grp} groups, {n_sec} sections")
    return 0


if __name__ == "__main__":
    sys.exit(main())
