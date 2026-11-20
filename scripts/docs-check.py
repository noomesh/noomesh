#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-only
# Copyright 2026 PersonifAI LLC

"""Documentation guardrails. Cheap greps, run in CI.

Checks:
  (a) every docs/**/*.md appears in docs/README.md exactly once
  (b) every relative link in docs/**/*.md, README.md, CONTRIBUTING.md and
      SECURITY.md resolves to an existing file (#anchors are ignored)
  (c) no docs/ file links to or cites internal/*.md (internal/ never
      ships — a public reader gets a dead link; write the OSS version into
      docs/ or drop the citation)
  (d) scripts/gen-cli-docs.py --check passes (generated CLI blocks are fresh)
      and scripts/gen-verify-rows.py --check (the verify-row registry matches
      the rows the CLI builds; docs/reference/verify-rows.md is fresh)
  (g) the agent-facing texts (AGENTS.md, prompts/*.md, the shipped core
      skills under prompts/skills/core/): every `noo …` they name resolves
      as in (f), and every `noo_*` tool they name is one the doors declare
      (gateway-rust/mcp-tools.json, mcp-tools-local.json, config/tools.json)
  (h) every page outside cli/ and reference/ has `## For people` then
      `## For agents`, except those still in SHAPE_PENDING (shrinks only)
  (f) every `noo …` invocation in a docs code block or backtick span
      resolves against the CLI registry (noo-cli/src/main.rs NATIVE):
      a group's subcommand must exist, a bare command may take any args,
      and a deliberately-retired verb may be named (see RETIRED)
  (e) docs/ contains none of the forbidden strings: `src/noo_mesh`,
      a `pai <command>` invocation, `fu[0-9]{2}`, `followup [0-9]`,
      `last_updated:` front-matter

Exit 1 on any failure except (c). Every finding prints file:line.
"""

from __future__ import annotations

import re
import subprocess
import sys
from collections import Counter
from pathlib import Path

def _repo_root() -> Path:
    """The tree the CALLER is standing in, not the one this file lives in.

    `Path(__file__).parent.parent` names the checkout the SCRIPT is in. Run
    from a worktree by a relative path — `../../scripts/docs-check.py` — that is the
    MAIN CLONE, so the script reads and writes the wrong tree while appearing
    to work. It bit on 2026-09-19: resolving a conflict in a worktree, a
    relative invocation regenerated the main clone's index instead, and the
    worktree's conflict sat unresolved while the command reported success.
    Harmless only because the output happened to be identical.

    Same reasoning and same fix as `scripts/cargo-docker.sh` (2026-08-13,
    where it produced a confident "0 tests matched" against unbuilt code):
    `git rev-parse` follows $PWD, so whichever copy is invoked, the tree you
    are STANDING IN is the one acted on.

    The toplevel is accepted only when it looks like THIS repo — otherwise a
    run from an unrelated checkout would silently act on that one. Outside
    any git tree, fall back to script-relative, which is correct for a
    tarball.
    """
    try:
        top = subprocess.run(
            ["git", "rev-parse", "--show-toplevel"],
            capture_output=True, text=True, check=True,
        ).stdout.strip()
    except (subprocess.CalledProcessError, FileNotFoundError, OSError):
        top = ""
    here = Path(__file__).resolve().parent.parent
    if top:
        cand = Path(top)
        if (cand / "scripts" / Path(__file__).name).is_file():
            return cand
    return here


REPO = _repo_root()
DOCS = REPO / "docs"
INDEX = DOCS / "README.md"
ROOT_MD = ["README.md", "CONTRIBUTING.md", "SECURITY.md", "AGENTS.md"]

LINK_RE = re.compile(r"\]\(([^)\s]+?)(?:#[^)\s]*)?\)")
CODE_FENCE_RE = re.compile(r"^(```|~~~)")

FORBIDDEN = [
    (re.compile(r"src/noo_mesh"), "src/noo_mesh (package is src/noomesh)"),
    (re.compile(r"`pai [a-z]"), "`pai <command>` (binary is noo)"),
    (re.compile(r"\bfu[0-9]{2}\b"), "fu<NN> followup reference"),
    (re.compile(r"\bfollowup [0-9]"), "followup <N> reference"),
    (re.compile(r"^last_updated:", re.M), "last_updated: front-matter"),
]


def rel(p: Path) -> str:
    return p.relative_to(REPO).as_posix()


def docs_md() -> list[Path]:
    return sorted(p for p in DOCS.rglob("*.md") if p.is_file())


def check_index(errors: list[str]) -> None:
    text = INDEX.read_text(encoding="utf-8")
    targets = Counter()
    for m in LINK_RE.finditer(text):
        t = m.group(1)
        if re.match(r"^[a-z]+:", t):
            continue
        targets[(DOCS / t).resolve()] += 1
    for p in docs_md():
        if p == INDEX:
            continue
        n = targets.get(p.resolve(), 0)
        if n == 0:
            errors.append(f"{rel(INDEX)}: {rel(p)} is not listed")
        elif n > 1:
            errors.append(f"{rel(INDEX)}: {rel(p)} is listed {n} times (want exactly once)")


def iter_links(path: Path):
    """(lineno, target) for every markdown link outside fenced code."""
    in_fence = False
    for i, line in enumerate(path.read_text(encoding="utf-8").splitlines(), 1):
        if CODE_FENCE_RE.match(line.strip()):
            in_fence = not in_fence
            continue
        if in_fence:
            continue
        for m in LINK_RE.finditer(line):
            yield i, m.group(1)


def check_links(errors: list[str], warnings: list[str]) -> None:
    files = docs_md() + [REPO / f for f in ROOT_MD if (REPO / f).exists()]
    for path in files:
        for lineno, target in iter_links(path):
            if re.match(r"^[a-zA-Z][a-zA-Z0-9+.-]*:", target) or target.startswith("#"):
                continue
            if target.startswith("<") or target.startswith("/"):
                continue
            dest = (path.parent / target).resolve()
            where = f"{rel(path)}:{lineno}"
            if not dest.exists():
                errors.append(f"{where}: broken link -> {target}")
                continue
            if path.is_relative_to(DOCS):
                try:
                    if dest.relative_to(REPO).as_posix().startswith("internal/"):
                        warnings.append(f"{where}: public doc links to internal/ -> {target}")
                except ValueError:
                    pass


INTERNAL_CITE_RE = re.compile(r"internal/[A-Za-z0-9_./-]+\.md")


def check_internal_citations(warnings: list[str]) -> None:
    """Backtick/plain citations of internal/*.md (not markdown links).

    Only paths that exist under the repo's internal/ count — the Go
    node-agent has its own `internal/` package tree, and those citations
    are fine.
    """
    for path in docs_md():
        for i, line in enumerate(path.read_text(encoding="utf-8").splitlines(), 1):
            for m in INTERNAL_CITE_RE.finditer(line):
                if "](" in line[: m.start()] and line[m.start() - 1 : m.start()] in ("(", "/"):
                    continue  # markdown link target — handled by check_links
                if (REPO / m.group(0)).exists():
                    warnings.append(f"{rel(path)}:{i}: public doc cites internal/ -> {m.group(0)}")


def check_generated(errors: list[str]) -> None:
    r = subprocess.run(
        [sys.executable, str(REPO / "scripts" / "gen-cli-docs.py"), "--check"],
        capture_output=True,
        text=True,
    )
    if r.returncode != 0:
        errors.append("scripts/gen-cli-docs.py --check failed:\n" + (r.stderr or r.stdout).rstrip())
    r = subprocess.run(
        [sys.executable, str(REPO / "scripts" / "gen-verify-rows.py"), "--check"],
        capture_output=True,
        text=True,
    )
    if r.returncode != 0:
        errors.append("scripts/gen-verify-rows.py --check failed:\n" + (r.stderr or r.stdout).rstrip())


def check_forbidden(errors: list[str]) -> None:
    for path in docs_md():
        for i, line in enumerate(path.read_text(encoding="utf-8").splitlines(), 1):
            for pat, label in FORBIDDEN:
                if pat.search(line):
                    errors.append(f"{rel(path)}:{i}: forbidden: {label}: {line.strip()[:100]}")


# Every `noo …` invocation printed in the docs must resolve to a real
# command. This is the counterpart of the generated tables: those cannot
# rot because CI diffs them, but the hand-written recipes around them can,
# and that drift is what the 2026-09 docs pass spent itself undoing
# (`noo mesh …` after the group was renamed to `stack`, `noo tui`, `noo
# test gen-stub`, six `cluster jobs …` verbs that had moved to `jobs`).
#
# Resolution is prefix-based: a command line is OK when its first word, or
# its first two words, name a registry entry — so `noo cluster status --json`
# and `noo stack start` both resolve while `noo stack strat` does not. Only
# fenced code blocks and inline `backtick` spans are scanned; running prose
# is not, because an English sentence containing "noo cluster provisioning
# takes…" is not a command and should not have to dodge a linter.
# `noo` must sit in COMMAND POSITION — start of the line/span (optionally
# behind a `$ ` prompt) or right after a shell operator. Without that,
# `pg_dump -U noo noomesh` reads as an invocation of `noo noomesh`.
CMD_IN_CODE = re.compile(
    r"(?:^\s*(?:\$\s+)?|[|;&(]\s*)noo ((?:[a-z][a-z0-9-]*)(?: [a-z][a-z0-9-]*)?)"
)
# Commands deliberately REMOVED from the registry that the docs may still
# name when explaining what became of them. "`noo cluster add-node` was
# removed" is the opposite of drift and must not fail this check. The
# accepted cost is that a stale INSTRUCTION using a retired verb also
# passes — add an entry only in the PR that deletes the command.
RETIRED = {
    ("cluster", "add-node"),  # deleted 2026-09-03, fu 83 item 2; drove the
                              # ansible tree removed in 3695e129
}

# Command groups an ADD-ON provides (PR #759: `noo <group> <verb>` is
# resolved from the add-on's cli-piece at run time, so these are NOT in
# NATIVE by design). Core cannot read the add-on's piece at lint time, so
# the verbs are listed here; the list is what the docs may name. Add a verb
# in the PR that adds it to the add-on's piece, and remove it with it.
ADDON_CLI = {
    "evolve": {
        "loop": {"status", "cycles", "detail", "run", "approve", "reject", "enable", "disable"},
        "ga": {"status", "pause", "resume", "rollback"},
    },
}
_ADDON_GROUPS = {g: verbs for groups in ADDON_CLI.values() for g, verbs in groups.items()}

# Words that follow `noo` in code without naming a command.
CMD_ALLOW = {
    "completions",  # `noo completions bash` — emitted by clap, not a registry row
    "upgraded",     # sample OUTPUT: upgrade.rs:282 prints "noo upgraded X → Y"
}


def _registry() -> tuple[set[str], set[str], set[tuple[str, str]]]:
    """(bare commands, group heads, two-word command names) from NATIVE.

    The registry splits cleanly: 9 bare commands (`chat`, `health`, …) that
    take free-form arguments, and 36 group heads whose second word must name
    a real subcommand. Checking only the head would accept `noo cluster
    stats` — and `noo cluster jobs`, which is exactly the drift this exists
    to catch (those six verbs moved to the `jobs` group).
    """
    sys.path.insert(0, str(REPO / "scripts"))
    import importlib.util

    spec = importlib.util.spec_from_file_location(
        "gen_cli_docs", REPO / "scripts" / "gen-cli-docs.py"
    )
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    src = (REPO / "noo-cli" / "src" / "main.rs").read_text(encoding="utf-8")
    entries = mod.parse_native(src)
    bare = {e[0] for e in entries if len(e) == 1}
    two = {(e[0], e[1]) for e in entries if len(e) > 1}
    return bare, {h for h, _ in two}, two


def _code_spans(text: str):
    """Yield (line_no, text) for fenced blocks and inline code spans only."""
    fenced = False
    for i, line in enumerate(text.splitlines(), 1):
        if line.lstrip().startswith("```"):
            fenced = not fenced
            continue
        if fenced:
            yield i, line
        else:
            for m in re.finditer(r"`([^`]+)`", line):
                yield i, m.group(1)


def agent_texts() -> list[Path]:
    """The texts an agent is handed: AGENTS.md, the coordinator prompts and
    the SHIPPED core skills (prompts/skills/evolved/ is written at runtime)."""
    out = [REPO / AGENTS_MD] if (REPO / AGENTS_MD).exists() else []
    out += sorted((REPO / "prompts").glob("*.md"))
    out += sorted((REPO / "prompts" / "skills" / "core").rglob("*.md"))
    return out


TOOL_DECLARATIONS = ("gateway-rust/mcp-tools.json", "gateway-rust/mcp-tools-local.json", "config/tools.json")
TOOL_NAME = re.compile(r"\bnoo_[a-z0-9_]+\b")


def _declared_tools() -> set[str]:
    import json

    names: set[str] = set()

    def walk(o):
        if isinstance(o, dict):
            n = o.get("name")
            if isinstance(n, str) and n.startswith("noo_"):
                names.add(n)
            for v in o.values():
                walk(v)
        elif isinstance(o, list):
            for v in o:
                walk(v)

    for rel_path in TOOL_DECLARATIONS:
        f = REPO / rel_path
        if f.exists():
            walk(json.loads(f.read_text(encoding="utf-8")))
    return names


def check_agent_tools(errors: list[str]) -> None:
    """(g) A tool an agent text names must be a tool the doors declare: a
    prompt that names a table, a retired tool or a guess sends an agent
    after something that is not there."""
    declared = _declared_tools()
    if not declared:
        errors.append("no tool declarations found (" + ", ".join(TOOL_DECLARATIONS) + ")")
        return
    for path in agent_texts():
        for i, line in enumerate(path.read_text(encoding="utf-8").splitlines(), 1):
            for m in TOOL_NAME.finditer(line):
                if m.group(0) not in declared:
                    errors.append(f"{rel(path)}:{i}: `{m.group(0)}` is not a tool the doors declare ({', '.join(TOOL_DECLARATIONS)})")


def check_commands(errors: list[str]) -> None:
    bare, groups, two = _registry()
    for path in docs_md() + agent_texts():
        for i, span in _code_spans(path.read_text(encoding="utf-8")):
            for m in CMD_IN_CODE.finditer(span):
                words = m.group(1).split()
                head = words[0]
                if head in CMD_ALLOW or head in bare:
                    continue  # bare command; its arguments are free-form
                if tuple(words[:2]) in RETIRED:
                    continue  # named while explaining its removal
                if head in groups and (len(words) == 1 or tuple(words[:2]) in two):
                    continue  # bare group prints usage; otherwise the verb resolved
                if head in _ADDON_GROUPS and (
                    len(words) == 1 or words[1] in _ADDON_GROUPS[head]
                ):
                    continue  # provided by an add-on's cli-piece (ADDON_CLI)
                errors.append(
                    f"{rel(path)}:{i}: `noo {m.group(1)}` is not in the CLI registry "
                    f"(noo-cli/src/main.rs NATIVE)"
                )


def check_proposal_numbers(errors: list[str]) -> None:
    """`internal/proposals/`: one number means one proposal, and the index
    lists every one of them.

    Followups got this guard when two files claimed 88. Proposals had neither
    a generated index nor a uniqueness check, and collided twice inside a
    week — 07, 20 and 37 are each used twice historically, and on 2026-09-05
    two different proposals were numbered 41 twelve minutes apart. A number
    that means two things breaks every citation of it, in both directions.

    The index is hand-written on purpose (a proposal's brief is a judgement,
    not a generated summary), so this checks completeness rather than
    regenerating it: add the row in the PR that adds the proposal.
    """
    # Three collisions predate this check. They are grandfathered by NUMBER
    # rather than waived wholesale, so a fourth still fails, and the list may
    # only shrink — a resolved pair left here is itself an error, which is
    # what stops it becoming a place to hide things.
    #
    # 07 and 20 sit in the stale group (`STALE?` in the index): renumbering a
    # proposal nobody will execute buys nothing. 37 is the one that matters —
    # `37-kiosk-gateway-mechanisms.md` has been waiting to move since it was
    # written, and its intended 39, then 40, then 41 were each taken while it
    # waited. It is NOT renumbered here on purpose: pai-mesh-ui cites
    # "an earlier change" about six times, and the two repositories merge into
    # `noomesh` shortly, at which point the file and its
    # citations move in one commit instead of two coordinated PRs.
    KNOWN_DUPLICATES = {"07", "20", "37"}

    root = REPO / "internal" / "proposals"
    if not root.is_dir():
        # an earlier change: the records are kept outside this repository now. Absent
        # is not failed, but it is said out loud, never a quiet pass.
        print(
            "docs-check: internal/proposals/ not present, SKIPPED "
            "(records are kept outside this repository)"
        )
        return
    index = root / "README.md"
    by_number: dict[str, list[str]] = {}
    for f in sorted(root.glob("*.md")):
        if f.name == "README.md":
            continue
        m = re.match(r"(\d+)-", f.name)
        if not m:
            errors.append(f"internal/proposals/{f.name} does not start with a number")
            continue
        by_number.setdefault(m.group(1), []).append(f.name)

    for number, names in sorted(by_number.items()):
        if len(names) > 1 and number not in KNOWN_DUPLICATES:
            errors.append(
                f"proposal number {number} is used by {len(names)} files: "
                f"{', '.join(names)} — renumber the newer one (git log "
                "--diff-filter=A says which) and fix any citation"
            )
    for number in sorted(KNOWN_DUPLICATES):
        if len(by_number.get(number, [])) <= 1:
            errors.append(
                f"proposal number {number} is no longer duplicated — drop it "
                "from KNOWN_DUPLICATES in scripts/docs-check.py, or the list "
                "stops meaning anything and the next collision hides in it"
            )

    if not index.exists():
        errors.append("internal/proposals/README.md is missing")
        return
    text = index.read_text(encoding="utf-8")
    linked = set(re.findall(r"\]\((\d[^)]+\.md)\)", text))
    for names in by_number.values():
        for name in names:
            if name not in linked:
                errors.append(
                    f"internal/proposals/{name} is not in the index — "
                    "add its row in the PR that adds the proposal"
                )
    for target in sorted(linked):
        if not (root / target).exists():
            errors.append(f"internal/proposals/README.md links {target}, which does not exist")


AGENTS_MD = "AGENTS.md"
TWO_PARTS = ("## For people", "## For agents")


def check_agents_pages(errors: list[str]) -> None:
    """A page AGENTS.md points agents at is written in the two-part shape:
    exactly one `## For people` and one `## For agents`, in that order, and
    no other H2 (operator, 2026-11-14: one page, a short part a person
    reads and an exact part an agent acts on, no fact in both)."""
    agents = REPO / AGENTS_MD
    if not agents.exists():
        return
    for lineno, target in iter_links(agents):
        if not target.startswith("docs/") or not target.endswith(".md"):
            continue
        page = REPO / target
        if not page.exists():
            continue  # check_links reports it
        h2 = [l.strip() for l in page.read_text(encoding="utf-8").splitlines() if l.startswith("## ")]
        if tuple(h2) != TWO_PARTS:
            errors.append(
                f"{AGENTS_MD}:{lineno}: {target} must have exactly the H2s "
                f"{' then '.join(TWO_PARTS)} (has {h2 or 'none'})"
            )


# Pages not yet in the two-part shape (proposal 62, step 4). It only
# shrinks: a page that gains both parts must leave this list, and no page
# is ever added (a new page is written in the shape).
SHAPE_PENDING = frozenset({
    "docs/channels/google-chat.md",
    "docs/channels/google-connections.md",
    "docs/channels/mcp-your-client.md",
    "docs/channels/telegram.md",
    "docs/development/addons.md",
    "docs/development/developer-guide.md",
    "docs/development/principles.md",
    "docs/getting-started/integrations.md",
    "docs/getting-started/kiosk.md",
    "docs/getting-started/supported-agent-harnesses.md",
    "docs/models/weight-cache.md",
    "docs/operating/monitoring.md",
    "docs/operating/operator-manual.md",
    "docs/operating/runbooks/at-rest-migrate.md",
    "docs/operating/runbooks/at-rest-recovery.md",
    "docs/operating/runbooks/backup-restore-secrets.md",
    "docs/operating/runbooks/data-root-recovery.md",
    "docs/operating/runbooks/host-updates.md",
    "docs/operating/runbooks/nats-isolation.md",
    "docs/operating/runbooks/security-release-upgrade.md",
    "docs/operating/token-budgets.md",
    "docs/security/model-context.md",
    "docs/security/networks-and-containers.md",
    "docs/security/node-agent.md",
    "docs/security/secrets.md",
    "docs/security/telemetry.md",
})


def check_page_shape(errors: list[str]) -> None:
    """(h) Every page outside cli/ and reference/ (and the index) has a
    `## For people` part, then a `## For agents` part (operator 2026-11-14)."""
    for path in docs_md():
        r = rel(path)
        if r.startswith(("docs/cli/", "docs/reference/")) or r == "docs/README.md":
            continue
        h2 = [l.strip() for l in path.read_text(encoding="utf-8").splitlines() if l.startswith("## ")]
        shaped = TWO_PARTS[0] in h2 and TWO_PARTS[1] in h2 and h2.index(TWO_PARTS[0]) < h2.index(TWO_PARTS[1])
        if r in SHAPE_PENDING:
            if shaped:
                errors.append(f"{r}: has both parts now; remove it from SHAPE_PENDING in scripts/docs-check.py")
        elif not shaped:
            errors.append(f"{r}: needs `{TWO_PARTS[0]}` then `{TWO_PARTS[1]}` (proposal 62; see docs/operating/disk-and-images.md)")
    for r in sorted(SHAPE_PENDING):
        if not (REPO / r).exists():
            errors.append(f"SHAPE_PENDING names {r}, which does not exist; remove it")


def main() -> int:
    errors: list[str] = []
    warnings: list[str] = []
    check_index(errors)
    check_links(errors, errors)
    check_internal_citations(errors)
    check_generated(errors)
    check_forbidden(errors)
    check_commands(errors)
    check_agent_tools(errors)
    check_proposal_numbers(errors)
    check_agents_pages(errors)
    check_page_shape(errors)
    for w in warnings:
        print(f"docs-check: WARNING {w}")
    for e in errors:
        print(f"docs-check: ERROR {e}")
    n = len(docs_md())
    if errors:
        print(f"docs-check: {len(errors)} error(s), {len(warnings)} warning(s) across {n} docs files")
        return 1
    print(f"docs-check: ok ({n} docs files, {len(warnings)} warning(s))")
    return 0


if __name__ == "__main__":
    sys.exit(main())
