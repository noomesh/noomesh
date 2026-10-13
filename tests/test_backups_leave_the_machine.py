# SPDX-License-Identifier: AGPL-3.0-only
# Copyright 2026 PersonifAI LLC

"""A backup on the machine it protects survives nothing.

The controller held 35 dumps, the Postgres volume and the encrypted copy of
the age key on one disk, with nothing copying any of it anywhere else. One
disk loss took the data and the means to read it back, together.

`NOO_BACKUP_OFFSITE` is the destination. These pin the two halves that are
easy to get wrong: the set of destination forms the writer and the reader
agree on, and the rule that a failed copy is loud rather than silent.
"""
from __future__ import annotations

import re
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
BACKUP = ROOT / "scripts/backup-controller.sh"
EXPORT = ROOT / "scripts/noo-backup-export.sh"

# The forms an operator can choose. `portable` and `none` are DECISIONS and
# must stay distinguishable from unset, which means nobody has decided yet.
FORMS = ["ssh:", "dir:", "s3:", "portable", "none"]


def _offsite_branches() -> str:
    """Only the `case` arms inside offsite_copy.

    The first version of this test searched the WHOLE file, so it passed on
    the doc comment at the top that merely LISTS the forms — deleting the
    `s3:*)` branch left it green. A guard that a comment can satisfy is not
    a guard.
    """
    body = BACKUP.read_text(encoding="utf-8")
    start = body.index("offsite_copy() {")
    end = body.index("\n}", start)
    fn = body[start:end]
    return "\n".join(l for l in fn.splitlines() if not l.lstrip().startswith("#"))


# A case ARM, not a mention. `s3:` appears in the function's own error text
# ("expected ssh:… dir:… s3:…"), so a substring search passed with the branch
# deleted — the second way this same test fooled itself.
ARM = {
    "ssh:": r"^\s*ssh:\*\)",
    "dir:": r"^\s*dir:\*\)",
    "s3:": r"^\s*s3:\*\)",
    "portable": r"^\s*(portable|none\|portable|portable\|none)\)",
    "none": r"^\s*(none|none\|portable|portable\|none)\)",
}


def test_every_destination_form_is_handled() -> None:
    body = BACKUP.read_text(encoding="utf-8")
    assert "NOO_BACKUP_OFFSITE" in body, "the backup script no longer reads the destination"
    fn = _offsite_branches()
    missing = [f for f, pat in ARM.items() if not re.search(pat, fn, re.M)]
    assert not missing, (
        f"offsite_copy has no case ARM for: {missing} — documented but not handled "
        "means an operator configures it and nothing copies"
    )


def test_an_unknown_destination_is_refused_not_ignored() -> None:
    """A typo in the destination must not read as 'copied fine'."""
    body = BACKUP.read_text(encoding="utf-8")
    assert re.search(r"unknown destination", body), (
        "no branch refuses an unrecognised NOO_BACKUP_OFFSITE — a typo would "
        "silently mean no offsite copy, which is the state this exists to end"
    )


def test_a_failed_copy_exits_non_zero() -> None:
    """The heartbeat action turns a non-zero exit into an operator alert.

    A copy that quietly stopped working is the same as no copy, found at the
    worst possible moment.
    """
    body = BACKUP.read_text(encoding="utf-8")
    assert "OFFSITE_RC" in body and re.search(r'exit "\$OFFSITE_RC"', body), (
        "a failed offsite copy must fail the run"
    )
    assert "LOCAL backup is intact" in body, (
        "and must say the local artifact survived, or the operator will assume "
        "the backup itself failed"
    )


def test_the_export_never_carries_plaintext() -> None:
    """The archive is meant to be carried around. A plaintext dump inside it
    would make it the most dangerous file on the machine."""
    body = EXPORT.read_text(encoding="utf-8")
    assert "refusing to put it in a portable archive" in body
    assert "UNENCRYPTED artifact" in body, (
        "a plaintext artifact in the backup dir must be REPORTED, not just "
        "skipped — it should not exist at all"
    )


def test_the_export_withholds_the_passphrases() -> None:
    """Ciphertext and its key in one archive is a plaintext backup with extra
    steps. The manifest has to say what is missing, or a future reader learns
    it during a restore."""
    body = EXPORT.read_text(encoding="utf-8")
    assert "NOT in here" in body
    for var in ("NOO_BACKUP_PASSPHRASE", "NOO_AGE_BACKUP_PASSPHRASE"):
        assert var in body, f"the manifest must name {var} as required and absent"
    assert "password manager" in body


# ─────────────────────────────────────────────────────────────────────────
# The CLI that WRITES the value and the script that READS it
# ─────────────────────────────────────────────────────────────────────────
#
# `noo backups setup` records the destination; `offsite_copy` acts on it.
# A form the CLI offers that the script does not handle is worse than a
# missing feature: the operator picks it, is told the backups are covered,
# and the copy silently never happens — or fails at 3am in a cron job.
#
# The reverse gap is quieter and still real. A form the script handles but
# the menu never offers is a capability nobody can reach through the
# supported path, so it rots untested until someone hand-edits `.env`.

CLI = ROOT / "noo-cli/src/commands/backups.rs"


def _cli_forms() -> set[str]:
    """The `prefix` of every entry in the CLI's own menu.

    Parsed from the CHOICES table rather than from the `parse_destination`
    match arms, because CHOICES is what an operator is actually shown. The
    two are pinned to each other by a Rust test
    (`every_offered_form_parses_to_what_it_offered`), so checking either one
    here is checking both.

    The regex deliberately does NOT anchor to the start of a line. The first
    version did, and a planted entry written on one line — `Choice { label:
    …, prefix: "rsync:" }` — was invisible to it, so adding a form the
    script cannot handle left the guard green. An extra option is exactly
    what this test exists to catch, and a parser that misses an entry
    reports a violation as compliance.

    The count check below is the backstop: whatever the formatting, one
    `Choice {` must yield one prefix.
    """
    body = CLI.read_text(encoding="utf-8")
    start = body.index("const CHOICES:")
    end = body.index("\n];", start)
    table = body[start:end]
    forms = re.findall(r'prefix:\s*"([^"]+)"', table)
    entries = table.count("Choice {")
    assert len(forms) == entries, (
        f"parsed {len(forms)} prefixes from {entries} menu entries — this guard cannot "
        "see the whole menu, so it cannot judge it"
    )
    return set(forms)


def test_the_cli_offers_exactly_what_the_script_handles() -> None:
    offered = _cli_forms()
    assert offered, "no menu entries parsed out of CHOICES — this guard is stale"

    handled = set(ARM)
    assert offered == handled, (
        f"the CLI offers {sorted(offered - handled)} that offsite_copy does not handle, "
        f"and offsite_copy handles {sorted(handled - offered)} that the CLI never offers"
    )


def test_the_cli_writes_the_key_the_script_reads() -> None:
    body = CLI.read_text(encoding="utf-8")
    assert 'OFFSITE_KEY: &str = "NOO_BACKUP_OFFSITE"' in body, (
        "the CLI writes a different variable than the backup script reads"
    )


def test_unset_stays_distinguishable_from_declined() -> None:
    """`none` is an answer; unset means nobody was ever asked. The script
    treats them differently — one reports a recorded decision, the other
    points at setup — so the CLI must not be able to collapse them."""
    body = CLI.read_text(encoding="utf-8")
    assert "Declined" in body and "fn decided(" in body, (
        "the three-state read is gone; unset and `none` can no longer differ"
    )
    script = BACKUP.read_text(encoding="utf-8")
    assert "not configured (noo backups setup)" in script, (
        "the script no longer distinguishes an unset destination from a declined one"
    )
