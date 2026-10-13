#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-only
# Copyright 2026 PersonifAI LLC

"""`noo doctor privileges` and prep-host.sh must agree on what is legacy.

prep-host.sh is the only thing that REMOVES legacy sudoers drop-ins, and it
only ever runs on an enrolled node — a controller is never enrolled, so
nothing cleans one. `noo doctor privileges` is what makes that visible, and
it can only report a name it knows about.

If the two lists drift, a controller keeps a NOPASSWD grant that nothing
removes and nothing reports. This is a repo-level check rather than a Rust
test because the noo-cli crate is built in isolation in CI and cannot read
a file outside its own tree.
"""
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
DOCTOR = ROOT / "noo-cli/src/commands/doctor.rs"
PREP = ROOT / "scripts/prep-host.sh"


def main() -> int:
    src = DOCTOR.read_text()
    m = re.search(r"const LEGACY_SUDOERS: &\[&str\] = &\[(.*?)\];", src, re.S)
    if not m:
        print("check-legacy-sudoers-sync: LEGACY_SUDOERS not found in doctor.rs", file=sys.stderr)
        return 1
    names = re.findall(r'"([^"]+)"', m.group(1))
    if not names:
        print("check-legacy-sudoers-sync: LEGACY_SUDOERS is empty", file=sys.stderr)
        return 1

    prep = PREP.read_text()
    missing = [n for n in names if f"/etc/sudoers.d/{n}" not in prep]
    if missing:
        print(
            "check-legacy-sudoers-sync: FAIL — reported as legacy but not in "
            f"prep-host's removal list: {', '.join(missing)}",
            file=sys.stderr,
        )
        return 1

    # And the other direction: a name prep-host removes that doctor does not
    # know about is a grant no operator will ever be told they still carry.
    removed = set(re.findall(r"/etc/sudoers\.d/([A-Za-z0-9._-]+)", prep))
    # Nothing is carved out any more. prep-host used to WRITE
    # /etc/sudoers.d/noo-apply, so it could not also be reported as legacy;
    # retiring the SSH gate removed that grant's only consumer, prep-host
    # stopped writing it, and it became legacy like the rest. A carve-out
    # that outlives its reason is how a name stops being checked.
    unreported = sorted(removed - set(names))
    if unreported:
        print(
            "check-legacy-sudoers-sync: FAIL — prep-host removes these but "
            f"`noo doctor privileges` never reports them: {', '.join(unreported)}",
            file=sys.stderr,
        )
        return 1

    print(f"check-legacy-sudoers-sync: ok ({len(names)} legacy drop-in(s) in sync)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
