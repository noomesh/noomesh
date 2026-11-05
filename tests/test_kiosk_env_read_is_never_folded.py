"""A seat that cannot read /etc/default/kiosk must say so (P3).

Through 0.6.16 the seat sync read the display's env file with
`std::fs::read_to_string(ENV_FILE).ok()...unwrap_or_default()`. The file was
0640 root:<display user> and the sync runs as the seat user, so every
heartbeat reported mode, view and quality as "", the same as a seat with no
kiosk at all. The controller could not tell "unreadable" from "not set".

`kiosk_env_from` now keeps the three answers apart (`read`, `absent`,
`unreadable: <error>`). This guard fails if a read of ENV_FILE in the seat
code goes back to discarding the error.
"""
from __future__ import annotations

import re
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SEAT = ROOT / "noo-cli" / "src" / "commands" / "kiosk_seat.rs"

READ = re.compile(r"read_to_string\(\s*super::kiosk::ENV_FILE\s*\)")


def env_reads(src: str) -> list[str]:
    """Each ENV_FILE read, with the rest of its statement."""
    out = []
    for m in READ.finditer(src):
        start = src.rfind("\n", 0, m.start()) + 1
        end = src.find(";", m.end())
        out.append(src[start:end if end != -1 else len(src)])
    return out


def folded(stmt: str) -> bool:
    return bool(re.search(r"\.ok\(\)|unwrap_or_default\(\)|unwrap_or\(", stmt)) and "kiosk_env_from(" not in stmt


def test_every_env_file_read_keeps_its_error():
    reads = env_reads(SEAT.read_text())
    assert len(reads) >= 2, f"found {len(reads)} ENV_FILE reads; the enroll facts and the heartbeat both read it"
    bad = [r.strip() for r in reads if folded(r) or "kiosk_env_from(" not in r]
    assert not bad, f"an ENV_FILE read drops its error (unreadable reads as unset): {bad}"


def test_the_source_names_all_three_answers():
    src = SEAT.read_text()
    body = src[src.index("fn kiosk_env_from("):]
    body = body[: body.index("\n}\n")]
    assert '"read"' in body and '"absent"' in body and '"unreadable: ' in body, body
    assert "ErrorKind::NotFound" in body, "absent must be told apart from unreadable"


def test_the_guard_catches_the_old_shape():
    old = "    let kiosk_env = std::fs::read_to_string(super::kiosk::ENV_FILE).ok().map(|t| read_kiosk_env(&t)).unwrap_or_default();\n"
    new = "    let kiosk_env = kiosk_env_from(std::fs::read_to_string(super::kiosk::ENV_FILE));\n"
    assert folded(env_reads(old)[0])
    assert not folded(env_reads(new)[0])
