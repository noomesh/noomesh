# SPDX-License-Identifier: AGPL-3.0-only
# Copyright 2026 PersonifAI LLC

"""an earlier change findings 5 and 6, pinned.

5. `security_cli.py`'s post-rotation gateway probe verified nothing
   (`verify=False`): a probe that accepts any certificate proves nothing
   about the leaf the rotation just installed. It verifies against the
   cluster CA (or the system store) now — never unverified.
6. `heartbeat.py` / `proactive_agent.py` swallowed `_apply_redis_tls`'s
   refusal of a plaintext `redis://` URL in a bare `except Exception` and
   ran without Redis in silence. The refusal is logged (once) now.
"""

from __future__ import annotations

import re
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def _code(path: Path) -> str:
    return "\n".join(l for l in path.read_text().splitlines() if not l.lstrip().startswith("#"))


def test_security_cli_never_skips_tls_verification():
    code = _code(ROOT / "src/noomesh/security_cli.py")
    assert "https://localhost:8080/health" in code, "the gateway probe moved — this guard checks nothing"
    assert not re.search(r"verify\s*=\s*False", code), "security_cli.py dials with verify=False again"
    assert "NOO_TLS_CA" in code, "the gateway probe no longer verifies against the cluster CA"


def test_the_redis_refusal_is_logged_not_swallowed():
    for rel in ("src/noomesh/gateway/heartbeat.py", "src/noomesh/gateway/proactive_agent.py"):
        code = _code(ROOT / rel)
        body = code[code.index("def _get_redis") :]
        body = body[: body.index("\n        return self._redis_client\n")]
        refused = body.find("except ValueError")
        generic = body.find("except Exception")
        assert refused >= 0 and "redis_url_refused" in body, f"{rel}: the plaintext-Redis refusal is swallowed"
        assert refused < generic, f"{rel}: `except Exception` catches the refusal before it is logged"
