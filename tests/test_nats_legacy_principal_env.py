# SPDX-License-Identifier: AGPL-3.0-only
# Copyright 2026 PersonifAI LLC

"""The legacy shared NATS principal is retired — and stays retired.

History: `noo cluster nats-users render` (noo-cli/src/commands/nats_users.rs)
wrote the shared principal into users.conf as `user: $NATS_USER` /
`password: $NATS_PASSWORD`, and NATS refuses to start on a users.conf whose
variable it cannot resolve. On 2026-09-29 the two variables were removed from
the nats service while the renderer still emitted them, and the stack-v0.2.78
roll took the controller's bus down (#543 → #560, which added this file as
"every `$VAR` the renderer emits is handed to nats").

an earlier change retired the principal, both variables and the
`NOO_NATS_LEGACY_SHARED_CREDS` bridge together. This is now the INVERSE
guard, and both halves have to hold at once:

1. the renderer emits NO `$VAR` into users.conf — it has no bare-value
   branch left, so nothing it writes can depend on the server's environment;
2. no compose service in the composed projection is handed `NATS_USER`,
   `NATS_PASSWORD`, a `_FILE` pointer for either, or the retired bridge — and
   no top-level compose secret sources `NATS_PASSWORD`.

Re-adding the legacy emission fails (1); re-adding the variables anywhere
fails (2). The launcher half — refusing to start nats on an OLD on-disk
users.conf that still names `$NATS_USER` — lives in
`commands::bind_sources` (unit-tested in the noo-cli job) and
`tests/test_launcher_bind_sources.py`.
"""

from __future__ import annotations

import re
from pathlib import Path

from tests._compose_projection import env_of, full_projection

ROOT = Path(__file__).resolve().parents[1]
RENDERER = ROOT / "noo-cli/src/commands/nats_users.rs"
RETIRED = ("NATS_USER", "NATS_PASSWORD", "NOO_NATS_LEGACY_SHARED_CREDS")

# The two shapes an env reference has ever been written in by the renderer:
# a principal PUSHED with a `$NAME` user (`user: "$NATS_USER".into()`), and
# a bare `$NAME` handed to `nats_value` / emitted as a password default.
_PUSHED = re.compile(r'user:\s*"\$([A-Z_][A-Z0-9_]*)"\.into\(\)')
_DEFAULTED = re.compile(r'unwrap_or\("\$([A-Z_][A-Z0-9_]*)"\)')


def _renderer_body() -> str:
    """nats_users.rs up to its test module: the tests legitimately spell the
    legacy text (to prove the parser can SEE it); the renderer must not."""
    src = RENDERER.read_text()
    cut = src.find("#[cfg(test)]")
    assert cut > 0, "nats_users.rs has no test module — the split this guard relies on moved"
    return src[:cut]


def _emitted_variables(body: str) -> set[str]:
    return set(_PUSHED.findall(body)) | set(_DEFAULTED.findall(body))


def test_the_parse_can_see_a_legacy_emission() -> None:
    # A guard is only as good as its parse: both historical shapes must be
    # found when they are there.
    planted = (
        'out.push(Principal { user: "$NATS_USER".into(), hash: None, role: Role::Legacy });\n'
        'fn password_value(h: &Option<String>) -> String { nats_value(h.as_deref().unwrap_or("$NATS_PASSWORD")) }\n'
    )
    assert _emitted_variables(planted) == {"NATS_USER", "NATS_PASSWORD"}


def test_the_renderer_emits_no_environment_variable() -> None:
    body = _renderer_body()
    assert "fn render_users_conf" in body, "the renderer moved — this guard is reading the wrong file"
    found = _emitted_variables(body)
    assert not found, (
        f"nats_users.rs emits {sorted(found)} into users.conf again. The shared principal was retired "
        "; NATS refuses a users.conf whose variable the nats service is not handed."
    )
    assert "Role::Legacy" not in body and "Legacy," not in body, "the Legacy role is back in the renderer"
    # Every value goes through ONE always-quoting function.
    m = re.search(r"fn nats_value\(v: &str\) -> String \{(.*?)\n\}", body, re.S)
    assert m, "nats_value not found"
    assert "is_env_ref" not in m.group(1), "nats_value has a bare (expanding) branch again"


def test_no_compose_service_is_handed_the_retired_pair_or_bridge() -> None:
    services = full_projection()["services"]
    assert "nats" in services and "gateway" in services, "the projection is missing core services — parse broke"
    bad = []
    for name, svc in services.items():
        for key in env_of(svc):
            base = key.removesuffix("_FILE")
            if base in RETIRED:
                bad.append(f"{name}: {key}")
    assert not bad, (
        f"retired shared-NATS names are handed to a container again: {bad}. an earlier change retired the "
        "shared user; every principal presents its own pair (NATS_GATEWAY_*, NATS_WORKER_*, NATS_NODE_*)."
    )


def test_no_top_level_secret_sources_the_retired_password() -> None:
    secrets = {k: (v or {}).get("environment") for k, v in (full_projection().get("secrets") or {}).items()}
    assert secrets, "no top-level secrets parsed — this guard is reading the wrong thing"
    bad = {k: v for k, v in secrets.items() if v in RETIRED or k == "nats_password"}
    assert not bad, f"a compose secret still sources the retired pair: {bad}"


def test_the_committed_baseline_names_no_environment_variable() -> None:
    text = (ROOT / "monitoring/nats/users.conf").read_text()
    body = "\n".join(l.split("#", 1)[0] for l in text.splitlines())
    refs = re.findall(r":\s*\$([A-Za-z_][A-Za-z0-9_]*)\s*$", body, re.M)
    assert not refs, f"the committed baseline references {refs}"
