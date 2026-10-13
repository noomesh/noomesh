# SPDX-License-Identifier: AGPL-3.0-only
# Copyright 2026 PersonifAI LLC

"""What the COMMITTED monitoring/nats/users.conf is allowed to be.

It is a placeholder that authenticates nobody, and both halves of that
sentence are load-bearing — see the tests at the bottom of this file for
the measurement behind them.

The rest of the file is the older guard: the shipped baseline must not
quote its env references.

NATS expands `$VAR` only when it is UNQUOTED. Quoted, it is a literal, and
the server registers a user whose name is the four characters `$NAT…` rather
than the value. Every principal presenting the real name is then rejected
with `authentication error - User "noo"`, and the gateway and node-agent
crash-loop while postgres, redis and nats stay up — so the box looks
half-alive rather than broken.

That shipped in stack v0.2.22 and stopped the release starting anywhere.

#1154 fixed the RENDERER (the Rust that regenerates this file during the
per-principal rollout) but not this BASELINE, which is the copy embedded in
noo-cli via `STANDALONE_DIRS` and written out by every `noo upgrade` and
every fresh onboard. So the bug survived its own fix: a patched box got the
broken file back on the next upgrade, which is exactly what happened.

The asymmetry is the tell and the reason this test exists: the password line
was always correct, the user line never was, and nothing compared them.
"""

import pathlib
import re

ROOT = pathlib.Path(__file__).resolve().parents[1]
BASELINE = ROOT / "monitoring" / "nats" / "users.conf"


def _env_ref_lines() -> list[tuple[str, str]]:
    """(key, raw value) for every line whose value mentions an env ref."""
    out: list[tuple[str, str]] = []
    for line in BASELINE.read_text().splitlines():
        m = re.match(r"\s*([A-Za-z_]+):\s*(.+?)\s*$", line)
        if m and "$" in m.group(2):
            out.append((m.group(1), m.group(2)))
    return out


def test_env_references_are_unquoted():
    """`user: $NATS_USER`, never `user: "$NATS_USER"`.

    NATS does not expand a quoted reference, so the quotes are the whole
    defect — not a style preference.
    """
    bad = [
        (k, v)
        for k, v in _env_ref_lines()
        if re.fullmatch(r'"\$[A-Za-z_][A-Za-z0-9_]*"', v)
    ]
    assert not bad, (
        "quoted env reference(s) in the shipped NATS baseline — NATS takes "
        f"these literally and every principal is rejected: {bad}"
    )


def test_the_user_and_password_lines_agree():
    """Whatever env references the file carries must be written alike.

    The original bug was one file, four lines apart: `user: "$NATS_USER"`
    quoted beside `password: $NATS_PASSWORD` bare, so the server registered
    a user literally named `$NATS_USER` and rejected everything.

    The baseline no longer carries an env-referenced user OR password — it
    is a placeholder with a literal name and a bcrypt digest, and the digest
    is quoted precisely because it is not an env reference. So this now
    asserts the weaker, still-true thing: any env references that ARE here
    are unquoted and agree with each other. The equivalent check on the
    RENDERER lives in `nats_users.rs`
    (`the_legacy_user_and_its_password_agree`), where the parity of the two
    fields is enforced by both going through one function.
    """
    refs = dict(_env_ref_lines())
    quoted = {
        k: v
        for k, v in refs.items()
        if re.fullmatch(r'"\$[A-Za-z_][A-Za-z0-9_]*"', v)
    }
    assert not quoted, f"quoted env reference(s) NATS will take literally: {quoted}"


def test_the_baseline_carries_no_env_reference_at_all():
    """The placeholder must not be satisfiable by any variable.

    This is the positive form of the test above, and it is the one that
    would have caught a "fix" that put `password: $NATS_PASSWORD` back: the
    baseline authenticates nobody only while nothing in the environment can
    complete it.
    """
    # A real reference is `$` + an IDENTIFIER. A bcrypt digest also starts
    # with `$` (`$2b$11$…`) and is not one — that distinction is the whole
    # reason `_env_ref_lines` is not itself the check here.
    IS_ENV_REF = r'"?\$[A-Za-z_][A-Za-z0-9_]*"?'
    refs = [(k, v) for k, v in _env_ref_lines() if re.fullmatch(IS_ENV_REF, v)]
    assert not refs, f"the committed baseline must reference no env var: {refs}"
    # The guard must be able to see one — otherwise it would pass on a file
    # that had gone straight back to `password: $NATS_PASSWORD`.
    assert re.fullmatch(IS_ENV_REF, "$NATS_PASSWORD")
    assert not re.fullmatch(IS_ENV_REF, '"$2b$11$abcdefghijklmnopqrstuv"')


def test_a_bcrypt_digest_would_still_be_quoted():
    """The obvious fix — never quote anything starting with `$` — is WRONG.

    A bcrypt digest starts with `$` too (`$2b$11$…`). Unquoting one would
    have NATS try to expand it, trading this outage for a subtler one. The
    rule is `$` followed by an IDENTIFIER; `2b$11$…` is not one, so a digest
    stays quoted and this test must not forbid it.
    """
    digest = '"$2b$11$abcdefghijklmnopqrstuv"'
    assert not re.fullmatch(r'"\$[A-Za-z_][A-Za-z0-9_]*"', digest), (
        "the guard must not classify a bcrypt digest as a quoted env reference"
    )


# ── the baseline must authenticate NOBODY ────────────────────────────────


def _text() -> str:
    return BASELINE.read_text()


def test_the_baseline_grants_nothing():
    """No `allow` of `>` anywhere in the committed file.

    The committed baseline used to be the legacy shared user with
    `publish/subscribe: { allow: [">"] }` — a bus-wide credential, in the
    repository, applied to any install that never ran the render. That is
    tracker row N8's server side and §3f row D9's reason for existing: the
    security page said each principal presents its own pair while the file
    the server actually read granted everything to one.

    The RENDERED file legitimately grants `>` to the `gateway` principal
    (it is the JetStream administrator). This check is about the committed
    one only.
    """
    text = _text()
    granting = [
        line.strip()
        for line in text.splitlines()
        if not line.strip().startswith("#") and "allow:" in line and '">"' in line
    ]
    assert not granting, (
        "the committed baseline grants `>` — an install that never rendered "
        f"users.conf would run with a bus-wide credential: {granting}"
    )


def test_the_baseline_names_a_user_so_nats_demands_one():
    """An empty `users: []` would be the OPEN configuration, not the safe one.

    Measured against the pinned image (nats@sha256:7ff2e641…), reading
    /varz after boot:

        accounts { NOO: { jetstream: enabled, users: [] } }  ->  auth_required unset
        one user with an unusable digest                     ->  auth_required: true

    With no user configured NATS requires no credential at all, so every
    container on `noo-cluster` would connect anonymously and be accepted.
    The file therefore has to name at least one user — and the only safe
    one to name is a user whose password nobody holds.
    """
    text = _text()
    body = "\n".join(l for l in text.splitlines() if not l.strip().startswith("#"))
    assert "users: []" not in body.replace(" ", "").replace("users:[]", "users: []"), (
        "an empty user list removes bus authentication entirely"
    )
    assert re.search(r"^\s*user:\s*\S", body, re.M), (
        "the baseline must declare a user, or NATS requires no credential at all"
    )


def test_the_baseline_password_is_an_unusable_digest():
    """A bcrypt digest, and not an env reference anybody could satisfy.

    `password: $NATS_PASSWORD` would make the placeholder usable the moment
    that variable is set — which it is, on every install — and the "nobody
    can authenticate" property would be a comment rather than a fact.
    """
    body = "\n".join(l for l in _text().splitlines() if not l.strip().startswith("#"))
    m = re.search(r"^\s*password:\s*(.+?)\s*$", body, re.M)
    assert m, "the baseline declares no password"
    value = m.group(1)
    assert value.startswith('"$2'), (
        f"the baseline password must be a quoted bcrypt digest, got: {value}"
    )
    # ...and it must NOT be an env reference the running fleet already holds.
    assert not re.fullmatch(r'\$[A-Za-z_][A-Za-z0-9_]*', value), value
