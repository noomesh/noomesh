"""The password policy exists in two crates that share no code: the gateway
enforces it on create / set-password, the CLI and the onboarding wizard check
it before sending. The two copies must stay byte-identical, or a password one
side accepts the other refuses (and the refusal reaches the operator late)."""

from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
GATEWAY = ROOT / "gateway-rust/src/password_policy.rs"
CLI = ROOT / "noo-cli/src/password_policy.rs"


def test_the_two_copies_are_byte_identical():
    assert GATEWAY.read_bytes() == CLI.read_bytes(), (
        "gateway-rust/src/password_policy.rs and noo-cli/src/password_policy.rs drifted; "
        "edit both together"
    )


def test_the_policy_has_the_floor_and_the_list():
    text = GATEWAY.read_text()
    assert "const FLOOR: usize = 12;" in text
    assert '"password123"' in text and "noomesh12345" in text
    assert "must not contain the username" in text


def test_nothing_still_enforces_the_old_eight_character_rule():
    users = (ROOT / "gateway-rust/src/routes/users.rs").read_text()
    assert "body.password.len() < 8" not in users
    assert "check_new_password(" in users
    cli = (ROOT / "noo-cli/src/commands/security.rs").read_text()
    assert "password.len() < 8" not in cli
    assert "password_policy::weak_password" in cli
    wizard = (ROOT / "noo-cli/src/onboard/steps.rs").read_text()
    assert "fn weak_password(" not in wizard, "the wizard must use the shared policy, not its own copy"
