// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 PersonifAI LLC

//! Secrets in plaintext `.env` — the one definition of "this install keeps a
//! secret in the clear", shared by every place that must refuse or report it.
//!
//! The operator's rule is "always sops, never plaintext". Until 2026-09-30
//! three lanes still ended with credentials in `.env`: `noo onboard
//! --secrets-backend env` (an explicit opt-out), a missing
//! `scripts/noo-secrets-sops-init.sh`, and a failing one — the last two
//! warned and let the wizard finish green. The wizard now refuses all three
//! (`onboard/steps.rs` `arm_secret_store`), and an install that predates that
//! is found by the readers here:
//!
//! * `noo cluster verify --controller` — the `secrets at rest` row
//!   ([`at_rest_row`]) FAILS;
//! * `noo security scan` — a CRITICAL `Secrets At Rest` finding;
//! * `noo upgrade --stack` — refuses the roll before anything moves;
//! * `noo security secrets tidy` — blanks each `.env` value the store already
//!   holds ([`blank_stored`]).
//!
//! All of them name [`REMEDY`]. What counts as a secret is the registry's
//! word, not a new list: a file-backed tier-1/tier-2 name
//! (`secrets_delivery::TIER1`), any rotation-registry row
//! (`secrets::registry()`), or a credential-shaped name
//! (`secrets::looks_like_credential`, which already excludes the bootstrap
//! flags such as `NOO_SECRETS_BACKEND` that belong in `.env`). Only NAMES
//! ever leave this module — never a value.

use crate::commands::cluster_verify::{Check, Verdict};
use std::path::Path;

/// The command that moves a plaintext install onto the encrypted store, and
/// the one that clears the copies afterwards. Parenthesised on purpose: the
/// CLI hint lint (`hint_lint.rs`) checks a literal that opens a `(` group, so
/// both commands are checked against usage.rs like any inline remedy.
#[allow(unused_parens)]
pub(crate) const REMEDY: &str =
    ("noo onboard --reconfigure --only secrets --secrets-backend sops   # then: noo security secrets tidy");

/// The onboard half of [`REMEDY`] alone — for `tidy` itself, which is the
/// second half. Parenthesised for the hint lint, as above.
#[allow(unused_parens)]
pub(crate) const REMEDY_ONBOARD: &str = ("noo onboard --reconfigure --only secrets --secrets-backend sops");

/// The second half of [`REMEDY`] alone — when the store already holds every
/// `.env` secret. Parenthesised for the hint lint, as above.
#[allow(unused_parens)]
pub(crate) const REMEDY_TIDY: &str = ("noo security secrets tidy");

/// Is `key` secret-class — a value that belongs in `secrets/env.sops` and
/// never in `.env`?
pub(crate) fn secret_class(key: &str) -> bool {
    crate::commands::secrets_delivery::TIER1.contains(&key)
        || crate::commands::secrets::spec_for(key).is_some()
        || crate::commands::secrets::looks_like_credential(key)
}

/// A value that is really empty: `KEY=`, `KEY=""`, `KEY=''`.
fn blank(v: &str) -> bool {
    v.trim().trim_matches('"').trim_matches('\'').trim().is_empty()
}

/// The secret-class keys that hold a VALUE in these `.env` pairs (last
/// assignment wins, as compose reads it), in first-seen order. A blank slot is
/// not a copy — the wizard blanks each slot once the store holds it.
pub(crate) fn plaintext_secret_keys(pairs: &[(String, String)]) -> Vec<String> {
    let mut last: std::collections::BTreeMap<&str, &str> = std::collections::BTreeMap::new();
    let mut order: Vec<&str> = Vec::new();
    for (k, v) in pairs {
        if !last.contains_key(k.as_str()) {
            order.push(k.as_str());
        }
        last.insert(k.as_str(), v.as_str());
    }
    order
        .into_iter()
        .filter(|k| secret_class(k) && !blank(last[k]))
        .map(str::to_string)
        .collect()
}

/// What an install's `.env` and store say about secrets at rest.
#[derive(Debug, Clone, PartialEq)]
pub(crate) struct AtRest {
    /// `.env` exists at all (a worker node or a bare checkout has none).
    pub env_present: bool,
    /// `NOO_SECRETS_BACKEND` as the launcher resolves it (process env first,
    /// then `.env`, last assignment) — empty when unset.
    pub backend: String,
    /// `secrets/env.sops` exists.
    pub store_present: bool,
    /// Where the store is (`<root>/secrets/env.sops`).
    pub store_path: std::path::PathBuf,
    /// Secret-class keys holding a value in `.env`. Names only.
    pub plaintext: Vec<String>,
    /// Which of [`Self::plaintext`] the store ALSO holds, and which live only
    /// in `.env` — read by OPENING the store ([`Self::with_store_split`]).
    /// `None` = not read (no store, nothing in `.env`, or the store could not
    /// be decrypted here); then nothing may claim a copy exists. Until
    /// 2026-10-02 the row printed "each is also a copy beside
    /// secrets/env.sops" whenever the store FILE existed, without looking:
    /// on host8 both keys it named lived only in `.env`, and the claim
    /// invites an operator to blank the only copy.
    pub store_split: Option<Blanked>,
}

impl AtRest {
    /// Read the install at `root`.
    pub(crate) fn read(root: &Path) -> Self {
        let env_path = root.join(".env");
        let pairs = crate::onboard::env::read_env_pairs(&env_path);
        let from_file = pairs
            .iter()
            .rev()
            .find(|(k, _)| k == "NOO_SECRETS_BACKEND")
            .map(|(_, v)| v.trim_matches('"').trim().to_string())
            .unwrap_or_default();
        let backend = std::env::var("NOO_SECRETS_BACKEND")
            .ok()
            .filter(|v| !v.trim().is_empty())
            .unwrap_or(from_file);
        AtRest {
            env_present: env_path.is_file(),
            backend,
            store_present: root.join("secrets/env.sops").is_file(),
            store_path: root.join("secrets/env.sops"),
            plaintext: plaintext_secret_keys(&pairs),
            store_split: None,
        }
    }

    /// Fill [`Self::store_split`] by opening the store — only when there is
    /// something to split (a secret in `.env`, the sops backend, a store
    /// file). A store that cannot be decrypted leaves it `None`.
    pub(crate) fn with_store_split(self) -> Self {
        let path = self.store_path.clone();
        self.with_store_split_from(&|| {
            let store = crate::commands::secrets::SecretStore::load_sops(&path)?;
            Ok(store
                .keys()
                .filter(|k| store.state(k) == crate::commands::secrets::State::Set)
                .cloned()
                .collect())
        })
    }

    /// [`Self::with_store_split`] over any reader of the store's key names
    /// (those holding a value) — pure, so the row is tested without sops.
    pub(crate) fn with_store_split_from(
        mut self,
        stored_keys: &dyn Fn() -> Result<std::collections::BTreeSet<String>, String>,
    ) -> Self {
        if self.plaintext.is_empty() || self.backend != "sops" || !self.store_present {
            return self;
        }
        self.store_split = stored_keys().ok().map(|set| split_by_store(&self.plaintext, &|k| set.contains(k)));
        self
    }

    /// The names, shortened for a one-line detail.
    fn names(&self) -> String {
        const SHOWN: usize = 6;
        let mut s = self.plaintext.iter().take(SHOWN).cloned().collect::<Vec<_>>().join(", ");
        if self.plaintext.len() > SHOWN {
            s.push_str(&format!(" and {} more", self.plaintext.len() - SHOWN));
        }
        s
    }

    /// Why `.env` holds a secret in the clear, or None. The criterion
    /// `noo security scan` applies on any box.
    pub(crate) fn plaintext_problem(&self) -> Option<String> {
        if self.plaintext.is_empty() {
            return None;
        }
        Some(format!(
            ".env holds {} secret(s) in plaintext: {}",
            self.plaintext.len(),
            self.names()
        ))
    }

    /// Why this CONTROLLER is not on the encrypted store, or None: a
    /// plaintext secret in `.env`, or the store not armed at all. The
    /// criterion `cluster verify --controller` and `upgrade --stack` apply.
    pub(crate) fn controller_problem(&self) -> Option<String> {
        if let Some(p) = self.plaintext_problem() {
            let tail = if self.backend != "sops" || !self.store_present {
                " — and this install is not on the encrypted store (NOO_SECRETS_BACKEND is not `sops`, or secrets/env.sops is absent)".to_string()
            } else {
                match &self.store_split {
                    None => " — whether secrets/env.sops also holds them was NOT checked (the store was not \
                             read here), so do not blank .env by hand"
                        .to_string(),
                    Some(split) => {
                        let mut t = String::new();
                        if !split.only_in_env.is_empty() {
                            t.push_str(&format!(
                                " — {} live ONLY in .env, the store has no copy (do not blank them; the remedy \
                                 carries them in first): {}",
                                split.only_in_env.len(),
                                split.only_in_env.join(", ")
                            ));
                        }
                        if !split.blanked.is_empty() {
                            t.push_str(&format!(
                                " — {} also in secrets/env.sops (a stale plaintext copy): {}",
                                split.blanked.len(),
                                split.blanked.join(", ")
                            ));
                        }
                        t
                    }
                }
            };
            return Some(format!("{p}{tail}"));
        }
        if self.backend != "sops" {
            return Some(format!(
                "NOO_SECRETS_BACKEND is `{}` — the plaintext .env backend is retired; secrets live only in secrets/env.sops",
                if self.backend.is_empty() { "env (unset)" } else { &self.backend }
            ));
        }
        if !self.store_present {
            return Some("NOO_SECRETS_BACKEND=sops but secrets/env.sops does not exist".into());
        }
        None
    }
}

/// The `secrets at rest` row for `noo cluster verify --controller`.
pub(crate) fn at_rest_check(state: &AtRest) -> Check {
    match state.controller_problem() {
        None => Check {
            name: "secrets at rest",
            verdict: Verdict::Ok,
            detail: "every secret is in secrets/env.sops; .env holds no secret-class value".into(),
            remedy: None,
        },
        Some(why) => Check {
            name: "secrets at rest",
            verdict: Verdict::Fail,
            detail: why,
            remedy: Some(state.remedy().into()),
        },
    }
}

impl AtRest {
    /// The remedy for [`Self::controller_problem`]: `tidy` alone when the
    /// store was READ and holds every `.env` secret (nothing to carry);
    /// otherwise the onboard carry first. Never "tidy" on an unread store.
    pub(crate) fn remedy(&self) -> &'static str {
        match &self.store_split {
            Some(split) if split.only_in_env.is_empty() && !split.blanked.is_empty() => REMEDY_TIDY,
            _ => REMEDY,
        }
    }
}

/// The row, read from this controller's install — with the store OPENED, so
/// the detail says truthfully which `.env` secrets have a store copy.
pub fn at_rest_row() -> Check {
    at_rest_check(&AtRest::read(&crate::envfile::repo_root()).with_store_split())
}

/// What [`blank_stored`] did.
#[derive(Debug, Default, Clone, PartialEq)]
pub(crate) struct Blanked {
    /// Blanked in `.env`: the store holds a value for each.
    pub blanked: Vec<String>,
    /// Left alone: the store holds NO value for these, so the `.env` copy is
    /// the only one. The onboard remedy carries them into the store.
    pub only_in_env: Vec<String>,
}

/// The pure decision: of the `.env` keys holding a secret, which may be
/// blanked (`stored(key)` — the store holds a value) and which are the only
/// copy.
pub(crate) fn split_by_store(plaintext: &[String], stored: &dyn Fn(&str) -> bool) -> Blanked {
    let mut out = Blanked::default();
    for k in plaintext {
        if stored(k) {
            out.blanked.push(k.clone());
        } else {
            out.only_in_env.push(k.clone());
        }
    }
    out
}

/// Blank every secret-class value in `.env` that the encrypted store already
/// holds — `noo security secrets tidy`'s plaintext half. Refuses (changing
/// nothing) when the install is not on the store: with the env backend `.env`
/// IS what the stack reads, and blanking it would take the value away. A key
/// the store lacks is never blanked — its `.env` copy is the only one.
pub(crate) fn blank_stored(root: &Path) -> Result<Blanked, String> {
    let state = AtRest::read(root);
    if state.plaintext.is_empty() {
        return Ok(Blanked::default());
    }
    if state.backend != "sops" || !state.store_present {
        return Err(format!(
            "{} — .env is what this install reads, so nothing was blanked. Move it onto the \
             encrypted store first: {REMEDY_ONBOARD}",
            state.plaintext_problem().unwrap_or_default()
        ));
    }
    let store = crate::commands::secrets::SecretStore::load_sops(&root.join("secrets/env.sops"))?;
    let split = split_by_store(&state.plaintext, &|k| {
        store.state(k) == crate::commands::secrets::State::Set
    });
    let env_path = root.join(".env");
    for k in &split.blanked {
        crate::onboard::env::update_env_key(&env_path, k, "").map_err(|e| format!("{k}: {e}"))?;
    }
    Ok(split)
}

/// `noo security secrets tidy`'s plaintext half: blank what the store holds,
/// refuse (exit 1, `.env` untouched) when the install is not on the store or
/// a secret's only copy is in `.env`. Human output only — the JSON document
/// `tidy` prints stays the store half's.
pub(crate) fn tidy_plaintext(g: &crate::Globals) {
    use crate::output::{fail, ExitCode};
    match blank_stored(&crate::envfile::repo_root()) {
        Err(e) => fail(g.json, ExitCode::Generic, "plaintext_secrets", &e, Some(REMEDY_ONBOARD)),
        Ok(b) => {
            if !b.blanked.is_empty() && !g.json {
                crate::ui::done(&format!(
                    "{} plaintext secret(s) blanked in .env (secrets/env.sops holds each): {}",
                    b.blanked.len(),
                    b.blanked.join(", ")
                ));
            }
            if !b.only_in_env.is_empty() {
                fail(
                    g.json,
                    ExitCode::Generic,
                    "plaintext_only_copy",
                    &format!(
                        ".env holds the ONLY copy of {} secret(s) — not blanked: {}",
                        b.only_in_env.len(),
                        b.only_in_env.join(", ")
                    ),
                    Some(REMEDY_ONBOARD),
                );
            }
        }
    }
}

/// Exit code of `noo config launch-check secrets-at-rest` when it refuses —
/// the same code `bind-sources` uses, so `scripts/lib-secrets.sh` can tell a
/// refusal (3) from an older `noo` that lacks the verb (anything else).
pub(crate) const LAUNCH_REFUSED: i32 = 3;

/// What the launcher prints when it refuses to start this install, or None
/// when the install may start. The criterion is `controller_problem` — the
/// one `cluster verify --controller` and `upgrade --stack` already apply —
/// so the launcher cannot disagree with them about what "plaintext" means.
pub(crate) fn launch_refusal(state: &AtRest) -> Option<String> {
    state.controller_problem().map(|why| {
        format!(
            "REFUSED: not starting — {why}.\n  \
             This launcher no longer starts an install that keeps its secrets in plaintext .env; \
             nothing was changed and no container was touched.\n  \
             fix: {}",
            state.remedy()
        )
    })
}

/// `noo config launch-check secrets-at-rest [<install-root>]` — hidden,
/// called by `scripts/lib-secrets.sh` `check_secrets_at_rest` in every
/// launcher before its first compose command. The root
/// defaults to the current directory: the launchers run from the repo root.
/// Exit 0 = on the encrypted store with no secret-class value in `.env`;
/// [`LAUNCH_REFUSED`] = refused, the reason and [`REMEDY`] on stderr. Names
/// only — never a value.
pub fn launch_check(args: &[String]) -> i32 {
    let root = args.first().map(std::path::PathBuf::from).unwrap_or_else(|| std::path::PathBuf::from("."));
    match launch_refusal(&AtRest::read(&root).with_store_split()) {
        None => 0,
        Some(msg) => {
            eprintln!("{msg}");
            LAUNCH_REFUSED
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn pairs(kv: &[(&str, &str)]) -> Vec<(String, String)> {
        kv.iter().map(|(k, v)| (k.to_string(), v.to_string())).collect()
    }

    fn state(backend: &str, store: bool, env: &[(&str, &str)]) -> AtRest {
        AtRest {
            env_present: true,
            backend: backend.into(),
            store_present: store,
            plaintext: plaintext_secret_keys(&pairs(env)),
            store_path: std::path::PathBuf::new(),
            store_split: None,
        }
    }

    #[test]
    fn secret_class_is_the_registry_word_and_spares_the_bootstrap_flags() {
        for k in ["NOO_JWT_SECRET", "POSTGRES_PASSWORD", "ANTHROPIC_API_KEY", "HF_TOKEN",
                  "NOO_BACKUP_PASSPHRASE", "GRAFANA_PASSWORD", "SOME_NEW_API_KEY"] {
            assert!(secret_class(k), "{k} is secret-class");
        }
        for k in ["NOO_SECRETS_BACKEND", "SOPS_AGE_KEY_FILE", "NOO_IMAGE_TAG", "NODE_ID",
                  "NATS_USER", "NOO_ADMIN_USER", "NOO_TLS_KEY_FILE"] {
            assert!(!secret_class(k), "{k} is config, not a secret");
        }
    }

    #[test]
    fn a_blank_slot_is_not_a_copy_and_the_last_assignment_wins() {
        let got = plaintext_secret_keys(&pairs(&[
            ("NOO_JWT_SECRET", ""),
            ("REDIS_PASSWORD", "\"\""),
            ("NATS_PASSWORD", "abc"),
            ("NATS_PASSWORD", ""), // later blank wins
            ("POSTGRES_PASSWORD", ""),
            ("POSTGRES_PASSWORD", "set-later"), // later value wins
            ("NOO_SECRETS_BACKEND", "sops"),
        ]));
        assert_eq!(got, vec!["POSTGRES_PASSWORD".to_string()]);
    }

    #[test]
    fn the_row_fails_on_a_secret_in_env_and_is_ok_when_it_is_blank() {
        let bad = at_rest_check(&state("sops", true, &[("NOO_SECRETS_BACKEND", "sops"), ("NOO_JWT_SECRET", "SENTINEL-VALUE-1")]));
        assert_eq!(bad.verdict, Verdict::Fail);
        assert!(bad.detail.contains("NOO_JWT_SECRET"), "{}", bad.detail);
        assert!(!bad.detail.contains("SENTINEL"), "a row never carries a value: {}", bad.detail);
        assert_eq!(bad.remedy.as_deref(), Some(REMEDY));

        let good = at_rest_check(&state("sops", true, &[("NOO_SECRETS_BACKEND", "sops"), ("NOO_JWT_SECRET", "")]));
        assert_eq!(good.verdict, Verdict::Ok, "{}", good.detail);
    }

    /// host8, 2026-10-02: two secrets in `.env`, NEITHER in the store. The
    /// row opens the store and names them as `.env`-only — it never says a
    /// copy exists — and its remedy carries them in before anything blanks.
    #[test]
    fn env_only_secrets_are_named_as_the_only_copy_never_as_a_copy() {
        let env = [("NOO_SECRETS_BACKEND", "sops"), ("NOO_ENTITLEMENT", "SENTINEL-ent"),
                   ("NOO_FILECRED_GOOGLE_CHAT_B64", "SENTINEL-cred")];
        let st = state("sops", true, &env).with_store_split_from(&|| {
            Ok(["NOO_JWT_SECRET".to_string(), "POSTGRES_PASSWORD".to_string()].into_iter().collect())
        });
        let c = at_rest_check(&st);
        assert_eq!(c.verdict, Verdict::Fail);
        assert!(c.detail.contains("ONLY in .env") && c.detail.contains("NOO_ENTITLEMENT")
            && c.detail.contains("NOO_FILECRED_GOOGLE_CHAT_B64"), "{}", c.detail);
        assert!(!c.detail.contains("also a copy") && !c.detail.contains("also in secrets/env.sops"),
            "claims a store copy that does not exist: {}", c.detail);
        assert!(!c.detail.contains("SENTINEL"), "{}", c.detail);
        assert_eq!(c.remedy.as_deref(), Some(REMEDY), "carry first, then tidy");
        assert!(launch_refusal(&st).unwrap().contains("ONLY in .env"));
    }

    /// The split is reported per key; only when the store holds every one is
    /// `tidy` alone the remedy. An unreadable store claims nothing.
    #[test]
    fn a_store_copy_is_claimed_only_after_the_store_was_read() {
        let env = [("NOO_SECRETS_BACKEND", "sops"), ("NOO_JWT_SECRET", "x"), ("NOO_ENTITLEMENT", "y")];
        let mixed = at_rest_check(&state("sops", true, &env)
            .with_store_split_from(&|| Ok(["NOO_JWT_SECRET".to_string()].into_iter().collect())));
        assert!(mixed.detail.contains("1 live ONLY in .env, the store has no copy (do not blank them; the remedy carries them in first): NOO_ENTITLEMENT"), "{}", mixed.detail);
        assert!(mixed.detail.contains("1 also in secrets/env.sops (a stale plaintext copy): NOO_JWT_SECRET"), "{}", mixed.detail);
        assert_eq!(mixed.remedy.as_deref(), Some(REMEDY));

        let all_stored = at_rest_check(&state("sops", true, &env).with_store_split_from(&|| {
            Ok(["NOO_JWT_SECRET".to_string(), "NOO_ENTITLEMENT".to_string()].into_iter().collect())
        }));
        assert!(!all_stored.detail.contains("ONLY"), "{}", all_stored.detail);
        assert_eq!(all_stored.remedy.as_deref(), Some(REMEDY_TIDY));

        let unread = at_rest_check(&state("sops", true, &env).with_store_split_from(&|| Err("no age key".into())));
        assert!(unread.detail.contains("NOT checked") && !unread.detail.contains("also in secrets/env.sops"), "{}", unread.detail);
        assert_eq!(unread.remedy.as_deref(), Some(REMEDY), "never tidy alone on an unread store");
    }

    #[test]
    fn the_row_fails_on_the_retired_env_backend_even_with_nothing_in_env() {
        let c = at_rest_check(&state("env", false, &[("NODE_ID", "x")]));
        assert_eq!(c.verdict, Verdict::Fail);
        assert!(c.detail.contains("retired"), "{}", c.detail);
        let c = at_rest_check(&state("", false, &[]));
        assert_eq!(c.verdict, Verdict::Fail);
        let c = at_rest_check(&state("sops", false, &[]));
        assert_eq!(c.verdict, Verdict::Fail, "sops declared but no store");
    }

    #[test]
    fn only_a_value_the_store_holds_is_blanked() {
        let plain = vec!["NOO_JWT_SECRET".to_string(), "TAVILY_API_KEY".to_string()];
        let got = split_by_store(&plain, &|k| k == "NOO_JWT_SECRET");
        assert_eq!(got.blanked, vec!["NOO_JWT_SECRET".to_string()]);
        assert_eq!(got.only_in_env, vec!["TAVILY_API_KEY".to_string()]);
    }

    /// With the env backend `.env` is the live copy: tidy refuses and writes
    /// nothing, naming the onboard remedy.
    #[test]
    fn tidy_refuses_to_blank_a_plaintext_install_and_writes_nothing() {
        let root = std::env::temp_dir().join(format!("noo-plaintext-env-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&root);
        std::fs::create_dir_all(&root).unwrap();
        let before = "NOO_SECRETS_BACKEND=env\nNOO_JWT_SECRET=SENTINEL-plain\n";
        std::fs::write(root.join(".env"), before).unwrap();
        let out = blank_stored(&root);
        let after = std::fs::read_to_string(root.join(".env")).unwrap();
        let _ = std::fs::remove_dir_all(&root);
        let e = out.expect_err("a plaintext install is refused");
        assert!(e.contains(REMEDY_ONBOARD), "{e}");
        assert!(!e.contains("SENTINEL"), "{e}");
        assert_eq!(after, before);
    }

    /// An install still on plaintext `.env`, read from disk: the upgrade and
    /// verify criterion fires; the same install with the value blanked and the
    /// store armed does not.
    #[test]
    fn a_plaintext_install_on_disk_is_a_controller_problem() {
        let root = std::env::temp_dir().join(format!("noo-plaintext-read-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&root);
        std::fs::create_dir_all(root.join("secrets")).unwrap();
        std::fs::write(root.join(".env"), "NOO_SECRETS_BACKEND=env\nPOSTGRES_PASSWORD=SENTINEL-pg\nNODE_ID=x\n").unwrap();
        let plain = AtRest::read(&root);
        std::fs::write(root.join(".env"), "NOO_SECRETS_BACKEND=sops\nPOSTGRES_PASSWORD=\nNODE_ID=x\n").unwrap();
        std::fs::write(root.join("secrets/env.sops"), "ciphertext").unwrap();
        let sealed = AtRest::read(&root);
        let _ = std::fs::remove_dir_all(&root);
        if std::env::var("NOO_SECRETS_BACKEND").is_ok() {
            return; // the process env overrides .env, as the launcher's does
        }
        let why = plain.controller_problem().expect("plaintext install is refused");
        assert!(why.contains("POSTGRES_PASSWORD") && !why.contains("SENTINEL"), "{why}");
        assert_eq!(sealed.controller_problem(), None, "{sealed:?}");
    }

    /// `upgrade --stack` refuses a plaintext install BEFORE anything in the
    /// roll moves: the slice refresh, the pin, the launcher.
    #[test]
    fn upgrade_refuses_a_plaintext_install_before_anything_moves() {
        use crate::commands::upgrade::phase_src;
        let list = phase_src::list();
        let at = |needle: &str| list.find(needle).unwrap_or_else(|| panic!("{needle} not in the phase list"));
        let refuse = at("refuse_plaintext_install(");
        for later in ["migrate_retired_yaml_gates(", "refresh_deploy_slice(", "launch_stack("] {
            assert!(refuse < at(later), "the plaintext refusal must come before `{later}`");
        }
        assert!(phase_src::body("refuse_plaintext_install").contains("plaintext_env::AtRest::read(root).controller_problem()"),
            "the refusal phase asks the at-rest reader");
    }

    /// Both commands in the remedy are real verbs (the hint lint checks the
    /// literal too; this pins it inside the crate).
    #[test]
    fn the_remedy_names_real_verbs() {
        let verbs: Vec<String> = crate::usage::USAGE.iter().map(|(p, _, _)| p.join(" ")).collect();
        assert_eq!(REMEDY_TIDY, "noo security secrets tidy");
        for v in ["onboard", "security secrets tidy"] {
            assert!(verbs.iter().any(|x| x == v), "{v} is not a CLI verb");
        }
        assert!(REMEDY.starts_with(REMEDY_ONBOARD));
    }

    /// host8's `.env` as of 2026-09-30: these exact keys hold a value, every
    /// secret is in the store. The launcher must start it — a refusal here
    /// would take the live controller down at its next restart.
    const HOST8_ENV_KEYS: &[&str] = &[
        "CLUSTER_MODE", "EMBEDDING_DIM", "GPU_MODEL", "LLAMACPP_MODEL", "NATS_GATEWAY_USER",
        "NATS_URL", "NATS_USER", "NATS_WORKER_USER", "N_CTX", "N_GPU_LAYERS", "NODE_ID", "NODE_IP",
        "NODE_TIER", "NOO_ADMIN_USER", "NOO_BASE_REGISTRY", "NOO_BIND_MODE", "NOO_DATA_ROOT",
        "NOO_DEFAULT_PROFILE", "NOO_IMAGE_PREFIX", "NOO_IMAGE_TAG", "NOO_INSTALL_MODE",
        "NOO_LOKI_TLS", "NOO_MODEL_ORIGINS", "NOO_MTLS_GATEWAY", "NOO_MTLS_NODES",
        "NOO_NATS_CONFIG", "NOO_NATS_TLS", "NOO_PG_DATA", "NOO_PG_SSLMODE", "NOO_PG_TLS",
        "NOO_PKI_DIR", "NOO_REDIS_TLS", "NOO_SECRETS_BACKEND", "NOO_TLS_CA", "NOO_TLS_CERT",
        "NOO_VLLM_TLS", "N_THREADS", "OLLAMA_MODEL", "OLLAMA_URL", "PAGEINDEX_EMBEDDING_BACKEND",
        "PAGEINDEX_EMBEDDING_MODEL", "PAGEINDEX_EMBEDDING_URL", "PAGEINDEX_LLM_URL", "REDIS_URL",
        "TELEGRAM_ALLOWED_USERS", "VRAM_GB",
    ];

    fn host8_env() -> Vec<(String, String)> {
        HOST8_ENV_KEYS
            .iter()
            .map(|k| (k.to_string(), if *k == "NOO_SECRETS_BACKEND" { "sops".into() } else { format!("value-of-{k}") }))
            .collect()
    }

    #[test]
    fn the_launcher_starts_host8() {
        assert_eq!(HOST8_ENV_KEYS.len(), 46, "the key set is host8's, exactly");
        let pairs = host8_env();
        assert_eq!(plaintext_secret_keys(&pairs), Vec::<String>::new(), "no host8 key is secret-class");
        let st = AtRest { env_present: true, backend: "sops".into(), store_present: true, store_path: Default::default(), plaintext: plaintext_secret_keys(&pairs), store_split: None };
        assert_eq!(launch_refusal(&st), None);
    }

    #[test]
    fn the_launcher_refuses_a_planted_secret_naming_it_and_the_remedy() {
        let mut pairs = host8_env();
        pairs.push(("NOO_JWT_SECRET".into(), "SENTINEL-planted".into()));
        let st = AtRest { env_present: true, backend: "sops".into(), store_present: true, store_path: Default::default(), plaintext: plaintext_secret_keys(&pairs), store_split: None };
        let msg = launch_refusal(&st).expect("a planted secret is refused");
        assert!(msg.contains("NOO_JWT_SECRET"), "{msg}");
        assert!(!msg.contains("SENTINEL"), "never a value: {msg}");
        assert!(msg.contains(REMEDY), "{msg}");
    }

    #[test]
    fn the_launcher_refuses_a_non_sops_backend() {
        for backend in ["env", "", "vault"] {
            let st = AtRest { env_present: true, backend: backend.into(), store_present: false, store_path: Default::default(), plaintext: vec![], store_split: None };
            let msg = launch_refusal(&st).unwrap_or_else(|| panic!("backend `{backend}` is refused"));
            assert!(msg.contains("NOO_SECRETS_BACKEND") && msg.contains(REMEDY), "{msg}");
        }
    }

    /// The verb end to end on disk: host8's key set exits 0, a planted
    /// secret exits LAUNCH_REFUSED.
    #[test]
    fn launch_check_reads_the_install_root_it_is_given() {
        if std::env::var("NOO_SECRETS_BACKEND").is_ok() {
            return; // the process env overrides .env, as the launcher's does
        }
        let root = std::env::temp_dir().join(format!("noo-launch-check-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&root);
        std::fs::create_dir_all(root.join("secrets")).unwrap();
        std::fs::write(root.join("secrets/env.sops"), "ciphertext").unwrap();
        let body: String = host8_env().iter().map(|(k, v)| format!("{k}={v}\n")).collect();
        std::fs::write(root.join(".env"), &body).unwrap();
        let arg = vec![root.to_string_lossy().into_owned()];
        let clean = launch_check(&arg);
        std::fs::write(root.join(".env"), format!("{body}POSTGRES_PASSWORD=SENTINEL-pg\n")).unwrap();
        let planted = launch_check(&arg);
        std::fs::write(root.join(".env"), body.replace("NOO_SECRETS_BACKEND=sops", "NOO_SECRETS_BACKEND=env")).unwrap();
        let env_backend = launch_check(&arg);
        let _ = std::fs::remove_dir_all(&root);
        assert_eq!((clean, planted, env_backend), (0, LAUNCH_REFUSED, LAUNCH_REFUSED));
    }
}
