// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 PersonifAI LLC

//! `noo security secrets remove <KEY>...` — take a stale key out of the sops
//! store, and refuse anything something still reads.
//!
//! Why this exists: `secrets audit` reports `node-password-unused` and says
//! "remove the key from the store", and the CLI had no verb that did — the
//! advice dead-ended in editing a sops file by hand, the one operation on
//! this store whose documented failure mode is a full replace that drops
//! every other credential.
//!
//! **The refusal is the feature.** A credential deleted while something
//! still reads it fails later, as a 401, at the next restart, nowhere near
//! the command that caused it. So each key is judged before anything is
//! touched, by [`judge_key`] (pure, tested), against every reader this
//! install can name:
//!
//!   1. the rotation registry (`CORE_REGISTRY` + add-on `x-noo-addon` keys);
//!   2. a RUNNING compose container holding it (`KEY` or `KEY_FILE` in its
//!      environment — the `secrets not in env` holder resolution);
//!   3. a compose file in the repo root that names it (declared, not
//!      necessarily running);
//!   4. `noomesh.yaml`;
//!   5. `monitoring/nats/users.conf`, and for a `NATS_NODE_PASSWORD_*` key the
//!      principals it authorises. A node password is removable ONLY when
//!      users.conf has principals and none of them maps to the key — an
//!      unreadable file proves nothing, so it refuses.
//!
//! What remains is removable, and the plan says why for every key. Any
//! refusal aborts the whole run: nothing is changed.
//!
//! The write is the store's one writer (`secrets::remove_keys`: in-memory
//! decrypt, verified re-encrypt, timestamped encrypted `.bak_<ts>`, atomic
//! rename). No restart: nothing reads an unused key. The audit line records
//! the key NAME only.

use std::collections::BTreeSet;
use std::path::{Path, PathBuf};

use crate::commands::secrets::{self, SecretStore};
use crate::commands::secrets_delivery::Holder;
use crate::output::{fail, ExitCode};
use crate::ui;
use crate::{envfile, Globals, Unhandled};

/// Everything the judgement reads, gathered by the caller so
/// [`judge_key`] stays pure.
pub(crate) struct Evidence<'a> {
    /// Key names in the store (names only).
    pub store_keys: &'a BTreeSet<String>,
    /// Running containers and their env var NAMES.
    pub holders: &'a [Holder],
    /// `(file name, text)` of the root `docker-compose*.yml` files.
    pub compose: &'a [(String, String)],
    pub noomesh_yaml: Option<&'a str>,
    pub users_conf: Option<&'a str>,
}

#[derive(Clone, Debug, PartialEq)]
pub(crate) enum Verdict {
    Removable(String),
    Refused(String),
}

/// Does `text` name `key` as a whole identifier (or its `_FILE` pointer)?
/// `NATS_NODE_PASSWORD_EDGE` must not match inside `..._EDGE_A`.
pub(crate) fn names_key(text: &str, key: &str) -> bool {
    let ident = |c: char| c.is_ascii_alphanumeric() || c == '_';
    let found = |needle: &str| {
        text.match_indices(needle).any(|(i, _)| {
            let before = text[..i].chars().next_back();
            let after = text[i + needle.len()..].chars().next();
            !before.is_some_and(ident) && !after.is_some_and(ident)
        })
    };
    found(key) || found(&format!("{key}_FILE"))
}

pub(crate) fn judge_key(key: &str, ev: &Evidence<'_>) -> Verdict {
    use Verdict::{Refused, Removable};
    if !ev.store_keys.contains(key) {
        return Refused("not in the store — nothing to remove".into());
    }
    if let Some(spec) = secrets::spec_for(key) {
        return Refused(format!(
            "a registered {} secret, consumed by {} — removing it breaks them. \
             `noo security secrets rotate {key}` replaces the value instead",
            spec.class.label(),
            spec.consumers.join(", ")
        ));
    }
    if let Some(d) = secrets::addon_decl(key) {
        return Refused(format!("the `{}` add-on's service key (x-noo-addon in {})", d.addon, d.overlay));
    }
    for h in ev.holders {
        if h.env_names.iter().any(|n| n == key || n.strip_suffix("_FILE") == Some(key)) {
            return Refused(format!("running container {} (service {}) holds it", h.container, h.service));
        }
    }
    for (name, text) in ev.compose {
        if names_key(text, key) {
            return Refused(format!("{name} declares it"));
        }
    }
    if ev.noomesh_yaml.is_some_and(|t| names_key(t, key)) {
        return Refused("noomesh.yaml references it".into());
    }
    if ev.users_conf.is_some_and(|t| names_key(t, key)) {
        return Refused(format!("{} references it", crate::commands::nats_users::USERS_CONF));
    }
    if key.starts_with("NATS_NODE_PASSWORD_") {
        let principals = ev
            .users_conf
            .map(crate::commands::nats_users::node_users_in_conf)
            .unwrap_or_default();
        if principals.is_empty() {
            return Refused(format!(
                "cannot prove it unused: {} is unreadable or lists no node principals, and \
                 \"no principals read\" is not \"no such node\"",
                crate::commands::nats_users::USERS_CONF
            ));
        }
        if let Some(id) = principals
            .iter()
            .find(|id| crate::commands::nats_users::node_secret_key(id) == key)
        {
            return Refused(format!("the bus authorises node `{id}` with it"));
        }
        return Removable(format!(
            "node-password-unused: no principal in {} maps to it (the bus authorises {})",
            crate::commands::nats_users::USERS_CONF,
            principals.join(", ")
        ));
    }
    if let Some(why) = secrets::retired_store_key(key) {
        return Removable(format!("retired — {why}"));
    }
    Removable(
        "unknown to every reader: not in the rotation registry, no add-on declares it, no \
         running container or compose file reads it, and noomesh.yaml and users.conf do not \
         name it"
            .into(),
    )
}

/// The plan, as text. Pure. Names and reasons only.
pub(crate) fn render_plan(plan: &[(String, Verdict)], dry_run: bool, store: &Path) -> String {
    let mut s = format!(
        "{} — {}\n",
        if dry_run { "Plan (dry run, nothing changed)" } else { "Plan" },
        store.display()
    );
    for (k, v) in plan {
        match v {
            Verdict::Removable(why) => s.push_str(&format!("  REMOVE   {k} — {why}\n")),
            Verdict::Refused(why) => s.push_str(&format!("  REFUSED  {k} — {why}\n")),
        }
    }
    s
}

fn read_compose(root: &Path) -> Vec<(String, String)> {
    let mut out = Vec::new();
    if let Ok(rd) = std::fs::read_dir(root) {
        for e in rd.flatten() {
            let name = e.file_name().to_string_lossy().into_owned();
            if name.starts_with("docker-compose") && (name.ends_with(".yml") || name.ends_with(".yaml")) {
                if let Ok(t) = std::fs::read_to_string(e.path()) {
                    out.push((name, t));
                }
            }
        }
    }
    out.sort();
    out
}

/// `noo security secrets remove <KEY>... [--yes] [--dry-run] [--sops-file <path>]`
pub fn secrets_remove(g: &Globals, args: &[String]) -> Result<i32, Unhandled> {
    let mut keys: Vec<String> = Vec::new();
    let mut dry_run = false;
    let mut yes = false;
    let mut sops_path: Option<PathBuf> = None;
    let mut iter = args.iter();
    while let Some(tok) = iter.next() {
        match tok.as_str() {
            "--dry-run" | "-n" => dry_run = true,
            "--yes" | "-y" => yes = true,
            "--sops-file" => sops_path = Some(PathBuf::from(iter.next().ok_or(Unhandled)?)),
            t if t.starts_with('-') => return Err(Unhandled),
            t => {
                if !keys.iter().any(|k| k == t) {
                    keys.push(t.to_string());
                }
            }
        }
    }
    if keys.is_empty() {
        fail(
            g.json,
            ExitCode::Usage,
            "no_keys",
            "no keys given",
            Some("pass one or more KEY names; `noo security secrets audit` lists the store and flags the unused ones"),
        );
    }
    let root = envfile::repo_root();
    let sops_path = sops_path.unwrap_or_else(|| root.join("secrets/env.sops"));
    let store = match SecretStore::load_sops(&sops_path) {
        Ok(s) => s,
        Err(e) => fail(
            g.json,
            ExitCode::Generic,
            "sops_decrypt_failed",
            &e,
            Some("removal decrypts in memory only; nothing was changed"),
        ),
    };
    let store_keys: BTreeSet<String> = store.keys().cloned().collect();
    let project = std::env::var("NOO_VERIFY_COMPOSE_PROJECT")
        .ok()
        .filter(|p| !p.is_empty())
        .or_else(super::secrets_delivery::stack_project);
    let holders = project.as_deref().map(super::secrets_delivery::holders_in).unwrap_or_default();
    let compose = read_compose(&root);
    let noomesh_yaml = std::fs::read_to_string(root.join("noomesh.yaml")).ok();
    let users_conf = std::fs::read_to_string(root.join(super::nats_users::USERS_CONF)).ok();
    let ev = Evidence {
        store_keys: &store_keys,
        holders: &holders,
        compose: &compose,
        noomesh_yaml: noomesh_yaml.as_deref(),
        users_conf: users_conf.as_deref(),
    };
    let plan: Vec<(String, Verdict)> = keys.iter().map(|k| (k.clone(), judge_key(k, &ev))).collect();
    let refused = plan.iter().filter(|(_, v)| matches!(v, Verdict::Refused(_))).count();

    if g.json {
        println!(
            "{}",
            serde_json::json!({
                "dry_run": dry_run,
                "store": sops_path.display().to_string(),
                "refused": refused,
                "items": plan.iter().map(|(k, v)| match v {
                    Verdict::Removable(w) => serde_json::json!({"key": k, "verdict": "remove", "why": w}),
                    Verdict::Refused(w) => serde_json::json!({"key": k, "verdict": "refused", "why": w}),
                }).collect::<Vec<_>>(),
            })
        );
    } else {
        print!("{}", render_plan(&plan, dry_run, &sops_path));
    }
    if refused > 0 {
        if !g.json {
            eprintln!(
                "{}",
                ui::warn(&format!("{refused} key(s) refused — nothing was changed. Fix or drop them from the command and re-run."))
            );
        }
        return Ok(1);
    }
    if dry_run {
        return Ok(0);
    }

    super::confirm_destructive(
        g,
        yes,
        "Remove",
        &format!("{} key(s) from {}: {}", keys.len(), sops_path.display(), keys.join(", ")),
    );
    let backup = match secrets::remove_keys(&keys, &sops_path) {
        Ok(b) => b,
        Err(e) => fail(g.json, ExitCode::Generic, "remove_failed", &e, Some("the previous store is intact")),
    };
    // Names only. Best-effort, like the reveal log: the removal is done.
    let when = super::secrets_reveal::now_rfc3339();
    let who = super::secrets_reveal::whoami();
    for k in &keys {
        let line = format!("{when} secret_removed name={k} by={who}");
        if let Err(e) = super::secrets_reveal::write_audit(&root, &line) {
            eprintln!("{}", ui::note(&format!("could not append secret_removed for {k} to the audit log: {e}")));
        }
    }
    if !g.json {
        ui::done(&format!("{} key(s) removed from the store: {}", keys.len(), keys.join(", ")));
        println!("{}", ui::muted(&format!("previous store (encrypted): {}", backup.display())));
        println!("{}", ui::muted("no restart needed — nothing reads an unused key"));
    }
    Ok(0)
}

#[cfg(test)]
mod tests {
    use super::super::nats_users::{render_users_conf, Principal, Role};
    use super::*;

    fn conf() -> String {
        render_users_conf(&[
            Principal { user: "gateway".into(), hash: "$2b$11$g".into(), role: Role::Gateway },
            Principal { user: "node-edge-a".into(), hash: "$2b$11$a".into(), role: Role::Node },
        ])
    }

    fn keys(ks: &[&str]) -> BTreeSet<String> {
        ks.iter().map(|k| k.to_string()).collect()
    }

    fn holder(env: &[&str]) -> Holder {
        Holder {
            container: "noo-gateway".into(),
            service: "gateway".into(),
            env_names: env.iter().map(|s| s.to_string()).collect(),
        }
    }

    fn judge(key: &str, ev: &Evidence<'_>) -> Verdict {
        judge_key(key, ev)
    }

    #[test]
    fn the_orphan_is_removable_and_the_real_node_key_is_not() {
        let store = keys(&["NATS_NODE_PASSWORD_EDGEA", "NATS_NODE_PASSWORD_EDGE_A"]);
        let c = conf();
        let ev = Evidence { store_keys: &store, holders: &[], compose: &[], noomesh_yaml: None, users_conf: Some(&c) };
        match judge("NATS_NODE_PASSWORD_EDGEA", &ev) {
            Verdict::Removable(w) => assert!(w.contains("node-password-unused"), "{w}"),
            v => panic!("the leftover spelling must be removable: {v:?}"),
        }
        match judge("NATS_NODE_PASSWORD_EDGE_A", &ev) {
            Verdict::Refused(w) => assert!(w.contains("`edge-a`"), "{w}"),
            v => panic!("the live node's password must be refused: {v:?}"),
        }
    }

    #[test]
    fn an_unreadable_users_conf_proves_nothing() {
        let store = keys(&["NATS_NODE_PASSWORD_EDGEA"]);
        for c in [None, Some(""), Some("authorization { users = [] }")] {
            let ev = Evidence { store_keys: &store, holders: &[], compose: &[], noomesh_yaml: None, users_conf: c };
            assert!(matches!(judge("NATS_NODE_PASSWORD_EDGEA", &ev), Verdict::Refused(_)), "{c:?}");
        }
    }

    #[test]
    fn registry_keys_are_refused() {
        let store = keys(&["NOO_JWT_SECRET", "POSTGRES_PASSWORD"]);
        let ev = Evidence { store_keys: &store, holders: &[], compose: &[], noomesh_yaml: None, users_conf: None };
        for k in ["NOO_JWT_SECRET", "POSTGRES_PASSWORD"] {
            assert!(matches!(judge(k, &ev), Verdict::Refused(_)), "{k}");
        }
    }

    #[test]
    fn every_reader_blocks_an_otherwise_unknown_key() {
        let store = keys(&["ZZ_OLD_TOKEN"]);
        let none = Evidence { store_keys: &store, holders: &[], compose: &[], noomesh_yaml: None, users_conf: None };
        assert!(matches!(judge("ZZ_OLD_TOKEN", &none), Verdict::Removable(_)));

        let h = [holder(&["ZZ_OLD_TOKEN_FILE"])];
        let ev = Evidence { holders: &h, ..none_clone(&none) };
        assert!(matches!(judge("ZZ_OLD_TOKEN", &ev), Verdict::Refused(w) if w.contains("noo-gateway")));

        let compose = [("docker-compose.yml".to_string(), "environment:\n  X: ${ZZ_OLD_TOKEN}\n".to_string())];
        let ev = Evidence { compose: &compose, ..none_clone(&none) };
        assert!(matches!(judge("ZZ_OLD_TOKEN", &ev), Verdict::Refused(w) if w.contains("docker-compose.yml")));

        let ev = Evidence { noomesh_yaml: Some("x: ZZ_OLD_TOKEN\n"), ..none_clone(&none) };
        assert!(matches!(judge("ZZ_OLD_TOKEN", &ev), Verdict::Refused(w) if w.contains("noomesh.yaml")));
    }

    fn none_clone<'a>(e: &Evidence<'a>) -> Evidence<'a> {
        Evidence { store_keys: e.store_keys, holders: e.holders, compose: e.compose, noomesh_yaml: e.noomesh_yaml, users_conf: e.users_conf }
    }

    #[test]
    fn a_key_absent_from_the_store_is_refused() {
        let store = keys(&[]);
        let ev = Evidence { store_keys: &store, holders: &[], compose: &[], noomesh_yaml: None, users_conf: None };
        assert!(matches!(judge("ZZ_NOPE", &ev), Verdict::Refused(_)));
    }

    #[test]
    fn a_prefix_is_not_a_mention() {
        assert!(!names_key("NATS_NODE_PASSWORD_EDGE_A", "NATS_NODE_PASSWORD_EDGE"));
        assert!(names_key("a: ${NATS_NODE_PASSWORD_EDGE}", "NATS_NODE_PASSWORD_EDGE"));
        assert!(names_key("a: NATS_NODE_PASSWORD_EDGE_FILE", "NATS_NODE_PASSWORD_EDGE"));
    }

    #[test]
    fn the_unused_finding_points_at_remove_and_that_verb_exists() {
        let cmd = "noo security secrets remove NATS_NODE_PASSWORD_EDGEA";
        let f = super::super::secrets::orphaned_node_password_findings_for_test(&["NATS_NODE_PASSWORD_EDGEA"], &conf());
        assert_eq!(f.len(), 1);
        assert!(f[0].message.contains(cmd), "{}", f[0].message);
        assert!(crate::usage::USAGE.iter().any(|(p, _, _)| p.join(" ") == "security secrets remove"));
    }

    #[test]
    fn the_plan_names_every_key_and_why() {
        let plan = vec![
            ("A".to_string(), Verdict::Removable("because".into())),
            ("B".to_string(), Verdict::Refused("held".into())),
        ];
        let s = render_plan(&plan, true, Path::new("/f/env.sops"));
        assert!(s.contains("dry run") && s.contains("REMOVE   A — because") && s.contains("REFUSED  B — held"), "{s}");
    }
}
