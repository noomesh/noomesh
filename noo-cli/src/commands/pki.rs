// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 PersonifAI LLC

//! `noo security pki …` — cluster certificate operations, fully local (no
//! gateway). Ports the Python surface in `noomesh/security_cli.py`:
//! init, status, issue (node), issue-service, issue-gateway, rotate; plus
//! `fix-modes` (private-key modes by reader, `pki::KeyReader`).
//! `rotate-all` (rotation + docker restarts + health probe + auto-revert)
//! lives in `commands/security.rs` with the rest of the WP-B1 surface.
//!
//! Profile-fidelity notes live in `src/pki.rs`; the compat proof against
//! Python-issued certs is documented in NOO_CLI.md.

use crate::output::{fail, ExitCode};
use crate::pki::{pki_dir, ClusterCa, DEFAULT_DAYS};
use crate::ui::{self, Col, Glyph};
use crate::{Globals, Unhandled};

fn ca() -> ClusterCa {
    ClusterCa::new(pki_dir())
}

fn fail_pki(g: &Globals, msg: &str) -> ! {
    let hint = if msg.contains("No cluster CA") {
        Some("run 'noo security pki init' first")
    } else {
        None
    };
    fail(g.json, ExitCode::Generic, "pki_error", msg, hint)
}

/// `noo security pki init` — generate the cluster CA (refuses to overwrite).
pub fn pki_init(g: &Globals, args: &[String]) -> Result<i32, Unhandled> {
    if !args.is_empty() {
        return Err(Unhandled);
    }
    let ca = ca();
    if ca.ca_cert_path().exists() {
        // Python prints a warning and exits 0 — keep that contract.
        if g.json {
            println!(
                "{}",
                serde_json::json!({
                    "status": "already_exists",
                    "ca_cert": ca.ca_cert_path().to_string_lossy(),
                })
            );
        } else {
            ui::warned(&format!("CA already exists at {}: not overwriting", ca.ca_cert_path().display()));
        }
        return Ok(0);
    }
    match ca.generate_ca("Mesh Cluster CA", 3650) {
        Ok((crt, key)) => {
            if g.json {
                println!(
                    "{}",
                    serde_json::json!({
                        "status": "created",
                        "ca_cert": crt.to_string_lossy(),
                        "ca_key": key.to_string_lossy(),
                    })
                );
            } else {
                ui::done(&format!("cluster CA created at {}", crt.display()));
                ui::guide(&[
                    ("noo security pki issue-gateway [<hostname>] [<ip>]", "the gateway's TLS cert, signed by this CA (defaults are fine)"),
                    ("noo security pki issue-node <node> [<ip>]", "a node-agent cert per worker"),
                    ("noo security trust-ca", "puts the CA in this machine's OS trust store so browsers accept the dashboard"),
                    ("noo security pki status", "lists every cert and its expiry"),
                ]);
            }
            Ok(0)
        }
        Err(e) => fail_pki(g, &e),
    }
}

/// `noo security pki status` — list every cert under the PKI dir with expiry.
pub fn pki_status(g: &Globals, args: &[String]) -> Result<i32, Unhandled> {
    if !args.is_empty() {
        return Err(Unhandled);
    }
    let ca = ca();
    let certs = ca.list_certs();
    if g.json {
        let items: Vec<serde_json::Value> = certs
            .iter()
            .map(|c| {
                serde_json::json!({
                    "name": c.name,
                    "path": c.path.to_string_lossy(),
                    "role": c.role,
                    "expires": c.expires,
                    "days_left": c.days_left,
                    "status": status_word(c.days_left),
                })
            })
            .collect();
        println!(
            "{}",
            serde_json::json!({ "pki_dir": ca.dir.to_string_lossy(), "certs": items })
        );
        return Ok(0);
    }
    if certs.is_empty() {
        println!("{}", ui::muted("no certificates"));
        ui::guide(&[("noo security pki init", "creates the cluster CA and the controller's gateway certificate")]);
        return Ok(0);
    }
    println!("{}", ui::header("pki", Some(&ca.dir.display().to_string())));
    println!("{}", ui::section("certificates"));
    let rows: Vec<Vec<String>> = certs
        .iter()
        .map(|c| {
            let (glyph, word) = match status_word(c.days_left) {
                "OK" => (Glyph::Ok, ui::state("ok")),
                "EXPIRED" => (Glyph::Err, ui::err("expired")),
                _ => (Glyph::Warn, ui::warn("expiring soon")),
            };
            vec![ui::glyph_cell(glyph), c.name.clone(), c.expires.clone(), c.days_left.to_string(), word]
        })
        .collect();
    print!(
        "{}",
        ui::table(
            &[Col::left(""), Col::left("name"), Col::left("expires"), Col::right("days left"), Col::left("status")],
            &rows,
        )
    );
    print_signing_adoption(&ca);
    Ok(0)
}

/// The fleet signing key and WHICH nodes have adopted it.
///
/// This is the fleet view of the thing that decides how a node verifies the
/// code it is about to install. Adoption used to be readable only as a side
/// effect of re-running `rotate-signing-key`, or by listing marker files by
/// hand — and the node most likely to be missing was the one nobody thought to
/// check, the controller's own (host8 held no key at all on 2026-09-12,
/// because the roll filtered the local hostname out of its targets).
///
/// A node WITHOUT the key takes only CA-signed ROLLOVER bundles (the
/// CA-signed apply lane is retired), so this section names it
/// as work rather than listing it as a state.
fn print_signing_adoption(ca: &crate::pki::ClusterCa) {
    let pub_path = ca.signing_pub_path();
    let Ok(pem) = std::fs::read(&pub_path) else {
        return;
    };
    let fp = super::security_local::signing_pub_fingerprint(&pem);
    let nodes_dir = ca.dir.join("nodes");
    let mut adopted: Vec<String> = Vec::new();
    let mut pending: Vec<String> = Vec::new();
    if let Ok(rd) = std::fs::read_dir(&nodes_dir) {
        for e in rd.filter_map(Result::ok).filter(|e| e.path().is_dir()) {
            let name = e.file_name().to_string_lossy().to_string();
            if e.path().join("signing-adopted").is_file() {
                adopted.push(name);
            } else {
                pending.push(name);
            }
        }
    }
    adopted.sort();
    pending.sort();
    println!("{}", ui::section("fleet signing key"));
    println!("{}", ui::kv(&[
        ("fingerprint", format!("sha256:{}", &fp[..16])),
        ("public key", pub_path.display().to_string()),
        ("adopted", if adopted.is_empty() { ui::muted("none") } else { adopted.join(", ") }),
    ]));
    if !pending.is_empty() {
        println!("  {}", ui::warn(&format!(
            "not adopted: {} — the CA-signed apply lane is retired, so these take only a signing-key rollover",
            pending.join(", ")
        )));
        println!("  {}", ui::muted("noo cluster provision <node> --wait   (the CA-signed bundle carries signing-pub; the node adopts on apply)"));
    }
}

/// The `--json` status word (unchanged contract); the human table maps it
/// onto the guide's state vocabulary.
fn status_word(days_left: i64) -> &'static str {
    if days_left < 0 {
        "EXPIRED"
    } else if days_left < 30 {
        "EXPIRING SOON"
    } else {
        "OK"
    }
}

/// `noo security pki issue NODE_ID IP [--days N] [--san S]…` — node cert.
pub fn pki_issue(g: &Globals, args: &[String]) -> Result<i32, Unhandled> {
    let (pos, days, sans) = parse_issue_args(args, &["--san"])?;
    let [node_id, ip] = pos.as_slice() else { return Err(Unhandled) };
    // #79: fold the node's tailnet IP into the SANs — the address its
    // agent registers and the gateway's watchdog loops dial.
    // i11a: the controller's own node also gets the controller names, so
    // this verb can no longer be the one that drops them.
    let role = crate::pki::NodeRole::of(node_id);
    let ts_ip: Vec<String> = role.tailnet_ip4(node_id).into_iter().collect();
    match ca().issue_node_cert(node_id, ip, days, &sans, &ts_ip, &role) {
        Ok((crt, key)) => emit_pair(g, "Node", &crt, &key),
        Err(e) => fail_pki(g, &e),
    }
}

/// `noo security pki issue-service SERVICE [--san S]… [--days N]`.
pub fn pki_issue_service(g: &Globals, args: &[String]) -> Result<i32, Unhandled> {
    let (pos, days, sans) = parse_issue_args(args, &["--san"])?;
    let [service] = pos.as_slice() else { return Err(Unhandled) };
    let ca = ca();
    let svc_dir = ca.dir.join("services").join(service);
    // The bare verb is the right one: start from the names
    // onboarding and `upgrade --stack` derive for this service on this box,
    // and add `--san` on top.
    let (hostname, node_ip, ts_dnsname) = crate::onboard::steps::local_cert_identity();
    let (names, ips) = issue_service_names(service, &sans, &hostname, &node_ip, &ts_dnsname);
    match ca.issue_service_cert(service, &names, &ips, days) {
        Ok((crt, key)) => emit_pair(g, "Service", &crt, &key),
        Err(e) => {
            // `noo cluster verify` names this exact verb as the remedy for a
            // release's new mounted service cert — but on an upgraded
            // install Docker has already created `services/<svc>` as root
            // (the bind-mount source, before the cert existed), and the
            // remedy it just recommended then fails the same way it is
            // meant to fix (newcomer-upgrade rehearsal, 2026-09-29). Say
            // whose directory it is and what to run, instead of the bare
            // "Permission denied" that sent the last operator to `sudo
            // chown` by trial and error.
            if let Some(hint) = permission_denied_hint(&e, &svc_dir) {
                fail(g.json, ExitCode::Generic, "pki_error", &e, Some(&hint));
            }
            fail_pki(g, &e)
        }
    }
}

/// The SAN set `issue-service` issues: the derived set
/// (`onboard::steps::service_cert_sans`) with the operator's `--san` values
/// added on top, an IP literal going to the IP pool. Pure.
pub(crate) fn issue_service_names(
    service: &str,
    sans: &[String],
    hostname: &str,
    node_ip: &str,
    ts_dnsname: &str,
) -> (Vec<String>, Vec<String>) {
    let (mut names, mut ips) = crate::onboard::steps::service_cert_sans(service, hostname, node_ip, ts_dnsname);
    for s in sans {
        let pool = if s.parse::<std::net::IpAddr>().is_ok() { &mut ips } else { &mut names };
        if !pool.contains(s) {
            pool.push(s.clone());
        }
    }
    (names, ips)
}

/// When issuing failed with a permission error AND the leaf's directory
/// already exists but isn't owned by this user, that ownership is the
/// actionable fact — everything else about the error is noise. `None`
/// covers both "not a permission error" and "no such directory" (a plain
/// mkdir failure elsewhere), where the generic message already says enough.
pub(crate) fn permission_denied_hint(err: &str, dir: &std::path::Path) -> Option<String> {
    if !err.to_lowercase().contains("permission denied") {
        return None;
    }
    let meta = std::fs::metadata(dir).ok()?;
    use std::os::unix::fs::MetadataExt as _;
    let owner_uid = meta.uid();
    if owner_uid == unsafe { libc::getuid() } {
        return None;
    }
    Some(permission_denied_message(&dir.display().to_string(), owner_uid))
}

/// Pure message builder, unit-tested without touching the filesystem.
fn permission_denied_message(dir_display: &str, owner_uid: u32) -> String {
    let owner = if owner_uid == 0 { "root".to_string() } else { format!("uid {owner_uid}") };
    format!(
        "{dir_display} is owned by {owner} (a bind mount created it before the certificate existed); \
         fix: sudo chown $USER {dir_display}, then re-run"
    )
}

/// `noo security pki issue-sso-key [--force]` — the Grafana SSO key pair
/// P-256, `sso/grafana.key` (0640, group 65532 so the
/// nonroot gateway reads it) and `sso/grafana.pub` (0644, the one file
/// Grafana mounts). Refuses to overwrite without `--force`, because a new
/// key logs every open Grafana tab out at once and needs the gateway AND
/// Grafana recreated together. `rotate-all` never rotates it (it is not a
/// certificate); this verb is the only way it changes.
pub fn pki_issue_sso_key(g: &Globals, args: &[String]) -> Result<i32, Unhandled> {
    let mut force = false;
    for a in args {
        match a.as_str() {
            "--force" => force = true,
            _ => return Err(Unhandled),
        }
    }
    let ca = ca();
    if ca.grafana_sso_key_exists() && !force {
        if g.json {
            println!(
                "{}",
                serde_json::json!({
                    "status": "already_exists",
                    "key": ca.grafana_sso_key_path().to_string_lossy(),
                    "pub": ca.grafana_sso_pub_path().to_string_lossy(),
                })
            );
        } else {
            ui::warned(&format!(
                "Grafana SSO key already exists at {}: not overwriting (--force re-mints it, which logs every open Grafana tab out)",
                ca.grafana_sso_key_path().display()
            ));
        }
        return Ok(0);
    }
    if let Err(e) = ca.mint_grafana_sso_key() {
        // `sso/` created as root by Docker (the grafana.pub bind source,
        // v0.2.78) turns a bare EACCES into the chown that fixes it.
        let dir = ca.grafana_sso_key_path().parent().map(|p| p.to_path_buf()).unwrap_or_default();
        fail_pki(g, &permission_denied_hint(&e, &dir).unwrap_or(e));
    }
    let grant = ca.grafana_sso_key_grant_gateway_read();
    if g.json {
        println!(
            "{}",
            serde_json::json!({
                "status": if force { "rotated" } else { "created" },
                "key": ca.grafana_sso_key_path().to_string_lossy(),
                "pub": ca.grafana_sso_pub_path().to_string_lossy(),
                "readable_by_gateway": grant.is_ok(),
                "fix": grant.as_ref().err(),
            })
        );
        return Ok(0);
    }
    ui::done(&format!("Grafana SSO key pair written under {}", ca.grafana_sso_key_path().parent().unwrap_or(&ca.dir).display()));
    if let Err(e) = grant {
        ui::warned(&e);
    }
    if force {
        ui::warned("every open Grafana tab is logged out when the gateway restarts; people click Open Grafana again");
    }
    ui::guide(&[("noo stack restart --force", "recreate the gateway (signs) and Grafana (verifies) with the new pair")]);
    Ok(0)
}

/// `noo security pki issue-gateway [HOSTNAME] [IP] [--days N]
///  [--extra-ip IP]… [--extra-san SAN]…` — dual-purpose gateway cert.
pub fn pki_issue_gateway(g: &Globals, args: &[String]) -> Result<i32, Unhandled> {
    let mut pos: Vec<String> = Vec::new();
    let mut days: i64 = DEFAULT_DAYS;
    let mut extra_sans: Vec<String> = Vec::new();
    let mut extra_ips: Vec<String> = Vec::new();
    let mut iter = args.iter();
    while let Some(tok) = iter.next() {
        match tok.as_str() {
            "--days" => days = next_i64(&mut iter)?,
            "--extra-san" => extra_sans.push(iter.next().ok_or(Unhandled)?.clone()),
            "--extra-ip" => extra_ips.push(iter.next().ok_or(Unhandled)?.clone()),
            t if t.starts_with('-') => return Err(Unhandled),
            t => pos.push(t.to_string()),
        }
    }
    if pos.len() > 2 {
        return Err(Unhandled);
    }
    let hostname = pos.first().map(String::as_str).unwrap_or("gateway");
    let ip = pos.get(1).map(String::as_str).unwrap_or("127.0.0.1");
    match ca().issue_gateway_cert(hostname, ip, days, &extra_sans, &extra_ips) {
        Ok((crt, key)) => emit_pair(g, "Gateway", &crt, &key),
        Err(e) => fail_pki(g, &e),
    }
}

/// `noo security pki rotate NODE_ID IP [--days N]` — re-issue a node cert
/// in place. (The Python command additionally calls a `revoke_node_cert`
/// method that does not exist in ca.py — it crashes before issuing; the
/// re-issue below is the intended behavior.)
pub fn pki_rotate(g: &Globals, args: &[String]) -> Result<i32, Unhandled> {
    let (pos, days, _) = parse_issue_args(args, &[])?;
    let [node_id, ip] = pos.as_slice() else { return Err(Unhandled) };
    let role = crate::pki::NodeRole::of(node_id);
    let ts_ip: Vec<String> = role.tailnet_ip4(node_id).into_iter().collect();
    match ca().issue_node_cert(node_id, ip, days, &[], &ts_ip, &role) {
        Ok((crt, key)) => {
            if g.json {
                println!(
                    "{}",
                    serde_json::json!({
                        "rotated": node_id,
                        "delivered": false,
                        "cert": crt.to_string_lossy(),
                        "key": key.to_string_lossy(),
                    })
                );
            } else {
                // fu72 #6: "Rotated" claimed delivery it never did — the
                // re-issue is LOCAL; the node keeps serving its old cert
                // until a bundle carries the new one over.
                ui::done(&format!("re-issued cert for {node_id}  {}", ui::muted("local files only: the node still runs its old cert")));
                print!("{}", ui::kv(&[("cert", crt.display().to_string()), ("key", key.display().to_string())]));
                ui::guide(&[
                    (&format!("noo cluster provision {node_id}"), "stages a pull bundle the node collects on its next fetch"),
                    ("noo security pki push-nodes", "stages the cert on the pull rail for every registered node in one pass"),
                ]);
            }
            Ok(0)
        }
        Err(e) => fail_pki(g, &e),
    }
}

/// Shared parser: positionals + `--days N` + one repeatable string flag.
/// What only `sudo` can repair, and therefore the only reason an operator
/// runs `fix-modes` by hand: every other mode is set when the key is
/// issued, re-set by `noo upgrade --stack` (`reconcile_key_modes`), by
/// `noo cluster provision` for the node's keys, and by `noo onboard`.
pub(crate) const NEEDS_A_HAND: &str = "only these need you: a key owned by another uid that this user cannot read (sudo chown), and a key read by a container uid when this user may neither chgrp to that uid nor setfacl (sudo chgrp; install the `acl` package to make it automatic)";

/// The mode pass `noo upgrade --stack` runs before the launcher (from
/// `upgrade::reconcile_service_certs`): every key to its reader's mode —
/// a foreign-owned key this user can read is taken back — every
/// directory 0755, every certificate 0644. Says what changed in one line
/// and, per key it could not repair, the exact `sudo` line. Never fails
/// the roll.
///
/// A key this user could not hand to its container uid (no `setfacl`, not
/// in that gid) was left 0644 so its service keeps starting. A roll that
/// MOVES a reader makes one on every such box: 0.6.12 hands the sandbox key
/// from 65532 to the sandbox server's own uid. So, as onboard does (i266),
/// the grant goes through `sudo -n` when sudo needs no password (the rail's
/// applier, a cloud image's user); otherwise the roll says LOUDLY that the
/// keys are world-readable and names the command that prints each line. No
/// password prompt in the middle of a roll.
pub(crate) fn reconcile_key_modes(g: &Globals, ca: &ClusterCa) -> ModeRepair {
    let mut repair = ModeRepair::run(ca);
    let pending = sudo_grant_pending(&repair.keys);
    if !pending.is_empty() && crate::onboard::steps::passwordless_sudo() {
        for i in pending {
            let f = &mut repair.keys[i];
            let crate::pki::KeyReader::ContainerUid(uid) = f.reader else { continue };
            if crate::pki::grant_read_to_uid_via_sudo(&ca.dir.join(&f.rel), uid, true).is_ok() {
                f.needs = None;
                f.granted_via = "sudo";
                f.after = 0o640;
            }
        }
    }
    let exposed = sudo_grant_pending(&repair.keys).into_iter().filter(|&i| repair.keys[i].after & 0o004 != 0).count();
    if g.json {
        return repair;
    }
    if repair.changed() > 0 {
        ui::done(&format!(
            "PKI modes repaired: {} key(s), {} dir(s), {} certificate(s)",
            repair.keys.iter().filter(|f| f.changed() && f.needs.is_none()).count(),
            repair.dirs.len(),
            repair.certs.len()
        ));
    }
    for f in repair.keys.iter().filter(|f| f.needs.is_some()) {
        ui::warned(&format!("{} ({}) needs a hand this process does not have — run: {}", f.rel, f.reader.describe(), f.needs.as_deref().unwrap_or_default()));
    }
    if exposed > 0 {
        ui::failed(&crate::pki::exposed_keys_failure(exposed), Some("noo security pki fix-modes --dry-run"));
    }
    repair
}

/// The keys of one repair pass that only `sudo chgrp` can hand to their
/// container uid (indices into `keys`): a uid-read key whose pending line
/// is the grant. A foreign-owned key's `sudo chown` line is not one.
pub(crate) fn sudo_grant_pending(keys: &[crate::pki::KeyFix]) -> Vec<usize> {
    keys.iter()
        .enumerate()
        .filter(|(_, f)| matches!(f.reader, crate::pki::KeyReader::ContainerUid(_)) && f.needs.as_deref().is_some_and(|n| n.starts_with("sudo chgrp")))
        .map(|(i, _)| i)
        .collect()
}

/// One pass of every mode this CLI owns.
pub(crate) struct ModeRepair {
    pub keys: Vec<crate::pki::KeyFix>,
    pub dirs: Vec<String>,
    pub certs: Vec<String>,
}

impl ModeRepair {
    pub(crate) fn run(ca: &ClusterCa) -> Self {
        let (keys, dirs) = ca.fix_key_modes();
        let certs = ca.fix_cert_modes();
        ModeRepair { keys, dirs, certs }
    }

    pub(crate) fn changed(&self) -> usize {
        self.keys.iter().filter(|f| f.changed()).count() + self.dirs.len() + self.certs.len()
    }
}

/// `noo security pki fix-modes [--dry-run]` — set every existing private
/// key under the PKI dir to its reader's mode (`pki::KeyReader`: 0600 for
/// the CLI and root-in-container readers, 0640 handed to the container uid
/// otherwise) and every directory to 0755. Idempotent; prints what changed
/// and, for a key this process could not hand over, the `sudo` line that
/// does. Onboard runs it on every pass; `noo security scan` reports what
/// it would change as CRITICAL; `noo cluster verify --controller` has a
/// `pki key modes` row. It also re-syncs `public/`, the certificate-only
/// view the gateway mounts instead of the PKI root
/// `gateway pki view` verify row).
pub fn pki_fix_modes(g: &Globals, args: &[String]) -> Result<i32, Unhandled> {
    let mut dry_run = false;
    for a in args {
        match a.as_str() {
            "--dry-run" => dry_run = true,
            _ => return Err(Unhandled),
        }
    }
    let ca = ca();
    if !ca.dir.is_dir() {
        fail_pki(g, &format!("No cluster CA: {} does not exist", ca.dir.display()));
    }
    if dry_run {
        let issues = ca.audit_key_modes();
        let drift = ca.public_view_drift();
        if !g.json && !drift.is_clean() {
            println!("{}", ui::status_line(Glyph::Warn, &format!(
                "public/ (the gateway's certificate-only view) is out of step: {} missing, {} stale, {} extra, {} key(s) — fix-modes re-syncs it",
                drift.missing.len() + drift.missing_roots.len(), drift.stale.len(), drift.extra.len(), drift.keys.len()
            )));
        }
        if g.json {
            let items: Vec<serde_json::Value> = issues
                .iter()
                .map(|i| serde_json::json!({
                    "key": i.rel, "mode": format!("{:04o}", i.mode), "reader": i.reader.describe(),
                    "issue": match i.kind {
                        crate::pki::KeyIssueKind::Exposed => "exposed",
                        crate::pki::KeyIssueKind::Unreadable => "unreadable",
                        crate::pki::KeyIssueKind::UnknownReader => "unknown-reader",
                        crate::pki::KeyIssueKind::WrongOwner => "wrong-owner",
                    },
                    "needs": ca.key_grant_command(&ca.dir.join(&i.rel)),
                }))
                .collect();
            println!("{}", serde_json::json!({ "dry_run": true, "would_change": items, "public_view_in_step": drift.is_clean() }));
            return Ok(0);
        }
        if issues.is_empty() {
            println!("{}", ui::status_line(Glyph::Ok, &format!("No change — every private key under {} is readable only by its reader", ca.dir.display())));
            return Ok(0);
        }
        println!("{}", ui::header("pki key modes", Some(&format!("dry-run · {} key(s)", issues.len()))));
        let rows: Vec<Vec<String>> = issues
            .iter()
            .map(|i| vec![ui::glyph_cell(Glyph::Warn), i.rel.clone(), format!("{:04o}", i.mode), i.reader.describe(), format!("Would {}", match i.kind {
                crate::pki::KeyIssueKind::Exposed => "tighten",
                crate::pki::KeyIssueKind::Unreadable => "hand to its reader",
                crate::pki::KeyIssueKind::UnknownReader => "leave (no reader entry)",
                crate::pki::KeyIssueKind::WrongOwner => "leave (owned by another uid; needs the sudo line)",
            })])
            .collect();
        print!("{}", ui::table(&[Col::left(""), Col::left("key"), Col::left("mode"), Col::left("reader"), Col::left("action")], &rows));
        ui::guide(&[("noo security pki fix-modes", "apply")]);
        return Ok(0);
    }

    // The gateway's certificate-only view first: it
    // creates `public/{nodes,services}` and `sso/` as the operator, so
    // the directory pass below finds them already 0755.
    let view = ca.sync_public_view();
    let (fixes, dirs) = ca.fix_key_modes();
    let certs = ca.fix_cert_modes();
    let changed: Vec<&crate::pki::KeyFix> = fixes.iter().filter(|f| f.changed()).collect();
    let needs: Vec<&crate::pki::KeyFix> = fixes.iter().filter(|f| f.needs.is_some()).collect();
    if g.json {
        let rows: Vec<serde_json::Value> = fixes
            .iter()
            .map(|f| serde_json::json!({
                "key": f.rel, "reader": f.reader.describe(),
                "before": format!("{:04o}", f.before), "after": format!("{:04o}", f.after),
                "granted_via": f.granted_via, "needs": f.needs,
            }))
            .collect();
        println!("{}", serde_json::json!({
            "keys": rows, "dirs_changed": dirs, "certs_changed": certs, "changed": changed.len(), "needs_sudo": needs.len(),
            "public_view": {
                "dir": ca.public_view_dir().to_string_lossy(),
                "certs": view.total, "copied": view.copied, "removed": view.removed, "errors": view.errors,
            },
        }));
        return Ok(if view.errors.is_empty() { 0 } else { 1 });
    }
    let view_quiet = view.copied.is_empty() && view.removed.is_empty() && view.errors.is_empty();
    for c in &certs {
        println!("{}", ui::status_line(Glyph::Ok, &format!("{c}: certificate set to 0644 (was group- or world-writable)")));
    }
    if changed.is_empty() && dirs.is_empty() && needs.is_empty() && view_quiet {
        println!("{}", ui::status_line(Glyph::Ok, &format!(
            "No change — {} private key(s) under {} already readable only by their readers; public/ mirrors {} certificate(s)",
            fixes.len(), ca.dir.display(), view.total
        )));
        return Ok(0);
    }
    print_public_view(&ca, &view);
    if changed.is_empty() && dirs.is_empty() && needs.is_empty() {
        return Ok(if view.errors.is_empty() { 0 } else { 1 });
    }
    println!("{}", ui::header("pki key modes", Some(&format!("{} key(s) · {} changed · {} dir(s)", fixes.len(), changed.len(), dirs.len()))));
    if !changed.is_empty() {
        println!("{}", ui::section("changed"));
        let rows: Vec<Vec<String>> = changed
            .iter()
            .map(|f| vec![ui::glyph_cell(Glyph::Ok), f.rel.clone(), format!("{:04o} → {:04o}", f.before, f.after), f.reader.describe(), match (f.reowned, f.granted_via) {
                (_, "group") => "handed over by group".to_string(),
                (_, "acl") => "handed over by ACL".to_string(),
                (true, _) => "taken back from another owner".to_string(),
                _ => String::new(),
            }])
            .collect();
        print!("{}", ui::table(&[Col::left(""), Col::left("key"), Col::left("mode"), Col::left("reader"), Col::left("grant")], &rows));
    }
    for d in &dirs {
        println!("{}", ui::status_line(Glyph::Ok, &format!("{}: directory set to 0755", if d == "." { ca.dir.display().to_string() } else { d.clone() })));
    }
    if !needs.is_empty() {
        println!("{}", ui::section("needs a hand this process does not have"));
        println!("{}", ui::note(NEEDS_A_HAND));
        for f in &needs {
            println!("{}", ui::status_line(Glyph::Warn, &format!("{} ({}) — left as is; run:", f.rel, f.reader.describe())));
            println!("    {}", f.needs.as_deref().unwrap_or_default());
        }
        ui::guide(&[("noo cluster verify --controller", "the 'pki key modes' row confirms it")]);
    }
    Ok(0)
}

/// One block for the gateway's certificate-only view:
/// what the sync wrote and removed, and — when it could not — the
/// directory and the fix. A `public/` subtree Docker created as root (an
/// older `noo` started the stack before this one laid it down) is the
/// usual cause; `permission_denied_hint` names the chown.
pub(crate) fn print_public_view(ca: &ClusterCa, view: &crate::pki::PublicViewSync) {
    if !view.copied.is_empty() || !view.removed.is_empty() {
        println!("{}", ui::status_line(Glyph::Ok, &format!(
            "public/ (the gateway's certificate-only view): {} certificate(s), {} written, {} removed",
            view.total, view.copied.len(), view.removed.len()
        )));
        for r in &view.removed {
            println!("    {}", ui::muted(&format!("removed {r}")));
        }
    }
    for e in &view.errors {
        let hint = public_view_hint(ca, e).unwrap_or_default();
        println!("{}", ui::status_line(Glyph::Warn, &format!("public/: {e}{}", if hint.is_empty() { String::new() } else { format!(" — {hint}") })));
    }
}

/// The chown for a permission error under the view: the first of its
/// directories (deepest first) that another uid owns — Docker's root, when
/// an older `noo` started the stack before `public/` existed.
pub(crate) fn public_view_hint(ca: &ClusterCa, err: &str) -> Option<String> {
    let public = ca.public_view_dir();
    let mut dirs: Vec<std::path::PathBuf> = crate::pki::PUBLIC_VIEW_TREES.iter().map(|t| public.join(t)).collect();
    dirs.push(ca.dir.join("sso"));
    dirs.push(public);
    dirs.iter().find_map(|d| permission_denied_hint(err, d))
}

fn parse_issue_args(
    args: &[String],
    san_flags: &[&str],
) -> Result<(Vec<String>, i64, Vec<String>), Unhandled> {
    let mut pos: Vec<String> = Vec::new();
    let mut days: i64 = DEFAULT_DAYS;
    let mut sans: Vec<String> = Vec::new();
    let mut iter = args.iter();
    while let Some(tok) = iter.next() {
        match tok.as_str() {
            "--days" => days = next_i64(&mut iter)?,
            t if san_flags.contains(&t) => sans.push(iter.next().ok_or(Unhandled)?.clone()),
            t if t.starts_with('-') => return Err(Unhandled),
            t => pos.push(t.to_string()),
        }
    }
    Ok((pos, days, sans))
}

fn next_i64(iter: &mut std::slice::Iter<'_, String>) -> Result<i64, Unhandled> {
    iter.next()
        .and_then(|v| v.parse::<i64>().ok())
        .filter(|d| *d > 0)
        .ok_or(Unhandled)
}

fn emit_pair(g: &Globals, kind: &str, crt: &std::path::Path, key: &std::path::Path) -> Result<i32, Unhandled> {
    if g.json {
        println!(
            "{}",
            serde_json::json!({
                "cert": crt.to_string_lossy(),
                "key": key.to_string_lossy(),
                "key_fix": ca().key_grant_command(key),
            })
        );
    } else {
        // Paths are the value a script captures: stdout, plain.
        let kind = kind.to_ascii_lowercase();
        print!("{}", ui::kv(&[(&format!("{kind} cert"), crt.display().to_string()), (&format!("{kind} key"), key.display().to_string())]));
        // The key was written with its reader's mode; if this process could
        // not hand it to that uid (chgrp needs root; no setfacl), the file
        // is as readable as before and the fix is one line the operator has.
        if let Some(cmd) = ca().key_grant_command(key) {
            ui::warned(&format!("{} is not readable by its container uid yet — run: {cmd}", key.display()));
        }
        match kind.as_str() {
            "gateway" => ui::guide(&[
                ("noo stack restart gateway", "the gateway reads its cert at start"),
                ("noo security pki status", "confirms the new expiry"),
            ]),
            "node" => ui::guide(&[
                ("noo security pki push-nodes <node>", "delivers the cert to the node and reloads its agent"),
                ("noo security pki status", "confirms the new expiry"),
            ]),
            _ => ui::guide(&[("noo security pki status", "lists every cert and its expiry")]),
        }
    }
    Ok(0)
}

// ── Operator client certificates ────────────────────────
//
// `issue-client`, `rotate-client`, `revoke-client`. The leaf is issued here
// (it needs the CA key, so on the controller), kept in the operator's OWN
// config dir (`crate::operator_cert`, never the PKI dir the containers
// mount), and registered with the gateway by the account it names. Posture
// writes then carry it plus a token bound to it (`http::post_posture_try`).

/// Parse `<operator> [--days N] [extra flags]`. `flags` are boolean flags
/// this verb accepts; their presence is returned.
fn parse_client_args(args: &[String], flags: &[&str]) -> Result<(String, i64, Vec<String>, Option<String>), Unhandled> {
    let mut pos: Vec<String> = Vec::new();
    let mut days = crate::operator_cert::OPERATOR_DAYS;
    let mut seen = Vec::new();
    let mut thumbprint = None;
    let mut iter = args.iter();
    while let Some(tok) = iter.next() {
        match tok.as_str() {
            "--days" => days = next_i64(&mut iter)?,
            "--thumbprint" if flags.contains(&"--thumbprint") => thumbprint = Some(iter.next().ok_or(Unhandled)?.clone()),
            t if flags.contains(&t) => seen.push(t.to_string()),
            t if t.starts_with('-') => return Err(Unhandled),
            t => pos.push(t.to_string()),
        }
    }
    let [account] = pos.as_slice() else { return Err(Unhandled) };
    Ok((account.clone(), days, seen, thumbprint))
}

/// Register `pair` with the gateway, over a connection presenting it, with
/// the operator's own login. `Ok(already_registered)`.
pub(crate) fn register_operator_cert(g: &Globals, pair: &crate::operator_cert::OperatorPair) -> Result<bool, String> {
    let base = crate::envfile::gateway_url(&g.gateway_override);
    let agent = crate::http::agent_with_client_cert(g, &base, 15, pair)?;
    let login = crate::http::operator_login(g)?;
    let url = format!("{base}/api/security/operator-certs/register");
    let (status, text) = crate::http::post_raw(&agent, &url, Some(&login), &serde_json::json!({}))
        .map_err(|e| crate::http::describe_send_error(&base, &e, 15))?;
    if !(200..=299).contains(&status) {
        let why = crate::http::detail_of(status, &text);
        return Err(if status == 404 {
            format!("the gateway predates operator certificates ({why}) — `noo upgrade --stack` first")
        } else {
            format!("the gateway refused to register it ({status}): {why}")
        });
    }
    let v: serde_json::Value = serde_json::from_str(&text).unwrap_or_default();
    Ok(v["already"].as_bool().unwrap_or(false))
}

/// Issue a leaf for `account`, write it to the operator dir, register it.
/// For `issue-client` and the onboard wizard. `Err` names the failed step;
/// the files stay on disk when only the registration failed (the message
/// says so), so a re-run with the gateway up is the whole fix.
pub(crate) fn issue_and_register(
    g: &Globals,
    account: &str,
    days: i64,
) -> Result<(std::path::PathBuf, std::path::PathBuf, String), String> {
    crate::operator_cert::validate_account(account)?;
    let ca = ca();
    if !ca.ca_exists() {
        return Err(format!(
            "no cluster CA at {} — operator certificates are issued on the controller",
            ca.dir.display()
        ));
    }
    let (cert_pem, key_pem) = ca.issue_operator_leaf(account, days)?;
    let pair = crate::operator_cert::OperatorPair { cert_pem, key_pem };
    let tp = pair.thumbprint()?;
    let dir = crate::operator_cert::dir_for(account);
    let (crt, key) = crate::operator_cert::write_pair(&dir, &pair, &ca.dir)?;
    register_operator_cert(g, &pair)
        .map_err(|e| format!("issued {} but NOT registered: {e}", crt.display()))?;
    Ok((crt, key, tp))
}

/// `noo security pki issue-client <operator> [--days N] [--force]`.
pub fn pki_issue_client(g: &Globals, args: &[String]) -> Result<i32, Unhandled> {
    let (account, days, flags, _) = parse_client_args(args, &["--force"])?;
    let force = flags.iter().any(|f| f == "--force");
    if !force && crate::operator_cert::load(&account).is_some() {
        fail(
            g.json,
            ExitCode::Generic,
            "already_issued",
            &format!("an operator certificate for '{account}' is already held at {}", crate::operator_cert::dir_for(&account).display()),
            Some(&format!("noo security pki rotate-client {account}   # replaces it and revokes the old one")),
        );
    }
    if let Some(sub) = crate::credentials::load().map(|c| c.subject) {
        if sub != account {
            fail(
                g.json,
                ExitCode::Usage,
                "wrong_account",
                &format!("you are logged in as '{sub}', and an operator certificate is registered by the account it names ('{account}')"),
                Some(&format!("noo auth login {account}   # then re-run")),
            );
        }
    }
    match issue_and_register(g, &account, days) {
        Ok((crt, key, tp)) => emit_client(g, "issued", &account, &crt, &key, &tp),
        Err(e) => fail(g.json, ExitCode::Generic, "operator_cert_error", &e, Some(&format!("noo security pki issue-client {account} --force   # once the cause is fixed"))),
    }
}

/// `noo security pki rotate-client <operator> [--days N]` — a new leaf,
/// registered, then the old one revoked with the new one's authority.
pub fn pki_rotate_client(g: &Globals, args: &[String]) -> Result<i32, Unhandled> {
    let (account, days, _, _) = parse_client_args(args, &[])?;
    let Some(old) = crate::operator_cert::load(&account) else {
        fail(
            g.json,
            ExitCode::Generic,
            "nothing_to_rotate",
            &format!("no operator certificate for '{account}' at {}", crate::operator_cert::dir_for(&account).display()),
            Some(&format!("noo security pki issue-client {account}")),
        );
    };
    let old_tp = old.thumbprint().unwrap_or_default();
    let ca = ca();
    let issued = crate::operator_cert::validate_account(&account)
        .and_then(|_| ca.issue_operator_leaf(&account, days))
        .map(|(cert_pem, key_pem)| crate::operator_cert::OperatorPair { cert_pem, key_pem });
    let new = issued.unwrap_or_else(|e| fail_pki(g, &e));
    // Register BEFORE replacing the files: a registration that fails leaves
    // the working pair in place.
    if let Err(e) = register_operator_cert(g, &new) {
        fail(g.json, ExitCode::Generic, "operator_cert_error", &format!("the new certificate was not registered, so the old one stays: {e}"), None);
    }
    let dir = crate::operator_cert::dir_for(&account);
    let (crt, key) = crate::operator_cert::write_pair(&dir, &new, &ca.dir).unwrap_or_else(|e| fail_pki(g, &e));
    let tp = new.thumbprint().unwrap_or_default();
    // Revoke the old one with the NEW certificate's authority.
    match crate::http::post_posture_try(
        g,
        "/api/security/operator-certs/revoke",
        &serde_json::json!({ "thumbprint": old_tp }),
        15,
    ) {
        Ok(_) => {}
        Err(e) => {
            if !g.json {
                ui::warned(&format!("the new certificate is live, but the old one ({}) was NOT revoked: {}", short_tp(&old_tp), e.msg));
                ui::guide(&[(&format!("noo security pki revoke-client {account} --thumbprint {old_tp}"), "revokes it")]);
            }
        }
    }
    emit_client(g, "rotated", &account, &crt, &key, &tp)
}

/// `noo security pki revoke-client <operator> [--thumbprint TP | --others]`
/// — revoke at the gateway (every live certificate of the account, one of
/// them, or every one but the pair held here), then delete the local pair
/// if it is among them. Authorised exactly as a posture write: your
/// operator certificate and a token bound to it — nothing else.
///
/// `--others` is the second half of recovering a LOST certificate: issue a
/// new one (`issue-client <you> --force`), then revoke everything else the
/// account holds, the lost leaf included, with the new one's authority.
pub fn pki_revoke_client(g: &Globals, args: &[String]) -> Result<i32, Unhandled> {
    let (account, _, flags, thumbprint) = parse_client_args(args, &["--thumbprint", "--others", "--yes", "-y"])?;
    let others = flags.iter().any(|f| f == "--others");
    let yes = flags.iter().any(|f| f == "--yes" || f == "-y");
    if others && thumbprint.is_some() {
        return Err(Unhandled);
    }
    // Revoking is not undoable, and the bare form takes EVERY certificate of
    // the account with it (and the local pair). Recovery needs an admin
    // password reset plus `issue-client --force`, so confirm first.
    super::confirm_destructive(g, yes, "revoke", &revoke_target(&account, thumbprint.as_deref(), others));
    let local = crate::operator_cert::load(&account);
    let local_tp = local.as_ref().and_then(|p| p.thumbprint().ok());
    let body = match (&thumbprint, others) {
        (Some(tp), _) => serde_json::json!({ "thumbprint": tp }),
        (None, true) => {
            let Some(keep) = local_tp.clone() else {
                fail(
                    g.json,
                    ExitCode::Generic,
                    "nothing_held",
                    &format!("--others keeps the certificate held here, and there is none for '{account}'"),
                    Some(&format!("noo security pki issue-client {account} --force")),
                );
            };
            serde_json::json!({ "operator": account, "keep": keep })
        }
        (None, false) => serde_json::json!({ "operator": account }),
    };
    let v = crate::http::post_json_operator(g, "/api/security/operator-certs/revoke", &body, 15);
    let drop_local = !others && local.is_some() && thumbprint.as_ref().is_none_or(|t| Some(t) == local_tp.as_ref());
    if drop_local {
        if let Err(e) = crate::operator_cert::remove(&account) {
            ui::warned(&format!("revoked, but the local copy could not be removed: {e}"));
        }
    }
    let n = v["revoked"].as_u64().unwrap_or(0);
    if g.json {
        println!("{}", serde_json::json!({ "operator": account, "revoked": n, "local_removed": drop_local }));
    } else {
        ui::done(&format!("{n} operator certificate(s) for '{account}' revoked"));
        if drop_local {
            println!("{}", ui::muted("the local copy was removed"));
        }
    }
    Ok(0)
}

/// What the confirmation names: the scope of the revoke, in words.
pub(crate) fn revoke_target(account: &str, thumbprint: Option<&str>, others: bool) -> String {
    match (thumbprint, others) {
        (Some(tp), _) => format!("operator certificate {} of '{account}'", short_tp(tp)),
        (None, true) => format!("every operator certificate of '{account}' except the one held here"),
        (None, false) => format!("EVERY operator certificate of '{account}' (the local pair is deleted too)"),
    }
}

fn short_tp(tp: &str) -> String {
    tp.chars().take(12).collect()
}

fn emit_client(g: &Globals, what: &str, account: &str, crt: &std::path::Path, key: &std::path::Path, tp: &str) -> Result<i32, Unhandled> {
    if g.json {
        println!(
            "{}",
            serde_json::json!({
                "status": what,
                "operator": account,
                "cert": crt.to_string_lossy(),
                "key": key.to_string_lossy(),
                "thumbprint": tp,
                "registered": true,
            })
        );
    } else {
        ui::done(&format!("operator certificate {what} for '{account}' and registered with the gateway"));
        print!("{}", ui::kv(&[("operator cert", crt.display().to_string()), ("operator key", key.display().to_string()), ("thumbprint", tp.to_string())]));
        println!("{}", ui::muted("the key is 0600 in your own config dir, outside the PKI dir the containers mount"));
        ui::guide(&[
            ("noo security posture list", "posture writes now use this certificate and a token bound to it"),
            (&format!("noo security pki revoke-client {account} --others"), "if this replaces a lost or expired one: revokes every other certificate of yours"),
            (&format!("noo security pki rotate-client {account}"), "before it expires (30 days by default)"),
        ]);
    }
    Ok(0)
}

#[cfg(test)]
mod permission_denied_tests {
    use super::*;

    /// The exact newcomer-upgrade rehearsal event (2026-09-29): Docker
    /// created `services/model-cache` as root before onboarding's
    /// `ensure_pki` had a chance to issue a cert into it. The message must
    /// name the directory and the fix, not just say "Permission denied".
    #[test]
    fn root_owned_directory_names_root_and_the_chown_fix() {
        let msg = permission_denied_message("/home/dev/.noo/pki/services/model-cache", 0);
        assert!(msg.contains("owned by root"));
        assert!(msg.contains("sudo chown $USER /home/dev/.noo/pki/services/model-cache"));
        assert!(msg.contains("bind mount"));
    }

    #[test]
    fn a_non_root_other_owner_is_named_by_uid() {
        let msg = permission_denied_message("/home/dev/.noo/pki/services/model-cache", 1001);
        assert!(msg.contains("owned by uid 1001"));
        assert!(!msg.contains("owned by root"));
    }
}

#[cfg(test)]
mod reconcile_tests {
    use super::*;
    use std::os::unix::fs::PermissionsExt as _;

    fn scratch(tag: &str) -> ClusterCa {
        let d = std::env::temp_dir().join(format!("noo-pki-reconcile-{tag}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&d);
        std::fs::create_dir_all(&d).unwrap();
        let ca = ClusterCa::new(d);
        ca.generate_ca("t", 3650).unwrap();
        ca
    }

    fn mode_of(p: &std::path::Path) -> u32 {
        std::fs::metadata(p).unwrap().permissions().mode() & 0o777
    }

    fn set(p: &std::path::Path, m: u32) {
        std::fs::set_permissions(p, std::fs::Permissions::from_mode(m)).unwrap();
    }

    /// PLANTED: the tree a pre-2026-09-28 install carries into `noo upgrade
    /// --stack` — 0644 node and service keys, a 0775 directory, 0664
    /// certificates. The reconcile stage (`ModeRepair`, what
    /// `reconcile_key_modes` runs before the launcher) brings each to the
    /// mode it owns, and a second pass changes nothing.
    #[test]
    fn the_upgrade_reconcile_repairs_the_modes_it_owns() {
        let ca = scratch("repair");
        let (node_crt, node_key) = ca.issue_node_cert("host3", "10.0.0.3", 90, &[], &[], &crate::pki::NodeRole::Worker).unwrap();
        let (_, nats_key) = ca.issue_service_cert("nats", &[], &[], 90).unwrap();
        let (_, standby_key) = ca.issue_service_cert("postgres-standby", &[], &[], 90).unwrap();
        for k in [&node_key, &nats_key, &standby_key] {
            set(k, 0o644);
        }
        set(node_key.parent().unwrap(), 0o775);
        set(&node_crt, 0o664);

        let repair = ModeRepair::run(&ca);
        assert!(repair.changed() >= 5, "keys, dir and cert: {} changed", repair.changed());
        for k in [&node_key, &nats_key, &standby_key] {
            assert_eq!(mode_of(k), 0o600, "{}", k.display());
        }
        assert_eq!(mode_of(node_key.parent().unwrap()), 0o755);
        assert_eq!(mode_of(&node_crt), 0o644);
        assert!(repair.keys.iter().all(|f| f.needs.is_none() || matches!(ca.key_reader(&ca.dir.join(&f.rel)), crate::pki::KeyReader::ContainerUid(_))),
            "a key only the CLI or container root reads never needs sudo when the operator owns it");
        assert_eq!(ModeRepair::run(&ca).changed(), 0, "idempotent");
        let _ = std::fs::remove_dir_all(&ca.dir);
    }

    /// The upgrade's sudo pass picks exactly the uid-read keys whose pending
    /// line is the `sudo chgrp` grant — the moved sandbox key on a box with
    /// no setfacl — never a CLI key, never a `sudo chown` (foreign owner).
    #[test]
    fn the_upgrade_hands_only_chgrp_pending_keys_to_sudo() {
        use crate::pki::{KeyFix, KeyReader};
        let fix = |rel: &str, reader: KeyReader, needs: Option<&str>| KeyFix {
            rel: rel.into(), reader, before: 0o640, after: 0o644, granted_via: "", needs: needs.map(str::to_string), reowned: false,
        };
        let keys = vec![
            fix("services/sandbox/service.key", KeyReader::ContainerUid(crate::pki::SANDBOX_SERVER_UID),
                Some("sudo chgrp 65590 /p/services/sandbox/service.key && sudo chmod 640 /p/services/sandbox/service.key")),
            fix("services/loki/service.key", KeyReader::ContainerUid(65532), None),
            fix("services/redis/service.key", KeyReader::ContainerUid(65532), Some("sudo chown 1000:65532 /p/k && sudo chmod 640 /p/k")),
            fix("nodes/h/node.key", KeyReader::Cli, Some("sudo chown 1000:1000 /p/n")),
        ];
        assert_eq!(sudo_grant_pending(&keys), vec![0]);
    }

    /// Provision's half: only the named node's keys are touched.
    #[test]
    fn provision_repairs_only_that_nodes_keys() {
        let ca = scratch("node");
        let (_, a) = ca.issue_node_cert("a", "10.0.0.4", 90, &[], &[], &crate::pki::NodeRole::Worker).unwrap();
        let (_, b) = ca.issue_node_cert("b", "10.0.0.5", 90, &[], &[], &crate::pki::NodeRole::Worker).unwrap();
        let (_, door) = ca.issue_node_service_cert("a", "tei", &[], 90).unwrap();
        for k in [&a, &b, &door] {
            set(k, 0o644);
        }
        let fixes = ca.fix_node_key_modes("a");
        assert_eq!(fixes.len(), 2, "{:?}", fixes.iter().map(|f| &f.rel).collect::<Vec<_>>());
        assert_eq!((mode_of(&a), mode_of(&door), mode_of(&b)), (0o600, 0o600, 0o644));
        let _ = std::fs::remove_dir_all(&ca.dir);
    }

    /// PLANTED: the `pki key modes` row of `noo cluster verify --controller`
    /// over a real tree FAILs on a 0644 key and is OK once repaired.
    #[test]
    fn the_verify_row_fails_a_0644_key() {
        use crate::commands::cluster_verify::{pki_key_modes_check, Verdict};
        let ca = scratch("verify");
        let (_, key) = ca.issue_node_cert("host9", "10.0.0.6", 90, &[], &[], &crate::pki::NodeRole::Worker).unwrap();
        let row = || {
            let lines: Vec<String> = ca.list_keys().iter().filter_map(|k| ca.key_grant_command(k)).collect();
            pki_key_modes_check(&ca.audit_key_modes(), &lines, ca.list_keys().len())
        };
        let clean = row();
        // A uid-read key this box cannot hand over (no setfacl, not root)
        // is a WARN elsewhere in the tree; the node key is what is planted.
        assert_ne!(clean.verdict, Verdict::Fail, "{}", clean.detail);
        set(&key, 0o644);
        let c = row();
        assert_eq!(c.verdict, Verdict::Fail, "{}", c.detail);
        assert!(c.detail.contains("nodes/host9/node.key 0644"), "{}", c.detail);
        ModeRepair::run(&ca);
        assert_ne!(row().verdict, Verdict::Fail);
        let _ = std::fs::remove_dir_all(&ca.dir);
    }
}

#[cfg(test)]
mod issue_service_names_tests {
    use super::issue_service_names;

    /// The bare verb carries the derived set (what onboarding
    /// and the upgrade reconcile issue), and `--san` adds on top of it.
    #[test]
    fn issue_service_with_no_san_is_the_full_derived_set() {
        let (names, ips) = issue_service_names("model-cache", &[], "Pop-Host", "10.0.0.5", "pop.ts.net");
        for want in ["noo-model-cache", "noo-controller", "Pop-Host", "pop-host", "pop.ts.net"] {
            assert!(names.iter().any(|n| n == want), "{want} missing from {names:?}");
        }
        assert_eq!(ips, vec!["10.0.0.5".to_string()]);
        let (names, ips) = issue_service_names("model-cache", &["extra.lan".into(), "192.168.1.9".into(), "pop.ts.net".into()], "Pop-Host", "10.0.0.5", "pop.ts.net");
        assert!(names.iter().any(|n| n == "extra.lan"));
        assert_eq!(names.iter().filter(|n| *n == "pop.ts.net").count(), 1, "no duplicates: {names:?}");
        assert!(ips.contains(&"192.168.1.9".to_string()) && ips.contains(&"10.0.0.5".to_string()));
    }
}

#[cfg(test)]
mod clifix_security_tests {
    use super::*;

    #[test]
    fn the_revoke_confirmation_names_how_much_goes() {
        assert!(revoke_target("ana", None, false).contains("EVERY operator certificate of 'ana'"));
        assert!(revoke_target("ana", None, true).contains("except the one held here"));
        let one = revoke_target("ana", Some("0123456789abcdef"), false);
        assert!(one.contains("0123456789ab") && !one.contains("EVERY"), "{one}");
    }

    #[test]
    fn revoke_client_confirms_before_the_gateway_is_called_and_accepts_yes() {
        let src = include_str!("pki.rs");
        let start = src.find("pub fn pki_revoke_client(").unwrap();
        let body = &src[start..start + src[start..].find("\n}\n").unwrap()];
        let c = body.find("confirm_destructive(").expect("revoke-client never confirms");
        let r = body.find("post_json_operator(").expect("no request");
        assert!(c < r, "confirm must come first");
        assert!(body.contains("\"--yes\"") && body.contains("\"-y\""));
    }
}
