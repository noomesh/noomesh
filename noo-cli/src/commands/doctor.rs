// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 PersonifAI LLC

//! `noo doctor` — host-plane health checks with guided recovery.
//!
//! Born from an unclean-shutdown outage: the damage
//! signature took hours to diagnose by hand and the recovery had three
//! silent traps (socket reactivation, the sudo-glob no-op, prune-resistant
//! image snapshots). This command detects the signature in seconds and
//! prints the exact, personalized recovery — traps pre-sprung.

use std::process::Command;

use crate::output::{fail, ExitCode};
use crate::ui::{self, Col, Glyph};
use crate::{Globals, Unhandled};

fn docker_lines(args: &[&str]) -> Vec<String> {
    Command::new("docker")
        .args(args)
        .output()
        .map(|o| {
            String::from_utf8_lossy(&o.stdout)
                .lines()
                .map(str::to_string)
                .filter(|l| !l.is_empty())
                .collect()
        })
        .unwrap_or_default()
}

/// `noo doctor docker` — detect the unclean-shutdown damage signature
/// (ghost records, empty names, fleet-wide 255s) and print the
/// recovery. Read-only: the repair needs root, and this box's sudo is the
/// operator's — the doctor hands over a recipe, never a surprise.
pub fn doctor_docker(g: &Globals, args: &[String]) -> Result<i32, Unhandled> {
    if !args.is_empty() {
        return Err(Unhandled);
    }

    // Daemon functional at all?
    let daemon_ok = Command::new("docker")
        .args(["version", "--format", "{{.Server.Version}}"])
        .output()
        .map(|o| o.status.success())
        .unwrap_or(false);
    if !daemon_ok {
        fail(g.json, ExitCode::Generic, "daemon_down",
            "the docker daemon is not answering",
            Some("sudo systemctl start docker — then re-run noo doctor docker"));
    }

    let ids = docker_lines(&["ps", "-aq"]);
    let names: Vec<String> = docker_lines(&["ps", "-a", "--format", "{{.Names}}"]);
    let empty_names = ids.len().saturating_sub(names.len());
    let exited_255 = docker_lines(&["ps", "-a", "--format", "{{.Status}}"])
        .iter()
        .filter(|s| s.starts_with("Exited (255)"))
        .count();
    // Ghosts: listed IDs whose inspect fails. Sample up to 25 — enough to
    // classify without hammering a damaged daemon.
    let mut ghosts = 0usize;
    for id in ids.iter().take(25) {
        let ok = Command::new("docker")
            .args(["inspect", "--format", "{{.Id}}", id])
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .status()
            .map(|s| s.success())
            .unwrap_or(false);
        if !ok {
            ghosts += 1;
        }
    }
    let orphans = names.iter().filter(|n| {
        n.len() > 13 && n.as_bytes()[12] == b'_'
            && n[..12].bytes().all(|b| b.is_ascii_hexdigit())
    }).count();

    let damaged = ghosts > 0 || empty_names > 0;
    if g.json {
        println!("{}", serde_json::json!({
            "status": if damaged { "damaged" } else { "healthy" },
            "containers": ids.len(), "ghosts_sampled": ghosts,
            "empty_names": empty_names, "exited_255": exited_255,
            "rename_orphans": orphans,
        }));
        return Ok(if damaged { 1 } else { 0 });
    }

    println!("{}", ui::header("docker host plane", None));
    print!(
        "{}",
        ui::kv(&[
            ("containers listed", ids.len().to_string()),
            (
                "ghost records",
                format!(
                    "{ghosts}  {}",
                    ui::muted(&format!("listed but uninspectable{}", if ids.len() > 25 { ", sampled 25" } else { "" }))
                ),
            ),
            ("empty names", empty_names.to_string()),
            ("exited(255)", exited_255.to_string()),
            ("rename orphans", format!("{orphans}  {}", ui::muted("<hex>_noo-*"))),
        ])
    );
    println!();
    if !damaged {
        println!("{}", ui::status_line(Glyph::Ok, "no unclean-shutdown damage signature"));
        return Ok(0);
    }
    println!("{}", ui::status_line(Glyph::Err, &format!("unclean-shutdown damage detected  {}", ui::muted("the unclean-shutdown shape"))));

    // The runbook is guidance: stdout, in full (guide rev 2 §5 "Runbooks").
    // Each trap below cost a real debugging hour; the order matters.
    let bullet = |s: &str| println!("{}", ui::status_line(Glyph::Bullet, s));
    let note = |s: &str| println!("{}", ui::note(s));
    let sh = |s: &str| println!("    {}", ui::cmd(s));
    println!("{}", ui::section("1. remove what docker can remove"));
    bullet("orphans go, ghosts stay — this is expected");
    sh("docker ps -aq | xargs -r docker rm -f");
    println!("{}", ui::section("2. purge the ghost records"));
    bullet("stop docker.socket too");
    note("any docker call — yours or a self-heal daemon's — reactivates the daemon mid-wipe");
    sh("sudo systemctl stop docker.socket docker");
    bullet("wipe the container records in a root shell");
    note("`sudo rm -rf <root-dir>/*` silently no-ops: your shell cannot expand that glob, so run it in a root shell");
    sh("sudo sh -c 'rm -rf /var/lib/docker/containers/*'");
    bullet("verify the zero before starting");
    sh("sudo ls /var/lib/docker/containers | wc -l    # must print 0");
    sh("sudo systemctl start docker");
    println!("{}", ui::section("3. if a later build fails with 'parent snapshot ... does not exist'"));
    bullet("prune is not enough — re-pull the base the error names");
    note("re-pulling re-unpacks the layers and recreates the missing snapshots");
    sh("docker builder prune -af && docker pull <base-image-from-the-error>");
    println!("{}", ui::section("4. one clean start"));
    bullet("zero containers means no compose-ownership conflict");
    sh("noo stack start");
    ui::guide(&[
        ("noo doctor docker", "re-run afterwards: must report no damage signature"),
        ("noo stack status", "then confirm every service is Running"),
    ]);
    println!("{}", ui::note("see docs/operating/runbooks/host-updates.md for the host-update practice"));
    Ok(1)
}

// ═══════════════════════════════════════════════════════════════
// `noo doctor privileges`
// ═══════════════════════════════════════════════════════════════

/// Legacy sudoers drop-ins from the `pai-*` era. `prep-host.sh` deletes
/// these on every prep — but prep-host only ever runs on an ENROLLED NODE.
/// A controller was never enrolled, so nothing has ever removed them there:
/// host8 was still carrying `pai-apply` and `pai-node-maintenance` from
/// August on 2026-09-05, both granting NOPASSWD on binaries that no longer
/// exist.
/// `noo-apply` joined this list in the same change that stopped prep-host
/// writing it. Its grant existed for ONE caller — `noo-gate apply` over SSH —
/// and retiring the gate left it with none: `noo-fetch.service` already runs
/// as root and calls the applier directly. A grant whose only consumer is
/// gone is legacy, whatever its name.
const LEGACY_SUDOERS: &[&str] = &[
    "pai-apply",
    "pai-node-maintenance",
    "pai-cluster",
    "noo-apply",
    "noo-cluster",
    "noo-node-maintenance",
];

// What a prepped node is expected to carry: NOTHING. prep-host writes no
// sudoers drop-in at all now, so every name in /etc/sudoers.d is either
// legacy (above) or something this fleet did not put there. There is no
// EXPECTED_SUDOERS constant any more because there is nothing to expect.

/// `noo doctor privileges` — what standing power exists on THIS box.
///
/// Answers "is any over-privilege still installed here?" without needing
/// root: the drop-in NAMES are listed from a world-readable directory, the
/// gate binaries are stat'd, and the SSH surface is read from the user's own
/// files. Reading a drop-in's CONTENTS does need root, so this reports what
/// it can see and hands over the exact command for the rest — the operator
/// drives box state, this only looks.
pub fn doctor_privileges(g: &Globals, args: &[String]) -> Result<i32, Unhandled> {
    if !args.is_empty() {
        return Err(Unhandled);
    }
    let role = crate::role::detect();
    let dropins = sudoers_dropins();
    let legacy: Vec<&String> = dropins
        .iter()
        .filter(|d| LEGACY_SUDOERS.contains(&d.as_str()))
        .collect();
    let unexpected: Vec<&String> = dropins
        .iter()
        .filter(|d| {
            d.as_str() != "README" && !LEGACY_SUDOERS.contains(&d.as_str())
        })
        .collect();
    let gate = std::path::Path::new("/usr/local/bin/noo-gate").exists();
    let apply = std::path::Path::new("/usr/local/bin/noo-apply").exists();
    let keys = authorized_keys();

    if g.json {
        println!(
            "{}",
            serde_json::json!({
                "role": role.label(),
                "sudoers_dropins": dropins,
                "legacy_dropins": legacy,
                "unexpected_dropins": unexpected,
                "noo_gate_installed": gate,
                "noo_apply_installed": apply,
                "authorized_keys": keys.len(),
                "forced_command_keys": keys.iter().filter(|k| k.forced).count(),
            })
        );
        return Ok(if legacy.is_empty() { 0 } else { 1 });
    }

    println!("{}", ui::header("privileges", Some(&role.label())));

    println!("{}", ui::section("sudoers drop-ins"));
    if dropins.is_empty() {
        println!("{}", ui::sub(&ui::muted("none")));
    }
    for d in &dropins {
        let note = if LEGACY_SUDOERS.contains(&d.as_str()) {
            ui::err("legacy — prep-host removes this on nodes, never on a controller")
        } else if d == "README" {
            ui::muted("distro file")
        } else {
            ui::warn("unrecognised — read it and decide")
        };
        println!("{}", ui::item(&format!("{d}  {note}")));
    }

    println!("{}", ui::section("SSH lane"));
    println!(
        "{}",
        ui::item(&format!(
            "noo-gate   {}",
            if gate {
                ui::warn("installed — this box is on the controller-SSH lane")
            } else {
                ui::ok("absent (pull-only)")
            }
        ))
    );
    println!(
        "{}",
        ui::item(&format!(
            "noo-apply  {}",
            if apply { ui::ok("installed") } else { ui::muted("absent") }
        ))
    );
    match keys.len() {
        0 => println!("{}", ui::item(&format!("authorized_keys  {}", ui::ok("empty")))),
        n => {
            println!("{}", ui::item(&format!("authorized_keys  {n} key(s)")));
            for k in &keys {
                let shape = if k.forced {
                    ui::ok("forced-command (shell-less)")
                } else {
                    ui::warn("full shell access")
                };
                println!("{}", ui::sub(&format!("{}  {shape}", k.label)));
            }
        }
    }

    println!();
    if !legacy.is_empty() {
        let names = legacy.iter().map(|s| s.as_str()).collect::<Vec<_>>().join(" ");
        ui::failed(
            &format!("{} legacy drop-in(s) still installed: {names}", legacy.len()),
            None,
        );
        ui::guide(&[(
            "sudo rm -f /etc/sudoers.d/{pai-apply,pai-node-maintenance,pai-cluster}",
            "remove them; they grant NOPASSWD on binaries that no longer exist",
        )]);
        return Ok(1);
    }
    if !unexpected.is_empty() {
        ui::warned(&format!(
            "{} unrecognised drop-in(s); read them with `sudo cat /etc/sudoers.d/<name>`",
            unexpected.len()
        ));
        return Ok(0);
    }
    ui::done("no legacy grants and no unexpected drop-ins on this box");
    Ok(0)
}

/// Drop-in names in `/etc/sudoers.d`. The directory is 0755 on every distro
/// checked, so the NAMES read without root even though the files do not.
fn sudoers_dropins() -> Vec<String> {
    let mut out: Vec<String> = std::fs::read_dir("/etc/sudoers.d")
        .map(|rd| {
            rd.filter_map(|e| e.ok())
                .filter_map(|e| e.file_name().into_string().ok())
                .collect()
        })
        .unwrap_or_default();
    out.sort_unstable();
    out
}

struct AuthKey {
    /// Type plus comment — never the key material, which is long and adds
    /// nothing to the answer.
    label: String,
    /// Pinned to a forced command (`command="…"`), so it cannot open a shell.
    forced: bool,
}

/// This user's `~/.ssh/authorized_keys`, summarised. Root's copy needs root
/// to read; the closing guidance says so rather than pretending it is empty.
fn authorized_keys() -> Vec<AuthKey> {
    let Ok(home) = std::env::var("HOME") else {
        return Vec::new();
    };
    let Ok(body) = std::fs::read_to_string(std::path::PathBuf::from(home).join(".ssh/authorized_keys"))
    else {
        return Vec::new();
    };
    authorized_keys_from(&body)
}

/// The parsing half, split out so it can be tested without a real file.
fn authorized_keys_from(body: &str) -> Vec<AuthKey> {
    body.lines()
        .map(str::trim)
        .filter(|l| !l.is_empty() && !l.starts_with('#'))
        .map(|l| {
            let forced = l.contains("command=\"");
            // Fields are [options] <type> <base64> [comment]. Show the type
            // and the comment; drop the material in between.
            let parts: Vec<&str> = l.split_whitespace().collect();
            let ty = parts
                .iter()
                .find(|p| p.starts_with("ssh-") || p.starts_with("ecdsa-"))
                .copied()
                .unwrap_or("key");
            let comment = parts.last().copied().filter(|c| !c.contains('/') && c.len() < 64);
            let label = match comment {
                Some(c) if c != ty => format!("{ty}  {c}"),
                _ => ty.to_string(),
            };
            AuthKey { label, forced }
        })
        .collect()
}

#[cfg(test)]
mod privilege_tests {
    use super::*;

    fn parse(line: &str) -> AuthKey {
        authorized_keys_from(line).into_iter().next().expect("one key")
    }

    #[test]
    fn a_forced_command_key_is_not_shell_access() {
        // The gate lane pins its key; that is the difference between
        // "the controller can run noo-gate here" and "the controller has
        // a shell here", and the report must not blur them.
        let k = parse(r#"command="/usr/local/bin/noo-gate",restrict ssh-ed25519 <key> fleet@controller"#);
        assert!(k.forced);
        assert!(k.label.contains("ssh-ed25519"));
        assert!(k.label.contains("fleet@controller"));
    }

    #[test]
    fn a_plain_key_is_reported_as_shell_access() {
        let k = parse("ssh-ed25519 <key> operator@laptop");
        assert!(!k.forced);
    }

    #[test]
    fn key_material_never_reaches_the_label() {
        // Placeholder rather than key-shaped base64: the leak scanner
        // rightly objects to the latter even in a test.
        let k = parse("ssh-rsa <key-material-here> operator@laptop");
        assert!(!k.label.contains("key-material"), "label leaked material: {}", k.label);
    }

    #[test]
    fn comments_and_blanks_are_not_keys() {
        assert!(authorized_keys_from("# a comment\n\n   \n").is_empty());
    }

}

// ═══════════════════════════════════════════════════════════════
// `noo doctor orphans`
// ═══════════════════════════════════════════════════════════════

/// One compose-created container, as `docker ps` labelled it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct ComposeContainer {
    pub name: String,
    pub project: String,
    pub service: String,
    pub config_files: String,
    pub working_dir: String,
    pub image: String,
    pub status: String,
}

/// Parse one tab-separated `docker ps --format` row into a compose container.
///
/// Returns `None` for anything WITHOUT a `com.docker.compose.service` label,
/// and that exclusion is the whole check's correctness. The node-agent creates
/// backend containers through the Docker API and stamps them
/// `com.docker.compose.project` so they join the project network — host8
/// 2026-09-13 carries `noo-vllm` with `com.docker.compose.project=pai-assistant`,
/// `noo.managed-by=node-agent-go` and NO service label. Keying on the project
/// label alone would report every vLLM, llama.cpp and Ollama backend in the
/// fleet as an orphan and hand the operator a `docker rm` for a container that
/// is serving traffic. Only compose sets `com.docker.compose.service`.
pub(crate) fn parse_ps_row(line: &str) -> Option<ComposeContainer> {
    let f: Vec<&str> = line.split('\t').collect();
    if f.len() != 7 {
        return None;
    }
    let (name, project, service) = (f[0].trim(), f[1].trim(), f[2].trim());
    if name.is_empty() || project.is_empty() || service.is_empty() {
        return None;
    }
    Some(ComposeContainer {
        name: name.to_string(),
        project: project.to_string(),
        service: service.to_string(),
        config_files: f[3].trim().to_string(),
        working_dir: f[4].trim().to_string(),
        image: f[5].trim().to_string(),
        status: f[6].trim().to_string(),
    })
}

/// Is this a project `noo doctor` should speak about at all?
///
/// A box may run compose projects that are none of our business. The test is
/// deliberately about what the containers ARE, not what the project is called:
/// project name comes from a directory and has already changed once
/// (`pai-assistant` → `noomesh`), so a name allow-list would go stale silently
/// and report nothing — the failure mode that reads as a clean bill of health.
pub(crate) fn is_ours(containers: &[ComposeContainer]) -> bool {
    containers.iter().any(|c| c.name.starts_with("noo-") || c.name.starts_with("pai-"))
}

/// Running compose services that the compose projection no longer declares.
///
/// `declared` must be the FULL service set including every profile. A service
/// gated behind a profile the operator did not activate is still declared —
/// calling it an orphan is how `--remove-orphans` on a partial `up` eats a
/// working vLLM container.
pub(crate) fn orphans_of<'a>(
    running: &'a [ComposeContainer],
    declared: &std::collections::BTreeSet<String>,
) -> Vec<&'a ComposeContainer> {
    running.iter().filter(|c| !declared.contains(&c.service)).collect()
}

/// One line of `config/retired-services.txt`: a compose service the repo
/// removed on purpose and says must stay gone.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct RetiredService {
    pub service: String,
    pub date: String,
    pub pr: String,
}

impl RetiredService {
    /// `service <svc> was retired on <date> (<PR>)`, the sentence the launcher
    /// prints when it removes one.
    pub(crate) fn sentence(&self) -> String {
        format!("service {} was retired on {} ({})", self.service, self.date, self.pr)
    }
}

/// Parse the retired-services list: `<service>  <YYYY-MM-DD>  <PR>` per line,
/// whole-line `#` comments and blank lines ignored (the PR column starts with
/// `#` too, so a comment is only a line that BEGINS with one). A missing date
/// or PR reads as empty rather than hiding the entry.
pub(crate) fn parse_retired_services(text: &str) -> Vec<RetiredService> {
    text.lines()
        .map(str::trim)
        .filter(|l| !l.is_empty() && !l.starts_with('#'))
        .filter_map(|l| {
            let mut it = l.split_whitespace();
            let service = it.next()?.to_string();
            let date = it.next().unwrap_or("").to_string();
            let pr = it.collect::<Vec<_>>().join(" ");
            Some(RetiredService { service, date, pr })
        })
        .collect()
}

/// The list as this install has it: `config/retired-services.txt` under the
/// install root (the file the launcher reads), else the copy embedded in this
/// binary. Err when neither can be read, so a caller never reads "nothing
/// retired" from a list it never saw.
pub(crate) fn retired_services() -> Result<Vec<RetiredService>, String> {
    let path = crate::envfile::repo_root().join("config/retired-services.txt");
    let text = match std::fs::read_to_string(&path) {
        Ok(t) => t,
        Err(e) => crate::onboard::standalone::STANDALONE_ASSETS
            .iter()
            .find(|(rel, _, _)| *rel == "config/retired-services.txt")
            .and_then(|(_, bytes, _)| std::str::from_utf8(bytes).ok().map(str::to_string))
            .ok_or_else(|| format!("{} is unreadable ({e}) and this binary embeds no copy", path.display()))?,
    };
    Ok(parse_retired_services(&text))
}

/// The running containers whose service is on the retired list, paired with
/// their entry. Needs no compose projection: a retired service is wrong
/// whatever the files say.
pub(crate) fn retired_of(
    running: &[ComposeContainer],
    list: &[RetiredService],
) -> Vec<(ComposeContainer, RetiredService)> {
    running
        .iter()
        .filter_map(|c| list.iter().find(|r| r.service == c.service).map(|r| (c.clone(), r.clone())))
        .collect()
}

// ═══════════════════════════════════════════════════════════════
// `noo doctor secrets`
// ═══════════════════════════════════════════════════════════════

/// A short digest, so a report can say "these differ" without printing either.
pub(crate) fn fingerprint(value: &str) -> String {
    use sha2::{Digest, Sha256};
    let d = Sha256::digest(value.as_bytes());
    d.iter().take(5).map(|b| format!("{b:02x}")).collect()
}

/// A container's environment as a map, or None when it is not running here.
fn container_env(name: &str) -> Option<std::collections::BTreeMap<String, String>> {
    let out = std::process::Command::new("docker")
        .args(["inspect", "-f", "{{range .Config.Env}}{{println .}}{{end}}", name])
        .output()
        .ok()?;
    if !out.status.success() {
        return None;
    }
    let mut map = std::collections::BTreeMap::new();
    for line in String::from_utf8_lossy(&out.stdout).lines() {
        if let Some((k, v)) = line.split_once('=') {
            map.insert(k.to_string(), v.to_string());
        }
    }
    Some(map)
}

/// `noo doctor secrets` — do the holders of each secret agree?
///
/// Deliberately NOT a comparison against `.env`. On a SOPS install `.env`
/// carries placeholders and the launcher injects the real values, so
/// comparing against the file reports the whole fleet as stale — which is
/// what the first version of this check did on the controller, and is worse
/// than no check at all.
///
/// Consensus needs no source of truth. A rotation that reached four
/// consumers and missed one leaves exactly one disagreeing value, and that
/// is the shape worth finding: the missed container keeps working until
/// whatever it authenticates to stops accepting the old value, and a refused
/// credential logs nothing.
pub fn doctor_secrets(g: &Globals, args: &[String]) -> Result<i32, Unhandled> {
    if !args.is_empty() {
        return Err(Unhandled);
    }
    println!("{}", ui::header("Secret Agreement", Some("across the containers that hold each")));

    let mut rows: Vec<Vec<String>> = Vec::new();
    let mut split = 0usize;
    let mut checked = 0usize;
    for spec in crate::commands::secrets::registry() {
        // (container, value) for every declared consumer running here.
        let held: Vec<(String, String)> = spec
            .consumers
            .iter()
            .filter_map(|c| {
                let env = container_env(c)?;
                let v = env.get(spec.key)?.clone();
                Some(((*c).to_string(), v))
            })
            .filter(|(_, v)| !v.is_empty())
            .collect();
        if held.len() < 2 {
            continue; // one holder cannot disagree with itself
        }
        checked += 1;
        let verdict = agreement(&held);
        if verdict.is_empty() {
            continue;
        }
        split += 1;
        // Name the minority — the container a rotation most likely missed.
        for (container, fp) in verdict {
            rows.push(vec![
                ui::glyph_cell(Glyph::Err),
                spec.key.to_string(),
                container,
                fp,
                format!("{} holder(s)", held.len()),
            ]);
        }
    }

    if checked == 0 {
        println!("{}", ui::status_line(Glyph::Warn,
            "no secret is held by two or more running consumers here — nothing to compare, \
             which is not the same as nothing wrong"));
        return Ok(0);
    }
    if rows.is_empty() {
        println!("{}", ui::status_line(Glyph::Ok, &format!(
            "{checked} secret(s) checked; every holder of each agrees")));
        return Ok(0);
    }
    print!("{}", ui::table(
        &[Col::left(""), Col::left("secret"), Col::left("container"),
          Col::left("digest"), Col::left("of")],
        &rows,
    ));
    println!();
    println!("{}", ui::status_line(Glyph::Err, &format!(
        "{split} secret(s) have holders that disagree")));
    println!("{}", ui::note(
        "a rotation that did not reach every consumer leaves exactly this. The odd container \
         keeps working until whatever it authenticates to stops accepting the old value, and \
         a refused credential logs nothing",
    ));
    println!("{}", ui::hint("noo stack restart --force"));
    let _ = g;
    Ok(1)
}

/// Containers whose value differs from the majority, with a digest of what
/// each is running. Empty when every holder agrees.
///
/// Values are never returned — only digests — so a report can say "these
/// differ" without putting a secret on a terminal or in a scrollback.
pub(crate) fn agreement(held: &[(String, String)]) -> Vec<(String, String)> {
    use std::collections::HashMap;
    let mut counts: HashMap<&str, usize> = HashMap::new();
    for (_, v) in held {
        *counts.entry(v.as_str()).or_default() += 1;
    }
    if counts.len() < 2 {
        return Vec::new();
    }
    // The majority value; on a tie, no value is the majority and EVERY
    // holder is reported — a 2-2 split has no innocent side to infer.
    let top = counts.iter().max_by_key(|(_, n)| **n).map(|(v, n)| (*v, *n));
    let majority = match top {
        Some((v, n)) if counts.values().filter(|m| **m == n).count() == 1 => Some(v),
        _ => None,
    };
    held.iter()
        .filter(|(_, v)| majority.is_none_or(|m| v.as_str() != m))
        .map(|(c, v)| (c.clone(), fingerprint(v)))
        .collect()
}

/// `noo doctor orphans` — containers compose still runs that compose no
/// longer defines.
///
/// Read-only, and it stays read-only: "no longer declared" and "safe to
/// destroy right now" are different claims, and the second one is the
/// operator's to make (the operator drives box state — this only looks).
///
/// Why it exists: `noo-cluster-executor` was deleted from
/// `docker-compose.cluster.yml` on 2026-09-11 and was still running on
/// host8 on 2026-09-13 — root, `${HOME}/.ssh` mounted, writable PKI, the
/// SSH sidecar that removal existed to retire. `--remove-orphans` is passed
/// on `down` and on none of the `up`/`restart`/`rebuild` paths, so the only
/// verb that clears an orphan is a full stop, which is the one verb a live
/// controller avoids. The repo had a test proving the SSH lane could not come
/// back; it greps our own source, so it could not see a container.
pub fn doctor_orphans(g: &Globals, args: &[String]) -> Result<i32, Unhandled> {
    if !args.is_empty() {
        return Err(Unhandled);
    }

    if !docker_daemon_up() {
        fail(g.json, ExitCode::Generic, "daemon_down",
            "the docker daemon is not answering",
            Some("sudo systemctl start docker — then re-run noo doctor orphans"));
    }

    let OrphanScan { by_project, found, retired, retired_why, unreadable } = scan_orphans();

    if g.json {
        println!("{}", serde_json::json!({
            "status": if !retired.is_empty() { "retired_running" }
                      else if !unreadable.is_empty() || retired_why.is_some() { "unreadable" }
                      else if found.is_empty() { "clean" } else { "orphans" },
            "retired": retired.iter().map(|(c, r)| serde_json::json!({
                "container": c.name, "service": c.service, "project": c.project,
                "retired_on": r.date, "pr": r.pr,
            })).collect::<Vec<_>>(),
            "retired_list_unreadable": retired_why,
            "projects": by_project.keys().collect::<Vec<_>>(),
            "orphans": found.iter().map(|c| serde_json::json!({
                "container": c.name, "service": c.service,
                "project": c.project, "image": c.image, "status": c.status,
            })).collect::<Vec<_>>(),
            "unreadable": unreadable.iter()
                .map(|(p, w)| serde_json::json!({"project": p, "why": w}))
                .collect::<Vec<_>>(),
        }));
        return Ok(if found.is_empty() && retired.is_empty() && unreadable.is_empty() && retired_why.is_none() { 0 } else { 1 });
    }

    println!("{}", ui::header("compose orphans", None));
    if by_project.is_empty() {
        println!("{}", ui::status_line(Glyph::Ok, "no noomesh compose project is running here"));
        return Ok(0);
    }
    print!("{}", ui::kv(&[
        ("projects", by_project.keys().cloned().collect::<Vec<_>>().join(", ")),
        ("compose services running", by_project.values().map(Vec::len).sum::<usize>().to_string()),
        ("orphans", found.len().to_string()),
        ("retired services running", retired.len().to_string()),
    ]));
    println!();

    if let Some(why) = &retired_why {
        println!("{}", ui::status_line(Glyph::Err,
            &format!("could not read config/retired-services.txt: {why}")));
        println!("{}", ui::note("this is NOT a report of no retired services — the list was not compared"));
    }
    for (c, r) in &retired {
        println!("{}", ui::status_line(Glyph::Err, &format!(
            "{} is running although {}", c.name, r.sentence())));
        println!("    {}", ui::cmd(&format!("docker rm -f {}", c.name)));
    }
    if !retired.is_empty() {
        println!("{}", ui::note("a retired service stays gone: the repo removed it on purpose, and the next start removes it too"));
        println!();
    }

    for (project, why) in &unreadable {
        println!("{}", ui::status_line(Glyph::Err,
            &format!("could not read the compose projection for {project}: {why}")));
        println!("{}", ui::note("this is NOT a report of zero orphans — nothing was compared for this project"));
    }

    if found.is_empty() && unreadable.is_empty() {
        if !retired.is_empty() || retired_why.is_some() {
            return Ok(1);
        }
        println!("{}", ui::status_line(Glyph::Ok, "every running compose container is still declared"));
        return Ok(0);
    }

    if !found.is_empty() {
        println!("{}", ui::status_line(Glyph::Err, &format!(
            "{} container(s) running that no compose file declares", found.len())));
        println!("{}", ui::note("compose does not stop a container because its service definition disappeared"));
        println!();
        for c in &found {
            println!("{}", ui::status_line(Glyph::Bullet, &format!(
                "{}  {}", c.name, ui::muted(&format!("service {} · {} · {}", c.service, c.image, c.status)))));
            println!("    {}", ui::cmd(&format!("docker stop {} && docker rm {}", c.name, c.name)));
        }
        println!();
        println!("{}", ui::note("read the container before removing it: an orphan is usually stale, but \
                                 a service removed from compose mid-migration may still be load-bearing"));
        ui::guide(&[
            ("docker inspect <name>", "what it mounts and what it runs, before you decide"),
            ("noo doctor orphans", "re-run afterwards: must report none"),
        ]);
    }
    Ok(1)
}

/// Is the docker daemon answering?
pub(crate) fn docker_daemon_up() -> bool {
    Command::new("docker")
        .args(["version", "--format", "{{.Server.Version}}"])
        .output()
        .map(|o| o.status.success())
        .unwrap_or(false)
}

/// What one pass over the running compose containers found.
pub(crate) struct OrphanScan {
    pub by_project: std::collections::BTreeMap<String, Vec<ComposeContainer>>,
    /// Undeclared containers that are NOT retired services (those are in `retired`).
    pub found: Vec<ComposeContainer>,
    /// Running containers of a service on config/retired-services.txt: FAIL, not WARN.
    pub retired: Vec<(ComposeContainer, RetiredService)>,
    /// Why the retired list could not be read, when it could not. NOT "none retired".
    pub retired_why: Option<String>,
    /// Projects whose projection could not be computed, with why. NOT clean.
    pub unreadable: Vec<(String, String)>,
}

/// The one computation behind `noo doctor orphans` and the `undeclared
/// containers` row of `noo cluster verify --controller`. Assumes the daemon
/// answers (callers check [`docker_daemon_up`] first and say so their way).
pub(crate) fn scan_orphans() -> OrphanScan {
    let fmt = concat!(
        r#"{{.Names}}	{{.Label "com.docker.compose.project"}}	"#,
        r#"{{.Label "com.docker.compose.service"}}	"#,
        r#"{{.Label "com.docker.compose.project.config_files"}}	"#,
        r#"{{.Label "com.docker.compose.project.working_dir"}}	"#,
        r#"{{.Image}}	{{.Status}}"#,
    );
    let running: Vec<ComposeContainer> = docker_lines(&["ps", "--format", fmt])
        .iter()
        .filter_map(|l| parse_ps_row(l))
        .collect();

    let mut by_project: std::collections::BTreeMap<String, Vec<ComposeContainer>> =
        std::collections::BTreeMap::new();
    for c in running {
        by_project.entry(c.project.clone()).or_default().push(c);
    }
    by_project.retain(|_, v| is_ours(v));

    let (list, retired_why) = match retired_services() {
        Ok(l) => (l, None),
        Err(w) => (Vec::new(), Some(w)),
    };
    let mut found: Vec<ComposeContainer> = Vec::new();
    let mut retired: Vec<(ComposeContainer, RetiredService)> = Vec::new();
    let mut unreadable: Vec<(String, String)> = Vec::new();
    for (project, containers) in &by_project {
        retired.extend(retired_of(containers, &list));
        match declared_services(project, containers) {
            Ok(declared) => found.extend(
                orphans_of(containers, &declared)
                    .into_iter()
                    .filter(|c| !list.iter().any(|r| r.service == c.service))
                    .cloned(),
            ),
            // A project whose projection we could not compute is NOT a project
            // with no orphans. R45's lesson: "0 found" from a lookup that never
            // happened is a clean bill of health for a fleet nobody looked at.
            Err(why) => unreadable.push((project.clone(), why)),
        }
    }
    OrphanScan { by_project, found, retired, retired_why, unreadable }
}

/// The compose files whose union decides what is "declared" for a project.
///
/// `labels` is each container's `com.docker.compose.project.config_files`
/// value; `install` is this install's own list (`compose_file_list`). The
/// result is: the install's files in their order, then every label file that
/// `exists` and is not already there. Containers created by different `up`s
/// carry different lists (an add-on's own `up` names its overlay, the core's
/// does not), and the old "first container with a label" rule made the verdict
/// depend on `docker ps` order. Distinct label lists are therefore sorted
/// (longest first, then text) before they contribute, so the answer is the
/// same for any container order.
pub(crate) fn declared_files(
    labels: &[&str],
    install: &[String],
    exists: &dyn Fn(&str) -> bool,
) -> Vec<String> {
    use crate::onboard::sh::normalize_path;
    // Compare paths, not spellings: `/x/./a.yml` from the install list and
    // `/x/a.yml` from a label are one file, and naming it twice makes compose
    // merge it with itself (rc.2: `security_opt array items must be unique`).
    let install: Vec<String> = install.iter().map(|f| normalize_path(f)).collect();
    let mut lists: Vec<Vec<String>> = labels
        .iter()
        .map(|l| {
            l.split(',')
                .map(str::trim)
                .filter(|s| !s.is_empty())
                .map(normalize_path)
                .collect::<Vec<_>>()
        })
        .filter(|v| !v.is_empty())
        .collect();
    lists.sort_by(|a, b| b.len().cmp(&a.len()).then_with(|| a.cmp(b)));
    lists.dedup();
    let mut out: Vec<String> = Vec::new();
    for f in install.iter().chain(lists.iter().flatten()) {
        if !out.contains(f) && (install.contains(f) || exists(f)) {
            out.push(f.clone());
        }
    }
    out
}

/// Every service the project's compose files declare, across EVERY profile.
///
/// Two flags carry the whole correctness argument. `--project-directory` makes
/// relative paths and `.env` resolve the way they did at `up` time, and the
/// `--profile` fan-out (from `config --profiles`) is what stops a
/// profile-gated service reading as undeclared. The files are the union
/// [`declared_files`] describes, never one container's label alone.
fn declared_services(
    project: &str,
    containers: &[ComposeContainer],
) -> Result<std::collections::BTreeSet<String>, String> {
    let labels: Vec<&str> = containers.iter().map(|c| c.config_files.as_str()).collect();
    // The install's own list belongs to the install's project: when
    // COMPOSE_PROJECT_NAME names another one, do not blend it in.
    let install: Vec<String> = match std::env::var("COMPOSE_PROJECT_NAME") {
        Ok(p) if !p.is_empty() && p != project => Vec::new(),
        _ => crate::onboard::sh::install_compose_files(&crate::envfile::repo_root())
            .into_iter()
            .filter(|f| std::path::Path::new(f).is_file())
            .collect(),
    };
    let files = declared_files(&labels, &install, &|f| std::path::Path::new(f).is_file());
    if files.is_empty() {
        return Err("no compose file of this project is on this box (the config_files labels name none that exist)".into());
    }
    // Deterministic whichever container docker listed first.
    let working_dir = containers
        .iter()
        .map(|c| c.working_dir.as_str())
        .filter(|w| !w.is_empty())
        .min()
        .unwrap_or("")
        .to_string();

    let base = |extra: &[&str]| -> Vec<String> {
        let mut a: Vec<String> = vec!["compose".into(), "--project-name".into(), project.into()];
        if !working_dir.is_empty() {
            a.push("--project-directory".into());
            a.push(working_dir.clone());
        }
        for f in &files {
            a.push("-f".into());
            a.push(f.clone());
        }
        a.extend(extra.iter().map(|s| (*s).to_string()));
        a
    };

    let run = |a: Vec<String>| -> Result<Vec<String>, String> {
        let out = Command::new("docker").args(&a).output()
            .map_err(|e| format!("docker compose did not run: {e}"))?;
        if !out.status.success() {
            let err = String::from_utf8_lossy(&out.stderr);
            return Err(err.lines().last().unwrap_or("compose config failed").trim().to_string());
        }
        Ok(String::from_utf8_lossy(&out.stdout)
            .lines()
            .map(|l| l.trim().to_string())
            .filter(|l| !l.is_empty())
            .collect())
    };

    let profiles = run(base(&["config", "--profiles"]))?;
    let mut with_profiles: Vec<&str> = Vec::new();
    for p in &profiles {
        with_profiles.push("--profile");
        with_profiles.push(p);
    }
    with_profiles.push("config");
    with_profiles.push("--services");
    Ok(run(base(&with_profiles))?.into_iter().collect())
}

#[cfg(test)]
mod orphan_tests {
    use super::*;
    use std::collections::BTreeSet;

    fn row(name: &str, project: &str, service: &str) -> String {
        format!("{name}\t{project}\t{service}\t/opt/noo/docker-compose.cluster.yml\t/opt/noo\timg:1\tUp 2 days")
    }

    /// The real host8 row, 2026-09-13: the node-agent stamps the PROJECT
    /// label so its backend joins the network, and sets no service label.
    /// If this ever parses, `noo doctor orphans` tells the operator to
    /// `docker rm` a vLLM that is serving traffic.
    #[test]
    fn a_node_agent_backend_is_not_a_compose_container() {
        let line = "noo-vllm\tpai-assistant\t\t\t\tvllm/vllm-openai:v0.29.0\tUp 27 minutes";
        assert!(
            parse_ps_row(line).is_none(),
            "a container with no com.docker.compose.service label must not be classified"
        );
    }

    #[test]
    fn a_compose_container_parses_with_its_service() {
        let c = parse_ps_row(&row("noo-gateway", "noomesh", "gateway")).expect("should parse");
        assert_eq!(c.service, "gateway");
        assert_eq!(c.project, "noomesh");
        assert_eq!(c.working_dir, "/opt/noo");
    }

    #[test]
    fn a_short_row_is_not_guessed_at() {
        assert!(parse_ps_row("noo-gateway\tnoomesh\tgateway").is_none());
    }

    /// The 2026-09-13 finding, as an assertion.
    #[test]
    fn a_service_deleted_from_compose_is_an_orphan() {
        let running = vec![
            parse_ps_row(&row("noo-gateway", "noomesh", "gateway")).unwrap(),
            parse_ps_row(&row("noo-cluster-executor", "noomesh", "cluster-executor")).unwrap(),
        ];
        let declared: BTreeSet<String> = ["gateway", "postgres"].iter().map(|s| s.to_string()).collect();
        let found = orphans_of(&running, &declared);
        assert_eq!(found.len(), 1);
        assert_eq!(found[0].name, "noo-cluster-executor");
    }

    /// Why `declared_services` fans out over `config --profiles`. A service
    /// behind an inactive profile is DECLARED; reporting it is how an
    /// operator gets told to delete a working backend.
    #[test]
    fn a_profile_gated_service_is_not_an_orphan() {
        let running = vec![parse_ps_row(&row("noo-vllm-svc", "noomesh", "vllm")).unwrap()];
        let declared: BTreeSet<String> =
            ["gateway", "vllm"].iter().map(|s| s.to_string()).collect();
        assert!(
            orphans_of(&running, &declared).is_empty(),
            "a profile-gated service is declared even when its profile is off"
        );
    }

    /// The orphan verdict must not depend on which container docker lists
    /// first. An add-on's own `up` stamps its overlay on ITS containers; the
    /// old code read the first labelled container only. Fails on that code:
    /// the overlay file was in or out of the set by order alone.
    #[test]
    fn declared_files_do_not_depend_on_container_order() {
        let core = "/o/base.yml,/o/override.yml";
        let addon = "/o/base.yml,/o/override.yml,/o/addon.yml";
        let exists = |_: &str| true;
        let a = declared_files(&[core, addon], &[], &exists);
        let b = declared_files(&[addon, core], &[], &exists);
        assert_eq!(a, b);
        assert_eq!(a, vec!["/o/base.yml", "/o/override.yml", "/o/addon.yml"]);
    }

    #[test]
    fn declared_files_union_the_install_list_and_skip_gone_label_files() {
        let install = vec!["/o/base.yml".to_string(), "/o/gpu.yml".to_string()];
        let exists = |f: &str| f != "/o/gone.yml";
        let got = declared_files(&["/o/base.yml,/o/gone.yml,/o/addon.yml", ""], &install, &exists);
        assert_eq!(got, vec!["/o/base.yml", "/o/gpu.yml", "/o/addon.yml"]);
    }

    /// rc.2 (Part B): `compose_file_list .` gave `./docker-compose.cluster.yml`,
    /// the install list became `/root/.noo/./docker-compose.cluster.yml`, the
    /// label said `/root/.noo/docker-compose.cluster.yml`, and the string
    /// dedup kept both, so compose read the file twice. Fails on that code.
    #[test]
    fn one_file_spelled_two_ways_is_declared_once() {
        let install = vec!["/x/./a.yml".to_string(), "/x//b.yml".to_string()];
        let got = declared_files(&["/x/a.yml,/x/b.yml,/x/c/../c.yml"], &install, &|_| true);
        assert_eq!(got, vec!["/x/a.yml", "/x/b.yml", "/x/c.yml"]);
    }

    #[test]
    fn no_labels_and_no_install_list_declares_nothing() {
        assert!(declared_files(&["", " "], &[], &|_| true).is_empty());
    }

    #[test]
    fn the_retired_list_parses_comments_and_columns() {
        let got = parse_retired_services(
            "# header\n\ncluster-executor  2026-09-11  #98\nfoo 2026-01-02 #1\n  \nbare\n");
        assert_eq!(got.len(), 3);
        assert_eq!(got[0], RetiredService {
            service: "cluster-executor".into(), date: "2026-09-11".into(), pr: "#98".into() });
        assert_eq!(got[2].service, "bare");
        assert_eq!(got[2].date, "");
    }

    #[test]
    fn the_shipped_retired_list_names_cluster_executor() {
        let got = parse_retired_services(include_str!("../../../config/retired-services.txt"));
        assert!(got.iter().any(|r| r.service == "cluster-executor" && r.date == "2026-09-11"), "{got:?}");
    }

    #[test]
    fn a_running_retired_service_is_found_and_only_that() {
        let running = vec![
            parse_ps_row(&row("noo-gateway", "noomesh", "gateway")).unwrap(),
            parse_ps_row(&row("noo-cluster-executor", "noomesh", "cluster-executor")).unwrap(),
        ];
        let list = parse_retired_services("cluster-executor  2026-09-11  #98\n");
        let got = retired_of(&running, &list);
        assert_eq!(got.len(), 1);
        assert_eq!(got[0].0.name, "noo-cluster-executor");
        assert_eq!(got[0].1.sentence(), "service cluster-executor was retired on 2026-09-11 (#98)");
        assert!(retired_of(&running, &[]).is_empty());
    }

    #[test]
    fn a_foreign_project_is_left_alone() {
        let theirs = vec![parse_ps_row(&row("wordpress", "blog", "web")).unwrap()];
        assert!(!is_ours(&theirs));
        let ours = vec![parse_ps_row(&row("noo-gateway", "noomesh", "gateway")).unwrap()];
        assert!(is_ours(&ours));
    }
}

// ═══════════════════════════════════════════════════════════════
// `noo doctor exposure`
// ═══════════════════════════════════════════════════════════════

// ── The tailnet bind and the boot race ─────────────────

/// Where the sysctl that makes a tailnet bind survive a reboot lives.
pub(crate) const NONLOCAL_BIND_DROPIN: &str = "/etc/sysctl.d/60-noo-tailnet-bind.conf";

/// The one command that fixes the boot race, printed wherever it is found.
pub(crate) fn nonlocal_bind_fix() -> String {
    format!(
        "echo 'net.ipv4.ip_nonlocal_bind=1' | sudo tee {NONLOCAL_BIND_DROPIN} && sudo sysctl -p {NONLOCAL_BIND_DROPIN}"
    )
}

/// `net.ipv4.ip_nonlocal_bind` on this host. `None` where there is no such
/// file (macOS, a container without /proc/sys) — unknown, never "fine".
pub(crate) fn nonlocal_bind_enabled() -> Option<bool> {
    std::fs::read_to_string("/proc/sys/net/ipv4/ip_nonlocal_bind")
        .ok()
        .map(|v| v.trim() == "1")
}

/// Would a reboot leave published ports unbound?
///
/// A port bound to a specific address (the tailnet IP, or a pinned one) can
/// only be bound once that address exists. `docker.service` waits for
/// `network-online.target`, not for `tailscaled` — so on a boot where Docker
/// restarts the stack first, every tailnet-bound port fails with `cannot
/// assign requested address` and the gateway, NATS and the model cache do
/// not start. `ip_nonlocal_bind=1` lets the bind succeed before the address
/// is up. Found switching the controller to tailnet mode on 2026-09-24,
/// where the two services started 7–9 s apart in tailscaled's favour — luck,
/// not ordering.
///
/// Judged on what is ACTUALLY bound, not on NOO_BIND_MODE: a pinned
/// NOO_BIND_ADDR has the same race, and a mode nobody applied has none.
pub(crate) fn boot_race(published: &[Published], nonlocal: Option<bool>) -> bool {
    nonlocal == Some(false)
        && published.iter().any(|p| matches!(p.reach, Reach::Tailnet | Reach::Address(_)))
}

/// NOO_BIND_MODE as the launcher resolves it: the environment, then `.env`
/// (the launcher reads the file by hand — `.env` is not in the CLI's
/// environment, which is why this used to report "unset" on a controller
/// whose .env said `tailnet`).
/// What `doctor exposure` says when a port is open and `NOO_BIND_MODE` is
/// unset. The launcher REFUSES an unset mode (`scripts/lib-bind-addr.sh`,
// So a running stack in that state was started by an
/// older launcher, or with `NOO_BIND_ADDR` set explicitly. It used to
/// print "the launcher used its default: all (0.0.0.0)" — a default that no
/// longer exists.
pub(crate) const UNSET_BIND_MODE_NOTE: &str =
    "NOO_BIND_MODE is unset. The launcher now refuses to start without it, so these ports were \
     published by an older launcher (the retired `all` default) or by an explicit NOO_BIND_ADDR. \
     The next start will stop until NOO_BIND_MODE is set";

pub(crate) fn bind_mode_setting() -> String {
    if let Ok(v) = std::env::var("NOO_BIND_MODE") {
        if !v.trim().is_empty() {
            return v.trim().to_string();
        }
    }
    let env = crate::envfile::repo_root().join(".env");
    crate::onboard::env::read_env_key(&env, "NOO_BIND_MODE")
}

/// Which interface a published port is reachable on.
///
/// The distinction the mesh cares about is not "is there a firewall" but
/// "can something that is not on the tailnet reach this". `0.0.0.0` means
/// yes — every LAN host, and anything routed to this machine.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum Reach {
    /// `0.0.0.0` / `[::]` — every interface. The tailnet ACL governs one
    /// door; this port has a second one that it does not govern.
    AnyInterface,
    /// A 100.64.0.0/10 address — the tailnet, where the ACL applies.
    Tailnet,
    /// `127.0.0.1` / `[::1]` — this machine only.
    Loopback,
    /// A literal address that is neither of the above (a LAN IP an operator
    /// pinned deliberately). Named, never assumed safe.
    Address(String),
}

/// One published port, as `docker ps` reports it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Published {
    pub container: String,
    pub host_ip: String,
    pub host_port: String,
    pub reach: Reach,
}

pub(crate) fn classify_reach(ip: &str) -> Reach {
    let bare = ip.trim_matches(|c| c == '[' || c == ']');
    if bare == "0.0.0.0" || bare == "::" {
        return Reach::AnyInterface;
    }
    if bare == "127.0.0.1" || bare == "::1" || bare.starts_with("127.") {
        return Reach::Loopback;
    }
    // Tailscale's CGNAT range, 100.64.0.0/10 — the same test
    // `scripts/lib-bind-addr.sh` uses to auto-detect this node's tailnet IP.
    let octets: Vec<&str> = bare.split('.').collect();
    if octets.len() == 4 {
        if let (Ok(a), Ok(b)) = (octets[0].parse::<u16>(), octets[1].parse::<u16>()) {
            if a == 100 && (64..=127).contains(&b) {
                return Reach::Tailnet;
            }
        }
    }
    Reach::Address(bare.to_string())
}

/// Parse one `docker ps --format '{{.Names}}\t{{.Ports}}'` row.
///
/// The Ports cell is a comma-separated list, and only the entries carrying
/// `->` are PUBLISHED — `8080/tcp` on its own is a container port exposed to
/// the docker network and reachable from nothing outside it. Counting those
/// would report every service as exposed and teach the reader to ignore this
/// command.
pub(crate) fn parse_published(line: &str) -> Vec<Published> {
    let mut out = Vec::new();
    let (name, ports) = match line.split_once('\t') {
        Some((n, p)) => (n.trim(), p.trim()),
        None => return out,
    };
    if name.is_empty() || ports.is_empty() {
        return out;
    }
    for part in ports.split(',') {
        let part = part.trim();
        let Some((host, _container)) = part.split_once("->") else { continue };
        // host is `0.0.0.0:8080` or `[::]:8080` or `100.64.0.12:4222`
        let Some(colon) = host.rfind(':') else { continue };
        let (ip, port) = host.split_at(colon);
        let port = port.trim_start_matches(':');
        if ip.is_empty() || port.is_empty() {
            continue;
        }
        out.push(Published {
            container: name.to_string(),
            host_ip: ip.trim_matches(|c| c == '[' || c == ']').to_string(),
            host_port: port.to_string(),
            reach: classify_reach(ip),
        });
    }
    out
}

/// Is this one of OUR containers? A box may publish ports we have no opinion
/// about. Same test `doctor orphans` uses, for the same reason: a name
/// prefix is what we can actually claim.
pub(crate) fn is_our_container(container: &str) -> bool {
    container.starts_with("noo-") || container.starts_with("pai-")
}

/// `noo doctor exposure` — which of this box's published ports are reachable
/// from outside the tailnet.
///
/// Read-only, and it names a knob rather than turning one: the bind address
/// is a property of how the stack was launched, so changing it is a declared
/// value plus a recreate, which is the operator's call.
///
/// Why it exists: `docker-compose.cluster.yml:110` publishes the gateway as
/// `${NOO_BIND_ADDR:-0.0.0.0}:8080`, and `NOO_BIND_MODE` defaults to `all`.
/// The default is deliberate and non-breaking — but nothing in onboarding
/// offers the tailnet mode and no check ever mentioned it, so an install that
/// never chose is indistinguishable from one that chose `all` on purpose.
/// Found 2026-09-18 while chasing the trellion-intel 401 burst: a LAN address
/// held nine connections to `:8080`, which the tailnet ACL does not govern.
pub fn doctor_exposure(g: &Globals, args: &[String]) -> Result<i32, Unhandled> {
    if !args.is_empty() {
        return Err(Unhandled);
    }
    let daemon_ok = Command::new("docker")
        .args(["version", "--format", "{{.Server.Version}}"])
        .output()
        .map(|o| o.status.success())
        .unwrap_or(false);
    if !daemon_ok {
        fail(g.json, ExitCode::Generic, "daemon_down",
            "the docker daemon is not answering",
            Some("sudo systemctl start docker — then re-run noo doctor exposure"));
    }

    let rows = docker_lines(&["ps", "--format", "{{.Names}}\t{{.Ports}}"]);
    let mut published: Vec<Published> = rows
        .iter()
        .flat_map(|l| parse_published(l))
        .filter(|p| is_our_container(&p.container))
        .collect();
    published.sort_by(|a, b| (&a.container, &a.host_port).cmp(&(&b.container, &b.host_port)));
    published.dedup();

    let open: Vec<&Published> = published.iter().filter(|p| p.reach == Reach::AnyInterface).collect();
    let bind_mode = bind_mode_setting();
    let nonlocal = nonlocal_bind_enabled();
    let race = boot_race(&published, nonlocal);

    if g.json {
        println!("{}", serde_json::json!({
            "status": if open.is_empty() { "confined" } else { "any_interface" },
            "bind_mode": if bind_mode.is_empty() { serde_json::Value::Null } else { bind_mode.clone().into() },
            "ip_nonlocal_bind": nonlocal,
            "boot_safe": if nonlocal.is_none() { serde_json::Value::Null } else { (!race).into() },
            "published": published.iter().map(|p| serde_json::json!({
                "container": p.container, "host_ip": p.host_ip, "host_port": p.host_port,
                "reach": match &p.reach {
                    Reach::AnyInterface => "any-interface".to_string(),
                    Reach::Tailnet => "tailnet".to_string(),
                    Reach::Loopback => "loopback".to_string(),
                    Reach::Address(a) => format!("address:{a}"),
                },
            })).collect::<Vec<_>>(),
        }));
        return Ok(if open.is_empty() && !race { 0 } else { 1 });
    }

    println!("{}", ui::header("port exposure", None));
    if published.is_empty() {
        println!("{}", ui::status_line(Glyph::Ok, "no noomesh container publishes a host port here"));
        return Ok(0);
    }
    let rows: Vec<Vec<String>> = published
        .iter()
        .map(|p| {
            let (glyph, label) = match &p.reach {
                Reach::AnyInterface => (Glyph::Err, ui::warn("ANY interface")),
                Reach::Tailnet => (Glyph::Ok, ui::muted("tailnet")),
                Reach::Loopback => (Glyph::Ok, ui::muted("loopback")),
                Reach::Address(a) => (Glyph::Warn, ui::warn(&format!("pinned {a}"))),
            };
            vec![ui::glyph_cell(glyph), p.container.clone(), p.host_port.clone(), p.host_ip.clone(), label]
        })
        .collect();
    print!("{}", ui::table(
        &[Col::left(""), Col::left("container"), Col::left("port"), Col::left("bound to"), Col::left("reachable from")],
        &rows,
    ));
    println!();

    if race {
        println!("{}", ui::status_line(Glyph::Err,
            "a reboot can leave these ports unbound: they bind a specific address, and ip_nonlocal_bind is 0"));
        println!("{}", ui::note(
            "docker.service does not wait for tailscaled. On a boot where Docker restarts the stack first, \
             the tailnet address does not exist yet and every port bound to it fails — the gateway, NATS \
             and the model cache stay down until someone restarts the stack."
        ));
        let fix = nonlocal_bind_fix();
        ui::guide(&[(fix.as_str(), "lets the bind succeed before the address is up; survives reboots")]);
        println!();
    }
    if open.is_empty() {
        if race {
            return Ok(1);
        }
        println!("{}", ui::status_line(Glyph::Ok, "every published port is confined to the tailnet or this machine"));
        return Ok(0);
    }
    println!("{}", ui::status_line(Glyph::Err, &format!(
        "{} port(s) are reachable from ANY interface — the tailnet policy governs one door, and these have a second",
        open.len()
    )));
    println!("{}", ui::note(
        "config/tailscale-acl.hujson decides who may reach these ports OVER THE TAILNET. It says nothing \
         about the LAN, so any host on the local network can reach them directly."
    ));
    println!();
    if bind_mode.is_empty() {
        println!("{}", ui::note(UNSET_BIND_MODE_NOTE));
    } else {
        println!("{}", ui::note(&format!("NOO_BIND_MODE={bind_mode}")));
    }
    ui::guide(&[
        ("NOO_BIND_MODE=tailnet in .env, then noo stack restart --force",
         "binds every cluster-plane port to this node's own tailnet IP (scripts/lib-bind-addr.sh auto-detects it)"),
        ("noo doctor exposure",
         "re-run afterwards: every row should read tailnet or loopback"),
    ]);
    println!("{}", ui::muted(
        "a deliberate `all` is a valid choice — this command exists so it is a choice rather than a default nobody saw"
    ));
    Ok(1)
}

#[cfg(test)]
mod exposure_tests {
    use super::*;

    /// The unset-mode note must not describe the retired
    /// `all` default as current, and must name the refusal.
    #[test]
    fn the_unset_note_names_the_refusal_not_a_default() {
        assert!(!UNSET_BIND_MODE_NOTE.contains("used its default"), "{UNSET_BIND_MODE_NOTE}");
        assert!(UNSET_BIND_MODE_NOTE.contains("refuses"), "{UNSET_BIND_MODE_NOTE}");
        assert!(UNSET_BIND_MODE_NOTE.contains("NOO_BIND_ADDR"), "{UNSET_BIND_MODE_NOTE}");
        let launcher = include_str!("../../../scripts/lib-bind-addr.sh");
        assert!(
            launcher.contains("NOO_BIND_MODE is not set") && launcher.contains("refusing to start"),
            "the launcher no longer refuses an unset NOO_BIND_MODE; this note would now be wrong"
        );
    }

    /// The real gateway row on host8, 2026-09-18. Both families, one port.
    fn row(ip: &str) -> Published {
        Published { container: "noo-gateway".into(), host_ip: ip.into(), host_port: "8080".into(), reach: classify_reach(ip) }
    }

    /// host8 on 2026-09-24 before the sysctl: tailnet-bound, nonlocal 0.
    #[test]
    fn a_tailnet_bind_without_nonlocal_bind_races_the_boot() {
        assert!(boot_race(&[row("100.64.0.12"), row("127.0.0.1")], Some(false)));
        assert!(!boot_race(&[row("100.64.0.12")], Some(true)), "the sysctl is the fix");
        assert!(!boot_race(&[row("100.64.0.12")], None), "unknown is not a verdict");
    }

    /// 0.0.0.0 and loopback always exist at boot: no race, whatever the sysctl.
    #[test]
    fn wildcard_and_loopback_binds_never_race() {
        assert!(!boot_race(&[row("0.0.0.0"), row("127.0.0.1")], Some(false)));
    }

    /// A pinned LAN address has the same race as the tailnet IP.
    #[test]
    fn a_pinned_address_races_too() {
        assert!(boot_race(&[row("192.0.2.10")], Some(false)));
    }

    #[test]
    fn the_fix_names_the_dropin_and_applies_it() {
        let f = nonlocal_bind_fix();
        assert!(f.contains("net.ipv4.ip_nonlocal_bind=1") && f.contains(NONLOCAL_BIND_DROPIN) && f.contains("sysctl -p"));
    }

    #[test]
    fn the_gateway_row_reads_as_any_interface() {
        let p = parse_published("noo-gateway\t0.0.0.0:8080->8080/tcp, [::]:8080->8080/tcp");
        assert_eq!(p.len(), 2, "{p:?}");
        assert!(p.iter().all(|x| x.reach == Reach::AnyInterface));
        assert_eq!(p[0].host_port, "8080");
    }

    /// A container port with no `->` is reachable only on the docker network.
    /// Counting it would mark every service exposed and make the command noise.
    #[test]
    fn an_unpublished_container_port_is_not_exposure() {
        assert!(parse_published("noo-trellion\t3100/tcp").is_empty());
        assert!(parse_published("noo-vllm\t").is_empty());
        assert!(parse_published("noo-redis").is_empty());
    }

    /// SYNTHETIC input, and deliberately so. Docker never prints a colon
    /// without an arrow, so for every real row the `->` check and the
    /// `rfind(':')` check reject exactly the same things and no live sample
    /// can tell them apart — a planted removal of the `->` guard passed the
    /// test above for that reason. This row exists to pin the INTENT: only a
    /// mapping is a publication. Without the guard it parses as a port
    /// exposed on every interface.
    #[test]
    fn a_mapping_is_required_not_merely_an_address() {
        assert!(
            parse_published("noo-x\t[::]:9999/tcp").is_empty(),
            "an address with no `->` mapping must not count as published"
        );
    }

    #[test]
    fn a_tailnet_bound_port_is_confined() {
        let p = parse_published("noo-nats\t100.64.0.12:4222->4222/tcp");
        assert_eq!(p[0].reach, Reach::Tailnet);
        // The boundaries of 100.64.0.0/10 — 100.63 and 100.128 are NOT tailnet.
        assert_eq!(classify_reach("100.64.0.1"), Reach::Tailnet);
        assert_eq!(classify_reach("100.127.255.254"), Reach::Tailnet);  // leak-ok: CGNAT range-edge test, not a real node
        assert_eq!(classify_reach("100.63.0.1"), Reach::Address("100.63.0.1".into()));  // leak-ok: CGNAT range-edge test, not a real node
        assert_eq!(classify_reach("100.128.0.1"), Reach::Address("100.128.0.1".into()));  // leak-ok: CGNAT range-edge test, not a real node
    }

    #[test]
    fn loopback_is_confined_and_a_lan_pin_is_named() {
        assert_eq!(classify_reach("127.0.0.1"), Reach::Loopback);
        assert_eq!(classify_reach("[::1]"), Reach::Loopback);
        assert_eq!(classify_reach("192.0.2.10"), Reach::Address("192.0.2.10".into()));
    }

    /// A box may run containers that are not ours; we have no opinion on them.
    #[test]
    fn a_foreign_container_is_left_alone() {
        assert!(!is_our_container("wordpress"));
        assert!(is_our_container("noo-gateway"));
    }

    /// The MCP park port is published on loopback ON PURPOSE
    /// (docker-compose.cluster.yml). It must not read as a finding.
    #[test]
    fn the_loopback_park_port_is_not_a_finding() {
        let p = parse_published("noo-trellion\t127.0.0.1:3199->3100/tcp");
        assert_eq!(p[0].reach, Reach::Loopback);
        assert_ne!(p[0].reach, Reach::AnyInterface);
    }
}

// ═══════════════════════════════════════════════════════════════
// `noo doctor strangers`
// ═══════════════════════════════════════════════════════════════

/// What a source address of a gateway request turned out to be.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum Caller {
    /// This machine.
    Loopback,
    /// A container on a docker network here, named.
    Container(String),
    /// A docker container whose address we could not map to a name — still
    /// local, still not a stranger, but say so rather than imply certainty.
    UnmappedContainer,
    /// A tailnet peer, named. Every mesh node is one.
    TailnetPeer(String),
    /// In 100.64.0.0/10 but not a peer this machine knows. A device on the
    /// tailnet that tailscale has not told us about, or a stale address.
    UnknownTailnet,
    /// An RFC 1918 address on a box that has NO tailnet. A LAN-only install
    /// (the wizard's "continue as LAN-only" answer) is reached from the LAN
    /// by design; calling its operator's laptop a stranger failed `cluster
    /// verify` on every such install (2026-09-24). Still worth a warning:
    /// nothing governs this path but the LAN itself.
    Lan,
    /// Anything else — a LAN host, or something routed here. The tailnet ACL
    /// does not govern this path.
    Stranger,
}

/// Everything this machine knows about who might legitimately call.
#[derive(Debug, Default, Clone)]
pub(crate) struct Known {
    /// tailnet IP → peer name (including this machine).
    pub tailnet: std::collections::BTreeMap<String, String>,
    /// container IP → container name, across every docker network.
    pub containers: std::collections::BTreeMap<String, String>,
}

/// Classify one peer address. Pure: the lookups are gathered separately, so
/// the decision can be tested without a daemon or a tailnet.
pub(crate) fn classify_caller(ip: &str, known: &Known) -> Caller {
    let bare = ip.trim_matches(|c| c == '[' || c == ']');
    if bare == "::1" || bare.starts_with("127.") {
        return Caller::Loopback;
    }
    if let Some(name) = known.containers.get(bare) {
        return Caller::Container(name.clone());
    }
    if let Some(name) = known.tailnet.get(bare) {
        return Caller::TailnetPeer(name.clone());
    }
    let octets: Vec<&str> = bare.split('.').collect();
    if octets.len() == 4 {
        if let (Ok(a), Ok(b)) = (octets[0].parse::<u16>(), octets[1].parse::<u16>()) {
            // Same CGNAT test as classify_reach and lib-bind-addr.sh.
            if a == 100 && (64..=127).contains(&b) {
                return Caller::UnknownTailnet;
            }
            // RFC 1918 172.16/12 is where docker's default bridges live. An
            // address there that we could not map is still a local container
            // — calling it a stranger would cry wolf on every install whose
            // network inspect we could not read.
            if a == 172 && (16..=31).contains(&b) {
                return Caller::UnmappedContainer;
            }
            // With no tailnet on this box there is no ACL for a LAN address
            // to be outside of. With one, a LAN caller is the 276 finding.
            if known.tailnet.is_empty() && (a == 10 || (a == 192 && b == 168)) {
                return Caller::Lan;
            }
        }
    }
    Caller::Stranger
}

/// Pull `peer` out of one gateway request log line.
///
/// The gateway logs JSON, but the line arrives wrapped in docker's own
/// timestamp and the field order is not guaranteed, so this looks for the
/// key rather than deserialising a shape that may grow a field tomorrow.
/// The `status` field of one request log line.
pub(crate) fn status_of(line: &str) -> Option<u16> {
    let at = line.find("\"status\":")?;
    let rest = &line[at + "\"status\":".len()..];
    let digits: String = rest.chars().take_while(|c| c.is_ascii_digit()).collect();
    digits.parse().ok()
}

/// A refusal: the gateway answered and said no to the credential or the
/// quota. Not a 404 (wrong path) and not a 5xx (the gateway's own fault).
pub(crate) fn is_refusal(status: u16) -> bool {
    matches!(status, 401 | 403 | 429)
}

/// A storm: enough refusals to be a loop, and most of what the peer sent.
/// 100 refusals in a window is a human retrying nothing; the share keeps a
/// busy healthy caller with a few 429s out of it.
pub(crate) fn is_refusal_storm(requests: usize, refused: usize) -> bool {
    refused >= 100 && refused * 10 >= requests * 9
}

/// The caller of one request line: the gateway's resolved `client` when it
/// differs from the socket peer (a trusted proxy vouched for it — Tailscale
/// Serve), else the peer.
pub(crate) fn caller_of(line: &str) -> Option<String> {
    let peer = peer_of(line)?;
    match field_of(line, "client") {
        Some(c) if c != peer && c != "unknown" && c != "-" => Some(c),
        _ => Some(peer),
    }
}

fn field_of(line: &str, name: &str) -> Option<String> {
    let key = format!("\"{name}\":");
    let at = line.find(&key)?;
    let rest = &line[at + key.len()..];
    let start = rest.find('"')? + 1;
    let end = rest[start..].find('"')? + start;
    Some(rest[start..end].to_string())
}

pub(crate) fn peer_of(line: &str) -> Option<String> {
    let at = line.find("\"peer\":")?;
    let rest = &line[at + "\"peer\":".len()..];
    let start = rest.find('"')? + 1;
    let end = rest[start..].find('"')? + start;
    let v = &rest[start..end];
    // `-` is what the logger writes when ConnectInfo gave no address.
    if v.is_empty() || v == "-" { None } else { Some(v.to_string()) }
}

fn tailnet_peers() -> std::collections::BTreeMap<String, String> {
    let mut out = std::collections::BTreeMap::new();
    let Ok(o) = Command::new("tailscale").args(["status", "--json"]).output() else {
        return out;
    };
    if !o.status.success() {
        return out;
    }
    let Ok(v) = serde_json::from_slice::<serde_json::Value>(&o.stdout) else {
        return out;
    };
    let mut add = |node: &serde_json::Value| {
        let name = node.get("HostName").and_then(|h| h.as_str()).unwrap_or("?").to_string();
        if let Some(ips) = node.get("TailscaleIPs").and_then(|i| i.as_array()) {
            for ip in ips.iter().filter_map(|i| i.as_str()) {
                out.insert(ip.to_string(), name.clone());
            }
        }
    };
    if let Some(s) = v.get("Self") {
        add(s);
    }
    if let Some(peers) = v.get("Peer").and_then(|p| p.as_object()) {
        for p in peers.values() {
            add(p);
        }
    }
    out
}

fn container_addresses() -> std::collections::BTreeMap<String, String> {
    let mut out = std::collections::BTreeMap::new();
    for net in docker_lines(&["network", "ls", "--format", "{{.Name}}"]) {
        for line in docker_lines(&[
            "network",
            "inspect",
            &net,
            "--format",
            "{{range .Containers}}{{.IPv4Address}} {{.Name}}{{println}}{{end}}",
        ]) {
            let mut it = line.split_whitespace();
            let (Some(cidr), Some(name)) = (it.next(), it.next()) else { continue };
            let ip = cidr.split('/').next().unwrap_or(cidr);
            if !ip.is_empty() {
                out.insert(ip.to_string(), name.to_string());
            }
        }
        // The bridge's own gateway address is how a container reaches a
        // published port on the host (hairpin NAT). It belongs to no
        // container, and without it every such call reads as unmapped.
        for gw in docker_lines(&[
            "network",
            "inspect",
            &net,
            "--format",
            "{{range .IPAM.Config}}{{.Gateway}}{{println}}{{end}}",
        ]) {
            let gw = gw.trim();
            if !gw.is_empty() {
                out.entry(gw.to_string())
                    .or_insert_with(|| format!("<{net} bridge — a container on this host>"));
            }
        }
    }
    out
}

/// `noo doctor strangers [--minutes N]` — who has been calling the gateway.
///
/// `doctor exposure` answers "what is reachable"; this answers "who has been
/// reaching it". Both were missing on 2026-09-14, when fifty unauthenticated
/// requests every twenty-five seconds ran for four days: the request line
/// carried no source at all until #226, and once it did, mapping
/// `172.19.0.10` to a container was still a manual `docker network inspect`.
/// This is that walk, as a verb.
pub fn doctor_strangers(g: &Globals, args: &[String]) -> Result<i32, Unhandled> {
    let mut minutes: u32 = 60;
    let mut it = args.iter();
    while let Some(tok) = it.next() {
        match tok.as_str() {
            "--minutes" => {
                minutes = it.next().and_then(|v| v.parse().ok()).ok_or(Unhandled)?;
            }
            _ => return Err(Unhandled),
        }
    }

    let container = crate::commands::mesh::resolve_container("gateway");
    let since = format!("{minutes}m");
    let out = Command::new("docker")
        .args(["logs", "--since", &since, &container])
        .output();
    let Ok(out) = out else {
        fail(g.json, ExitCode::Generic, "logs_unavailable",
            &format!("could not read logs from {container}"),
            Some("run this on the controller, where the gateway container is"));
    };
    if !out.status.success() {
        fail(g.json, ExitCode::Generic, "logs_unavailable",
            &format!("docker logs {container} failed — is the gateway running here?"),
            Some("noo stack status"));
    }
    let text = format!(
        "{}{}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );

    let mut saw_request_line = false;
    let mut peers: std::collections::BTreeMap<String, usize> = std::collections::BTreeMap::new();
    // Refusals (401/403/429) per peer. A caller whose requests are mostly
    // refused is retrying a credential the gateway rejects — an outage that
    // reads as traffic. an add-on once made 17,320 refused embedding
    // calls in one hour and this table showed it as a healthy "container"
    // row with a big number.
    let mut refused: std::collections::BTreeMap<String, usize> = std::collections::BTreeMap::new();
    for line in text.lines() {
        if !line.contains("\"message\":\"request\"") {
            continue;
        }
        saw_request_line = true;
        if let Some(p) = caller_of(line) {
            *peers.entry(p.clone()).or_insert(0) += 1;
            if status_of(line).is_some_and(is_refusal) {
                *refused.entry(p).or_insert(0) += 1;
            }
        }
    }

    // A gateway older than #226 logs request lines with no peer field. That
    // is NOT "no strangers" — it is a question this build cannot answer, and
    // reporting it as clean would be the exact failure that made the 2026-09
    // burst take two days to attribute.
    if saw_request_line && peers.is_empty() {
        fail(g.json, ExitCode::Generic, "no_peer_field",
            "the gateway logged requests but none carried a `peer` field — this build predates #226 (stack-v0.2.49)",
            Some("upgrade the controller; until then the source of a request is not recorded anywhere"));
    }

    let known = Known { tailnet: tailnet_peers(), containers: container_addresses() };
    let mut rows: Vec<(String, usize, Caller)> = peers
        .into_iter()
        .map(|(ip, n)| {
            let c = classify_caller(&ip, &known);
            (ip, n, c)
        })
        .collect();
    rows.sort_by(|a, b| b.1.cmp(&a.1).then(a.0.cmp(&b.0)));
    let strangers: Vec<&(String, usize, Caller)> = rows
        .iter()
        .filter(|(_, _, c)| matches!(c, Caller::Stranger | Caller::UnknownTailnet))
        .collect();
    let storms: Vec<(String, usize, usize)> = rows
        .iter()
        .filter_map(|(ip, n, _)| {
            let r = refused.get(ip).copied().unwrap_or(0);
            is_refusal_storm(*n, r).then(|| (ip.clone(), *n, r))
        })
        .collect();

    if g.json {
        println!("{}", serde_json::json!({
            "status": if !strangers.is_empty() { "strangers" } else if rows.iter().any(|(ip, n, _)| is_refusal_storm(*n, refused.get(ip).copied().unwrap_or(0))) { "storm" } else { "known" },
            "window_minutes": minutes,
            "callers": rows.iter().map(|(ip, n, c)| serde_json::json!({
                "peer": ip, "requests": n,
                "refused": refused.get(ip).copied().unwrap_or(0),
                "storm": is_refusal_storm(*n, refused.get(ip).copied().unwrap_or(0)),
                "kind": match c {
                    Caller::Loopback => "loopback".to_string(),
                    Caller::Container(n) => format!("container:{n}"),
                    Caller::UnmappedContainer => "container:unmapped".to_string(),
                    Caller::TailnetPeer(n) => format!("tailnet:{n}"),
                    Caller::UnknownTailnet => "tailnet:unknown".to_string(),
                    Caller::Lan => "lan".to_string(),
                    Caller::Stranger => "stranger".to_string(),
                },
            })).collect::<Vec<_>>(),
        }));
        return Ok(if strangers.is_empty() && storms.is_empty() { 0 } else { 1 });
    }

    println!("{}", ui::header("who has called the gateway", Some(&format!("last {minutes}m"))));
    if rows.is_empty() {
        println!("{}", ui::status_line(Glyph::Bullet, "no requests in the window"));
        return Ok(0);
    }
    let table: Vec<Vec<String>> = rows
        .iter()
        .map(|(ip, n, c)| {
            let (mut glyph, what) = match c {
                Caller::Loopback => (Glyph::Ok, ui::muted("this machine")),
                Caller::Container(name) => (Glyph::Ok, ui::muted(&format!("container {name}"))),
                Caller::UnmappedContainer => (Glyph::Bullet, ui::muted("a container here (name not resolved)")),
                Caller::TailnetPeer(name) => (Glyph::Ok, ui::muted(&format!("tailnet {name}"))),
                Caller::UnknownTailnet => (Glyph::Warn, ui::warn("on the tailnet, not a peer this machine knows")),
                Caller::Lan => (Glyph::Warn, ui::warn("LAN — this box has no tailnet; only the LAN governs this path")),
                Caller::Stranger => (Glyph::Err, ui::warn("NOT the tailnet and not local")),
            };
            let r = refused.get(ip).copied().unwrap_or(0);
            let refused_cell = if r == 0 { ui::muted("-") } else if is_refusal_storm(*n, r) {
                glyph = Glyph::Err;
                ui::err(&format!("{r} STORM"))
            } else {
                r.to_string()
            };
            vec![ui::glyph_cell(glyph), ip.clone(), n.to_string(), refused_cell, what]
        })
        .collect();
    print!("{}", ui::table(
        &[Col::left(""), Col::left("peer"), Col::right("requests"), Col::right("refused"), Col::left("what it is")],
        &table,
    ));
    println!();
    for (ip, n, r) in &storms {
        println!("{}", ui::status_line(Glyph::Err, &format!(
            "{ip} is in a refusal storm: {r} of {n} requests were refused (401/403/429) — a caller \
             retrying a credential the gateway rejects is an outage, not traffic"
        )));
        ui::guide(&[
            (&format!("docker logs noo-gateway --since {minutes}m | grep '\"peer\":\"{ip}\"' | grep -oE '\"path\":\"[^\"]+\"' | sort | uniq -c"), "which surface refuses it"),
            ("docker logs <that container> --since 10m", "what credential it presents, and why it keeps trying"),
            ("noo security service-key list", "whether the key it holds is active and carries the scopes that surface needs"),
        ]);
        println!();
    }
    if strangers.is_empty() {
        if storms.is_empty() {
            println!("{}", ui::status_line(Glyph::Ok, "every caller is this machine, a container here, or a known tailnet peer"));
            return Ok(0);
        }
        println!("{}", ui::status_line(Glyph::Ok, "every caller is known — but one of them is being refused in a loop (above)"));
        return Ok(1);
    }
    println!("{}", ui::status_line(Glyph::Err, &format!(
        "{} caller(s) the tailnet policy does not account for", strangers.len()
    )));
    println!("{}", ui::note(
        "config/tailscale-acl.hujson governs the tailnet door only — a port on 0.0.0.0 has a second one"
    ));
    ui::guide(&[
        ("noo doctor exposure", "which ports have that second door"),
        ("docker logs noo-gateway --since 10m | grep '\"peer\":\"<ip>\"'", "what that caller asked for, and what it got"),
    ]);
    Ok(1)
}

#[cfg(test)]
mod stranger_tests {
    use super::*;

    fn known() -> Known {
        let mut k = Known::default();
        k.tailnet.insert("100.64.0.12".into(), "node-2".into());
        k.containers.insert("172.19.0.10".into(), "noo-trellion-intel".into());
        k
    }

    /// The 2026-09-14 burst, as a one-line answer. This is the whole point of
    /// the command: `172.19.0.10` took two days to name by hand.
    #[test]
    fn the_burst_peer_resolves_to_its_container() {
        assert_eq!(
            classify_caller("172.19.0.10", &known()),
            Caller::Container("noo-trellion-intel".into())
        );
    }

    #[test]
    fn a_known_tailnet_peer_and_this_machine_are_fine() {
        assert_eq!(classify_caller("100.64.0.12", &known()), Caller::TailnetPeer("node-2".into()));
        assert_eq!(classify_caller("127.0.0.1", &known()), Caller::Loopback);
        assert_eq!(classify_caller("[::1]", &known()), Caller::Loopback);
    }

    /// A LAN host is the case this covers: it reaches a port on
    /// 0.0.0.0 over a path the ACL never sees.
    #[test]
    fn a_lan_address_is_a_stranger() {
        assert_eq!(classify_caller("192.0.2.50", &known()), Caller::Stranger);
    }

    /// In the tailnet range but unknown to this machine — worth naming, but
    /// not the same finding as a LAN caller, so not the same verdict.
    #[test]
    fn an_unrecognised_tailnet_address_is_its_own_verdict() {
        let c = classify_caller("100.64.0.31", &known());
        assert_eq!(c, Caller::UnknownTailnet);
        assert_ne!(c, Caller::Stranger);
    }

    /// An unmapped docker address must NOT cry wolf: if `network inspect`
    /// could not be read, every container call would otherwise read as a
    /// stranger and the command would be noise on day one.
    #[test]
    fn an_unmapped_bridge_address_is_not_a_stranger() {
        let c = classify_caller("172.19.0.99", &Known::default());
        assert_eq!(c, Caller::UnmappedContainer);
        assert_ne!(c, Caller::Stranger);
        // but a non-docker RFC1918 range is still a stranger on a box with a tailnet
        assert_eq!(classify_caller("10.1.2.3", &known()), Caller::Stranger);
    }

    /// A LAN-only install (no tailnet at all) is reached from the LAN by
    /// design. Its operator's laptop is not a stranger — and it is not
    /// nothing either, so it gets its own verdict rather than `Loopback`.
    #[test]
    fn a_lan_address_on_a_box_with_no_tailnet_is_lan_not_stranger() {
        assert_eq!(classify_caller("192.168.1.20", &Known::default()), Caller::Lan);
        assert_eq!(classify_caller("10.1.2.3", &Known::default()), Caller::Lan);
        // a public address is a stranger on any box
        assert_eq!(classify_caller("192.0.2.50", &Known::default()), Caller::Stranger);
    }

    #[test]
    fn the_peer_field_is_read_out_of_a_real_log_line() {
        let line = r#"2026-09-16T15:24:46.1Z {"timestamp":"2026-09-16T15:24:46Z","level":"INFO","fields":{"message":"request","method":"POST","path":"/v1/chat/completions","status":401,"elapsed_ms":0,"peer":"172.19.0.10","client":"172.19.0.10"},"target":"noo_gateway::middleware"}"#;
        assert_eq!(peer_of(line).as_deref(), Some("172.19.0.10"));
    }

    /// Through Tailscale Serve the peer is the controller and the client is
    /// the real caller; that caller is who `strangers` must name.
    #[test]
    fn a_proxied_request_is_attributed_to_its_client() {
        let line = r#"{"fields":{"message":"request","status":200,"peer":"100.64.0.12","client":"100.64.0.21"}}"#;
        assert_eq!(caller_of(line).as_deref(), Some("100.64.0.21"));
        let direct = r#"{"fields":{"message":"request","status":200,"peer":"100.64.0.22","client":"100.64.0.22"}}"#;
        assert_eq!(caller_of(direct).as_deref(), Some("100.64.0.22"));
        let old = r#"{"fields":{"message":"request","status":200,"peer":"172.19.0.10"}}"#;
        assert_eq!(caller_of(old).as_deref(), Some("172.19.0.10"), "a line without `client` falls back to the peer");
    }

    #[test]
    fn the_status_is_read_out_of_the_same_line() {
        let line = r#"{"fields":{"message":"request","status":403,"peer":"172.19.0.10"}}"#;
        assert_eq!(status_of(line), Some(403));
        assert_eq!(status_of(r#"{"fields":{"peer":"x"}}"#), None);
    }

    /// The 2026-09-22 shape: 17,320 of 17,343 requests refused. And the
    /// shapes that must NOT read as a storm: a busy healthy caller with a
    /// handful of 429s, and a human who got 401 twelve times.
    #[test]
    fn a_storm_is_many_refusals_that_are_most_of_the_traffic() {
        assert!(is_refusal_storm(17343, 17320));
        assert!(is_refusal_storm(100, 100));
        assert!(!is_refusal_storm(20000, 150), "a few 429s on a busy caller are not a storm");
        assert!(!is_refusal_storm(12, 12), "a dozen refusals is a person, not a loop");
        assert!(is_refusal(401) && is_refusal(403) && is_refusal(429));
        assert!(!is_refusal(404) && !is_refusal(500) && !is_refusal(200));
    }

    /// `-` is what the logger writes when there was no ConnectInfo. Counting
    /// it as a caller would invent a peer named "-".
    #[test]
    fn a_dash_peer_is_not_a_caller() {
        assert_eq!(peer_of(r#"{"fields":{"peer":"-","client":"x"}}"#), None);
        assert_eq!(peer_of(r#"{"fields":{"status":401}}"#), None);
    }
}

#[cfg(test)]
mod secret_drift_tests {
    use super::{agreement, fingerprint};

    fn held(pairs: &[(&str, &str)]) -> Vec<(String, String)> {
        pairs.iter().map(|(c, v)| (c.to_string(), v.to_string())).collect()
    }

    #[test]
    fn holders_that_agree_report_nothing() {
        assert!(agreement(&held(&[("a", "v1"), ("b", "v1"), ("c", "v1")])).is_empty());
    }

    /// The shape a missed rotation leaves: four recreated, one not.
    #[test]
    fn the_container_a_rotation_missed_is_the_one_named() {
        let out = agreement(&held(&[("a", "new"), ("b", "new"), ("c", "new"), ("stale-one", "old")]));
        assert_eq!(out.len(), 1);
        assert_eq!(out[0].0, "stale-one");
        assert_eq!(out[0].1, fingerprint("old"), "the report carries a digest, never the value");
    }

    /// An even split has no innocent side. Naming a "minority" there would
    /// point an operator at a container chosen by iteration order.
    #[test]
    fn an_even_split_names_every_holder_rather_than_guessing() {
        let out = agreement(&held(&[("a", "x"), ("b", "x"), ("c", "y"), ("d", "y")]));
        assert_eq!(out.len(), 4, "2-2 has no majority, so every holder is reported");
    }

    #[test]
    fn a_single_holder_cannot_disagree_with_itself() {
        assert!(agreement(&held(&[("only", "v")])).is_empty());
    }

    /// The report names digests, never values — including not leaking how
    /// long a secret is.
    #[test]
    fn a_fingerprint_reveals_neither_the_value_nor_its_length() {
        let short = fingerprint("a");
        let long = fingerprint(&"a".repeat(4096));
        assert_eq!(short.len(), long.len(), "length must not leak through the digest");
        assert_ne!(short, long);
        assert_ne!(fingerprint("old-secret"), fingerprint("new-secret"));
        assert_eq!(fingerprint("same"), fingerprint("same"), "a digest must be stable");
    }
}
