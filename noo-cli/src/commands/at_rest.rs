// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 PersonifAI LLC

//! At-rest encryption, part 1 (i10a, PR-A): what this machine can do, and the
//! person's recorded decision. Nothing here encrypts anything.
//!
//! - [`TpmFacts::probe`] reads the facts that decide whether a TPM 2.0 can
//!   hold the keys (TPM version, `/dev/tpmrm0`, Secure Boot, container / WSL /
//!   VM, CPU vendor, the tools). It is PURE over a sysroot: every path is
//!   joined under it, so a test builds a fake root in a temp directory and
//!   the real call passes `/`.
//! - [`enable_hint`] says exactly how to get a TPM when there is none. A TPM
//!   cannot be installed in software; it can be switched on in firmware or
//!   added to a VM.
//! - `noo security at-rest status|opt-out|opt-in`: the recorded decision is
//!   the db_only, person-only setting [`SETTING`], written through the same
//!   audited route as `noo kiosk labels` (its `updated_by`/`updated_at` say
//!   who and when).
//! - [`plan`] is what onboard calls; a "yes" runs
//!   `at_rest_volume::setup_fresh` (PR-C: the encrypted state volume).
//!
//! The two disclosure sentences below are the operator's wording
//! (i10a, 2026-10-11) and are pinned by tests: no "your data is secure", and
//! no silence.

use std::path::Path;

use serde_json::{json, Value};

use crate::output::{fail, ExitCode};
use crate::ui;
use crate::{Globals, Unhandled};

/// The controller setting that records the opt-out. Registered in
/// `gateway-rust/src/routes/settings.rs` (`AT_REST_UNENCRYPTED_ACCEPTED`);
/// db_only, and settable only by a person's own credential.
pub(crate) const SETTING: &str = "at_rest.unencrypted_accepted";

/// What the person is told when encryption is on.
pub(crate) const DISCLOSURE_ON: &str = "Your data, keys and secrets are encrypted on disk and unlock only on this machine. This protects against a stolen or lost drive. It does not protect against someone with admin access to the running machine.";

/// What the person is told when they opted out.
pub(crate) const DISCLOSURE_OFF: &str = "Your data is stored unencrypted on disk. Anyone with the drive can read it.";

/// The onboard question. The frontend adds the `[Y/n]`.
pub(crate) const ONBOARD_PROMPT: &str = "Encrypt your data, keys and secrets on disk, unlocked only on this machine? (recommended)";

const SECURE_BOOT_VAR: &str = "sys/firmware/efi/efivars/SecureBoot-8be4df61-93ca-11d2-aa0d-00e098032b8c";

// ── facts ──────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum TpmState {
    /// No `/sys/class/tpm/tpm*` at all.
    Absent,
    /// A TPM 1.2: not supported.
    Tpm12,
    /// A TPM 2.0 is listed but `/dev/tpmrm0` (the kernel resource manager) is not there.
    Tpm2NoDevice,
    /// A TPM 2.0 with its resource manager.
    Tpm2,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Cpu {
    Intel,
    Amd,
    Other,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Vm {
    /// QEMU / KVM / libvirt / Proxmox (they all report QEMU DMI strings).
    Qemu,
    Vmware,
    HyperV,
    VirtualBox,
    Other,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub(crate) struct Tools {
    pub systemd_creds: bool,
    pub systemd_cryptenroll: bool,
    pub cryptsetup: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct TpmFacts {
    pub tpm: TpmState,
    /// `Some(true)` Secure Boot on, `Some(false)` off, `None` no EFI variable (legacy BIOS, VM, container).
    pub secure_boot: Option<bool>,
    pub container: bool,
    pub wsl: bool,
    pub vm: Option<Vm>,
    pub sys_vendor: String,
    pub product_name: String,
    pub cpu: Cpu,
    pub tools: Tools,
}

fn read(root: &Path, rel: &str) -> Option<String> {
    std::fs::read_to_string(root.join(rel)).ok()
}

/// Whether `name` is an executable file in one of the standard binary
/// directories UNDER `root`. Sysroot-relative on purpose (not a `$PATH`
/// search), so the probe stays pure.
fn has_tool(root: &Path, name: &str) -> bool {
    use std::os::unix::fs::PermissionsExt as _;
    ["usr/bin", "usr/sbin", "bin", "sbin", "usr/local/bin", "usr/local/sbin"].iter().any(|d| {
        std::fs::metadata(root.join(d).join(name))
            .map(|m| m.is_file() && m.permissions().mode() & 0o111 != 0)
            .unwrap_or(false)
    })
}

fn classify_vm(vendor: &str, product: &str) -> Option<Vm> {
    let v = vendor.to_ascii_lowercase();
    let p = product.to_ascii_lowercase();
    let any = |hay: &str, needles: &[&str]| needles.iter().any(|n| hay.contains(n));
    if any(&v, &["vmware"]) || any(&p, &["vmware"]) {
        Some(Vm::Vmware)
    } else if v.contains("microsoft") && p.contains("virtual machine") {
        Some(Vm::HyperV)
    } else if any(&v, &["innotek"]) || p.contains("virtualbox") {
        Some(Vm::VirtualBox)
    } else if any(&v, &["qemu"]) || any(&p, &["kvm", "qemu", "standard pc"]) {
        Some(Vm::Qemu)
    } else if any(&v, &["xen", "amazon ec2", "google", "openstack", "parallels", "bochs", "digitalocean"])
        || any(&p, &["google compute engine", "hvm domu", "openstack", "parallels"])
    {
        Some(Vm::Other)
    } else {
        None
    }
}

impl TpmFacts {
    /// Read the facts under `sysroot` (`/` on a real host).
    pub(crate) fn probe(sysroot: &Path) -> TpmFacts {
        // The TPM: version from sysfs, the resource manager from /dev.
        let mut version: Option<String> = None;
        if let Ok(rd) = std::fs::read_dir(sysroot.join("sys/class/tpm")) {
            let mut names: Vec<String> = rd
                .filter_map(|e| e.ok())
                .map(|e| e.file_name().to_string_lossy().into_owned())
                .filter(|n| n.starts_with("tpm"))
                .collect();
            names.sort();
            for n in names {
                if let Some(v) = read(sysroot, &format!("sys/class/tpm/{n}/tpm_version_major")) {
                    let v = v.trim().to_string();
                    // Prefer a 2.0 over anything else listed.
                    if version.is_none() || v == "2" {
                        version = Some(v);
                    }
                }
            }
        }
        let has_rm = sysroot.join("dev/tpmrm0").exists();
        let tpm = match version.as_deref() {
            Some("2") if has_rm => TpmState::Tpm2,
            Some("2") => TpmState::Tpm2NoDevice,
            Some(_) => TpmState::Tpm12,
            None => TpmState::Absent,
        };

        // Secure Boot: an EFI variable is 4 attribute bytes, then the value.
        let secure_boot = std::fs::read(sysroot.join(SECURE_BOOT_VAR))
            .ok()
            .and_then(|b| b.get(4).copied())
            .map(|v| v == 1);

        let container = sysroot.join(".dockerenv").exists() || sysroot.join("run/.containerenv").exists();
        let wsl = read(sysroot, "proc/sys/kernel/osrelease")
            .is_some_and(|s| s.to_ascii_lowercase().contains("microsoft"));
        let sys_vendor = read(sysroot, "sys/class/dmi/id/sys_vendor").unwrap_or_default().trim().to_string();
        let product_name = read(sysroot, "sys/class/dmi/id/product_name").unwrap_or_default().trim().to_string();
        let vm = classify_vm(&sys_vendor, &product_name);

        let cpu = read(sysroot, "proc/cpuinfo")
            .and_then(|t| {
                t.lines()
                    .find(|l| l.starts_with("vendor_id"))
                    .and_then(|l| l.split(':').nth(1))
                    .map(|v| v.trim().to_string())
            })
            .map(|v| match v.as_str() {
                "GenuineIntel" => Cpu::Intel,
                "AuthenticAMD" => Cpu::Amd,
                _ => Cpu::Other,
            })
            .unwrap_or(Cpu::Other);

        let tools = Tools {
            systemd_creds: has_tool(sysroot, "systemd-creds"),
            systemd_cryptenroll: has_tool(sysroot, "systemd-cryptenroll"),
            cryptsetup: has_tool(sysroot, "cryptsetup"),
        };
        TpmFacts { tpm, secure_boot, container, wsl, vm, sys_vendor, product_name, cpu, tools }
    }

    /// A TPM 2.0 with its resource manager, on a machine that can hold one
    /// (a container or WSL cannot, whatever it can see).
    pub(crate) fn tpm2_usable(&self) -> bool {
        self.tpm == TpmState::Tpm2 && !self.container && !self.wsl
    }

    /// Why there is no usable TPM. Empty when there is one.
    pub(crate) fn unavailable_reason(&self) -> String {
        if self.tpm2_usable() {
            String::new()
        } else if self.container {
            "this is a container".into()
        } else if self.wsl {
            "this is WSL, which has no TPM".into()
        } else {
            match self.tpm {
                TpmState::Tpm12 => "the TPM here is version 1.2, which is not supported".into(),
                TpmState::Tpm2NoDevice => "a TPM 2.0 is listed but /dev/tpmrm0 is missing".into(),
                _ => "no TPM was found".into(),
            }
        }
    }

    /// The tools the sealing steps will need that are not installed.
    pub(crate) fn missing_tools(&self) -> Vec<&'static str> {
        let mut out = Vec::new();
        if !self.tools.systemd_creds {
            out.push("systemd-creds");
        }
        if !self.tools.systemd_cryptenroll {
            out.push("systemd-cryptenroll");
        }
        if !self.tools.cryptsetup {
            out.push("cryptsetup");
        }
        out
    }

    pub(crate) fn secure_boot_phrase(&self) -> &'static str {
        match self.secure_boot {
            Some(true) => "on",
            Some(false) => "off",
            None => "unknown (no EFI variable)",
        }
    }

    pub(crate) fn environment_phrase(&self) -> String {
        if self.container {
            "container".into()
        } else if self.wsl {
            "WSL".into()
        } else if self.vm.is_some() {
            format!("virtual machine ({} {})", self.sys_vendor, self.product_name).trim_end().to_string()
        } else {
            "physical machine".into()
        }
    }

    pub(crate) fn tpm_phrase(&self) -> String {
        if self.tpm2_usable() {
            "TPM 2.0 present".into()
        } else {
            format!("no usable TPM 2.0 ({})", self.unavailable_reason())
        }
    }

    pub(crate) fn to_json(&self) -> Value {
        json!({
            "tpm": match self.tpm {
                TpmState::Absent => "absent",
                TpmState::Tpm12 => "tpm1.2",
                TpmState::Tpm2NoDevice => "tpm2-no-resource-manager",
                TpmState::Tpm2 => "tpm2",
            },
            "usable": self.tpm2_usable(),
            "reason": if self.tpm2_usable() { Value::Null } else { Value::String(self.unavailable_reason()) },
            "secure_boot": self.secure_boot,
            "container": self.container,
            "wsl": self.wsl,
            "vm": self.vm.is_some(),
            "sys_vendor": self.sys_vendor,
            "product_name": self.product_name,
            "cpu": match self.cpu { Cpu::Intel => "intel", Cpu::Amd => "amd", Cpu::Other => "other" },
            "tools_missing": self.missing_tools(),
        })
    }
}

/// How to get a TPM 2.0 on this machine, or that none is needed. A TPM cannot
/// be installed in software: it is switched on in firmware or added to the VM.
pub(crate) fn enable_hint(f: &TpmFacts) -> String {
    if f.container {
        return "A container cannot hold a TPM — run on the host.".into();
    }
    if f.wsl {
        return "WSL cannot hold a TPM — run on the host (Windows or a Linux machine).".into();
    }
    match f.tpm {
        TpmState::Tpm2 => return "A TPM 2.0 is present; nothing to enable.".into(),
        TpmState::Tpm12 => {
            return "This machine has a TPM 1.2, which is not supported (TPM 2.0 is required). \
                    If the firmware offers a TPM 2.0 mode (Intel PTT or AMD fTPM), enable it in the BIOS; \
                    otherwise this machine stays unencrypted at rest."
                .into();
        }
        TpmState::Tpm2NoDevice => {
            return "A TPM 2.0 is listed but /dev/tpmrm0 (the kernel resource manager) is missing: \
                    load the tpm_crb or tpm_tis driver, or use a kernel built with the TPM resource manager."
                .into();
        }
        TpmState::Absent => {}
    }
    match f.vm {
        Some(Vm::Qemu) => "This VM has no virtual TPM. In KVM/libvirt add \
            <tpm model='tpm-crb'><backend type='emulator' version='2.0'/></tpm> to the domain (needs swtpm and UEFI/OVMF firmware). \
            In Proxmox add a TPM State disk (VM > Hardware > Add > TPM State, version v2.0) and use OVMF (UEFI) firmware."
            .into(),
        Some(Vm::Vmware) => "This VM has no virtual TPM. In VMware edit the VM, Add New Device > Trusted Platform Module \
            (the VM must use UEFI firmware)."
            .into(),
        Some(Vm::HyperV) => "This VM has no virtual TPM. On the Hyper-V host, for a Generation 2 VM, run in PowerShell: \
            Set-VMKeyProtector -VMName <vm> -NewLocalKeyProtector, then Enable-VMTPM -VMName <vm>."
            .into(),
        Some(Vm::VirtualBox) => "This VM has no virtual TPM. VirtualBox 7 can add one: VM Settings > System > Motherboard > \
            TPM, choose v2.0 (EFI must be enabled)."
            .into(),
        Some(Vm::Other) => format!(
            "This looks like a virtual machine ({} {}). Ask the hypervisor for a virtual TPM 2.0 (vTPM) for this VM.",
            f.sys_vendor, f.product_name
        )
        .trim_end()
        .to_string(),
        None => match f.cpu {
            Cpu::Intel => "No TPM found. Enable Intel PTT (Platform Trust Technology) in the BIOS/UEFI setup \
                (usually under Security or Advanced), save and reboot."
                .into(),
            Cpu::Amd => "No TPM found. Enable AMD fTPM (firmware TPM) in the BIOS/UEFI setup \
                (usually under Advanced > AMD fTPM configuration), save and reboot."
                .into(),
            Cpu::Other => "No TPM found. Enable the firmware TPM 2.0 in the BIOS/UEFI setup \
                (look for TPM, PTT or fTPM), or fit a TPM 2.0 module."
                .into(),
        },
    }
}

// ── the recorded decision ──────────────────────────────────────────────

/// The setting as the gateway reports it in `GET /api/settings/flags`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct AcceptedState {
    /// True: the person accepted unencrypted data at rest.
    pub accepted: bool,
    /// `db` (someone set it) or `default` (never set: not accepted).
    pub source: String,
    pub updated_by: Option<String>,
    pub updated_at: Option<String>,
}

/// Find the at-rest row in a `GET /api/settings/flags` answer. `None` when
/// the gateway does not list it (an older stack), which is NOT "not accepted".
pub(crate) fn state_from_flags(body: &Value) -> Option<AcceptedState> {
    let row = body["flags"].as_array()?.iter().find(|f| f["key"] == SETTING)?;
    Some(AcceptedState {
        accepted: row["value"].as_bool()?,
        source: row["source"].as_str().unwrap_or("unknown").to_string(),
        updated_by: row["updated_by"].as_str().map(str::to_string),
        updated_at: row["updated_at"].as_str().map(str::to_string),
    })
}

/// "accepted (opted out by alice at 2026-10-23T12:00:00Z)" / "not accepted (never set; the default)".
pub(crate) fn state_line(s: &AcceptedState) -> String {
    let who = match (&s.updated_by, &s.updated_at) {
        (Some(b), Some(a)) => format!("by {b} at {a}"),
        (Some(b), None) => format!("by {b}"),
        (None, Some(a)) => format!("at {a}"),
        (None, None) if s.source == "default" => "never set; the default".to_string(),
        (None, None) => format!("source: {}", s.source),
    };
    if s.accepted {
        format!("accepted: opted out {who}")
    } else {
        format!("not accepted ({who})")
    }
}

// ── commands ───────────────────────────────────────────────────────────

/// `noo security at-rest status [--json]`
pub fn security_at_rest_status(g: &Globals, args: &[String]) -> Result<i32, Unhandled> {
    run(g, args, None)
}

/// `noo security at-rest opt-out` — record that unencrypted data at rest is accepted.
pub fn security_at_rest_opt_out(g: &Globals, args: &[String]) -> Result<i32, Unhandled> {
    run(g, args, Some(true))
}

/// `noo security at-rest opt-in` — withdraw the opt-out.
pub fn security_at_rest_opt_in(g: &Globals, args: &[String]) -> Result<i32, Unhandled> {
    run(g, args, Some(false))
}

fn run(g: &Globals, args: &[String], want: Option<bool>) -> Result<i32, Unhandled> {
    let mut json_out = g.json;
    for a in args {
        if a == "--json" {
            json_out = true;
        } else {
            fail(
                g.json,
                ExitCode::Usage,
                "usage",
                "noo security at-rest takes status, opt-out or opt-in (status accepts --json)",
                Some("noo security at-rest status"),
            );
        }
    }
    if let Some(accepted) = want {
        // The person's own stored login: the setter refuses the cluster
        // credential and service keys, so who decided is on record.
        crate::http::post_json(g, "/api/settings/flags/set", &json!({ "key": SETTING, "value": accepted }), true, 10);
    }
    let facts = TpmFacts::probe(Path::new("/"));
    let flags = crate::http::get_json_opt(g, "/api/settings/flags", true, 10);
    let state = flags.as_ref().and_then(state_from_flags);
    if want.is_some() && state.is_none() {
        fail(
            g.json,
            ExitCode::RemoteError,
            "unsupported",
            &format!("this gateway does not offer the {SETTING} setting — it predates the switch"),
            Some("noo upgrade --stack"),
        );
    }
    let hint = enable_hint(&facts);
    if json_out {
        println!(
            "{}",
            json!({
                "setting": SETTING,
                "tpm": facts.to_json(),
                "hint": hint,
                "accepted": state.as_ref().map(|s| s.accepted),
                "source": state.as_ref().map(|s| s.source.clone()),
                "updated_by": state.as_ref().and_then(|s| s.updated_by.clone()),
                "updated_at": state.as_ref().and_then(|s| s.updated_at.clone()),
            })
        );
        return Ok(0);
    }
    match want {
        Some(true) => ui::done("recorded: you accept unencrypted data at rest on this controller"),
        Some(false) => ui::done("opt-out withdrawn: encryption at rest is wanted on this controller"),
        None => println!("{}", ui::header("at rest", None)),
    }
    let mut rows: Vec<(&str, String)> = vec![
        ("tpm", facts.tpm_phrase()),
        ("secure boot", facts.secure_boot_phrase().to_string()),
        ("environment", facts.environment_phrase()),
    ];
    if facts.tpm2_usable() && !facts.missing_tools().is_empty() {
        rows.push(("tools missing", facts.missing_tools().join(", ")));
    }
    if !facts.tpm2_usable() {
        rows.push(("to enable", hint));
    }
    rows.push((
        "decision",
        match &state {
            Some(s) => state_line(s),
            None => "unknown (the gateway did not answer, or predates the setting)".to_string(),
        },
    ));
    println!("{}", ui::kv(&rows));
    println!("{}", if state.as_ref().is_some_and(|s| s.accepted) { DISCLOSURE_OFF } else { DISCLOSURE_ON });
    if state.as_ref().is_some_and(|s| s.accepted) {
        ui::guide(&[("noo security at-rest opt-in", "withdraw the opt-out; then noo security at-rest create-volume")]);
    } else if want.is_none() {
        ui::guide(&[("noo security at-rest opt-out", "record that you accept unencrypted data on disk (audited)")]);
    }
    Ok(0)
}

// ── onboard ────────────────────────────────────────────────────────────

/// What onboard does about at-rest encryption on this machine.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Plan {
    /// No usable TPM: explain and record nothing.
    Unavailable,
    /// Encrypt (the recommended default).
    Encrypt,
    /// The person said no: record the decision.
    OptOut,
}

/// The decision, pure so it can be pinned. `ask` is only called when a TPM is
/// usable and the wizard is interactive; non-interactive (`--ci`) never
/// prompts and defaults to Encrypt.
pub(crate) fn plan(facts: &TpmFacts, non_interactive: bool, ask: &mut dyn FnMut() -> bool) -> Plan {
    if !facts.tpm2_usable() {
        return Plan::Unavailable;
    }
    if non_interactive || ask() {
        Plan::Encrypt
    } else {
        Plan::OptOut
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use std::path::PathBuf;

    /// A fake root under the OS temp dir, removed on drop.
    struct Root(PathBuf);
    impl Root {
        fn new(tag: &str) -> Root {
            let p = std::env::temp_dir().join(format!("noo-at-rest-{tag}-{}", std::process::id()));
            let _ = fs::remove_dir_all(&p);
            fs::create_dir_all(&p).unwrap();
            Root(p)
        }
        fn file(&self, rel: &str, body: &[u8]) -> &Self {
            let p = self.0.join(rel);
            fs::create_dir_all(p.parent().unwrap()).unwrap();
            fs::write(p, body).unwrap();
            self
        }
        fn tool(&self, rel: &str) -> &Self {
            let p = self.0.join(rel);
            fs::create_dir_all(p.parent().unwrap()).unwrap();
            crate::test_exec::write_exec(&p, b"#!/bin/sh\n", 0o755);
            self
        }
        fn tpm(&self, version: &str, with_rm: bool) -> &Self {
            self.file("sys/class/tpm/tpm0/tpm_version_major", format!("{version}\n").as_bytes());
            if with_rm {
                self.file("dev/tpmrm0", b"");
            }
            self
        }
        fn secure_boot(&self, on: bool) -> &Self {
            self.file(SECURE_BOOT_VAR, &[7, 0, 0, 0, if on { 1 } else { 0 }])
        }
        fn dmi(&self, vendor: &str, product: &str) -> &Self {
            self.file("sys/class/dmi/id/sys_vendor", format!("{vendor}\n").as_bytes());
            self.file("sys/class/dmi/id/product_name", format!("{product}\n").as_bytes())
        }
        fn cpu(&self, vendor: &str) -> &Self {
            self.file("proc/cpuinfo", format!("processor\t: 0\nvendor_id\t: {vendor}\nmodel name\t: x\n").as_bytes())
        }
        fn probe(&self) -> TpmFacts {
            TpmFacts::probe(&self.0)
        }
    }
    impl Drop for Root {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }

    #[test]
    fn intel_tpm2_with_secure_boot_on_is_usable() {
        let r = Root::new("intel");
        r.tpm("2", true).secure_boot(true).dmi("Dell Inc.", "XPS 15").cpu("GenuineIntel")
            .tool("usr/bin/systemd-creds").tool("usr/bin/systemd-cryptenroll").tool("usr/sbin/cryptsetup");
        let f = r.probe();
        assert_eq!(f.tpm, TpmState::Tpm2);
        assert!(f.tpm2_usable());
        assert_eq!(f.secure_boot, Some(true));
        assert_eq!(f.cpu, Cpu::Intel);
        assert_eq!(f.vm, None);
        assert!(!f.container && !f.wsl);
        assert!(f.missing_tools().is_empty(), "{:?}", f.missing_tools());
        assert_eq!(f.unavailable_reason(), "");
        assert!(enable_hint(&f).contains("nothing to enable"));
    }

    #[test]
    fn amd_ftpm_is_a_tpm2() {
        let r = Root::new("amd");
        r.tpm("2", true).secure_boot(false).cpu("AuthenticAMD");
        let f = r.probe();
        assert!(f.tpm2_usable());
        assert_eq!(f.cpu, Cpu::Amd);
        assert_eq!(f.secure_boot, Some(false));
        assert_eq!(f.secure_boot_phrase(), "off");
        assert_eq!(f.missing_tools(), vec!["systemd-creds", "systemd-cryptenroll", "cryptsetup"]);
    }

    #[test]
    fn tpm2_without_the_resource_manager_is_not_usable() {
        let r = Root::new("norm");
        r.tpm("2", false).cpu("GenuineIntel");
        let f = r.probe();
        assert_eq!(f.tpm, TpmState::Tpm2NoDevice);
        assert!(!f.tpm2_usable());
        assert!(f.unavailable_reason().contains("/dev/tpmrm0"));
        assert!(enable_hint(&f).contains("tpmrm0"));
    }

    #[test]
    fn kvm_without_a_tpm_gets_the_libvirt_and_proxmox_hint() {
        let r = Root::new("kvm");
        r.dmi("QEMU", "Standard PC (Q35 + ICH9, 2009)").cpu("AuthenticAMD");
        let f = r.probe();
        assert_eq!(f.tpm, TpmState::Absent);
        assert_eq!(f.vm, Some(Vm::Qemu));
        assert_eq!(f.secure_boot, None);
        assert!(!f.tpm2_usable());
        assert_eq!(f.unavailable_reason(), "no TPM was found");
        let h = enable_hint(&f);
        assert!(h.contains("<tpm model='tpm-crb'><backend type='emulator' version='2.0'/></tpm>"), "{h}");
        assert!(h.contains("Proxmox"), "{h}");
    }

    #[test]
    fn other_hypervisors_name_their_own_switch() {
        let hint = |vendor: &str, product: &str| {
            let r = Root::new(&format!("vm-{}", vendor.replace(' ', "")));
            r.dmi(vendor, product);
            enable_hint(&r.probe())
        };
        assert!(hint("VMware, Inc.", "VMware7,1").contains("Trusted Platform Module"));
        assert!(hint("Microsoft Corporation", "Virtual Machine").contains("Enable-VMTPM"));
        assert!(hint("innotek GmbH", "VirtualBox").contains("VirtualBox 7"));
        assert!(hint("Google", "Google Compute Engine").contains("virtual TPM"));
    }

    #[test]
    fn bare_metal_without_a_tpm_names_ptt_or_ftpm_by_cpu() {
        let hint = |cpu: &str| {
            let r = Root::new(&format!("bare-{cpu}"));
            r.dmi("ASUSTeK", "PRIME").cpu(cpu);
            enable_hint(&r.probe())
        };
        assert!(hint("GenuineIntel").contains("Intel PTT"));
        assert!(hint("AuthenticAMD").contains("AMD fTPM"));
        assert!(hint("CentaurHauls").contains("firmware TPM 2.0"));
    }

    #[test]
    fn a_container_cannot_hold_a_tpm_even_if_it_sees_one() {
        let r = Root::new("docker");
        r.file(".dockerenv", b"").tpm("2", true).cpu("GenuineIntel");
        let f = r.probe();
        assert!(f.container);
        assert!(!f.tpm2_usable(), "a container reported a usable TPM");
        assert_eq!(f.unavailable_reason(), "this is a container");
        let h = enable_hint(&f);
        assert!(h.contains("cannot hold a TPM") && h.contains("run on the host"), "{h}");
    }

    #[test]
    fn wsl_is_detected_from_the_kernel_release() {
        let r = Root::new("wsl");
        r.file("proc/sys/kernel/osrelease", b"6.18.40.1-microsoft-standard-WSL2\n").cpu("AuthenticAMD");
        let f = r.probe();
        assert!(f.wsl);
        assert!(!f.tpm2_usable());
        let h = enable_hint(&f);
        assert!(h.contains("WSL cannot hold a TPM") && h.contains("run on the host"), "{h}");
        let plain = Root::new("notwsl");
        plain.file("proc/sys/kernel/osrelease", b"6.8.0-45-generic\n");
        assert!(!plain.probe().wsl);
    }

    #[test]
    fn a_tpm_1_2_is_unsupported() {
        let r = Root::new("tpm12");
        r.tpm("1", true).cpu("GenuineIntel");
        let f = r.probe();
        assert_eq!(f.tpm, TpmState::Tpm12);
        assert!(!f.tpm2_usable());
        assert!(f.unavailable_reason().contains("1.2"));
        assert!(enable_hint(&f).contains("TPM 1.2, which is not supported"));
    }

    #[test]
    fn secure_boot_is_the_fifth_byte() {
        let off = Root::new("sb-off");
        off.secure_boot(false);
        assert_eq!(off.probe().secure_boot, Some(false));
        let on = Root::new("sb-on");
        on.secure_boot(true);
        assert_eq!(on.probe().secure_boot, Some(true));
        let none = Root::new("sb-none");
        assert_eq!(none.probe().secure_boot, None);
        let short = Root::new("sb-short");
        short.file(SECURE_BOOT_VAR, &[7, 0, 0]);
        assert_eq!(short.probe().secure_boot, None, "a truncated variable is unknown, not off");
    }

    /// The operator's two sentences, word for word (i10a, 2026-10-11).
    #[test]
    fn the_disclosure_sentences_are_the_operators() {
        assert_eq!(
            DISCLOSURE_ON,
            "Your data, keys and secrets are encrypted on disk and unlock only on this machine. This protects against a stolen or lost drive. It does not protect against someone with admin access to the running machine."
        );
        assert_eq!(
            DISCLOSURE_OFF,
            "Your data is stored unencrypted on disk. Anyone with the drive can read it."
        );
        assert!(!DISCLOSURE_ON.to_lowercase().contains("secure"), "no 'your data is secure' claim");
        assert_eq!(SETTING, "at_rest.unencrypted_accepted");
        assert_eq!(
            ONBOARD_PROMPT,
            "Encrypt your data, keys and secrets on disk, unlocked only on this machine? (recommended)"
        );
    }

    #[test]
    fn the_decision_is_read_from_the_flags_list() {
        let body = json!({"flags": [
            {"key": "kiosk.graph_labels", "value": true},
            {"key": "at_rest.unencrypted_accepted", "value": true, "source": "db",
             "updated_by": "alice", "updated_at": "2026-10-23T12:00:00Z"},
        ]});
        let s = state_from_flags(&body).expect("row not found");
        assert!(s.accepted);
        assert_eq!(state_line(&s), "accepted: opted out by alice at 2026-10-23T12:00:00Z");
        let never = state_from_flags(&json!({"flags": [
            {"key": "at_rest.unencrypted_accepted", "value": false, "source": "default", "updated_by": null, "updated_at": null},
        ]}))
        .unwrap();
        assert!(!never.accepted);
        assert_eq!(state_line(&never), "not accepted (never set; the default)");
        assert_eq!(state_from_flags(&json!({"flags": [{"key": "CLOUD_PROVIDERS_ENABLED", "value": false}]})), None);
        assert_eq!(state_from_flags(&json!({})), None);
    }

    #[test]
    fn onboard_plan_follows_the_tpm_and_never_prompts_unattended() {
        let with = {
            let r = Root::new("plan-tpm");
            r.tpm("2", true);
            r.probe()
        };
        let without = Root::new("plan-none").probe();
        let mut asked = 0;
        // no TPM: nothing recorded, and the question is not asked
        assert_eq!(plan(&without, false, &mut || { asked += 1; true }), Plan::Unavailable);
        assert_eq!(asked, 0);
        // --ci: default yes, never prompts
        assert_eq!(plan(&with, true, &mut || { asked += 1; false }), Plan::Encrypt);
        assert_eq!(asked, 0, "--ci prompted");
        // interactive: the answer decides
        assert_eq!(plan(&with, false, &mut || true), Plan::Encrypt);
        assert_eq!(plan(&with, false, &mut || false), Plan::OptOut);
    }
}
