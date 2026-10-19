// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 PersonifAI LLC

//! Cluster PKI — native port of `noomesh/pki/ca.py` (`ClusterCA`).
//!
//! CORRECTNESS-SENSITIVE: certs issued here must be accepted by every
//! verifier in the fleet (Rust gateway rustls, Go node-agent, Python httpx,
//! stunnel/openssl, Postgres/NATS/Redis TLS). The profile mirrors ca.py
//! byte-for-byte wherever a verifier could care:
//!
//!   - CA:   self-signed EC P-384 / SHA-384, CN="Mesh Cluster CA",
//!           O="Mesh Cluster", 3650d, BasicConstraints CA:TRUE pathlen:0
//!           (critical), KeyUsage digitalSignature+keyCertSign+cRLSign
//!           (critical), SKI = SHA-1 of the subjectPublicKey BIT STRING.
//!   - Leaf: EC P-384 / SHA-384, subject CN=<name> + O=<role org>
//!           (UTF8String, CN first — matches python-cryptography),
//!           BasicConstraints CA:FALSE (critical), SAN (DNS then IP, order
//!           preserved, de-duplicated), EKU = clientAuth + serverAuth (that
//!           order; every leaf is dual-purpose), SKI = SHA-1(subject key
//!           bits), AKI = SHA-1(CA key bits) — RFC 5280 method 1, exactly
//!           what `x509.SubjectKeyIdentifier.from_public_key` /
//!           `AuthorityKeyIdentifier.from_issuer_public_key` produce. rcgen
//!           defaults to RFC 7093 SHA-256 key IDs, so both are pre-computed
//!           here and injected via `KeyIdMethod::PreSpecified`.
//!   - Serial: 159-bit random (20 urandom bytes >> 1), same distribution as
//!           `x509.random_serial_number()`.
//!   - Validity: notBefore = now − 5 min, notAfter = now + days (UTCTime).
//!   - Keys: PKCS#8 PEM ("BEGIN PRIVATE KEY"). ca.key and signing.key 0600.
//!           A leaf key's mode follows WHO READS IT (`KeyReader`, table
//!           `SERVICE_KEY_READERS`): 0600 when only this CLI or a
//!           root-in-container process reads it, 0640 handed to the
//!           container's uid when a non-root process does. Leaves used to
//!           be 0644 so any container uid could read them through a
//!           read-only bind mount (the 2026-07-08 note in ca.py) — which
//!           also let the gateway, mounting the whole tree as uid 65532,
//!           read every node's and every service's private key.
//!
//! Every extension is hand-encoded DER injected via `custom_extensions`,
//! NOT rcgen's builders, for two load-bearing reasons discovered in
//! compat testing:
//!   1. rcgen's `IsCa::ExplicitNoCa` encodes BasicConstraints as
//!      `SEQUENCE { BOOLEAN FALSE }` — invalid strict DER (a value equal
//!      to its DEFAULT must be omitted). python-cryptography ≥42 REFUSES
//!      to parse such certs (`ParseError: EncodedDefault`), which would
//!      break ca.py's own inventory/rotation and any Python code loading
//!      the cert. Correct encoding is an empty SEQUENCE (`30 00`).
//!   2. rcgen writes KeyUsage as a fixed 9-bit BIT STRING; DER named-bit
//!      values must strip trailing zero bits (`03 02 01 86` for
//!      digitalSignature|keyCertSign|cRLSign).
//! Hand-encoding also reproduces ca.py's extension ORDER exactly
//! (CA: BC,KU,SKI — leaf: BC,SAN,EKU,SKI,AKI), so the decoded profiles
//! diff clean field-for-field.
//!
//! Layout under the PKI dir (identical to ca.py):
//!   ca.crt, ca.key
//!   gateway/gateway.crt|key           CN=<host>, O=Mesh Cluster Gateway
//!   nodes/<id>/node.crt|key           CN=<id>,   O=Mesh Cluster Node
//!   services/<svc>/service.crt|key    CN=<svc>,  O=Mesh Cluster Service
//!   nodes/<id>/services/<svc>/service.crt|key
//!                                     CN=<svc>,  O=Mesh Cluster Service —
//!                                     a NODE's backend door leaf
//!                                     1244 A), carried to that node by the
//!                                     provision bundle; node-scoped so one
//!                                     node's leaf is revocable on its own
//!   gateway/pg/<role>.crt|key         the gateway's Postgres role leaves
//!   services/<owner>/pg/<role>.crt|key
//!                                     CN=<role>, O=Mesh Cluster Service —
//!                                     one leaf per Postgres role per
//!                                     container (`PG_LEAVES`), so
//!                                     pg_hba's `clientcert=verify-full`
//!                                     can say which role a certificate
//!                                     may log in as
//!   sso/grafana.key|pub               the Grafana SSO pair (not a cert)
//!   public/{nodes,services}/…/*.crt   a copy of every certificate under
//!                                     nodes/ and services/ and nothing
//!                                     else — the gateway's view of them
//!                                     

use std::io::Read as _;
use std::net::IpAddr;
use std::os::unix::fs::PermissionsExt as _;
use std::path::{Path, PathBuf};

use rcgen::{Certificate, CertificateParams, CustomExtension, DnType, KeyPair, SerialNumber};
use sha1::{Digest as _, Sha1};
use time::{Duration, OffsetDateTime};

const CA_O: &str = "Mesh Cluster";
/// The organization of an operator client leaf. The
/// gateway reads the same string (`gateway-rust/src/node_identity.rs`
/// `OPERATOR_ORG`); a test pins the two together.
pub const OPERATOR_ORG: &str = "Mesh Cluster Operator";
/// `CN=operator:<account>` — never readable as a node id.
pub const OPERATOR_CN_PREFIX: &str = "operator:";
/// Operator leaves are short-lived: re-issue is one command on the
/// controller, and a person's credential should not outlive a quarter.
pub const OPERATOR_DAYS: i64 = 30;
pub const DEFAULT_DAYS: i64 = 90;

/// $NOO_PKI_DIR, else ~/.config/mesh/pki — same resolution as the Python
/// CLI (`os.getenv("NOO_PKI_DIR", "~/.config/mesh/pki")`); the repo .env is
/// already loaded by `ensure_repo_env` before handlers run.
pub fn pki_dir() -> PathBuf {
    if let Ok(d) = std::env::var("NOO_PKI_DIR") {
        if !d.is_empty() {
            return PathBuf::from(d);
        }
    }
    let home = std::env::var("HOME").unwrap_or_else(|_| String::from("/root"));
    PathBuf::from(home).join(".config/mesh/pki")
}

pub struct ClusterCa {
    pub dir: PathBuf,
}

pub struct CertInfo {
    pub name: String,
    pub path: PathBuf,
    pub role: &'static str,
    /// YYYY-MM-DD (UTC), matching Python's `%Y-%m-%d`.
    pub expires: String,
    /// Floor of the remaining time in whole days — Python `timedelta.days`
    /// floors toward −∞, so an expired cert shows e.g. −1, not 0.
    pub days_left: i64,
}

/// Outcome of one cert in a `rotate_all_expiring` pass (ca.py dict parity:
/// `{"name","role","status"[,"error"]}`).
pub struct RotateResult {
    pub name: String,
    pub role: &'static str,
    pub status: &'static str, // "rotated" | "error"
    pub error: String,        // empty unless status == "error"
}

impl ClusterCa {
    pub fn new(dir: PathBuf) -> Self {
        Self { dir }
    }

    pub fn ca_cert_path(&self) -> PathBuf {
        self.dir.join("ca.crt")
    }

    pub fn ca_key_path(&self) -> PathBuf {
        self.dir.join("ca.key")
    }

    pub fn ca_exists(&self) -> bool {
        self.ca_cert_path().exists() && self.ca_key_path().exists()
    }

    // ── fleet signing key ─────────────────────────────────
    //
    // The CA private key used to do two unrelated jobs: issue mTLS
    // identities, and sign the node bundles that carry ROOT CODE to every
    // box (agent binary, hostd, the applier itself, fleet secrets). One
    // key, two blast radii — and no way to rotate the code-signing half
    // without re-issuing every identity in the cluster.
    //
    // They are split. `signing.key` signs bundles; `ca.key` signs certs.
    // Nodes verify bundles against `signing.pub`, which they receive in a
    // bundle they already trust. The CA keeps exactly ONE code-delivery
    // power: it signs the ROLLOVER bundle that installs (or replaces) a
    // node's `signing.pub`. That is the bootstrap, and it is also the
    // rotation story — see `noo security pki rotate-signing-key`.

    /// The fleet code-signing private key (PKCS#8 PEM, 0600).
    pub fn signing_key_path(&self) -> PathBuf {
        self.dir.join("signing.key")
    }

    /// Its SPKI public key (PEM, 0644) — the form `openssl dgst -verify`
    /// takes directly, and the form `openssl x509 -pubkey` emits, so the
    /// node's verifier treats both anchors identically.
    pub fn signing_pub_path(&self) -> PathBuf {
        self.dir.join("signing.pub")
    }

    pub fn signing_key_exists(&self) -> bool {
        self.signing_key_path().exists() && self.signing_pub_path().exists()
    }

    /// Generate the fleet signing keypair if it is not already there.
    /// Idempotent: safe to call on every bundle build, which is what makes
    /// a cluster created before this split acquire one without a migration.
    pub fn ensure_signing_key(&self) -> Result<(), String> {
        if self.signing_key_exists() {
            return Ok(());
        }
        self.mint_signing_key()
    }

    /// Mint a NEW signing keypair, overwriting whatever is there. The old
    /// pair is archived beside it (`signing.key.<unix>.bak`). It never signs
    /// a bundle on its own; it COUNTERSIGNS a CA-signed rollover
    /// (`retained_signing_keys`) so a node that was offline
    /// through the rotation, and still holds the old key, can move.
    pub fn mint_signing_key(&self) -> Result<(), String> {
        std::fs::create_dir_all(&self.dir)
            .map_err(|e| format!("mkdir {}: {e}", self.dir.display()))?;
        if self.signing_key_path().exists() {
            let ts = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_secs())
                .unwrap_or(0);
            for (src, ext) in [(self.signing_key_path(), "key"), (self.signing_pub_path(), "pub")] {
                let _ = std::fs::copy(&src, self.dir.join(format!("signing.{ext}.{ts}.bak")));
            }
        }
        let key = KeyPair::generate_for(&rcgen::PKCS_ECDSA_P384_SHA384)
            .map_err(|e| format!("signing keygen failed: {e}"))?;
        write_key_file(&self.signing_key_path(), key.serialize_pem().as_bytes())?;
        write_file(&self.signing_pub_path(), key.public_key_pem().as_bytes(), Some(0o644))?;
        Ok(())
    }

    // ── Grafana SSO key ───────────────────────────
    //
    // The gateway signs short Grafana session tokens (ES256) with this
    // private half; Grafana verifies them against the public half
    // (`[auth.jwt] key_file`). It lives under `sso/`, not `services/`, so
    // nothing that walks the leaves — `rotate-all`, the SVC_LIST SAN
    // logic, `pki status` — mistakes it for a TLS identity: `list_certs`
    // collects `*.crt` and there is no certificate here. Rotating it logs
    // every open Grafana tab out at once (tokens live ≤ 60 min), so
    // `rotate-all` leaves it alone by construction and `issue-sso-key`
    // refuses to overwrite without `--force`.

    pub const GRAFANA_SSO_KEY_REL: &'static str = "sso/grafana.key";
    pub const GRAFANA_SSO_PUB_REL: &'static str = "sso/grafana.pub";

    /// The uid the gateway container runs as (nonroot). The private half
    /// is 0640 with this group so the gateway can read it through its
    /// read-only PKI mount without the key being world-readable.
    pub const GATEWAY_CONTAINER_GID: u32 = 65532;

    /// P-256 private key, PKCS#8 PEM, 0640 group 65532.
    pub fn grafana_sso_key_path(&self) -> PathBuf {
        self.dir.join(Self::GRAFANA_SSO_KEY_REL)
    }

    /// SPKI public key, PEM, 0644 — the only SSO file Grafana mounts.
    pub fn grafana_sso_pub_path(&self) -> PathBuf {
        self.dir.join(Self::GRAFANA_SSO_PUB_REL)
    }

    pub fn grafana_sso_key_exists(&self) -> bool {
        self.grafana_sso_key_path().is_file() && self.grafana_sso_pub_path().is_file()
    }

    /// Issue the pair if it is not there. Idempotent, so onboard can call
    /// it on every run and an install created before this key acquires
    /// one without a migration. `Ok(false)` = already present, untouched.
    pub fn ensure_grafana_sso_key(&self) -> Result<bool, String> {
        if self.grafana_sso_key_exists() {
            return Ok(false);
        }
        self.mint_grafana_sso_key().map(|()| true)
    }

    /// Mint a NEW pair, overwriting whatever is there. P-256 because
    /// Grafana verifies ES256 and nothing else (the CA and fleet signing
    /// keys are P-384, which the gateway refuses by name).
    pub fn mint_grafana_sso_key(&self) -> Result<(), String> {
        let key = KeyPair::generate_for(&rcgen::PKCS_ECDSA_P256_SHA256)
            .map_err(|e| format!("grafana sso keygen failed: {e}"))?;
        write_key_file(&self.grafana_sso_key_path(), key.serialize_pem().as_bytes())?;
        set_mode(&self.grafana_sso_key_path(), 0o640);
        write_file(&self.grafana_sso_pub_path(), key.public_key_pem().as_bytes(), Some(0o644))?;
        // The directory too, or the gateway cannot traverse into it.
        let _ = std::fs::set_permissions(
            self.grafana_sso_key_path().parent().unwrap_or(&self.dir),
            std::fs::Permissions::from_mode(0o755),
        );
        Ok(())
    }

    /// Can uid 65532 (the gateway container) read the private half? The
    /// mode says: world-readable, or group-readable with group 65532.
    /// `None` when the file is absent.
    pub fn grafana_sso_key_readable_by_gateway(&self) -> Option<bool> {
        readable_by_uid(&self.grafana_sso_key_path(), Self::GATEWAY_CONTAINER_GID)
    }

    /// Hand the private half to group 65532 so the nonroot gateway can
    /// read it. `chgrp` to a group the caller is not in needs root, so
    /// this is best-effort: the `Err` is the exact command to run. The
    /// gateway's 503 names the same fix, and so does `cluster verify`.
    pub fn grafana_sso_key_grant_gateway_read(&self) -> Result<(), String> {
        grant_read_to_uid(&self.grafana_sso_key_path(), Self::GATEWAY_CONTAINER_GID).map(|_| ())
    }
}

// ── Private-key modes: who reads which key ──────────────────────────
//
// Every private key under the PKI dir has exactly one reader besides
// this CLI, and the file mode says so. Three classes:
//
//   * only the CLI reads it (ca.key, signing.key, and on the controller
//     every nodes/<id>/node.key — the CLI builds the signed bundle that
//     carries a node its key; the gateway only ever serves bundles) →
//     0600;
//   * a container process that is ROOT inside its container reads it
//     (nats, vllm, nginx…) → 0600 too: root on a
//     bind mount has CAP_DAC_OVERRIDE and reads an owner-only file, so
//     nothing else needs to be able to;
//   * a container process with a fixed non-root uid reads it (the
//     gateway, worker and trellion as 65532; the DHI monitoring images
//     as 65532; postgres as 70) → 0640 with the file HANDED to that uid:
//     its group when we may `chgrp`, else a POSIX ACL entry, else the
//     file is left as it was and the exact `sudo` line is printed —
//     we never tighten a key we cannot re-grant, because that turns a
//     scan finding into a service that will not start.
//
// A service the table does not name keeps the legacy 0644; the scan
// reports it as "no reader entry" so the table grows rather than a
// guess breaking an unknown consumer.

/// Which process reads a private key, and therefore its mode.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum KeyReader {
    /// Only this CLI, as the operator: 0600.
    Cli,
    /// A container whose reading process is root inside the container
    /// (CAP_DAC_OVERRIDE reads an owner-only bind-mounted file): 0600.
    ContainerRoot,
    /// A container process with this fixed uid (gid == uid on every
    /// image in the table): 0640, handed to that uid.
    ContainerUid(u32),
    /// Not in the table: legacy 0644, reported by the scan.
    Unknown,
}

impl KeyReader {
    /// The mode a key with this reader is written with.
    pub fn mode(self) -> u32 {
        match self {
            KeyReader::Cli | KeyReader::ContainerRoot => 0o600,
            KeyReader::ContainerUid(_) => 0o640,
            KeyReader::Unknown => 0o644,
        }
    }

    pub fn describe(self) -> String {
        match self {
            KeyReader::Cli => "the CLI only".into(),
            KeyReader::ContainerRoot => "root inside its container".into(),
            KeyReader::ContainerUid(u) => format!("container uid {u}"),
            KeyReader::Unknown => "no reader entry".into(),
        }
    }
}

/// Who reads each service leaf's private key inside its container —
/// the image's `USER`, verified 2026-09-28 by `docker image inspect`
/// of the mirrored DHI images (`.github/workflows/mirror-images.yml`)
/// and the Dockerfiles under `docker/` — or the compose `user:` where the
/// service overrides the image. A DHI runtime image runs as `nonroot` =
/// 65532; a DHI `-dev` variant's image USER is root, so redis and grafana
/// (the two `-dev` runtime services) are pinned to 65532 by compose `user:`
/// (i64) and the "image family" verify row asserts they are not uid 0.
///
/// Every name in `onboard::steps::SVC_LIST` must be here (pinned by
/// `service_key_reader_table_covers_every_onboarded_service`); a name
/// here that onboard does not issue is a table entry nothing uses.
pub const SERVICE_KEY_READERS: &[(&str, KeyReader)] = &[
    // dhi.io/redis:8.6-debian13-dev's image USER is 0, but the compose
    // service runs it as `user: nonroot`, the image's uid 65532 (i64, operator 2026-10-15:
    // redis must not run as root). The -dev variant is kept because the
    // runtime variant has no shell and docker/redis-entrypoint.sh is sh.
    ("redis", KeyReader::ContainerUid(65532)),
    // nats:latest (official): root.
    ("nats", KeyReader::ContainerRoot),
    // docker/Dockerfile.postgres ends `USER postgres` (alpine uid 70) and the
    // compose entrypoint `cp`s the key to /tmp as that uid.
    ("postgres", KeyReader::ContainerUid(70)),
    // vllm/vllm-openai: root.
    ("vllm", KeyReader::ContainerRoot),
    // docker/Dockerfile.llamacpp: USER nonroot on a DHI base.
    ("llamacpp", KeyReader::ContainerUid(65532)),
    // Read by the stunnel sidecar (docker/Dockerfile.stunnel ends `USER
    // nonroot` = uid 65532, and compose pins `user: nonroot`; i132): uid 65532. The
    // doors a NODE's agent starts (node-agent-go docker/sidecar.go) keep
    // running as root with their own root-owned 0600 copy of the leaf under
    // /etc/noo/pki, which is a different file from these.
    ("ollama", KeyReader::ContainerUid(65532)),
    ("ollama-embed", KeyReader::ContainerUid(65532)),
    ("ollama-embed-cpu", KeyReader::ContainerUid(65532)),
    ("tei", KeyReader::ContainerUid(65532)),
    ("reranker", KeyReader::ContainerUid(65532)),
    // DHI runtime images: nonroot 65532.
    ("loki", KeyReader::ContainerUid(65532)),
    ("prometheus", KeyReader::ContainerUid(65532)),
    ("alertmanager", KeyReader::ContainerUid(65532)),
    ("node-exporter", KeyReader::ContainerUid(65532)),
    // docker/Dockerfile.trellion (and -intel, FROM it) ends `USER nonroot`:
    // 65532, measured on the live noo-trellion. Each container
    // mounts only its own leaf dir, so the shared uid does
    // not let one read the other's key.
    ("trellion", KeyReader::ContainerUid(65532)),
    ("trellion-intel", KeyReader::ContainerUid(65532)),
    // docker/Dockerfile.worker ends `USER nonroot`: 65532, measured on the
    // live noo-worker (/proc/<pid>/status). noo-worker and worker-extra
    // share this one leaf through the compose anchor.
    ("worker", KeyReader::ContainerUid(65532)),
    // docker/Dockerfile.nvidia-exporter: nvidia/cuda base, `USER nonroot` (uid 65532) and
    // compose `user: nonroot` (i132). NVML only needs the runtime's
    // /dev/nvidia* nodes, which the NVIDIA container toolkit makes 0666.
    ("nvidia-exporter", KeyReader::ContainerUid(65532)),
    // dhi.io/grafana:12-debian13-dev's image USER is 0; the compose service
    // runs it as `user: grafana`, the image's uid 65532 (i64). grafana-server reads
    // GF_SERVER_CERT_KEY itself, as that uid.
    ("grafana", KeyReader::ContainerUid(65532)),
    // nginx:1.27-alpine: the master process loads certificates as root.
    ("model-cache", KeyReader::ContainerRoot),
    // evolve: python:3.12-slim with no USER line (root); the overlay's
    // entrypoint stages the key to /tmp as that uid before libpq reads it.
    ("evolve", KeyReader::ContainerRoot),
    // docker/Dockerfile.sandbox ends `USER nonroot`: 65532, measured with
    // `docker run --rm --entrypoint id` on the published sandbox image.
    // uvicorn reads the key itself (`--ssl-keyfile`). Mounted under /tls,
    // which is not in the sandbox's bwrap RO_PATHS, so code run by /exec
    // never sees it.
    ("sandbox", KeyReader::ContainerUid(65532)),
    // The voice add-on's doors: docker/Dockerfile.whisper and
    // Dockerfile.piper end `USER nonroot` (uid/gid 65532, i105; through
    // v0.6.4 they had no USER line and ran as root). uvicorn reads the key
    // itself (`--ssl-keyfile`). `noo cluster verify --controller` → `voice
    // images` judges the live uid against this entry.
    ("whisper", KeyReader::ContainerUid(65532)),
    ("piper", KeyReader::ContainerUid(65532)),
    // A warm standby's replication client identity.
    // No container on THIS box mounts it: the operator's CLI reads it, and
    // `scripts/bootstrap-standby.sh join` stages a 0600 copy owned by the
    // standby's postgres uid inside the standby's data volume.
    ("postgres-standby", KeyReader::Cli),
];

// ── Postgres client identities: a leaf per ROLE, per container ───────
//
// `docker/postgres/pg_hba.conf` used to ask only that a TCP client present
// SOME cluster-CA leaf (`clientcert=verify-ca`) and then know a role's
// password: the gateway leaf logged in as `noo`, `noo_app`, anything, and
// five roles shared it. A role leaf is a leaf whose CN IS the role name, so
// `clientcert=verify-full` (CN == the database role being asked for) makes
// the certificate say WHICH role may use it, not just that it is ours.
//
// Layout: each container's role leaves live INSIDE the directory it already
// mounts, so no mount changes and no container reaches another's key:
//
//   gateway/pg/<role>.crt|key            the gateway     (noo, noo_app)
//   services/worker/pg/<role>.crt|key    worker, worker-extra (noo_app)
//   services/trellion/pg/<role>...       trellion        (noo_app, noo_trellion, noo_trellion_ddl)
//   services/trellion-intel/pg/<role>... trellion-intel  (the same three)
//
// trellion-intel `extends` trellion's service and swaps only the leaf mount
// (`/app/pki/leaf`), so its DSNs, which name `/app/pki/leaf/pg/<role>.*`,
// resolve to ITS OWN role leaves with no change in the add-on repo.
//
// Add-on roles whose clients live in the add-on repos (noo_evolve,
// noo_evolve_ddl) and the standby's `replicator` are NOT here; pg_hba keeps
// them on `verify-ca` until their repos present a leaf of their own
// (docs/security/networks-and-containers.md).

/// One Postgres role leaf: which container presents it, and as which role.
#[derive(Debug)]
pub struct PgLeaf {
    /// The directory-owner: `gateway`, or a `services/<owner>` name.
    pub owner: &'static str,
    /// The database role; also the leaf's CN and its file name.
    pub role: &'static str,
    /// Containers that present this leaf (restarted when it rotates).
    pub consumers: &'static [&'static str],
}

/// Every role leaf. The per-role `verify-full` lines in pg_hba.conf are the
/// distinct roles in this table (tests/test_postgres_role_identity.py).
pub const PG_LEAVES: &[PgLeaf] = &[
    PgLeaf { owner: "gateway", role: "noo", consumers: &["noo-gateway"] },
    PgLeaf { owner: "gateway", role: "noo_app", consumers: &["noo-gateway"] },
    PgLeaf { owner: "worker", role: "noo_app", consumers: &["noo-worker"] },
    PgLeaf { owner: "trellion", role: "noo_app", consumers: &["noo-trellion"] },
    PgLeaf { owner: "trellion", role: "noo_trellion", consumers: &["noo-trellion"] },
    PgLeaf { owner: "trellion", role: "noo_trellion_ddl", consumers: &["noo-trellion"] },
    PgLeaf { owner: "trellion-intel", role: "noo_app", consumers: &["noo-trellion-intel"] },
    PgLeaf { owner: "trellion-intel", role: "noo_trellion", consumers: &["noo-trellion-intel"] },
    PgLeaf { owner: "trellion-intel", role: "noo_trellion_ddl", consumers: &["noo-trellion-intel"] },
];

/// Every consumer container has this uid (gateway, worker and the trellion
/// images all run as `nonroot`), so every role key is `ContainerUid`.
pub const PG_LEAF_UID: u32 = 65532;

impl PgLeaf {
    /// The PKI-relative directory: `gateway/pg` or `services/<owner>/pg`.
    pub fn dir_rel(&self) -> String {
        if self.owner == "gateway" { "gateway/pg".into() } else { format!("services/{}/pg", self.owner) }
    }
    /// PKI-relative `<dir>/<role>.crt`.
    pub fn cert_rel(&self) -> String {
        format!("{}/{}.crt", self.dir_rel(), self.role)
    }
    /// PKI-relative `<dir>/<role>.key`.
    pub fn key_rel(&self) -> String {
        format!("{}/{}.key", self.dir_rel(), self.role)
    }
}

/// The leaf a PKI-relative `.crt` or `.key` path is, if it is one of
/// [`PG_LEAVES`].
pub fn pg_leaf_at(rel: &str) -> Option<&'static PgLeaf> {
    PG_LEAVES.iter().find(|l| l.cert_rel() == rel || l.key_rel() == rel)
}

/// The distinct roles with a leaf, in table order.
pub fn pg_leaf_roles() -> Vec<&'static str> {
    let mut out: Vec<&'static str> = Vec::new();
    for l in PG_LEAVES {
        if !out.contains(&l.role) {
            out.push(l.role);
        }
    }
    out
}

/// The roles a pg_hba.conf body protects with `clientcert=verify-full`: the
/// user column of every `hostssl` line that names one role, not `all`, and
/// keeps the password (`scram-sha-256`). A line that says verify-full with
/// `trust` or `cert` does not count: the role's password check is the other
/// half of the rule.
pub fn pg_hba_verify_full_roles(hba: &str) -> Vec<String> {
    let mut out: Vec<String> = Vec::new();
    for line in hba.lines() {
        let f: Vec<&str> = line.split('#').next().unwrap_or("").split_whitespace().collect();
        if f.len() >= 6
            && f[0] == "hostssl"
            && f[2] != "all"
            && f[4] == "scram-sha-256"
            && f[5..].contains(&"clientcert=verify-full")
            && !out.contains(&f[2].to_string())
        {
            out.push(f[2].to_string());
        }
    }
    out
}

/// What keeps a Postgres role on a shared leaf: for every role in
/// [`PG_LEAVES`], each leaf that is missing, has the wrong CN or has no key
/// (its container would present the wrong identity or none), and, when the
/// pg_hba.conf body is known, a role the file does not hold to
/// `clientcert=verify-full` (any cluster-CA leaf then reaches its password
/// check). Empty = every role has its leaf and the file enforces it. `hba`
/// `None` = the file could not be read: only the leaves are judged, and the
/// caller must say the file was NOT CHECKED.
pub fn pg_identity_gaps(ca: &ClusterCa, hba: Option<&str>) -> Vec<String> {
    let mut gaps = Vec::new();
    for leaf in PG_LEAVES {
        if let Err(why) = ca.pg_leaf_state(leaf) {
            gaps.push(format!("{} ({}): {why}", leaf.role, leaf.owner));
        }
    }
    if let Some(hba) = hba {
        let enforced = pg_hba_verify_full_roles(hba);
        for role in pg_leaf_roles() {
            if !enforced.iter().any(|r| r == role) {
                gaps.push(format!(
                    "{role}: pg_hba.conf has no `hostssl … {role} … scram-sha-256 clientcert=verify-full` line, so any cluster-CA leaf reaches its password check"
                ));
            }
        }
    }
    gaps
}

/// Something `fix_key_modes` did, or could not do, to one key.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct KeyFix {
    /// Path relative to the PKI dir.
    pub rel: String,
    pub reader: KeyReader,
    pub before: u32,
    pub after: u32,
    /// How the reader was handed the file: "group", "acl", or "" when
    /// no grant was needed or none could be made.
    pub granted_via: &'static str,
    /// The command the operator must run, when we could not do it.
    pub needs: Option<String>,
    /// The key was owned by another uid (root, after a `sudo` issue or a
    /// Docker-created bind source) and readable: it was re-written as the
    /// operator's, same bytes, so the mode below could be set at all.
    pub reowned: bool,
}

impl KeyFix {
    pub fn changed(&self) -> bool {
        self.before != self.after || !self.granted_via.is_empty() || self.reowned
    }
}

/// One thing wrong with a key's mode, for the scan and `cluster verify`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct KeyIssue {
    pub rel: String,
    pub mode: u32,
    pub reader: KeyReader,
    pub kind: KeyIssueKind,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KeyIssueKind {
    /// Readable by someone other than the owner and the reader.
    Exposed,
    /// The reader (a container uid) cannot read it.
    Unreadable,
    /// A service leaf the reader table does not name, still 0644.
    UnknownReader,
    /// Its mode is right, but it is owned by a uid other than the PKI
    /// dir's owner, and this CLI could not take it back (unreadable to
    /// the operator, or in a directory the operator cannot write). Every
    /// re-issue, rotation and mode repair of it fails with EACCES until
    /// the printed `sudo chown` runs.
    WrongOwner,
}

impl ClusterCa {
    /// The reader — and so the mode — of a private key at `path`
    /// (absolute or PKI-relative).
    pub fn key_reader(&self, path: &Path) -> KeyReader {
        let rel = path.strip_prefix(&self.dir).unwrap_or(path);
        let parts: Vec<&str> = rel
            .components()
            .filter_map(|c| c.as_os_str().to_str())
            .collect();
        match parts.as_slice() {
            ["ca.key"] | ["signing.key"] => KeyReader::Cli,
            ["sso", "grafana.key"] | ["gateway", "gateway.key"] => {
                KeyReader::ContainerUid(Self::GATEWAY_CONTAINER_GID)
            }
            // A Postgres role leaf (i132): read by the owning container's
            // nonroot process, like the leaf beside it.
            ["gateway", "pg", _] | ["services", _, "pg", _] if pg_leaf_at(&parts.join("/")).is_some() => {
                KeyReader::ContainerUid(PG_LEAF_UID)
            }
            ["nodes", _, "node.key"] => KeyReader::Cli,
            // A node's backend door leaf: on THIS disk only the CLI reads
            // it (to pack the provision bundle). On the node it is read by
            // root in the door's container and installed 0600 by the
            // applier — the same answer, so the same mode.
            ["nodes", _, "services", _, "service.key"] => KeyReader::Cli,
            ["services", svc, "service.key"] => SERVICE_KEY_READERS
                .iter()
                .find(|(name, _)| name == svc)
                .map(|(_, r)| *r)
                .unwrap_or(KeyReader::Unknown),
            _ => KeyReader::Unknown,
        }
    }

    /// Every `*.key` under the PKI dir, sorted, relative to it.
    pub fn list_keys(&self) -> Vec<PathBuf> {
        let mut out = Vec::new();
        collect_ext(&self.dir, "key", &mut out);
        out.sort();
        out
    }

    /// Set one key to its reader's mode and hand it to the reader.
    /// Idempotent. Never fails the caller: the outcome is in the
    /// returned `KeyFix`, whose `needs` is the command we could not run.
    pub fn apply_key_mode(&self, key: &Path) -> KeyFix {
        let rel = key.strip_prefix(&self.dir).unwrap_or(key).to_string_lossy().into_owned();
        let reader = self.key_reader(key);
        let before = std::fs::metadata(key).map(|m| m.permissions().mode() & 0o777).unwrap_or(0);
        let mut fix = KeyFix { rel, reader, before, after: before, granted_via: "", needs: None, reowned: false };
        // A key this process does not own cannot be chmod-ed, chgrp-ed or
        // ACL-ed — every step below would fail and say nothing. Take it
        // back when the operator can read it and write its directory (same
        // bytes, a new inode owned by the operator, 0600, renamed over the
        // old one); otherwise the one `sudo` line that can. The SSO key is
        // never re-written here: it fails closed (#524), and a re-owned
        // copy would drop the gateway's grant.
        if !owned_by_me(key) {
            if fix.rel.starts_with("sso/") || reown(key).is_err() {
                fix.needs = Some(self.owner_fix_line(key));
                return fix;
            }
            fix.reowned = true;
            fix.after = 0o600;
        }
        match reader {
            KeyReader::Unknown => {}
            KeyReader::Cli | KeyReader::ContainerRoot => {
                if fix.after != reader.mode() && set_mode(key, reader.mode()) {
                    fix.after = reader.mode();
                }
            }
            KeyReader::ContainerUid(uid) => {
                if !fix.reowned && readable_by_uid(key, uid) == Some(true) && before & 0o007 == 0 && !group_read_beyond(key, uid) {
                    return fix; // already exactly right
                }
                // The SSO signing key fails CLOSED on purpose (#524): a 503
                // on "Open Grafana" beats a world-readable key that mints
                // Grafana sessions. Its own helpers hand it over; here it
                // is audited, never loosened.
                if fix.rel.starts_with("sso/") {
                    if readable_by_uid(key, uid) != Some(true) {
                        fix.needs = Some(sudo_grant_line(key, uid));
                    }
                    return fix;
                }
                match grant_read_to_uid(key, uid) {
                    Ok(via) => {
                        fix.granted_via = via;
                        fix.after = std::fs::metadata(key).map(|m| m.permissions().mode() & 0o777).unwrap_or(before);
                    }
                    Err(cmd) => {
                        // Fail open: a key the reader cannot be handed
                        // must stay readable by it, or the service stops
                        // starting — so it is 0644 (the legacy mode) until
                        // the printed line runs; the scan and verify name
                        // it with that line.
                        if readable_by_uid(key, uid) != Some(true) && set_mode(key, 0o644) {
                            fix.after = 0o644;
                        }
                        fix.needs = Some(cmd);
                    }
                }
            }
        }
        fix
    }

    /// Tighten every existing key to its reader's mode and every
    /// directory to 0755 (traversable, not group-writable: the gateway
    /// walks the certificate copies under `public/` for expiry).
    /// Returns what it did per key, then the directories it changed.
    pub fn fix_key_modes(&self) -> (Vec<KeyFix>, Vec<String>) {
        let keys: Vec<KeyFix> = self.list_keys().iter().map(|k| self.apply_key_mode(k)).collect();
        let mut dirs = Vec::new();
        let mut all_dirs = Vec::new();
        collect_dirs(&self.dir, &mut all_dirs);
        all_dirs.sort();
        for d in all_dirs {
            let mode = std::fs::metadata(&d).map(|m| m.permissions().mode() & 0o777).unwrap_or(0o755);
            if (mode & 0o022 != 0 || mode & 0o055 != 0o055) && set_mode(&d, 0o755) {
                dirs.push(d.strip_prefix(&self.dir).map(|p| p.to_string_lossy().into_owned()).unwrap_or_else(|_| ".".into()));
            }
        }
        (keys, dirs)
    }

    /// Every key whose mode says more, or less, than its reader.
    pub fn audit_key_modes(&self) -> Vec<KeyIssue> {
        let mut out = Vec::new();
        for key in self.list_keys() {
            let rel = key.strip_prefix(&self.dir).unwrap_or(&key).to_string_lossy().into_owned();
            let reader = self.key_reader(&key);
            let Some(acc) = access_of(&key) else { continue };
            let mode = acc.mode;
            let kind = classify_key_access(reader, &acc);
            // The mode is right; is it the operator's to keep right?
            let kind = kind.or_else(|| self.stuck_foreign(&key).then_some(KeyIssueKind::WrongOwner));
            let Some(kind) = kind else { continue };
            out.push(KeyIssue { rel, mode, reader, kind });
        }
        out
    }

    /// The hand-over for one uid-read key that is not (only) its
    /// reader's yet, as the operator would type it. `None` when the key is
    /// exactly right or its reader is not a container uid.
    pub fn key_grant_command(&self, key: &Path) -> Option<String> {
        if self.stuck_foreign(key) {
            return Some(self.owner_fix_line(key));
        }
        let KeyReader::ContainerUid(uid) = self.key_reader(key) else { return None };
        let extras = extra_readers(&access_of(key)?);
        (!reader_can_read(&extras, uid) || beyond_reader(&extras, uid)).then(|| sudo_grant_line(key, uid))
    }

    /// Is `key` owned by someone other than the owner of the PKI dir (the
    /// operator)? `false` when either cannot be read.
    pub fn foreign_owner(&self, key: &Path) -> bool {
        use std::os::unix::fs::MetadataExt as _;
        match (std::fs::metadata(&self.dir), std::fs::metadata(key)) {
            (Ok(d), Ok(k)) => d.uid() != k.uid(),
            _ => false,
        }
    }

    /// Foreign-owned AND beyond this process's reach: it can neither
    /// read the file nor replace it in its directory, so `apply_key_mode`
    /// cannot take it back and only `sudo` can. A foreign key it CAN
    /// reach is not stuck — the next repair re-writes it as the operator's.
    pub fn stuck_foreign(&self, key: &Path) -> bool {
        self.foreign_owner(key) && !owned_by_me(key) && !can_reclaim(key)
    }

    /// The one line that hands a foreign-owned key back to the operator
    /// with its reader's mode — the only key repair this CLI cannot make
    /// itself (the file is unreadable to it, or its directory is not
    /// writable by it).
    pub fn owner_fix_line(&self, key: &Path) -> String {
        use std::os::unix::fs::MetadataExt as _;
        let (uid, gid) = std::fs::metadata(&self.dir).map(|m| (m.uid(), m.gid())).unwrap_or((0, 0));
        owner_fix_line(key, self.key_reader(key), uid, gid)
    }

    /// Every private key under `nodes/<node>/` set to its reader's mode —
    /// the node's own key and its door leaves, the ones `provision` packs.
    pub fn fix_node_key_modes(&self, node: &str) -> Vec<KeyFix> {
        let root = self.dir.join("nodes").join(node);
        self.list_keys().iter().filter(|k| k.starts_with(&root)).map(|k| self.apply_key_mode(k)).collect()
    }

    /// Certificates are public, but a group- or world-WRITABLE one (the
    /// 0664 a umask-002 shell leaves) lets someone else swap an identity.
    /// Every `*.crt` this process owns goes to 0644. Returns what changed.
    pub fn fix_cert_modes(&self) -> Vec<String> {
        let mut crts = Vec::new();
        collect_ext(&self.dir, "crt", &mut crts);
        crts.sort();
        crts.into_iter()
            .filter(|c| std::fs::symlink_metadata(c).map(|m| m.file_type().is_file() && m.permissions().mode() & 0o022 != 0).unwrap_or(false))
            .filter(|c| set_mode(c, 0o644))
            .map(|c| c.strip_prefix(&self.dir).unwrap_or(&c).to_string_lossy().into_owned())
            .collect()
    }
}

/// What is wrong with one key's access, from its reader and what decides
/// who reads it — the mode bits, the owning gid, and the ACL text when
/// the file has one (`access_of`: `getfacl -c -n`, the same reading
/// `fix-modes` grants against). `None` = readable by exactly its reader.
///
/// A named `user:<reader>:r--` ACL entry under an `r--` mask, with the
/// owning group's own entry `---`, is exactly right whatever the group
/// is: that is the shape `grant_read_to_uid` writes, and `stat` shows it
/// as 0640 because the group bits display the mask.
///
/// Anyone beyond the reader outranks the reader being unable to read: a
/// 0640 key in some other group with no grant is exposed to that group
/// AND down for its service, and the verify row must fail it. The fix
/// for both is the same hand-over line.
pub(crate) fn classify_key_access(reader: KeyReader, acc: &Access) -> Option<KeyIssueKind> {
    let extras = extra_readers(acc);
    match reader {
        KeyReader::Unknown if !extras.is_empty() => Some(KeyIssueKind::UnknownReader),
        KeyReader::Cli | KeyReader::ContainerRoot if !extras.is_empty() => Some(KeyIssueKind::Exposed),
        KeyReader::ContainerUid(uid) if beyond_reader(&extras, uid) => Some(KeyIssueKind::Exposed),
        KeyReader::ContainerUid(uid) if !reader_can_read(&extras, uid) => Some(KeyIssueKind::Unreadable),
        _ => None,
    }
}

/// `sudo chown` back to the operator plus the reader's mode, in one line.
pub(crate) fn owner_fix_line(key: &Path, reader: KeyReader, uid: u32, gid: u32) -> String {
    let p = key.display();
    match reader {
        KeyReader::ContainerUid(r) => format!("sudo chown {uid}:{r} {p} && sudo chmod 640 {p}"),
        KeyReader::Cli | KeyReader::ContainerRoot => format!("sudo chown {uid}:{gid} {p} && sudo chmod 600 {p}"),
        KeyReader::Unknown => format!("sudo chown {uid}:{gid} {p}"),
    }
}

/// May this process change the file's mode (it owns it, or is root)?
fn owned_by_me(path: &Path) -> bool {
    use std::os::unix::fs::MetadataExt as _;
    let euid = unsafe { libc::geteuid() };
    euid == 0 || std::fs::metadata(path).map(|m| m.uid() == euid).unwrap_or(true)
}

/// Could `reown` succeed: the file is readable and its directory
/// writable by this process?
fn can_reclaim(path: &Path) -> bool {
    use std::os::unix::ffi::OsStrExt as _;
    let dir = path.parent().unwrap_or(Path::new("."));
    let Ok(c) = std::ffi::CString::new(dir.as_os_str().as_bytes()) else { return false };
    std::fs::File::open(path).is_ok() && unsafe { libc::access(c.as_ptr(), libc::W_OK | libc::X_OK) } == 0
}

/// Re-write a foreign-owned key as this process's: read it, write the
/// same bytes to a sibling created 0600, rename it over the original.
/// Needs read on the file and write on its directory — no privilege.
fn reown(path: &Path) -> std::io::Result<()> {
    use std::io::Write as _;
    use std::os::unix::fs::OpenOptionsExt as _;
    let data = std::fs::read(path)?;
    let name = path.file_name().map(|n| n.to_string_lossy().into_owned()).unwrap_or_default();
    let tmp = path.with_file_name(format!(".{name}.reown"));
    let _ = std::fs::remove_file(&tmp);
    let written = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(&tmp)
        .and_then(|mut f| f.write_all(&data).and_then(|_| f.sync_all()))
        .and_then(|_| std::fs::rename(&tmp, path));
    if written.is_err() {
        let _ = std::fs::remove_file(&tmp);
    }
    written
}

/// Write a private key so that no other principal can read it at any
/// instant: an existing file is taken to 0600 BEFORE its bytes change
/// (and a foreign-owned one is unlinked first — the operator owns the
/// directory, not necessarily the file), a new one is created 0600. The
/// reader's mode is applied afterwards by the caller.
fn write_key_file(path: &Path, data: &[u8]) -> Result<(), String> {
    use std::io::Write as _;
    use std::os::unix::fs::OpenOptionsExt as _;
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent).map_err(|e| format!("mkdir {}: {e}", parent.display()))?;
    }
    if path.exists() && (!owned_by_me(path) || !set_mode(path, 0o600)) {
        std::fs::remove_file(path).map_err(|e| format!("replace {}: {e}", path.display()))?;
    }
    let mut f = std::fs::OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .mode(0o600)
        .open(path)
        .map_err(|e| format!("write {}: {e}", path.display()))?;
    f.write_all(data).map_err(|e| format!("write {}: {e}", path.display()))?;
    set_mode(path, 0o600);
    Ok(())
}

/// A principal that can read a file besides its owner.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Principal {
    User(u32),
    Group(u32),
    Other,
}

/// What decides who reads a file: mode bits, owning gid, and the ACL
/// text when the file has one (`getfacl -c -n`; base entries mirror
/// the mode bits, named entries and the mask come from `setfacl`).
pub(crate) struct Access {
    pub mode: u32,
    pub gid: u32,
    pub acl: Option<String>,
}

fn access_of(path: &Path) -> Option<Access> {
    use std::os::unix::fs::MetadataExt as _;
    let md = std::fs::metadata(path).ok()?;
    let acl = std::process::Command::new("getfacl")
        .args(["-c", "-n"])
        .arg(path)
        .output()
        .ok()
        .filter(|o| o.status.success())
        .map(|o| String::from_utf8_lossy(&o.stdout).into_owned());
    Some(Access { mode: md.mode() & 0o777, gid: md.gid(), acl })
}

/// Everyone besides the owner who may read, from the ACL when there is
/// one (effective permissions: a named entry or the owning group is
/// read-capable only if the mask lets it), else from the mode bits.
pub(crate) fn extra_readers(acc: &Access) -> Vec<Principal> {
    let mut out = Vec::new();
    if let Some(text) = acc.acl.as_deref().filter(|t| t.lines().any(|l| l.starts_with("user::"))) {
        let entries: Vec<(&str, &str, &str)> = text
            .lines()
            .filter_map(|l| {
                let l = l.split_whitespace().next()?; // drop "#effective:" annotations
                let mut it = l.splitn(3, ':');
                Some((it.next()?, it.next()?, it.next()?))
            })
            .collect();
        let mask_reads = entries
            .iter()
            .find(|(tag, _, _)| *tag == "mask")
            .map(|(_, _, p)| p.contains('r'))
            .unwrap_or(true);
        for (tag, who, perms) in entries {
            let reads = perms.contains('r');
            match (tag, who) {
                ("user", "") => {}
                ("user", n) if reads && mask_reads => {
                    if let Ok(u) = n.parse() { out.push(Principal::User(u)) }
                }
                ("group", "") if reads && mask_reads => out.push(Principal::Group(acc.gid)),
                ("group", n) if reads && mask_reads => {
                    if let Ok(g) = n.parse() { out.push(Principal::Group(g)) }
                }
                ("other", _) if reads => out.push(Principal::Other),
                _ => {}
            }
        }
        return out;
    }
    if acc.mode & 0o040 != 0 {
        out.push(Principal::Group(acc.gid));
    }
    if acc.mode & 0o004 != 0 {
        out.push(Principal::Other);
    }
    out
}

/// Can a process with `uid` (and gid == uid) read the file? `None`
/// when it is absent. The owner is not consulted: the operator's uid
/// is never a container's.
pub fn readable_by_uid(path: &Path, uid: u32) -> Option<bool> {
    Some(reader_can_read(&extra_readers(&access_of(path)?), uid))
}

/// Can `uid` read: named for it, its group, or everyone.
fn reader_can_read(extras: &[Principal], uid: u32) -> bool {
    extras.iter().any(|p| match p {
        Principal::User(u) | Principal::Group(u) => *u == uid,
        Principal::Other => true,
    })
}

/// Can anyone who is neither the owner nor `uid` read: another user or
/// group entry, or everyone.
fn beyond_reader(extras: &[Principal], uid: u32) -> bool {
    extras.iter().any(|p| !matches!(p, Principal::User(u) | Principal::Group(u) if *u == uid))
}

/// Is the owning group (some group other than `uid`'s) read-capable?
fn group_read_beyond(path: &Path, uid: u32) -> bool {
    access_of(path).map(|acc| beyond_reader(&extra_readers(&acc), uid)).unwrap_or(false)
}

fn sudo_grant_line(path: &Path, uid: u32) -> String {
    format!("sudo chgrp {uid} {p} && sudo chmod 640 {p}", p = path.display())
}

/// Hand `path` to `uid` for reading, with nothing else able to: its
/// group when the caller may `chgrp` (root, or a member of that gid),
/// else a POSIX ACL entry on an owner-only file. `Ok` says which. `Err`
/// is the exact `sudo` line; the file is left as it was.
pub fn grant_read_to_uid(path: &Path, uid: u32) -> Result<&'static str, String> {
    use std::os::unix::fs::MetadataExt as _;
    let before = std::fs::metadata(path).map_err(|e| format!("{}: {e}", path.display()))?;
    if before.gid() == uid || std::os::unix::fs::chown(path, None, Some(uid)).is_ok() {
        return if set_mode(path, 0o640) { Ok("group") } else { Err(sudo_grant_line(path, uid)) };
    }
    // Owner-only first so the owning group does not ride along under
    // the ACL mask; setfacl then recomputes the mask from the entry.
    let prior = before.permissions().mode() & 0o777;
    if !set_mode(path, 0o600) {
        return Err(sudo_grant_line(path, uid));
    }
    let ok = std::process::Command::new("setfacl")
        .args(["-m", &format!("u:{uid}:r")])
        .arg(path)
        .output()
        .map(|o| o.status.success())
        .unwrap_or(false);
    if ok && readable_by_uid(path, uid) == Some(true) {
        return Ok("acl");
    }
    let _ = set_mode(path, prior);
    Err(sudo_grant_line(path, uid))
}

fn set_mode(path: &Path, mode: u32) -> bool {
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(mode)).is_ok()
}

fn collect_ext(dir: &Path, ext: &str, out: &mut Vec<PathBuf>) {
    let Ok(rd) = std::fs::read_dir(dir) else { return };
    for entry in rd.flatten() {
        let p = entry.path();
        if p.is_dir() {
            collect_ext(&p, ext, out);
        } else if p.extension().is_some_and(|e| e == ext) {
            out.push(p);
        }
    }
}

fn collect_dirs(dir: &Path, out: &mut Vec<PathBuf>) {
    out.push(dir.to_path_buf());
    let Ok(rd) = std::fs::read_dir(dir) else { return };
    for entry in rd.flatten() {
        let p = entry.path();
        if p.is_dir() {
            collect_dirs(&p, out);
        }
    }
}

// ── The gateway's certificate-only view ─────────────
//
// The gateway (uid 65532) used to bind-mount the WHOLE PKI dir. Modes
// confine every key to its one reader — except the keys whose reader IS
// uid 65532 (loki, prometheus, alertmanager, node-exporter, llamacpp):
// same uid, no mode can tell the gateway from them. So the fix is on the
// mount. The gateway reads `.crt` files under `nodes/` and `services/`
// (cert expiry, `/api/security/pki/status`) and no key there, so it
// mounts `public/nodes` and `public/services` — a mirror of every `*.crt`
// under those two trees and NOTHING else — at the same container paths
// (`/app/pki/nodes`, `/app/pki/services`) the whole-tree mount put them.
// The gateway's code, old image or new, reads the same paths it always
// did. Its other PKI mounts are `ca.crt`, `gateway/` and `sso/`.
//
// Kept in step by every writer of a certificate: `issue_leaf` (issue,
// issue-service, issue-gateway, rotate, rotate-all, provision, onboard,
// the upgrade's reconcile) re-syncs after writing, and `fix-modes`,
// onboard, `upgrade --stack` and `stack start|restart|rebuild` re-sync
// before anything is started. The two mirrored directories are never
// removed or replaced, only their contents: a running container's bind
// mount follows the directory inode.

/// The certificate-only mirror, relative to the PKI dir.
pub const PUBLIC_VIEW_REL: &str = "public";
/// The trees mirrored into it, each at the same relative path.
pub const PUBLIC_VIEW_TREES: &[&str] = &["nodes", "services"];

/// What `sync_public_view` did.
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct PublicViewSync {
    /// Certificates written (new or changed), relative to `public/`.
    pub copied: Vec<String>,
    /// Entries removed from `public/` (a cert whose source is gone, or
    /// anything that is not a mirrored certificate).
    pub removed: Vec<String>,
    /// Certificates now mirrored.
    pub total: usize,
    /// What could not be done; empty on success.
    pub errors: Vec<String>,
}

/// How `public/` differs from what it should hold. Every path is
/// relative to `public/`.
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct PublicViewDrift {
    /// A mirrored tree (`nodes`, `services`) that is not a directory.
    pub missing_roots: Vec<String>,
    /// A certificate under `nodes/`/`services/` with no copy.
    pub missing: Vec<String>,
    /// A copy whose bytes differ from its source (a rotation not synced).
    pub stale: Vec<String>,
    /// Anything else in `public/` — a cert whose source is gone, a
    /// symlink, a stray file.
    pub extra: Vec<String>,
    /// A private key (`*.key`) in `public/`: the one thing the view
    /// exists to keep from the gateway.
    pub keys: Vec<String>,
    /// Certificates mirrored correctly.
    pub total: usize,
}

impl PublicViewDrift {
    pub fn is_clean(&self) -> bool {
        self.missing_roots.is_empty()
            && self.missing.is_empty()
            && self.stale.is_empty()
            && self.extra.is_empty()
            && self.keys.is_empty()
    }
}

impl ClusterCa {
    /// `<pki>/public`.
    pub fn public_view_dir(&self) -> PathBuf {
        self.dir.join(PUBLIC_VIEW_REL)
    }

    /// Every `*.crt` under the mirrored trees, as (path relative to the
    /// PKI dir — which is also its path relative to `public/` — source).
    /// Regular files only: a symlink is never followed into the view.
    fn public_view_sources(&self) -> Vec<(PathBuf, PathBuf)> {
        let mut out = Vec::new();
        for tree in PUBLIC_VIEW_TREES {
            let mut crts = Vec::new();
            collect_regular_crts(&self.dir.join(tree), &mut crts);
            for src in crts {
                if let Ok(rel) = src.strip_prefix(&self.dir) {
                    out.push((rel.to_path_buf(), src.clone()));
                }
            }
        }
        out.sort();
        out
    }

    /// Bring `public/` in step with the certificates under `nodes/` and
    /// `services/`, and make sure every directory the gateway bind-mounts
    /// from the PKI dir exists (`public/nodes`, `public/services`, `sso/`)
    /// — owned by the operator, 0755 — so the launcher's bind-source check
    /// passes and Docker never creates one as root. Idempotent. Never
    /// fails the caller: what could not be done is in `errors`.
    pub fn sync_public_view(&self) -> PublicViewSync {
        let mut out = PublicViewSync::default();
        let public = self.public_view_dir();
        let mut roots: Vec<PathBuf> = PUBLIC_VIEW_TREES.iter().map(|t| public.join(t)).collect();
        roots.push(self.dir.join("sso"));
        for dir in std::iter::once(&public).chain(roots.iter()) {
            match std::fs::symlink_metadata(dir) {
                Ok(m) if m.is_dir() => continue,
                Ok(_) => {
                    // A file or symlink where a mount-source directory
                    // belongs: remove it rather than mount through it.
                    if let Err(e) = std::fs::remove_file(dir) {
                        out.errors.push(format!("remove {}: {e}", dir.display()));
                        continue;
                    }
                }
                Err(_) => {}
            }
            if let Err(e) = std::fs::create_dir_all(dir) {
                out.errors.push(format!("mkdir {}: {e}", dir.display()));
                continue;
            }
            set_mode(dir, 0o755);
        }

        let sources = self.public_view_sources();
        let wanted: std::collections::BTreeSet<PathBuf> = sources.iter().map(|(rel, _)| rel.clone()).collect();
        for (rel, src) in &sources {
            let bytes = match std::fs::read(src) {
                Ok(b) => b,
                Err(e) => {
                    out.errors.push(format!("read {}: {e}", src.display()));
                    continue;
                }
            };
            let dst = public.join(rel);
            let same = std::fs::symlink_metadata(&dst).map(|m| m.is_file()).unwrap_or(false)
                && std::fs::read(&dst).map(|b| b == bytes).unwrap_or(false);
            if same {
                out.total += 1;
                continue;
            }
            if let Some(parent) = dst.parent() {
                if !parent.is_dir() {
                    if let Err(e) = std::fs::create_dir_all(parent) {
                        out.errors.push(format!("mkdir {}: {e}", parent.display()));
                        continue;
                    }
                    set_mode(parent, 0o755);
                }
            }
            // Written beside, then renamed over: a reader never sees half
            // a certificate, and a symlink at `dst` is replaced, not
            // followed.
            let tmp = dst.with_extension("crt.sync-tmp");
            let wrote = std::fs::write(&tmp, &bytes)
                .and_then(|_| std::fs::set_permissions(&tmp, std::fs::Permissions::from_mode(0o644)))
                .and_then(|_| std::fs::rename(&tmp, &dst));
            match wrote {
                Ok(()) => {
                    out.copied.push(rel.to_string_lossy().into_owned());
                    out.total += 1;
                }
                Err(e) => {
                    let _ = std::fs::remove_file(&tmp);
                    out.errors.push(format!("write {}: {e}", dst.display()));
                }
            }
        }

        // Everything else under public/ goes: a copy whose source was
        // removed, a key someone put there, a symlink.
        let mut present = Vec::new();
        collect_entries(&public, &mut present);
        for p in present {
            let Ok(rel) = p.strip_prefix(&public) else { continue };
            let Ok(meta) = std::fs::symlink_metadata(&p) else { continue };
            if meta.is_dir() || wanted.contains(rel) {
                continue;
            }
            match std::fs::remove_file(&p) {
                Ok(()) => out.removed.push(rel.to_string_lossy().into_owned()),
                Err(e) => out.errors.push(format!("remove {}: {e}", p.display())),
            }
        }
        // Empty directories left behind, deepest first — never the view's
        // own roots, which running containers have bind-mounted.
        let mut dirs = Vec::new();
        collect_dirs(&public, &mut dirs);
        dirs.sort_by_key(|d| std::cmp::Reverse(d.components().count()));
        for d in dirs {
            if d == public || roots.contains(&d) {
                continue;
            }
            let empty = std::fs::read_dir(&d).map(|mut r| r.next().is_none()).unwrap_or(false);
            if empty && std::fs::remove_dir(&d).is_ok() {
                if let Ok(rel) = d.strip_prefix(&public) {
                    out.removed.push(format!("{}/", rel.to_string_lossy()));
                }
            }
        }
        out.copied.sort();
        out.removed.sort();
        out
    }

    /// How `public/` differs from what `sync_public_view` would make it.
    /// Reads only; `cluster verify --controller` and the tests use it.
    pub fn public_view_drift(&self) -> PublicViewDrift {
        let mut out = PublicViewDrift::default();
        let public = self.public_view_dir();
        for tree in PUBLIC_VIEW_TREES {
            if !std::fs::symlink_metadata(public.join(tree)).map(|m| m.is_dir()).unwrap_or(false) {
                out.missing_roots.push((*tree).to_string());
            }
        }
        let sources = self.public_view_sources();
        let wanted: std::collections::BTreeSet<PathBuf> = sources.iter().map(|(rel, _)| rel.clone()).collect();
        for (rel, src) in &sources {
            let dst = public.join(rel);
            let name = rel.to_string_lossy().into_owned();
            if !std::fs::symlink_metadata(&dst).map(|m| m.is_file()).unwrap_or(false) {
                out.missing.push(name);
            } else if std::fs::read(&dst).ok() != std::fs::read(src).ok() {
                out.stale.push(name);
            } else {
                out.total += 1;
            }
        }
        let mut present = Vec::new();
        collect_entries(&public, &mut present);
        present.sort();
        for p in present {
            let Ok(rel) = p.strip_prefix(&public) else { continue };
            let Ok(meta) = std::fs::symlink_metadata(&p) else { continue };
            if meta.is_dir() || wanted.contains(rel) {
                continue;
            }
            let name = rel.to_string_lossy().into_owned();
            if p.extension().is_some_and(|e| e == "key") {
                out.keys.push(name);
            } else {
                out.extra.push(name);
            }
        }
        out
    }
}

/// Every `*.crt` under `dir` that is a regular file (not a symlink).
fn collect_regular_crts(dir: &Path, out: &mut Vec<PathBuf>) {
    let Ok(rd) = std::fs::read_dir(dir) else { return };
    for entry in rd.flatten() {
        let p = entry.path();
        let Ok(ft) = entry.file_type() else { continue };
        if ft.is_dir() {
            collect_regular_crts(&p, out);
        } else if ft.is_file() && p.extension().is_some_and(|e| e == "crt") {
            out.push(p);
        }
    }
}

/// Every entry under `dir` (files, symlinks, directories), without
/// following symlinks.
fn collect_entries(dir: &Path, out: &mut Vec<PathBuf>) {
    let Ok(rd) = std::fs::read_dir(dir) else { return };
    for entry in rd.flatten() {
        let p = entry.path();
        let is_dir = entry.file_type().map(|t| t.is_dir()).unwrap_or(false);
        out.push(p.clone());
        if is_dir {
            collect_entries(&p, out);
        }
    }
}

impl ClusterCa {
    /// Marker: this node has been handed the current `signing.pub` and
    /// confirmed it applied. Until it exists, bundles for that node are
    /// still signed with the CA key, because that is the only anchor the
    /// node can verify. Written by `rotate-signing-key` on a confirmed
    /// delivery, cleared by minting a new signing key.
    pub fn signing_adopted_path(&self, node: &str) -> PathBuf {
        self.dir.join("nodes").join(node).join("signing-adopted")
    }

    pub fn signing_adopted(&self, node: &str) -> bool {
        self.signing_adopted_path(node).exists()
    }

    /// Is `key` this cluster's CA private key? A bundle signed with it is a
    /// ROLLOVER: it must carry `signing-pub` and be
    /// countersigned with the retained signing keys.
    pub fn is_ca_key(&self, key: &Path) -> bool {
        key == self.ca_key_path()
    }

    /// Every fleet signing key this controller still holds, current first,
    /// then the archived `signing.key.<unix>.bak` pairs `mint_signing_key`
    /// leaves behind, newest first (at most four of those).
    ///
    /// A CA-signed rollover is accepted by a node that
    /// already holds a signing key only when that key COUNTERSIGNED it. A node
    /// that was offline through a rotation still holds the previous key, so
    /// the rollover is countersigned with each retained key and the node
    /// verifies whichever one it has. An archive deleted by hand strands such
    /// a node until it re-enrolls — which is the point: the CA alone cannot
    /// replace an adopted key.
    pub fn retained_signing_keys(&self) -> Vec<PathBuf> {
        let mut out = Vec::new();
        if self.signing_key_path().is_file() {
            out.push(self.signing_key_path());
        }
        let mut archived: Vec<(u64, PathBuf)> = std::fs::read_dir(&self.dir)
            .map(|rd| {
                rd.flatten()
                    .filter_map(|e| {
                        let name = e.file_name().to_string_lossy().to_string();
                        let ts = name.strip_prefix("signing.key.")?.strip_suffix(".bak")?.parse::<u64>().ok()?;
                        Some((ts, e.path()))
                    })
                    .collect()
            })
            .unwrap_or_default();
        archived.sort_by_key(|(ts, _)| std::cmp::Reverse(*ts));
        out.extend(archived.into_iter().take(4).map(|(_, p)| p));
        out
    }

    /// Which private key signs a bundle addressed to `node`.
    ///
    /// A node that has not yet adopted the signing key can only verify the
    /// CA, so signing with the new key would hand it a bundle it must
    /// refuse. Adoption is per-node and recorded on this controller; the
    /// fleet converges one `rotate-signing-key` at a time, and nothing is
    /// broken in between.
    pub fn bundle_signing_key(&self, node: &str) -> PathBuf {
        if self.signing_adopted(node) && self.signing_key_exists() {
            self.signing_key_path()
        } else {
            self.ca_key_path()
        }
    }

    // ── CA ──────────────────────────────────────────────────────────

    /// Create the self-signed cluster CA. Refuses to overwrite.
    pub fn generate_ca(&self, cn: &str, days: i64) -> Result<(PathBuf, PathBuf), String> {
        if self.ca_exists() {
            return Err(format!("CA already exists at {}", self.ca_cert_path().display()));
        }
        let key = KeyPair::generate_for(&rcgen::PKCS_ECDSA_P384_SHA384)
            .map_err(|e| format!("keygen failed: {e}"))?;

        let mut params = CertificateParams::default();
        params.distinguished_name.push(DnType::CommonName, cn);
        params.distinguished_name.push(DnType::OrganizationName, CA_O);
        // ca.py order + exact DER (see module docs on why not rcgen's builders):
        //   BasicConstraints critical CA:TRUE pathlen:0 → 30 06 01 01 FF 02 01 00
        //   KeyUsage critical digitalSignature|keyCertSign|cRLSign → 03 02 01 86
        //   SubjectKeyIdentifier = SHA-1(subjectPublicKey bits)
        params.custom_extensions = vec![
            ext(OID_BASIC_CONSTRAINTS, true, vec![0x30, 0x06, 0x01, 0x01, 0xFF, 0x02, 0x01, 0x00]),
            ext(OID_KEY_USAGE, true, vec![0x03, 0x02, 0x01, 0x86]),
            ext(OID_SKI, false, der_tlv(0x04, &sha1_of(key.public_key_raw()))),
        ];
        let now = OffsetDateTime::now_utc();
        params.not_before = now - Duration::minutes(5);
        params.not_after = now + Duration::days(days);
        params.serial_number = Some(random_serial());

        let cert = params
            .self_signed(&key)
            .map_err(|e| format!("CA self-sign failed: {e}"))?;

        std::fs::create_dir_all(&self.dir).map_err(|e| format!("mkdir {}: {e}", self.dir.display()))?;
        write_file(&self.ca_cert_path(), cert.pem().as_bytes(), None)?;
        write_key_file(&self.ca_key_path(), key.serialize_pem().as_bytes())?;
        // The fleet signing key is born with the CA, not lazily on the
        // first push: an operator who inspects the PKI dir right after
        // `pki init` should see both halves of the split, and `onboard`
        // gets one without a second step.
        self.ensure_signing_key()?;
        Ok((self.ca_cert_path(), self.ca_key_path()))
    }

    /// Load the on-disk CA for signing. The issuer's DN is re-encoded by
    /// rcgen from the parsed ca.crt — UTF8String attrs round-trip
    /// byte-identically (verified against webpki's exact-DER issuer match).
    fn load_ca(&self) -> Result<(Certificate, KeyPair), String> {
        if !self.ca_exists() {
            return Err(format!(
                "No cluster CA at {} — run 'noo security pki init' first",
                self.dir.display()
            ));
        }
        let ca_pem = std::fs::read_to_string(self.ca_cert_path())
            .map_err(|e| format!("read ca.crt: {e}"))?;
        let key_pem = std::fs::read_to_string(self.ca_key_path())
            .map_err(|e| format!("read ca.key: {e}"))?;
        let ca_key = KeyPair::from_pem(&key_pem).map_err(|e| format!("parse ca.key: {e}"))?;
        let params = CertificateParams::from_ca_cert_pem(&ca_pem)
            .map_err(|e| format!("parse ca.crt: {e}"))?;
        let ca_cert = params
            .self_signed(&ca_key)
            .map_err(|e| format!("reconstruct CA: {e}"))?;
        Ok((ca_cert, ca_key))
    }

    // ── Leaf issuance ───────────────────────────────────────────────

    fn issue_leaf(
        &self,
        cn: &str,
        org: &str,
        cert_path: &Path,
        key_path: &Path,
        dns_sans: &[String],
        ip_sans: &[String],
        days: i64,
    ) -> Result<(PathBuf, PathBuf), String> {
        let (ca_cert, ca_key) = self.load_ca()?;
        let key = KeyPair::generate_for(&rcgen::PKCS_ECDSA_P384_SHA384)
            .map_err(|e| format!("keygen failed: {e}"))?;

        // De-dup while preserving order; drop empties (ca.py parity: DNS
        // and IP pools de-dup separately; a non-IP in the IP pool becomes a
        // DNS SAN appended in the IP block's position).
        let mut dns_seen: Vec<&String> = Vec::new();
        for d in dns_sans {
            if !d.is_empty() && !dns_seen.contains(&d) {
                dns_seen.push(d);
            }
        }
        let mut ip_seen: Vec<&String> = Vec::new();
        for i in ip_sans {
            if !i.is_empty() && !ip_seen.contains(&i) {
                ip_seen.push(i);
            }
        }
        // GeneralNames DER: dNSName = [2] IMPLICIT IA5String,
        // iPAddress = [7] IMPLICIT OCTET STRING (4 or 16 octets).
        let mut general_names: Vec<u8> = Vec::new();
        for d in &dns_seen {
            general_names.extend(der_tlv(0x82, d.as_bytes()));
        }
        for i in &ip_seen {
            match i.parse::<IpAddr>() {
                Ok(IpAddr::V4(a)) => general_names.extend(der_tlv(0x87, &a.octets())),
                Ok(IpAddr::V6(a)) => general_names.extend(der_tlv(0x87, &a.octets())),
                Err(_) => general_names.extend(der_tlv(0x82, i.as_bytes())), // not an IP — a name
            }
        }

        let mut params = CertificateParams::default();
        params.distinguished_name.push(DnType::CommonName, cn);
        params.distinguished_name.push(DnType::OrganizationName, org);
        // ca.py order + exact DER (see module docs):
        //   BasicConstraints critical CA:FALSE → empty SEQUENCE (30 00)
        //   SubjectAlternativeName
        //   ExtendedKeyUsage = clientAuth, serverAuth (that order)
        //   SKI = SHA-1(subject key bits), AKI = SHA-1(CA key bits)
        params.custom_extensions = vec![
            ext(OID_BASIC_CONSTRAINTS, true, vec![0x30, 0x00]),
            ext(OID_SAN, false, der_tlv(0x30, &general_names)),
            ext(
                OID_EKU,
                false,
                der_tlv(0x30, &[DER_OID_CLIENT_AUTH, DER_OID_SERVER_AUTH].concat()),
            ),
            ext(OID_SKI, false, der_tlv(0x04, &sha1_of(key.public_key_raw()))),
            ext(
                OID_AKI,
                false,
                der_tlv(0x30, &der_tlv(0x80, &sha1_of(ca_key.public_key_raw()))),
            ),
        ];
        let now = OffsetDateTime::now_utc();
        params.not_before = now - Duration::minutes(5);
        params.not_after = now + Duration::days(days);
        params.serial_number = Some(random_serial());

        let cert = params
            .signed_by(&key, &ca_cert, &ca_key)
            .map_err(|e| format!("sign failed: {e}"))?;

        // Certificates are public but not anyone's to rewrite: 0644 always,
        // not whatever the umask leaves (0664 under a umask-002 shell).
        write_file(cert_path, cert.pem().as_bytes(), Some(0o644))?;
        // The key is 0600 from its first byte (`write_key_file`), then gets
        // its reader's mode. A re-issue truncates in place, so a key
        // already handed to its reader (group or ACL) keeps the group and
        // the ACL entry; `apply_key_mode` makes the grant on a first issue
        // and restores the 0640 on a re-issue. Its outcome is not an error
        // here: issuance succeeded, and the callers (`emit_pair`, onboard,
        // `fix-modes`, the scan, `cluster verify`) say what still needs a
        // hand the operator has and this process does not.
        write_key_file(key_path, key.serialize_pem().as_bytes())?;
        if self.key_reader(key_path) == KeyReader::Unknown {
            // No reader row: the legacy 0644 until the table names one, so
            // an unlisted consumer still starts; the scan reports it.
            set_mode(key_path, KeyReader::Unknown.mode());
        }
        let _ = self.apply_key_mode(key_path);
        // The gateway reads certificates through `public/`:
        // every issue and every rotation re-syncs it, or the
        // gateway reports the old expiry of a cert this just replaced.
        // Its failures are not issuance's; `fix-modes` and `cluster
        // verify --controller` (the "gateway pki view" row) name them.
        let _ = self.sync_public_view();
        Ok((cert_path.to_path_buf(), key_path.to_path_buf()))
    }

    /// Best-effort tailnet IPv4 for `host` via the local tailscale CLI —
    /// the address the node's agent registers as its `agent_url` (finding
    /// #79), so callers fold it into `extra_ips` at issuance. `None` when
    /// tailscale is absent or does not know the host; issuance proceeds
    /// without it exactly as before.
    pub fn tailscale_ip4(host: &str) -> Option<String> {
        let out = std::process::Command::new("tailscale")
            .args(["ip", "-4", host])
            .output()
            .ok()?;
        if !out.status.success() {
            return None;
        }
        let ip = String::from_utf8_lossy(&out.stdout).lines().next()?.trim().to_string();
        if ip.is_empty() { None } else { Some(ip) }
    }

    /// Cert for a worker node-agent (server + mTLS client).
    ///
    /// `extra_ips`: the agent registers `agent_url` with the IP of its route
    /// to the controller — on a tailnet controller that is the node's
    /// TAILSCALE address, which was never a SAN here while the gateway's
    /// gpu_health/node_dispatch_health loops dial exactly that address every
    /// 300s. rustls answered NotValidForName → "bad certificate" in the
    /// agent journal, and both GPU watchdogs sat silently disarmed (finding
    /// #79 — the node-cert half of the same class finding #33 fixed for
    /// service and gateway certs).
    ///
    /// `role`: the controller's OWN node cert must carry the
    /// names the controller is reached by. The gateway dials its own agent
    /// at `https://<controller name>:8081` (`self_agent_base`) for the kiosk
    /// mint and tailnet enrollment. Every re-issue path used to rebuild the
    /// SAN set from the node name and address alone, so a provision or an
    /// upgrade silently dropped `noo-controller.<tailnet>` and the kiosk
    /// went dark. The role is a required argument so no call site can
    /// forget it, and [`NodeRole::of`] is the one place that decides it.
    pub fn issue_node_cert(
        &self,
        node_id: &str,
        ip: &str,
        days: i64,
        extra_sans: &[String],
        extra_ips: &[String],
        role: &NodeRole,
    ) -> Result<(PathBuf, PathBuf), String> {
        let node_dir = self.dir.join("nodes").join(node_id);
        let crt_path = node_dir.join("node.crt");
        let mut dns: Vec<String> = vec![node_id.into(), "localhost".into()];
        for s in extra_sans {
            push_unique(&mut dns, s);
        }
        let mut ips: Vec<String> = vec![ip.into(), "127.0.0.1".into()];
        for extra in extra_ips {
            push_unique(&mut ips, extra);
        }
        if let NodeRole::Controller(names) = role {
            for s in &names.dns {
                push_unique(&mut dns, s);
            }
            for s in &names.ips {
                push_unique(&mut ips, s);
            }
            // Never drop a NAME the controller's cert already carries: an
            // operator's `--san` (the i11a workaround was exactly that) or a
            // name declared before a config change survives a routine
            // re-issue. Names only. An address is what drifts, and carrying
            // addresses forward is how a stray one would stick for good.
            if let Ok(have) = Self::cert_names(&crt_path) {
                for s in &have.dns {
                    push_unique(&mut dns, s);
                }
            }
        }
        let out = self.issue_leaf(
            node_id,
            "Mesh Cluster Node",
            &crt_path,
            &node_dir.join("node.key"),
            &dns,
            &ips,
            days,
        )?;
        if let NodeRole::Controller(names) = role {
            // Loud, not trusted: read back what was written.
            let have = Self::cert_names(&out.0)?;
            let missing = missing_names(&have, &names.dns, &names.ips);
            if !missing.is_empty() {
                return Err(format!(
                    "the controller's node cert for {node_id} was issued WITHOUT the controller names {}; \
                     the gateway's self-agent calls (kiosk, tailnet enrollment) would fail by name",
                    missing.join(", ")
                ));
            }
        }
        Ok(out)
    }

    /// Dual-purpose (server + client) cert for the gateway.
    pub fn issue_gateway_cert(
        &self,
        hostname: &str,
        ip: &str,
        days: i64,
        extra_sans: &[String],
        extra_ips: &[String],
    ) -> Result<(PathBuf, PathBuf), String> {
        let gw_dir = self.dir.join("gateway");
        let mut dns: Vec<String> = vec![
            hostname.into(),
            hostname.to_lowercase(),
            "localhost".into(),
            "gateway".into(),
            "noo-controller".into(),
            "noo-gateway".into(),
        ];
        // On a named instance the gateway's network alias is
        // prefixed (noo-galaxy-gateway) — the cert must cover the name
        // other containers actually dial, or in-cluster TLS fails on
        // hostname verification. Default instance: no-op duplicate guard.
        let instanced_alias = crate::envfile::container("gateway");
        if !dns.contains(&instanced_alias) {
            dns.push(instanced_alias);
        }
        dns.extend(extra_sans.iter().cloned());
        let mut ips: Vec<String> = vec!["127.0.0.1".into(), ip.into()];
        ips.extend(extra_ips.iter().cloned());
        self.issue_leaf(
            hostname,
            "Mesh Cluster Gateway",
            &gw_dir.join("gateway.crt"),
            &gw_dir.join("gateway.key"),
            &dns,
            &ips,
            days,
        )
    }

    /// Cert for an internal service (postgres, nats, redis, …).
    /// `extra_ips` add to the default `127.0.0.1` SAN — externally-reachable
    /// services (nats/redis/postgres) need the controller's LAN IP so remote
    /// workers can verify the cert (parity with `ca.py`'s `ips=` argument).
    pub fn issue_service_cert(
        &self,
        service: &str,
        hostnames: &[String],
        extra_ips: &[String],
        days: i64,
    ) -> Result<(PathBuf, PathBuf), String> {
        let svc_dir = self.dir.join("services").join(service);
        let mut dns: Vec<String> = vec![service.into(), "localhost".into()];
        dns.extend(hostnames.iter().cloned());
        let mut ips: Vec<String> = vec!["127.0.0.1".into()];
        ips.extend(extra_ips.iter().cloned());
        self.issue_leaf(
            service,
            "Mesh Cluster Service",
            &svc_dir.join("service.crt"),
            &svc_dir.join("service.key"),
            &dns,
            &ips,
            days,
        )
    }

    /// A NODE's backend door leaf: the same profile as
    /// [`issue_service_cert`] — CN=<service>, O=Mesh Cluster Service,
    /// `<service>` + `localhost` + `hostnames` as DNS SANs, `127.0.0.1` —
    /// but stored under `nodes/<node>/services/<service>/`, so each node
    /// holds its own key and one node's leaf can be re-issued or dropped
    /// without touching any other node's or the controller's own
    /// `services/<service>` leaf. The key is 0600 (`key_reader`: CLI).
    pub fn issue_node_service_cert(
        &self,
        node: &str,
        service: &str,
        hostnames: &[String],
        days: i64,
    ) -> Result<(PathBuf, PathBuf), String> {
        let dir = self.node_service_dir(node, service);
        let mut dns: Vec<String> = vec![service.into(), "localhost".into()];
        dns.extend(hostnames.iter().cloned());
        self.issue_leaf(
            service,
            "Mesh Cluster Service",
            &dir.join("service.crt"),
            &dir.join("service.key"),
            &dns,
            &["127.0.0.1".to_string()],
            days,
        )
    }

    /// Issue one Postgres role leaf: CN = the role, O = "Mesh Cluster
    /// Service", client authentication. Its one DNS SAN is a name no door
    /// pins on (`pg-<owner>-<role>`), so a role leaf can never pass a
    /// stunnel `checkHost` pin meant for the gateway, worker or trellion.
    pub fn issue_pg_leaf(&self, leaf: &PgLeaf, days: i64) -> Result<(PathBuf, PathBuf), String> {
        self.issue_leaf(
            leaf.role,
            "Mesh Cluster Service",
            &self.dir.join(leaf.cert_rel()),
            &self.dir.join(leaf.key_rel()),
            &[format!("pg-{}-{}", leaf.owner, leaf.role)],
            &[],
            days,
        )
    }

    /// The CN of an issued role leaf: `Ok(None)` when there is no such
    /// file, `Err` when it cannot be read or parsed (so a caller can tell
    /// "missing" from "cannot tell").
    pub fn pg_leaf_cn(&self, leaf: &PgLeaf) -> Result<Option<String>, String> {
        let crt = self.dir.join(leaf.cert_rel());
        if !crt.is_file() {
            return Ok(None);
        }
        let data = std::fs::read(&crt).map_err(|e| format!("read {}: {e}", crt.display()))?;
        let (_, pem) = x509_parser::pem::parse_x509_pem(&data)
            .map_err(|e| format!("parse PEM {}: {e}", crt.display()))?;
        let cert = pem.parse_x509().map_err(|e| format!("parse cert {}: {e}", crt.display()))?;
        Ok(cert.subject().iter_common_name().next().and_then(|a| a.as_str().ok()).map(str::to_string))
    }

    /// Is this role leaf present, with CN == its role, and with a private
    /// key beside it? `Err` carries the reason it is not.
    pub fn pg_leaf_state(&self, leaf: &PgLeaf) -> Result<(), String> {
        match self.pg_leaf_cn(leaf) {
            Ok(Some(cn)) if cn == leaf.role => {}
            Ok(Some(cn)) => return Err(format!("{} has CN {cn}, not {}", leaf.cert_rel(), leaf.role)),
            Ok(None) => return Err(format!("{} does not exist", leaf.cert_rel())),
            Err(e) => return Err(e),
        }
        if !self.dir.join(leaf.key_rel()).is_file() {
            return Err(format!("{} does not exist", leaf.key_rel()));
        }
        Ok(())
    }

    /// Issue every role leaf in [`PG_LEAVES`] that is missing, has no key,
    /// or whose CN is not its role. Idempotent: a leaf that is right is left
    /// alone, so a second call changes nothing. Returns, per leaf,
    /// `Ok(true)` when it issued one, `Ok(false)` when it was already right,
    /// `Err` with the reason when it could not.
    pub fn ensure_pg_leaves(&self, days: i64) -> Vec<(&'static PgLeaf, Result<bool, String>)> {
        PG_LEAVES
            .iter()
            .map(|l| {
                let r = if self.pg_leaf_state(l).is_ok() {
                    Ok(false)
                } else {
                    self.issue_pg_leaf(l, days).map(|_| true)
                };
                (l, r)
            })
            .collect()
    }

    /// `nodes/<node>/services/<service>` under this PKI dir.
    pub fn node_service_dir(&self, node: &str, service: &str) -> PathBuf {
        self.dir.join("nodes").join(node).join("services").join(service)
    }

    /// An OPERATOR client leaf: a person, not a node or a
    /// service. `CN=operator:<account>`, `O=Mesh Cluster Operator`, client
    /// authentication ONLY (no serverAuth, no SAN — it can never stand as a
    /// server), `digitalSignature`.
    ///
    /// Returns `(cert_pem, key_pem)` and WRITES NOTHING: the pair belongs in
    /// the operator's own config directory (`crate::operator_cert`), never
    /// under this PKI dir, which containers bind-mount. Keeping the write
    /// out of this type is what makes "the key never lands in the shared
    /// tree" a property of the code rather than of a path argument.
    pub fn issue_operator_leaf(&self, account: &str, days: i64) -> Result<(String, String), String> {
        let (ca_cert, ca_key) = self.load_ca()?;
        let key = KeyPair::generate_for(&rcgen::PKCS_ECDSA_P384_SHA384)
            .map_err(|e| format!("keygen failed: {e}"))?;
        let mut params = CertificateParams::default();
        params
            .distinguished_name
            .push(DnType::CommonName, format!("{OPERATOR_CN_PREFIX}{account}"));
        params.distinguished_name.push(DnType::OrganizationName, OPERATOR_ORG);
        params.custom_extensions = vec![
            ext(OID_BASIC_CONSTRAINTS, true, vec![0x30, 0x00]),
            // KeyUsage critical digitalSignature → BIT STRING 03 02 07 80
            ext(OID_KEY_USAGE, true, vec![0x03, 0x02, 0x07, 0x80]),
            ext(OID_EKU, false, der_tlv(0x30, &DER_OID_CLIENT_AUTH)),
            ext(OID_SKI, false, der_tlv(0x04, &sha1_of(key.public_key_raw()))),
            ext(
                OID_AKI,
                false,
                der_tlv(0x30, &der_tlv(0x80, &sha1_of(ca_key.public_key_raw()))),
            ),
        ];
        let now = OffsetDateTime::now_utc();
        params.not_before = now - Duration::minutes(5);
        params.not_after = now + Duration::days(days);
        params.serial_number = Some(random_serial());
        let cert = params
            .signed_by(&key, &ca_cert, &ca_key)
            .map_err(|e| format!("sign failed: {e}"))?;
        Ok((cert.pem(), key.serialize_pem()))
    }

    // ── Inventory ───────────────────────────────────────────────────

    /// Every *.crt under the PKI dir, sorted by path (ca.py `sorted(rglob)`
    /// parity). Unparseable files are skipped silently, like Python.
    pub fn list_certs(&self) -> Vec<CertInfo> {
        let mut paths: Vec<PathBuf> = Vec::new();
        collect_crts(&self.dir, &mut paths);
        // `public/` holds copies of certificates listed here already
        // (the gateway's view): never a second entry, and
        // never something `rotate-all` could pick up.
        let public = self.public_view_dir();
        paths.retain(|p| !p.starts_with(&public));
        paths.sort();
        let now = OffsetDateTime::now_utc().unix_timestamp();
        let mut out = Vec::new();
        for p in paths {
            let Ok(data) = std::fs::read(&p) else { continue };
            let Ok((_, pem)) = x509_parser::pem::parse_x509_pem(&data) else { continue };
            let Ok(cert) = pem.parse_x509() else { continue };
            let exp = cert.validity().not_after.timestamp();
            let days_left = (exp - now).div_euclid(86_400);
            let d = OffsetDateTime::from_unix_timestamp(exp)
                .unwrap_or(OffsetDateTime::UNIX_EPOCH);
            out.push(CertInfo {
                name: p
                    .strip_prefix(&self.dir)
                    .unwrap_or(&p)
                    .to_string_lossy()
                    .into_owned(),
                role: self.role_of(&p),
                expires: format!("{:04}-{:02}-{:02}", d.year(), u8::from(d.month()), d.day()),
                days_left,
                path: p,
            });
        }
        out
    }

    /// Certs under the PKI dir expiring within `warn_days` — ca.py
    /// `get_expiring_certs` parity: the filter is `days_left <= warn_days`
    /// (an inclusive boundary, so a cert with exactly `warn_days` left IS
    /// reported).
    pub fn expiring_certs(&self, warn_days: i64) -> Vec<CertInfo> {
        self.list_certs()
            .into_iter()
            .filter(|c| c.days_left <= warn_days)
            .collect()
    }

    /// Re-issue every expiring LEAF cert in place, preserving its subject
    /// (CN + O) and SANs. The CA itself is never rotated. Per-cert errors
    /// are captured so the rest keep rotating — ca.py `rotate_all_expiring`
    /// parity, including the `role in ("ca","other") → skip` rule.
    ///
    /// `role_for` names the role of a NODE cert's node (i11a): the
    /// controller's own node cert gains any controller name it lacks.
    pub fn rotate_all_expiring(
        &self,
        warn_days: i64,
        new_days: i64,
        role_for: impl Fn(&str) -> NodeRole,
    ) -> Vec<RotateResult> {
        let mut results = Vec::new();
        for info in self.expiring_certs(warn_days) {
            if info.role == "ca" || info.role == "other" {
                continue;
            }
            let role = match self.node_of_cert(&info.path) {
                Some(node) if info.role == "node" => role_for(&node),
                _ => NodeRole::Worker,
            };
            let entry = match self.reissue_in_place(&info.path, new_days, &role) {
                Ok(()) => RotateResult {
                    name: info.name,
                    role: info.role,
                    status: "rotated",
                    error: String::new(),
                },
                Err(e) => RotateResult {
                    name: info.name,
                    role: info.role,
                    status: "error",
                    error: e,
                },
            };
            results.push(entry);
        }
        results
    }

    /// Do the cert's SANs cover every required DNS name and IP? Any parse
    /// failure returns false (treat unreadable as not-covering → reissue).
    /// Exists for first-contact finding #33: certs issued before the tailnet
    /// name joined the SAN set must be detected and re-issued, not skipped.
    pub fn cert_covers_sans(cert_path: &Path, dns: &[String], ips: &[String]) -> bool {
        match Self::cert_names(cert_path) {
            Ok(have) => missing_names(&have, dns, ips).is_empty(),
            Err(_) => false,
        }
    }

    /// The DNS and IP SANs the leaf at `cert_path` carries. `Err` = the file
    /// is unreadable or not a certificate (the message says which), so a
    /// caller can tell "short" from "cannot tell".
    pub fn cert_names(cert_path: &Path) -> Result<CertNames, String> {
        use x509_parser::extensions::GeneralName;
        let data = std::fs::read(cert_path).map_err(|e| format!("read {}: {e}", cert_path.display()))?;
        let (_, pem) = x509_parser::pem::parse_x509_pem(&data)
            .map_err(|e| format!("parse PEM {}: {e}", cert_path.display()))?;
        let cert = pem
            .parse_x509()
            .map_err(|e| format!("parse cert {}: {e}", cert_path.display()))?;
        let mut have = CertNames::default();
        if let Ok(Some(san)) = cert.subject_alternative_name() {
            for gn in &san.value.general_names {
                match gn {
                    GeneralName::DNSName(d) => have.dns.push((*d).to_string()),
                    GeneralName::IPAddress(b) => match b.len() {
                        4 => {
                            let o: [u8; 4] = (*b).try_into().unwrap();
                            have.ips.push(IpAddr::from(o).to_string());
                        }
                        16 => {
                            let o: [u8; 16] = (*b).try_into().unwrap();
                            have.ips.push(IpAddr::from(o).to_string());
                        }
                        _ => {}
                    },
                    _ => {}
                }
            }
        }
        Ok(have)
    }

    /// Parse the existing cert at `cert_path`, extract CN / O / SANs, and
    /// issue a fresh leaf to the same `.crt`/`.key` paths. Mirrors the
    /// extraction in ca.py: O defaults to "Mesh Cluster" when absent; a
    /// cert with no SAN extension gets `dns=[cn], ips=[]`.
    ///
    /// For the controller's own node cert (`role` = Controller), any
    /// controller name the cert lacks is added (i11a): a rotation never
    /// drops one, and it repairs a cert that already had.
    pub(crate) fn reissue_in_place(&self, cert_path: &Path, days: i64, role: &NodeRole) -> Result<(), String> {
        use x509_parser::extensions::GeneralName;

        let data = std::fs::read(cert_path).map_err(|e| format!("read {}: {e}", cert_path.display()))?;
        let (_, pem) = x509_parser::pem::parse_x509_pem(&data)
            .map_err(|e| format!("parse PEM {}: {e}", cert_path.display()))?;
        let cert = pem
            .parse_x509()
            .map_err(|e| format!("parse cert {}: {e}", cert_path.display()))?;

        let cn = cert
            .subject()
            .iter_common_name()
            .next()
            .and_then(|a| a.as_str().ok())
            .ok_or_else(|| format!("no CN in {}", cert_path.display()))?
            .to_string();
        let org = cert
            .subject()
            .iter_organization()
            .next()
            .and_then(|a| a.as_str().ok())
            .unwrap_or(CA_O)
            .to_string();

        let mut dns_sans: Vec<String> = Vec::new();
        let mut ip_sans: Vec<String> = Vec::new();
        if let Ok(Some(san)) = cert.subject_alternative_name() {
            for gn in &san.value.general_names {
                match gn {
                    GeneralName::DNSName(d) => dns_sans.push((*d).to_string()),
                    GeneralName::IPAddress(b) => match b.len() {
                        4 => {
                            let o: [u8; 4] = (*b).try_into().unwrap();
                            ip_sans.push(IpAddr::from(o).to_string());
                        }
                        16 => {
                            let o: [u8; 16] = (*b).try_into().unwrap();
                            ip_sans.push(IpAddr::from(o).to_string());
                        }
                        _ => {}
                    },
                    _ => {}
                }
            }
        }
        if dns_sans.is_empty() && ip_sans.is_empty() {
            dns_sans = vec![cn.clone()];
        }
        if let NodeRole::Controller(names) = role {
            for d in &names.dns {
                push_unique(&mut dns_sans, d);
            }
            for i in &names.ips {
                push_unique(&mut ip_sans, i);
            }
        }

        let key_path = cert_path.with_extension("key");
        self.issue_leaf(&cn, &org, cert_path, &key_path, &dns_sans, &ip_sans, days)?;
        Ok(())
    }

    /// `<node>` for a cert at `nodes/<node>/node.crt` under this PKI.
    pub(crate) fn node_of_cert(&self, cert_path: &Path) -> Option<String> {
        let rel = cert_path.strip_prefix(&self.dir).ok()?;
        let parts: Vec<&str> = rel.iter().filter_map(|c| c.to_str()).collect();
        match parts.as_slice() {
            ["nodes", node, "node.crt"] => Some((*node).to_string()),
            _ => None,
        }
    }

    fn role_of(&self, cert_path: &Path) -> &'static str {
        let rel = cert_path.strip_prefix(&self.dir).unwrap_or(cert_path);
        match rel.components().next().and_then(|c| c.as_os_str().to_str()) {
            Some("gateway") => "gateway",
            Some("nodes") => "node",
            Some("services") => "service",
            _ => {
                if cert_path.file_name().is_some_and(|n| n == "ca.crt") {
                    "ca"
                } else {
                    "other"
                }
            }
        }
    }
}

fn collect_crts(dir: &Path, out: &mut Vec<PathBuf>) {
    let Ok(rd) = std::fs::read_dir(dir) else { return };
    for entry in rd.flatten() {
        let p = entry.path();
        if p.is_dir() {
            collect_crts(&p, out);
        } else if p.extension().is_some_and(|e| e == "crt") {
            out.push(p);
        }
    }
}

// X.509v3 extension OIDs (id-ce arc).
const OID_SKI: &[u64] = &[2, 5, 29, 14];
const OID_KEY_USAGE: &[u64] = &[2, 5, 29, 15];
const OID_SAN: &[u64] = &[2, 5, 29, 17];
const OID_BASIC_CONSTRAINTS: &[u64] = &[2, 5, 29, 19];
const OID_EKU: &[u64] = &[2, 5, 29, 37];
const OID_AKI: &[u64] = &[2, 5, 29, 35];
// Full OID TLVs for id-kp-clientAuth (1.3.6.1.5.5.7.3.2) and
// id-kp-serverAuth (1.3.6.1.5.5.7.3.1) — leaf EKU lists client FIRST,
// matching ca.py.
const DER_OID_CLIENT_AUTH: [u8; 10] = [0x06, 0x08, 0x2B, 0x06, 0x01, 0x05, 0x05, 0x07, 0x03, 0x02];
const DER_OID_SERVER_AUTH: [u8; 10] = [0x06, 0x08, 0x2B, 0x06, 0x01, 0x05, 0x05, 0x07, 0x03, 0x01];

fn ext(oid: &[u64], critical: bool, content: Vec<u8>) -> CustomExtension {
    let mut e = CustomExtension::from_oid_content(oid, content);
    e.set_criticality(critical);
    e
}

/// Minimal DER TLV writer (definite length, up to 64 KiB — SAN lists and
/// key identifiers are far below that).
fn der_tlv(tag: u8, content: &[u8]) -> Vec<u8> {
    let len = content.len();
    assert!(len <= 0xFFFF, "DER value too large");
    let mut out = Vec::with_capacity(len + 4);
    out.push(tag);
    if len < 128 {
        out.push(len as u8);
    } else if len < 256 {
        out.extend([0x81, len as u8]);
    } else {
        out.push(0x82);
        out.extend((len as u16).to_be_bytes());
    }
    out.extend_from_slice(content);
    out
}

/// RFC 5280 §4.2.1.2 method 1 key identifier: SHA-1 over the
/// subjectPublicKey BIT STRING contents (the raw uncompressed EC point).
fn sha1_of(public_key_bits: &[u8]) -> Vec<u8> {
    Sha1::digest(public_key_bits).to_vec()
}

/// `x509.random_serial_number()` parity: 20 bytes of urandom interpreted as
/// a big-endian integer, shifted right one bit → uniform 159-bit positive.
fn random_serial() -> SerialNumber {
    let mut b = [0u8; 20];
    std::fs::File::open("/dev/urandom")
        .and_then(|mut f| f.read_exact(&mut b))
        .expect("read /dev/urandom");
    let mut carry = 0u8;
    for byte in b.iter_mut() {
        let next_carry = *byte & 1;
        *byte = (*byte >> 1) | (carry << 7);
        carry = next_carry;
    }
    SerialNumber::from(b.to_vec())
}

/// Write with parent mkdir; chmod only when `mode` is given (certs keep the
/// umask default like Python's `Path.write_bytes`).
/// The names a leaf certificate carries (DNS SANs, IP SANs as text).
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct CertNames {
    pub dns: Vec<String>,
    pub ips: Vec<String>,
}

/// Which of the wanted names the leaf lacks, DNS first then IPs, in the
/// order asked. Pure: the comparison behind both the upgrade re-issue and
/// the `cluster verify` row. Empty = the leaf covers them.
pub fn missing_names(have: &CertNames, want_dns: &[String], want_ips: &[String]) -> Vec<String> {
    let mut out: Vec<String> = Vec::new();
    for d in want_dns.iter().filter(|d| !d.is_empty()) {
        if !have.dns.contains(d) && !out.contains(d) {
            out.push(d.clone());
        }
    }
    for i in want_ips.iter().filter(|i| !i.is_empty()) {
        if !have.ips.contains(i) && !out.contains(i) {
            out.push(i.clone());
        }
    }
    out
}

/// Append `s` unless it is empty or already present (DNS names compare
/// case-insensitively, which is how a verifier compares them).
fn push_unique(v: &mut Vec<String>, s: &str) {
    let s = s.trim();
    if !s.is_empty() && !v.iter().any(|h| h.eq_ignore_ascii_case(s)) {
        v.push(s.to_string());
    }
}

/// The controller's role alias. Always a SAN on the controller's own node
/// cert, as it always is on the gateway cert (`issue_gateway_cert`) and on
/// the externally reachable service certs (`service_cert_sans`).
pub const CONTROLLER_ALIAS: &str = "noo-controller";

/// Whose node cert is being issued.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum NodeRole {
    /// Any enrolled node: its SANs are its name, its address and the
    /// caller's extras, exactly as before.
    Worker,
    /// The controller's own node. Its cert must also carry every name the
    /// controller is reached by.
    Controller(ControllerNames),
}

/// The names (and addresses) the controller is reached by. Built only by
/// [`ControllerNames::from_sources`], so the role alias is always in it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ControllerNames {
    dns: Vec<String>,
    ips: Vec<String>,
}

impl ControllerNames {
    /// From what the controller DECLARES about itself: URLs or bare hosts,
    /// in any order. `noo-controller` is always included. Loopback, the
    /// docker-internal `gateway` alias and empty values are skipped, and an
    /// IP literal lands in `ips`. Pure, so the derivation is testable.
    pub fn from_sources<S: AsRef<str>>(sources: &[S]) -> Self {
        let mut dns: Vec<String> = vec![CONTROLLER_ALIAS.to_string()];
        let mut ips: Vec<String> = Vec::new();
        for raw in sources {
            let Some(host) = host_of(raw.as_ref()) else { continue };
            if host.parse::<IpAddr>().is_ok() {
                push_unique(&mut ips, &host);
            } else {
                push_unique(&mut dns, &host.to_lowercase());
            }
        }
        Self { dns, ips }
    }

    /// Every source this controller declares its names in, read now:
    /// `NOO_CONTROLLER_DNS` (the floating service name), `NOO_SELF_AGENT_URL`
    /// and `NOO_GATEWAY_URL` (what the gateway dials, from the environment
    /// or the repo `.env`), `services.gateway_url` in noomesh.yaml, the
    /// tailnet device's MagicDNS name and address, and the URL onboarding
    /// recorded at `/etc/noo/controller-url`.
    pub fn declared() -> Self {
        Self::from_sources(&Self::declared_sources())
    }

    /// The raw values [`ControllerNames::declared`] derives from, for a
    /// caller that holds one more (onboarding's tailnet step).
    pub fn declared_sources() -> Vec<String> {
        crate::envfile::ensure_repo_env();
        let mut sources: Vec<String> = Vec::new();
        for k in ["NOO_CONTROLLER_DNS", "NOO_SELF_AGENT_URL", "NOO_GATEWAY_URL"] {
            if let Ok(v) = std::env::var(k) {
                sources.push(v);
            }
        }
        let root = crate::envfile::repo_root();
        for k in ["NOO_CONTROLLER_DNS", "NOO_SELF_AGENT_URL", "NOO_GATEWAY_URL"] {
            sources.push(crate::onboard::env::read_env_key(&root.join(".env"), k));
        }
        if let Some(url) = std::fs::read_to_string(root.join("noomesh.yaml"))
            .ok()
            .and_then(|t| serde_yaml::from_str::<serde_yaml::Value>(&t).ok())
            .and_then(|d| d.get("services")?.get("gateway_url")?.as_str().map(str::to_string))
        {
            sources.push(url);
        }
        if let Ok((dns, ip)) = crate::onboard::steps::tailscale_identity() {
            sources.push(dns);
            sources.push(ip);
        }
        if let Some(u) = crate::envfile::controller_url_from_file(Path::new(crate::envfile::ENROLLED_CONTROLLER_URL)) {
            sources.push(u);
        }
        sources
    }
}

/// The host part of a URL or a bare host, or `None` for anything that
/// cannot name this controller from outside its own container.
fn host_of(raw: &str) -> Option<String> {
    let s = raw.trim();
    let s = s.split_once("://").map(|(_, r)| r).unwrap_or(s);
    let s = s.split(['/', '?', '#']).next().unwrap_or(s);
    let s = s.rsplit_once('@').map(|(_, h)| h).unwrap_or(s);
    let host = if let Some(rest) = s.strip_prefix('[') {
        rest.split(']').next().unwrap_or("")
    } else if s.matches(':').count() == 1 {
        s.split(':').next().unwrap_or("")
    } else {
        s
    };
    let host = host.trim().trim_end_matches('.');
    if host.is_empty()
        || host.eq_ignore_ascii_case("localhost")
        || host.eq_ignore_ascii_case("gateway")
        || host.starts_with("127.")
        || host == "::1"
        || host == "0.0.0.0"
    {
        return None;
    }
    Some(host.to_string())
}

impl NodeRole {
    /// The role of `node` as seen from THIS box. The controller's own node
    /// is the one [`crate::role::is_self_node`] names, on a box that holds
    /// a controller install. Anything else is a worker.
    pub fn of(node: &str) -> Self {
        if crate::role::is_self_node(node) && crate::role::detect().controller.is_some() {
            NodeRole::Controller(ControllerNames::declared())
        } else {
            NodeRole::Worker
        }
    }

    /// The tailnet IPv4 to fold into `node`'s cert. For the controller it
    /// is this device's own address. Looking the controller's NODE name up
    /// on the tailnet (`tailscale ip -4 <name>`) answers with whichever
    /// device holds that name, and on a controller whose device is named
    /// `noo-controller` that is some other machine: a second Pop!_OS box
    /// still called `host8` put its address into the controller's cert.
    pub fn tailnet_ip4(&self, node: &str) -> Option<String> {
        match self {
            NodeRole::Controller(names) => names.ips.iter().find(|i| i.starts_with("100.")).cloned(),
            NodeRole::Worker => ClusterCa::tailscale_ip4(node),
        }
    }

    /// The DNS names a cert for this role must carry beyond the node's own.
    pub fn required_dns(&self) -> &[String] {
        match self {
            NodeRole::Controller(names) => &names.dns,
            NodeRole::Worker => &[],
        }
    }
}

fn write_file(path: &Path, data: &[u8], mode: Option<u32>) -> Result<(), String> {
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent).map_err(|e| format!("mkdir {}: {e}", parent.display()))?;
    }
    std::fs::write(path, data).map_err(|e| format!("write {}: {e}", path.display()))?;
    if let Some(m) = mode {
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(m))
            .map_err(|e| format!("chmod {}: {e}", path.display()))?;
    }
    Ok(())
}

#[cfg(test)]
mod san_drift_tests {
    use super::*;

    /// The rule provisioning depends on: a cert whose SANs no longer name
    /// the node's current address must read as NOT covering, so the caller
    /// re-issues instead of keeping it. Before this was wired into
    /// `provision`, a node that had ever been issued a cert kept it through
    /// every restage — which is how a node ended up presenting a cert for
    /// an address it no longer had, failing every inbound handshake by name
    /// while reporting itself healthy (2026-09-04).
    #[test]
    fn a_cert_that_misses_the_current_address_does_not_cover() {
        let tmp = std::env::temp_dir().join(format!("noo-san-drift-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&tmp);
        std::fs::create_dir_all(&tmp).unwrap();
        let ca = ClusterCa::new(tmp.clone());
        ca.generate_ca("noo-test-ca", 3650).expect("ca");
        let (crt, _key) = ca
            .issue_node_cert("node-3", "100.64.0.13", 365, &["node-agent".into()], &[], &NodeRole::Worker)
            .expect("issue");

        let dns = vec!["node-3".to_string(), "localhost".into(), "node-agent".into()];
        // The address it was issued for: covered.
        assert!(ClusterCa::cert_covers_sans(
            &crt,
            &dns,
            &["100.64.0.13".to_string(), "127.0.0.1".into()]
        ));
        // The address it moved to: NOT covered — this is the re-issue trigger.
        assert!(!ClusterCa::cert_covers_sans(
            &crt,
            &dns,
            &["100.64.0.18".to_string(), "127.0.0.1".into()]
        ));
        // An unreadable or missing cert never counts as covering.
        assert!(!ClusterCa::cert_covers_sans(
            &tmp.join("nope.crt"),
            &dns,
            &["127.0.0.1".to_string()]
        ));
        let _ = std::fs::remove_dir_all(&tmp);
    }
}

#[cfg(test)]
mod grafana_sso_tests {
    use super::*;

    fn scratch() -> PathBuf {
        let d = std::env::temp_dir().join(format!("noo-pki-sso-{}", std::process::id()))
            .join(format!("{:x}", std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_nanos()));
        std::fs::create_dir_all(&d).unwrap();
        d
    }

    /// The pair is P-256 (Grafana verifies ES256 only), the private half
    /// is not world-readable, the public half is; `ensure` is idempotent.
    #[test]
    fn the_sso_pair_is_p256_with_the_documented_modes() {
        let ca = ClusterCa::new(scratch());
        assert_eq!(ca.ensure_grafana_sso_key(), Ok(true));
        let before = std::fs::read(ca.grafana_sso_key_path()).unwrap();
        assert_eq!(ca.ensure_grafana_sso_key(), Ok(false), "a second ensure must not re-mint");
        assert_eq!(std::fs::read(ca.grafana_sso_key_path()).unwrap(), before);
        assert_eq!(std::fs::metadata(ca.grafana_sso_key_path()).unwrap().permissions().mode() & 0o777, 0o640);
        assert_eq!(std::fs::metadata(ca.grafana_sso_pub_path()).unwrap().permissions().mode() & 0o777, 0o644);
        let kp = KeyPair::from_pem(std::str::from_utf8(&before).unwrap()).unwrap();
        assert_eq!(kp.public_key_raw().len(), 65, "a P-256 uncompressed point; the gateway refuses anything else");
        assert!(std::str::from_utf8(&std::fs::read(ca.grafana_sso_pub_path()).unwrap()).unwrap().contains("BEGIN PUBLIC KEY"));
    }

    /// `fix-modes` never loosens it: the SSO key fails closed (#524). A
    /// pass over a tree holding an unhanded 0640 `sso/grafana.key` leaves
    /// it 0640 and names the sudo line, where a service leaf in the same
    /// state would be opened to 0644 so its service keeps starting.
    #[test]
    fn fix_modes_never_opens_the_sso_key() {
        let ca = ClusterCa::new(scratch());
        ca.mint_grafana_sso_key().unwrap();
        let key = ca.grafana_sso_key_path();
        let (fixes, _) = ca.fix_key_modes();
        let f = fixes.iter().find(|f| f.rel == "sso/grafana.key").expect("audited");
        let mode = std::fs::metadata(&key).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode & 0o004, 0, "never world-readable: {mode:o}");
        if ca.grafana_sso_key_readable_by_gateway() != Some(true) {
            assert!(f.needs.as_deref().unwrap_or_default().contains("sudo chgrp 65532"), "{f:?}");
        }
    }

    /// `rotate-all` never sees it: the SSO pair is not a certificate, so
    /// the leaf walk cannot rotate it — a rotation would log every open
    /// Grafana tab out. Planted: writing a `grafana.crt` beside it shows
    /// up in `list_certs`, which is exactly what `sso/` must never hold.
    #[test]
    fn rotate_all_leaves_the_sso_pair_alone() {
        let ca = ClusterCa::new(scratch());
        ca.mint_grafana_sso_key().unwrap();
        let before = std::fs::read(ca.grafana_sso_key_path()).unwrap();
        assert!(ca.list_certs().is_empty(), "the SSO pair is not a certificate");
        let rotated = ca.rotate_all_expiring(36500, 90, |_| NodeRole::Worker);
        assert!(rotated.is_empty(), "nothing to rotate under sso/: {:?}", rotated.iter().map(|r| &r.name).collect::<Vec<_>>());
        assert_eq!(std::fs::read(ca.grafana_sso_key_path()).unwrap(), before);
    }

    #[test]
    fn readability_by_the_gateway_is_judged_from_mode_and_group() {
        let ca = ClusterCa::new(scratch());
        assert_eq!(ca.grafana_sso_key_readable_by_gateway(), None, "absent");
        ca.mint_grafana_sso_key().unwrap();
        // 0640 owned by the test user's group, which is not 65532 here.
        use std::os::unix::fs::MetadataExt as _;
        let gid = std::fs::metadata(ca.grafana_sso_key_path()).unwrap().gid();
        let expect = gid == ClusterCa::GATEWAY_CONTAINER_GID;
        assert_eq!(ca.grafana_sso_key_readable_by_gateway(), Some(expect));
        std::fs::set_permissions(ca.grafana_sso_key_path(), std::fs::Permissions::from_mode(0o644)).unwrap();
        assert_eq!(ca.grafana_sso_key_readable_by_gateway(), Some(true), "world-readable is readable");
        std::fs::set_permissions(ca.grafana_sso_key_path(), std::fs::Permissions::from_mode(0o600)).unwrap();
        assert_eq!(ca.grafana_sso_key_readable_by_gateway(), Some(false), "0600 as the host user: the gateway (uid 65532) cannot read it");
    }
}

#[cfg(test)]
mod key_mode_tests {
    use super::*;

    fn scratch() -> PathBuf {
        let d = std::env::temp_dir()
            .join(format!("noo-pki-modes-{}", std::process::id()))
            .join(format!("{:x}", std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_nanos()));
        std::fs::create_dir_all(&d).unwrap();
        d
    }

    fn mode_of(p: &Path) -> u32 {
        std::fs::metadata(p).unwrap().permissions().mode() & 0o777
    }

    /// The reader table names every service onboard issues a leaf for,
    /// and nothing else: a service without a row would be issued 0644 and
    /// reported by the scan forever; a row without a service is a claim
    /// about a container that does not exist.
    #[test]
    fn service_key_reader_table_covers_every_onboarded_service() {
        let table: Vec<&str> = SERVICE_KEY_READERS.iter().map(|(n, _)| *n).collect();
        for svc in crate::onboard::steps::SVC_LIST {
            assert!(table.contains(svc), "{svc} is in SVC_LIST but SERVICE_KEY_READERS has no row: its key would stay 0644");
        }
        for name in &table {
            assert!(crate::onboard::steps::SVC_LIST.contains(name), "{name} has a reader row but onboard never issues it");
        }
        assert!(!table.iter().any(|n| SERVICE_KEY_READERS.iter().filter(|(m, _)| m == n).count() > 1), "duplicate row");
    }

    /// Noo-trellion and noo-trellion-intel present leaves of
    /// their own, issued the way onboard and `upgrade --stack` issue every
    /// SVC_LIST name (same SAN derivation), never the controller's gateway
    /// leaf. The EKU carries clientAuth, which is what the gateway's client
    /// verifier and every mTLS door they dial (Postgres, Redis, NATS) check.
    #[test]
    fn the_trellion_addons_are_issued_their_own_leaves() {
        use x509_parser::extensions::GeneralName;
        let ca = ClusterCa::new(scratch());
        ca.generate_ca("t", 3650).unwrap();
        for svc in ["trellion", "trellion-intel"] {
            assert!(crate::onboard::steps::SVC_LIST.contains(&svc), "{svc}: onboard and upgrade --stack would never issue it");
            let (extra, ips) = crate::onboard::steps::service_cert_sans(svc, "Pop-Host", "10.0.0.1", "pop.ts.net");
            let (crt, key) = ca.issue_service_cert(svc, &extra, &ips, 90).unwrap();
            assert_eq!(crt, ca.dir.join("services").join(svc).join("service.crt"));
            let data = std::fs::read(&crt).unwrap();
            let (_, pem) = x509_parser::pem::parse_x509_pem(&data).unwrap();
            let cert = pem.parse_x509().unwrap();
            let cn = cert.subject().iter_common_name().next().and_then(|a| a.as_str().ok());
            let org = cert.subject().iter_organization().next().and_then(|a| a.as_str().ok());
            assert_eq!(cn, Some(svc));
            assert_eq!(org, Some("Mesh Cluster Service"),
                "a SERVICE leaf: the gateway and node agents never read it as a node or the controller");
            let eku = cert.extended_key_usage().unwrap().expect("EKU present").value;
            assert!(eku.client_auth, "{svc} dials mTLS doors as a client");
            let dns: Vec<String> = cert.subject_alternative_name().unwrap().unwrap().value.general_names.iter()
                .filter_map(|g| if let GeneralName::DNSName(d) = g { Some(d.to_string()) } else { None })
                .collect();
            assert!(dns.contains(&svc.to_string()) && dns.contains(&format!("noo-{svc}")), "{svc}: {dns:?}");
            for controller_name in ["gateway", "noo-controller", "noo-gateway", "Pop-Host", "pop.ts.net"] {
                assert!(!dns.contains(&controller_name.to_string()), "{svc} claims the controller's name {controller_name}: {dns:?}");
            }
            // Read by the add-on's nonroot process (65532), like the gateway's
            // key; the mount, not the mode, keeps the two apart.
            assert_eq!(ca.key_reader(&key), KeyReader::ContainerUid(65532));
            assert_eq!(readable_by_uid(&key, 65532), Some(true), "{svc} can start");
        }
    }

    /// A Postgres role leaf is named for the ROLE (i132): `clientcert=verify-full`
    /// compares the CN with the role being asked for, so each leaf carries
    /// CN=<role> however it was issued, keeps it through a rotation, and its
    /// key is handed to the container that reads it.
    #[test]
    fn a_postgres_role_leaf_carries_the_role_as_its_cn_and_keeps_it_on_rotation() {
        let ca = ClusterCa::new(scratch());
        ca.generate_ca("t", 3650).unwrap();
        for l in PG_LEAVES {
            let (crt, key) = ca.issue_pg_leaf(l, 90).unwrap();
            assert_eq!(crt, ca.dir.join(l.cert_rel()));
            assert_eq!(key, ca.dir.join(l.key_rel()));
            assert_eq!(ca.pg_leaf_cn(l).unwrap().as_deref(), Some(l.role), "CN is the role: {}", l.cert_rel());
            assert_eq!(ca.key_reader(&key), KeyReader::ContainerUid(PG_LEAF_UID), "{}", l.key_rel());
            assert_eq!(readable_by_uid(&key, PG_LEAF_UID), Some(true), "the {} consumers can start", l.role);
            // Rotation re-issues in place from the old certificate's subject.
            ca.reissue_in_place(&crt, 90, &NodeRole::Worker).unwrap();
            assert_eq!(ca.pg_leaf_cn(l).unwrap().as_deref(), Some(l.role), "rotation kept the CN");
            // A client leaf: it must never be mistaken for the door pins'
            // callers (stunnel checkHost gateway/worker/trellion/...).
            let data = std::fs::read(&crt).unwrap();
            let (_, pem) = x509_parser::pem::parse_x509_pem(&data).unwrap();
            let cert = pem.parse_x509().unwrap();
            let dns: Vec<String> = cert.subject_alternative_name().unwrap().unwrap().value.general_names.iter()
                .filter_map(|g| if let x509_parser::extensions::GeneralName::DNSName(d) = g { Some(d.to_string()) } else { None })
                .collect();
            for pinned in ["gateway", "worker", "trellion", "trellion-intel", "evolve", "localhost"] {
                assert!(!dns.contains(&pinned.to_string()), "{} carries the pinned name {pinned}: {dns:?}", l.cert_rel());
            }
            assert!(cert.extended_key_usage().unwrap().expect("EKU").value.client_auth);
        }
        assert_eq!(pg_leaf_at("gateway/pg/noo_app.key").map(|l| l.owner), Some("gateway"));
        assert_eq!(pg_leaf_at("services/worker/pg/noo_app.crt").map(|l| l.owner), Some("worker"));
        assert!(pg_leaf_at("services/worker/pg/noo.key").is_none(), "the worker has no `noo` leaf");
        assert!(pg_leaf_at("services/worker/service.key").is_none());
        assert_eq!(pg_leaf_roles(), vec!["noo", "noo_app", "noo_trellion", "noo_trellion_ddl"]);
    }

    /// The upgrade path: an install that has only the shared leaves gets
    /// every role leaf from one call, a second call changes nothing, and a
    /// leaf with the wrong CN (or no key) is replaced rather than trusted.
    #[test]
    fn ensure_pg_leaves_mints_the_missing_ones_once_and_repairs_a_wrong_cn() {
        let ca = ClusterCa::new(scratch());
        ca.generate_ca("t", 3650).unwrap();
        ca.issue_service_cert("worker", &[], &[], 90).unwrap();
        for l in PG_LEAVES {
            assert_eq!(ca.pg_leaf_cn(l), Ok(None), "an old install has none");
            assert!(ca.pg_leaf_state(l).is_err());
        }
        let first = ca.ensure_pg_leaves(90);
        assert_eq!(first.len(), PG_LEAVES.len());
        assert!(first.iter().all(|(_, r)| *r == Ok(true)), "{:?}", first.iter().map(|(l, r)| (l.cert_rel(), r.clone())).collect::<Vec<_>>());
        let worker = PG_LEAVES.iter().find(|l| l.owner == "worker").unwrap();
        let before = std::fs::read(ca.dir.join(worker.cert_rel())).unwrap();
        let second = ca.ensure_pg_leaves(90);
        assert!(second.iter().all(|(_, r)| *r == Ok(false)), "idempotent");
        assert_eq!(std::fs::read(ca.dir.join(worker.cert_rel())).unwrap(), before, "a right leaf is not re-issued");
        // The worker's own service leaf is untouched and is not a role identity.
        assert_eq!(ca.pg_leaf_cn(worker).unwrap().as_deref(), Some("noo_app"));
        // A leaf whose CN is wrong is repaired.
        let gw = PG_LEAVES.iter().find(|l| l.owner == "gateway" && l.role == "noo").unwrap();
        ca.issue_leaf("gateway-host", "Mesh Cluster Service", &ca.dir.join(gw.cert_rel()), &ca.dir.join(gw.key_rel()),
            &["x".to_string()], &[], 90).unwrap();
        assert!(ca.pg_leaf_state(gw).unwrap_err().contains("not noo"));
        let third = ca.ensure_pg_leaves(90);
        let fixed = third.iter().find(|(l, _)| l.owner == "gateway" && l.role == "noo").unwrap();
        assert_eq!(fixed.1, Ok(true), "wrong CN replaced");
        assert_eq!(ca.pg_leaf_cn(gw).unwrap().as_deref(), Some("noo"));
        // A leaf with no key beside it is not usable either.
        std::fs::remove_file(ca.dir.join(gw.key_rel())).unwrap();
        assert!(ca.pg_leaf_state(gw).unwrap_err().contains("does not exist"));
        assert!(ca.ensure_pg_leaves(90).iter().any(|(l, r)| l.role == "noo" && *r == Ok(true)));
    }

    /// The hba reader counts a role only when the line keeps the password,
    /// and the gap list says WHICH half is missing for which role.
    #[test]
    fn pg_identity_gaps_name_the_role_and_the_missing_half() {
        let ca = ClusterCa::new(scratch());
        ca.generate_ca("t", 3650).unwrap();
        let hba = "hostssl all all samehost scram-sha-256 clientcert=verify-ca\n\
                   hostssl all noo all scram-sha-256 clientcert=verify-full\n\
                   hostssl all noo_app all scram-sha-256 clientcert=verify-full\n\
                   hostssl all noo_trellion all scram-sha-256 clientcert=verify-full\n\
                   hostssl all noo_trellion_ddl all scram-sha-256 clientcert=verify-full\n\
                   hostssl all all all scram-sha-256 clientcert=verify-ca\n";
        assert_eq!(pg_hba_verify_full_roles(hba), vec!["noo", "noo_app", "noo_trellion", "noo_trellion_ddl"]);
        // An upgraded install, leaves not minted yet: every leaf is a gap.
        let before = pg_identity_gaps(&ca, Some(hba));
        assert_eq!(before.len(), PG_LEAVES.len(), "{before:?}");
        assert!(before.iter().all(|g| g.contains("does not exist")), "{before:?}");
        ca.ensure_pg_leaves(90);
        assert_eq!(pg_identity_gaps(&ca, Some(hba)), Vec::<String>::new(), "leaves + a strict file = no gap");
        // The OLD file: leaves are right but the file still takes any leaf.
        let old = "hostssl all all all scram-sha-256 clientcert=verify-ca\n";
        let gaps = pg_identity_gaps(&ca, Some(old));
        assert_eq!(gaps.len(), 4, "{gaps:?}");
        assert!(gaps.iter().any(|g| g.starts_with("noo_app: pg_hba.conf has no") && g.contains("clientcert=verify-full")), "{gaps:?}");
        // verify-full that drops the password does not count.
        let no_pw = hba.replace("noo_app all scram-sha-256", "noo_app all cert");
        assert!(pg_identity_gaps(&ca, Some(&no_pw)).iter().any(|g| g.starts_with("noo_app:")));
        // An unreadable file judges the leaves only.
        assert_eq!(pg_identity_gaps(&ca, None), Vec::<String>::new());
        std::fs::remove_file(ca.dir.join("services/worker/pg/noo_app.key")).unwrap();
        assert_eq!(pg_identity_gaps(&ca, None).len(), 1);
    }

    /// Each role leaf sits in a directory its owner already mounts (the
    /// compose guard test_postgres_role_identity.py pins the mounts), and
    /// two owners never share a file.
    #[test]
    fn role_leaves_live_in_their_owners_directory_and_never_collide() {
        let mut seen = std::collections::HashSet::new();
        for l in PG_LEAVES {
            assert!(seen.insert(l.key_rel()), "two leaves share {}", l.key_rel());
            assert!(l.dir_rel() == "gateway/pg" || l.dir_rel().starts_with("services/"), "{}", l.dir_rel());
            let owner_in_svc_list = l.owner == "gateway" || crate::onboard::steps::SVC_LIST.contains(&l.owner);
            assert!(owner_in_svc_list, "{}: the owner's directory is issued by onboard, so it exists", l.owner);
            assert!(!l.consumers.is_empty());
        }
    }

    /// Noo-worker (and worker-extra, through the
    /// compose anchor) presents a leaf of its own, `services/worker`, never
    /// the controller's gateway leaf. It must be a SERVICE leaf: a node
    /// agent's ControllerOnly routes read `O=Mesh Cluster Gateway` as "this
    /// caller may command me", and the worker commands no node.
    #[test]
    fn the_worker_is_issued_its_own_leaf() {
        let ca = ClusterCa::new(scratch());
        ca.generate_ca("t", 3650).unwrap();
        assert!(crate::onboard::steps::SVC_LIST.contains(&"worker"), "onboard and upgrade --stack would never issue it");
        let (extra, ips) = crate::onboard::steps::service_cert_sans("worker", "Pop-Host", "10.0.0.1", "pop.ts.net");
        let (crt, key) = ca.issue_service_cert("worker", &extra, &ips, 90).unwrap();
        assert_eq!(crt, ca.dir.join("services").join("worker").join("service.crt"));
        let data = std::fs::read(&crt).unwrap();
        let (_, pem) = x509_parser::pem::parse_x509_pem(&data).unwrap();
        let cert = pem.parse_x509().unwrap();
        let cn = cert.subject().iter_common_name().next().and_then(|a| a.as_str().ok());
        let orgs: Vec<&str> = cert.subject().iter_organization().filter_map(|a| a.as_str().ok()).collect();
        assert_eq!(cn, Some("worker"));
        assert_eq!(orgs, vec!["Mesh Cluster Service"], "never the controller's org");
        assert!(cert.extended_key_usage().unwrap().expect("EKU").value.client_auth, "the worker dials mTLS doors as a client");
        let dns: Vec<String> = cert.subject_alternative_name().unwrap().unwrap().value.general_names.iter()
            .filter_map(|g| if let x509_parser::extensions::GeneralName::DNSName(d) = g { Some(d.to_string()) } else { None })
            .collect();
        assert!(dns.contains(&"worker".to_string()) && dns.contains(&"noo-worker".to_string()), "{dns:?}");
        for controller_name in ["gateway", "noo-controller", "noo-gateway", "Pop-Host", "pop.ts.net"] {
            assert!(!dns.contains(&controller_name.to_string()), "the worker claims the controller's name {controller_name}: {dns:?}");
        }
        assert_eq!(ca.key_reader(&key), KeyReader::ContainerUid(65532));
        assert_eq!(readable_by_uid(&key, 65532), Some(true), "noo-worker (nonroot) can start");
    }

    /// The sandbox door (mTLS doors phase 1): its own SERVICE leaf, onboarded
    /// and upgrade-issued like every SVC_LIST name, serving `sandbox` (the
    /// alias the gateway, the worker and trellion dial, which the
    /// sandbox-extra replicas carry too) and `localhost` (the container's own
    /// healthcheck). The key is handed to the image's nonroot uid, which is
    /// what uvicorn reads it as.
    #[test]
    fn the_sandbox_is_issued_its_own_server_leaf() {
        let ca = ClusterCa::new(scratch());
        ca.generate_ca("t", 3650).unwrap();
        assert!(crate::onboard::steps::SVC_LIST.contains(&"sandbox"), "onboard and upgrade --stack would never issue it");
        let (extra, ips) = crate::onboard::steps::service_cert_sans("sandbox", "Pop-Host", "10.0.0.1", "pop.ts.net");
        assert!(ips.is_empty(), "the sandbox is compose-network only: no LAN IP in its leaf: {ips:?}");
        let (crt, key) = ca.issue_service_cert("sandbox", &extra, &ips, 90).unwrap();
        let data = std::fs::read(&crt).unwrap();
        let (_, pem) = x509_parser::pem::parse_x509_pem(&data).unwrap();
        let cert = pem.parse_x509().unwrap();
        let orgs: Vec<&str> = cert.subject().iter_organization().filter_map(|a| a.as_str().ok()).collect();
        assert_eq!(orgs, vec!["Mesh Cluster Service"], "a service leaf names no node and no controller");
        assert!(cert.extended_key_usage().unwrap().expect("EKU").value.server_auth, "uvicorn serves it");
        let dns: Vec<String> = cert.subject_alternative_name().unwrap().unwrap().value.general_names.iter()
            .filter_map(|g| if let x509_parser::extensions::GeneralName::DNSName(d) = g { Some(d.to_string()) } else { None })
            .collect();
        for name in ["sandbox", "localhost", "noo-sandbox", "sandbox-extra"] {
            assert!(dns.contains(&name.to_string()), "{name} missing: {dns:?}");
        }
        for controller_name in ["gateway", "noo-controller", "Pop-Host", "pop.ts.net"] {
            assert!(!dns.contains(&controller_name.to_string()), "the sandbox claims {controller_name}: {dns:?}");
        }
        assert_eq!(ca.key_reader(&key), KeyReader::ContainerUid(65532));
        assert_eq!(readable_by_uid(&key, 65532), Some(true), "noo-sandbox (nonroot) can start");
    }

    /// The voice doors (mTLS doors phase 2): each its own SERVICE leaf,
    /// onboarded and upgrade-issued like every SVC_LIST name, serving the
    /// container name the gateway dials (`noo-whisper` / `noo-piper`), the
    /// compose service name, and `localhost` (the healthcheck). Neither
    /// claims the other's names nor any controller name; the keys go to the
    /// images' reader, `nonroot` (65532, i105), 0640.
    #[test]
    fn the_voice_doors_are_issued_their_own_server_leaves() {
        let ca = ClusterCa::new(scratch());
        ca.generate_ca("t", 3650).unwrap();
        for (svc, other) in [("whisper", "piper"), ("piper", "whisper")] {
            assert!(crate::onboard::steps::SVC_LIST.contains(&svc), "onboard and upgrade --stack would never issue {svc}");
            let (extra, ips) = crate::onboard::steps::service_cert_sans(svc, "Pop-Host", "10.0.0.1", "pop.ts.net");
            assert!(ips.is_empty(), "{svc} is compose-network only: no LAN IP in its leaf: {ips:?}");
            let (crt, key) = ca.issue_service_cert(svc, &extra, &ips, 90).unwrap();
            let data = std::fs::read(&crt).unwrap();
            let (_, pem) = x509_parser::pem::parse_x509_pem(&data).unwrap();
            let cert = pem.parse_x509().unwrap();
            let orgs: Vec<&str> = cert.subject().iter_organization().filter_map(|a| a.as_str().ok()).collect();
            assert_eq!(orgs, vec!["Mesh Cluster Service"], "a service leaf names no node and no controller");
            assert!(cert.extended_key_usage().unwrap().expect("EKU").value.server_auth, "uvicorn serves it");
            let dns: Vec<String> = cert.subject_alternative_name().unwrap().unwrap().value.general_names.iter()
                .filter_map(|g| if let x509_parser::extensions::GeneralName::DNSName(d) = g { Some(d.to_string()) } else { None })
                .collect();
            for name in [svc.to_string(), format!("noo-{svc}"), "localhost".into()] {
                assert!(dns.contains(&name), "{name} missing: {dns:?}");
            }
            for wrong in [other.to_string(), format!("noo-{other}"), "gateway".into(), "noo-controller".into(), "Pop-Host".into(), "pop.ts.net".into()] {
                assert!(!dns.contains(&wrong), "{svc} claims {wrong}: {dns:?}");
            }
            assert_eq!(ca.key_reader(&key), KeyReader::ContainerUid(65532), "{svc}: uvicorn runs as nonroot (i105)");
            assert_eq!(KeyReader::ContainerUid(65532).mode(), 0o640);
            assert_eq!(readable_by_uid(&key, 65532), Some(true), "noo-{svc} (nonroot) can read its own key");
        }
    }

    /// The mode table, file by file: who reads it decides the bits.
    #[test]
    fn the_reader_of_each_key_follows_its_path() {
        let ca = ClusterCa::new(PathBuf::from("/p"));
        let r = |rel: &str| ca.key_reader(&PathBuf::from("/p").join(rel));
        assert_eq!(r("ca.key"), KeyReader::Cli);
        assert_eq!(r("signing.key"), KeyReader::Cli);
        assert_eq!(r("gateway/gateway.key"), KeyReader::ContainerUid(65532));
        assert_eq!(r("sso/grafana.key"), KeyReader::ContainerUid(65532));
        assert_eq!(r("nodes/host3/node.key"), KeyReader::Cli, "the CLI builds node bundles; the gateway only serves them");
        assert_eq!(r("services/redis/service.key"), KeyReader::ContainerUid(65532), "compose user: 65532 (i64)");
        assert_eq!(r("services/grafana/service.key"), KeyReader::ContainerUid(65532), "compose user: 65532 (i64)");
        assert_eq!(r("services/nats/service.key"), KeyReader::ContainerRoot);
        assert_eq!(r("services/loki/service.key"), KeyReader::ContainerUid(65532));
        assert_eq!(r("services/sandbox/service.key"), KeyReader::ContainerUid(65532), "Dockerfile.sandbox USER nonroot");
        assert_eq!(r("services/whisper/service.key"), KeyReader::ContainerUid(65532), "Dockerfile.whisper USER nonroot (i105)");
        assert_eq!(r("services/piper/service.key"), KeyReader::ContainerUid(65532), "Dockerfile.piper USER nonroot (i105)");
        assert_eq!(r("services/postgres/service.key"), KeyReader::ContainerUid(70));
        // The stunnel doors and the NVIDIA exporter run as 65532 (i132).
        for door in ["ollama", "ollama-embed", "ollama-embed-cpu", "tei", "reranker", "llamacpp", "nvidia-exporter"] {
            assert_eq!(r(&format!("services/{door}/service.key")), KeyReader::ContainerUid(65532), "{door}: Dockerfile USER 65532 + compose user:");
        }
        // Postgres role leaves: read by the owner's nonroot process; an
        // unlisted file under a `pg/` directory is not one.
        assert_eq!(r("gateway/pg/noo_app.key"), KeyReader::ContainerUid(65532));
        assert_eq!(r("services/worker/pg/noo_app.key"), KeyReader::ContainerUid(65532));
        assert_eq!(r("services/trellion-intel/pg/noo_trellion_ddl.key"), KeyReader::ContainerUid(65532));
        assert_eq!(r("services/worker/pg/noo.key"), KeyReader::Unknown, "the worker has no `noo` leaf");
        assert_eq!(r("services/not-a-thing/service.key"), KeyReader::Unknown);
        assert_eq!(r("stray.key"), KeyReader::Unknown);
        // A relative path resolves the same way.
        assert_eq!(ca.key_reader(Path::new("nodes/x/node.key")), KeyReader::Cli);
        assert_eq!(KeyReader::Cli.mode(), 0o600);
        assert_eq!(KeyReader::ContainerRoot.mode(), 0o600);
        assert_eq!(KeyReader::ContainerUid(70).mode(), 0o640);
        assert_eq!(KeyReader::Unknown.mode(), 0o644);
    }

    /// Issuance writes the reader's mode: a node key and a root-read
    /// service key are owner-only; an unknown service keeps 0644. (A
    /// uid-read key's final bits depend on whether this process may hand
    /// it over — `fix_key_modes_tightens_a_planted_0644_key` covers that.)
    #[test]
    fn issuance_writes_owner_only_keys_for_cli_and_root_readers() {
        let ca = ClusterCa::new(scratch());
        ca.generate_ca("t", 3650).unwrap();
        assert_eq!(mode_of(&ca.ca_key_path()), 0o600);
        let (_, node_key) = ca.issue_node_cert("host9", "10.0.0.2", 90, &[], &[], &crate::pki::NodeRole::Worker).unwrap();
        assert_eq!(mode_of(&node_key), 0o600, "nodes/*/node.key: the CLI alone");
        let (_, nats_key) = ca.issue_service_cert("nats", &[], &[], 90).unwrap();
        assert_eq!(mode_of(&nats_key), 0o600, "nats runs as root in its container");
        let (_, odd_key) = ca.issue_service_cert("not-a-thing", &[], &[], 90).unwrap();
        assert_eq!(mode_of(&odd_key), 0o644, "no reader row: left readable, reported by the scan");
        // The gateway key (uid 65532): handed over and not world-readable,
        // or — when this process cannot hand it over — left readable with
        // the sudo line pending. In both states the gateway can read it.
        let (_, gw_key) = ca.issue_gateway_cert("h", "10.0.0.1", 90, &[], &[]).unwrap();
        assert_eq!(readable_by_uid(&gw_key, 65532), Some(true), "the gateway can always start");
        if mode_of(&gw_key) & 0o004 != 0 {
            assert!(ca.key_grant_command(&gw_key).is_some(), "world-readable only while a hand-over is pending");
        } else {
            assert!(ca.key_grant_command(&gw_key).is_none());
        }
        // The certs beside them stay readable (the CLI's own reads; the
        // gateway reads their copies under public/).
        assert_eq!(mode_of(&node_key.with_extension("crt")) & 0o044, 0o044);
    }

    /// Can this process hand a key to another uid at all — root (chgrp to
    /// any gid) or a working `setfacl`? When it cannot, a uid-read key is
    /// left readable with the sudo line pending (never a service that
    /// cannot start); that is the one state the tests below tolerate.
    fn can_hand_over() -> bool {
        let root = unsafe { libc::geteuid() } == 0;
        root || std::process::Command::new("setfacl").arg("--version").output().map(|o| o.status.success()).unwrap_or(false)
    }

    /// Correct by construction: every private key
    /// onboard and provision issue (every SVC_LIST leaf, the gateway, a
    /// node, a node's door leaves, the CA, the signing and SSO keys) is
    /// 0600 when only the CLI or a root-in-container process reads it, and
    /// 0640 handed to exactly its reader when a container uid does. The
    /// files are PRE-PLANTED 0644/0664 — what a pre-2026-09-28 install or a
    /// umask-002 shell leaves — so a writer that merely keeps the existing
    /// mode fails here. Certificates come out 0644, never group-writable.
    #[test]
    fn every_issued_key_is_confined_to_its_reader() {
        let ca = ClusterCa::new(scratch());
        ca.generate_ca("t", 3650).unwrap();
        let plant = |rel: &str, mode: u32| {
            let p = ca.dir.join(rel);
            std::fs::create_dir_all(p.parent().unwrap()).unwrap();
            std::fs::write(&p, b"stale").unwrap();
            std::fs::set_permissions(&p, std::fs::Permissions::from_mode(mode)).unwrap();
        };
        for svc in crate::onboard::steps::SVC_LIST {
            plant(&format!("services/{svc}/service.key"), 0o644);
            plant(&format!("services/{svc}/service.crt"), 0o664);
            ca.issue_service_cert(svc, &[], &[], 90).unwrap();
        }
        plant("gateway/gateway.key", 0o644);
        plant("nodes/host3/node.key", 0o644);
        plant("nodes/host3/node.crt", 0o666);
        plant("nodes/host3/services/vllm/service.key", 0o644);
        ca.issue_gateway_cert("h", "10.0.0.1", 90, &[], &[]).unwrap();
        ca.issue_node_cert("host3", "10.0.0.3", 90, &[], &[], &crate::pki::NodeRole::Worker).unwrap();
        ca.issue_node_service_cert("host3", "vllm", &[], 90).unwrap();
        ca.mint_signing_key().unwrap();

        let keys = ca.list_keys();
        assert!(keys.len() >= crate::onboard::steps::SVC_LIST.len() + 4, "the issue loop found too few keys: {keys:?}");
        for key in &keys {
            let rel = key.strip_prefix(&ca.dir).unwrap().display().to_string();
            assert_ne!(std::fs::read(key).unwrap(), b"stale", "{rel} was not re-written");
            match ca.key_reader(key) {
                KeyReader::Cli | KeyReader::ContainerRoot => assert_eq!(mode_of(key), 0o600, "{rel}"),
                KeyReader::ContainerUid(uid) => {
                    assert_eq!(readable_by_uid(key, uid), Some(true), "{rel}: its reader uid {uid} must be able to start");
                    if can_hand_over() {
                        assert_eq!(mode_of(key), 0o640, "{rel}");
                        assert!(ca.key_grant_command(key).is_none(), "{rel} readable beyond uid {uid}");
                    } else {
                        assert!(ca.key_grant_command(key).is_some(), "{rel} {:o}: readable beyond its reader with no sudo line", mode_of(key));
                    }
                }
                KeyReader::Unknown => panic!("{rel} has no reader row"),
            }
        }
        let exposed: Vec<KeyIssue> = ca.audit_key_modes().into_iter().filter(|i| i.kind == KeyIssueKind::Exposed && ca.key_grant_command(&ca.dir.join(&i.rel)).is_none()).collect();
        assert!(exposed.is_empty(), "exposed with no pending hand-over: {exposed:?}");
        let mut crts = Vec::new();
        collect_ext(&ca.dir, "crt", &mut crts);
        for c in crts {
            assert_eq!(mode_of(&c), 0o644, "{}", c.display());
        }
    }

    /// The upgrade/provision repair of a key re-written by another owner
    /// cannot be exercised without root; its two halves can: the copy keeps
    /// the bytes and lands 0600, and the line names the operator's uid and
    /// the reader's group and mode.
    #[test]
    fn a_foreign_key_is_taken_back_or_named_with_one_line() {
        let dir = scratch();
        let key = dir.join("service.key");
        std::fs::write(&key, b"key-bytes\n").unwrap();
        std::fs::set_permissions(&key, std::fs::Permissions::from_mode(0o644)).unwrap();
        reown(&key).unwrap();
        assert_eq!(mode_of(&key), 0o600);
        assert_eq!(std::fs::read(&key).unwrap(), b"key-bytes\n");
        assert!(!dir.join(".service.key.reown").exists(), "no temp file left behind");
        let p = Path::new("/p/services/loki/service.key");
        assert_eq!(owner_fix_line(p, KeyReader::ContainerUid(65532), 1000, 1000),
            "sudo chown 1000:65532 /p/services/loki/service.key && sudo chmod 640 /p/services/loki/service.key");
        assert_eq!(owner_fix_line(p, KeyReader::Cli, 1000, 1001),
            "sudo chown 1000:1001 /p/services/loki/service.key && sudo chmod 600 /p/services/loki/service.key");
        // Own files are never "foreign".
        let ca = ClusterCa::new(dir);
        assert!(!ca.foreign_owner(&key));
    }

    /// PLANTED: a node key left 0644 (what every install before this
    /// change has) is reported as exposed, tightened to 0600 by
    /// `fix_key_modes`, and then clean. Group-writable directories come
    /// down to 0755 in the same pass. Running it twice changes nothing.
    #[test]
    fn fix_key_modes_tightens_a_planted_0644_key() {
        let ca = ClusterCa::new(scratch());
        ca.generate_ca("t", 3650).unwrap();
        let (_, node_key) = ca.issue_node_cert("host3", "10.0.0.3", 90, &[], &[], &crate::pki::NodeRole::Worker).unwrap();
        std::fs::set_permissions(&node_key, std::fs::Permissions::from_mode(0o644)).unwrap();
        std::fs::set_permissions(node_key.parent().unwrap(), std::fs::Permissions::from_mode(0o775)).unwrap();

        let issues = ca.audit_key_modes();
        let planted: Vec<&KeyIssue> = issues.iter().filter(|i| i.rel == "nodes/host3/node.key").collect();
        assert_eq!(planted.len(), 1, "the planted key must be found: {issues:?}");
        assert_eq!(planted[0].kind, KeyIssueKind::Exposed);
        assert_eq!(planted[0].mode, 0o644);
        assert_eq!(planted[0].reader, KeyReader::Cli);

        let (fixes, dirs) = ca.fix_key_modes();
        let f = fixes.iter().find(|f| f.rel == "nodes/host3/node.key").expect("a fix row for the planted key");
        assert!(f.changed());
        assert_eq!((f.before, f.after), (0o644, 0o600));
        assert!(f.needs.is_none());
        assert_eq!(mode_of(&node_key), 0o600);
        assert!(dirs.contains(&"nodes/host3".to_string()), "the 0775 dir was tightened: {dirs:?}");
        assert_eq!(mode_of(node_key.parent().unwrap()), 0o755);
        assert!(!ca.audit_key_modes().iter().any(|i| i.rel == "nodes/host3/node.key"), "clean after the fix");

        let (again, dirs_again) = ca.fix_key_modes();
        assert!(again.iter().all(|f| !f.changed() || f.reader == KeyReader::ContainerUid(65532)), "second pass is a no-op: {again:?}");
        assert!(dirs_again.is_empty(), "{dirs_again:?}");
    }

    /// A uid-read key: either this process could hand it over (group or
    /// ACL) and the audit is clean, or it could not, the file is left
    /// READABLE (0644 — fail open: the service must keep starting), the
    /// audit reports it exposed and the exact sudo line is the fix. Never
    /// a third state.
    #[test]
    fn a_uid_read_key_is_granted_or_left_with_the_sudo_line() {
        let ca = ClusterCa::new(scratch());
        ca.generate_ca("t", 3650).unwrap();
        let (_, loki_key) = ca.issue_service_cert("loki", &[], &[], 90).unwrap();
        let (fixes, _) = ca.fix_key_modes();
        let f = fixes.iter().find(|f| f.rel == "services/loki/service.key").unwrap();
        let mode = mode_of(&loki_key);
        match (&f.needs, readable_by_uid(&loki_key, 65532)) {
            (None, Some(true)) => {
                assert_ne!(mode & 0o004, 0o004, "granted, so not world-readable");
                assert!(!ca.audit_key_modes().iter().any(|i| i.rel == f.rel), "granted keys audit clean");
            }
            (Some(cmd), Some(true)) => {
                assert!(cmd.contains("sudo chgrp 65532") && cmd.contains("chmod 640"), "{cmd}");
                assert_eq!(mode, 0o644, "not handed over, so left readable: the service keeps starting");
                let issue = ca.audit_key_modes().into_iter().find(|i| i.rel == f.rel).expect("audited");
                assert_eq!(issue.kind, KeyIssueKind::Exposed);
                assert_eq!(ca.key_grant_command(&loki_key).as_deref(), Some(cmd.as_str()));
                // A key someone set 0640 without the hand-over: the owning
                // group (not the reader's) can read it and the reader cannot.
                // Exposure is what is reported — the verify row fails it —
                // and the next fix pass opens it again rather than leaving
                // the service dead.
                std::fs::set_permissions(&loki_key, std::fs::Permissions::from_mode(0o640)).unwrap();
                let issue = ca.audit_key_modes().into_iter().find(|i| i.rel == f.rel).expect("audited");
                assert_eq!(issue.kind, KeyIssueKind::Exposed, "{issue:?}");
                let (again, _) = ca.fix_key_modes();
                let f2 = again.iter().find(|f| f.rel == "services/loki/service.key").unwrap();
                assert_eq!((f2.before, f2.after, f2.needs.is_some()), (0o640, 0o644, true), "{f2:?}");
            }
            other => panic!("granted-and-unreadable or ungranted-and-readable: {other:?}"),
        }
    }

    /// Re-issuing in place (what `rotate-all` does) keeps the tightened
    /// mode — the operator owns the files, so the CLI can always rewrite
    /// them, and the new key is not looser than the old one.
    #[test]
    fn rotate_all_keeps_the_tightened_mode() {
        let ca = ClusterCa::new(scratch());
        ca.generate_ca("t", 3650).unwrap();
        let (_, node_key) = ca.issue_node_cert("host6", "10.0.0.4", 1, &[], &[], &crate::pki::NodeRole::Worker).unwrap();
        let (_, nats_key) = ca.issue_service_cert("nats", &[], &[], 1).unwrap();
        let before_node = std::fs::read(&node_key).unwrap();
        let rotated = ca.rotate_all_expiring(36500, 90, |_| NodeRole::Worker);
        assert_eq!(rotated.len(), 2, "{:?}", rotated.iter().map(|r| (&r.name, r.status, &r.error)).collect::<Vec<_>>());
        assert!(rotated.iter().all(|r| r.status == "rotated"), "{:?}", rotated.iter().map(|r| &r.error).collect::<Vec<_>>());
        assert_ne!(std::fs::read(&node_key).unwrap(), before_node, "a new key was written");
        assert_eq!(mode_of(&node_key), 0o600);
        assert_eq!(mode_of(&nats_key), 0o600);
    }

    /// The ACL reader: named entries count only under the mask, the
    /// owning group is who the metadata says, `#effective:` annotations
    /// are ignored, and text without base entries falls back to the mode.
    #[test]
    fn extra_readers_are_read_from_the_acl_under_its_mask() {
        let acl = |t: &str, mode: u32| extra_readers(&Access { mode, gid: 1000, acl: Some(t.to_string()) });
        // setfacl -m u:65532:r on a 0600 file: group entry ---, mask r--.
        let t = "user::rw-\nuser:65532:r--\ngroup::---\nmask::r--\nother::---\n";
        assert_eq!(acl(t, 0o640), vec![Principal::User(65532)]);
        // The mask blocks the named user: getfacl annotates it.
        let t = "user::rw-\nuser:65532:r--\t\t#effective:---\ngroup::---\nmask::---\nother::---\n";
        assert_eq!(acl(t, 0o600), vec![]);
        // Owning group rides along under a read mask; world too.
        let t = "user::rw-\nuser:70:r--\ngroup::r--\nmask::r--\nother::r--\n";
        assert_eq!(acl(t, 0o644), vec![Principal::User(70), Principal::Group(1000), Principal::Other]);
        // No ACL text (getfacl absent): the mode bits decide.
        let plain = |mode: u32, gid: u32| extra_readers(&Access { mode, gid, acl: None });
        assert_eq!(plain(0o600, 1000), vec![]);
        assert_eq!(plain(0o640, 65532), vec![Principal::Group(65532)]);
        assert_eq!(plain(0o644, 1000), vec![Principal::Group(1000), Principal::Other]);
    }
}

#[cfg(test)]
mod public_view_tests {
    //! The gateway's certificate-only view: `public/`
    //! carries a copy of every certificate under `nodes/` and `services/`
    //! and nothing else, and every writer of a certificate keeps it so.
    use super::*;

    fn scratch() -> PathBuf {
        let d = std::env::temp_dir()
            .join(format!("noo-pki-public-{}", std::process::id()))
            .join(format!("{:x}", std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_nanos()));
        std::fs::create_dir_all(&d).unwrap();
        d
    }

    fn files_under(dir: &Path) -> Vec<String> {
        let mut all = Vec::new();
        collect_entries(dir, &mut all);
        let mut out: Vec<String> = all
            .into_iter()
            .filter(|p| !std::fs::symlink_metadata(p).unwrap().is_dir())
            .map(|p| p.strip_prefix(dir).unwrap().to_string_lossy().into_owned())
            .collect();
        out.sort();
        out
    }

    /// Issuing a node, a node's backend door leaf, a service and the
    /// gateway leaves `public/` holding exactly the node and service
    /// certificates — no key, no gateway leaf (the gateway mounts its own
    /// `gateway/`), no CA key — and `list_certs` does not count the copies.
    #[test]
    fn issuance_mirrors_every_node_and_service_cert_and_no_key() {
        let ca = ClusterCa::new(scratch());
        ca.generate_ca("t", 3650).unwrap();
        ca.issue_node_cert("host9", "10.0.0.2", 90, &[], &[], &crate::pki::NodeRole::Worker).unwrap();
        ca.issue_node_service_cert("host9", "vllm", &[], 90).unwrap();
        ca.issue_service_cert("loki", &[], &[], 90).unwrap();
        ca.issue_gateway_cert("h", "10.0.0.1", 90, &[], &[]).unwrap();
        assert_eq!(
            files_under(&ca.public_view_dir()),
            vec![
                "nodes/host9/node.crt".to_string(),
                "nodes/host9/services/vllm/service.crt".to_string(),
                "services/loki/service.crt".to_string(),
            ]
        );
        for rel in files_under(&ca.public_view_dir()) {
            assert_eq!(
                std::fs::read(ca.public_view_dir().join(&rel)).unwrap(),
                std::fs::read(ca.dir.join(&rel)).unwrap(),
                "{rel}: the copy is the certificate"
            );
            let mode = std::fs::metadata(ca.public_view_dir().join(&rel)).unwrap().permissions().mode() & 0o777;
            assert_eq!(mode, 0o644, "{rel}");
        }
        let drift = ca.public_view_drift();
        assert!(drift.is_clean(), "{drift:?}");
        assert_eq!(drift.total, 3);
        assert!(ca.dir.join("sso").is_dir(), "sso/ is a gateway bind source: it must exist as the operator's");
        let listed: Vec<String> = ca.list_certs().into_iter().map(|c| c.name).collect();
        assert!(listed.iter().all(|n| !n.starts_with("public")), "copies counted twice: {listed:?}");
        assert_eq!(listed.len(), 5, "ca, gateway, node, node door, loki: {listed:?}");
    }

    /// PLANT TARGET: rotation (`rotate-all`, `rotate`, the heartbeat's
    /// spooled rotate) re-issues in place through `issue_leaf`; the copy
    /// must follow, or the gateway keeps reporting the OLD expiry and the
    /// expiry alarm never clears. Remove the sync from `issue_leaf` and
    /// this fails on `stale`.
    #[test]
    fn rotation_keeps_the_view_in_step() {
        let ca = ClusterCa::new(scratch());
        ca.generate_ca("t", 3650).unwrap();
        let (node_crt, _) = ca.issue_node_cert("host6", "10.0.0.4", 1, &[], &[], &crate::pki::NodeRole::Worker).unwrap();
        ca.issue_service_cert("prometheus", &[], &[], 1).unwrap();
        // In step before the rotation, whatever issuance did: what follows
        // is the rotation's own sync, and nothing else.
        assert!(ca.sync_public_view().errors.is_empty());
        assert!(ca.public_view_drift().is_clean());
        let before = std::fs::read(&node_crt).unwrap();
        let rotated = ca.rotate_all_expiring(36500, 90, |_| NodeRole::Worker);
        assert_eq!(rotated.len(), 2, "{:?}", rotated.iter().map(|r| (&r.name, &r.error)).collect::<Vec<_>>());
        assert_ne!(std::fs::read(&node_crt).unwrap(), before);
        let drift = ca.public_view_drift();
        assert!(drift.stale.is_empty(), "rotation left the gateway's view behind: {drift:?}");
        assert!(drift.is_clean(), "{drift:?}");
        assert_eq!(
            std::fs::read(ca.public_view_dir().join("nodes/host6/node.crt")).unwrap(),
            std::fs::read(&node_crt).unwrap()
        );
    }

    /// PLANTED: a key, a copy whose source is gone, a symlink to a key and
    /// a stray file in `public/` are each reported by the drift and
    /// removed by a sync; the mirrored roots survive (a running gateway
    /// has them bind-mounted).
    #[test]
    fn sync_removes_what_is_not_a_mirrored_certificate() {
        let ca = ClusterCa::new(scratch());
        ca.generate_ca("t", 3650).unwrap();
        let (_, loki_key) = ca.issue_service_cert("loki", &[], &[], 90).unwrap();
        let public = ca.public_view_dir();
        std::fs::write(public.join("services/loki/service.key"), b"planted").unwrap();
        std::fs::create_dir_all(public.join("nodes/ghost")).unwrap();
        std::fs::write(public.join("nodes/ghost/node.crt"), b"gone").unwrap();
        std::os::unix::fs::symlink(&loki_key, public.join("services/loki/link.crt")).unwrap();
        std::fs::write(public.join("README"), b"x").unwrap();
        let drift = ca.public_view_drift();
        assert_eq!(drift.keys, vec!["services/loki/service.key".to_string()]);
        assert_eq!(drift.extra, vec!["README".to_string(), "nodes/ghost/node.crt".to_string(), "services/loki/link.crt".to_string()]);
        use std::os::unix::fs::MetadataExt as _;
        let roots_before: Vec<u64> = ["nodes", "services"].iter().map(|t| std::fs::metadata(public.join(t)).unwrap().ino()).collect();
        let sync = ca.sync_public_view();
        assert!(sync.errors.is_empty(), "{:?}", sync.errors);
        assert!(sync.removed.contains(&"services/loki/service.key".to_string()), "{:?}", sync.removed);
        assert!(sync.removed.contains(&"nodes/ghost/".to_string()), "{:?}", sync.removed);
        assert!(ca.public_view_drift().is_clean());
        assert_eq!(files_under(&public), vec!["services/loki/service.crt".to_string()]);
        let roots_after: Vec<u64> = ["nodes", "services"].iter().map(|t| std::fs::metadata(public.join(t)).unwrap().ino()).collect();
        assert_eq!(roots_before, roots_after, "the bind-mounted roots must be the same directories");
        assert_eq!(ca.sync_public_view(), PublicViewSync { total: 1, ..Default::default() }, "idempotent");
    }

    /// A cert changed by something that is not this CLI's issuer (an older
    /// `noo`, a hand copy) reads as stale until the next sync; an empty PKI
    /// dir gets every gateway bind source created as the operator.
    #[test]
    fn a_cert_changed_behind_the_view_is_stale_until_synced() {
        let ca = ClusterCa::new(scratch());
        let fresh = ca.public_view_drift();
        assert_eq!(fresh.missing_roots, vec!["nodes".to_string(), "services".to_string()]);
        assert!(ca.sync_public_view().errors.is_empty());
        for d in ["public/nodes", "public/services", "sso"] {
            let m = std::fs::metadata(ca.dir.join(d)).unwrap();
            assert!(m.is_dir(), "{d}");
            assert_eq!(m.permissions().mode() & 0o777, 0o755, "{d}");
        }
        ca.generate_ca("t", 3650).unwrap();
        let (crt, _) = ca.issue_service_cert("nats", &[], &[], 90).unwrap();
        let mut bytes = std::fs::read(&crt).unwrap();
        bytes.extend_from_slice(b"\n");
        std::fs::write(&crt, &bytes).unwrap();
        assert_eq!(ca.public_view_drift().stale, vec!["services/nats/service.crt".to_string()]);
        let sync = ca.sync_public_view();
        assert_eq!(sync.copied, vec!["services/nats/service.crt".to_string()]);
        assert!(ca.public_view_drift().is_clean());
    }
}

#[cfg(test)]
mod missing_names_tests {
    use super::*;

    fn v(a: &[&str]) -> Vec<String> {
        a.iter().map(|s| s.to_string()).collect()
    }

    /// The comparison behind the upgrade re-issue and the
    /// verify row. Names the leaf lacks come back, DNS first then IPs;
    /// what it has, empties and repeats do not.
    #[test]
    fn missing_names_is_the_wanted_set_minus_what_the_leaf_has() {
        let have = CertNames { dns: v(&["model-cache", "localhost"]), ips: v(&["127.0.0.1"]) };
        let want_dns = v(&["model-cache", "localhost", "noo-controller", "box.ts.net", "noo-controller", ""]);
        let want_ips = v(&["127.0.0.1", "10.0.0.5"]);
        assert_eq!(missing_names(&have, &want_dns, &want_ips), v(&["noo-controller", "box.ts.net", "10.0.0.5"]));
        assert!(missing_names(&have, &v(&["localhost"]), &v(&["127.0.0.1"])).is_empty());
    }

    /// A parse failure is an `Err`, never an empty (= covering) name set.
    #[test]
    fn cert_names_of_a_non_certificate_is_an_error() {
        let p = std::env::temp_dir().join(format!("noo-names-junk-{}", std::process::id()));
        std::fs::write(&p, "not a certificate").unwrap();
        assert!(ClusterCa::cert_names(&p).is_err());
        assert!(ClusterCa::cert_names(&p.with_extension("absent")).is_err());
        let _ = std::fs::remove_file(&p);
    }
}

#[cfg(test)]
mod controller_node_names_tests {
    //! The controller's own node cert keeps the controller
    //! names through every re-issue path.
    use super::*;

    fn scratch(tag: &str) -> PathBuf {
        let d = std::env::temp_dir().join(format!("noo-i11a-{tag}-{}-{:?}", std::process::id(), std::thread::current().id()));
        let _ = std::fs::remove_dir_all(&d);
        std::fs::create_dir_all(&d).unwrap();
        d
    }

    fn v(xs: &[&str]) -> Vec<String> {
        xs.iter().map(|s| s.to_string()).collect()
    }

    /// The live controller's declared identity: the gateway URL names the
    /// tailnet role device, tailscale reports the same name (trailing dot)
    /// and its address, and the loopback / docker-internal values that
    /// cannot name it from outside are skipped.
    fn host8_names() -> ControllerNames {
        ControllerNames::from_sources(&[
            "https://noo-controller.tailnet-0000.ts.net:8080",
            "noo-controller.tailnet-0000.ts.net.",
            "100.64.0.1",
            "https://localhost:8080",
            "https://gateway:8080/",
            "",
        ])
    }

    #[test]
    fn the_declared_names_always_include_the_role_alias() {
        let n = host8_names();
        assert_eq!(n.dns.as_slice(), v(&["noo-controller", "noo-controller.tailnet-0000.ts.net"]).as_slice());
        assert_eq!(n.ips.as_slice(), v(&["100.64.0.1"]).as_slice());
        // Nothing declared at all (a LAN controller before onboarding):
        // the alias is still there.
        let bare = ControllerNames::from_sources::<&str>(&[]);
        assert_eq!(bare.dns.as_slice(), v(&["noo-controller"]).as_slice());
        assert!(bare.ips.as_slice().is_empty());
    }

    #[test]
    fn hosts_are_parsed_from_urls_and_bare_values() {
        assert_eq!(host_of("https://Box.Example:8443/path?q"), Some("Box.Example".into()));
        assert_eq!(host_of("https://user@box:1/"), Some("box".into()));
        assert_eq!(host_of("https://[fd7a:115c::1]:8080"), Some("fd7a:115c::1".into()));
        assert_eq!(host_of("fd7a:115c::1"), Some("fd7a:115c::1".into()));
        assert_eq!(host_of("127.0.0.1:8080"), None);
        assert_eq!(host_of("http://[::1]:80"), None);
        assert_eq!(host_of("  "), None);
        // Names are lowercased into the set (verifiers compare that way).
        let n = ControllerNames::from_sources(&["https://NOO-B.tail.ts.net:8080"]);
        assert!(n.dns.as_slice().contains(&"noo-b.tail.ts.net".to_string()));
    }

    /// The controller's tailnet address is its own device's, never a lookup
    /// of its NODE name, which on the live tailnet named another machine.
    #[test]
    fn the_controllers_tailnet_address_is_its_own() {
        let role = NodeRole::Controller(host8_names());
        assert_eq!(role.tailnet_ip4("host8").as_deref(), Some("100.64.0.1"));
        assert_eq!(role.required_dns(), v(&["noo-controller", "noo-controller.tailnet-0000.ts.net"]).as_slice());
        assert!(NodeRole::Worker.required_dns().is_empty());
    }

    /// The incident: the controller's node cert was re-issued from an
    /// address that was not its own and without the controller names. Now
    /// a re-issue for the controller carries them, drops the stray address
    /// (addresses are not carried forward), and keeps a name an operator
    /// added by hand with `--san`, even when this run's derivation does not
    /// produce it (tailscale down at that moment).
    #[test]
    fn a_controller_reissue_keeps_the_controller_names() {
        let dir = scratch("reissue");
        let ca = ClusterCa::new(dir.clone());
        ca.generate_ca("noo-test-ca", 3650).unwrap();

        // First issue, as onboarding does.
        let role = NodeRole::Controller(host8_names());
        let (crt, _) = ca
            .issue_node_cert("host8", "192.168.1.10", 90, &v(&["node-agent", "kiosk.lan"]), &v(&["100.64.0.2"]), &role)
            .unwrap();
        let have = ClusterCa::cert_names(&crt).unwrap();
        assert!(missing_names(&have, &v(&["host8", "noo-controller", "noo-controller.tailnet-0000.ts.net"]), &v(&["100.64.0.1"])).is_empty(), "{have:?}");

        // A later re-issue whose derivation found only the alias (no
        // tailnet, no gateway URL) and a corrected address.
        let thin = NodeRole::Controller(ControllerNames::from_sources::<&str>(&[]));
        ca.issue_node_cert("host8", "192.168.1.10", 90, &v(&["node-agent"]), &[], &thin).unwrap();
        let have = ClusterCa::cert_names(&crt).unwrap();
        for name in ["host8", "noo-controller", "noo-controller.tailnet-0000.ts.net", "kiosk.lan"] {
            assert!(have.dns.iter().any(|d| d == name), "{name} dropped: {have:?}");
        }
        assert!(!have.ips.contains(&"100.64.0.2".to_string()), "a stray address was carried forward: {have:?}");

        // A worker re-issue is exactly what it was: name, address, extras.
        let (wcrt, _) = ca.issue_node_cert("host8-ma", "100.64.0.2", 90, &v(&["node-agent"]), &[], &NodeRole::Worker).unwrap();
        let w = ClusterCa::cert_names(&wcrt).unwrap();
        assert_eq!(w.dns, v(&["host8-ma", "localhost", "node-agent"]));
        assert_eq!(w.ips, v(&["100.64.0.2", "127.0.0.1"]));
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// The rotation path (`pki rotate-all`, `rotate-ca`'s local leaves):
    /// a controller node cert that had already lost the names gets them
    /// back, and a worker's cert is re-issued as it was.
    #[test]
    fn rotation_restores_the_controller_names() {
        let dir = scratch("rotate");
        let ca = ClusterCa::new(dir.clone());
        ca.generate_ca("noo-test-ca", 3650).unwrap();
        // The broken state found live: issued as a worker would be.
        let (crt, _) = ca.issue_node_cert("host8", "100.64.0.1", 1, &[], &[], &NodeRole::Worker).unwrap();
        let (wcrt, _) = ca.issue_node_cert("host6", "100.64.0.4", 1, &[], &[], &NodeRole::Worker).unwrap();
        assert_eq!(ca.node_of_cert(&crt).as_deref(), Some("host8"));
        assert_eq!(ca.node_of_cert(&dir.join("gateway/gateway.crt")), None);

        let rotated = ca.rotate_all_expiring(36500, 90, |n| {
            if n == "host8" { NodeRole::Controller(host8_names()) } else { NodeRole::Worker }
        });
        assert!(rotated.iter().all(|r| r.status == "rotated"), "{:?}", rotated.iter().map(|r| &r.error).collect::<Vec<_>>());
        let have = ClusterCa::cert_names(&crt).unwrap();
        assert!(missing_names(&have, &v(&["noo-controller", "noo-controller.tailnet-0000.ts.net"]), &[]).is_empty(), "{have:?}");
        let w = ClusterCa::cert_names(&wcrt).unwrap();
        assert!(!w.dns.iter().any(|d| d.starts_with("noo-controller")), "a worker gained controller names: {w:?}");
        let _ = std::fs::remove_dir_all(&dir);
    }
}
