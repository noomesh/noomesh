// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 PersonifAI LLC

//! The security audit log's integrity key, its one-time checkpoint, and the
//! verifier.
//!
//! Every `noo_security_audit` row carries `entry_hash`: HMAC-SHA256 over the
//! row — v1 over six varchar fields ([`row_hash_with`], mirrored by
//! `src/noomesh/gateway/audit_log.py::audit_row_hash`), v2 over every column
//! ([`canonical_v2`], mirrored by `audit_log.py::canonical_v2`; see "Hash
//! version 2" below). Until this module the
//! key was, when `NOO_AUDIT_HMAC_KEY` was unset — which was every install —
//! DERIVED from `NOO_JWT_SECRET` (`sha256("audit-hmac:" + secret)`), and from
//! the public literal `"audit-integrity-fallback"` when even that was absent.
//! So anyone holding the HS256 login secret, which four containers held, could
//! also re-sign an audit row after editing it, and a row signed with the
//! literal was tamper-evident against nobody.
//!
//! Now:
//!
//! * **Writers sign with `NOO_AUDIT_HMAC_KEY` and nothing else.** Absent, a
//!   row is REFUSED at `error!` (both runtimes); there is no fallback.
//! * **One checkpoint row hands the chain over.** On the first boot with the
//!   dedicated key, the gateway finds the newest row signed under the retired
//!   derivation and appends ONE `audit_key_checkpoint` row, SIGNED UNDER THAT
//!   RETIRED KEY, naming a fingerprint of the new key (never the key), the
//!   `entry_hash` of that last retired-key row, and the time. From then on
//!   every row is signed with the new key. An install with no retired-key
//!   rows (fresh, or one that always had the key) gets a *genesis*
//!   checkpoint instead, signed with the new key and naming no predecessor.
//! * **The verifier knows both.** Rows before the checkpoint verify under the
//!   retired derivation (which needs `NOO_JWT_SECRET`, so the verifier runs in
//!   the gateway: `GET /api/security/audit/verify`, `noo security audit
//!   verify`); rows after it verify under the new key ONLY — a row after the
//!   checkpoint that verifies under the retired key is a forgery by someone
//!   holding the login secret, and is reported as exactly that.
//!
//! The retired derivation survives here as a VERIFY-ONLY key. Nothing signs
//! with it except the checkpoint itself, once.
//!
//! **The roll window**. A roll recreates the gateway while
//! old-image Python writers (noo-worker, worker-extra, trellion,
//! trellion-intel) can still be running; up to v0.2.81 they fell back to the
//! retired derivation, so one row from them after the checkpoint used to fail
//! the log for good. Such a row is a WARNING, not a failure, only when it
//! verifies under the retired key, carries one of the fixed (actor,
//! event_type) pairs those writers emit (`ROLL_WINDOW_WRITERS`), and is
//! stamped within `ROLL_WINDOW_SECS` after the checkpoint's signed `at`.
//! Every such row is counted and its writer named. Anything else signed with
//! the retired key after the checkpoint is still a forgery.
//!
//! **Hash version 2**. The v1 form above covered six varchar
//! fields only. The row's `timestamp`, `id`, `details` (where `source_ip`
//! lives) and `prev_hash` were outside it, so anyone with database write
//! access could re-time a row, or copy one under a new id, without breaking
//! its hash. From v0.2.83 both writers sign the v2 form ([`canonical_v2`]):
//! every column but `entry_hash` itself, length-prefixed, the time as the
//! STORED microseconds, `details` as Postgres's own `jsonb` text. A v2 hash is
//! stored as `v2:<hex>`; a bare 64-hex `entry_hash` is v1. The format is read
//! from the hash itself, so no column was added.
//!
//! The switch is marked, not dated: the first v0.2.83 gateway boot appends
//! one `audit_hash_v2` row ([`HASH_V2_MARKER_EVENT`]), signed v2 with the
//! audit key. A v1 row is accepted before that marker and FAILS after it —
//! except a row from one of the fixed old-image writers (`ROLL_WINDOW_WRITERS`)
//! stamped within `ROLL_WINDOW_SECS` of the marker: a v0.2.82 Python writer
//! still running during the roll signs v1 under the audit key. (A v0.2.81
//! writer signs v1 under the RETIRED key; that row is the checkpoint's roll
//! window above, unchanged.) The marker's own position is bound, because its
//! timestamp is hashed; a v2 row stamped more than the window BEFORE the
//! marker means a marker was deleted and a later boot wrote another.
//!
//! What this does not do: `entry_hash` is per-row, not a `prev_hash` chain,
//! so it detects EDITED rows and rows signed with the wrong key, not a row
//! deleted from the middle of an epoch (four processes write concurrently; a
//! true chain needs one sealing writer — migration 024's note). The
//! checkpoint's `after:` link does detect deletion of the retired epoch's
//! last rows, the one place it matters most.

use hmac::{Hmac, KeyInit, Mac};
use serde::Serialize;
use sha2::{Digest, Sha256};

/// The dedicated key. Delivered as a file (`NOO_AUDIT_HMAC_KEY_FILE`).
pub const KEY_ENV: &str = "NOO_AUDIT_HMAC_KEY";
/// `event_type` of the checkpoint row.
pub const CHECKPOINT_EVENT: &str = "audit_key_checkpoint";
/// The literal the retired derivation fell back to when `NOO_JWT_SECRET` was
/// unreadable. Public, so a row signed with it proves nothing.
const PUBLIC_FALLBACK_SEED: &str = "audit-integrity-fallback";
/// Domain separator for the key fingerprint.
const FP_CONTEXT: &[u8] = b"noo-audit-key-fingerprint-v1";
/// Field separator of the v1 hashed form (MUST match audit_log.py).
const SEP: &str = "\u{1f}";
/// `entry_hash` prefix of a v2 hash. A v1 hash is bare hex.
pub const V2_PREFIX: &str = "v2:";
/// Domain tag that opens the v2 canonical form (MUST match audit_log.py).
const V2_DOMAIN: &str = "noo-audit-row-v2";
/// `event_type` of the one row marking the switch to hash v2.
pub const HASH_V2_MARKER_EVENT: &str = "audit_hash_v2";
/// `resource` of the marker row.
pub const HASH_V2_MARKER_RESOURCE: &str = "audit-hash:v2";
/// How far a key checkpoint's row `timestamp` may sit from the `at` it signed.
/// The gateway computes `at` and inserts the row in one step; a v1 checkpoint
/// cannot hash its own timestamp, so this is what pins where it sits.
const CHECKPOINT_AT_SKEW_SECS: i64 = 300;
/// How long after the checkpoint's `at` a row signed with the RETIRED key by
/// an old-image Python writer is a warning rather than a forgery.
///
/// The roll is one `docker compose up -d --force-recreate` (the launcher,
/// `scripts/noomesh-start.sh`): images are pulled before anything is
/// recreated, and the gateway and the Python writers are recreated in the
/// same invocation, normally seconds apart. A whole `noo upgrade --all` took
/// about four minutes in the upgrade rehearsal; the launcher's one retry adds
/// 5 s plus a resumed pull. Fifteen minutes covers that with margin, and is
/// the whole span in which someone holding NOO_JWT_SECRET (not the audit
/// key) could add a row that does not fail — and then only as one of the
/// two benign events below, named in a warning.
pub const ROLL_WINDOW_SECS: i64 = 15 * 60;
/// The (actor, event_type) pairs the pre-v0.2.82 Python writers emit with a
/// FIXED actor — `src/noomesh/gateway/worker_pool.py` at stack-v0.2.81: the
/// startup marker (`audit("audit_logger_started", actor="worker_pool")`) and
/// the bus refusal (`audit("bus_principal_refused", actor="bus")`). The
/// trellion and trellion-intel images run the same worker_pool. The other
/// Python call sites (auth.py, exec_approval.py, cluster_auth.py) take the
/// actor from a username, approver or client address, so no allow-list can
/// name them without admitting any actor: a retired-key row from them stays
/// a failure.
const ROLL_WINDOW_WRITERS: &[(&str, &str)] =
    &[("worker_pool", "audit_logger_started"), ("bus", "bus_principal_refused")];

/// The dedicated key, or `None` when this process was not given one.
pub fn current_key() -> Option<Vec<u8>> {
    let found = key_from(&|name| crate::config::secret_env::secret_opt(name));
    // Test builds only: the DB-backed suites (channels, refresh rotation, …)
    // assert that their audit rows LAND, and a test process has no key.
    // The refusal itself is pinned through `key_from`, which has no such arm.
    #[cfg(test)]
    let found = found.or_else(|| Some(b"test-build-audit-key".to_vec()));
    found
}

/// The key as found by `lookup` (a `secret_opt`). `NOO_AUDIT_HMAC_KEY` and
/// nothing else: no derivation of `NOO_JWT_SECRET`, no literal.
pub fn key_from(lookup: &dyn Fn(&str) -> Option<String>) -> Option<Vec<u8>> {
    lookup(KEY_ENV).filter(|k| !k.is_empty()).map(String::into_bytes)
}

/// A gateway with no audit key does not serve: every security audit row
/// would be refused (nothing is written unsigned), so a login failure, an
/// exec denial, a posture change and an erase would all go unrecorded while
/// the product reported healthy. Same standard as `auth::LEGACY_REFUSAL`.
pub const MISSING_KEY_REFUSAL: &str =
    "NOO_AUDIT_HMAC_KEY is not set. Without it every security audit row is refused — logins, exec \
     denials, posture changes and erases would go unrecorded — so the gateway refuses to start. \
     Mint it: `noo upgrade --stack` (mints it into the encrypted store when absent, then recreates \
     the stack), or `noo security secrets rotate NOO_AUDIT_HMAC_KEY` and `noo stack restart --force`. \
     Existing audit rows stay verifiable: the first boot with the key writes the checkpoint that \
     hands the chain over.";

/// The boot refusal, given a secret lookup. `None` = a key is present.
pub fn boot_refusal_from(lookup: &dyn Fn(&str) -> Option<String>) -> Option<&'static str> {
    key_from(lookup).is_none().then_some(MISSING_KEY_REFUSAL)
}

/// The boot refusal for this process's environment (env or `_FILE`).
pub fn boot_refusal() -> Option<&'static str> {
    boot_refusal_from(&|name| crate::config::secret_env::secret_opt(name))
}

/// The RETIRED derivation, for verifying rows written before the checkpoint.
/// Never a signing source for an ordinary row.
pub fn retired_key_from(jwt_secret: &str) -> Vec<u8> {
    let mut h = Sha256::new();
    h.update(format!("audit-hmac:{jwt_secret}").as_bytes());
    h.finalize().to_vec()
}

/// The retired derivation of THIS gateway's `NOO_JWT_SECRET`.
pub fn retired_key() -> Option<Vec<u8>> {
    crate::config::secret_env::secret_opt("NOO_JWT_SECRET").map(|s| retired_key_from(&s))
}

fn public_fallback_key() -> Vec<u8> {
    retired_key_from(PUBLIC_FALLBACK_SEED)
}

/// A key's fingerprint: 128 bits of HMAC(key, context). Keyed, so it says
/// nothing about the key beyond "the same one".
pub fn fingerprint(key: &[u8]) -> String {
    let mut mac = <Hmac<Sha256>>::new_from_slice(key).expect("HMAC accepts any key length");
    mac.update(FP_CONTEXT);
    hex::encode(&mac.finalize().into_bytes()[..16])
}

/// HMAC-SHA256 over the stable fields under `key` — the `entry_hash` form.
pub fn row_hash_with(
    key: &[u8],
    event_type: &str,
    severity: &str,
    actor: &str,
    resource: &str,
    outcome: &str,
    request_id: &str,
) -> String {
    let canonical = [event_type, severity, actor, resource, outcome, request_id].join(SEP);
    let mut mac = <Hmac<Sha256>>::new_from_slice(key).expect("HMAC accepts any key length");
    mac.update(canonical.as_bytes());
    hex::encode(mac.finalize().into_bytes())
}

/// Every column of a row but `entry_hash`, as the v2 hash covers it.
///
/// `ts_us` is the STORED value: microseconds since the Unix epoch, Postgres
/// `timestamptz`'s own precision. A writer hashes the timestamp it binds, after
/// truncating it to microseconds, never a finer in-memory clock reading.
/// `details` is Postgres's `jsonb` text for the value (`$1::jsonb::text`): jsonb
/// re-orders keys and re-spaces on store, so the writer asks Postgres for that
/// text before hashing, and the verifier reads `details::text`.
#[derive(Debug, Clone, Copy)]
pub struct RowV2<'a> {
    pub id: &'a str,
    pub ts_us: i64,
    pub event_type: &'a str,
    pub severity: &'a str,
    pub actor: &'a str,
    pub resource: &'a str,
    pub outcome: &'a str,
    pub request_id: Option<&'a str>,
    pub details: Option<&'a str>,
    pub prev_hash: Option<&'a str>,
}

/// The v2 canonical form. `noo-audit-row-v2`, then per column, in this order,
/// `\n<name>=` followed by `-` for SQL NULL or `<utf-8 byte length>:<value>`.
/// Length-prefixed, so no value can shift a field boundary (v1's `\x1f` join
/// could), and NULL is not the empty string.
///
/// ⚠️ MUST stay byte-identical to `audit_log.py::canonical_v2`; pinned by the
/// shared vectors in `gateway-rust/tests/fixtures/audit_hash_v2_vectors.json`.
pub fn canonical_v2(r: &RowV2) -> String {
    let ts = r.ts_us.to_string();
    let fields: [(&str, Option<&str>); 10] = [
        ("id", Some(r.id)),
        ("timestamp_us", Some(&ts)),
        ("event_type", Some(r.event_type)),
        ("severity", Some(r.severity)),
        ("actor", Some(r.actor)),
        ("resource", Some(r.resource)),
        ("outcome", Some(r.outcome)),
        ("request_id", r.request_id),
        ("details", r.details),
        ("prev_hash", r.prev_hash),
    ];
    let mut out = String::from(V2_DOMAIN);
    for (name, value) in fields {
        out.push('\n');
        out.push_str(name);
        out.push('=');
        match value {
            None => out.push('-'),
            Some(v) => {
                out.push_str(&v.len().to_string());
                out.push(':');
                out.push_str(v);
            }
        }
    }
    out
}

/// The v2 `entry_hash`: `v2:` + HMAC-SHA256 over [`canonical_v2`].
pub fn row_hash_v2(key: &[u8], r: &RowV2) -> String {
    let mut mac = <Hmac<Sha256>>::new_from_slice(key).expect("HMAC accepts any key length");
    mac.update(canonical_v2(r).as_bytes());
    format!("{V2_PREFIX}{}", hex::encode(mac.finalize().into_bytes()))
}

/// One row as the verifier reads it.
#[derive(Debug, Clone)]
pub struct AuditRow {
    pub id: String,
    /// For display: the stored time as RFC 3339.
    pub timestamp: String,
    /// The stored time, microseconds since the Unix epoch — what v2 hashes.
    pub ts_us: i64,
    pub event_type: String,
    pub severity: String,
    pub actor: String,
    pub resource: String,
    pub outcome: String,
    pub request_id: Option<String>,
    /// `details::text`.
    pub details: Option<String>,
    pub prev_hash: Option<String>,
    pub entry_hash: Option<String>,
    /// Position in the hash chain (`audit_chain`); NULL for a row written before it.
    pub chain_seq: Option<i64>,
    pub chain_hash: Option<String>,
}

impl AuditRow {
    /// Is the stored hash in the v2 form?
    pub fn is_v2(&self) -> bool {
        self.entry_hash.as_deref().is_some_and(|h| h.starts_with(V2_PREFIX))
    }

    fn v2_fields(&self) -> RowV2<'_> {
        RowV2 {
            id: &self.id,
            ts_us: self.ts_us,
            event_type: &self.event_type,
            severity: &self.severity,
            actor: &self.actor,
            resource: &self.resource,
            outcome: &self.outcome,
            request_id: self.request_id.as_deref(),
            details: self.details.as_deref(),
            prev_hash: self.prev_hash.as_deref(),
        }
    }

    /// The hash under `key` in the format the row's stored hash claims.
    fn hash_under(&self, key: &[u8]) -> String {
        if self.is_v2() {
            row_hash_v2(key, &self.v2_fields())
        } else {
            row_hash_with(
                key,
                &self.event_type,
                &self.severity,
                &self.actor,
                &self.resource,
                &self.outcome,
                self.request_id.as_deref().unwrap_or(""),
            )
        }
    }

    /// Is this the hash-v2 marker, signed v2 under `key`?
    fn is_hash_v2_marker(&self, key: &[u8]) -> bool {
        self.event_type == HASH_V2_MARKER_EVENT && self.is_v2() && self.signed_by(key)
    }

    /// One of the fixed old-image writers, stamped within the roll window
    /// after `opened_us`. Says nothing about the signature.
    fn in_v1_roll_window(&self, opened_us: i64) -> bool {
        ROLL_WINDOW_WRITERS
            .iter()
            .any(|(actor, event)| self.actor == *actor && self.event_type == *event)
            && (0..=ROLL_WINDOW_SECS * 1_000_000).contains(&(self.ts_us - opened_us))
    }

    /// An old-image Python writer's row, stamped inside the roll window that
    /// opens at the checkpoint's signed `at`. Says nothing about the
    /// signature: the caller has already established it is the retired key.
    fn in_roll_window(&self, checkpoint_at: i64) -> bool {
        if !ROLL_WINDOW_WRITERS
            .iter()
            .any(|(actor, event)| self.actor == *actor && self.event_type == *event)
        {
            return false;
        }
        (0..=ROLL_WINDOW_SECS).contains(&(self.ts_us.div_euclid(1_000_000) - checkpoint_at))
    }

    pub(crate) fn signed_by(&self, key: &[u8]) -> bool {
        let Some(stored) = self.entry_hash.as_deref() else { return false };
        let expected = self.hash_under(key);
        // Constant-time: the comparison is against attacker-editable data.
        expected.len() == stored.len()
            && expected
                .bytes()
                .zip(stored.bytes())
                .fold(0u8, |acc, (a, b)| acc | (a ^ b))
                == 0
    }
}

/// The checkpoint's fields, parsed back out of `resource` / `outcome`.
///
/// `resource` = `audit-key:<new fp>;after:<entry_hash|none>;at:<unix secs>`
/// `outcome`  = `from:<retired fp>` or `from:none` (genesis)
///
/// Both are HASHED fields, so the checkpoint's signature covers every one of
/// them (`details` is not hashed — see audit_log.py — and carries only prose).
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Checkpoint {
    pub new_fingerprint: String,
    pub after: Option<String>,
    pub at: i64,
    pub from: Option<String>,
}

impl Checkpoint {
    pub fn genesis(&self) -> bool {
        self.from.is_none()
    }

    pub fn resource(&self) -> String {
        format!(
            "audit-key:{};after:{};at:{}",
            self.new_fingerprint,
            self.after.as_deref().unwrap_or("none"),
            self.at
        )
    }

    pub fn outcome(&self) -> String {
        format!("from:{}", self.from.as_deref().unwrap_or("none"))
    }

    pub fn parse(row: &AuditRow) -> Option<Checkpoint> {
        if row.event_type != CHECKPOINT_EVENT {
            return None;
        }
        let mut new_fingerprint = None;
        let mut after = None;
        let mut at = None;
        for part in row.resource.split(';') {
            if let Some(v) = part.strip_prefix("audit-key:") {
                new_fingerprint = Some(v.to_string());
            } else if let Some(v) = part.strip_prefix("after:") {
                after = Some(if v == "none" { None } else { Some(v.to_string()) });
            } else if let Some(v) = part.strip_prefix("at:") {
                at = v.parse::<i64>().ok();
            }
        }
        let from = match row.outcome.strip_prefix("from:")? {
            "none" => None,
            v => Some(v.to_string()),
        };
        Some(Checkpoint { new_fingerprint: new_fingerprint?, after: after?, at: at?, from })
    }
}

/// The keys a verifier holds.
pub struct Keys {
    pub current: Option<Vec<u8>>,
    pub retired: Option<Vec<u8>>,
}

#[derive(Debug, Clone, Serialize)]
pub struct Break {
    pub id: String,
    pub timestamp: String,
    pub reason: String,
}

/// One old-image writer's rows inside the roll window.
#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct RollWindowWriter {
    pub actor: String,
    pub rows: u64,
}

#[derive(Debug, Clone, Serialize)]
pub struct CheckpointView {
    pub id: String,
    pub timestamp: String,
    #[serde(flatten)]
    pub checkpoint: Checkpoint,
    pub genesis: bool,
}

#[derive(Debug, Clone, Serialize)]
pub struct MarkerView {
    pub id: String,
    pub timestamp: String,
}

/// The verdict over the whole table.
#[derive(Debug, Clone, Serialize, Default)]
pub struct Report {
    /// `ok` | `fail`.
    pub verdict: String,
    pub key_present: bool,
    pub key_fingerprint: Option<String>,
    pub checked: u64,
    pub ok: u64,
    /// Written before migration 024 (no `entry_hash`) — neither ok nor failed.
    pub unhashed: u64,
    /// Before the checkpoint, signed with the PUBLIC fallback literal: not
    /// tampered, and not evidence of anything either.
    pub public_fallback: u64,
    /// Before the checkpoint, and this verifier does not hold the key that
    /// signed them (its NOO_JWT_SECRET is not the one the checkpoint retired).
    pub unverifiable: u64,
    pub retired_epoch_rows: u64,
    pub current_epoch_rows: u64,
    /// After the checkpoint, inside `ROLL_WINDOW_SECS`, from an old-image
    /// Python writer, signed with the retired key: warned, not failed.
    pub roll_window_rows: u64,
    /// The same rows by writer, each also a line in `warnings`.
    pub roll_window: Vec<RollWindowWriter>,
    pub checkpoint: Option<CheckpointView>,
    /// Hashed rows by hash format.
    pub v1_rows: u64,
    pub v2_rows: u64,
    /// The `audit_hash_v2` row after which a v1 hash fails.
    pub hash_v2_marker: Option<MarkerView>,
    /// After the hash-v2 marker, inside `ROLL_WINDOW_SECS`, from an old-image
    /// (v0.2.82) Python writer, hashed v1 under the audit key: warned, not failed.
    pub v1_roll_window_rows: u64,
    pub v1_roll_window: Vec<RollWindowWriter>,
    /// Row-level failures, each naming the row.
    pub breaks: Vec<Break>,
    /// The hash chain over the rows: deletion and reordering evidence
    /// (`audit_chain`). Its breaks are also in `breaks`, prefixed `chain:`.
    pub chain: crate::audit_chain::ChainReport,
    /// Table-level failures (no key, no checkpoint).
    pub problems: Vec<String>,
    pub warnings: Vec<String>,
}

/// Judge every row, in `(timestamp, id)` order. Pure, so each rule below is
/// pinned by a test with no database.
pub fn verify_rows(rows: &[AuditRow], keys: &Keys) -> Report {
    let mut r = Report {
        key_present: keys.current.is_some(),
        key_fingerprint: keys.current.as_deref().map(fingerprint),
        ..Report::default()
    };
    let public = public_fallback_key();

    // THE checkpoint: the first one naming the key this gateway holds.
    let cp_idx = r.key_fingerprint.as_ref().and_then(|fp| {
        rows.iter().position(|row| {
            Checkpoint::parse(row).is_some_and(|c| &c.new_fingerprint == fp)
        })
    });
    let cp = cp_idx.and_then(|i| Checkpoint::parse(&rows[i]));

    // Is the retired key we hold the one the checkpoint retired? If the login
    // secret has been rotated since, it is not, and the epoch before the
    // checkpoint cannot be judged either way.
    let retired_fp = keys.retired.as_deref().map(fingerprint);
    let retired_usable = match (&keys.retired, &cp) {
        (None, _) => false,
        (Some(_), Some(c)) if !c.genesis() => c.from == retired_fp,
        (Some(_), _) => true,
    };
    if keys.retired.is_some() && !retired_usable {
        r.warnings.push(
            "the checkpoint retired a key derived from a different NOO_JWT_SECRET than this \
             gateway holds (rotated since?): rows before it are counted unverifiable, not tampered"
                .into(),
        );
    }
    let retired = keys.retired.as_deref().filter(|_| retired_usable);

    // THE hash-v2 marker: the first one signed v2 under the audit key. Its
    // timestamp is hashed, so where it sits is where it was written.
    let marker_idx = keys
        .current
        .as_deref()
        .and_then(|k| rows.iter().position(|row| row.is_hash_v2_marker(k)));
    let marker_us = marker_idx.map(|m| rows[m].ts_us);
    if let Some(m) = marker_idx {
        r.hash_v2_marker = Some(MarkerView { id: rows[m].id.clone(), timestamp: rows[m].timestamp.clone() });
    }

    let mut last_retired_hash: Option<String> = None;
    let mut roll_window: std::collections::BTreeMap<String, u64> = Default::default();
    let mut v1_roll_window: std::collections::BTreeMap<String, u64> = Default::default();
    for (i, row) in rows.iter().enumerate() {
        r.checked += 1;
        let Some(hash) = row.entry_hash.clone() else {
            r.unhashed += 1;
            continue;
        };
        if row.is_v2() {
            r.v2_rows += 1;
        } else {
            r.v1_rows += 1;
        }
        let brk = |reason: String| Break { id: row.id.clone(), timestamp: row.timestamp.clone(), reason };
        let by_current = keys.current.as_deref().is_some_and(|k| row.signed_by(k));
        let by_retired = retired.is_some_and(|k| row.signed_by(k));
        let by_public = row.signed_by(&public);

        // A v2 row's time is signed. One stamped more than the roll window
        // before the marker means the marker is not the first one: an
        // earlier marker was deleted and a later boot wrote this one, and
        // every v1 row between them would otherwise pass as "before".
        if let (true, Some(m), Some(mus)) = (row.is_v2(), marker_idx, marker_us) {
            if i < m && mus - row.ts_us > ROLL_WINDOW_SECS * 1_000_000 && (by_current || by_retired) {
                r.breaks.push(brk(
                    "hashed v2 more than the roll window before the hash-v2 marker: the first marker \
                     was deleted (or the gateway failed to write it at the switch — \
                     audit_hash_v2_marker_failed in its log), so v1 rows after the real switch \
                     cannot be told from rows before it"
                        .into(),
                ));
                continue;
            }
        }
        // A v1 row after the marker: its time is not signed. Fails, except
        // an old-image (v0.2.82) Python writer still running during the roll.
        let v1_after_marker = !row.is_v2() && marker_idx.is_some_and(|m| i > m);
        if v1_after_marker && by_current {
            if marker_us.is_some_and(|mus| row.in_v1_roll_window(mus)) {
                r.v1_roll_window_rows += 1;
                *v1_roll_window.entry(row.actor.clone()).or_default() += 1;
            } else {
                r.breaks.push(brk(
                    "hashed v1 after the hash-v2 marker: a v1 hash does not cover the row's time or \
                     id, so this row could be re-timed or copied — no current writer signs v1"
                        .into(),
                ));
            }
            continue;
        }

        if Some(i) == cp_idx {
            let c = cp.as_ref().expect("cp_idx implies cp");
            // The checkpoint's `at` is signed; its row time must agree, or the
            // row was moved (a v1 checkpoint cannot sign its own timestamp).
            if (row.ts_us.div_euclid(1_000_000) - c.at).abs() > CHECKPOINT_AT_SKEW_SECS {
                r.breaks.push(brk(format!(
                    "checkpoint: its row time is not the `at:{}` it signed — the row was moved",
                    c.at
                )));
            }
            r.checkpoint = Some(CheckpointView {
                id: row.id.clone(),
                timestamp: row.timestamp.clone(),
                checkpoint: c.clone(),
                genesis: c.genesis(),
            });
            let signed = if c.genesis() {
                Some(by_current)
            } else if retired.is_some() {
                Some(by_retired)
            } else {
                None
            };
            match signed {
                Some(true) => r.ok += 1,
                Some(false) => r.breaks.push(brk(
                    "checkpoint: its signature does not verify under the key it hands over from".into(),
                )),
                None => {
                    r.unverifiable += 1;
                    r.warnings.push(
                        "checkpoint: this gateway does not hold the retired key, so the \
                         checkpoint's own signature cannot be checked"
                            .into(),
                    );
                }
            }
            if c.genesis() {
                if r.retired_epoch_rows > 0 {
                    r.breaks.push(brk(format!(
                        "checkpoint: a genesis checkpoint (no predecessor) is preceded by {} row(s) \
                         signed under the retired key",
                        r.retired_epoch_rows
                    )));
                }
            } else if retired.is_some() {
                match (&c.after, &last_retired_hash) {
                    (Some(a), Some(l)) if a == l => {}
                    (Some(_), None) => r.warnings.push(
                        "checkpoint: the row it names as the last retired-key row is no longer in \
                         the table (partition retention?) — the link was not checked"
                            .into(),
                    ),
                    (a, l) => r.breaks.push(brk(format!(
                        "checkpoint link: it names after={} but the last row signed under the \
                         retired key before it is {}",
                        a.as_deref().unwrap_or("none"),
                        l.as_deref().unwrap_or("none")
                    ))),
                }
            }
            continue;
        }

        let after_checkpoint = cp_idx.is_some_and(|c| i > c);
        if after_checkpoint {
            if by_current {
                r.ok += 1;
                r.current_epoch_rows += 1;
            } else if by_retired
                && cp.as_ref().is_some_and(|c| row.in_roll_window(c.at))
            {
                r.roll_window_rows += 1;
                *roll_window.entry(row.actor.clone()).or_default() += 1;
            } else if by_public
                || keys.retired.as_deref().is_some_and(|k| row.signed_by(k))
            {
                r.breaks.push(brk(
                    "signed with the RETIRED key after the checkpoint — whoever wrote it holds \
                     NOO_JWT_SECRET, not the audit key"
                        .into(),
                ));
            } else {
                r.breaks.push(brk("tampered: entry_hash does not verify under the audit key".into()));
            }
        } else if by_current {
            // A writer that already had the new key while the gateway had not
            // yet written the checkpoint (the roll). The new key is trusted
            // everywhere; only the retired one is confined to its epoch.
            r.ok += 1;
            r.current_epoch_rows += 1;
        } else if by_retired {
            r.ok += 1;
            r.retired_epoch_rows += 1;
            last_retired_hash = Some(hash);
        } else if by_public {
            r.public_fallback += 1;
        } else if retired.is_none() {
            r.unverifiable += 1;
        } else {
            r.breaks.push(brk("tampered: entry_hash does not verify under the retired key".into()));
            // The link is over STORED hashes: an edited row keeps its hash,
            // so it is still the row the checkpoint named. It has already
            // failed on its own line; it must not fail the link as well.
            last_retired_hash = Some(hash);
        }
    }

    if !r.key_present {
        r.problems.push(format!(
            "{KEY_ENV} is not set: every new audit row is being REFUSED — run \
             `noo upgrade --stack`, which mints it when absent and recreates the stack"
        ));
    } else if cp_idx.is_none()
        && r.retired_epoch_rows + r.public_fallback + r.unverifiable > 0
    {
        r.problems.push(
            "checkpoint missing: rows not signed with the audit key exist and no \
             audit_key_checkpoint row hands the log over to it — restart the gateway, \
             which writes one on boot"
                .into(),
        );
    }
    if marker_idx.is_none() && r.key_present && r.v1_rows > 0 && r.v2_rows > 0 {
        r.problems.push(
            "hash-v2 marker missing: rows hashed v1 and v2 both exist and no audit_hash_v2 row \
             marks where v1 stopped — restart the gateway, which writes one on boot (if a marker \
             was deleted, the rows it hid are then reported)"
                .into(),
        );
    }
    for (actor, rows) in v1_roll_window {
        r.warnings.push(format!(
            "{rows} row(s) written by {actor} during the roll window, hashed v1 (time not covered) \
             after the hash-v2 marker (an old-image container still running)"
        ));
        r.v1_roll_window.push(RollWindowWriter { actor, rows });
    }
    for (actor, rows) in roll_window {
        r.warnings.push(format!(
            "{rows} row(s) written by {actor} during the roll window, signed with the retired key \
             (an old-image container still running)"
        ));
        r.roll_window.push(RollWindowWriter { actor, rows });
    }
    if r.public_fallback > 0 {
        r.warnings.push(format!(
            "{} row(s) before the checkpoint were signed with the public fallback literal \
             (a writer that could not read NOO_JWT_SECRET): not tampered, but not evidence either",
            r.public_fallback
        ));
    }
    r.verdict = if r.breaks.is_empty() && r.problems.is_empty() { "ok" } else { "fail" }.into();
    r
}

/// [`verify_rows`] plus the hash chain ([`crate::audit_chain::verify`]): the
/// whole verdict `GET /api/security/audit/verify` serves. Kept apart so the
/// per-row rules stay testable on rows that carry no chain.
pub fn verify_all(rows: &[AuditRow], keys: &Keys) -> Report {
    let mut r = verify_rows(rows, keys);
    crate::audit_chain::verify(rows, keys.current.as_deref(), &mut r);
    r.verdict = if r.breaks.is_empty() && r.problems.is_empty() { "ok" } else { "fail" }.into();
    r
}

// ── Database side ────────────────────────────────────────────────────────────

type RowTuple = crate::repo::audit::VerifyRow;

fn to_row(t: RowTuple) -> AuditRow {
    AuditRow {
        id: t.0,
        timestamp: t.1.to_rfc3339(),
        ts_us: t.1.timestamp_micros(),
        event_type: t.2,
        severity: t.3,
        actor: t.4,
        resource: t.5,
        outcome: t.6,
        request_id: t.7,
        entry_hash: t.8,
        details: t.9,
        prev_hash: t.10,
        chain_seq: t.11,
        chain_hash: t.12,
    }
}

/// `details::text` is Postgres's jsonb rendering — the text the v2 writer
/// hashed, because it asked Postgres for exactly that before signing.
const SELECT_ROWS: &str = crate::repo::audit::SELECT_ROWS;

/// Read the whole table and judge it with the keys this process holds.
pub async fn verify_db(db: &sqlx::PgPool) -> Result<Report, sqlx::Error> {
    let rows: Vec<RowTuple> = crate::repo::audit::all_for_verify(db).await?;
    let rows: Vec<AuditRow> = rows.into_iter().map(to_row).collect();
    let keys = Keys { current: current_key(), retired: retired_key() };
    let mut report = verify_all(&rows, &keys);
    // The chain head against the copy kept outside the database: truncation
    // of the newest rows is invisible to the table itself.
    let file = crate::audit_head_export::head_file();
    crate::audit_head_export::check(&file, crate::audit_head_export::read_file(&file), keys.current.as_deref(), &rows, &mut report);
    report.verdict = if report.breaks.is_empty() && report.problems.is_empty() { "ok" } else { "fail" }.into();
    Ok(report)
}

/// What boot did about the checkpoint — logged, and returned for the tests.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CheckpointOutcome {
    /// No `NOO_AUDIT_HMAC_KEY`: nothing written, every audit row refused.
    KeyMissing,
    /// A checkpoint for this key already exists.
    AlreadyPresent,
    /// Wrote the hand-over row, signed under the retired derivation.
    Handover { after: String },
    /// No retired-key rows: wrote a genesis row, signed under the new key.
    Genesis,
    Failed(String),
}

/// Boot hook: append the checkpoint for the key this gateway holds, once.
pub async fn ensure_checkpoint(db: &sqlx::PgPool) -> CheckpointOutcome {
    let out = ensure_checkpoint_with(db, current_key(), retired_key()).await;
    match &out {
        CheckpointOutcome::KeyMissing => tracing::error!(
            "audit_key_missing: {KEY_ENV} is not set — every security audit row will be REFUSED \
             (there is no fallback key any more). Run `noo upgrade --stack`, which mints it when \
             absent and recreates the stack"
        ),
        CheckpointOutcome::AlreadyPresent => tracing::info!("audit_key_checkpoint_present"),
        CheckpointOutcome::Handover { after } => tracing::warn!(
            after = %after,
            "audit_key_checkpoint_written: the audit log now signs with {KEY_ENV}; rows before this \
             checkpoint stay verifiable under the retired NOO_JWT_SECRET derivation"
        ),
        CheckpointOutcome::Genesis => tracing::info!("audit_key_checkpoint_genesis_written"),
        CheckpointOutcome::Failed(e) => tracing::error!(
            error = %e,
            "audit_key_checkpoint_failed: `noo security audit verify` will report the checkpoint missing"
        ),
    }
    out
}

pub(crate) async fn ensure_checkpoint_with(
    db: &sqlx::PgPool,
    current: Option<Vec<u8>>,
    retired: Option<Vec<u8>>,
) -> CheckpointOutcome {
    use futures::TryStreamExt;

    let Some(current) = current else { return CheckpointOutcome::KeyMissing };
    let fp = fingerprint(&current);
    let present = crate::repo::audit::count_event_resource_like(
        db,
        CHECKPOINT_EVENT,
        &format!("audit-key:{fp};%"),
    )
    .await;
    match present {
        Ok(n) if n > 0 => return CheckpointOutcome::AlreadyPresent,
        Ok(_) => {}
        Err(e) => return CheckpointOutcome::Failed(e.to_string()),
    }

    // Newest first, stopping at the first row the retired key signed. On an
    // install mid-switch that is the first row read; only an install with no
    // retired-key rows at all reads the whole table, once.
    let mut last_retired: Option<AuditRow> = None;
    if let Some(retired) = retired.as_deref() {
        let sql = format!(
            "{SELECT_ROWS} WHERE entry_hash IS NOT NULL ORDER BY \"timestamp\" DESC, id DESC"
        );
        let mut stream = sqlx::query_as::<_, RowTuple>(sqlx::AssertSqlSafe(&*sql)).fetch(db);
        loop {
            match stream.try_next().await {
                Ok(Some(t)) => {
                    let row = to_row(t);
                    if row.signed_by(retired) && !row.signed_by(&current) {
                        last_retired = Some(row);
                        break;
                    }
                }
                Ok(None) => break,
                Err(e) => return CheckpointOutcome::Failed(e.to_string()),
            }
        }
    }

    let at = chrono::Utc::now().timestamp();
    let (cp, signing_key, outcome) = match (&last_retired, retired.as_deref()) {
        (Some(row), Some(rk)) => (
            Checkpoint {
                new_fingerprint: fp.clone(),
                after: row.entry_hash.clone(),
                at,
                from: Some(fingerprint(rk)),
            },
            rk.to_vec(),
            CheckpointOutcome::Handover { after: row.entry_hash.clone().unwrap_or_default() },
        ),
        _ => (
            Checkpoint { new_fingerprint: fp.clone(), after: None, at, from: None },
            current.clone(),
            CheckpointOutcome::Genesis,
        ),
    };
    let (severity, actor) = ("info", "noo-gateway");
    let resource = cp.resource();
    let outcome_field = cp.outcome();
    let details = serde_json::json!({
        "what": "the audit log's signing key changed; rows after this one are signed with NOO_AUDIT_HMAC_KEY",
        "signed_with": if cp.genesis() { "NOO_AUDIT_HMAC_KEY (genesis: no earlier key signed any row)" }
                       else { "the retired NOO_JWT_SECRET derivation (verify-only from here on)" },
        "after_row_id": last_retired.as_ref().map(|r| r.id.clone()),
    })
    .to_string();
    let written = crate::audit::write_audit_row(
        db,
        &signing_key,
        CHECKPOINT_EVENT,
        severity,
        actor,
        &resource,
        &outcome_field,
        &details,
        cp.after.as_deref(),
    )
    .await;
    if written { outcome } else { CheckpointOutcome::Failed("insert failed (logged above)".into()) }
}

/// What boot did about the hash-v2 marker.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum MarkerOutcome {
    KeyMissing,
    AlreadyPresent,
    /// Wrote it; `after_v1` says whether v1 rows precede it.
    Written { after_v1: bool },
    /// No v1 rows remain and v2 rows older than the roll window exist: the
    /// marker went with partition retention, and there is nothing left for
    /// it to separate. Writing one now would stamp it after those rows.
    NotNeeded,
    Failed(String),
}

/// Boot hook, after [`ensure_checkpoint`]: append the hash-v2 marker once.
pub async fn ensure_hash_v2_marker(db: &sqlx::PgPool) -> MarkerOutcome {
    let out = ensure_hash_v2_marker_with(db, current_key()).await;
    match &out {
        MarkerOutcome::KeyMissing => {} // ensure_checkpoint already said so, at error
        MarkerOutcome::AlreadyPresent => tracing::info!("audit_hash_v2_marker_present"),
        MarkerOutcome::Written { after_v1 } => tracing::info!(
            after_v1,
            "audit_hash_v2_marker_written: audit rows are hashed v2 (time, id and details covered) \
             from here on; a v1 row after this marker fails `noo security audit verify`"
        ),
        MarkerOutcome::NotNeeded => {
            tracing::info!("audit_hash_v2_marker_not_needed: no v1 rows remain")
        }
        MarkerOutcome::Failed(e) => tracing::error!(
            error = %e,
            "audit_hash_v2_marker_failed: `noo security audit verify` will report the marker missing"
        ),
    }
    out
}

pub(crate) async fn ensure_hash_v2_marker_with(
    db: &sqlx::PgPool,
    current: Option<Vec<u8>>,
) -> MarkerOutcome {
    let Some(current) = current else { return MarkerOutcome::KeyMissing };
    let existing: Vec<RowTuple> =
        match sqlx::query_as(sqlx::AssertSqlSafe(format!("{SELECT_ROWS} WHERE event_type = $1")))
            .bind(HASH_V2_MARKER_EVENT)
            .fetch_all(db)
            .await
        {
            Ok(r) => r,
            Err(e) => return MarkerOutcome::Failed(e.to_string()),
        };
    if existing.into_iter().map(to_row).any(|r| r.is_hash_v2_marker(&current)) {
        return MarkerOutcome::AlreadyPresent;
    }
    let probe = sqlx::query_as::<_, (bool, bool)>(
        "SELECT \
           EXISTS (SELECT 1 FROM noo_security_audit \
                    WHERE entry_hash IS NOT NULL AND entry_hash NOT LIKE 'v2:%'), \
           EXISTS (SELECT 1 FROM noo_security_audit \
                    WHERE entry_hash LIKE 'v2:%' \
                      AND \"timestamp\" < now() - make_interval(secs => $1))",
    )
    .bind(ROLL_WINDOW_SECS as f64)
    .fetch_one(db)
    .await;
    let (has_v1, old_v2) = match probe {
        Ok(p) => p,
        Err(e) => return MarkerOutcome::Failed(e.to_string()),
    };
    if !has_v1 && old_v2 {
        return MarkerOutcome::NotNeeded;
    }
    let details = serde_json::json!({
        "what": "audit rows are hashed v2 from here on: the hash covers the row's time, id, details \
                 and prev_hash as well; a v1 row after this one fails verification",
    })
    .to_string();
    let written = crate::audit::write_audit_row(
        db,
        &current,
        HASH_V2_MARKER_EVENT,
        "info",
        "noo-gateway",
        HASH_V2_MARKER_RESOURCE,
        if has_v1 { "from:v1" } else { "from:none" },
        &details,
        None,
    )
    .await;
    if written {
        MarkerOutcome::Written { after_v1: has_v1 }
    } else {
        MarkerOutcome::Failed("insert failed (logged above)".into())
    }
}

#[cfg(test)]
mod tests {

    /// A gateway with no audit key refuses to boot (it used to serve with
    /// every audit row refused). `key_from` has no test-build arm, so this
    /// exercises the real decision.
    #[test]
    fn a_missing_or_blank_audit_key_is_a_boot_refusal() {
        for lookup in [None, Some(String::new())] {
            let l = lookup.clone();
            let r = boot_refusal_from(&move |_| l.clone());
            let msg = r.expect("no key must refuse");
            assert!(msg.contains("NOO_AUDIT_HMAC_KEY") && msg.contains("noo upgrade --stack"), "{msg}");
        }
        assert!(boot_refusal_from(&|_| Some("k".into())).is_none());
    }
    use super::*;

    const NEW: &[u8] = b"a-dedicated-audit-key-32-bytes!!";
    /// The test checkpoint's signed `at`.
    const CP_AT: i64 = 1_790_000_000;

    fn retired() -> Vec<u8> {
        retired_key_from("the-login-secret")
    }

    fn row(id: &str, et: &str, resource: &str, outcome: &str, key: &[u8]) -> AuditRow {
        let mut r = AuditRow {
            id: id.into(),
            timestamp: format!("t{id}"),
            // The checkpoint's `at`: a checkpoint row's time must match it.
            ts_us: CP_AT * 1_000_000,
            event_type: et.into(),
            severity: "info".into(),
            actor: "alice".into(),
            resource: resource.into(),
            outcome: outcome.into(),
            request_id: None,
            details: Some(r#"{"source_ip": "10.0.0.7"}"#.into()),
            prev_hash: None,
            entry_hash: None,
            chain_seq: None,
            chain_hash: None,
        };
        r.entry_hash = Some(r.hash_under(key)); // no hash yet → the v1 form
        r
    }

    fn checkpoint_row(id: &str, after: Option<&str>, from: &[u8]) -> AuditRow {
        let cp = Checkpoint {
            new_fingerprint: fingerprint(NEW),
            after: after.map(str::to_string),
            at: CP_AT,
            from: Some(fingerprint(from)),
        };
        row(id, CHECKPOINT_EVENT, &cp.resource(), &cp.outcome(), from)
    }

    /// Two rows under the retired key, the checkpoint, two under the new one.
    fn chain() -> Vec<AuditRow> {
        let r1 = row("01", "auth_success", "gateway", "ok", &retired());
        let r2 = row("02", "auth_failure", "gateway", "bad_password", &retired());
        let cp = checkpoint_row("03", r2.entry_hash.as_deref(), &retired());
        let r4 = row("04", "admin_action", "config", "ok", NEW);
        let r5 = row("05", "auth_success", "gateway", "ok", NEW);
        vec![r1, r2, cp, r4, r5]
    }

    fn both() -> Keys {
        Keys { current: Some(NEW.to_vec()), retired: Some(retired()) }
    }

    #[test]
    fn a_chain_across_the_checkpoint_verifies() {
        let r = verify_rows(&chain(), &both());
        assert_eq!(r.verdict, "ok", "{r:?}");
        assert_eq!((r.retired_epoch_rows, r.current_epoch_rows, r.ok), (2, 2, 5));
        let cp = r.checkpoint.expect("checkpoint found");
        assert_eq!(cp.id, "03");
        assert!(!cp.genesis);
    }

    #[test]
    fn a_tampered_row_before_the_checkpoint_fails_by_name() {
        let mut rows = chain();
        rows[0].actor = "mallory".into();
        let r = verify_rows(&rows, &both());
        assert_eq!(r.verdict, "fail");
        assert_eq!(r.breaks.len(), 1, "{r:?}");
        assert_eq!(r.breaks[0].id, "01");
        assert!(r.breaks[0].reason.contains("tampered"));
        // The row the checkpoint names, edited: one break, on the row — the
        // link is over stored hashes and still holds.
        let mut rows = chain();
        rows[1].actor = "mallory".into();
        let r = verify_rows(&rows, &both());
        assert_eq!(r.breaks.len(), 1, "{r:?}");
        assert_eq!(r.breaks[0].id, "02");
    }

    #[test]
    fn a_tampered_row_after_the_checkpoint_fails_by_name() {
        let mut rows = chain();
        rows[3].outcome = "denied".into();
        let r = verify_rows(&rows, &both());
        assert_eq!(r.verdict, "fail");
        assert_eq!(r.breaks.len(), 1, "{r:?}");
        assert_eq!(r.breaks[0].id, "04");
    }

    #[test]
    fn a_row_resigned_with_the_login_secret_after_the_checkpoint_is_a_forgery() {
        // The whole point of the new key: holding NOO_JWT_SECRET no longer
        // lets you write a row that verifies.
        let mut rows = chain();
        rows[4] = row("05", "auth_success", "gateway", "ok", &retired());
        let r = verify_rows(&rows, &both());
        assert_eq!(r.verdict, "fail");
        assert!(r.breaks[0].reason.contains("RETIRED key after the checkpoint"), "{r:?}");
        // …and so is a row signed with the public literal.
        rows[4] = row("05", "auth_success", "gateway", "ok", &public_fallback_key());
        assert_eq!(verify_rows(&rows, &both()).verdict, "fail");
    }

    /// A row by `actor`, stamped `secs` after the checkpoint's `at`.
    fn stamped(id: &str, actor: &str, et: &str, key: &[u8], secs: i64) -> AuditRow {
        let mut r = row(id, et, "gateway", "ok", key);
        r.actor = actor.into();
        r.entry_hash = Some(r.hash_under(key));
        r.timestamp = chrono::DateTime::from_timestamp(CP_AT + secs, 0)
            .expect("in range")
            .to_rfc3339();
        r.ts_us = (CP_AT + secs) * 1_000_000;
        r
    }

    /// `extra` placed right after the checkpoint in `chain()`.
    fn chain_with(extra: Vec<AuditRow>) -> Vec<AuditRow> {
        let mut rows = chain();
        for (n, r) in extra.into_iter().enumerate() {
            rows.insert(3 + n, r);
        }
        rows
    }

    #[test]
    fn an_old_worker_row_inside_the_roll_window_is_a_warning_naming_it() {
        // a v0.2.81 worker still running when the new gateway
        // wrote the checkpoint signs its startup marker with the retired key.
        let rows = chain_with(vec![stamped(
            "03a", "worker_pool", "audit_logger_started", &retired(), 2 * 60,
        )]);
        let r = verify_rows(&rows, &both());
        assert_eq!(r.verdict, "ok", "{r:?}");
        assert!(r.breaks.is_empty(), "{r:?}");
        assert_eq!(r.roll_window_rows, 1);
        assert_eq!(r.roll_window, vec![RollWindowWriter { actor: "worker_pool".into(), rows: 1 }]);
        assert!(
            r.warnings.iter().any(|w| w
                == "1 row(s) written by worker_pool during the roll window, signed with the retired \
                    key (an old-image container still running)"),
            "{:?}",
            r.warnings
        );
        // Counted per writer, the window's last second included.
        let rows = chain_with(vec![
            stamped("03a", "worker_pool", "audit_logger_started", &retired(), 0),
            stamped("03b", "bus", "bus_principal_refused", &retired(), 60),
            stamped("03c", "bus", "bus_principal_refused", &retired(), ROLL_WINDOW_SECS),
        ]);
        let r = verify_rows(&rows, &both());
        assert_eq!(r.verdict, "ok", "{r:?}");
        assert_eq!(r.roll_window_rows, 3);
        assert_eq!(
            r.roll_window,
            vec![
                RollWindowWriter { actor: "bus".into(), rows: 2 },
                RollWindowWriter { actor: "worker_pool".into(), rows: 1 },
            ]
        );
    }

    #[test]
    fn an_old_worker_row_after_the_roll_window_is_still_a_forgery() {
        let rows = chain_with(vec![stamped(
            "03a", "worker_pool", "audit_logger_started", &retired(), 40 * 60,
        )]);
        let r = verify_rows(&rows, &both());
        assert_eq!(r.verdict, "fail", "{r:?}");
        assert_eq!(r.roll_window_rows, 0);
        assert_eq!(r.breaks.len(), 1, "{r:?}");
        assert_eq!(r.breaks[0].id, "03a");
        assert!(r.breaks[0].reason.contains("RETIRED key after the checkpoint"), "{r:?}");
        // One second past the window is past it.
        let rows = chain_with(vec![stamped(
            "03a", "worker_pool", "audit_logger_started", &retired(), ROLL_WINDOW_SECS + 1,
        )]);
        assert_eq!(verify_rows(&rows, &both()).verdict, "fail");
    }

    #[test]
    fn a_retired_key_row_in_the_window_from_any_other_writer_is_a_forgery() {
        // The gateway itself never signs with the retired key after the
        // checkpoint, whatever the time.
        for (actor, event) in [
            ("noo-gateway", "auth_success"),
            ("alice", "admin_action"),
            // The right actor saying something its writer never says.
            ("worker_pool", "admin_action"),
            ("bus", "auth_success"),
        ] {
            let rows = chain_with(vec![stamped("03a", actor, event, &retired(), 2 * 60)]);
            let r = verify_rows(&rows, &both());
            assert_eq!(r.verdict, "fail", "{actor}/{event}: {r:?}");
            assert_eq!(r.roll_window_rows, 0);
            assert!(r.breaks[0].reason.contains("RETIRED key after the checkpoint"), "{r:?}");
        }
        // …and the public literal is not the retired key.
        let rows = chain_with(vec![stamped(
            "03a", "worker_pool", "audit_logger_started", &public_fallback_key(), 2 * 60,
        )]);
        assert_eq!(verify_rows(&rows, &both()).verdict, "fail");
    }

    #[test]
    fn a_tampered_row_in_the_window_is_still_tampered() {
        let mut w = stamped("03a", "worker_pool", "audit_logger_started", &retired(), 2 * 60);
        w.outcome = "denied".into();
        let r = verify_rows(&chain_with(vec![w]), &both());
        assert_eq!(r.verdict, "fail", "{r:?}");
        assert_eq!(r.roll_window_rows, 0);
        assert_eq!(r.breaks[0].id, "03a");
        assert!(r.breaks[0].reason.contains("tampered"), "{r:?}");
    }

    #[test]
    fn without_the_checkpoint_the_chain_fails() {
        let mut rows = chain();
        rows.remove(2);
        let r = verify_rows(&rows, &both());
        assert_eq!(r.verdict, "fail");
        assert!(r.problems[0].contains("checkpoint missing"), "{r:?}");
    }

    #[test]
    fn a_checkpoint_not_signed_by_the_retired_key_fails() {
        let mut rows = chain();
        let after = rows[1].entry_hash.clone();
        rows[2] = checkpoint_row("03", after.as_deref(), &retired());
        // Re-sign with the NEW key: a checkpoint someone minted without the old one.
        rows[2].entry_hash = Some(rows[2].hash_under(NEW));
        let r = verify_rows(&rows, &both());
        assert_eq!(r.verdict, "fail");
        assert!(r.breaks.iter().any(|b| b.id == "03"), "{r:?}");
    }

    #[test]
    fn a_deleted_last_retired_row_breaks_the_link() {
        let mut rows = chain();
        rows.remove(1); // the row the checkpoint names
        let r = verify_rows(&rows, &both());
        assert_eq!(r.verdict, "fail");
        assert!(r.breaks.iter().any(|b| b.reason.contains("checkpoint link")), "{r:?}");
    }

    #[test]
    fn a_missing_key_is_a_failure_not_a_fallback() {
        let r = verify_rows(&chain(), &Keys { current: None, retired: Some(retired()) });
        assert_eq!(r.verdict, "fail");
        assert!(!r.key_present);
        assert!(r.problems[0].contains("REFUSED"), "{r:?}");
    }

    #[test]
    fn a_rotated_login_secret_makes_the_old_epoch_unverifiable_not_tampered() {
        let keys = Keys { current: Some(NEW.to_vec()), retired: Some(retired_key_from("rotated")) };
        let r = verify_rows(&chain(), &keys);
        assert!(r.breaks.is_empty(), "{r:?}");
        assert_eq!(r.unverifiable, 3); // two rows + the checkpoint's own signature
        assert_eq!(r.current_epoch_rows, 2);
        assert!(!r.warnings.is_empty());
    }

    #[test]
    fn a_genesis_install_verifies_and_rejects_backdated_retired_rows() {
        let cp = Checkpoint { new_fingerprint: fingerprint(NEW), after: None, at: 1, from: None };
        let mut g = row("01", CHECKPOINT_EVENT, &cp.resource(), &cp.outcome(), NEW);
        g.ts_us = 1_000_000;
        g.entry_hash = Some(g.hash_under(NEW));
        let r2 = row("02", "auth_success", "gateway", "ok", NEW);
        let r = verify_rows(&[g.clone(), r2.clone()], &both());
        assert_eq!(r.verdict, "ok", "{r:?}");
        assert!(r.checkpoint.unwrap().genesis);
        let forged = row("00", "auth_success", "gateway", "ok", &retired());
        assert_eq!(verify_rows(&[forged, g, r2], &both()).verdict, "fail");
    }

    #[test]
    fn early_new_key_rows_before_the_checkpoint_are_accepted() {
        // The roll: a worker restarted with the key writes before the
        // gateway has written the checkpoint.
        let mut rows = chain();
        rows.insert(2, row("02b", "audit_logger_started", "gateway", "ok", NEW));
        assert_eq!(verify_rows(&rows, &both()).verdict, "ok");
    }

    #[test]
    fn the_checkpoint_round_trips_and_fits_the_columns() {
        let cp = Checkpoint {
            new_fingerprint: fingerprint(NEW),
            after: Some("f".repeat(64)),
            at: 1_790_000_000,
            from: Some(fingerprint(&retired())),
        };
        let r = row("x", CHECKPOINT_EVENT, &cp.resource(), &cp.outcome(), NEW);
        assert_eq!(Checkpoint::parse(&r), Some(cp.clone()));
        // resource varchar(512), outcome varchar(64) (0001_baseline.sql).
        assert!(cp.resource().len() <= 512 && cp.outcome().len() <= 64);
        assert_eq!(fingerprint(NEW).len(), 32);
        assert_ne!(fingerprint(NEW), fingerprint(&retired()));
    }

    #[test]
    fn the_retired_derivation_is_the_one_that_signed_the_old_rows() {
        // Frozen: sha256("audit-hmac:" + seed), the derivation both writers
        // used before this change. If it drifts, every historical row reads
        // as tampered.
        let k = retired_key_from("audit-integrity-fallback");
        assert_eq!(k, public_fallback_key());
        assert_eq!(
            hex::encode(&k),
            hex::encode(Sha256::digest(b"audit-hmac:audit-integrity-fallback"))
        );
    }

    // ── Hash v2 ──────────────────────────────────────────

    /// The marker's distance after the key checkpoint in [`v2_chain`]: an
    /// install that rolled to v0.2.82 an hour before rolling to v0.2.83.
    const MARKER_AT: i64 = 3600;

    fn at(r: &mut AuditRow, secs: i64) {
        r.ts_us = (CP_AT + secs) * 1_000_000;
        r.timestamp = chrono::DateTime::from_timestamp(CP_AT + secs, 0).expect("in range").to_rfc3339();
    }

    fn sign_v2(r: &mut AuditRow, key: &[u8]) {
        r.entry_hash = Some(row_hash_v2(key, &r.v2_fields()));
    }

    /// A row as a v0.2.83 writer makes it: hashed v2, `secs` after CP_AT.
    fn v2_row(id: &str, et: &str, actor: &str, key: &[u8], secs: i64) -> AuditRow {
        let mut r = row(id, et, "gateway", "ok", key);
        r.actor = actor.into();
        r.request_id = Some(format!("req{id}"));
        at(&mut r, secs);
        sign_v2(&mut r, key);
        r
    }

    /// A v1 row under `key`, `secs` after CP_AT — as a v0.2.82 writer (audit
    /// key) or a v0.2.81 one (retired key) makes it.
    fn v1_row(id: &str, et: &str, actor: &str, key: &[u8], secs: i64) -> AuditRow {
        let mut r = row(id, et, "gateway", "ok", key);
        r.actor = actor.into();
        r.entry_hash = Some(r.hash_under(key));
        at(&mut r, secs);
        r
    }

    fn marker(id: &str, key: &[u8], secs: i64) -> AuditRow {
        let mut r = v2_row(id, HASH_V2_MARKER_EVENT, "noo-gateway", key, secs);
        r.resource = HASH_V2_MARKER_RESOURCE.into();
        r.outcome = "from:v1".into();
        r.request_id = None;
        sign_v2(&mut r, key);
        r
    }

    /// `chain()` (v1 rows on both sides of the key checkpoint), then the
    /// hash-v2 marker, then two v2 rows.
    fn v2_chain() -> Vec<AuditRow> {
        let mut rows = chain();
        rows.push(marker("06", NEW, MARKER_AT));
        rows.push(v2_row("07", "auth_success", "alice", NEW, MARKER_AT + 1));
        rows.push(v2_row("08", "bus_principal_refused", "bus", NEW, MARKER_AT + 2));
        rows
    }

    /// `extra` placed right after the marker in `v2_chain()`.
    fn v2_chain_with(extra: Vec<AuditRow>) -> Vec<AuditRow> {
        let mut rows = v2_chain();
        for (n, r) in extra.into_iter().enumerate() {
            rows.insert(6 + n, r);
        }
        rows
    }

    #[test]
    fn the_shared_v2_vectors_match_the_python_writer() {
        // tests/fixtures/audit_hash_v2_vectors.json is asserted, field for
        // field, by tests/test_audit_integrity.py against the real Python
        // functions and the real Python writer. Both reproduce it, so both
        // hash the same row to the same digest.
        const VECTORS: &str = include_str!("../../tests/fixtures/audit_hash_v2_vectors.json");
        let doc: serde_json::Value = serde_json::from_str(VECTORS).expect("vectors parse");
        let key = doc["key"].as_str().expect("key").as_bytes();
        let vectors = doc["vectors"].as_array().expect("vectors");
        assert!(vectors.len() >= 3, "the fixture lost its vectors");
        for v in vectors {
            let r = &v["row"];
            let s = |k: &str| r[k].as_str().unwrap_or_else(|| panic!("{k} missing"));
            let o = |k: &str| r[k].as_str();
            let row = RowV2 {
                id: s("id"),
                ts_us: r["timestamp_us"].as_i64().expect("timestamp_us"),
                event_type: s("event_type"),
                severity: s("severity"),
                actor: s("actor"),
                resource: s("resource"),
                outcome: s("outcome"),
                request_id: o("request_id"),
                details: o("details"),
                prev_hash: o("prev_hash"),
            };
            let name = v["name"].as_str().unwrap_or("?");
            assert_eq!(canonical_v2(&row), v["canonical"].as_str().unwrap(), "{name}: canonical");
            assert_eq!(row_hash_v2(key, &row), v["entry_hash"].as_str().unwrap(), "{name}: entry_hash");
        }
    }

    #[test]
    fn a_v2_chain_verifies_and_names_its_marker() {
        let r = verify_rows(&v2_chain(), &both());
        assert_eq!(r.verdict, "ok", "{r:?}");
        assert_eq!((r.v1_rows, r.v2_rows), (5, 3));
        assert_eq!(r.hash_v2_marker.as_ref().map(|m| m.id.as_str()), Some("06"));
        assert_eq!(r.ok, 8);
    }

    #[test]
    fn a_v2_row_with_its_timestamp_altered_is_tampered() {
        // The finding: v1 never covered the time. v2 does — by one microsecond.
        for delta_us in [1, -1, 3_600_000_000, -86_400_000_000] {
            let mut rows = v2_chain();
            rows[6].ts_us += delta_us;
            let r = verify_rows(&rows, &both());
            assert_eq!(r.verdict, "fail", "re-timed by {delta_us}µs: {r:?}");
            assert_eq!(r.breaks.len(), 1, "{r:?}");
            assert_eq!(r.breaks[0].id, "07");
            assert!(r.breaks[0].reason.contains("tampered"), "{r:?}");
        }
    }

    #[test]
    fn every_other_column_of_a_v2_row_is_covered() {
        type Edit = fn(&mut AuditRow);
        let edits: [(&str, Edit); 10] = [
            ("id", |r| r.id = "07-copy".into()),
            ("event_type", |r| r.event_type = "auth_failure".into()),
            ("severity", |r| r.severity = "critical".into()),
            ("actor", |r| r.actor = "mallory".into()),
            ("resource", |r| r.resource = "config".into()),
            ("outcome", |r| r.outcome = "denied".into()),
            ("request_id", |r| r.request_id = None),
            ("details (source_ip)", |r| r.details = Some(r#"{"source_ip": "203.0.113.9"}"#.into())),
            ("details NULL", |r| r.details = None),
            ("prev_hash", |r| r.prev_hash = Some("ab".repeat(32))),
        ];
        for (column, edit) in edits {
            let mut rows = v2_chain();
            edit(&mut rows[6]);
            let r = verify_rows(&rows, &both());
            assert_eq!(r.verdict, "fail", "{column} edited and the row still verifies: {r:?}");
            assert!(r.breaks.iter().any(|b| b.reason.contains("tampered")), "{column}: {r:?}");
        }
        // NULL is not "": a request_id emptied is a different row.
        let mut rows = v2_chain();
        rows[6].request_id = Some(String::new());
        assert_eq!(verify_rows(&rows, &both()).verdict, "fail");
    }

    #[test]
    fn a_v1_row_before_the_marker_is_ok() {
        // chain()'s rows 04 and 05 are v1 under the audit key (v0.2.82
        // writers); 01 and 02 v1 under the retired key. All precede the marker.
        let r = verify_rows(&v2_chain(), &both());
        assert_eq!(r.verdict, "ok", "{r:?}");
        assert!(r.breaks.is_empty());
        assert_eq!(r.v1_roll_window_rows, 0);
        // A v1 row just before the marker, too.
        let mut rows = v2_chain();
        rows.insert(5, v1_row("05b", "admin_action", "alice", NEW, MARKER_AT - 1));
        assert_eq!(verify_rows(&rows, &both()).verdict, "ok");
    }

    #[test]
    fn a_v1_row_after_the_marker_outside_the_roll_window_fails() {
        // Any writer, past the window: no current writer signs v1.
        for (actor, event) in [("alice", "admin_action"), ("worker_pool", "audit_logger_started")] {
            let rows = v2_chain_with(vec![v1_row(
                "06a", event, actor, NEW, MARKER_AT + ROLL_WINDOW_SECS + 1,
            )]);
            let r = verify_rows(&rows, &both());
            assert_eq!(r.verdict, "fail", "{actor}/{event}: {r:?}");
            assert_eq!(r.breaks.len(), 1, "{r:?}");
            assert_eq!(r.breaks[0].id, "06a");
            assert!(r.breaks[0].reason.contains("hashed v1 after the hash-v2 marker"), "{r:?}");
        }
        // Inside the window but not one of the fixed old-image writers: fails.
        let rows = v2_chain_with(vec![v1_row("06a", "auth_success", "alice", NEW, MARKER_AT + 60)]);
        let r = verify_rows(&rows, &both());
        assert_eq!(r.verdict, "fail", "{r:?}");
        assert!(r.breaks[0].reason.contains("hashed v1 after the hash-v2 marker"), "{r:?}");
        // A v1 copy of a pre-marker row replayed later: the attack v2 closes.
        let mut replay = v2_chain()[3].clone();
        replay.id = "06a".into();
        at(&mut replay, MARKER_AT + 5 * 3600);
        let r = verify_rows(&v2_chain_with(vec![replay]), &both());
        assert_eq!(r.verdict, "fail", "{r:?}");
    }

    #[test]
    fn a_v0_2_82_writer_in_the_roll_window_after_the_marker_is_a_warning() {
        // A v0.2.82 noo-worker still running when the v0.2.83 gateway wrote the
        // marker: v1, under the audit key, one of the fixed pairs, in the window.
        let rows = v2_chain_with(vec![
            v1_row("06a", "audit_logger_started", "worker_pool", NEW, MARKER_AT),
            v1_row("06b", "bus_principal_refused", "bus", NEW, MARKER_AT + ROLL_WINDOW_SECS),
        ]);
        let r = verify_rows(&rows, &both());
        assert_eq!(r.verdict, "ok", "{r:?}");
        assert_eq!(r.v1_roll_window_rows, 2);
        assert_eq!(
            r.v1_roll_window,
            vec![
                RollWindowWriter { actor: "bus".into(), rows: 1 },
                RollWindowWriter { actor: "worker_pool".into(), rows: 1 },
            ]
        );
        assert!(r.warnings.iter().any(|w| w.contains("hashed v1 (time not covered)")), "{:?}", r.warnings);
        // …and still tampered when edited.
        let mut w = v1_row("06a", "audit_logger_started", "worker_pool", NEW, MARKER_AT + 60);
        w.outcome = "denied".into();
        let r = verify_rows(&v2_chain_with(vec![w]), &both());
        assert_eq!(r.verdict, "fail", "{r:?}");
        assert!(r.breaks[0].reason.contains("tampered"), "{r:?}");
    }

    #[test]
    fn a_v0_2_81_writer_across_both_markers_is_still_the_checkpoint_roll_window() {
        // Straight from v0.2.81 to v0.2.83: one boot writes the key checkpoint
        // (v2, under the retired key) and then the hash-v2 marker; a v0.2.81
        // worker still running signs v1 under the RETIRED key.
        let r1 = row("01", "auth_success", "gateway", "ok", &retired());
        let r2 = row("02", "auth_failure", "gateway", "bad_password", &retired());
        let mut cp = checkpoint_row("03", r2.entry_hash.as_deref(), &retired());
        sign_v2(&mut cp, &retired());
        let rows = vec![
            r1,
            r2,
            cp,
            marker("04", NEW, 1),
            v1_row("05", "audit_logger_started", "worker_pool", &retired(), 90),
            v2_row("06", "auth_success", "alice", NEW, 120),
        ];
        let r = verify_rows(&rows, &both());
        assert_eq!(r.verdict, "ok", "{r:?}");
        assert_eq!(r.roll_window_rows, 1, "{r:?}");
        assert_eq!(r.v1_roll_window_rows, 0);
        // Another writer, or past the window: a forgery, as before.
        let mut late = rows.clone();
        late[4] = v1_row("05", "audit_logger_started", "worker_pool", &retired(), ROLL_WINDOW_SECS + 1);
        assert_eq!(verify_rows(&late, &both()).verdict, "fail");
        let mut other = rows.clone();
        other[4] = v1_row("05", "admin_action", "alice", &retired(), 90);
        assert_eq!(verify_rows(&other, &both()).verdict, "fail");
    }

    #[test]
    fn a_deleted_marker_rewritten_later_is_caught() {
        // Delete the marker, slip a replayed v1 row in after the switch, let
        // the next boot write a fresh marker after it: the v2 rows that
        // precede the new marker by more than the window give it away.
        let mut rows = v2_chain();
        rows.remove(5); // the marker
        rows.push(v1_row("09", "auth_success", "alice", NEW, MARKER_AT + 3 * 3600));
        rows.push(marker("10", NEW, MARKER_AT + 4 * 3600));
        let r = verify_rows(&rows, &both());
        assert_eq!(r.verdict, "fail", "{r:?}");
        assert!(r.breaks.iter().any(|b| b.reason.contains("first marker was deleted")), "{r:?}");
        // Deleted and not yet rewritten: v1 and v2 rows with no marker fail.
        let mut rows = v2_chain();
        rows.remove(5);
        let r = verify_rows(&rows, &both());
        assert_eq!(r.verdict, "fail", "{r:?}");
        assert!(r.problems.iter().any(|p| p.contains("hash-v2 marker missing")), "{r:?}");
        // A v2 row a moment before the marker (a v0.2.83 worker that started
        // first) is the roll, not a deletion.
        let mut rows = v2_chain();
        rows.insert(5, v2_row("05b", "audit_logger_started", "worker_pool", NEW, MARKER_AT - 30));
        assert_eq!(verify_rows(&rows, &both()).verdict, "ok");
    }

    #[test]
    fn a_marker_not_signed_with_the_audit_key_is_not_a_marker() {
        let mut rows = v2_chain();
        sign_v2(&mut rows[5], &retired());
        let r = verify_rows(&rows, &both());
        assert!(r.hash_v2_marker.is_none(), "{r:?}");
        assert_eq!(r.verdict, "fail", "{r:?}");
    }

    #[test]
    fn a_moved_checkpoint_fails() {
        // A v1 checkpoint cannot sign its own time; its signed `at` pins it.
        let mut rows = chain();
        rows[2].ts_us += 3600 * 1_000_000;
        let r = verify_rows(&rows, &both());
        assert_eq!(r.verdict, "fail", "{r:?}");
        assert!(r.breaks.iter().any(|b| b.reason.contains("the row was moved")), "{r:?}");
    }

    /// v2 hashes `details` as Postgres renders it (`$1::jsonb::text`). This
    /// asks a LIVE server to render the shared vectors' details and the
    /// fixture's `jsonb_renderings`, and compares. Runs when
    /// NOO_AUDIT_JSONB_CHECK_DSN (or CI's NOO_BROKER_TEST_DSN, the sqlx-drift
    /// job's database) names a server; the step before a Postgres MAJOR
    /// upgrade runbook points it at the new version.
    #[tokio::test]
    async fn the_v2_details_render_the_same_on_this_postgres() {
        let Some(dsn) = ["NOO_AUDIT_JSONB_CHECK_DSN", "NOO_BROKER_TEST_DSN"]
            .iter()
            .find_map(|k| std::env::var(k).ok().filter(|v| !v.is_empty()))
        else {
            return;
        };
        let db = sqlx::PgPool::connect(&dsn).await.expect("connect to the DSN under test");
        let version: String = sqlx::query_scalar("SHOW server_version").fetch_one(&db).await.unwrap();
        const VECTORS: &str = include_str!("../../tests/fixtures/audit_hash_v2_vectors.json");
        let doc: serde_json::Value = serde_json::from_str(VECTORS).expect("vectors parse");
        let mut pairs: Vec<(String, String)> = doc["vectors"]
            .as_array()
            .expect("vectors")
            .iter()
            .filter_map(|v| v["row"]["details"].as_str())
            .map(|d| (d.to_string(), d.to_string())) // stored text renders as itself
            .collect();
        for r in doc["jsonb_renderings"].as_array().expect("jsonb_renderings") {
            pairs.push((r["input"].as_str().unwrap().into(), r["text"].as_str().unwrap().into()));
        }
        assert!(pairs.len() >= 4, "the fixture lost its renderings");
        for (input, want) in pairs {
            let got: String = sqlx::query_scalar("SELECT $1::jsonb::text")
                .bind(&input)
                .fetch_one(&db)
                .await
                .unwrap();
            assert_eq!(
                got, want,
                "Postgres {version} renders jsonb differently: every v2 audit row with details \
                 would fail verification on it"
            );
        }
        println!("audit v2 jsonb rendering: identical on Postgres {version}");
    }

    /// Cross-language proof: ignored unless
    /// NOO_AUDIT_PROOF_DB_URL names a SCRATCH database into which the REAL
    /// Python sinks (`audit_log.AuditLogger`, sync and async) have written
    /// rows with `NOO_AUDIT_HMAC_KEY=proof-dedicated-audit-key-0123456789`.
    /// Every one must read back hashed v2 and verify here.
    #[tokio::test]
    #[ignore]
    async fn python_written_rows_verify_in_a_scratch_postgres() {
        let Ok(url) = std::env::var("NOO_AUDIT_PROOF_DB_URL") else { return };
        let db = sqlx::PgPool::connect(&url).await.expect("connect");
        let key = b"proof-dedicated-audit-key-0123456789";
        let rows: Vec<RowTuple> = sqlx::query_as(sqlx::AssertSqlSafe(format!(
            "{SELECT_ROWS} WHERE actor LIKE 'py-proof%' ORDER BY \"timestamp\" ASC, id ASC"
        )))
        .fetch_all(&db)
        .await
        .unwrap();
        let rows: Vec<AuditRow> = rows.into_iter().map(to_row).collect();
        assert!(!rows.is_empty(), "no Python-written rows to judge");
        for r in &rows {
            println!("PROOF python row {} {} us={} v2={} verifies={}", r.actor, r.event_type, r.ts_us, r.is_v2(), r.signed_by(key));
            assert!(r.is_v2() && r.signed_by(key), "{r:?}");
        }
    }

    /// Proof harness against a real Postgres: ignored
    /// unless NOO_AUDIT_PROOF_DB_URL names a SCRATCH database holding a
    /// `noo_security_audit` table. Writes rows with the retired key, switches
    /// to the new key, writes the checkpoint, verifies, tampers each side.
    #[tokio::test]
    #[ignore]
    async fn proof_against_a_scratch_postgres() {
        let Ok(url) = std::env::var("NOO_AUDIT_PROOF_DB_URL") else { return };
        let db = sqlx::PgPool::connect(&url).await.expect("connect");
        let jwt = "proof-login-secret";
        let rk = retired_key_from(jwt);
        let nk = b"proof-dedicated-audit-key-0123456789".to_vec();
        let keys = || Keys { current: Some(nk.clone()), retired: Some(rk.clone()) };
        // Rows as the pre-v0.2.83 writers made them: v1, the time left to
        // the column default (here: bound as now, which is the same thing).
        let insert = |et: &'static str, key: Vec<u8>| {
            let db = db.clone();
            async move {
                let h = row_hash_with(&key, et, "info", "proof", "gateway", "ok", "");
                let id = uuid::Uuid::new_v4().to_string();
                assert!(
                    crate::audit::insert_signed_audit_row(
                        &db, &id, chrono::Utc::now(), et, "info", "proof", "gateway", "ok", "{}",
                        None, &h, None
                    )
                    .await
                );
                tokio::time::sleep(std::time::Duration::from_millis(20)).await;
            }
        };
        let read = || async {
            let rows: Vec<RowTuple> =
                sqlx::query_as(sqlx::AssertSqlSafe(format!("{SELECT_ROWS} ORDER BY \"timestamp\" ASC, id ASC")))
                    .fetch_all(&db)
                    .await
                    .unwrap();
            rows.into_iter().map(to_row).collect::<Vec<_>>()
        };
        let show = |label: &str, r: &Report| {
            println!(
                "PROOF {label}: verdict={} checked={} ok={} retired_epoch={} current_epoch={} breaks={:?} problems={:?}",
                r.verdict, r.checked, r.ok, r.retired_epoch_rows, r.current_epoch_rows,
                r.breaks.iter().map(|b| (&b.id, &b.reason)).collect::<Vec<_>>(), r.problems
            );
        };

        // 1. The old world: rows signed with the derived key.
        insert("auth_success", rk.clone()).await;
        insert("auth_failure", rk.clone()).await;
        show("before switch (no dedicated key)", &verify_rows(&read().await, &Keys { current: None, retired: Some(rk.clone()) }));
        // 2. The dedicated key arrives; boot writes the checkpoint.
        let out = ensure_checkpoint_with(&db, Some(nk.clone()), Some(rk.clone())).await;
        println!("PROOF boot 1: {out:?}");
        assert!(matches!(out, CheckpointOutcome::Handover { .. }));
        let out2 = ensure_checkpoint_with(&db, Some(nk.clone()), Some(rk.clone())).await;
        println!("PROOF boot 2: {out2:?}");
        // …and, as `main` does right after it, the hash-v2 marker.
        let m1 = ensure_hash_v2_marker_with(&db, Some(nk.clone())).await;
        println!("PROOF marker boot 1: {m1:?}");
        assert_eq!(m1, MarkerOutcome::Written { after_v1: true });
        // From here the real writer: hash v2.
        let insert_v2 = |et: &'static str| {
            let db = db.clone();
            let nk = nk.clone();
            async move {
                assert!(
                    crate::audit::write_audit_row(
                        &db, &nk, et, "info", "proof", "gateway", "ok", "{}", None
                    )
                    .await
                );
                tokio::time::sleep(std::time::Duration::from_millis(20)).await;
            }
        };
        insert_v2("admin_action").await;
        insert_v2("auth_success").await;
        let rows = read().await;
        for r in &rows {
            println!("PROOF row {} {} {} {}", r.timestamp, r.event_type, r.resource, r.outcome);
        }
        let ok = verify_rows(&rows, &keys());
        show("whole chain", &ok);
        assert_eq!(ok.verdict, "ok");
        assert_eq!(out2, CheckpointOutcome::AlreadyPresent, "the checkpoint is written once per key");
        // 3. Tamper one row on each side.
        let pre = rows.iter().find(|r| r.event_type == "auth_failure").unwrap().id.clone();
        sqlx::query("UPDATE noo_security_audit SET actor = 'mallory' WHERE id::text = $1")
            .bind(&pre).execute(&db).await.unwrap();
        let r = verify_rows(&read().await, &keys());
        show(&format!("tampered pre-checkpoint row {pre}"), &r);
        assert!(r.verdict == "fail" && r.breaks.iter().any(|b| b.id == pre));
        sqlx::query("UPDATE noo_security_audit SET actor = 'proof' WHERE id::text = $1")
            .bind(&pre).execute(&db).await.unwrap();
        let post = rows.iter().find(|r| r.event_type == "admin_action").unwrap().id.clone();
        sqlx::query("UPDATE noo_security_audit SET outcome = 'denied' WHERE id::text = $1")
            .bind(&post).execute(&db).await.unwrap();
        let r = verify_rows(&read().await, &keys());
        show(&format!("tampered post-checkpoint row {post}"), &r);
        assert!(r.verdict == "fail" && r.breaks.iter().any(|b| b.id == post));
        sqlx::query("UPDATE noo_security_audit SET outcome = 'ok' WHERE id::text = $1")
            .bind(&post).execute(&db).await.unwrap();
        // 4. A forger with the login secret, after the switch.
        insert("auth_success", rk.clone()).await;
        let r = verify_rows(&read().await, &keys());
        show("row signed with NOO_JWT_SECRET's derivation after the checkpoint", &r);
        assert_eq!(r.verdict, "fail");
        let forged = r.breaks[0].id.clone();
        sqlx::query("DELETE FROM noo_security_audit WHERE id::text = $1")
            .bind(&forged).execute(&db).await.unwrap();

        // 5. Hash v2: the marker, then rows through the real
        // writer — details in an order jsonb will not keep, a fraction jsonb
        // keeps as numeric, a time with microseconds.
        let m2 = ensure_hash_v2_marker_with(&db, Some(nk.clone())).await;
        println!("PROOF marker boot 2: {m2:?}");
        assert_eq!(m2, MarkerOutcome::AlreadyPresent);
        for et in ["admin_action", "auth_failure"] {
            assert!(
                crate::audit::write_audit_row(
                    &db, &nk, et, "warning", "alice", "gateway", "denied",
                    r#"{"zeta":1,"source_ip":"10.0.0.7","a":[1.50,{"y":null,"x":"é"}]}"#, None,
                )
                .await
            );
        }
        let rows = read().await;
        for r in rows.iter().filter(|r| r.is_v2() && r.actor == "alice") {
            println!("PROOF v2 row {} us={} details={:?} hash={:?}", r.timestamp, r.ts_us, r.details, r.entry_hash);
        }
        let ok = verify_rows(&rows, &keys());
        show("v2 rows through the real writer", &ok);
        assert_eq!(ok.verdict, "ok", "{ok:?}");
        assert!(ok.hash_v2_marker.is_some());
        // 6. Re-time a v2 row by ONE microsecond in the database.
        let v2 = rows.iter().find(|r| r.is_v2() && r.actor == "alice").unwrap().id.clone();
        sqlx::query("UPDATE noo_security_audit SET \"timestamp\" = \"timestamp\" + interval '1 microsecond' WHERE id::text = $1")
            .bind(&v2).execute(&db).await.unwrap();
        let r = verify_rows(&read().await, &keys());
        show(&format!("v2 row {v2} re-timed by 1µs"), &r);
        assert!(r.verdict == "fail" && r.breaks.iter().any(|b| b.id == v2 && b.reason.contains("tampered")));
        sqlx::query("UPDATE noo_security_audit SET \"timestamp\" = \"timestamp\" - interval '1 microsecond' WHERE id::text = $1")
            .bind(&v2).execute(&db).await.unwrap();
        // …and its source_ip.
        sqlx::query("UPDATE noo_security_audit SET details = jsonb_set(details, '{source_ip}', '\"203.0.113.9\"') WHERE id::text = $1")
            .bind(&v2).execute(&db).await.unwrap();
        let r = verify_rows(&read().await, &keys());
        show(&format!("v2 row {v2} source_ip edited"), &r);
        assert!(r.verdict == "fail" && r.breaks.iter().any(|b| b.id == v2));
        sqlx::query("UPDATE noo_security_audit SET details = jsonb_set(details, '{source_ip}', '\"10.0.0.7\"') WHERE id::text = $1")
            .bind(&v2).execute(&db).await.unwrap();
        assert_eq!(verify_rows(&read().await, &keys()).verdict, "ok");
        // 7. A v1 row (audit key) after the marker, as a v0.2.82 writer
        // would, outside the fixed writers: fails.
        insert("auth_success", nk.clone()).await;
        let r = verify_rows(&read().await, &keys());
        show("v1 row after the hash-v2 marker", &r);
        assert!(r.verdict == "fail" && r.breaks.iter().any(|b| b.reason.contains("hashed v1 after the hash-v2 marker")));
    }
}
