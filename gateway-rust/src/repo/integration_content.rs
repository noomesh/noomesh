// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 PersonifAI LLC

//! A separate, encrypted personal corpus. Shared KB roles, deduplication,
//! administrator reads, graph builders and worker caches cannot reach it.
use crate::integrations::{
    crypto::{hash, Vault},
    Error,
};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use sqlx::PgPool;
use std::collections::BTreeMap;
use uuid::Uuid;

pub const MAX_TEXT: usize = 32 * 1024;
pub const MAX_DOCUMENTS: i64 = 1000;

#[derive(Clone, Serialize, Deserialize)]
pub struct Document {
    pub external_id: String,
    pub title: String,
    pub text: String,
    pub url: String,
    /// Provider revision, encrypted with the document; never a shared index.
    #[serde(default)]
    pub version: String,
}

impl Drop for Document {
    fn drop(&mut self) {
        use zeroize::Zeroize;
        self.external_id.zeroize();
        self.title.zeroize();
        self.text.zeroize();
        self.url.zeroize();
        self.version.zeroize();
    }
}

pub struct Job {
    pub source: Uuid,
    pub owner: Uuid,
    pub account: Uuid,
    pub policy: crate::connections::SourcePolicy,
    pub generation: Uuid,
    pub lease: Uuid,
    pub cursor: Option<Value>,
}

fn context(owner: Uuid, source: Uuid, item: &str) -> String {
    format!("noomesh/personal-content/v1/{owner}/{source}/{item}")
}

fn cursor_context(owner: Uuid, source: Uuid) -> String {
    format!("noomesh/personal-cursor/v1/{owner}/{source}")
}

/// Called only with the authenticated owner's UUID. Jobs derive that UUID
/// from this source row, never from a caller's body or an unsigned bus message.
pub async fn enable(db: &PgPool, owner: Uuid, source: Uuid, enabled: bool) -> Result<(), Error> {
    let mut tx = db.begin().await?;
    let row: Option<(Value, String)> = sqlx::query_as(
        "SELECT s.policy,a.status FROM noo_connection_sources s JOIN noo_connected_accounts a ON a.id=s.account_id AND a.owner_uuid=s.owner_uuid WHERE s.id=$1 AND s.owner_uuid=$2 FOR UPDATE OF s")
        .bind(source).bind(owner).fetch_optional(&mut *tx).await?;
    let (policy, status) = row.ok_or(Error::NotFound)?;
    let policy: crate::connections::SourcePolicy = serde_json::from_value(policy)
        .map_err(|_| Error::Invalid("Invalid source policy".into()))?;
    if enabled {
        policy.validate_for_sync().map_err(Error::Invalid)?;
        if status != "connected" {
            return Err(Error::Reauth);
        }
    }
    sqlx::query("UPDATE noo_connection_sources SET sync_enabled=$3 WHERE id=$1 AND owner_uuid=$2")
        .bind(source)
        .bind(owner)
        .bind(enabled)
        .execute(&mut *tx)
        .await?;
    if enabled {
        // Clicking start again never revokes a currently running lease.
        sqlx::query("INSERT INTO noo_integration_sync (source_id,owner_uuid) VALUES ($1,$2) ON CONFLICT (source_id) DO UPDATE SET next_run=now(),status='queued',fault=NULL,attempts=0,cursor_sealed=NULL,generation=NULL WHERE noo_integration_sync.lease IS NULL OR noo_integration_sync.lease_until < now()")
            .bind(source).bind(owner).execute(&mut *tx).await?;
    } else {
        sqlx::query("UPDATE noo_integration_sync SET status='paused',lease=NULL,lease_until=NULL,cursor_sealed=NULL,generation=NULL WHERE source_id=$1 AND owner_uuid=$2")
            .bind(source).bind(owner).execute(&mut *tx).await?;
    }
    tx.commit().await?;
    Ok(())
}

pub async fn claim(db: &PgPool, vault: &Vault) -> Result<Option<Job>, Error> {
    // Bound work per poll, committing poisoned rows individually so a bad
    // owner's storage never holds locks or stalls healthy users behind it.
    for _ in 0..32 {
        let mut tx = db.begin().await?;
        let row: Option<(Uuid, Uuid, Uuid, Value, Option<Uuid>, Option<Value>)> = sqlx::query_as(
            "SELECT j.source_id,j.owner_uuid,s.account_id,s.policy,j.generation,j.cursor_sealed FROM noo_integration_sync j JOIN noo_connection_sources s ON s.id=j.source_id AND s.owner_uuid=j.owner_uuid JOIN noo_connected_accounts a ON a.id=s.account_id AND a.owner_uuid=s.owner_uuid JOIN noo_users u ON u.user_uuid=j.owner_uuid WHERE s.sync_enabled AND a.status='connected' AND NOT u.disabled AND j.next_run<=now() AND (j.lease IS NULL OR j.lease_until<now()) AND j.status<>'error' ORDER BY j.next_run FOR UPDATE OF j SKIP LOCKED LIMIT 1")
            .fetch_optional(&mut *tx).await?;
        let Some((source, owner, account, policy, generation, cursor)) = row else {
            return Ok(None);
        };
        let starting = generation.is_none();
        let lease = Uuid::new_v4();
        let generation = generation.unwrap_or_else(Uuid::new_v4);
        let cursor = cursor
            .map(|v| vault.open::<Value>(&v, &cursor_context(owner, source)))
            .transpose();
        let policy = serde_json::from_value::<crate::connections::SourcePolicy>(policy)
            .ok().filter(|p| p.validate_for_sync().is_ok());
        let (Ok(cursor), Some(policy)) = (cursor, policy) else {
            sqlx::query("UPDATE noo_integration_sync SET status='error',fault='storage',lease=NULL,lease_until=NULL,attempts=attempts+1 WHERE source_id=$1 AND owner_uuid=$2")
                .bind(source).bind(owner).execute(&mut *tx).await?;
            tx.commit().await?;
            tracing::warn!("private sync source quarantined: unreadable cursor or policy");
            continue;
        };
        let gmail = matches!(policy, crate::connections::SourcePolicy::Gmail { .. });
        if gmail {
            // Serialize claims for this owner without locking other job rows.
            // The transaction lock releases automatically on commit/rollback.
            let locked: bool = sqlx::query_scalar("SELECT pg_try_advisory_xact_lock(hashtextextended('noomesh/google-owner/' || $1::uuid::text, 0))")
                .bind(owner).fetch_one(&mut *tx).await?;
            let due: Option<chrono::DateTime<chrono::Utc>> = if locked {
                sqlx::query_scalar("SELECT due FROM (SELECT GREATEST(max(last_gmail_page)+interval '1 second',CASE WHEN $2 THEN max(last_gmail_scan)+interval '1 minute' ELSE NULL END) AS due FROM noo_integration_sync WHERE owner_uuid=$1) AS pacing WHERE due>now()")
                    .bind(owner).bind(starting).fetch_optional(&mut *tx).await?
            } else {
                Some(sqlx::query_scalar("SELECT now()+interval '1 second'").fetch_one(&mut *tx).await?)
            };
            if let Some(due) = due {
                sqlx::query("UPDATE noo_integration_sync SET next_run=$3 WHERE source_id=$1 AND owner_uuid=$2")
                    .bind(source).bind(owner).bind(due).execute(&mut *tx).await?;
                tx.commit().await?;
                continue;
            }
        }
        sqlx::query("UPDATE noo_integration_sync SET lease=$2,lease_until=now()+interval '5 minutes',imported=CASE WHEN generation IS NULL THEN 0 ELSE imported END,skipped=CASE WHEN generation IS NULL THEN 0 ELSE skipped END,generation=$3,status='syncing',last_gmail_page=CASE WHEN $4 THEN now() ELSE last_gmail_page END,last_gmail_scan=CASE WHEN $4 AND $5 THEN now() ELSE last_gmail_scan END WHERE source_id=$1")
            .bind(source).bind(lease).bind(generation).bind(gmail).bind(starting).execute(&mut *tx).await?;
        tx.commit().await?;
        return Ok(Some(Job {
            source,
            owner,
            account,
            policy,
            generation,
            lease,
            cursor,
        }));
    }
    Ok(None)
}

/// Commit one provider page atomically with its cursor. A retry replaces only
/// this owner's own source item. Removal, pause, lease replacement or user
/// erasure while HTTP is in flight makes the entire page a no-op.
pub async fn commit(
    db: &PgPool,
    vault: &Vault,
    job: &Job,
    page: &crate::integrations::sync::Page,
) -> Result<bool, Error> {
    let docs = &page.docs;
    let cursor = page.cursor.as_ref();
    let skipped = page.skipped;
    if page.retained.len() > MAX_DOCUMENTS as usize {
        return Err(Error::Invalid("Personal scan exceeded its limit".into()));
    }
    let mut tx = db.begin().await?;
    // Same lock ordering as disconnect and user erasure.
    let owner: Option<Uuid> = sqlx::query_scalar(
        "SELECT user_uuid FROM noo_users WHERE user_uuid=$1 AND NOT disabled FOR UPDATE",
    )
    .bind(job.owner)
    .fetch_optional(&mut *tx)
    .await?;
    if owner.is_none() {
        return Ok(false);
    }
    // Lock source then job explicitly, matching enable/pause. A join with
    // FOR UPDATE of both rows leaves lock order to the query planner.
    let source: Option<Uuid> = sqlx::query_scalar("SELECT s.id FROM noo_connection_sources s JOIN noo_connected_accounts a ON a.id=s.account_id AND a.owner_uuid=s.owner_uuid WHERE s.id=$1 AND s.owner_uuid=$2 AND s.account_id=$3 AND s.sync_enabled AND a.status='connected' FOR UPDATE OF s")
        .bind(job.source).bind(job.owner).bind(job.account).fetch_optional(&mut *tx).await?;
    if source.is_none() {
        return Ok(false);
    }
    let valid: Option<Uuid> = sqlx::query_scalar("SELECT source_id FROM noo_integration_sync WHERE source_id=$1 AND owner_uuid=$2 AND lease=$3 AND generation=$4 AND lease_until>now() FOR UPDATE")
        .bind(job.source).bind(job.owner).bind(job.lease).bind(job.generation).fetch_optional(&mut *tx).await?;
    if valid.is_none() {
        return Ok(false);
    }
    for doc in docs {
        if doc.text.len() > MAX_TEXT
            || doc.title.len() > 1024
            || doc.external_id.len() > 1024
            || doc.url.len() > 4096
            || doc.version.len() > 256
        {
            return Err(Error::Invalid(
                "Personal document exceeded its limit".into(),
            ));
        }
        let item = hash(&doc.external_id);
        if !page.retained.contains(&item) {
            return Err(Error::Invalid("Personal scan omitted an imported item".into()));
        }
        // Old providers/fixtures without a revision still avoid encryption and
        // writes when the visible document is identical. A changed revision
        // must persist, otherwise it would download again on every scan.
        let existing: Option<Value> = sqlx::query_scalar("SELECT sealed FROM noo_integration_documents WHERE owner_uuid=$1 AND source_id=$2 AND item_key=$3")
            .bind(job.owner).bind(job.source).bind(&item).fetch_optional(&mut *tx).await?;
        if let Some(existing) = existing {
            if let Ok(old) = vault.open::<Document>(&existing, &context(job.owner, job.source, &item)) {
                if old.version == doc.version && old.title == doc.title && old.text == doc.text && old.url == doc.url {
                    continue;
                }
            }
        }
        let sealed = vault.seal(doc, &context(job.owner, job.source, &item))?;
        sqlx::query("INSERT INTO noo_integration_documents (id,owner_uuid,source_id,item_key,generation,sealed) VALUES ($1,$2,$3,$4,$5,$6) ON CONFLICT (owner_uuid,source_id,item_key) DO UPDATE SET generation=EXCLUDED.generation,sealed=EXCLUDED.sealed,updated_at=now()")
            .bind(Uuid::new_v4()).bind(job.owner).bind(job.source).bind(item).bind(job.generation).bind(sealed).execute(&mut *tx).await?;
    }
    let count = page.retained.len() as i64;
    let total: i64 = sqlx::query_scalar("SELECT count(*) FROM noo_integration_documents WHERE owner_uuid=$1 AND source_id=$2")
        .bind(job.owner).bind(job.source).fetch_one(&mut *tx).await?;
    if total > 2 * MAX_DOCUMENTS {
        return Err(Error::Invalid(
            "Source limit reached; choose fewer folders or a shorter Gmail lookback".into(),
        ));
    }
    if cursor.is_none() {
        let retained: Vec<_> = page.retained.iter().cloned().collect();
        sqlx::query("DELETE FROM noo_integration_documents WHERE owner_uuid=$1 AND source_id=$2 AND NOT (item_key=ANY($3))")
            .bind(job.owner).bind(job.source).bind(retained).execute(&mut *tx).await?;
    }
    let cursor = cursor
        .map(|v| vault.seal(v, &cursor_context(job.owner, job.source)))
        .transpose()?;
    sqlx::query("UPDATE noo_integration_sync SET lease=NULL,lease_until=NULL,cursor_sealed=$2,generation=CASE WHEN $2 IS NULL THEN NULL ELSE generation END,status=CASE WHEN $2 IS NULL THEN 'idle' ELSE 'queued' END,next_run=CASE WHEN $2 IS NULL THEN now()+CASE WHEN $6 THEN interval '6 hours' ELSE interval '30 minutes' END ELSE now() END,attempts=0,fault=NULL,imported=CASE WHEN $2 IS NULL THEN $3 ELSE imported+$4 END,skipped=skipped+$5 WHERE source_id=$1")
        .bind(job.source).bind(cursor).bind(count as i32).bind(docs.len() as i32).bind(skipped as i32).bind(matches!(job.policy, crate::connections::SourcePolicy::Gmail { .. })).execute(&mut *tx).await?;
    tx.commit().await?;
    Ok(true)
}

/// Load only this source owner's encrypted revision inventory at the beginning
/// of a scan. Subsequent pages carry it in the authenticated encrypted cursor.
pub async fn versions(db: &PgPool, vault: &Vault, job: &Job) -> Result<BTreeMap<String, String>, Error> {
    let rows: Vec<(String, Value)> = sqlx::query_as("SELECT item_key,sealed FROM noo_integration_documents WHERE owner_uuid=$1 AND source_id=$2 LIMIT 2000")
        .bind(job.owner).bind(job.source).fetch_all(db).await?;
    let mut known = BTreeMap::new();
    let mut unreadable = false;
    for (item, sealed) in rows {
        match vault.open::<Document>(&sealed, &context(job.owner, job.source, &item)) {
            Ok(doc) if !doc.version.is_empty() => { known.insert(item, doc.version.clone()); }
            Ok(_) => {}
            Err(_) => { unreadable = true; }
        }
    }
    if unreadable { tracing::warn!("private sync inventory contains unreadable documents; refetching"); }
    Ok(known)
}

pub async fn fail(db: &PgPool, job: &Job, error: &Error) -> Result<(), Error> {
    let fault = match error {
        Error::Reauth => "reauth",
        Error::Invalid(_) => "limit",
        Error::Storage(_) => "storage",
        _ => "provider",
    };
    let result = sqlx::query("UPDATE noo_integration_sync SET lease=NULL,lease_until=NULL,attempts=attempts+1,fault=$4,status=CASE WHEN attempts>=4 OR $4 IN ('reauth','limit') THEN 'error' ELSE 'queued' END,next_run=now()+interval '1 minute' * power(2,least(attempts,4)) WHERE source_id=$1 AND owner_uuid=$2 AND lease=$3")
        .bind(job.source).bind(job.owner).bind(job.lease).bind(fault).execute(db).await?;
    if result.rows_affected() > 0 { tracing::warn!(fault, "private sync failed; retry policy applied"); }
    Ok(())
}

/// No role or caller-supplied owner override exists, including for admins.
pub fn requester_account(principal: &crate::bus_principal::Principal) -> Option<&str> {
    if principal.kind != crate::bus_principal::Kind::User
        || principal.act.is_some()
        || principal.harness.is_some()
        || principal.scopes.iter().any(|s| s == "kb:shared-room")
        || crate::coordinator::in_shared_room()
        || crate::mcp_bridge::current_conversation().is_some()
        || !crate::routes::communication::turn_principal().conversation_id.is_empty()
    {
        return None;
    }
    let name = crate::auth::account_of(&principal.sub);
    if name.is_empty() {
        None
    } else {
        Some(name)
    }
}

pub async fn search(
    db: &PgPool,
    vault: &Vault,
    owner: Uuid,
    query: &str,
    limit: usize,
) -> Result<Value, Error> {
    let terms: Vec<String> = query
        .split_whitespace()
        .filter(|s| s.chars().count() > 1)
        .take(32)
        .map(str::to_lowercase)
        .collect();
    if terms.is_empty() {
        return Ok(json!({"items":[],"truncated":false}));
    }
    // Bound decryption and memory. Personal content is never indexed or cached
    // by the shared service. The caller is told when this initial window caps.
    let rows: Vec<(Uuid, Uuid, String, Value)> = sqlx::query_as("SELECT d.id,d.source_id,d.item_key,d.sealed FROM noo_integration_documents d JOIN noo_connection_sources s ON s.id=d.source_id AND s.owner_uuid=d.owner_uuid JOIN noo_connected_accounts a ON a.id=s.account_id AND a.owner_uuid=s.owner_uuid JOIN noo_users u ON u.user_uuid=d.owner_uuid WHERE d.owner_uuid=$1 AND NOT u.disabled AND a.status='connected' ORDER BY d.updated_at DESC,d.id LIMIT 1001")
        .bind(owner).fetch_all(db).await?;
    let truncated = rows.len() > 1000;
    let mut hits = Vec::new();
    let mut unavailable = false;
    for (id, source, item, sealed) in rows.into_iter().take(1000) {
        let doc: Document = match vault.open(&sealed, &context(owner, source, &item)) {
            Ok(doc) => doc,
            Err(_) => { unavailable = true; continue; }
        };
        let lower = format!("{}\n{}", doc.title, doc.text).to_lowercase();
        let score = terms.iter().filter(|t| lower.contains(t.as_str())).count();
        if score > 0 {
            let chars: Vec<char> = doc.text.chars().collect();
            let snippet = chars
                .chunks(1500)
                .map(|c| c.iter().collect::<String>())
                .find(|chunk| {
                    let lower = chunk.to_lowercase();
                    terms.iter().any(|t| lower.contains(t.as_str()))
                })
                .unwrap_or_else(|| doc.text.chars().take(1500).collect());
            hits.push((
                score,
                json!({"id":id,"source_id":source,"title":doc.title,"url":doc.url,"text":snippet}),
            ));
        }
    }
    hits.sort_by_key(|a| std::cmp::Reverse(a.0));
    if unavailable { tracing::warn!("private search skipped unreadable documents"); }
    Ok(
        json!({"items":hits.into_iter().take(limit.min(20)).map(|(_,v)|v).collect::<Vec<_>>(),"truncated":truncated,"unavailable":unavailable}),
    )
}

pub async fn current_evidence(db: &PgPool, query: &str) -> Result<Value, Error> {
    let owner = current_owner(db).await?;
    let Some(owner) = owner else {
        return Ok(json!({"items":[]}));
    };
    // Unconfigured installations with no personal content retain legacy reads.
    let exists: bool = sqlx::query_scalar(
        "SELECT EXISTS(SELECT 1 FROM noo_integration_documents WHERE owner_uuid=$1)",
    )
    .bind(owner)
    .fetch_one(db)
    .await?;
    if !exists {
        return Ok(json!({"items":[]}));
    }
    search(db, &Vault::configured()?, owner, query, 5).await
}

/// The same authenticated owner resolution is used by direct search and
/// injected/chat retrieval; unsigned request fields never enter this function.
pub async fn current_owner(db: &PgPool) -> Result<Option<Uuid>, Error> {
    let principal = crate::bus_principal::current();
    let Some(account) = requester_account(&principal) else {
        return Ok(None);
    };
    Ok(crate::repo::integrations::owner_uuid(db, account).await?)
}

#[cfg(test)]
mod tests;

pub fn evidence_text(evidence: &Value) -> String {
    evidence["items"]
        .as_array()
        .map(|items| {
            items
                .iter()
                .map(|d| {
                    format!(
                        "{}\n{}\nSource: {}",
                        d["title"].as_str().unwrap_or(""),
                        d["text"].as_str().unwrap_or(""),
                        d["url"].as_str().unwrap_or("")
                    )
                })
                .collect::<Vec<_>>()
                .join("\n---\n")
        })
        .unwrap_or_default()
}
