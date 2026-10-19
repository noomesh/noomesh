// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 PersonifAI LLC

//! Promotion proposals for prompt skills written at runtime
//! (`noo_prompt_skill_proposals`, migration 096).
//!
//! A skill written through the API, an agent tool or the evolve add-on is DATA
//! to the model (framed in the user's message). A person can PROMOTE a reviewed
//! one to instructions, or reject it. The pattern is the user-proposal queue
//! (`noo_user_proposals`): the writer files a row, a logged-in person decides.
//!
//! One row per `(name, content_sha)`, where the hash is
//! [`crate::prompt_skills::PromptSkill::review_hash`]. The decision belongs to
//! that text: edit the skill and the old row no longer matches, so the skill is
//! data again and a new pending row is opened.

use sqlx::PgPool;

use crate::prompt_skills::{PromptSkill, SkillTrust};

/// Who files the rows no request caused (the startup/list sweep).
pub const SWEEP_ACTOR: &str = "system:sweep";

#[derive(Debug, PartialEq, Eq)]
pub enum Opened {
    /// A pending proposal for this text (new, or the one already open).
    Pending(i64),
    /// A person already decided this exact text.
    Decided(String),
}

/// What `open_proposal` does given the status of the row for this exact text.
#[derive(Debug, PartialEq, Eq)]
pub enum OpenPlan {
    /// No row: file one.
    Insert,
    /// Already pending: nothing to do.
    KeepPending,
    /// A person decided this exact text: do not ask twice.
    AlreadyDecided,
    /// Superseded or withdrawn, and the text is back: ask again.
    Reopen,
}

pub fn plan_open(existing: Option<&str>) -> OpenPlan {
    match existing {
        None => OpenPlan::Insert,
        Some("pending") => OpenPlan::KeepPending,
        Some("promoted") | Some("rejected") => OpenPlan::AlreadyDecided,
        Some(_) => OpenPlan::Reopen,
    }
}

/// May a row in `current` be moved to `wanted` (`promoted` / `rejected`)?
/// Pending rows can; so can a decided one the other way (revoke a promotion,
/// reconsider a rejection). Superseded and withdrawn ones name text that is no
/// longer the skill's, so they cannot.
pub fn plan_decide(current: &str, wanted: &str) -> Result<(), DecideError> {
    if current == wanted {
        return Err(DecideError::Unchanged(current.to_string()));
    }
    if !matches!(current, "pending" | "promoted" | "rejected") {
        return Err(DecideError::Closed(current.to_string()));
    }
    Ok(())
}

/// Open (or refresh) the pending proposal for this skill's CURRENT text.
/// Pending rows for older text of the same skill are superseded. A text a
/// person already decided is left as decided: the same words are not asked twice.
pub async fn open_proposal(db: &PgPool, skill: &PromptSkill, proposed_by: &str) -> Result<Opened, sqlx::Error> {
    let sha = skill.review_hash();
    let mut tx = db.begin().await?;
    sqlx::query(
        "UPDATE noo_prompt_skill_proposals SET status = 'superseded' \
         WHERE name = $1 AND status = 'pending' AND content_sha <> $2",
    )
    .bind(&skill.name)
    .bind(&sha)
    .execute(&mut *tx)
    .await?;
    let existing: Option<(i64, String)> = sqlx::query_as(
        "SELECT id, status FROM noo_prompt_skill_proposals WHERE name = $1 AND content_sha = $2 FOR UPDATE",
    )
    .bind(&skill.name)
    .bind(&sha)
    .fetch_optional(&mut *tx)
    .await?;
    let out = match (plan_open(existing.as_ref().map(|(_, st)| st.as_str())), existing) {
        (OpenPlan::KeepPending, Some((id, _))) => Opened::Pending(id),
        (OpenPlan::AlreadyDecided, Some((_, status))) => Opened::Decided(status),
        (OpenPlan::Reopen, Some((id, _))) => {
            // superseded or withdrawn: the text is back, ask again.
            sqlx::query(
                "UPDATE noo_prompt_skill_proposals SET status = 'pending', proposed_by = $2, \
                 proposed_at = now(), decided_by = NULL, decided_at = NULL, reason = NULL, \
                 description = $3, content = $4 WHERE id = $1",
            )
            .bind(id)
            .bind(proposed_by)
            .bind(&skill.description)
            .bind(skill.content.trim())
            .execute(&mut *tx)
            .await?;
            Opened::Pending(id)
        }
        _ => {
            let id: i64 = sqlx::query_scalar(
                "INSERT INTO noo_prompt_skill_proposals (name, content_sha, description, content, proposed_by) \
                 VALUES ($1, $2, $3, $4, $5) RETURNING id",
            )
            .bind(&skill.name)
            .bind(&sha)
            .bind(&skill.description)
            .bind(skill.content.trim())
            .bind(proposed_by)
            .fetch_one(&mut *tx)
            .await?;
            Opened::Pending(id)
        }
    };
    tx.commit().await?;
    Ok(out)
}

/// A skill was retired: its open proposal has nothing left to promote.
pub async fn withdraw(db: &PgPool, name: &str) -> Result<u64, sqlx::Error> {
    Ok(sqlx::query("UPDATE noo_prompt_skill_proposals SET status = 'withdrawn' WHERE name = $1 AND status = 'pending'")
        .bind(name)
        .execute(db)
        .await?
        .rows_affected())
}

/// What a decision did, for the audit row and the answer.
#[derive(Debug)]
pub struct Decided {
    pub id: i64,
    pub name: String,
    pub content_sha: String,
    pub status: &'static str,
}

#[derive(Debug, PartialEq, Eq)]
pub enum DecideError {
    NotFound,
    /// Superseded or withdrawn: the text it names is no longer the skill's.
    Closed(String),
    /// Already in the state asked for.
    Unchanged(String),
    Db(String),
}

/// Record a person's decision. `promote` and `reject` both work on a pending row
/// and on one already decided the other way (a promotion can be revoked, a
/// rejection reconsidered); a superseded or withdrawn row cannot be decided.
pub async fn decide(db: &PgPool, id: i64, trust: SkillTrust, by: &str, reason: Option<&str>) -> Result<Decided, DecideError> {
    let status = match trust {
        SkillTrust::Promoted => "promoted",
        SkillTrust::Rejected => "rejected",
        SkillTrust::Evolved => return Err(DecideError::Db("a decision is promote or reject".into())),
    };
    let db_err = |e: sqlx::Error| DecideError::Db(e.to_string());
    let mut tx = db.begin().await.map_err(db_err)?;
    let row: Option<(String, String, String)> = sqlx::query_as(
        "SELECT name, content_sha, status FROM noo_prompt_skill_proposals WHERE id = $1 FOR UPDATE",
    )
    .bind(id)
    .fetch_optional(&mut *tx)
    .await
    .map_err(db_err)?;
    let Some((name, content_sha, current)) = row else { return Err(DecideError::NotFound) };
    plan_decide(&current, status)?;
    sqlx::query(
        "UPDATE noo_prompt_skill_proposals SET status = $2, decided_by = $3, decided_at = now(), reason = $4 WHERE id = $1",
    )
    .bind(id)
    .bind(status)
    .bind(by)
    .bind(reason)
    .execute(&mut *tx)
    .await
    .map_err(db_err)?;
    tx.commit().await.map_err(db_err)?;
    Ok(Decided { id, name, content_sha, status })
}

/// The promoted and rejected rows, for [`crate::prompt_skills::SkillRegistry::set_decisions`].
pub async fn load_decisions(db: &PgPool) -> Result<Vec<(String, String, SkillTrust)>, sqlx::Error> {
    let rows: Vec<(String, String, String)> = sqlx::query_as(
        "SELECT name, content_sha, status FROM noo_prompt_skill_proposals WHERE status IN ('promoted', 'rejected')",
    )
    .fetch_all(db)
    .await?;
    Ok(rows
        .into_iter()
        .map(|(n, h, st)| (n, h, if st == "promoted" { SkillTrust::Promoted } else { SkillTrust::Rejected }))
        .collect())
}

/// Proposals, pending ahead of decided, newest first. `status` filters.
pub async fn list(db: &PgPool, status: Option<&str>, limit: i64) -> Result<Vec<serde_json::Value>, sqlx::Error> {
    use sqlx::Row;
    let rows = sqlx::query(
        "SELECT id, name, content_sha, description, content, status, proposed_by, proposed_at, \
         decided_by, decided_at, reason FROM noo_prompt_skill_proposals \
         WHERE ($1::text IS NULL OR status = $1) \
         ORDER BY (status = 'pending') DESC, proposed_at DESC LIMIT $2",
    )
    .bind(status)
    .bind(limit)
    .fetch_all(db)
    .await?;
    rows.iter()
        .map(|r| {
            Ok(serde_json::json!({
                "id": r.try_get::<i64, _>("id")?,
                "name": r.try_get::<String, _>("name")?,
                "content_sha": r.try_get::<String, _>("content_sha")?,
                "description": r.try_get::<String, _>("description")?,
                "content": r.try_get::<String, _>("content")?,
                "status": r.try_get::<String, _>("status")?,
                "proposed_by": r.try_get::<String, _>("proposed_by")?,
                "proposed_at": r.try_get::<chrono::DateTime<chrono::Utc>, _>("proposed_at")?,
                "decided_by": r.try_get::<Option<String>, _>("decided_by")?,
                "decided_at": r.try_get::<Option<chrono::DateTime<chrono::Utc>>, _>("decided_at")?,
                "reason": r.try_get::<Option<String>, _>("reason")?,
            }))
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_new_text_is_filed_and_a_decided_one_is_not_asked_twice() {
        assert_eq!(plan_open(None), OpenPlan::Insert);
        assert_eq!(plan_open(Some("pending")), OpenPlan::KeepPending);
        assert_eq!(plan_open(Some("promoted")), OpenPlan::AlreadyDecided);
        assert_eq!(plan_open(Some("rejected")), OpenPlan::AlreadyDecided);
        for back in ["superseded", "withdrawn"] {
            assert_eq!(plan_open(Some(back)), OpenPlan::Reopen, "{back}: the text is back, ask again");
        }
    }

    #[test]
    fn only_a_live_text_can_be_decided_and_a_decision_can_be_revoked() {
        assert_eq!(plan_decide("pending", "promoted"), Ok(()));
        assert_eq!(plan_decide("pending", "rejected"), Ok(()));
        assert_eq!(plan_decide("promoted", "rejected"), Ok(()), "revoke");
        assert_eq!(plan_decide("rejected", "promoted"), Ok(()), "reconsider");
        assert_eq!(plan_decide("promoted", "promoted"), Err(DecideError::Unchanged("promoted".into())));
        for dead in ["superseded", "withdrawn"] {
            assert_eq!(plan_decide(dead, "promoted"), Err(DecideError::Closed(dead.into())));
        }
    }
}
