//! Context ingress for a running task (i143 part C).
//!
//! `POST /api/tasks/{id}/context {text, revision}` lands here. Revisions are
//! monotonic per task and idempotent by revision; the text is picked up at
//! the next loop boundary ([`take_pending`], called by
//! `task_budget::check`), never mid-loop. This is distinct from `answer`,
//! which needs a pending question.

use anyhow::{anyhow, Result};
use sha2::{Digest, Sha256};
use sqlx::Row;

/// Largest context text, in bytes.
pub const MAX_BYTES: usize = 32 * 1024;

/// What a submission came to.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ContextOutcome {
    /// A new revision, stored.
    Accepted,
    /// The same revision with the same text (a retry): nothing changed.
    Duplicate { current: i32 },
    /// The same revision with different text, or a lower revision.
    Conflict { current: i32 },
    /// The task is done, failed or stopped.
    Terminal { state: String },
    TooLarge,
}

pub fn sha256_hex(text: &str) -> String {
    hex::encode(Sha256::digest(text.as_bytes()))
}

/// The decision, pure. `current` is the task's `context_revision`;
/// `current_sha` the stored hash of that revision (if a row exists); `len`
/// the text's byte length. Size is checked first, then the task's state,
/// then the revision: a retry of an old revision against a finished task is
/// told the task is finished.
pub fn decide(current: i32, current_sha: Option<&str>, revision: i32, new_sha: &str, state: &str, len: usize) -> ContextOutcome {
    if len > MAX_BYTES {
        return ContextOutcome::TooLarge;
    }
    if matches!(state, "done" | "failed" | "stopped") {
        return ContextOutcome::Terminal { state: state.to_string() };
    }
    if revision < 1 {
        return ContextOutcome::Conflict { current };
    }
    if revision > current {
        ContextOutcome::Accepted
    } else if revision == current && current_sha == Some(new_sha) {
        ContextOutcome::Duplicate { current }
    } else {
        ContextOutcome::Conflict { current }
    }
}

/// Submit a revision. Race-safe: the task row is locked for the decision and
/// the write.
pub async fn submit(db: &sqlx::PgPool, task_id: &str, revision: i32, text: &str) -> Result<ContextOutcome> {
    let uuid = uuid::Uuid::parse_str(task_id)?;
    let mut tx = db.begin().await?;
    let row = sqlx::query("SELECT state, context_revision FROM noo_tasks WHERE id = $1 FOR UPDATE")
        .bind(uuid)
        .fetch_optional(&mut *tx)
        .await?
        .ok_or_else(|| anyhow!("task {task_id} not found"))?;
    let state: String = row.try_get("state")?;
    let current: i32 = row.try_get("context_revision")?;
    let sha = sha256_hex(text);
    let current_sha: Option<String> = if current > 0 {
        sqlx::query_scalar("SELECT sha256 FROM noo_task_context WHERE task_id = $1 AND revision = $2")
            .bind(uuid)
            .bind(current)
            .fetch_optional(&mut *tx)
            .await?
    } else {
        None
    };
    let out = decide(current, current_sha.as_deref(), revision, &sha, &state, text.len());
    if out == ContextOutcome::Accepted {
        sqlx::query("INSERT INTO noo_task_context (task_id, revision, text, sha256) VALUES ($1, $2, $3, $4)")
            .bind(uuid)
            .bind(revision)
            .bind(text)
            .bind(&sha)
            .execute(&mut *tx)
            .await?;
        sqlx::query("UPDATE noo_tasks SET context_revision = $2, updated_at = now() WHERE id = $1")
            .bind(uuid)
            .bind(revision)
            .execute(&mut *tx)
            .await?;
    }
    tx.commit().await?;
    Ok(out)
}

/// Combine pending revisions (ascending) into the one text the next loop
/// reads, and the highest revision. One revision is its text as written;
/// several are labelled so the model sees the order.
pub fn combine(pending: &[(i32, String)]) -> Option<(i32, String)> {
    let last = pending.last()?;
    if pending.len() == 1 {
        return Some((last.0, last.1.clone()));
    }
    let text = pending.iter().map(|(r, t)| format!("[revision {r}]\n{t}")).collect::<Vec<_>>().join("\n\n");
    Some((last.0, text))
}

/// The not-yet-applied revisions, combined and marked applied. `None` when
/// there is nothing new. Called once per loop boundary.
pub async fn take_pending(db: &sqlx::PgPool, task_id: &str) -> Result<Option<(i32, String)>> {
    let uuid = uuid::Uuid::parse_str(task_id)?;
    let mut tx = db.begin().await?;
    let rows = sqlx::query("SELECT revision, text FROM noo_task_context WHERE task_id = $1 AND applied_at IS NULL ORDER BY revision FOR UPDATE")
        .bind(uuid)
        .fetch_all(&mut *tx)
        .await?;
    let pending: Vec<(i32, String)> = rows
        .iter()
        .filter_map(|r| Some((r.try_get::<i32, _>("revision").ok()?, r.try_get::<String, _>("text").ok()?)))
        .collect();
    let Some(out) = combine(&pending) else { return Ok(None) };
    sqlx::query("UPDATE noo_task_context SET applied_at = now() WHERE task_id = $1 AND applied_at IS NULL")
        .bind(uuid)
        .execute(&mut *tx)
        .await?;
    tx.commit().await?;
    Ok(Some(out))
}

/// The sentence the loop's prompt starts with.
pub fn preamble(revision: i32, text: &str) -> String {
    format!("The owner updated this task's context (revision {revision}): {}", text.trim())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn decide_table() {
        let (a, b) = (sha256_hex("alpha"), sha256_hex("beta"));
        let (a, b) = (a.as_str(), b.as_str());
        let cases: Vec<(i32, Option<&str>, i32, &str, &str, usize, ContextOutcome)> = vec![
            // (current, current_sha, revision, new_sha, state, len, want)
            (0, None, 1, a, "running", 5, ContextOutcome::Accepted),
            (1, Some(a), 2, b, "running", 4, ContextOutcome::Accepted),
            (1, Some(a), 5, b, "checkpointed", 4, ContextOutcome::Accepted),
            (1, Some(a), 1, a, "running", 5, ContextOutcome::Duplicate { current: 1 }),
            (1, Some(a), 1, b, "running", 4, ContextOutcome::Conflict { current: 1 }),
            (3, Some(a), 2, a, "running", 5, ContextOutcome::Conflict { current: 3 }),
            (0, None, 0, a, "running", 5, ContextOutcome::Conflict { current: 0 }),
            (0, None, -1, a, "running", 5, ContextOutcome::Conflict { current: 0 }),
            (1, Some(a), 2, b, "done", 4, ContextOutcome::Terminal { state: "done".into() }),
            (1, Some(a), 1, a, "stopped", 5, ContextOutcome::Terminal { state: "stopped".into() }),
            (0, None, 1, a, "failed", 5, ContextOutcome::Terminal { state: "failed".into() }),
            (0, None, 1, a, "open", MAX_BYTES, ContextOutcome::Accepted),
            (0, None, 1, a, "open", MAX_BYTES + 1, ContextOutcome::TooLarge),
            (0, None, 1, a, "done", MAX_BYTES + 1, ContextOutcome::TooLarge),
        ];
        for (cur, sha, rev, nsha, st, len, want) in cases {
            assert_eq!(decide(cur, sha, rev, nsha, st, len), want, "current={cur} rev={rev} state={st} len={len}");
        }
    }

    #[test]
    fn sha_is_stable_hex() {
        assert_eq!(sha256_hex("").len(), 64);
        assert_eq!(sha256_hex("a"), sha256_hex("a"));
        assert_ne!(sha256_hex("a"), sha256_hex("b"));
    }

    #[test]
    fn combine_labels_only_when_there_are_several() {
        assert_eq!(combine(&[]), None);
        assert_eq!(combine(&[(2, "x".into())]), Some((2, "x".into())));
        let (r, t) = combine(&[(2, "x".into()), (3, "y".into())]).unwrap();
        assert_eq!(r, 3);
        assert!(t.starts_with("[revision 2]\nx") && t.ends_with("[revision 3]\ny"));
    }

    #[test]
    fn preamble_names_the_revision() {
        assert_eq!(preamble(4, " use the new file \n"), "The owner updated this task's context (revision 4): use the new file");
    }
}
