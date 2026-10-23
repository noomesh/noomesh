// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 PersonifAI LLC

//! `noo_agent_messages` — the trace of agent-to-agent messages.
//! Single writer: the recorder in `agent_messages.rs`. Readers: the HTTP
//! routes (scoped to the requester unless admin/operator).

use serde_json::{json, Value};
use sqlx::PgPool;

use crate::agent_messages::Envelope;

/// Idempotent on `id` (JetStream may redeliver). `sig_verified` = the
/// recorder checked the signature; `received_at` is the
/// DB clock, set by default.
pub async fn insert(db: &PgPool, e: &Envelope, sig_verified: bool) -> Result<(), sqlx::Error> {
    let ts = chrono::DateTime::parse_from_rfc3339(&e.ts)
        .map(|t| t.with_timezone(&chrono::Utc))
        .unwrap_or_else(|_| chrono::Utc::now());
    let f = e.from_id.clone().unwrap_or_default();
    let t = e.to_id.clone().unwrap_or_default();
    sqlx::query(
        "INSERT INTO noo_agent_messages \
             (id, thread_id, from_agent, to_agent, kind, body, refs, ts, enc, sig, \
              from_user, from_node, from_harness, to_user, to_node, to_harness, enc_meta, sig_verified) \
         VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16, $17, $18) \
         ON CONFLICT (id) DO NOTHING",
    )
    .bind(&e.id)
    .bind(&e.thread_id)
    .bind(&e.from)
    .bind(&e.to)
    .bind(&e.kind)
    .bind(&e.body)
    .bind(json!(e.refs))
    .bind(ts)
    .bind(&e.enc)
    .bind(&e.sig)
    .bind(&f.user)
    .bind(&f.node)
    .bind(&f.harness)
    .bind(&t.user)
    .bind(&t.node)
    .bind(&t.harness)
    .bind(&e.enc_meta)
    .bind(sig_verified)
    .execute(db)
    .await?;
    Ok(())
}

/// Is `agent` a sender or recipient somewhere in `thread`? Used to keep
/// outsiders from posting into a thread they are not part of. A thread nobody has posted to yet has no parties — the first
/// message creates it.
pub async fn is_party(db: &PgPool, thread: &str, agent: &str) -> Result<Option<bool>, sqlx::Error> {
    let exists: bool = sqlx::query_scalar("SELECT EXISTS (SELECT 1 FROM noo_agent_messages WHERE thread_id = $1)")
        .bind(thread)
        .fetch_one(db)
        .await?;
    if !exists {
        return Ok(None);
    }
    let party: bool = sqlx::query_scalar(
        "SELECT EXISTS (SELECT 1 FROM noo_agent_messages WHERE thread_id = $1 AND (from_agent = $2 OR to_agent = $2))",
    )
    .bind(thread)
    .bind(agent)
    .fetch_one(db)
    .await?;
    Ok(Some(party))
}

#[derive(Debug, Default)]
pub struct Filter<'a> {
    /// Messages where this agent is sender OR recipient.
    pub agent: Option<&'a str>,
    /// "Everything that is mine", for a holder of this name — the
    /// participation rule `auth::owns_name` states, as a filter. A bare ACCOUNT (`bob`) holds its own name and every name
    /// under it (`bob/self-bob`, `bob/frontier-smoke`); a
    /// CONNECTION (`bob/codex`) holds exactly itself. The thread arm
    /// follows the same rule: a `thread` post is visible when any name the
    /// holder owns took part in the thread.
    ///
    /// This is THE definition of "you" for a non-privileged reader; the
    /// HTTP inbox and the loop's native inbox both set it and neither
    /// spells the clause itself. Before it, the loop matched one exact
    /// name and the HTTP inbox another.
    pub owner: Option<&'a str>,
    /// Messages where the sender OR recipient lives on this node
    /// (`<node>/…`) — the view a node-bound cluster caller gets.
    pub node_prefix: Option<&'a str>,
    pub from: Option<&'a str>,
    pub to: Option<&'a str>,
    pub thread: Option<&'a str>,
    pub kind: Option<&'a str>,
    /// Structured sender filters (phase 2).
    pub user: Option<&'a str>,
    pub node: Option<&'a str>,
    pub harness: Option<&'a str>,
    pub since: Option<chrono::DateTime<chrono::Utc>>,
    pub unread_only: bool,
    /// Whose unread it is. Read state is per READER (migration
    /// 075): a message is unread for `reader` until that reader acks it,
    /// whatever any sibling window did. `None` with `unread_only` falls
    /// back to the old whole-message `read_at` — only a privileged caller
    /// with no acting identity should reach that.
    pub reader: Option<&'a str>,
    pub limit: i64,
}

/// A row as the API returns it. Sealed bodies are OPENED here with the
/// review key (this is the gateway; callers have already been authorised
/// by the route) — `enc` tells the reader how the message travelled:
/// `none` (plaintext), `sealed` (gateway-sealed, opened for you), `e2e`
/// (also wrapped to the recipient's own key). If the review key cannot
/// open it, the ciphertext is returned and `enc` gains `:closed`.
fn row_json(r: &sqlx::postgres::PgRow) -> Value {
    use sqlx::Row;
    let enc: String = r.get("enc");
    let raw_body: Value = r.get("body");
    let enc_meta: Option<Value> = r.get("enc_meta");
    let aad = crate::agent_messages::envelope_aad(
        &r.get::<String, _>("id"),
        &r.get::<String, _>("thread_id"),
        &r.get::<String, _>("from_agent"),
        &r.get::<String, _>("to_agent"),
        &r.get::<String, _>("kind"),
    );
    let (body, enc_out) = match crate::agent_messages::open_body(&enc, &raw_body, enc_meta.as_ref(), &aad) {
        Ok(b) => (b, enc.clone()),
        Err(_) => (raw_body, format!("{enc}:closed")),
    };
    json!({
        "id": r.get::<String, _>("id"),
        "thread_id": r.get::<String, _>("thread_id"),
        "from": r.get::<String, _>("from_agent"),
        "to": r.get::<String, _>("to_agent"),
        "kind": r.get::<String, _>("kind"),
        "body": body,
        "refs": r.get::<Value, _>("refs"),
        "ts": r.get::<chrono::DateTime<chrono::Utc>, _>("ts").to_rfc3339(),
        "delivered_at": r.get::<Option<chrono::DateTime<chrono::Utc>>, _>("delivered_at").map(|t| t.to_rfc3339()),
        "read_at": r.get::<Option<chrono::DateTime<chrono::Utc>>, _>("read_at").map(|t| t.to_rfc3339()),
        "received_at": r.get::<chrono::DateTime<chrono::Utc>, _>("received_at").to_rfc3339(),
        "sig_verified": r.get::<bool, _>("sig_verified"),
        "enc": enc_out,
        "from_id": {
            "user": r.get::<Option<String>, _>("from_user"),
            "node": r.get::<Option<String>, _>("from_node"),
            "harness": r.get::<Option<String>, _>("from_harness"),
        },
        "to_id": {
            "user": r.get::<Option<String>, _>("to_user"),
            "node": r.get::<Option<String>, _>("to_node"),
            "harness": r.get::<Option<String>, _>("to_harness"),
        },
    })
}

/// One exact name: what it sent or received, plus thread-addressed posts in
/// threads it took part in.
const AGENT_CLAUSE: &str = " AND (from_agent = $N OR to_agent = $N OR (to_agent = 'thread' AND thread_id IN \
    (SELECT thread_id FROM noo_agent_messages WHERE from_agent = $N OR to_agent = $N)))";

/// An ACCOUNT's view: [`AGENT_CLAUSE`] widened from one name to the name
/// and everything under `<name>/`. `starts_with` rather than `LIKE`, so a
/// `_` or `%` in a name needs no escaping and cannot become a wildcard.
/// The bind is the account; `$N` repeats because it is the same value.
fn owner_clause() -> String {
    let mine = |col: &str| format!("{col} = $N OR starts_with({col}, $N::text || '/')");
    format!(
        " AND (({f}) OR ({t}) OR (to_agent = 'thread' AND thread_id IN \
            (SELECT thread_id FROM noo_agent_messages WHERE ({f}) OR ({t}))))",
        f = mine("from_agent"),
        t = mine("to_agent"),
    )
}

/// Newest first. Every filter is optional; SQL built from fixed fragments
/// with positional binds — no interpolated values.
pub async fn list(db: &PgPool, f: &Filter<'_>) -> Result<Vec<Value>, sqlx::Error> {
    let mut sql = String::from(
        "SELECT id, thread_id, from_agent, to_agent, kind, body, refs, ts, delivered_at, read_at, enc, from_user, from_node, from_harness, to_user, to_node, to_harness, enc_meta, received_at, sig_verified \
         FROM noo_agent_messages WHERE 1=1",
    );
    let mut n = 0;
    let mut binds: Vec<String> = Vec::new();
    let mut push = |sql: &mut String, clause: &str, v: &str| {
        n += 1;
        sql.push_str(&clause.replace("$N", &format!("${n}")));
        binds.push(v.to_string());
    };
    // An agent's view: what it sent or received, plus thread-addressed
    // posts in threads it took part in.
    if let Some(a) = f.agent {
        push(&mut sql, AGENT_CLAUSE, a);
    }
    if let Some(o) = f.owner {
        // A connection owns exactly itself (the `agent` clause); an
        // account owns its name and everything under it.
        push(&mut sql, &owner_scope_clause(o), o);
    }
    if let Some(node) = f.node_prefix {
        // LIKE with the node name escaped (`_` and `%` are wildcards).
        let pat = format!("{}/%", node.replace('\\', "\\\\").replace('_', "\\_").replace('%', "\\%"));
        push(&mut sql, " AND (from_agent LIKE $N ESCAPE '\\' OR to_agent LIKE $N ESCAPE '\\')", &pat);
    }
    if let Some(v) = f.from { push(&mut sql, " AND from_agent = $N", v); }
    if let Some(v) = f.to { push(&mut sql, " AND to_agent = $N", v); }
    if let Some(v) = f.thread { push(&mut sql, " AND thread_id = $N", v); }
    if let Some(v) = f.kind { push(&mut sql, " AND kind = $N", v); }
    if let Some(v) = f.user { push(&mut sql, " AND from_user = $N", v); }
    if let Some(v) = f.node { push(&mut sql, " AND from_node = $N", v); }
    if let Some(v) = f.harness { push(&mut sql, " AND from_harness = $N", v); }
    let since_idx = f.since.map(|_| { n += 1; sql.push_str(&format!(" AND ts >= ${n}")); n });
    // Past this point `push` is not used again: `since_idx` above touched
    // `n` directly, so the closure's borrow is over and the unread clause
    // binds by hand rather than re-borrowing it.
    let reader_idx = match (f.unread_only, f.reader) {
        (true, Some(_)) => {
            n += 1;
            sql.push_str(&format!(
                " AND NOT EXISTS (SELECT 1 FROM noo_agent_message_reads x \
                   WHERE x.message_id = noo_agent_messages.id AND x.reader = ${n})"
            ));
            Some(n)
        }
        (true, None) => {
            sql.push_str(" AND read_at IS NULL");
            None
        }
        _ => None,
    };
    n += 1;
    sql.push_str(&format!(" ORDER BY ts DESC LIMIT ${n}"));
    let mut q = sqlx::query(sqlx::AssertSqlSafe(&*sql));
    for b in &binds { q = q.bind(b); }
    if let (Some(_), Some(s)) = (since_idx, f.since) { q = q.bind(s); }
    if let (Some(_), Some(r)) = (reader_idx, f.reader) { q = q.bind(r); }
    q = q.bind(f.limit.clamp(1, 1000));
    let rows = q.fetch_all(db).await?;
    Ok(rows.iter().map(row_json).collect())
}

pub async fn get(db: &PgPool, id: &str) -> Result<Option<Value>, sqlx::Error> {
    let row = sqlx::query(
        "SELECT id, thread_id, from_agent, to_agent, kind, body, refs, ts, delivered_at, read_at, enc, from_user, from_node, from_harness, to_user, to_node, to_harness, enc_meta, received_at, sig_verified \
         FROM noo_agent_messages WHERE id = $1",
    )
    .bind(id)
    .fetch_optional(db)
    .await?;
    Ok(row.as_ref().map(row_json))
}

/// Mark read FOR `reader` (and delivered if not yet) — the `ack` route.
///
/// Two writes, one transaction. The per-reader row is what unread is
/// computed from; the message's `read_at` is still set on the first ack
/// by anyone, because existing readers of that column mean "seen at all"
/// by it and nothing here should change what they see.
pub async fn mark_read(db: &PgPool, id: &str, reader: &str) -> Result<bool, sqlx::Error> {
    let mut tx = db.begin().await?;
    let res = sqlx::query(
        "UPDATE noo_agent_messages SET read_at = COALESCE(read_at, now()), \
             delivered_at = COALESCE(delivered_at, now()) WHERE id = $1",
    )
    .bind(id)
    .execute(&mut *tx)
    .await?;
    if res.rows_affected() == 0 {
        tx.rollback().await?;
        return Ok(false);
    }
    sqlx::query(
        "INSERT INTO noo_agent_message_reads (message_id, reader) VALUES ($1, $2) \
         ON CONFLICT (message_id, reader) DO NOTHING",
    )
    .bind(id)
    .bind(reader)
    .execute(&mut *tx)
    .await?;
    tx.commit().await?;
    Ok(true)
}

/// The clause for "mail that is mine" given the name a caller holds: a
/// connection (`account/label`) owns exactly itself, an account owns its
/// name and everything under `<name>/`. One definition, used by [`list`]
/// (`Filter::owner`) and [`threads`], so "mine" cannot drift between them.
fn owner_scope_clause(owner: &str) -> String {
    if owner.contains(crate::auth::CONNECTION_SEP) {
        AGENT_CLAUSE.to_string()
    } else {
        owner_clause()
    }
}

/// Threads: derived from the messages (no thread table). Newest activity
/// first. `agent` scopes to one exact name's view; `owner` to everything a
/// caller holds ([`owner_scope_clause`]); neither lists every thread.
pub async fn threads(db: &PgPool, agent: Option<&str>, owner: Option<&str>, limit: i64) -> Result<Vec<Value>, sqlx::Error> {
    use sqlx::Row;
    let scope = agent.or(owner);
    let clause = match (agent, owner) {
        (Some(_), _) => AGENT_CLAUSE.replace("$N", "$1"),
        (None, Some(o)) => owner_scope_clause(o).replace("$N", "$1"),
        (None, None) => " AND $1::text IS NULL".to_string(),
    };
    let sql = format!(
        "SELECT thread_id, COUNT(*) AS n, MIN(ts) AS started, MAX(ts) AS last, \
                array_agg(DISTINCT from_agent) AS senders, array_agg(DISTINCT to_agent) AS recipients \
         FROM noo_agent_messages WHERE 1=1{clause} \
         GROUP BY thread_id ORDER BY MAX(ts) DESC LIMIT $2"
    );
    let rows = sqlx::query(sqlx::AssertSqlSafe(&*sql))
        .bind(scope)
        .bind(limit.clamp(1, 500))
        .fetch_all(db)
        .await?;
    Ok(rows
        .iter()
        .map(|r| {
            json!({
                "thread_id": r.get::<String, _>("thread_id"),
                "messages": r.get::<i64, _>("n"),
                "started": r.get::<chrono::DateTime<chrono::Utc>, _>("started").to_rfc3339(),
                "last": r.get::<chrono::DateTime<chrono::Utc>, _>("last").to_rfc3339(),
                "senders": r.get::<Vec<String>, _>("senders"),
                "recipients": r.get::<Vec<String>, _>("recipients"),
            })
        })
        .collect())
}


/// Default retention for the message record ( piece,
/// shipped with phase 4). Sealed bodies are still bytes on disk. Past this
/// window a row is archived (still sealed) to cold storage by
/// `agent_mail_archive` before it is deleted.
pub const RETENTION_DAYS: i64 = 90;

pub async fn count_expired(db: &PgPool, days: i64) -> Result<i64, sqlx::Error> {
    sqlx::query_scalar("SELECT COUNT(*) FROM noo_agent_messages WHERE received_at < now() - make_interval(days => $1::int)")
        .bind(days as i32)
        .fetch_one(db)
        .await
}

/// Delete exactly these messages. Retention calls it with the ids it has
/// just archived and verified, never with the age predicate, so a row that
/// was not archived cannot be deleted by it. Read receipts go with them (FK
/// cascade).
pub async fn delete_ids(db: &PgPool, ids: &[String]) -> Result<u64, sqlx::Error> {
    let res = sqlx::query("DELETE FROM noo_agent_messages WHERE id = ANY($1)")
        .bind(ids)
        .execute(db)
        .await?;
    Ok(res.rows_affected())
}

/// Is `sender` on `agent`'s trust list?
///
/// The list holds EXCEPTIONS only — identities outside the agent's own
/// owner that it will nonetheless accept. The default (an identity the
/// owner holds) is answered by `auth::owns_name` without touching the
/// database, so the common case costs no query at all.
///
/// An entry may name an account or one connection. An account entry
/// covers every connection under it, by the same prefix rule that governs
/// ownership — trusting a person is one row, not one per window they have
/// open. The comparison is therefore `owns_name(entry, sender)`, not
/// string equality, and it is done in SQL against the small per-agent set
/// rather than by loading the table.
pub async fn is_trusted(db: &PgPool, agent: &str, sender: &str) -> Result<bool, sqlx::Error> {
    let entries: Vec<(String,)> =
        sqlx::query_as("SELECT allowed FROM noo_agent_trust WHERE agent = $1")
            .bind(agent)
            .fetch_all(db)
            .await?;
    Ok(entries
        .iter()
        .any(|(allowed,)| crate::auth::owns_name(allowed, sender)))
}

#[cfg(test)]
mod owner_tests {
    use super::*;

    /// Evaluate the clause the way Postgres would, over `(from, to,
    /// thread members)`, by substituting the account and reading the same
    /// `col = $ OR starts_with(col, $ || '/')` terms. Not a SQL engine: it
    /// pins that the clause is built from those terms for BOTH `from` and
    /// `to`, in the outer query and in the thread sub-select.
    fn terms(sql: &str) -> usize {
        sql.matches("starts_with(").count()
    }

    #[test]
    fn thread_listing_reuses_the_one_definition_of_mine() {
        assert_eq!(owner_scope_clause("bob"), owner_clause());
        assert_eq!(owner_scope_clause("bob/laptop"), AGENT_CLAUSE);
        let src = include_str!("agent_messages.rs");
        let body = src.split("pub async fn threads(").nth(1).expect("threads fn");
        assert!(body.contains("owner_scope_clause(o)"), "threads must reuse the owner clause");
    }

    #[test]
    fn the_owner_clause_covers_from_to_and_the_thread_members() {
        let sql = owner_clause();
        // from + to in the outer query, from + to in the thread sub-select.
        assert_eq!(terms(&sql), 4, "{sql}");
        assert!(sql.contains("to_agent = 'thread' AND thread_id IN"), "{sql}");
        assert!(sql.contains("starts_with(from_agent, $N::text || '/')"), "{sql}");
        assert!(sql.contains("starts_with(to_agent, $N::text || '/')"), "{sql}");
        assert!(!sql.contains("LIKE"), "no wildcard to escape: {sql}");
        assert!(!sql.contains('{'), "unformatted placeholder: {sql}");
    }

    /// The scenario, against the rule the clause renders
    /// (`auth::owns_name`, which the clause's `= acct OR starts_with(acct/)`
    /// is the SQL spelling of): a loop that reads as `bob` sees a direct
    /// message to `bob`, one to `bob/other`, and a `thread` post in a
    /// thread where `bob` posted; it does not see `alice`'s.
    #[test]
    fn an_account_reader_sees_its_names_and_its_threads_not_a_strangers() {
        let owns = |holder: &str, name: &str| crate::auth::owns_name(holder, name);
        for holder in ["bob", "bob/harness-node-a"] {
            // exact name is always mine
            assert!(owns(holder, holder));
            // another account's is never mine
            assert!(!owns(holder, "alice"));
            assert!(!owns(holder, "alice/bob"));
        }
        assert!(owns("bob", "bob/other"), "an account holds its connections");
        assert!(owns("bob", "bob"));
        assert!(!owns("bob/harness-node-a", "bob/other"), "a connection holds exactly itself");
        assert!(!owns("bob/harness-node-a", "bob"));
        assert!(!owns("bob", "bobe"), "a prefix of the string is not a prefix of the name");
        // The list() dispatch: a compound holder takes the exact clause.
        assert!("bob/harness-node-a".contains(crate::auth::CONNECTION_SEP));
        assert!(!"bob".contains(crate::auth::CONNECTION_SEP));
    }
}
