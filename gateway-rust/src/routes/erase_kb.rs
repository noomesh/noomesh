// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 PersonifAI LLC

//! Right-to-be-forgotten for knowledge-base documents.
//!
//! A document's audience is `metadata.roles`, and an upload defaults to its
//! uploader alone (`user:<account>`, `workers/rag.py`). The row-keyed erase
//! targets in `users.rs` never looked at `docs`, so a user's private uploads
//! outlived the erase of their account. The rule here:
//!
//! * **Personal**: a document whose roles reduce to exactly `{user:<erased>}`
//!   (nothing left once that role is removed) is the user's own data. It is
//!   deleted with everything trellion keeps per document: pages, chunks, their
//!   embeddings and mentions (all `ON DELETE CASCADE` from `docs`), graph
//!   entities mentioned ONLY on those documents (cascading their embeddings,
//!   signals, cluster memberships and edges), and edges whose evidence came
//!   only from those documents. An edge also corroborated elsewhere keeps the
//!   other evidence and loses the personal one (the snippet is document text).
//! * **Shared** (a team, the org, admin, another user also in the audience, or
//!   untagged = everyone): the organisation's data and kept, with the erased
//!   identity scrubbed: `user:<erased>` leaves `roles`, `metadata.ingest.by`
//!   and the user's entries in `metadata.audience_history` are pseudonymised.
//!
//! Archive-then-delete like every other store: each row deleted or rewritten
//! is first copied to `noo_user_erasure_staging` under the erase's `run_id`.
//! The same [`plan`] answers the dry run, so the preview counts are the ones
//! the erase acts on. The KB's regenerable LLM response cache (`noo:cache:*`)
//! expires on its own five-minute TTL and is keyed by prompt hash, not by
//! document, so there is nothing to address there.

use serde_json::{json, Value};
use sqlx::PgConnection;

/// What an erased identity is replaced with where a record is kept.
pub(crate) const PSEUDONYM: &str = "erased-user";

/// Does this deployment have the knowledge-base tables at all? A mesh-only
/// database (and the ops tests' scratch one) has none: nothing to erase.
const KB_PRESENT_SQL: &str = "SELECT to_regclass('docs') IS NOT NULL";

/// `$1` = username. The document's roles, as an array, or `[]`.
const ROLES_ARRAY: &str =
    "(CASE WHEN jsonb_typeof(d.metadata->'roles') = 'array' THEN d.metadata->'roles' ELSE '[]'::jsonb END)";

/// Personal: `user:<erased>` is in the audience and nothing else is.
fn personal_where() -> String {
    format!(
        "(jsonb_exists({ROLES_ARRAY}, 'user:' || $1) \
          AND NOT EXISTS (SELECT 1 FROM jsonb_array_elements({ROLES_ARRAY}) r \
                          WHERE r <> to_jsonb('user:' || $1)))"
    )
}

/// The erased identity appears somewhere on the document: its audience, its
/// provenance (`ingest.by`) or its audience history.
fn touched_where() -> String {
    format!(
        "(jsonb_exists({ROLES_ARRAY}, 'user:' || $1) \
          OR d.metadata->'ingest'->>'by' = $1 \
          OR EXISTS (SELECT 1 FROM jsonb_array_elements( \
                       CASE WHEN jsonb_typeof(d.metadata->'audience_history') = 'array' \
                            THEN d.metadata->'audience_history' ELSE '[]'::jsonb END) h \
                     WHERE jsonb_typeof(h) = 'object' AND (h->>'by' = $1 \
                       OR (jsonb_typeof(h->'from') = 'array' AND jsonb_exists(h->'from', 'user:' || $1)) \
                       OR (jsonb_typeof(h->'to') = 'array' AND jsonb_exists(h->'to', 'user:' || $1)))))"
    )
}

/// Entities that exist only because of the personal documents: mentioned on
/// one of their pages and on no other page. `$1` = username, `$2` = the
/// personal doc ids (`text[]`). Another user's conversation entity
/// (`user_id` set to someone else) is never touched.
const DERIVED_ENTITIES_SQL: &str = "SELECT e.entity_id::text FROM entities e \
     WHERE (e.user_id IS NULL OR e.user_id = $1) \
       AND EXISTS (SELECT 1 FROM mentions m JOIN pages p ON p.page_id = m.page_id \
                   WHERE m.entity_id = e.entity_id AND p.doc_id::text = ANY($2::text[])) \
       AND NOT EXISTS (SELECT 1 FROM mentions m JOIN pages p ON p.page_id = m.page_id \
                       WHERE m.entity_id = e.entity_id AND NOT (p.doc_id::text = ANY($2::text[])))";

/// Edges that go: touching a derived entity, or evidenced only by personal
/// documents (the original evidence is, and the last corroboration — when
/// there is one — is too). `$1` = personal doc ids, `$2` = derived entity ids.
const EDGE_DELETE_WHERE: &str = "COALESCE( \
       src_entity_id::text = ANY($2::text[]) OR dst_entity_id::text = ANY($2::text[]) \
       OR (evidence_json->>'doc_id' = ANY($1::text[]) \
           AND (jsonb_typeof(evidence_json->'last_evidence') IS DISTINCT FROM 'object' \
                OR evidence_json->'last_evidence'->>'doc_id' = ANY($1::text[]))), false)";

/// Edges that stay but carry a personal document's evidence in one slot.
fn edge_scrub_where() -> String {
    format!(
        "(NOT {EDGE_DELETE_WHERE} \
          AND COALESCE(evidence_json->>'doc_id' = ANY($1::text[]) \
                       OR evidence_json->'last_evidence'->>'doc_id' = ANY($1::text[]), false))"
    )
}

/// Keep the evidence that is not the personal document's: the last
/// corroboration replaces a personal original; a personal last corroboration
/// is dropped.
const EDGE_SCRUB_SET: &str = "evidence_json = CASE \
       WHEN COALESCE(evidence_json->>'doc_id' = ANY($1::text[]), false) THEN evidence_json->'last_evidence' \
       ELSE evidence_json - 'last_evidence' - 'reinforced_at' END";

/// The documents and graph rows an erase of one user affects.
#[derive(Debug, Default)]
pub(crate) struct KbPlan {
    /// The KB tables exist on this deployment.
    pub present: bool,
    /// Personal documents (deleted), as text ids.
    pub personal: Vec<String>,
    /// Pages of the personal documents (deleted with them).
    pub pages: i64,
    /// Shared documents to scrub: `(doc_id, metadata)`.
    pub shared: Vec<(String, Value)>,
    /// Entities mentioned only on the personal documents (deleted).
    pub entities: Vec<String>,
    /// Edges deleted / edges whose evidence is rewritten.
    pub edges_deleted: i64,
    pub edges_scrubbed: i64,
}

impl KbPlan {
    /// The preview / result rows, in the erase's `{store, table, rows}` shape.
    /// `_scrub` stores are rewritten, not deleted.
    pub fn rows(&self) -> Vec<Value> {
        if !self.present {
            return Vec::new();
        }
        vec![
            json!({ "store": "kb_docs_personal", "table": "docs", "rows": self.personal.len() }),
            json!({ "store": "kb_pages_personal", "table": "pages", "rows": self.pages }),
            json!({ "store": "kb_entities_derived", "table": "entities", "rows": self.entities.len() }),
            json!({ "store": "kb_edges_derived", "table": "edges", "rows": self.edges_deleted }),
            json!({ "store": "kb_edges_scrub", "table": "edges", "rows": self.edges_scrubbed }),
            json!({ "store": "kb_docs_shared_scrub", "table": "docs", "rows": self.shared.len() }),
        ]
    }

    pub fn total(&self) -> i64 {
        self.personal.len() as i64
            + self.pages
            + self.entities.len() as i64
            + self.edges_deleted
            + self.edges_scrubbed
            + self.shared.len() as i64
    }

    /// Counts for the audit row.
    pub fn summary(&self) -> Value {
        json!({
            "personal_docs": self.personal.len(),
            "pages": self.pages,
            "entities": self.entities.len(),
            "edges_deleted": self.edges_deleted,
            "edges_scrubbed": self.edges_scrubbed,
            "shared_docs_scrubbed": self.shared.len(),
        })
    }
}

/// Work out what the erase of `username` does to the knowledge base. Run on
/// the pool for a dry run and inside the erase's transaction (with
/// `lock = true`, so the documents cannot change under it) for the real one.
pub(crate) async fn plan(conn: &mut PgConnection, username: &str, lock: bool) -> Result<KbPlan, sqlx::Error> {
    let present: bool = sqlx::query_scalar(KB_PRESENT_SQL).fetch_one(&mut *conn).await?;
    if !present {
        return Ok(KbPlan::default());
    }
    let for_update = if lock { " FOR UPDATE" } else { "" };
    let personal: Vec<String> = sqlx::query_scalar(&format!(
        "SELECT d.doc_id::text FROM docs d WHERE {}{for_update}",
        personal_where()
    ))
    .bind(username)
    .fetch_all(&mut *conn)
    .await?;
    let shared: Vec<(String, Option<Value>)> = sqlx::query_as(&format!(
        "SELECT d.doc_id::text, d.metadata FROM docs d WHERE {} AND NOT {}{for_update}",
        touched_where(),
        personal_where()
    ))
    .bind(username)
    .fetch_all(&mut *conn)
    .await?;
    let shared = shared.into_iter().map(|(id, m)| (id, m.unwrap_or_else(|| json!({})))).collect();
    let pages: i64 = sqlx::query_scalar("SELECT count(*) FROM pages WHERE doc_id::text = ANY($1::text[])")
        .bind(&personal)
        .fetch_one(&mut *conn)
        .await?;
    let entities: Vec<String> = sqlx::query_scalar(DERIVED_ENTITIES_SQL)
        .bind(username)
        .bind(&personal)
        .fetch_all(&mut *conn)
        .await?;
    let edges_deleted: i64 = sqlx::query_scalar(&format!("SELECT count(*) FROM edges WHERE {EDGE_DELETE_WHERE}"))
        .bind(&personal)
        .bind(&entities)
        .fetch_one(&mut *conn)
        .await?;
    let edges_scrubbed: i64 = sqlx::query_scalar(&format!("SELECT count(*) FROM edges WHERE {}", edge_scrub_where()))
        .bind(&personal)
        .bind(&entities)
        .fetch_one(&mut *conn)
        .await?;
    Ok(KbPlan { present, personal, pages, shared, entities, edges_deleted, edges_scrubbed })
}

/// Execute `plan` inside the erase's transaction: archive, then delete or
/// rewrite. Returns the `{store, table, rows}` result rows.
pub(crate) async fn apply(
    conn: &mut PgConnection,
    username: &str,
    run_id: uuid::Uuid,
    plan: &KbPlan,
) -> Result<Vec<Value>, sqlx::Error> {
    if !plan.present {
        return Ok(Vec::new());
    }
    let stage = |store: &str, from: &str, filter: &str| {
        format!(
            "INSERT INTO noo_user_erasure_staging (run_id, username, store, payload) \
             SELECT $3, $4, '{store}', to_jsonb(x) FROM {from} x WHERE {filter}"
        )
    };
    // `$1` = the ids, `$2` = run_id, `$3` = username.
    let stage_ids = |store: &str, from: &str, id_col: &str| {
        format!(
            "INSERT INTO noo_user_erasure_staging (run_id, username, store, payload) \
             SELECT $2, $3, '{store}', to_jsonb(x) FROM {from} x WHERE x.{id_col}::text = ANY($1::text[])"
        )
    };

    // Edges first (the archive must hold what the entity cascade would take).
    sqlx::query(&stage("kb_edges", "edges", EDGE_DELETE_WHERE))
        .bind(&plan.personal)
        .bind(&plan.entities)
        .bind(run_id)
        .bind(username)
        .execute(&mut *conn)
        .await?;
    let edges_deleted = sqlx::query(&format!("DELETE FROM edges WHERE {EDGE_DELETE_WHERE}"))
        .bind(&plan.personal)
        .bind(&plan.entities)
        .execute(&mut *conn)
        .await?
        .rows_affected();
    sqlx::query(&stage("kb_edges_scrubbed", "edges", &edge_scrub_where()))
        .bind(&plan.personal)
        .bind(&plan.entities)
        .bind(run_id)
        .bind(username)
        .execute(&mut *conn)
        .await?;
    let edges_scrubbed = sqlx::query(&format!("UPDATE edges SET {EDGE_SCRUB_SET} WHERE {}", edge_scrub_where()))
        .bind(&plan.personal)
        .bind(&plan.entities)
        .execute(&mut *conn)
        .await?
        .rows_affected();

    // Entities only the personal documents mention (cascade: their mentions,
    // embeddings, graph signals, cluster memberships).
    sqlx::query(&stage_ids("kb_entities", "entities", "entity_id"))
        .bind(&plan.entities)
        .bind(run_id)
        .bind(username)
        .execute(&mut *conn)
        .await?;
    let entities = sqlx::query("DELETE FROM entities WHERE entity_id::text = ANY($1::text[])")
        .bind(&plan.entities)
        .execute(&mut *conn)
        .await?
        .rows_affected();

    // The documents and their pages (cascade: chunks, page/chunk embeddings,
    // mentions). Pages carry the text; chunks and vectors are derived from it.
    for (store, table) in [("kb_pages", "pages"), ("kb_docs", "docs")] {
        sqlx::query(&stage_ids(store, table, "doc_id"))
            .bind(&plan.personal)
            .bind(run_id)
            .bind(username)
            .execute(&mut *conn)
            .await?;
    }
    let pages: i64 = sqlx::query_scalar("SELECT count(*) FROM pages WHERE doc_id::text = ANY($1::text[])")
        .bind(&plan.personal)
        .fetch_one(&mut *conn)
        .await?;
    let personal = sqlx::query("DELETE FROM docs WHERE doc_id::text = ANY($1::text[])")
        .bind(&plan.personal)
        .execute(&mut *conn)
        .await?
        .rows_affected();

    // Shared documents: archive the pre-image, write the scrubbed metadata.
    let mut scrubbed = 0u64;
    for (doc_id, meta) in &plan.shared {
        sqlx::query(
            "INSERT INTO noo_user_erasure_staging (run_id, username, store, payload) \
             SELECT $1, $2, 'kb_docs_scrubbed', to_jsonb(x) FROM docs x WHERE x.doc_id::text = $3",
        )
        .bind(run_id)
        .bind(username)
        .bind(doc_id)
        .execute(&mut *conn)
        .await?;
        scrubbed += sqlx::query("UPDATE docs SET metadata = $1 WHERE doc_id::text = $2")
            .bind(scrub_metadata(meta, username))
            .bind(doc_id)
            .execute(&mut *conn)
            .await?
            .rows_affected();
    }

    Ok(vec![
        json!({ "store": "kb_docs_personal", "table": "docs", "rows": personal }),
        json!({ "store": "kb_pages_personal", "table": "pages", "rows": pages }),
        json!({ "store": "kb_entities_derived", "table": "entities", "rows": entities }),
        json!({ "store": "kb_edges_derived", "table": "edges", "rows": edges_deleted }),
        json!({ "store": "kb_edges_scrub", "table": "edges", "rows": edges_scrubbed }),
        json!({ "store": "kb_docs_shared_scrub", "table": "docs", "rows": scrubbed }),
    ])
}

/// A shared document's metadata with `username` scrubbed out: `user:<name>`
/// removed from `roles`, `ingest.by` and the user's `audience_history`
/// entries pseudonymised. Everything else is untouched. Pure, so a test pins it.
pub(crate) fn scrub_metadata(meta: &Value, username: &str) -> Value {
    let role = format!("user:{username}");
    let pseudo_role = format!("user:{PSEUDONYM}");
    let mut out = meta.clone();
    let Some(obj) = out.as_object_mut() else { return out };
    if let Some(Value::Array(roles)) = obj.get_mut("roles") {
        roles.retain(|r| r.as_str() != Some(role.as_str()));
    }
    if let Some(Value::Object(ingest)) = obj.get_mut("ingest") {
        if ingest.get("by").and_then(Value::as_str) == Some(username) {
            ingest.insert("by".into(), json!(PSEUDONYM));
        }
    }
    if let Some(Value::Array(history)) = obj.get_mut("audience_history") {
        for entry in history.iter_mut().filter_map(Value::as_object_mut) {
            if entry.get("by").and_then(Value::as_str) == Some(username) {
                entry.insert("by".into(), json!(PSEUDONYM));
            }
            for side in ["from", "to"] {
                if let Some(Value::Array(rs)) = entry.get_mut(side) {
                    for r in rs.iter_mut() {
                        if r.as_str() == Some(role.as_str()) {
                            *r = json!(pseudo_role);
                        }
                    }
                }
            }
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn scrub_removes_the_role_and_pseudonymises_provenance_and_history() {
        let meta = json!({
            "roles": ["team:eng", "user:x", "user:y"],
            "ingest": {"by": "x", "via": "cli", "at": "t0"},
            "audience_history": [
                {"at": "t1", "by": "x", "from": ["user:x"], "to": ["team:eng", "user:x"]},
                {"at": "t2", "by": "root", "from": ["admin"], "to": ["user:y"]},
            ],
            "folder_path": "/a",
        });
        let out = scrub_metadata(&meta, "x");
        assert_eq!(out["roles"], json!(["team:eng", "user:y"]));
        assert_eq!(out["ingest"], json!({"by": PSEUDONYM, "via": "cli", "at": "t0"}));
        assert_eq!(out["audience_history"][0]["by"], PSEUDONYM);
        assert_eq!(out["audience_history"][0]["from"], json!(["user:erased-user"]));
        assert_eq!(out["audience_history"][0]["to"], json!(["team:eng", "user:erased-user"]));
        assert_eq!(out["audience_history"][1], meta["audience_history"][1], "another actor's entry is untouched");
        assert_eq!(out["folder_path"], "/a");
        assert!(!out.to_string().contains("\"x\"") && !out.to_string().contains("user:x\""), "{out}");
    }

    #[test]
    fn scrub_leaves_another_users_document_alone() {
        let meta = json!({"roles": ["user:xavier"], "ingest": {"by": "xavier"}});
        assert_eq!(scrub_metadata(&meta, "x"), meta, "a prefix of a name is not the name");
        assert_eq!(scrub_metadata(&json!(null), "x"), json!(null));
    }
    /// The rehearsal finding (v0.2.91-rc.3): user X's private upload outlived
    /// the erase of X. X ingests a private document and a team-shared one
    /// (rows as `workers/rag.py` + `kb_trace` write them); Y has their own.
    /// The preview counts what the erase then does: the private document, its
    /// page, chunk and embedding go, with the entity only it mentions and the
    /// edges only it evidences; the shared document stays with `user:X`
    /// removed and X pseudonymised; Y's document is untouched; everything
    /// deleted or rewritten is in the staging archive. Real `erase_account`
    /// on a migrated scratch database; skips without NOO_BROKER_TEST_DSN.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn rtbf_erases_a_users_private_kb_document_and_scrubs_the_shared_one() {
        let _serial = crate::ops::tests::DB_LOCK.lock().await;
        let Some(db) = crate::ops::tests::scratch("rtbf_kb_docs").await else { return };
        for ddl in [
            "CREATE TABLE docs (doc_id uuid PRIMARY KEY, source_uri text, title text, hash text UNIQUE, \
             created_at timestamptz NOT NULL DEFAULT now(), metadata jsonb DEFAULT '{}'::jsonb)",
            "CREATE TABLE pages (page_id uuid PRIMARY KEY, doc_id uuid NOT NULL REFERENCES docs(doc_id) ON DELETE CASCADE, \
             page_no int NOT NULL, text text NOT NULL)",
            "CREATE TABLE page_chunks (chunk_id uuid PRIMARY KEY, page_id uuid NOT NULL REFERENCES pages(page_id) ON DELETE CASCADE, \
             chunk_no int NOT NULL, text text NOT NULL)",
            "CREATE TABLE chunk_embeddings (chunk_id uuid PRIMARY KEY REFERENCES page_chunks(chunk_id) ON DELETE CASCADE, \
             embedding vector(3))",
            "CREATE TABLE entities (entity_id uuid PRIMARY KEY, canonical_name text NOT NULL, type text NOT NULL, user_id text)",
            "CREATE TABLE mentions (mention_id uuid PRIMARY KEY, entity_id uuid NOT NULL REFERENCES entities(entity_id) ON DELETE CASCADE, \
             page_id uuid NOT NULL REFERENCES pages(page_id) ON DELETE CASCADE, quote text)",
            "CREATE TABLE edges (edge_id uuid PRIMARY KEY, src_entity_id uuid NOT NULL REFERENCES entities(entity_id) ON DELETE CASCADE, \
             rel_type text NOT NULL, dst_entity_id uuid NOT NULL REFERENCES entities(entity_id) ON DELETE CASCADE, \
             evidence_json jsonb, user_id text)",
        ] {
            sqlx::query(ddl).execute(&db).await.unwrap();
        }
        crate::ops::tests::stub_erase_stores(&db).await;
        use crate::auth::Role;
        let _ = crate::ops::tests::account(&db, "xuser", Role::User).await;
        let _ = crate::ops::tests::account(&db, "yuser", Role::User).await;

        // (title, metadata, page text, entity names on the page)
        let docs = [
            ("private", json!({"roles": ["user:xuser"], "ingest": {"by": "xuser", "via": "cli", "at": "t0"}}),
             "PRIVATE-TEXT of xuser", vec!["Zorblax", "Acme"]),
            ("shared", json!({"roles": ["team:eng", "user:xuser"], "ingest": {"by": "xuser", "via": "cli", "at": "t0"},
                              "audience_history": [{"at": "t1", "by": "xuser", "from": ["user:xuser"], "to": ["team:eng", "user:xuser"]}]}),
             "team text", vec!["Acme", "Eng"]),
            ("yours", json!({"roles": ["user:yuser"], "ingest": {"by": "yuser", "via": "cli", "at": "t0"}}),
             "yuser text", vec!["Eng"]),
        ];
        let mut doc_ids = std::collections::HashMap::new();
        let mut entity_ids: std::collections::HashMap<&str, uuid::Uuid> = std::collections::HashMap::new();
        for (title, meta, text, ents) in &docs {
            let (d, p, c) = (uuid::Uuid::new_v4(), uuid::Uuid::new_v4(), uuid::Uuid::new_v4());
            sqlx::query("INSERT INTO docs (doc_id, title, hash, metadata) VALUES ($1, $2, $2, $3)")
                .bind(d).bind(*title).bind(meta).execute(&db).await.unwrap();
            sqlx::query("INSERT INTO pages (page_id, doc_id, page_no, text) VALUES ($1, $2, 1, $3)")
                .bind(p).bind(d).bind(*text).execute(&db).await.unwrap();
            sqlx::query("INSERT INTO page_chunks (chunk_id, page_id, chunk_no, text) VALUES ($1, $2, 0, $3)")
                .bind(c).bind(p).bind(*text).execute(&db).await.unwrap();
            sqlx::query("INSERT INTO chunk_embeddings (chunk_id, embedding) VALUES ($1, '[1,2,3]')")
                .bind(c).execute(&db).await.unwrap();
            for name in ents {
                let e = *entity_ids.entry(*name).or_insert_with(uuid::Uuid::new_v4);
                sqlx::query("INSERT INTO entities (entity_id, canonical_name, type) VALUES ($1, $2, 'org') ON CONFLICT DO NOTHING")
                    .bind(e).bind(*name).execute(&db).await.unwrap();
                sqlx::query("INSERT INTO mentions (mention_id, entity_id, page_id, quote) VALUES ($1, $2, $3, $4)")
                    .bind(uuid::Uuid::new_v4()).bind(e).bind(p).bind(*name).execute(&db).await.unwrap();
            }
            doc_ids.insert(*title, d);
        }
        let ev = |doc: &str, snippet: &str| json!({"source_type": "graph_edge", "doc_id": doc_ids[doc].to_string(), "snippet": snippet});
        // (src, rel, dst, evidence)
        let edges = [
            ("Zorblax", "RELATED_TO", "Acme", ev("private", "PRIVATE-TEXT")),       // goes with Zorblax
            ("Acme", "RELATED_TO", "Eng", ev("private", "PRIVATE-TEXT")),            // only the private doc evidences it
            ("Acme", "REFERENCES", "Eng", {                                            // corroborated by the shared doc
                let mut e = ev("private", "PRIVATE-TEXT");
                e["reinforced_at"] = json!("t2");
                e["last_evidence"] = ev("shared", "team text");
                e
            }),
            ("Acme", "PART_OF", "Eng", ev("shared", "team text")),                    // not X's: untouched
        ];
        for (s, rel, d, evidence) in &edges {
            sqlx::query("INSERT INTO edges (edge_id, src_entity_id, rel_type, dst_entity_id, evidence_json) VALUES ($1,$2,$3,$4,$5)")
                .bind(uuid::Uuid::new_v4()).bind(entity_ids[s]).bind(*rel).bind(entity_ids[d]).bind(evidence)
                .execute(&db).await.unwrap();
        }

        // The preview counts it all, and mutates nothing.
        let preview = crate::routes::users::erase_account(&db, "xuser", true, false).await.expect("preview");
        assert_eq!(
            preview["kb"],
            json!({"personal_docs": 1, "pages": 1, "entities": 1, "edges_deleted": 2, "edges_scrubbed": 1, "shared_docs_scrubbed": 1}),
            "{preview}"
        );
        let row = |v: &Value, store: &str| {
            v.as_array().unwrap().iter().find(|p| p["store"] == store).map(|p| p["rows"].as_i64().unwrap())
        };
        assert_eq!(row(&preview["plan"], "kb_docs_personal"), Some(1));
        assert_eq!(row(&preview["plan"], "kb_docs_shared_scrub"), Some(1));
        let n_docs: i64 = sqlx::query_scalar("SELECT count(*) FROM docs").fetch_one(&db).await.unwrap();
        assert_eq!(n_docs, 3, "a preview deletes nothing");

        let done = crate::routes::users::erase_account(&db, "xuser", false, false).await.expect("erase");
        assert_eq!(done["kb"], preview["kb"], "the erase does what the preview said");
        for store in ["kb_docs_personal", "kb_pages_personal", "kb_entities_derived", "kb_edges_derived", "kb_edges_scrub", "kb_docs_shared_scrub"] {
            assert_eq!(row(&done["deleted"], store), row(&preview["plan"], store), "{store}: {done}");
        }

        let strings = |sql: &'static str| {
            let db = db.clone();
            async move { sqlx::query_scalar::<_, String>(sql).fetch_all(&db).await.unwrap() }
        };
        assert_eq!(strings("SELECT title FROM docs ORDER BY 1").await, ["shared", "yours"], "the private doc is gone");
        assert_eq!(strings("SELECT text FROM pages ORDER BY 1").await, ["team text", "yuser text"]);
        assert_eq!(strings("SELECT text FROM page_chunks ORDER BY 1").await, ["team text", "yuser text"], "its chunks too");
        let emb: i64 = sqlx::query_scalar("SELECT count(*) FROM chunk_embeddings").fetch_one(&db).await.unwrap();
        assert_eq!(emb, 2, "and its embeddings");
        assert_eq!(strings("SELECT canonical_name FROM entities ORDER BY 1").await, ["Acme", "Eng"], "only the private doc named Zorblax");
        assert_eq!(strings("SELECT rel_type FROM edges ORDER BY 1").await, ["PART_OF", "REFERENCES"]);
        let leaked: i64 = sqlx::query_scalar("SELECT count(*) FROM edges WHERE evidence_json::text LIKE '%PRIVATE-TEXT%'")
            .fetch_one(&db).await.unwrap();
        assert_eq!(leaked, 0, "no edge keeps the private document's text as evidence");

        let shared: Value = sqlx::query_scalar("SELECT metadata FROM docs WHERE title = 'shared'").fetch_one(&db).await.unwrap();
        assert_eq!(shared["roles"], json!(["team:eng"]));
        assert_eq!(shared["ingest"]["by"], PSEUDONYM);
        assert!(!shared.to_string().contains("xuser"), "the shared doc no longer names xuser: {shared}");
        let yours: Value = sqlx::query_scalar("SELECT metadata FROM docs WHERE title = 'yours'").fetch_one(&db).await.unwrap();
        assert_eq!(yours, docs[2].1, "another user's document is untouched");

        let staged = strings("SELECT store FROM noo_user_erasure_staging WHERE username = 'xuser' AND store LIKE 'kb_%' ORDER BY 1").await;
        assert_eq!(staged, ["kb_docs", "kb_docs_scrubbed", "kb_edges", "kb_edges", "kb_edges_scrubbed", "kb_entities", "kb_pages"]);
        let archived = strings("SELECT payload->>'text' FROM noo_user_erasure_staging WHERE store = 'kb_pages'").await;
        assert_eq!(archived, ["PRIVATE-TEXT of xuser"], "archive-then-delete: the page text is recoverable from staging");
    }
}
