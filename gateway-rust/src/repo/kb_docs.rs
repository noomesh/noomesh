// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 PersonifAI LLC

//! Knowledge-base document reads — `docs`, `pages` (trellion-owned tables).
//!
//! One page of one document, for `GET /api/v1/docs/{doc_id}/pages/{page_no}`.
//! The audience is [`DOC_VISIBLE`], the constant every scoped document read
//! is built on (shared, never copied).
//!
//! Runtime-checked (`query_as`), like `scope::doc_detail`: the statement is
//! assembled around the shared predicate and a new `query!` would need the
//! `.sqlx` offline cache regenerated.

use crate::memory::scope::DOC_VISIBLE;

/// `(title, page count, the page exists, text cut to the caller's cap,
/// the page's real length in characters)`.
pub type DocPageRow = (Option<String>, i64, bool, Option<String>, Option<i32>);

/// One page of a document, if the caller may read the DOCUMENT. `roles =
/// None` is an operator (sees all). `None` is "missing or not readable"; a
/// row whose flag is false is a readable document without that page (only
/// then is the count safe to tell). A held document reads like it does in
/// `scope::doc_detail`: no hold filter. Read-only.
pub async fn doc_page<'e, E>(
    db: E,
    roles: Option<&[String]>,
    doc_id: &str,
    page_no: i32,
    max_chars: i32,
) -> Result<Option<DocPageRow>, sqlx::Error>
where
    E: sqlx::PgExecutor<'e>,
{
    let sql = format!(
        "SELECT d.title, \
                (SELECT COUNT(*) FROM pages c WHERE c.doc_id = d.doc_id), \
                (pg.page_id IS NOT NULL), \
                left(pg.text, $4), \
                length(pg.text) \
         FROM docs d LEFT JOIN pages pg ON pg.doc_id = d.doc_id AND pg.page_no = $3 \
         WHERE d.doc_id = $2::uuid AND ($1::text[] IS NULL OR {DOC_VISIBLE}) \
         ORDER BY pg.page_id LIMIT 1"
    );
    sqlx::query_as::<_, DocPageRow>(sqlx::AssertSqlSafe(&*sql))
        .bind(roles)
        .bind(doc_id)
        .bind(page_no)
        .bind(max_chars)
        .fetch_optional(db)
        .await
}
