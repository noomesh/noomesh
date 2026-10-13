// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 PersonifAI LLC

//! Knowledge-graph reads — `entities`, `edges`.
//!
//! These are trellion-owned tables, and reading them from Rust is deliberate:
//! graph traversal is the hottest path in the database (`edges` 288M index
//! scans, `entities` 115M, against `noo_conversations` 15k) and must never
//! cross a network boundary. See `RUST_PYTHON_SPLIT.md` — the service boundary
//! is compute, not data.
//!
//! Consolidated because the degree CTE below appeared FOUR times in
//! `routes/knowledge.rs`: twice per call site, once with an entity-type filter
//! and once without, differing only in line wrapping. A four-way copy of a
//! whole-table aggregate is four places to forget when it needs an index.
//!
//! ## Why two statements rather than one with an optional filter
//!
//! The obvious consolidation is `($2::text IS NULL OR e.type = $2)`. That is
//! ONE statement but a worse plan: a nullable-parameter predicate is opaque to
//! the planner, so it cannot use `type` selectivity and the filter degrades to
//! a post-join scan. Keeping two `query!` branches preserves the exact plans
//! that ran before, which is the point of a refactor that is supposed to change
//! nothing. The duplication moves from four call sites to one function.

/// `(entity_id, canonical_name, type, degree)`.
pub type EntityDegree = (String, String, String, i64);

/// Top entities by degree — the count of edges where the entity is either
/// endpoint — optionally restricted to one entity type.
///
/// `min_degree` filters the aggregate, so callers asking for `>= 1` still pay
/// for the full `edges` scan; the CTE aggregates the whole table either way.
/// That is pre-existing behaviour and is preserved here, but it is the reason
/// this query is worth having in one place: an eventual materialised
/// degree table or partial index has exactly one call site to change.
///
/// The `!` suffixes are required, not decorative. `e.entity_id::text` is a cast
/// and `COUNT(*)` is an aggregate, and sqlx cannot prove either is non-NULL, so
/// it would otherwise hand back `Option<String>` / `Option<i64>`. Both are
/// total here: `entity_id` is `NOT NULL` and `COUNT` over a `GROUP BY` always
/// yields a row.
pub async fn top_entities_by_degree<'e, E>(
    db: E,
    min_degree: i32,
    entity_type: Option<&str>,
    limit: i32,
) -> Result<Vec<EntityDegree>, sqlx::Error>
where
    E: sqlx::PgExecutor<'e>,
{
    match entity_type {
        Some(etype) => {
            let rows = sqlx::query!(
                r#"WITH degrees AS (
                     SELECT entity_id, COUNT(*) AS deg FROM (
                       SELECT src_entity_id AS entity_id FROM edges
                       UNION ALL
                       SELECT dst_entity_id AS entity_id FROM edges
                     ) e GROUP BY entity_id
                   )
                   SELECT e.entity_id::text AS "entity_id!",
                          e.canonical_name, e.type, d.deg AS "deg!"
                   FROM entities e
                   JOIN degrees d ON e.entity_id = d.entity_id
                   WHERE d.deg >= $1 AND e.type = $2
                   ORDER BY d.deg DESC
                   LIMIT $3"#,
                i64::from(min_degree),
                etype,
                i64::from(limit),
            )
            .fetch_all(db)
            .await?;
            Ok(rows
                .into_iter()
                .map(|r| (r.entity_id, r.canonical_name, r.r#type, r.deg))
                .collect())
        }
        None => {
            let rows = sqlx::query!(
                r#"WITH degrees AS (
                     SELECT entity_id, COUNT(*) AS deg FROM (
                       SELECT src_entity_id AS entity_id FROM edges
                       UNION ALL
                       SELECT dst_entity_id AS entity_id FROM edges
                     ) e GROUP BY entity_id
                   )
                   SELECT e.entity_id::text AS "entity_id!",
                          e.canonical_name, e.type, d.deg AS "deg!"
                   FROM entities e
                   JOIN degrees d ON e.entity_id = d.entity_id
                   WHERE d.deg >= $1
                   ORDER BY d.deg DESC
                   LIMIT $2"#,
                i64::from(min_degree),
                i64::from(limit),
            )
            .fetch_all(db)
            .await?;
            Ok(rows
                .into_iter()
                .map(|r| (r.entity_id, r.canonical_name, r.r#type, r.deg))
                .collect())
        }
    }
}

/// One row of a neighbourhood traversal:
/// `(edge_id, src_entity_id, rel_type, dst_entity_id, evidence_json, depth)`.
pub type NeighborEdge = (String, String, String, String, Option<serde_json::Value>, i32);

/// Breadth-first neighbourhood around `entity_id`, up to `hops` deep,
/// optionally restricted to a set of relation types.
///
/// This is the single most expensive query in the system — a recursive CTE over
/// `edges`, which carries 288M index scans. It was duplicated as two near
/// identical 30-line CTEs in `routes/knowledge.rs` differing only by
/// `AND e.rel_type = ANY(...)` in both the base and recursive terms, plus
/// parameter renumbering. Two copies of a recursive traversal is two places to
/// get the cycle guard wrong.
///
/// `visited` is the cycle guard: each row carries the array of entities already
/// reached on its path, and the join refuses to revisit them. That is why the
/// recursive term cannot be simplified to a plain `depth <` bound — dropping it
/// turns a cyclic graph into an infinite walk.
///
/// As with [`top_entities_by_degree`], the filtered and unfiltered forms stay
/// as two statements rather than one with `($n IS NULL OR ...)`: a
/// nullable-parameter predicate is opaque to the planner, and on the hottest
/// query in the database that is not a trade worth making silently.
///
/// The `::text` casts force `!` overrides — sqlx cannot prove a cast is
/// non-NULL. All four columns are `NOT NULL` in `edges`, so the assertion is
/// sound; `evidence_json` is genuinely nullable and stays `Option`.
///
/// `entity_id` is a real `Uuid`, not a string. The previous call site bound a
/// `String` against `$1::uuid` and relied on Postgres coercing it, so a
/// malformed id reached the database and came back as a 500. Parsing at the
/// edge turns that into a 400, which is a deliberate (small) behaviour change.
pub async fn neighbors<'e, E>(
    db: E,
    entity_id: uuid::Uuid,
    hops: i32,
    rel_types: Option<&[String]>,
) -> Result<Vec<NeighborEdge>, sqlx::Error>
where
    E: sqlx::PgExecutor<'e>,
{
    match rel_types {
        Some(types) => {
            let rows = sqlx::query!(
                r#"WITH RECURSIVE neighbors AS (
                     SELECT e.edge_id, e.src_entity_id, e.rel_type,
                            e.dst_entity_id, e.evidence_json,
                            1 AS depth,
                            ARRAY[e.src_entity_id, e.dst_entity_id] AS visited
                     FROM edges e
                     WHERE (e.src_entity_id = $1::uuid OR e.dst_entity_id = $1::uuid)
                       AND e.rel_type = ANY($2)
                     UNION ALL
                     SELECT e.edge_id, e.src_entity_id, e.rel_type,
                            e.dst_entity_id, e.evidence_json,
                            n.depth + 1,
                            n.visited || CASE
                                WHEN e.src_entity_id = ANY(n.visited)
                                THEN ARRAY[e.dst_entity_id]
                                ELSE ARRAY[e.src_entity_id]
                            END
                     FROM edges e
                     JOIN neighbors n ON (
                         (e.src_entity_id = n.dst_entity_id AND NOT e.dst_entity_id = ANY(n.visited))
                         OR
                         (e.dst_entity_id = n.src_entity_id AND NOT e.src_entity_id = ANY(n.visited))
                     )
                     WHERE n.depth < $3
                       AND e.rel_type = ANY($4)
                   )
                   SELECT DISTINCT edge_id::text AS "edge_id!",
                          src_entity_id::text AS "src_entity_id!",
                          rel_type AS "rel_type!",
                          dst_entity_id::text AS "dst_entity_id!",
                          evidence_json, depth
                   FROM neighbors
                   ORDER BY depth, edge_id::text"#,
                entity_id,
                types,
                hops,
                types,
            )
            .fetch_all(db)
            .await?;
            Ok(rows
                .into_iter()
                .map(|r| (r.edge_id, r.src_entity_id, r.rel_type, r.dst_entity_id,
                          r.evidence_json, r.depth.unwrap_or(0)))
                .collect())
        }
        None => {
            let rows = sqlx::query!(
                r#"WITH RECURSIVE neighbors AS (
                     SELECT e.edge_id, e.src_entity_id, e.rel_type,
                            e.dst_entity_id, e.evidence_json,
                            1 AS depth,
                            ARRAY[e.src_entity_id, e.dst_entity_id] AS visited
                     FROM edges e
                     WHERE (e.src_entity_id = $1::uuid OR e.dst_entity_id = $1::uuid)
                     UNION ALL
                     SELECT e.edge_id, e.src_entity_id, e.rel_type,
                            e.dst_entity_id, e.evidence_json,
                            n.depth + 1,
                            n.visited || CASE
                                WHEN e.src_entity_id = ANY(n.visited)
                                THEN ARRAY[e.dst_entity_id]
                                ELSE ARRAY[e.src_entity_id]
                            END
                     FROM edges e
                     JOIN neighbors n ON (
                         (e.src_entity_id = n.dst_entity_id AND NOT e.dst_entity_id = ANY(n.visited))
                         OR
                         (e.dst_entity_id = n.src_entity_id AND NOT e.src_entity_id = ANY(n.visited))
                     )
                     WHERE n.depth < $2
                   )
                   SELECT DISTINCT edge_id::text AS "edge_id!",
                          src_entity_id::text AS "src_entity_id!",
                          rel_type AS "rel_type!",
                          dst_entity_id::text AS "dst_entity_id!",
                          evidence_json, depth
                   FROM neighbors
                   ORDER BY depth, edge_id::text"#,
                entity_id,
                hops,
            )
            .fetch_all(db)
            .await?;
            Ok(rows
                .into_iter()
                .map(|r| (r.edge_id, r.src_entity_id, r.rel_type, r.dst_entity_id,
                          r.evidence_json, r.depth.unwrap_or(0)))
                .collect())
        }
    }
}
