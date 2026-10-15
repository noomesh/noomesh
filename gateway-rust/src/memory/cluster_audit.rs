// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 PersonifAI LLC

//! Read-only audit of how knowledge-graph clusters mix audiences
//! ("Per-audience clustering": the measure-first step).
//!
//! Clusters are global: clustering runs over every edge, whoever may read the
//! documents behind it. The design weighs clustering per
//! audience tier against the interim "readable members, neutral label" rule
//! in [`super::scope::clusters`]. Which one is worth building depends on how
//! mixed the real clusters are, and nothing measured that. This does.
//!
//! ## What is measured
//!
//! A member entity's TIERS are the union of `docs.metadata.roles` over every
//! document it is mentioned in (`mentions -> pages -> docs`, the same
//! provenance chain the scoped reads use). A document with no tag (absent,
//! null, `[]`) contributes `untagged`; an entity with no mention at all has no
//! provenance and counts as `untagged` too (and is counted separately as
//! `no_provenance_members`). A member with exactly one distinct tier is
//! SINGLE-tier, anything else is MULTI-tier. Purity compares the raw tags, so a
//! cluster of `user:a` members plus `user:b` members is `mixed`: a cannot read
//! b's.
//!
//! Display folds every `user:<account>` into `user:*` with a distinct-user
//! count. An account name is never returned. `team:<name>` is kept per team.
//!
//! Readability for the hypothetical reader `{company, system}` (what a non-admin
//! with no teams is) reuses [`DOC_VISIBLE`], the predicate every scoped read is
//! built on, so this cannot disagree with `scope::clusters`; a test pins the
//! two together.
//!
//! ## Cost
//!
//! Two aggregate statements and a scalar one, no per-cluster round trips. See
//! [`ENTITY_TIERS_SQL`]; it reads each clustered entity's DISTINCT documents
//! once and groups the result by (cluster, tier signature), so the rows that
//! come back are a few per cluster, not one per entity.

use std::collections::{BTreeMap, BTreeSet, HashSet};

use chrono::{DateTime, Utc};
use serde_json::{json, Value};
use sqlx::PgPool;

use super::scope::DOC_VISIBLE;

/// The hypothetical restricted reader the buckets are computed for: a non-admin
/// with no team grants (`user:<self>` is irrelevant, it reads only its own).
pub const READER_ROLES: [&str; 2] = ["company", "system"];

/// Above this share of clustered entities coming ONLY from untagged documents
/// the mix numbers mostly measure missing tags, so the caveat says to
/// backfill and retag first.
pub const UNTAGGED_CAVEAT_FRACTION: f64 = 0.25;

/// Below this share of all entities being clustered at all, the audit speaks
/// for a minority of the graph (only entities with an edge are clustered).
pub const COVERAGE_CAVEAT_FRACTION: f64 = 0.5;

/// (cluster_id, name, level, parent_cluster_id, member_count, generation, computed_at)
pub type HeadRow = (String, String, i32, Option<String>, i32, i32, Option<DateTime<Utc>>);
/// (cluster_id, tiers, readable, has_doc, members): members of one cluster that
/// share the same tier signature.
pub type SigRow = (String, Vec<String>, bool, bool, i64);

const HEADS_SQL: &str = "SELECT cluster_id::text, name, level, parent_cluster_id::text, \
     member_count, generation, computed_at FROM entity_clusters";

/// `$1` = the reader's role set (the only parameter).
///
/// EXPLAIN ANALYZE shape, postgres 16, synthetic 42,110 entities / 168K
/// mentions / 60K pages / 3K docs / 250 clusters: no nested loops, 0.69 s with
/// EVERY entity clustered (worst case; 0.23 s with 3,882 clustered, the live
/// size). Reading it bottom-up: one seq scan of `docs` (the role predicate runs
/// once per DOCUMENT and is unnested to a few `(doc, tier)` rows), mentions and
/// pages hash-joined and semi-joined to the clustered entity set, a HashAggregate
/// to DISTINCT `(entity, doc)`, a hash join back to the membership rows, a sort
/// + GroupAggregate to one tier signature per member, and a final
/// GroupAggregate to `(cluster, signature)` counts: a few rows per cluster come
/// back, not one per entity.
///
/// The shape matters: an earlier version joined a per-entity aggregate CTE back
/// to the membership rows, the planner guessed 200 rows for the aggregate
/// instead of 42,110 and picked a nested loop (156 s at 42K). Aggregating over
/// the membership rows directly leaves it nothing to misjudge.
pub const ENTITY_TIERS_SQL_BODY: &str = "doc_tiers AS ( \
        SELECT d.doc_id, \
               CASE WHEN jsonb_typeof(d.metadata->'roles') = 'array' \
                         AND jsonb_array_length(d.metadata->'roles') > 0 \
                    THEN ARRAY(SELECT jsonb_array_elements_text(d.metadata->'roles')) \
                    WHEN jsonb_typeof(d.metadata->'roles') = 'string' \
                    THEN ARRAY[d.metadata->>'roles'] \
                    ELSE ARRAY['untagged']::text[] END AS tiers, \
               {VISIBLE} AS readable \
        FROM docs d), \
     doc_tier_rows AS (SELECT dt.doc_id, dt.readable, t.tier \
                       FROM doc_tiers dt CROSS JOIN LATERAL unnest(dt.tiers) AS t(tier)), \
     entity_docs AS ( \
        SELECT DISTINCT mn.entity_id, p.doc_id \
        FROM mentions mn JOIN pages p ON p.page_id = mn.page_id \
        WHERE mn.entity_id IN (SELECT entity_id FROM entity_cluster_members)), \
     per_member AS ( \
        SELECT m.cluster_id, m.entity_id, \
               COALESCE(array_agg(DISTINCT r.tier) FILTER (WHERE r.tier IS NOT NULL), ARRAY[]::text[]) AS tiers, \
               COALESCE(bool_or(r.readable), false) AS readable, \
               COUNT(r.doc_id) > 0 AS has_doc \
        FROM entity_cluster_members m \
        LEFT JOIN entity_docs ed ON ed.entity_id = m.entity_id \
        LEFT JOIN doc_tier_rows r ON r.doc_id = ed.doc_id \
        GROUP BY m.cluster_id, m.entity_id) \
     SELECT cluster_id::text, tiers, readable, has_doc, COUNT(*) \
     FROM per_member GROUP BY cluster_id, tiers, readable, has_doc";

fn entity_tiers_sql() -> String {
    format!("WITH {}", ENTITY_TIERS_SQL_BODY.replace("{VISIBLE}", DOC_VISIBLE))
}

/// Everything the audit reads, before it is folded.
pub struct RawAudit {
    pub heads: Vec<HeadRow>,
    pub sigs: Vec<SigRow>,
    pub total_entities: i64,
    pub clustered_entities: i64,
}

/// Run the audit statements. Read-only.
pub async fn fetch(db: &PgPool) -> Result<RawAudit, sqlx::Error> {
    let reader: Vec<String> = READER_ROLES.iter().map(|s| s.to_string()).collect();
    let heads: Vec<HeadRow> = sqlx::query_as(HEADS_SQL).fetch_all(db).await?;
    let sigs: Vec<SigRow> = sqlx::query_as(sqlx::AssertSqlSafe(&*entity_tiers_sql())).bind(&reader).fetch_all(db).await?;
    let (total_entities, clustered_entities): (i64, i64) = sqlx::query_as(
        "SELECT (SELECT COUNT(*) FROM entities), \
                (SELECT COUNT(DISTINCT entity_id) FROM entity_cluster_members)",
    )
    .fetch_one(db)
    .await?;
    Ok(RawAudit { heads, sigs, total_entities, clustered_entities })
}

/// The display bucket of one raw tier tag. `user:<account>` is folded so no
/// account name is ever returned.
pub fn tier_key(raw: &str) -> String {
    match raw {
        "company" | "system" | "generated" | "admin" | "untagged" => raw.to_string(),
        r if r.starts_with("team:") && r.len() > "team:".len() => r.to_string(),
        r if r.starts_with("user:") && r.len() > "user:".len() => "user:*".to_string(),
        _ => "other".to_string(),
    }
}

fn round4(x: f64) -> f64 {
    (x * 10_000.0).round() / 10_000.0
}

fn share(num: i64, den: i64) -> f64 {
    if den <= 0 {
        0.0
    } else {
        round4(num as f64 / den as f64)
    }
}

#[derive(Default)]
struct Acc {
    members: i64,
    single: i64,
    multi: i64,
    readable: i64,
    untagged_only: i64,
    no_provenance: i64,
    tiers: BTreeMap<String, i64>,
    raw: BTreeSet<String>,
    users: HashSet<String>,
}

/// Fold the raw rows into the audit document. `limit` caps the per-cluster
/// list (largest first); the summary always covers every cluster.
pub fn build(raw: RawAudit, limit: usize) -> Value {
    let RawAudit { heads, sigs, total_entities, clustered_entities } = raw;

    let mut accs: BTreeMap<String, Acc> = BTreeMap::new();
    for (cid, tiers, readable, has_doc, n) in sigs {
        let a = accs.entry(cid).or_default();
        let mut set: BTreeSet<String> = tiers.into_iter().collect();
        if set.is_empty() {
            set.insert("untagged".to_string());
        }
        let keys: BTreeSet<String> = set.iter().map(|t| tier_key(t)).collect();
        a.members += n;
        if set.len() == 1 {
            a.single += n;
        } else {
            a.multi += n;
        }
        if readable {
            a.readable += n;
        }
        if set.len() == 1 && set.contains("untagged") {
            a.untagged_only += n;
        }
        if !has_doc {
            a.no_provenance += n;
        }
        for k in keys {
            *a.tiers.entry(k).or_insert(0) += n;
        }
        for t in &set {
            if t.starts_with("user:") {
                a.users.insert(t.clone());
            }
        }
        a.raw.extend(set);
    }

    let head_of: BTreeMap<&str, &HeadRow> = heads.iter().map(|h| (h.0.as_str(), h)).collect();

    let mut clusters: Vec<Value> = Vec::new();
    let mut sort_keys: Vec<(i64, String)> = Vec::new();
    let mut by_mix: BTreeMap<String, i64> = BTreeMap::new();
    let mut distinct_tiers: BTreeMap<String, i64> = BTreeMap::new();
    let mut members_by_tier: BTreeMap<String, i64> = BTreeMap::new();
    let (mut whole, mut partial, mut none) = (0i64, 0i64, 0i64);
    let (mut all_members, mut all_untagged_only, mut all_no_prov) = (0i64, 0i64, 0i64);
    let (mut all_single, mut all_multi, mut all_readable) = (0i64, 0i64, 0i64);

    for (cid, a) in &accs {
        let Some(h) = head_of.get(cid.as_str()) else { continue };
        let mix = if a.multi == 0 && a.raw.len() == 1 {
            format!("pure:{}", tier_key(a.raw.iter().next().unwrap()))
        } else {
            "mixed".to_string()
        };
        let visibility = if a.readable == a.members {
            whole += 1;
            "whole"
        } else if a.readable == 0 {
            none += 1;
            "none"
        } else {
            partial += 1;
            "partial"
        };
        *by_mix.entry(mix.clone()).or_insert(0) += 1;
        *distinct_tiers.entry(a.raw.len().to_string()).or_insert(0) += 1;
        for (k, v) in &a.tiers {
            *members_by_tier.entry(k.clone()).or_insert(0) += v;
        }
        all_members += a.members;
        all_untagged_only += a.untagged_only;
        all_no_prov += a.no_provenance;
        all_single += a.single;
        all_multi += a.multi;
        all_readable += a.readable;

        let mut tiers = serde_json::Map::new();
        for (k, v) in &a.tiers {
            tiers.insert(k.clone(), json!(v));
        }
        let mut c = json!({
            "cluster_id": cid,
            "name": h.1,
            "level": h.2,
            "parent_cluster_id": h.3,
            "member_count": a.members,
            "stored_member_count": h.4,
            "mix": mix,
            "tiers": Value::Object(tiers),
            "distinct_tiers": a.raw.len(),
            "single_tier_members": a.single,
            "multi_tier_members": a.multi,
            "untagged_only_members": a.untagged_only,
            "readable_members": a.readable,
            "readable_share": share(a.readable, a.members),
            "reader_visibility": visibility,
        });
        if !a.users.is_empty() {
            c["distinct_users"] = json!(a.users.len());
        }
        sort_keys.push((a.members, cid.clone()));
        clusters.push(c);
    }

    // Largest first, id as the tiebreak, so the listing is stable.
    let mut order: Vec<usize> = (0..clusters.len()).collect();
    order.sort_by(|&x, &y| sort_keys[y].0.cmp(&sort_keys[x].0).then_with(|| sort_keys[x].1.cmp(&sort_keys[y].1)));
    let total_clusters = clusters.len();
    let truncated = total_clusters > limit;
    let listed: Vec<Value> = order.into_iter().take(limit).map(|i| clusters[i].clone()).collect();

    // ── run metadata ──
    let latest_generation = heads.iter().map(|h| h.5).max();
    let generations: BTreeSet<i32> = heads.iter().map(|h| h.5).collect();
    let computed_at = heads
        .iter()
        .filter(|h| Some(h.5) == latest_generation)
        .filter_map(|h| h.6)
        .max()
        .map(|t| t.to_rfc3339());
    let meta_clusters = heads.iter().filter(|h| h.2 > 0).count();
    let mut children: BTreeMap<&str, i64> = BTreeMap::new();
    for h in &heads {
        if let Some(p) = h.3.as_deref() {
            *children.entry(p).or_insert(0) += 1;
        }
    }
    let largest_meta_children = children.values().copied().max().unwrap_or(0);

    let untagged_fraction = share(all_untagged_only, all_members);
    let coverage = share(clustered_entities, total_entities);

    // ── caveats ──
    let mut caveats: Vec<String> = Vec::new();
    if total_clusters == 0 {
        caveats.push(
            "no clusters with members are stored: the graph has not been clustered, so there is \
             nothing to measure"
                .to_string(),
        );
    } else {
        if untagged_fraction >= UNTAGGED_CAVEAT_FRACTION {
            caveats.push(format!(
                "{:.0}% of clustered entities come only from untagged documents (or have no \
                 document at all), so most of this mix is missing tags, not a real audience \
                 split. The evaluation is premature: list the gap with `noo rag docs --untagged`, \
                 run the audience backfill and retag (`noo rag retag`), then re-run this audit",
                untagged_fraction * 100.0
            ));
        }
        if total_entities > 0 && coverage < COVERAGE_CAVEAT_FRACTION {
            caveats.push(format!(
                "only {:.0}% of entities are in a cluster ({clustered_entities} of \
                 {total_entities}); clustering covers entities with at least one edge, so this \
                 audit describes that part of the graph only",
                coverage * 100.0
            ));
        }
        if generations.len() > 1 {
            caveats.push(format!(
                "clusters from {} generations are stored; a clustering run may be in progress or \
                 may have stopped before removing the previous one",
                generations.len()
            ));
        }
    }

    json!({
        "run": {
            "latest_generation": latest_generation,
            "computed_at": computed_at,
            "generations_present": generations.len(),
            "clusters_stored": heads.len(),
            "meta_clusters": meta_clusters,
            "largest_meta_cluster_children": largest_meta_children,
        },
        "summary": {
            "total_clusters": total_clusters,
            "by_mix": by_mix,
            "reader": {
                "roles": READER_ROLES,
                "rule": "a cluster is shown whole only when every member is readable, partly (readable members, neutral label) when some are, and not at all when none are",
                "whole": whole,
                "partial": partial,
                "none": none,
                "readable_share_of_members": share(all_readable, all_members),
            },
            "distinct_tiers_per_cluster": distinct_tiers,
            "members_by_tier": members_by_tier,
            "single_tier_members": all_single,
            "multi_tier_members": all_multi,
            "coverage": {
                "entities_total": total_entities,
                "clustered_entities": clustered_entities,
                "clustered_share": coverage,
                "untagged_only_members": all_untagged_only,
                "untagged_only_fraction": untagged_fraction,
                "no_provenance_members": all_no_prov,
            },
        },
        "caveats": caveats,
        "clusters": listed,
        "truncated": truncated,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tiers_fold_to_display_buckets_and_never_carry_an_account_name() {
        for (raw, want) in [
            ("company", "company"),
            ("system", "system"),
            ("generated", "generated"),
            ("admin", "admin"),
            ("untagged", "untagged"),
            ("team:ops", "team:ops"),
            ("user:alice", "user:*"),
            ("user:", "other"),
            ("team:", "other"),
            ("user", "other"),
            ("whatever", "other"),
        ] {
            assert_eq!(tier_key(raw), want, "{raw}");
        }
    }

    fn head(id: &str, level: i32, parent: Option<&str>, gen: i32) -> HeadRow {
        (id.into(), format!("name-{id}"), level, parent.map(String::from), 0, gen, None)
    }

    #[test]
    fn an_empty_graph_says_there_is_nothing_to_measure_rather_than_reporting_zero_mixing() {
        let v = build(
            RawAudit { heads: vec![], sigs: vec![], total_entities: 100, clustered_entities: 0 },
            10,
        );
        assert_eq!(v["summary"]["total_clusters"], 0);
        let c = v["caveats"].as_array().unwrap();
        assert_eq!(c.len(), 1);
        assert!(c[0].as_str().unwrap().contains("has not been clustered"));
        assert!(v["run"]["latest_generation"].is_null());
    }

    #[test]
    fn the_coverage_and_generation_caveats_fire_on_their_own_and_the_list_is_capped_largest_first() {
        let sig = |c: &str, n: i64| (c.to_string(), vec!["company".to_string()], true, true, n);
        let v = build(
            RawAudit {
                heads: vec![head("a", 0, None, 1), head("b", 0, None, 2), head("m", 1, None, 2)],
                sigs: vec![sig("a", 3), sig("b", 5)],
                total_entities: 100,
                clustered_entities: 8,
            },
            1,
        );
        let caveats: Vec<&str> = v["caveats"].as_array().unwrap().iter().map(|c| c.as_str().unwrap()).collect();
        assert_eq!(caveats.len(), 2, "{caveats:?}");
        assert!(caveats.iter().any(|c| c.contains("8% of entities")));
        assert!(caveats.iter().any(|c| c.contains("2 generations")));
        assert_eq!(v["truncated"], true);
        assert_eq!(v["clusters"].as_array().unwrap().len(), 1);
        assert_eq!(v["clusters"][0]["cluster_id"], "b", "largest first");
        assert_eq!(v["summary"]["total_clusters"], 2, "the summary covers every cluster, not the page");
        assert_eq!(v["run"]["latest_generation"], 2);
        assert_eq!(v["run"]["meta_clusters"], 1);
    }

    // ── DB-backed ─────────────────────────────────────────────────────
    //
    // Runs when NOO_KB_AUDIENCE_TEST_DSN (or CI's NOO_BROKER_TEST_DSN) names a
    // Postgres, otherwise SKIPS, loudly (same pattern as `scope::tests`):
    //
    //   docker run -d --rm --name caudit-pg -e POSTGRES_PASSWORD=x -p 127.0.0.1::5432 postgres:16-alpine
    //   NOO_KB_AUDIENCE_TEST_DSN=postgres://postgres:x@127.0.0.1:<port>/postgres \
    //     cargo test --bin noo-gateway cluster_audit

    use crate::memory::scope;
    use std::collections::HashMap;

    fn dsn() -> Option<String> {
        ["NOO_KB_AUDIENCE_TEST_DSN", "NOO_BROKER_TEST_DSN"]
            .iter()
            .find_map(|k| std::env::var(k).ok().filter(|v| !v.is_empty()))
    }

    const DDL: &[&str] = &[
        "CREATE TABLE docs (doc_id uuid PRIMARY KEY, source_uri text, title text, hash text, \
         created_at timestamptz NOT NULL DEFAULT now(), metadata jsonb)",
        "CREATE TABLE pages (page_id uuid PRIMARY KEY, doc_id uuid NOT NULL, page_no int, text text)",
        "CREATE TABLE entities (entity_id uuid PRIMARY KEY, canonical_name text NOT NULL, \
         type text NOT NULL, aliases_json jsonb, created_at timestamptz NOT NULL DEFAULT now())",
        "CREATE TABLE mentions (mention_id uuid PRIMARY KEY DEFAULT gen_random_uuid(), \
         entity_id uuid NOT NULL, page_id uuid NOT NULL)",
        "CREATE TABLE edges (edge_id uuid PRIMARY KEY, src_entity_id uuid NOT NULL, \
         rel_type text NOT NULL, dst_entity_id uuid NOT NULL, evidence_json jsonb, \
         created_at timestamptz NOT NULL DEFAULT now(), confidence double precision DEFAULT 1.0)",
        "CREATE TABLE entity_clusters (cluster_id uuid PRIMARY KEY, name text NOT NULL, \
         level int NOT NULL DEFAULT 0, parent_cluster_id uuid, member_count int NOT NULL DEFAULT 0, \
         computed_at timestamptz NOT NULL DEFAULT now(), generation int NOT NULL DEFAULT 0)",
        "CREATE TABLE entity_cluster_members (entity_id uuid NOT NULL, cluster_id uuid NOT NULL, \
         membership_score double precision NOT NULL DEFAULT 1.0)",
    ];

    fn uid() -> String {
        uuid::Uuid::new_v4().to_string()
    }

    struct World {
        db: PgPool,
        schema: String,
    }

    async fn world() -> Option<World> {
        let dsn = dsn()?;
        let schema = format!("caudit_{}", uuid::Uuid::new_v4().simple());
        let s2 = schema.clone();
        let db = sqlx::postgres::PgPoolOptions::new()
            .max_connections(1)
            .after_connect(move |c, _| {
                let s = s2.clone();
                Box::pin(async move {
                    sqlx::query(sqlx::AssertSqlSafe(format!("SET search_path TO {s}"))).execute(&mut *c).await?;
                    Ok(())
                })
            })
            .connect(&dsn)
            .await
            .expect("connect to the DSN under test");
        sqlx::query(sqlx::AssertSqlSafe(format!("CREATE SCHEMA {schema}"))).execute(&db).await.unwrap();
        sqlx::query(sqlx::AssertSqlSafe(format!("SET search_path TO {schema}"))).execute(&db).await.unwrap();
        for ddl in DDL {
            sqlx::query(*ddl).execute(&db).await.unwrap();
        }
        Some(World { db, schema })
    }

    async fn add_doc(db: &PgPool, key: &str, meta: Value) -> String {
        let (doc, page) = (uid(), uid());
        sqlx::query("INSERT INTO docs (doc_id, source_uri, title, hash, metadata) VALUES ($1::uuid,$2,$3,$4,$5)")
            .bind(&doc).bind(format!("file:///{key}")).bind(format!("title-{key}")).bind(format!("h-{key}")).bind(&meta)
            .execute(db).await.unwrap();
        sqlx::query("INSERT INTO pages (page_id, doc_id, page_no) VALUES ($1::uuid,$2::uuid,1)")
            .bind(&page).bind(&doc).execute(db).await.unwrap();
        page
    }

    async fn add_entity(db: &PgPool, name: &str, pages: &[&String]) -> String {
        let id = uid();
        sqlx::query("INSERT INTO entities (entity_id, canonical_name, type) VALUES ($1::uuid,$2,'concept')")
            .bind(&id).bind(name).execute(db).await.unwrap();
        for p in pages {
            sqlx::query("INSERT INTO mentions (entity_id, page_id) VALUES ($1::uuid,$2::uuid)")
                .bind(&id).bind(p).execute(db).await.unwrap();
        }
        id
    }

    async fn add_cluster(db: &PgPool, name: &str, level: i32, parent: Option<&str>, gen: i32, members: &[String]) -> String {
        let id = uid();
        sqlx::query("INSERT INTO entity_clusters (cluster_id, name, level, parent_cluster_id, member_count, generation) \
                     VALUES ($1::uuid,$2,$3,$4::uuid,$5,$6)")
            .bind(&id).bind(name).bind(level).bind(parent).bind(members.len() as i32).bind(gen)
            .execute(db).await.unwrap();
        for m in members {
            sqlx::query("INSERT INTO entity_cluster_members (entity_id, cluster_id) VALUES ($1::uuid,$2::uuid)")
                .bind(m).bind(&id).execute(db).await.unwrap();
        }
        id
    }

    #[tokio::test]
    async fn cluster_audit_measures_the_mix_the_reader_buckets_and_the_untagged_gap_without_naming_accounts() {
        let Some(w) = world().await else {
            eprintln!("SKIPPED: set NOO_KB_AUDIENCE_TEST_DSN to run the DB-backed cluster audit test");
            return;
        };
        let db = &w.db;
        let p_co = add_doc(db, "co", json!({"roles": ["company"]})).await;
        let p_alice = add_doc(db, "alice", json!({"roles": ["user:alice"]})).await;
        let p_bob = add_doc(db, "bob", json!({"roles": ["user:bob"]})).await;
        let p_team = add_doc(db, "team", json!({"roles": ["team:ops"]})).await;
        let p_none = add_doc(db, "none", json!({})).await;
        let p_empty = add_doc(db, "empty", json!({"roles": []})).await;

        // cluster 1: pure company
        let c1: Vec<String> = vec![
            add_entity(db, "co1", &[&p_co]).await,
            add_entity(db, "co2", &[&p_co]).await,
            add_entity(db, "co3", &[&p_co]).await,
        ];
        // cluster 2: mixed company + two users; one member sits on company AND alice's doc
        let c2: Vec<String> = vec![
            add_entity(db, "mx1", &[&p_co]).await,
            add_entity(db, "mx2", &[&p_alice]).await,
            add_entity(db, "mx3", &[&p_bob]).await,
            add_entity(db, "mx4", &[&p_co, &p_alice]).await,
        ];
        // cluster 3: untagged only (no tag, empty tag, and no mention at all)
        let c3: Vec<String> = vec![
            add_entity(db, "un1", &[&p_none]).await,
            add_entity(db, "un2", &[&p_empty]).await,
            add_entity(db, "un3", &[]).await,
            add_entity(db, "un4", &[&p_none]).await,
        ];
        // cluster 4: a team
        let c4: Vec<String> = vec![
            add_entity(db, "tm1", &[&p_team]).await,
            add_entity(db, "tm2", &[&p_team]).await,
        ];
        // entities that are in no cluster
        for i in 0..5 {
            add_entity(db, &format!("loose{i}"), &[&p_co]).await;
        }
        let meta = add_cluster(db, "meta", 1, None, 3, &[]).await;
        add_cluster(db, "pure-company", 0, Some(&meta), 3, &c1).await;
        add_cluster(db, "mixed-company-users", 0, Some(&meta), 3, &c2).await;
        add_cluster(db, "untagged-only", 0, None, 3, &c3).await;
        add_cluster(db, "team-ops", 0, None, 3, &c4).await;

        let v = build(fetch(db).await.unwrap(), 100);
        let by_name: HashMap<String, Value> = v["clusters"]
            .as_array().unwrap().iter()
            .map(|c| (c["name"].as_str().unwrap().to_string(), c.clone()))
            .collect();

        // labels and per-cluster counts
        let pc = &by_name["pure-company"];
        assert_eq!(pc["mix"], "pure:company");
        assert_eq!(pc["tiers"], json!({"company": 3}));
        assert_eq!((pc["single_tier_members"].as_i64(), pc["multi_tier_members"].as_i64()), (Some(3), Some(0)));
        assert_eq!(pc["reader_visibility"], "whole");
        assert_eq!(pc["readable_share"], 1.0);
        assert_eq!(pc["parent_cluster_id"], json!(meta));

        let mx = &by_name["mixed-company-users"];
        assert_eq!(mx["mix"], "mixed");
        assert_eq!(mx["tiers"], json!({"company": 2, "user:*": 3}));
        assert_eq!(mx["distinct_users"], 2);
        assert_eq!(mx["distinct_tiers"], 3);
        assert_eq!((mx["single_tier_members"].as_i64(), mx["multi_tier_members"].as_i64()), (Some(3), Some(1)));
        assert_eq!(mx["readable_members"], 2);
        assert_eq!(mx["readable_share"], 0.5);
        assert_eq!(mx["reader_visibility"], "partial");

        let un = &by_name["untagged-only"];
        assert_eq!(un["mix"], "pure:untagged");
        assert_eq!(un["tiers"], json!({"untagged": 4}));
        assert_eq!(un["untagged_only_members"], 4);
        assert_eq!(un["reader_visibility"], "none");

        let tm = &by_name["team-ops"];
        assert_eq!(tm["mix"], "pure:team:ops");
        assert_eq!(tm["tiers"], json!({"team:ops": 2}));
        assert_eq!(tm["reader_visibility"], "none");
        assert!(tm.get("distinct_users").is_none());

        // summary
        let s = &v["summary"];
        assert_eq!(s["total_clusters"], 4, "the meta cluster has no members and is not audited");
        assert_eq!(
            s["by_mix"],
            json!({"mixed": 1, "pure:company": 1, "pure:team:ops": 1, "pure:untagged": 1})
        );
        assert_eq!(s["reader"]["roles"], json!(["company", "system"]));
        assert_eq!((s["reader"]["whole"].as_i64(), s["reader"]["partial"].as_i64(), s["reader"]["none"].as_i64()),
                   (Some(1), Some(1), Some(2)));
        assert_eq!(s["distinct_tiers_per_cluster"], json!({"1": 3, "3": 1}));
        assert_eq!(s["coverage"]["entities_total"], 18);
        assert_eq!(s["coverage"]["clustered_entities"], 13);
        assert_eq!(s["coverage"]["untagged_only_members"], 4);
        assert_eq!(s["coverage"]["no_provenance_members"], 1);
        assert_eq!(s["coverage"]["untagged_only_fraction"], 0.3077);

        // the untagged caveat triggers (4 of 13 > the threshold) and says what to do
        let caveats: Vec<&str> = v["caveats"].as_array().unwrap().iter().map(|c| c.as_str().unwrap()).collect();
        assert_eq!(caveats.len(), 1, "{caveats:?}");
        assert!(caveats[0].contains("premature") && caveats[0].contains("noo rag retag"), "{}", caveats[0]);

        // run metadata
        assert_eq!(v["run"]["latest_generation"], 3);
        assert_eq!(v["run"]["meta_clusters"], 1);
        assert_eq!(v["run"]["largest_meta_cluster_children"], 2);
        assert!(v["run"]["computed_at"].is_string());

        // no account name, no document title, no entity name leaves the audit
        let text = v.to_string();
        for leak in ["alice", "bob", "title-", "mx2", "co1"] {
            assert!(!text.contains(leak), "`{leak}` leaked: {text}");
        }

        // The buckets agree with what the real reader path serves: the same
        // `{company, system}` set through `scope::clusters` returns exactly the
        // whole + partial clusters, and keeps the stored name only for whole ones.
        let served = scope::clusters(db, &READER_ROLES.map(String::from), 0, 1, 50).await.unwrap();
        let names: BTreeSet<String> = served.iter().map(|r| r.1.clone()).collect();
        assert_eq!(served.len(), 2, "{served:?}");
        assert!(names.contains("pure-company"), "{names:?}");
        assert!(!names.contains("mixed-company-users") && !names.contains("untagged-only") && !names.contains("team-ops"));

        sqlx::query(sqlx::AssertSqlSafe(format!("DROP SCHEMA {} CASCADE", w.schema))).execute(db).await.unwrap();
    }

    use std::collections::BTreeSet;
}
