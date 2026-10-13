# SPDX-License-Identifier: AGPL-3.0-only
# Copyright 2026 PersonifAI LLC

"""Audience-scoped concept graph for ``GET /api/snapshots/{id}/curriculum``.

What a snapshot is built from
-----------------------------
Not from knowledge-base documents directly. ``trellion.snapshots`` slices the
live TEMPORAL graph (``noo_entities_typed`` / ``noo_temporal_edges``, written by
conversation extraction and by document-derived facts), canonicalises it into
concepts, and records which live entity each concept came from
(``trellion_provenance.source_id``). So the knowledge-base ``metadata.roles``
predicate cannot be applied to a concept directly; ownership on this graph is:

* ``user_id`` on an entity or an edge, the person it is personal data OF
  (NULL = shared / system-owned, e.g. the agent's own state);
* ``source_page_id`` on an edge, for a fact drawn from a knowledge-base page.

The rule here is the temporal analogue of the knowledge-base one (entity =
at least one readable mention; edge = readable evidence) and is as strict:

* a temporal EDGE is readable by a restricted caller iff it is the caller's own
  (``user_id`` is one of the caller's ``user:<account>`` tags) OR it was drawn
  from a page on a document the caller can read (trellion's ``_ROLES_WHERE``,
  imported by reference, not restated). An edge with neither is unreadable:
  no provenance, no proof it is theirs (this is what keeps the agent's own
  self-model, ``user_id`` NULL and no page, out of every restricted view);
* a live ENTITY is readable iff it is the caller's own OR touches a readable
  edge;
* a CONCEPT is readable iff at least one entity it was built from is;
* a DAG edge is kept iff both concepts are readable AND a readable temporal
  edge joins an entity of one to an entity of the other (the build step only
  reduces / orients relations, it never invents one, so every DAG edge has such
  a source edge; the DAG edge itself records none).

A restricted caller's graph is therefore built from the readable concepts and
DAG edges only, with the same assembly the open loader does, so every
traversal the query router runs (prerequisites, paths, taxonomy listings,
shared neighbours) is a walk over readable nodes: nothing to route through,
nothing to count. Community names are ``L<level>.C<n>`` (generated, not LLM
labels) so they carry no text about members; their member lists are cut to the
readable concepts.

``roles`` None never gets here: the unrestricted path is ``get_cached_ckg``,
unchanged.
"""

from __future__ import annotations

from typing import Any

from sqlalchemy import text

def _roles_where() -> str:
    """trellion's document predicate (alias ``d``, parameter ``:roles``), by reference."""
    from trellion.live.pageindex_store import PageIndexStore

    return PageIndexStore._ROLES_WHERE


def own_user_ids(roles: "list[str]") -> "list[str]":
    """``user:<account>`` tags as the ids ``user_id`` may carry (bare or tagged)."""
    out: list[str] = []
    for r in roles:
        if r.startswith("user:") and len(r) > 5:
            out.extend([r[5:], r])
    return out


def _scope_sql() -> str:
    return f"""
    scoped_docs AS (SELECT d.doc_id FROM docs d WHERE {_roles_where()}),
    readable_edges AS (
        SELECT te.subject_id, te.object_entity_id
        FROM noo_temporal_edges te
        WHERE (te.user_id IS NOT NULL AND te.user_id = ANY(CAST(:uids AS text[])))
           OR (te.source_page_id IS NOT NULL AND EXISTS (
                SELECT 1 FROM pages p
                WHERE p.page_id = te.source_page_id
                  AND p.doc_id IN (SELECT doc_id FROM scoped_docs)))
    ),
    readable_entities AS (
        SELECT et.id AS entity_id FROM noo_entities_typed et
        WHERE et.user_id IS NOT NULL AND et.user_id = ANY(CAST(:uids AS text[]))
        UNION SELECT subject_id FROM readable_edges
        UNION SELECT object_entity_id FROM readable_edges WHERE object_entity_id IS NOT NULL
    ),
    readable_concepts AS (
        SELECT c.id, c.snapshot_id FROM trellion_concepts c
        WHERE c.snapshot_id = ANY(CAST(:sids AS uuid[])) AND EXISTS (
            SELECT 1 FROM trellion_provenance pr
            WHERE pr.snapshot_id = c.snapshot_id AND pr.concept_id = c.id
              AND pr.source_id IN (SELECT entity_id FROM readable_entities))
    ),
    readable_dag_edges AS (
        SELECT de.snapshot_id, de.src_concept_id, de.dst_concept_id, de.rel_type
        FROM trellion_dag_edges de
        WHERE de.snapshot_id = ANY(CAST(:sids AS uuid[]))
          AND de.src_concept_id IN (SELECT id FROM readable_concepts)
          AND de.dst_concept_id IN (SELECT id FROM readable_concepts)
          AND EXISTS (
              SELECT 1 FROM readable_edges re
              JOIN trellion_provenance ps
                ON ps.snapshot_id = de.snapshot_id
               AND ps.concept_id = de.src_concept_id
               AND ps.source_id IN (re.subject_id, re.object_entity_id)
              JOIN trellion_provenance pd
                ON pd.snapshot_id = de.snapshot_id
               AND pd.concept_id = de.dst_concept_id
               AND pd.source_id IN (re.subject_id, re.object_entity_id)
              WHERE ps.source_id <> pd.source_id)
    )
    """


def _params(snapshot_ids, roles: "list[str]") -> dict:
    ids = [snapshot_ids] if isinstance(snapshot_ids, str) else list(snapshot_ids)
    return {
        "sid": ids[0] if ids else None,
        "sids": ids,
        "roles": list(roles),
        "uids": own_user_ids(roles),
    }


async def readable_concepts(engine: Any, snapshot_id: str, roles: "list[str]") -> "list[tuple[str, str]]":
    """``(canonical_name, type)`` of the concepts of one snapshot ``roles`` may read.

    What ``POST /api/snapshots/diff`` diffs for a restricted caller: the same readable set the curriculum is built from.
    """
    async with engine.connect() as conn:
        rows = (
            await conn.execute(
                text(
                    "WITH " + _scope_sql()
                    + " SELECT c.canonical_name, c.type FROM trellion_concepts c "
                    "WHERE c.id IN (SELECT id FROM readable_concepts)"
                ),
                _params(snapshot_id, roles),
            )
        ).fetchall()
    return [(r[0], r[1]) for r in rows]


async def readable_counts(engine: Any, snapshot_ids: "list[str]", roles: "list[str]") -> "dict[str, dict]":
    """Per snapshot, how many concepts and DAG edges ``roles`` may read.

    One scope computation for the whole list, not one per snapshot. A snapshot
    the caller can read nothing of counts zero.
    """
    if not snapshot_ids:
        return {}
    async with engine.connect() as conn:
        rows = (
            await conn.execute(
                text(
                    "WITH " + _scope_sql()
                    + """ SELECT s.id::text,
                       (SELECT count(*) FROM readable_concepts rc WHERE rc.snapshot_id = s.id),
                       (SELECT count(*) FROM readable_dag_edges re WHERE re.snapshot_id = s.id)
                    FROM unnest(CAST(:sids AS uuid[])) AS s(id)"""
                ),
                _params(snapshot_ids, roles),
            )
        ).fetchall()
    return {r[0]: {"concepts": int(r[1]), "dag_edges": int(r[2])} for r in rows}


async def load_ckg_for_audience(engine: Any, snapshot_id: str, roles: "list[str]"):
    """A CKG holding only what ``roles`` may read of the snapshot.

    Same assembly as ``trellion.snapshots.ckg_adapter.load_ckg_from_snapshot``
    (kept deliberately line-for-line comparable; ``tests/test_snapshot_audience.py``
    pins the two to the same result when every concept is readable), with the
    concept, edge and community rows restricted first.
    """
    from trellion.query.graph import CKG, Concept

    def _norm(label: str) -> str:
        return " ".join(str(label).lower().split())

    params = _params(snapshot_id, roles)
    with_scope = "WITH " + _scope_sql()
    g = CKG()
    uuid_to_cid: dict[str, int] = {}

    async with engine.connect() as conn:
        concept_rows = (
            await conn.execute(
                text(
                    with_scope
                    + """
                SELECT c.id::text, c.canonical_name, c.type
                FROM trellion_concepts c
                WHERE c.id IN (SELECT id FROM readable_concepts)
                ORDER BY c.canonical_name
                """
                ),
                params,
            )
        ).fetchall()
        for i, (uuid_str, name, ctype) in enumerate(concept_rows):
            cid = i + 1
            uuid_to_cid[uuid_str] = cid
            concept = Concept(
                cid=cid,
                label=name,
                dependencies=[],
                taxonomy=ctype or "UNASSIGNED",
                relation_type="PREREQ",
                source_chunks=[],
            )
            g.concepts[cid] = concept
            g.label_to_id[_norm(name)] = cid
            g.taxonomy_members[concept.taxonomy].append(cid)

        edge_rows = (
            await conn.execute(
                text(
                    with_scope
                    + """
                SELECT de.src_concept_id::text, de.dst_concept_id::text, de.rel_type
                FROM readable_dag_edges de
                """
                ),
                params,
            )
        ).fetchall()
        for src_uuid, dst_uuid, rel_type in edge_rows:
            src_cid = uuid_to_cid.get(src_uuid)
            dst_cid = uuid_to_cid.get(dst_uuid)
            if src_cid is None or dst_cid is None:
                continue
            g.concepts[src_cid].dependencies.append(dst_cid)
            g.forward[src_cid].append(dst_cid)
            g.backward[dst_cid].append(src_cid)
            if rel_type and rel_type != "PREREQ":
                g.concepts[src_cid].relation_type = rel_type

        community_rows = (
            await conn.execute(
                text(
                    """
                SELECT name, level, member_concept_ids
                FROM trellion_communities
                WHERE snapshot_id = CAST(:sid AS uuid)
                ORDER BY level
                """
                ),
                {"sid": snapshot_id},
            )
        ).fetchall()
        cid_to_community: dict[int, tuple[int, str]] = {}
        for name, level, member_ids in community_rows:
            for member_uuid in member_ids or []:
                cid = uuid_to_cid.get(member_uuid)  # unreadable members are simply absent
                if cid is None:
                    continue
                if cid not in cid_to_community or level < cid_to_community[cid][0]:
                    cid_to_community[cid] = (level, name)
        if cid_to_community:
            g.taxonomy_members.clear()
            for cid, concept in g.concepts.items():
                if cid in cid_to_community:
                    concept.taxonomy = cid_to_community[cid][1]
                g.taxonomy_members[concept.taxonomy].append(cid)
    return g
