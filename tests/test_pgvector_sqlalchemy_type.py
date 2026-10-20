# SPDX-License-Identifier: AGPL-3.0-only
# Copyright 2026 PersonifAI LLC

"""pgvector (python) 0.5.x: the one API this tree uses is ``pgvector.sqlalchemy.Vector``.

``noomesh.db.models`` declares every embedding column with it. No Postgres is
needed to pin what the type does: the DDL it emits, and how it serialises a
Python list to the wire text form and parses it back (those are the two
functions a pgvector release could change). The DB-backed tests
(NOO_KB_AUDIENCE_TEST_DSN) cover the rest where Postgres exists.
"""

from __future__ import annotations

from importlib.metadata import version

from pgvector.sqlalchemy import Vector
from sqlalchemy.dialects import postgresql
from sqlalchemy.schema import CreateTable
from sqlalchemy import Column, Integer, MetaData, Table

from noomesh.db import models

DIALECT = postgresql.dialect()


def test_the_models_module_really_got_the_vector_type() -> None:
    assert models.Vector is Vector, "noomesh.db.models fell back to Vector = None"
    assert tuple(int(x) for x in version("pgvector").split(".")[:2]) >= (0, 5)


def test_ddl_is_vector_n() -> None:
    t = Table("t", MetaData(), Column("id", Integer, primary_key=True), Column("e", Vector(3)))
    assert "e VECTOR(3)" in str(CreateTable(t).compile(dialect=DIALECT))


def test_a_list_round_trips_through_the_wire_text_form() -> None:
    col = Vector(3)
    bind = col.bind_processor(DIALECT)
    result = col.result_processor(DIALECT, None)
    wire = bind([1.0, 2.5, -3.0])
    assert wire == "[1.0,2.5,-3.0]"
    # The driver hands back the text form; it must parse to floats again.
    assert list(result("[1.0,2.5,-3.0]")) == [1.0, 2.5, -3.0]


def test_a_none_embedding_stays_null() -> None:
    col = Vector(3)
    assert col.bind_processor(DIALECT)(None) is None
    assert col.result_processor(DIALECT, None)(None) is None
