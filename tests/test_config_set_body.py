# SPDX-License-Identifier: AGPL-3.0-only
# Copyright 2026 PersonifAI LLC

"""`noo_config_set` must send the section's keys, not a wrapper around them.

`PUT /api/config/{section}` deep-merges the request body INTO that section.
`ToolDef.get_body` builds `{field_name: value}` for every non-path field,
which is right for a route with named body fields and wrong for this one:
it wrote a literal `updates` key holding the change and left the real keys
untouched — and reported success, because the route merged exactly what it
was given.

Observed on a live controller: an update to `kb.source_roles` landed as
`kb.updates.source_roles`, the rule never took effect, and the section grew
a junk block. Nothing failed anywhere.
"""

from __future__ import annotations

import pytest

from noomesh.mcp.tool_defs.config import PaiConfigSet
from noomesh.mcp.tool_defs.users import PaiUserPropose


def test_the_body_is_the_section_keys_themselves():
    tool = PaiConfigSet(section="kb", updates={"source_roles": [{"match": "gdrive://*"}]})
    body = tool.get_body()
    assert "source_roles" in body, "the section's keys must be at the top level"
    assert "updates" not in body, (
        "the body is wrapped in `updates` again — the route will deep-merge "
        "that wrapper into the section as a literal key, exactly as it did "
        "on the controller"
    )


def test_the_section_stays_in_the_path_not_the_body():
    tool = PaiConfigSet(section="kb", updates={"default_roles": []})
    assert tool.get_path().endswith("/kb")
    assert "section" not in tool.get_body()


def test_an_empty_update_is_still_an_object():
    """`get_body` returning None would make the route see no body at all."""
    tool = PaiConfigSet(section="kb", updates={})
    assert tool.get_body() == {}


def test_the_body_is_a_copy():
    """A handler that mutates the body must not reach back into the model."""
    updates = {"a": 1}
    tool = PaiConfigSet(section="kb", updates=updates)
    tool.get_body()["a"] = 2
    assert updates["a"] == 1


def test_nested_values_survive_untouched():
    payload = {"source_roles": [{"match": "gdrive://*", "roles": ["team:founders"]}]}
    body = PaiConfigSet(section="kb", updates=payload).get_body()
    assert body["source_roles"][0]["roles"] == ["team:founders"]


def test_the_sibling_that_nests_on_purpose_still_nests():
    """`noo_user_propose`'s route reads `action` and `payload` as named body
    fields, which is why the fix is an override and not a base-class change.
    Flattening it would send a user record where an action was expected."""
    tool = PaiUserPropose(action="grant_roles", payload={"username": "x", "roles": ["team:y"]})
    body = tool.get_body()
    assert body["action"] == "grant_roles"
    assert body["payload"]["username"] == "x"


@pytest.mark.parametrize("section", ["kb", "cluster", "services"])
def test_every_section_is_affected_by_the_same_rule(section):
    body = PaiConfigSet(section=section, updates={"k": "v"}).get_body()
    assert body == {"k": "v"}
