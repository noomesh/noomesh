# SPDX-License-Identifier: AGPL-3.0-only
# Copyright 2026 PersonifAI LLC
"""i300 F1: the model-set and node-workload contract, held in one place.

Three validators read ONE fixture set (tests/fixtures/i300): the node agent's
(node-agent-go/internal/nodewl), the CLI's (noo-cli/src/addons/decls.rs) and
the gateway's (gateway-rust/src/addon_workloads.rs). A Rust test cannot reach
outside its crate's Docker build context, and a Go test reaches only its own
module, so each component keeps a byte-identical COPY and this test compares
them, the way tests/test_lanes_fixture_parity.py does for the lanes heartbeat.
Change the canonical fixtures, copy them over, and every validator judges the
same bytes.

It also holds the two JSON schemas (docs/reference/noo-model-set-1.schema.json
and noo-addon-node-workloads-1.schema.json) to the fixtures: every valid case
passes, and every refusal the schema can state is rejected. test-core has no
`jsonschema`, so a small checker for the subset the schemas use sits below; it
refuses a keyword it does not know, so a schema cannot quietly outgrow it.
"""

import json
import re
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parent.parent
CANON = REPO / "tests/fixtures/i300"
AGENT = REPO / "node-agent-go/internal/nodewl/testdata/i300"
SCHEMAS = REPO / "docs/reference"
DOC = REPO / "docs/reference/node-workloads.md"
RHADDON = REPO / "tests/fixtures/addons/rhaddon"

# Future copies. They become REQUIRED when the validators land: the gateway's
# (harness) and the CLI's (F2). Until then a copy is compared only if it exists.
FUTURE_COPIES = [
    REPO / "gateway-rust/src/testdata/i300",
    REPO / "noo-cli/src/addons/testdata/i300",
]

DIRS = ["model-sets", "node-workloads", "desired"]


def files(root: Path) -> dict[str, bytes]:
    return {str(p.relative_to(root)): p.read_bytes() for p in sorted(root.rglob("*")) if p.is_file()}


def cases(d: str) -> list[dict]:
    return json.loads((CANON / d / "cases.json").read_text())


# ------------------------------------------------------------------ parity


def test_the_agent_has_a_byte_identical_copy_of_every_fixture() -> None:
    canon, agent = files(CANON), files(AGENT)
    assert canon, "tests/fixtures/i300 is empty"
    assert set(agent) == set(canon), (
        f"copy differs in membership: missing {sorted(set(canon) - set(agent))}, "
        f"extra {sorted(set(agent) - set(canon))}: "
        "rm -rf node-agent-go/internal/nodewl/testdata/i300 && cp -r tests/fixtures/i300 node-agent-go/internal/nodewl/testdata/"
    )
    stale = [n for n in canon if canon[n] != agent[n]]
    assert not stale, f"differ from the canonical fixtures: {stale}: copy tests/fixtures/i300 over the agent's testdata"


@pytest.mark.parametrize("copy", FUTURE_COPIES, ids=lambda p: str(p.relative_to(REPO)))
def test_a_validators_copy_when_it_exists_is_byte_identical(copy: Path) -> None:
    if not copy.exists():
        pytest.skip("this validator has not landed; the copy becomes required with it")
    assert files(copy) == files(CANON), f"{copy.relative_to(REPO)} differs from tests/fixtures/i300"


def test_the_fixture_addons_declaration_is_the_valid_rhaddon_fixture() -> None:
    a = (RHADDON / "node-workloads.json").read_bytes()
    assert a == (CANON / "node-workloads/valid-rhaddon.json").read_bytes()


def test_every_fixture_is_in_its_cases_file_and_back() -> None:
    for d in DIRS:
        listed = {c["file"] for c in cases(d)}
        on_disk = {p.name for p in (CANON / d).iterdir()} - {"cases.json", "lock.json", "routes.json"}
        assert listed == on_disk, f"{d}: cases.json and the directory disagree: {listed ^ on_disk}"
        for c in cases(d):
            assert set(c) <= {"file", "valid", "code", "addon", "set"}
            if "set" in c:  # a desired case paired with a model-set fixture
                assert d == "desired" and (CANON / c["set"]).is_file(), c
            assert c["valid"] == (c["code"] == ""), f"{d}/{c['file']}"


# ---------------------------------------------- a small JSON Schema checker

_IGNORED = {"$schema", "$id", "title", "description", "default", "x-noo-rules", "$defs"}


def _is_int(v) -> bool:
    return (isinstance(v, int) and not isinstance(v, bool)) or (isinstance(v, float) and v.is_integer())


_TYPES = {
    "object": lambda v: isinstance(v, dict),
    "array": lambda v: isinstance(v, list),
    "string": lambda v: isinstance(v, str),
    "boolean": lambda v: isinstance(v, bool),
    "integer": _is_int,
    "number": lambda v: isinstance(v, (int, float)) and not isinstance(v, bool),
}


def ok(schema: dict, v, root: dict) -> bool:
    """True when v satisfies schema. Unknown keywords raise: extend the checker."""
    for k, s in schema.items():
        if k in _IGNORED:
            continue
        if k == "$ref":
            assert s.startswith("#/$defs/"), s
            if not ok(root["$defs"][s.split("/")[-1]], v, root):
                return False
        elif k == "type":
            if not _TYPES[s](v):
                return False
        elif k == "const":
            if v != s or type(v) is not type(s):
                return False
        elif k == "enum":
            if v not in s or any(v == e and type(v) is not type(e) for e in s):
                return False
        elif k == "pattern":
            if isinstance(v, str) and not re.search(s, v):
                return False
        elif k in ("minLength", "maxLength"):
            if isinstance(v, str) and (len(v) < s if k == "minLength" else len(v) > s):
                return False
        elif k in ("minimum", "maximum"):
            if _TYPES["number"](v) and (v < s if k == "minimum" else v > s):
                return False
        elif k in ("minItems", "maxItems"):
            if isinstance(v, list) and (len(v) < s if k == "minItems" else len(v) > s):
                return False
        elif k in ("minProperties", "maxProperties"):
            if isinstance(v, dict) and (len(v) < s if k == "minProperties" else len(v) > s):
                return False
        elif k == "required":
            if isinstance(v, dict) and any(r not in v for r in s):
                return False
        elif k == "properties":
            if isinstance(v, dict) and any(n in v and not ok(sub, v[n], root) for n, sub in s.items()):
                return False
        elif k == "additionalProperties":
            if isinstance(v, dict):
                extra = [n for n in v if n not in schema.get("properties", {})]
                if s is False and extra:
                    return False
                if isinstance(s, dict) and any(not ok(s, v[n], root) for n in extra):
                    return False
        elif k == "propertyNames":
            if isinstance(v, dict) and any(not ok(s, n, root) for n in v):
                return False
        elif k == "items":
            if isinstance(v, list) and any(not ok(s, i, root) for i in v):
                return False
        elif k == "oneOf":
            if sum(ok(sub, v, root) for sub in s) != 1:
                return False
        elif k == "allOf":
            if not all(ok(sub, v, root) for sub in s):
                return False
        elif k == "not":
            if ok(s, v, root):
                return False
        elif k == "if":
            branch = "then" if ok(s, v, root) else "else"
            if branch in schema and not ok(schema[branch], v, root):
                return False
        elif k in ("then", "else"):
            pass  # applied with `if`
        else:
            raise AssertionError(f"the test's schema checker does not know `{k}`: extend it, do not drop it")
    return True


def load_schema(name: str) -> dict:
    return json.loads((SCHEMAS / name).read_text())


# Refusals a schema cannot state: not JSON, or a rule that needs the lock, the
# add-on's name, or a comparison between two values. Each is named in the
# schema's x-noo-rules. Everything else must be rejected by the schema alone.
NOT_IN_SCHEMA = {
    "model-sets": {
        "refuse-trailing-data.json",
        "refuse-duplicate-key.json",
        "refuse-notice-not-in-files.json",
        "refuse-additional-notice-not-in-files.json",
        "refuse-additional-notice-not-a-notice.json",
        "refuse-files-duplicate-path.json",
    },
    "node-workloads": {
        "refuse-trailing-data.json",
        "refuse-duplicate-key.json",
        "refuse-image-not-in-lock.json",
        "refuse-service-drain-route-unknown.json",
        "refuse-service-drain-route-public.json",
        "refuse-accel-slots-env-undeclared.json",
        "refuse-accel-slots-env-enum.json",
        "refuse-name-duplicate.json",
        "refuse-env-key-outside-prefix.json",
        "refuse-env-bound-inverted.json",
        "refuse-scratch-in-model-slot.json",
        "refuse-scratch-equals-model-slot.json",
        "refuse-scratch-exec-two.json",
        "refuse-scratch-nested.json",
        "refuse-scratch-nested-exec.json",
        "refuse-scratch-exec-over-cap.json",
        "refuse-scratch-exec-tmpfs-over-cap.json",
        "refuse-addon-underscore.json",
        "refuse-addon-uppercase.json",
        "refuse-addon-trailing-dash.json",
        "refuse-door-name-52.json",
        "refuse-door-name-52-by-addon.json",
    },
}

SCHEMA_FOR = {
    "model-sets": "noo-model-set-1.schema.json",
    "node-workloads": "noo-addon-node-workloads-1.schema.json",
}


@pytest.mark.parametrize("d", ["model-sets", "node-workloads"])
def test_the_schema_accepts_every_valid_case_and_rejects_what_it_can_state(d: str) -> None:
    schema = load_schema(SCHEMA_FOR[d])
    skip = NOT_IN_SCHEMA[d]
    names = {c["file"] for c in cases(d)}
    assert skip <= names, f"NOT_IN_SCHEMA names a file that is not a case: {skip - names}"
    wrong = []
    for c in cases(d):
        text = (CANON / d / c["file"]).read_text()
        if c["file"] in skip:
            continue
        accepted = ok(schema, json.loads(text), schema)
        if accepted != c["valid"]:
            wrong.append((c["file"], "accepted" if accepted else "rejected", c["code"] or "valid"))
    assert not wrong, f"the schema and the fixtures disagree: {wrong}"
    # A file in NOT_IN_SCHEMA that parses and is valid for the schema is a
    # hole in the list the other way: the schema would catch it, so say so.
    stale = []
    for f in skip:
        try:
            obj = json.loads((CANON / d / f).read_text())
        except ValueError:
            continue
        if not ok(schema, obj, schema):
            stale.append(f)
    assert not stale, f"the schema rejects these after all; drop them from NOT_IN_SCHEMA: {stale}"


def test_the_schemas_state_their_formats_and_closed_shapes() -> None:
    ms = load_schema(SCHEMA_FOR["model-sets"])
    nw = load_schema(SCHEMA_FOR["node-workloads"])
    assert ms["properties"]["format"]["const"] == "noo-model-set/1"
    assert nw["properties"]["format"]["const"] == "noo-addon-node-workloads/1"

    def closed(node, path="$"):
        if isinstance(node, dict):
            if node.get("type") == "object" and "properties" in node and "propertyNames" not in node:
                assert node.get("additionalProperties") is False, f"{path} is open"
            for k, v in node.items():
                if k != "x-noo-rules":
                    closed(v, f"{path}.{k}")
        elif isinstance(node, list):
            for i, v in enumerate(node):
                closed(v, f"{path}[{i}]")

    closed(ms)
    closed(nw)
    for s in (ms, nw):
        assert any("door" in r or "signature" in r or "unknown" in r for r in s["x-noo-rules"])
    # the door label rule is in the description AND the rules
    assert "51" in nw["description"] and any("> 51" in r for r in nw["x-noo-rules"])


def test_the_refused_env_prefixes_match_the_agent() -> None:
    go = (REPO / "node-agent-go/internal/nodewl/decl.go").read_text()
    m = re.search(r"refusedEnvPrefixes = \[\]string\{([^}]*)\}", go)
    assert m
    go_prefixes = re.findall(r'"([A-Z_]+)"', m.group(1))
    nw = load_schema(SCHEMA_FOR["node-workloads"])
    pat = nw["$defs"]["workload"]["properties"]["env"]["propertyNames"]["not"]["pattern"]
    assert set(pat.strip("^()").split("|")) == set(go_prefixes)
    assert go_prefixes == ["NOO_", "NVIDIA_", "CUDA_", "LD_", "PYTHON", "HF_", "TRANSFORMERS_"]


# --------------------------------------------------------------- the doc


def doc_text() -> str:
    assert DOC.is_file(), "docs/reference/node-workloads.md is the contract"
    return DOC.read_text()


def test_the_doc_lists_exactly_the_agents_reasons() -> None:
    go = (REPO / "node-agent-go/internal/nodewl/reasons.go").read_text()
    go_reasons = re.findall(r'Reason\w+\s*=\s*"([a-z_]+)"', go)
    assert len(go_reasons) == len(set(go_reasons)) > 10
    section = doc_text().split("## Reasons", 1)[1].split("\n## ", 1)[0]
    doc_reasons = re.findall(r"^\| `([a-z_]+)` \|", section, re.M)
    assert doc_reasons == go_reasons, "docs/reference/node-workloads.md 'Reasons' and nodewl/reasons.go must list the same reasons in the same order"
    # the three the brief required to be there, whatever else is added
    for r in ("decl_invalid", "door_leaf_missing", "drain_timeout"):
        assert r in doc_reasons
    row = re.search(r"^\| `door_leaf_missing` \|.*$", section, re.M).group(0)
    assert "noo upgrade --nodes" in row


def test_the_nullable_table_is_the_agents_list_and_the_fixtures_use_no_other_null() -> None:
    section = doc_text().split("## Nullable fields", 1)[1].split("\n## ", 1)[0]
    doc_ptrs = sorted(re.findall(r"^\| [^|]+\| `(/[^`]*)` \|", section, re.M))
    go = (REPO / "node-agent-go/internal/nodewl/nullable.go").read_text()
    go_ptrs = sorted(re.findall(r'^\s+"(/[^"]*)",$', go, re.M))
    assert doc_ptrs == go_ptrs == ["/node_workloads/*/reservation"]

    def nulls(node, path=""):
        if node is None:
            yield path
        elif isinstance(node, dict):
            for k, v in node.items():
                yield from nulls(v, f"{path}/{k}")
        elif isinstance(node, list):
            for i, v in enumerate(node):
                yield from nulls(v, f"{path}/*")

    allowed = set(doc_ptrs)
    for p in sorted(CANON.rglob("*.json")):
        try:
            obj = json.loads(p.read_text())
        except ValueError:
            continue
        if p.name in ("cases.json",):
            continue
        bad = {n for n in nulls(obj) if n not in allowed}
        rel = p.relative_to(CANON)
        # A refusal fixture may carry the null it is there to refuse.
        if p.name.startswith("refuse-null-"):
            assert len(bad) == 1, (rel, bad)
        else:
            assert not bad, f"{rel} carries a null at {bad} that the contract does not name nullable"


def test_the_doc_names_every_refusal_code_the_fixtures_pin() -> None:
    text = doc_text()
    codes = {c["code"] for d in DIRS for c in cases(d) if c["code"]}
    missing = sorted(c for c in codes if f"`{c}`" not in text)
    assert not missing, f"docs/reference/node-workloads.md does not list these refusal codes: {missing}"


def test_the_doc_states_the_signing_key_and_the_relay_rule() -> None:
    text = doc_text()
    for needle in ("ECDSA", "P-384", "signing.pub", "/etc/noo/pki", "X-Noo-Reservation", "X-Noo-Requester-Sub", "X-Noo-Requester-Role", "Origin", "Authorization", "Cookie", "Sec-WebSocket-Protocol", "NOO_SELF_NODE", "NOO_ADDON_WORKLOADS_ON_CONTROLLER", "NOO_ADDON_WORKLOADS", "addon-workload-approvals.json", "weights_only=True", "**409**", "done_path"):
        assert needle in text, needle


# ---------------------------------------------------------- the examples

HEARTBEAT_TYPES = {
    "os": str,  # runtime.GOOS, always reported
    "gpu_compute_cap": str,
    "nvidia_runtime": bool,
    "nvidia_driver_caps_ok": bool,
    "controller_host": bool,
    "data_root_free_gb": (int, float),
    "model_sets_free_bytes": int,  # i607b: free bytes of <models dir>/sets' filesystem
    "addon_workloads_policy": str,
    "addon_workloads_approvals": list,
    "model_sets": list,
    "node_workloads": list,
}


def test_the_heartbeat_example_has_the_a4_keys_and_only_them() -> None:
    hb = json.loads((CANON / "heartbeat-i300.json").read_text())
    assert set(hb) == set(HEARTBEAT_TYPES)
    for k, t in HEARTBEAT_TYPES.items():
        assert isinstance(hb[k], t), k
    assert hb["os"] in ("linux", "darwin", "windows")
    assert re.fullmatch(r"\d{1,2}\.\d", hb["gpu_compute_cap"])
    assert hb["addon_workloads_policy"] in ("none", "approve", "auto")
    assert all(set(a) == {"addon", "digest"} for a in hb["addon_workloads_approvals"])
    assert hb["model_sets_free_bytes"] >= 0 and not isinstance(hb["model_sets_free_bytes"], bool)
    # i607b: the delivery fields are optional, and each rides only its state.
    row_keys = {"id", "revision", "state", "reason", "bytes_done", "bytes_total", "retry_at", "free_bytes", "need_bytes"}
    only_with = {
        "bytes_done": {"fetching"},
        "bytes_total": {"fetching", "verified"},
        "retry_at": {"refused"},
        "free_bytes": {"refused"},
        "need_bytes": {"refused"},
    }
    for s in hb["model_sets"]:
        assert {"id", "revision", "state"} <= set(s) <= row_keys and s["state"] in ("verified", "fetching", "refused")
        assert ("reason" in s) == (s["state"] == "refused"), "a reason rides a refused set"
        for k, states in only_with.items():
            if k in s:
                assert s["state"] in states, f"{k} rides only {sorted(states)}, not {s['state']}"
                assert isinstance(s[k], int) and not isinstance(s[k], bool) and s[k] >= 0 if k != "retry_at" else True
        # free and need ride a disk refusal, and only together.
        assert ("free_bytes" in s) == ("need_bytes" in s)
        if "free_bytes" in s:
            assert s["reason"] == "disk", "the disk numbers ride reason=disk"
        if "retry_at" in s:
            assert re.fullmatch(r"\d{4}-\d\d-\d\dT\d\d:\d\d:\d\dZ", s["retry_at"]), "RFC 3339, UTC"
        if "bytes_done" in s:
            assert "bytes_total" in s and s["bytes_done"] <= s["bytes_total"]
    states = {s["state"] for s in hb["model_sets"]}
    assert states == {"verified", "fetching", "refused"}, "the example shows every state"
    assert any(s.get("reason") == "disk" and "free_bytes" in s for s in hb["model_sets"]), "the example shows a disk refusal"
    reasons = set(re.findall(r'Reason\w+\s*=\s*"([a-z_]+)"', (REPO / "node-agent-go/internal/nodewl/reasons.go").read_text()))
    for s in hb["model_sets"]:
        assert s.get("reason", "set_unverified") in reasons
    for w in hb["node_workloads"]:
        # An unknown value is OMITTED, never defaulted or null (the i495 rule:
        # an error must not become a fact).
        # (`slots` is not a phase 2 row key: placement sizes it from slots_env.)
        assert {"addon", "name", "state", "ready", "door_port"} <= set(w) <= {"addon", "name", "state", "ready", "model", "door_port", "reservation", "reason"}
        assert None not in w.values()
        # Reported states: the desired three plus draining and needs_attention,
        # which never appear in desired-config.
        assert w["state"] in ("provisioned", "running", "absent", "draining", "needs_attention")
        assert (w["state"] == "needs_attention") == (w.get("reason") == "drain_timeout")
        assert w.get("reason", "crashed") in reasons


def test_the_desired_example_is_one_provisioned_and_one_running_entry() -> None:
    d = json.loads((CANON / "desired-node-workloads.json").read_text())
    assert list(d) == ["node_workloads"]
    assert [e["state"] for e in d["node_workloads"]] == ["provisioned", "running"]
    assert d["node_workloads"][0]["reservation"] is None
    assert re.fullmatch(r"[0-9a-f-]{36}", d["node_workloads"][1]["reservation"])
