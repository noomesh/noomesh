# SPDX-License-Identifier: AGPL-3.0-only
# Copyright 2026 PersonifAI LLC

"""Grafana's JWT login agrees with the gateway that mints the token.

an earlier change. Three files describe one credential and cannot see each
other:

* `gateway-rust/src/auth.rs` mints it — issuer `JWT_ISSUER`, audience
  `GRAFANA_AUDIENCE`, and `grafana_role` from `GRAFANA_ORG_ROLES`, the ONE
  tier → Grafana org-role table;
* `configs/grafana/grafana.ini` verifies it — `[auth.jwt] expect_claims`,
  `role_attribute_path` (a JMESPath over the claims), `key_file`;
* `docker-compose.cluster.yml` hands Grafana the public key at the path
  `key_file` names, and the gateway the private one.

Drift in any pair is a login that fails for everyone, or — the strict
role mapping aside — one that admits a tier nobody mapped. Each check here
was planted once (a wrong audience, a wrong role name, a wrong key path,
the private key mounted into Grafana) and watched fail.

`role_attribute_path` is evaluated by a small evaluator for the ONE
expression shape Grafana's docs use for this (`role == 'x' && 'Y' || …`)
because the `jmespath` package is not installed in this environment. It
parses the expression into (claim, literal, result) arms, so a fourth arm or
a reordered one is read, not guessed; anything outside that shape fails the
test rather than passing by string match.
"""

from __future__ import annotations

import configparser
import json
import re
from pathlib import Path

import pytest

from tests._compose_projection import env_of, full_projection

ROOT = Path(__file__).resolve().parents[1]
AUTH_RS = ROOT / "gateway-rust" / "src" / "auth.rs"
MONITORING_RS = ROOT / "gateway-rust" / "src" / "routes" / "monitoring.rs"
PKI_RS = ROOT / "noo-cli" / "src" / "pki.rs"
GRAFANA_INI = ROOT / "configs" / "grafana" / "grafana.ini"

# Grafana's org roles, the only values the pass-through may produce.
GRAFANA_ROLES = {"Admin", "Editor", "Viewer"}


def _rust_const(src: str, name: str) -> str:
    m = re.search(rf'pub const {name}:\s*&(?:\'static )?str\s*=\s*"([^"]+)"', src)
    assert m, f"{name} not found — the grep is stale, not the constant"
    return m.group(1)


@pytest.fixture(scope="module")
def auth_rs() -> str:
    return AUTH_RS.read_text()


@pytest.fixture(scope="module")
def ini() -> configparser.ConfigParser:
    cp = configparser.ConfigParser(interpolation=None)
    cp.optionxform = str  # type: ignore[assignment]
    cp.read_string(GRAFANA_INI.read_text())
    assert cp.has_section("auth.jwt"), "grafana.ini has no [auth.jwt] — the whole feature is off"
    return cp


@pytest.fixture(scope="module")
def org_roles(auth_rs: str) -> dict[str, str]:
    """`GRAFANA_ORG_ROLES` rows (Role variant → Grafana org role), read from
    the source: the one place the mapping lives."""
    body = auth_rs.split("pub const GRAFANA_ORG_ROLES: &[(Role, &str)] = &[", 1)[1].split("];", 1)[0]
    rows = dict(re.findall(r'\(Role::(\w+),\s*"([A-Za-z]+)"\)', body))
    assert rows, "GRAFANA_ORG_ROLES not found — the grep is stale, not the table"
    return rows


def test_the_login_form_is_off_and_jwt_is_on(ini: configparser.ConfigParser) -> None:
    assert ini.get("auth", "disable_login_form") == "true"
    assert ini.get("auth", "disable_signout_menu") == "true"
    assert ini.get("users", "allow_sign_up") == "false"
    jwt = ini["auth.jwt"]
    assert jwt.get("enabled") == "true"
    assert jwt.get("url_login") == "true", "the console opens Grafana with ?auth_token="
    assert jwt.get("header_name"), "header_name MUST be set or Grafana's SPA sends its API calls unauthenticated"
    assert jwt.get("username_claim") == "sub"
    assert jwt.get("auto_sign_up") == "true"
    assert jwt.get("role_attribute_strict") == "true", "an unmapped tier must be refused, not admitted as Viewer"
    assert jwt.get("allow_assign_grafana_admin") == "false"
    assert jwt.get("skip_org_role_sync") == "false", "a demotion must take effect at the next token"
    assert "key_id" not in jwt, "the gateway sends no kid; a key_id here would refuse every token"


def test_expect_claims_match_the_gateway_constants(ini: configparser.ConfigParser, auth_rs: str) -> None:
    expect = json.loads(ini.get("auth.jwt", "expect_claims"))
    assert expect == {
        "iss": _rust_const(auth_rs, "JWT_ISSUER"),
        "aud": _rust_const(auth_rs, "GRAFANA_AUDIENCE"),
    }
    # The Grafana audience is NOT the gateway's own: that difference is what
    # makes the gateway refuse the token.
    assert _rust_const(auth_rs, "GRAFANA_AUDIENCE") != _rust_const(auth_rs, "JWT_AUDIENCE")


_ARM = re.compile(r"^\s*(\w+)\s*==\s*'([^']*)'\s*&&\s*'([^']*)'\s*$")


def evaluate_role_path(expression: str, claims: dict) -> str | None:
    """Evaluate `claim == 'x' && 'Y' || claim == 'z' && 'W' …` as JMESPath
    would: the first arm whose comparison holds yields its literal; none
    yields null (which strict mode refuses). Any other shape is an error."""
    arms = []
    for part in expression.split("||"):
        m = _ARM.match(part)
        assert m, f"role_attribute_path arm {part!r} is not `claim == 'x' && 'Y'` — extend the evaluator or use jmespath"
        arms.append(m.groups())
    for claim, literal, result in arms:
        if claims.get(claim) == literal:
            return result
    return None


def test_grafana_ini_passes_the_gateway_table_through_and_maps_nothing_itself(
    ini: configparser.ConfigParser, org_roles: dict[str, str]
) -> None:
    expr = ini.get("auth.jwt", "role_attribute_path")
    # Every role the table can stamp arrives as itself.
    assert set(org_roles.values()) <= GRAFANA_ROLES, org_roles
    for grafana_role in org_roles.values():
        assert evaluate_role_path(expr, {"grafana_role": grafana_role}) == grafana_role
    # And the file holds no mapping of its own: the noomesh tier claim alone
    # gets nothing, nor does anything outside the three org roles.
    for bad in (
        {"role": "admin"},
        {"role": "user"},
        {"grafana_role": "GrafanaAdmin"},
        {"grafana_role": "admin"},
        {"grafana_role": ""},
        {},
    ):
        assert evaluate_role_path(expr, bad) is None, bad


GRAFANA_DS_RS = ROOT / "gateway-rust" / "src" / "routes" / "grafana_ds.rs"
DATASOURCES = ROOT / "configs" / "grafana" / "datasources"
DASHBOARDS = ROOT / "configs" / "grafana" / "dashboards"
GATEWAY_DS = "https://gateway:8080/api/grafana-ds/"


def _datasource_urls() -> dict[str, str]:
    """type → url of every provisioned data source (one `url:` per entry)."""
    out: dict[str, str] = {}
    for f in sorted(DATASOURCES.glob("*.yml")):
        typ = url = None
        for line in f.read_text().splitlines():
            t = line.strip().lstrip("- ").strip()
            if t.startswith("type:"):
                typ = t.split(":", 1)[1].strip()
            elif t.startswith("url:"):
                url = t.split(":", 1)[1].strip()
            if typ and url:
                out[typ] = url
                typ = url = None
    assert out, f"no data sources parsed from {DATASOURCES} — the parse is stale, not the files"
    return out


def test_read_only_users_are_viewers_only_behind_the_gateway(
    org_roles: dict[str, str], ini: configparser.ConfigParser
) -> None:
    """an earlier change. A read-only account is a Grafana Viewer ONLY because
    Grafana's data sources dial the gateway, which holds a Viewer to the
    provisioned dashboards' own queries. Open-source Grafana answers any
    Viewer's own POST /api/ds/query, so the User row and a data source that
    dials Prometheus or Loki directly cannot both exist. Planted (loki.yml
    back to https://loki:3100) and watched fail."""
    assert org_roles == {"User": "Viewer", "Operator": "Editor", "Admin": "Admin"}, org_roles
    urls = _datasource_urls()
    assert set(urls) == {"prometheus", "loki"}, urls
    for typ, url in urls.items():
        assert url == f"{GATEWAY_DS}{typ}", (
            f"the {typ} data source dials {url}: with a Viewer row in GRAFANA_ORG_ROLES every read-only "
            f"account could run its own queries there — point it at {GATEWAY_DS}{typ}"
        )
    # The gateway can only enforce a person it is told about.
    assert ini.get("dataproxy", "send_user_header") == "true"
    # A shared dashboard queries with no user; nothing shares outside accounts.
    assert ini.get("public_dashboards", "enabled") == "false"
    # And the leaf the gateway admits is the one the data sources present.
    for f in DATASOURCES.glob("*.yml"):
        assert "tlsClientCert: $__file{/app/pki/services/grafana/service.crt}" in f.read_text(), f.name
    assert 'pub const GRAFANA_SERVICE: &str = "grafana";' in AUTH_RS.read_text()


def test_every_provisioned_dashboard_feeds_the_viewer_allowlist() -> None:
    """The gateway's read-only allow-list is compiled from the dashboards
    (`routes/grafana_ds.rs` DASHBOARDS). A dashboard added to the directory
    and not to that list would render nothing for a Viewer; one listed and
    not COPYed into the image fails the image build."""
    on_disk = sorted(p.name for p in DASHBOARDS.glob("*.json"))
    assert on_disk, DASHBOARDS
    rs = GRAFANA_DS_RS.read_text()
    listed = sorted(re.findall(r'include_str!\("\.\./\.\./\.\./configs/grafana/dashboards/([^"]+)"\)', rs))
    assert listed == on_disk, (listed, on_disk)
    dockerfile = (ROOT / "docker" / "Dockerfile.gateway-rust").read_text()
    for name in on_disk:
        assert f"COPY configs/grafana/dashboards/{name} /configs/grafana/dashboards/{name}" in dockerfile, name


def _panel_exprs(d: dict) -> list[str]:
    out: list[str] = []

    def walk(panels: list) -> None:
        for p in panels:
            for t in p.get("targets", []):
                if t.get("expr"):
                    out.append(t["expr"])
            walk(p.get("panels", []))

    walk(d.get("panels", []))
    return out


def test_no_provisioned_panel_query_takes_a_template_variable() -> None:
    """The template-variable guard. A Viewer's query must be
    byte-for-byte a dashboard's own; a panel whose expression contains a
    `$variable` is filled in by the viewer (`?var-x=…`), so an exact list
    cannot hold it without a grammar for the value. Until the gateway has
    one, no provisioned panel may use a variable."""
    for f in sorted(DASHBOARDS.glob("*.json")):
        exprs = _panel_exprs(json.loads(f.read_text()))
        assert exprs, f"{f.name}: no panel queries parsed — the walk is stale"
        templated = [e for e in exprs if "$" in e]
        assert not templated, f"{f.name}: {templated}"


def test_viewers_see_dashboards_only(ini: configparser.ConfigParser) -> None:
    """A read-only user is a Viewer — no editing, no Explore,
    no data-source or admin settings in Grafana's UI. Grafana gives Viewers
    Explore only with viewers_can_edit; both knobs are spelled out. What a
    Viewer's queries may read is the gateway's call, pinned above."""
    assert ini.get("users", "viewers_can_edit") == "false"
    assert ini.get("users", "editors_can_admin") == "false"
    assert ini.get("users", "auto_assign_org_role") == "Viewer"
    # Explore stays on for Editors and Admins; Viewers are kept out by role.
    assert ini.get("explore", "enabled") == "true"
    assert ini.get("auth.jwt", "allow_assign_grafana_admin") == "false"


def test_the_evaluator_reads_the_expression_not_the_expected_table() -> None:
    # Not vacuous: a reordered or altered expression changes the answer.
    assert evaluate_role_path("role == 'user' && 'Admin'", {"role": "user"}) == "Admin"
    assert evaluate_role_path("x == 'a' && 'B' || x == 'c' && 'D'", {"x": "c"}) == "D"
    with pytest.raises(AssertionError):
        evaluate_role_path("contains(groups, 'admins') && 'Admin'", {})


@pytest.fixture(scope="module")
def services() -> dict:
    return full_projection()["services"]


def _pki_mounts(svc: dict) -> dict[str, str]:
    """host-relative PKI path → container path, for `${NOO_PKI_DIR…}/…` mounts."""
    out: dict[str, str] = {}
    for vol in svc.get("volumes") or []:
        if isinstance(vol, dict):
            src, dst = str(vol.get("source") or ""), str(vol.get("target") or "")
        else:
            depth, cut = 0, None
            for i, ch in enumerate(str(vol)):
                depth += ch == "{"
                depth -= ch == "}"
                if ch == ":" and depth == 0:
                    cut = i
                    break
            if cut is None:
                continue
            src, rest = str(vol)[:cut], str(vol)[cut + 1 :]
            dst = rest.split(":")[0]
        m = re.match(r"^\$\{?NOO_PKI_DIR(?::?-[^}]*)?\}?/?(?P<rel>.*)$", src)
        if m:
            out[m.group("rel")] = dst
    return out


def test_grafana_mounts_only_the_public_half_at_the_path_key_file_names(
    ini: configparser.ConfigParser, services: dict
) -> None:
    mounts = _pki_mounts(services["grafana"])
    assert mounts, "grafana has no PKI mounts — the projection or the mount syntax changed"
    key_file = ini.get("auth.jwt", "key_file")
    pub_rel = _rust_const(PKI_RS.read_text(), "GRAFANA_SSO_PUB_REL")
    assert mounts.get(pub_rel) == key_file, f"key_file={key_file!r} but grafana mounts {mounts}"
    # Grafana holds no private key from sso/: not the key, not the directory.
    assert not any(rel == "sso" or rel.startswith("sso/") and rel.endswith(".key") for rel in mounts), mounts
    assert not any(v.endswith(".key") and "/sso/" in v for v in mounts.values()), mounts


def test_the_gateway_reads_the_private_half_under_its_pki_mount(services: dict) -> None:
    gw = services["gateway"]
    env = env_of(gw)
    key_rel = _rust_const(MONITORING_RS.read_text(), "GRAFANA_SSO_KEY_REL")
    assert key_rel == _rust_const(PKI_RS.read_text(), "GRAFANA_SSO_KEY_REL"), "the CLI writes where the gateway reads"
    key_env = _rust_const(MONITORING_RS.read_text(), "GRAFANA_SSO_KEY_ENV")
    url_env = _rust_const(MONITORING_RS.read_text(), "GRAFANA_URL_ENV")
    assert key_env in env and url_env in env, f"gateway env lacks {key_env}/{url_env}: {sorted(env)[:5]}…"
    mounts = _pki_mounts(gw)
    # Where the key is inside the container, through whichever PKI mount
    # covers it — `sso/` the earlier change took the root away.
    served = set()
    for rel, dst in mounts.items():
        if rel == "":
            served.add(f"{dst}/{key_rel}")
        elif key_rel == rel:
            served.add(dst)
        elif key_rel.startswith(rel + "/"):
            served.add(f"{dst}/{key_rel[len(rel) + 1:]}")
    assert served, f"no gateway PKI mount carries {key_rel}: {mounts}"
    assert env[key_env] in served, (env[key_env], sorted(served))
    assert "GRAFANA_ROOT_URL" in env[url_env], "NOO_GRAFANA_URL must be the browser's URL, GRAFANA_ROOT_URL"
    # The same path the CLI's `issue-sso-key` writes, relative to the PKI dir.
    assert key_rel.startswith("sso/") and not key_rel.startswith("services/"), "sso/ keeps it out of the leaf loops"


def test_the_route_is_in_the_spec_and_mounted_by_its_literal() -> None:
    spec = json.loads((ROOT / "src" / "noomesh" / "gateway" / "static" / "openapi.json").read_text())
    assert "/api/monitoring/grafana-session" in spec["paths"]
    src = MONITORING_RS.read_text()
    assert '.route("/api/monitoring/grafana-session"' in src, "register the literal, or the generator cannot see it"


def test_the_viewer_grant_ships_in_the_same_compose_as_the_configs(services: dict, ini: configparser.ConfigParser) -> None:
    """an earlier change (fail closed). The gateway grants read-only users a
    Grafana Viewer only when its compose declares NOO_GRAFANA_DS_VIA_GATEWAY=1.
    The compose and configs/grafana/ ship in the same CLI release, so an older
    CLI rolling a newer gateway image renders its own compose WITHOUT the
    declaration while laying down its own direct data sources: the gateway
    then refuses the Viewer. The value is a literal, never an .env knob."""
    gate = _rust_const(AUTH_RS.read_text(), "GRAFANA_DS_GATE_ENV")
    assert gate == "NOO_GRAFANA_DS_VIA_GATEWAY"
    env = env_of(services["gateway"])
    assert env.get(gate) == "1", f"the gateway service must declare {gate}=1: {env.get(gate)!r}"
    raw = (ROOT / "docker-compose.cluster.yml").read_text()
    assert f"      - {gate}=1\n" in raw, "a literal in the compose file, not ${…} from .env"
    # The data sources the same release ships go through the gateway.
    for typ, url in _datasource_urls().items():
        assert url == f"{GATEWAY_DS}{typ}", url
    # The probe signs in with the header Grafana reads.
    assert _rust_const(AUTH_RS.read_text(), "GRAFANA_JWT_HEADER") == ini.get("auth.jwt", "header_name")


def test_a_stack_roll_recreates_grafana() -> None:
    """New grafana.ini / provisioning only load when the container is
    recreated: grafana.ini is a FILE bind mount, pinned to the inode it was
    created with, and Grafana reads data-source provisioning at start. The
    roll (`noo upgrade --stack`) runs the launcher with no service names,
    and that path force-recreates every service, grafana included."""
    upgrade = (ROOT / "noo-cli" / "src" / "commands" / "upgrade.rs").read_text()
    # The launcher invocation lives in the launch phase of the roll.
    body = upgrade.split("fn launch_stack(", 1)[1].split("\n}\n", 1)[0]
    assert '.arg(root.join("scripts/noomesh-start.sh")).arg("--dist")\n' in body, "the roll names no services"
    start = (ROOT / "scripts" / "noomesh-start.sh").read_text()
    full = start.split('if [ ${#SERVICES[@]} -eq 0 ]', 1)
    assert len(full) == 2, "the launcher's all-services branch moved — re-read it"
    all_branch = full[1].split("\nelse\n", 1)[0]
    assert "up -d --force-recreate" in all_branch, "the all-services `up` must force-recreate"


# Grafana's calls home, each turned off (PR #692). Grafana 12.4
# makes every one of these by default (`defaults.ini`); measured on 12.4.11
# with a DNS/SYN capture, the defaults reached grafana.com and
# storage.googleapis.com within a minute and this file reaches nothing.
# `noo cluster verify --controller` FAILs its "grafana door" row on the same
# list (`grafana_door::PHONE_HOME`), which the last test holds to this one.
PHONE_HOME_OFF = {
    ("analytics", "reporting_enabled"): "false",
    ("analytics", "check_for_updates"): "false",
    ("analytics", "check_for_plugin_updates"): "false",
    ("analytics", "feedback_links_enabled"): "false",
    ("news", "news_feed_enabled"): "false",
    ("snapshots", "external_enabled"): "false",
    ("security", "disable_gravatar"): "true",
    ("plugins", "plugin_admin_enabled"): "false",
    ("plugins", "public_key_retrieval_disabled"): "true",
    ("plugins", "preinstall_disabled"): "true",
    ("plugins", "preinstall_auto_update"): "false",
    ("cloud_migration", "enabled"): "false",
}
GRAFANA_DOOR_RS = ROOT / "noo-cli" / "src" / "commands" / "grafana_door.rs"


@pytest.mark.parametrize(("section", "key"), sorted(PHONE_HOME_OFF))
def test_grafana_does_not_phone_home(ini: configparser.ConfigParser, section: str, key: str) -> None:
    assert ini.has_option(section, key), f"[{section}] {key} is left to Grafana's default, which calls home"
    assert ini.get(section, key) == PHONE_HOME_OFF[(section, key)], f"[{section}] {key}"


def test_grafana_com_api_points_at_grafanas_own_loopback(ini: configparser.ConfigParser) -> None:
    """The calls no switch turns off — the remote plugin catalog behind
    Administration → Plugins (/api/gnet) and the angular-detection pattern
    refresh — were measured still reaching grafana.com with every switch
    above off; they go to a closed loopback port instead."""
    assert ini.get("grafana_com", "api_url") == "http://127.0.0.1:9/api"


def test_the_verify_row_judges_the_same_list() -> None:
    body = GRAFANA_DOOR_RS.read_text().split("pub const PHONE_HOME:", 1)[1].split("];", 1)[0]
    rows = re.findall(r'\("([a-z_.]+)",\s*"([a-z_]+)",\s*"(true|false)",\s*"(true|false)"', body)
    assert rows, "PHONE_HOME not found — the grep is stale, not the table"
    assert {(s, k): off for s, k, off, _ in rows} == PHONE_HOME_OFF
    # Each default is the opposite of off: the row's absent-key reading.
    assert all(off != default for _, _, off, default in rows)


def test_a_bookmark_of_grafana_leads_to_the_console(ini: configparser.ConfigParser, services: dict) -> None:
    """Grafana has no login form, so a bookmark of its port (or an expired
    session) lands on a bare /login. On the tailnet door serve maps /login to
    Grafana's /logout, which answers 302 to signout_redirect_url for anyone
    (measured on 12.4.11): the console URL compose passes."""
    assert ini.get("auth", "signout_redirect_url") == "$__env{NOO_GRAFANA_CONSOLE_URL}"
    env = env_of(services["grafana"])
    assert "NOO_GRAFANA_CONSOLE_URL" in env, "compose must hand Grafana the console URL"
    # Not a GF_AUTH_* override: the verify row FAILs any of those.
    assert not any(k.startswith("GF_AUTH_") for k in env)
    serve = (ROOT / "noo-cli" / "src" / "tailnet_serve.rs").read_text()
    assert 'pub const GRAFANA_LOGIN_MOUNT: &str = "/login";' in serve
    assert 'format!("https://127.0.0.1:{port}/logout")' in serve
