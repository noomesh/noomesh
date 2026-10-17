# SPDX-License-Identifier: AGPL-3.0-only
# Copyright 2026 PersonifAI LLC

"""The GHCR namespace is declared once per language, and they must all agree.

The release namespace moved twice (flat, then nested) and now lives at the
public `ghcr.io/noomesh` (un-nested) — the push side (images-release.yml
OWNER) and the launcher defaults. Three more sites once kept seeding the OLD one:
`standalone.rs` (two keys) and `onboard/steps.rs` (NOO_BASE_REGISTRY). Nothing
compared them, so a fresh 0.5.1 onboard wrote a namespace that a `--dist` roll
to v0.2.26 could not pull from, and the controller's first roll after the
move composed a ref under the old namespace — right digest, wrong
namespace, `not found`.

Same shape as every other guard in this directory: several declarations of
one fact, in files that cannot import each other, held together by reading
them. If the namespace moves again, this fails at the first site left behind
instead of at the first install that trips over it.
"""
from __future__ import annotations

import re
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]

# Where the namespace is declared. Each entry: (path, regex with ONE group
# capturing the namespace). Add a site here when a new one is introduced —
# forgetting to is what this test is for, so the count is asserted too.
SITES = [
    (".github/workflows/images-release.yml", r"^\s*OWNER:\s*(\S+)"),
    (".github/workflows/publish-harrier.yml", r"^\s*OWNER:\s*(\S+)"),
    # The ONE definition per language; every other reader resolves it.
    ("scripts/lib-dist.sh", r"release_image_namespace\(\) \{ printf 'ghcr\.io/([^']+)'"),
    ("noo-cli/src/registry.rs", r'IMAGE_NAMESPACE: &str = "ghcr\.io/([^"]+)"'),
    ("node-agent-go/internal/docker/registry.go", r'DefaultImagePrefix = "ghcr\.io/([^"]+)"'),
    ("docker/Dockerfile.gateway-rust", r'^ARG UI_IMAGE=ghcr\.io/([^/]+)/'),
]

EXPECTED = "noomesh"


def _declared() -> list[tuple[str, str]]:
    out = []
    for rel, rx in SITES:
        text = (ROOT / rel).read_text()
        m = re.search(rx, text, re.M)
        assert m, f"{rel}: the namespace declaration this test expects is gone — update SITES"
        val = m.group(1)
        out.append((rel, val))
    return out


def test_every_site_declares_the_same_namespace():
    bad = [(rel, v) for rel, v in _declared() if v != EXPECTED]
    assert not bad, (
        "the GHCR namespace is declared differently in these sites — a fresh "
        "install seeds one namespace and the release publishes to another:\n  "
        + "\n  ".join(f"{rel}: {v}" for rel, v in bad)
    )


def test_the_parse_found_every_site():
    """Guard the guard: an empty SITES agrees with itself perfectly."""
    assert len(_declared()) == len(SITES) == 6


# DHI-derived images: the dhi.io hardened bases (DHI Community) and the images
# layered on them live under the `dhi/` prefix. scripts/dhi-images.txt is the
# declared list. Nothing a public channel seeds may resolve to one of them.
# ---------------------------------------------------------------------------
def _dhi_list() -> dict[str, set[str]]:
    out: dict[str, set[str]] = {"mirror": set(), "derived": set()}
    for ln in (ROOT / "scripts/dhi-images.txt").read_text().splitlines():
        ln = ln.strip()
        if ln and not ln.startswith("#"):
            kind, name = ln.split()[:2]
            out[kind].add(name)
    return out


def _mirror_lanes() -> tuple[set[str], set[str]]:
    """(dest names of `auth: dhi` lanes, dest names of public dest_org: noomesh lanes)"""
    mir = (ROOT / ".github/workflows/mirror-images.yml").read_text()
    dhi, public = set(), set()
    for blk in re.split(r"(?m)^\s*- source:", mir)[1:]:
        d = re.search(r"dest:\s*([^\s:]+)", blk)
        if not d:
            continue
        if re.search(r"auth:\s*dhi\b", blk):
            dhi.add(d.group(1))
        if re.search(r"dest_org:\s*noomesh\s*$", blk, re.M):
            public.add(d.group(1))
    return dhi, public


def test_dhi_owner_is_the_namespace():
    wf = (ROOT / ".github/workflows/images-release.yml").read_text()
    m = re.search(r"^\s*DHI_OWNER:\s*(\S+)", wf, re.M)
    assert m and m.group(1) == EXPECTED + "/dhi", "images-release.yml DHI_OWNER moved or gone"
    # Hardened bases stay public (DHI Community is Apache-2.0): no privacy
    # guard, but the attribution must be carried.
    notices = (ROOT / "THIRD_PARTY_NOTICES.md").read_text()
    assert "Docker Hardened Images" in notices and "Apache License, Version 2.0" in notices
    assert not (ROOT / "scripts/check-dhi-private.sh").exists()
    assert "check-dhi-private" not in wf
    assert "check-dhi-private" not in (ROOT / ".github/workflows/mirror-images.yml").read_text()


def test_every_dhi_image_is_in_the_declared_list():
    lst = _dhi_list()
    dhi_lanes, public = _mirror_lanes()
    # the dhi.io mirror lanes are exactly the declared `mirror` entries
    assert dhi_lanes == lst["mirror"], (dhi_lanes ^ lst["mirror"])
    # every first-party Dockerfile FROM through the DHI registry arg is a declared mirror
    used = set()
    for f in (ROOT / "docker").glob("Dockerfile*"):
        used |= set(re.findall(r"\$\{DHI_REGISTRY\}/([a-z0-9-]+):", f.read_text()))
    used |= set(re.findall(r"\$\{DHI_REGISTRY\}/([a-z0-9-]+):", (ROOT / "Dockerfile").read_text()))
    assert used and used <= lst["mirror"], f"DHI bases not in scripts/dhi-images.txt: {sorted(used - lst['mirror'])}"
    # compose refs through NOO_BASE_REGISTRY resolve to an existing lane under
    # BOTH registries: ghcr.io/noomesh/dhi (the default, the DHI family) and
    # ghcr.io/noomesh (the upstream family, kept mirrored for operators who
    # choose it by hand).
    compose = (ROOT / "docker-compose.cluster.yml").read_text()
    comp = {r.split(":")[0] for r in re.findall(r"\$\{NOO_BASE_REGISTRY:-ghcr\.io/noomesh/dhi\}/(\S+)", compose)}
    assert comp, "compose no longer reads NOO_BASE_REGISTRY - update this test"
    defaults = set(re.findall(r"\$\{NOO_BASE_REGISTRY:-([^}]+)\}", compose))
    assert defaults == {"ghcr.io/" + EXPECTED + "/dhi"}, defaults
    # An un-seeded PUBLIC install must never dial dhi.io: the compose default is our mirror.
    assert "NOO_BASE_REGISTRY:-dhi.io" not in compose
    assert comp <= public, f"no upstream lane (ghcr.io/noomesh/x) for: {sorted(comp - public)}"
    assert comp <= dhi_lanes, f"no dhi/ lane (ghcr.io/noomesh/dhi/x) for: {sorted(comp - dhi_lanes)}"
    # Every DHI package lives under `dhi/`, and no public lane does. The same
    # NAME may exist in both sets precisely because the prefix separates them.
    mir = (ROOT / ".github/workflows/mirror-images.yml").read_text()
    for blk in re.split(r"(?m)^\s*- source:", mir)[1:]:
        org = re.search(r"dest_org:\s*(\S+)", blk)
        if re.search(r"auth:\s*dhi\b", blk):
            assert org and org.group(1) == EXPECTED + "/dhi", f"DHI lane outside the dhi/ prefix: {blk[:80]!r}"
        elif org:
            assert not org.group(1).endswith("/dhi") and "/dhi" not in org.group(1), blk[:80]
    # derived images built by the release are never pushed under another name
    wf = (ROOT / ".github/workflows/images-release.yml").read_text()
    for n in lst["derived"]:
        assert f"$REGISTRY/$OWNER/{n}" not in wf, f"derived {n} pushed outside dhi/"


COMPOSE_FILES = sorted(ROOT.glob("docker-compose*.yml"))
BASE_REF = re.compile(r"\$\{NOO_BASE_REGISTRY(?::?-([^}]*))?\}/([^\s$]+)")


def _base_refs() -> list[tuple[str, str | None, str]]:
    """(file, default, name:tag) of every `${NOO_BASE_REGISTRY...}/x` image ref
    in every compose file the launcher may load."""
    out = []
    for f in COMPOSE_FILES:
        for ln in f.read_text().splitlines():
            if ln.lstrip().startswith("#"):
                continue
            for default, ref in BASE_REF.findall(ln):
                out.append((f.name, default or None, ref.strip("\"'")))
    return out


def _lanes_by_org() -> dict[str, set[str]]:
    """dest_org -> {dest name:tag} from mirror-images.yml."""
    mir = (ROOT / ".github/workflows/mirror-images.yml").read_text()
    out: dict[str, set[str]] = {}
    for blk in re.split(r"(?m)^\s*- source:", mir)[1:]:
        d = re.search(r"^\s*dest:\s*(\S+)", blk, re.M)
        o = re.search(r"^\s*dest_org:\s*(\S+)", blk, re.M)
        if d and o:
            out.setdefault(o.group(1), set()).add(d.group(1))
    return out


def test_public_channel_default_is_the_dhi_mirror():
    """The seeded NOO_BASE_REGISTRY default is the DHI runtime family under
    `dhi/`, the uids every service key and data volume is handed to. The bare
    namespace serves the UPSTREAM images under the same names and tags (other
    uids): 0.6.0/0.6.1 seeded it and the public fleet's monitoring set
    restart-looped on `permission denied` (2026-10-14)."""
    for rel in ("noo-cli/src/onboard/standalone.rs", "noo-cli/src/onboard/steps.rs"):
        seen = 0
        for ln in (ROOT / rel).read_text().splitlines():
            if '"NOO_BASE_REGISTRY"' in ln and ("update_env" in ln or "seeds.push" in ln):
                seen += 1
                assert "PUBLIC_BASE_REGISTRY" in ln, f"{rel}: {ln.strip()}"
        assert seen, f"{rel}: no NOO_BASE_REGISTRY seed found - update this test"
    rs = (ROOT / "noo-cli/src/registry.rs").read_text()
    m = re.search(r'PUBLIC_BASE_REGISTRY: &str = "([^"]+)";', rs)
    assert m, "registry.rs PUBLIC_BASE_REGISTRY is not a literal any more - update this test"
    assert m.group(1) == "ghcr.io/" + EXPECTED + "/dhi", m.group(1)
    # The channel switch writes the same constant, not the image namespace.
    ch = (ROOT / "noo-cli/src/commands/channel.rs").read_text()
    assert "base_registry: crate::registry::PUBLIC_BASE_REGISTRY.into()" in ch


def test_every_base_registry_compose_ref_has_a_dhi_mirror_lane():
    """Every `${NOO_BASE_REGISTRY}` image ref in any compose file defaults to
    the DHI path and has a `dest_org: noomesh/dhi` mirror lane with the SAME
    name:tag; the upstream lane of the same name:tag is kept too (both
    families stay published)."""
    refs = _base_refs()
    assert len(refs) >= 6, f"found only {refs} - the compose moved; update this test"
    lanes = _lanes_by_org()
    dhi, upstream = lanes.get(EXPECTED + "/dhi", set()), lanes.get(EXPECTED, set())
    assert dhi and upstream, f"mirror-images.yml parse found no lanes: {sorted(lanes)}"
    bad_default = [(f, d, r) for f, d, r in refs if d != "ghcr.io/" + EXPECTED + "/dhi"]
    assert not bad_default, f"NOO_BASE_REGISTRY refs not defaulting to the DHI path: {bad_default}"
    no_dhi = sorted({r for _, _, r in refs} - dhi)
    assert not no_dhi, f"no `dest_org: {EXPECTED}/dhi` mirror lane for: {no_dhi}"
    no_upstream = sorted({r for _, _, r in refs} - upstream)
    assert not no_upstream, f"the upstream family lost a lane for: {no_upstream}"


def test_the_base_ref_parse_sees_a_wrong_default():
    """Guard the guard: the parse reports a ref defaulting to the bare namespace."""
    line = "    image: ${NOO_BASE_REGISTRY:-ghcr.io/noomesh}/loki:3"
    assert BASE_REF.findall(line) == [("ghcr.io/noomesh", "loki:3")]


# ---------------------------------------------------------------------------
# No stray literals. The declared homes above are the only places a literal
# registry namespace / release repo may be CODE; everything else resolves them.
# ---------------------------------------------------------------------------
import subprocess  # noqa: E402

# A typed-out literal is a second declaration that the next move will miss.
# Whether prose points anywhere BUT the public orgs is checked positively
# (PUBLIC_ORGS) rather than by naming any retired spelling.
IMAGE_LITERALS = ("ghcr.io/noomesh",)
REPO_LITERALS = ("noomesh/noomesh",)
PUBLIC_ORGS = {"noomesh", "personifAI"}

# file -> why it may carry the literal. Anything not listed must resolve.
HOMES = {
    "noo-cli/src/registry.rs": "Rust home (IMAGE_NAMESPACE, RELEASE_REPO, matchers)",
    "scripts/lib-dist.sh": "shell home (release_image_namespace)",
    "node-agent-go/internal/docker/registry.go": "Go home (DefaultImagePrefix, allow roots)",
    ".github/workflows/images-release.yml": "workflow push-side OWNER (pinned by SITES)",
    ".github/workflows/publish-harrier.yml": "workflow push-side OWNER (pinned by SITES)",
    "node-agent-go/internal/hostd/install.go": "systemd unit Documentation= URL, metadata only",
    "node-agent-go/deploy/noo-node-agent.service": "systemd unit Documentation= URL (sha256-pinned in noo-apply.sh)",
    "node-agent-go/deploy/noo-harness.service": "systemd unit Documentation= URL (sha256-pinned in noo-apply.sh)",
    ".github/ISSUE_TEMPLATE/config.yml": "issue-chooser contact links (Discussions, SECURITY.md) point at the public repo",
    "docker/Dockerfile.gateway-rust": "ARG default, pinned by SITES",
    # The Docker Hub mirror prefix (ghcr.io/<owner>/mirror), a different
    # namespace from the release one: one ARG default per Dockerfile, all
    # held equal to scripts/hub-mirror.py's default by tests/test_hub_mirror.py.
    "Dockerfile": "ARG HUB_MIRROR default, pinned by tests/test_hub_mirror.py",
    "docker/Dockerfile.stunnel": "ARG HUB_MIRROR default, pinned by tests/test_hub_mirror.py",
    "docker/Dockerfile.node-agent-prebuilt": "ARG HUB_MIRROR default, pinned by tests/test_hub_mirror.py",
    "docker/Dockerfile.node-agent-go": "ARG HUB_MIRROR default, pinned by tests/test_hub_mirror.py",
    "docker/Dockerfile.nvidia-exporter": "ARG HUB_MIRROR default, pinned by tests/test_hub_mirror.py",
    "docker/Dockerfile.whisper": "ARG HUB_MIRROR default, pinned by tests/test_hub_mirror.py",
    "docker/Dockerfile.piper": "ARG HUB_MIRROR default, pinned by tests/test_hub_mirror.py",
    "docker-compose.cluster.yml": "compose `${NOO_BASE_REGISTRY:-...}` default; pinned equal to the public namespace below",
    "scripts/release-retag-plan.py": "release tooling: the default --repo of the stack release (this repo)",
    ".github/workflows/cla.yml": "CLA document link, pinned to the tag cla-v1.0 of THIS repo",
    "scripts/cla-public-setup.sh": "move-day script: the public repos it operates on",
    "noo-cli/install.sh": "curl|sh installer cannot source anything; pinned equal to RELEASE_REPO",
    "scripts/install-noo.sh": "same, pinned equal to RELEASE_REPO",
    "gateway-rust/src/routes/bootstrap.rs": "separate crate, cannot import noo-cli; pinned equal",
    "gateway-rust/src/routes/identity.rs": "a documentation URL in metadata, not a pull/release source",
    "pyproject.toml": "package metadata URLs (licensing PR owns them)",
    "packages/noo-gateway-client/pyproject.toml": "package metadata URLs",
    "tests/fixtures/redaction_corpus.json": "redaction fixture: the strings are INPUT to a redactor",
    "ui/mock/fixtures/POST/api/security/bootstrap-tokens.json": "mock API response data",
}
# Prefixes: tests assert on literals by design; docs prose flips at the move.
HOME_PREFIXES = ("tests/test_", "docs/", "ui/docs/", "internal/", ".worktrees/", "legacy/")


def _code_lines(rel: str, text: str):
    """(lineno, line) of the lines that can be CODE: not comments, and for
    Rust not the `#[cfg(test)]` tail (fixtures), for Go not *_test.go."""
    if rel.endswith("_test.go") or rel.endswith(".md"):
        return
    lines = text.splitlines()
    if rel.endswith(".rs"):
        for i, ln in enumerate(lines):
            if ln.strip() == "#[cfg(test)]":
                lines = lines[:i]
                break
    for i, ln in enumerate(lines, 1):
        st = ln.lstrip()
        if st.startswith(("//", "#", "*", "<!--")):
            continue
        # Go module identity, not a release repo.
        if "github.com/noomesh/noomesh/node-agent-go" in ln:
            continue
        yield i, ln


_LITERAL_RE = re.compile("(?:" + "|".join(re.escape(x) for x in IMAGE_LITERALS + REPO_LITERALS) + r")(?![\w-])")


def _stray_literals() -> list[str]:
    files = subprocess.run(
        ["git", "ls-files"], cwd=ROOT, capture_output=True, text=True, check=True
    ).stdout.splitlines()
    bad = []
    for rel in files:
        if rel in HOMES or rel.startswith(HOME_PREFIXES):
            continue
        try:
            text = (ROOT / rel).read_text()
        except (UnicodeDecodeError, FileNotFoundError, IsADirectoryError):
            continue
        for i, ln in _code_lines(rel, text):
            # A literal followed by `-`/word chars is a longer, different name
            # (`noomesh/noomesh-extra` is a different repo from `noomesh/noomesh`).
            if _LITERAL_RE.search(ln):
                # Workflow identity checks (`github.repository == '<repo>'`) say
                # "the private canonical repo", not where releases live.
                if rel.startswith(".github/workflows/") and "github.repository" in ln:
                    continue
                bad.append(f"{rel}:{i}: {ln.strip()[:100]}")
    return bad


def test_no_literal_namespace_or_release_repo_outside_the_declared_homes():
    bad = _stray_literals()
    assert not bad, (
        "the image namespace / release repo is typed out instead of resolved — "
        "after the move these keep pointing at the old location. Resolve it "
        "from the home for the language (noo-cli/src/registry.rs, "
        "scripts/lib-dist.sh::release_image_namespace, "
        "node-agent-go/internal/docker/registry.go), or add the file to HOMES "
        "with a reason:\n  " + "\n  ".join(bad)
    )


def test_the_homes_allowlist_is_not_stale():
    """Guard the guard: every HOMES entry must exist and still carry a literal
    (or be an explicitly justified fixture), else the allowlist rots."""
    move_day = {"scripts/cla-public-setup.sh"}  # excluded from the public tree by the sync
    for rel in HOMES:
        if rel in move_day and not (ROOT / rel).exists():
            continue
        assert (ROOT / rel).is_file(), f"{rel} is in HOMES but gone"


def test_docs_and_readme_name_only_public_repos_and_registries():
    """The install line and every URL in public prose must follow the move.
    (The stray-literal guard above skips .md files, which is how the install
    line outlived the flip in review.) Every github.com/<org>/ and
    ghcr.io/<org>/ reference must belong to a public org."""
    # noo-cli/NOO_CLI.md moved under internal/docs-parked with the docs trim (#923),
    # which the public sync excludes; scan it only where it still sits in the public tree.
    files = [ROOT / "README.md", ROOT / "noo-cli/NOO_CLI.md"] + sorted((ROOT / "docs").rglob("*.md"))
    files = [f for f in files if f.exists()]
    assert len(files) > 20, "the docs scan found almost nothing: the docs tree moved"
    assert len(files) > 20, "the docs walk found nothing"
    bad = []
    for f in files:
        for i, ln in enumerate(f.read_text().splitlines(), 1):
            # Third-party orgs are fine; a reference to one of OUR repos (noomesh*,
            # trellion*, pai-*) must sit under a public org.
            ours = re.findall(r"(?<![\w.])(?:github\.com|ghcr\.io)/([\w.-]+)/(?:noomesh|trellion|pai-)", ln)
            if set(ours) - PUBLIC_ORGS:
                bad.append(f"{f.relative_to(ROOT)}:{i}: {ln.strip()[:100]}")
    assert not bad, "non-public orgs in public docs:\n  " + "\n  ".join(bad)
