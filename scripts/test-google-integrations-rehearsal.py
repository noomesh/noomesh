#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-only
# Copyright 2026 PersonifAI LLC
"""Rehearse personal Google boundaries with fixtures and disposable PostgreSQL.

No controller credentials, provider calls, host ports, or installation files.
Build the gateway test binary with scripts/cargo-docker.sh first; see
docs/channels/google-connections.md for the release checklist.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import subprocess
import sys
import time
import uuid


ROOT = Path(__file__).resolve().parents[1]
# Minimum counts fail closed if a renamed filter would under-run the rehearsal.
SUITES = {
    "repo::integration_content::": 8,
    "repo::integrations::": 1,
    "repo::integration_pairing::": 1,
    "repo::connections::": 1,
    "integrations::": 10,
    "routes::connections::": 4,
    "connections::tests::": 4,
    "pg_stat_statements_revision_is_ordered_and_idempotent": 1,
    "embedding_space_migration_revision_adds_nullable_columns": 1,
}


def run(*args: str, check: bool = True, timeout: int = 120) -> subprocess.CompletedProcess:
    return subprocess.run(args, cwd=ROOT, text=True, stdout=subprocess.PIPE,
                          stderr=subprocess.STDOUT, check=check, timeout=timeout)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--gateway-tests", required=True, type=Path,
                        help="freshly built gateway libtest executable from cargo test --no-run")
    parser.add_argument("--postgres-image", default="pgvector/pgvector:pg18")
    parser.add_argument("--runner-image", default="rust:1-bookworm")
    args = parser.parse_args()
    binary = args.gateway_tests.resolve(strict=True)
    if not binary.is_file() or not os.access(binary, os.X_OK):
        parser.error("--gateway-tests must name an executable file")
    images = {}
    for image in (args.postgres_image, args.runner_image):
        images[image] = run("docker", "image", "inspect", "--format", "{{.Id}}", image).stdout.strip()
    name = "noo-google-rehearsal-" + uuid.uuid4().hex[:12]
    database = name + "-pg"
    network_created = False
    database_started = False
    digest = hashlib.sha256()
    with binary.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    binary_hash = digest.hexdigest()
    report = {"head": run("git", "rev-parse", "HEAD").stdout.strip(),
              "tracked_dirty": bool(run("git", "status", "--porcelain", "--untracked-files=no").stdout),
              "test_binary_sha256": binary_hash,
              "images": images, "suites": []}
    try:
        run("docker", "network", "create", "--internal", name)
        network_created = True
        # Trust is confined to this new internal network, with no published
        # ports. Both containers are disposable; nothing mounts an install.
        database_started = True
        run("docker", "run", "--detach", "--rm", "--pull=never", "--name", database,
            "--network", name, "--network-alias", "postgres", "--read-only",
            "--tmpfs", "/var/lib/postgresql:rw", "--tmpfs", "/var/run/postgresql:rw",
            "--tmpfs", "/tmp:rw", "--memory", "1g",
            "-e", "PGDATA=/var/lib/postgresql/rehearsal",
            "-e", "POSTGRES_HOST_AUTH_METHOD=trust", "-e", "POSTGRES_USER=noo",
            "-e", "POSTGRES_DB=noomesh", args.postgres_image)
        for _ in range(60):
            if run("docker", "exec", database, "pg_isready", "-U", "noo", "-d", "noomesh",
                   check=False).returncode == 0:
                break
            time.sleep(1)
        else:
            raise RuntimeError("disposable PostgreSQL did not become ready")
        container_args = (
            "docker", "run", "--rm", "--pull=never", "--read-only", "--cap-drop", "ALL",
            "--security-opt", "no-new-privileges", "--user", f"{os.getuid()}:{os.getgid()}",
            "--memory", "2g", "--network", name, "--entrypoint", "/integration-tests",
            "--mount", f"type=bind,src={binary},dst=/integration-tests,readonly",
            "-e", "NOO_REQUIRE_GOOGLE_REHEARSAL=1",
        )
        # Prove the same binary refuses the otherwise silent no-DSN skip.
        refusal = run(*container_args, args.runner_image,
                      "repo::connections::tests::connections_keep_multiple_accounts_and_sources_private",
                      "--exact", "--test-threads=1", check=False)
        if refusal.returncode == 0 or "Google rehearsal requires NOO_BROKER_TEST_DSN" not in refusal.stdout:
            raise RuntimeError("missing-DSN refusal did not execute as expected")
        report["missing_dsn_refused"] = True
        for suite, minimum in SUITES.items():
            skips = ("--skip", "repo::integrations::") if suite == "integrations::" else ()
            if suite == "connections::tests::":
                skips = ("--skip", "repo::connections::", "--skip", "routes::connections::")
            result = run(*container_args,
                         "-e", "NOO_BROKER_TEST_DSN=postgresql://noo@postgres:5432/noomesh",
                         args.runner_image, suite, *skips, "--test-threads=1", check=False, timeout=300)
            print(result.stdout, end="", file=sys.stderr)
            verdict = re.search(r"test result: ok\. (\d+) passed; 0 failed; (\d+) ignored", result.stdout)
            if result.returncode or not verdict or int(verdict[1]) < minimum or int(verdict[2]):
                raise RuntimeError(f"rehearsal failed or under-ran: {suite}")
            report["suites"].append({"filter": suite, "passed": int(verdict[1])})
        report["passed"] = sum(s["passed"] for s in report["suites"])
        report["ok"] = True
        print(json.dumps(report, indent=2))
        return 0
    finally:
        # Remove only this invocation's resources, including on test failure.
        if database_started:
            run("docker", "rm", "--force", database, check=False)
        if network_created:
            run("docker", "network", "rm", name, check=False)


if __name__ == "__main__":
    try:
        sys.exit(main())
    except (OSError, RuntimeError, subprocess.SubprocessError) as exc:
        print(f"Google integration rehearsal failed: {exc}", file=sys.stderr)
        sys.exit(1)
