// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 PersonifAI LLC

// The typed client's schema is GENERATED: `npm run gen:api` writes
// src/schema.d.ts from ../../contracts/openapi.json. Nothing used to check
// that the committed file is what the generator makes from the committed
// contract, so a route could land in the contract and never reach the
// types (two did: the add-on workload reserve and release). This runs the
// same generator, at the version the lockfile pins, into a temp file and
// refuses any difference.
//
// Run with `npm run check:api` from ui/ (CI's console job does).

import { spawnSync } from "node:child_process";
import { mkdtempSync, readFileSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

const pkg = join(dirname(fileURLToPath(import.meta.url)), "..");
const contract = join(pkg, "..", "..", "contracts", "openapi.json");
const committed = join(pkg, "src", "schema.d.ts");

const dir = mkdtempSync(join(tmpdir(), "schema-check-"));
const fresh = join(dir, "schema.d.ts");
try {
  // `npm run` puts the workspace's node_modules/.bin on PATH, so this is
  // the locked openapi-typescript, never a fetched one.
  const run = spawnSync("openapi-typescript", [contract, "-o", fresh], { cwd: pkg, encoding: "utf8" });
  if (run.error || run.status !== 0) {
    console.error(`could not run openapi-typescript: ${run.error ?? run.stderr}`);
    process.exit(2);
  }
  const want = readFileSync(fresh, "utf8");
  const got = readFileSync(committed, "utf8");
  if (got !== want) {
    const a = got.split("\n");
    const b = want.split("\n");
    let i = 0;
    while (i < a.length && i < b.length && a[i] === b[i]) i++;
    console.error("packages/api/src/schema.d.ts is not what the generator makes from contracts/openapi.json.");
    console.error(`first difference at line ${i + 1}:`);
    console.error(`  committed: ${a[i] ?? "<end of file>"}`);
    console.error(`  generated: ${b[i] ?? "<end of file>"}`);
    console.error("Fix: cd ui && npm run gen:api, then commit src/schema.d.ts.");
    process.exit(1);
  }
  console.log("schema.d.ts matches contracts/openapi.json.");
} finally {
  rmSync(dir, { recursive: true, force: true });
}
