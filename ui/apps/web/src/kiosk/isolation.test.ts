// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 PersonifAI LLC

// Acceptance test #1 from an earlier change: the kiosk bundle imports nothing
// from src/features or src/shell — asserted, not left to convention. This is
// what stops the display acquiring a chat pane over the next six months.
//
// Walks the source rather than the built bundle so it runs in `npm test`
// without a build, and so a violation names the file and the line.

import { describe, it, expect } from 'vitest';
import { readdirSync, readFileSync, statSync } from 'node:fs';
import { join, relative } from 'node:path';

const KIOSK = join(__dirname);
const FORBIDDEN = [
  /['"]@\/features\//,
  /['"]@\/shell\//,
  /['"](?:\.\.\/)+features\//,
  /['"](?:\.\.\/)+shell\//,
  /['"](?:\.\.\/)+App['"]/,
  // The console's composition root pulls in the whole panel registry.
  /['"](?:\.\.\/)+main['"]/,
];

function walk(dir: string, out: string[] = []): string[] {
  for (const name of readdirSync(dir)) {
    const p = join(dir, name);
    if (statSync(p).isDirectory()) walk(p, out);
    else if (/\.(tsx?|css)$/.test(name) && !/\.test\.tsx?$/.test(name)) out.push(p);
  }
  return out;
}

describe('kiosk bundle isolation', () => {
  const files = walk(KIOSK);

  it('has source files to check', () => {
    expect(files.length).toBeGreaterThan(0);
  });

  for (const f of files) {
    it(`${relative(KIOSK, f)} imports nothing from features/ or shell/`, () => {
      const lines = readFileSync(f, 'utf8').split(/\r?\n/);
      const hits = lines
        .map((line, i) => ({ line, n: i + 1 }))
        .filter(({ line }) => /^\s*(import|export)\b/.test(line) || /@import/.test(line))
        .filter(({ line }) => FORBIDDEN.some((re) => re.test(line)))
        .map(({ line, n }) => `${n}: ${line.trim()}`);
      expect(hits).toEqual([]);
    });
  }
});

describe('the kiosk carries no credential', () => {
  // The design changed on 2026-09-06: the token moved off the page and onto
  // the device's filesystem, held by `noo kiosk serve`. These assertions are
  // the thing that notices if it comes back — a bearer token in the DOM of a
  // machine standing unattended in a corridor is the weak point no amount of
  // scoping fixes.
  // `join(__dirname)` like the checks above — `import.meta.url` is not a
  // file URL under this runner.
  const entry = readFileSync(join(KIOSK, 'main.tsx'), 'utf8');

  it('does not read or write browser storage', () => {
    const code = entry.replace(/\/\/[^\n]*/g, '').replace(/\/\*[\s\S]*?\*\//g, '');
    expect(code).not.toMatch(/localStorage|sessionStorage|webTokenStore/);
  });

  it('builds no bearer transport', () => {
    const code = entry.replace(/\/\/[^\n]*/g, '').replace(/\/\*[\s\S]*?\*\//g, '');
    expect(code).not.toMatch(/createBearerFetch|tokenStore|Authorization/);
  });

  it('stays same-origin, which is now the local proxy', () => {
    // `baseUrl: ''` is load-bearing: the page is served BY `noo kiosk serve`,
    // so relative paths reach the proxy. An absolute gateway URL here would
    // put the controller's address back in the page and require a credential
    // to go with it.
    expect(entry).toMatch(/baseUrl:\s*''/);
    expect(entry).not.toMatch(/baseUrl:\s*['"`]https?:/);
  });
});
