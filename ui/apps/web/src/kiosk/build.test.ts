// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 PersonifAI LLC

import { readFileSync } from 'node:fs';
import { resolve } from 'node:path';
import { describe, it, expect } from 'vitest';
import { CONSOLE_BUILD } from './build';

describe('the console carries the build it came from', () => {
  it('is a string, and says so honestly when built outside a release', () => {
    expect(typeof CONSOLE_BUILD).toBe('string');
    expect(CONSOLE_BUILD.length).toBeGreaterThan(0);
    // A local `npm run build` has no tag; it must not claim one.
    expect(CONSOLE_BUILD).toBe('dev');
  });

  it('the entry publishes it, or nothing on the wire can be checked', () => {
    const src = readFileSync(resolve(process.cwd(), 'src/kiosk/main.tsx'), 'utf8')
      .replace(/\/\*[\s\S]*?\*\//g, '')
      .split('\n')
      .filter((l) => !l.trim().startsWith('//'))
      .join('\n');
    expect(src, 'main.tsx no longer imports the build stamp: this guard is stale').toContain(
      'CONSOLE_BUILD',
    );
    expect(src).toContain('__nooKioskBuild');
  });

  it('the release workflow passes the tag in, or every console says dev', () => {
    const wf = readFileSync(resolve(process.cwd(), '../../../.github/workflows/publish-web.yml'), 'utf8');
    expect(wf, 'the build step moved: this guard is stale').toContain('npm run build -w @metis/web');
    expect(wf).toMatch(/NOO_CONSOLE_BUILD:\s*\S/);
  });
});
