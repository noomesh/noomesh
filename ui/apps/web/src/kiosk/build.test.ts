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

  it('the release workflow passes a CONTENT identity in, never the tag', () => {
    const wf = readFileSync(resolve(process.cwd(), '../../../.github/workflows/publish-web.yml'), 'utf8');
    expect(wf, 'the build step moved: this guard is stale').toContain('npm run build -w @metis/web');
    // ui-<tree hash of ui/>: equal for an rc and its final, so a final can
    // re-tag the rc's gateway; a stale display still reports its OLD id.
    expect(wf).toContain('tree="$(git rev-parse HEAD:ui)"');
    expect(wf).toContain('NOO_CONSOLE_BUILD: ${{ steps.console.outputs.value }}');
    expect(wf, 'the console must not carry the release tag again').not.toMatch(/NOO_CONSOLE_BUILD:\s*stack-/);
    expect(wf, 'the gateway serves this file').toContain('ui/apps/web/dist/console-build.txt');
  });
});
