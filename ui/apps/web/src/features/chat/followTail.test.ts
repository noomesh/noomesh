// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 PersonifAI LLC

import { describe, it, expect } from 'vitest';
import { readFileSync } from 'node:fs';
import { resolve } from 'node:path';
import { atTail, TAIL_SLACK } from './followTail';

describe('following the tail of a generation', () => {
  it('a transcript scrolled to the end is following', () => {
    expect(atTail({ scrollHeight: 2000, scrollTop: 1400, clientHeight: 600 })).toBe(true);
  });

  it('a reader who scrolled up to re-read is not', () => {
    expect(atTail({ scrollHeight: 2000, scrollTop: 400, clientHeight: 600 })).toBe(false);
  });

  it('a pixel short of the end still counts', () => {
    // The case that matters: browsers leave a sub-pixel gap at the true end,
    // and an exact comparison would read it as "the reader scrolled away" and
    // stop following mid-generation.
    expect(atTail({ scrollHeight: 2000, scrollTop: 1399, clientHeight: 600 })).toBe(true);
  });

  it('stops following once past the slack', () => {
    expect(
      atTail({ scrollHeight: 2000, scrollTop: 1400 - TAIL_SLACK - 1, clientHeight: 600 }),
    ).toBe(false);
  });

  it('content shorter than the viewport is always at the tail', () => {
    // Nothing to scroll. Reporting "not following" here would leave a short
    // conversation refusing to auto-scroll for the rest of its life.
    expect(atTail({ scrollHeight: 300, scrollTop: 0, clientHeight: 600 })).toBe(true);
  });

  it('the slack stays about one line, not a screenful', () => {
    expect(TAIL_SLACK).toBeGreaterThan(0);
    expect(TAIL_SLACK).toBeLessThanOrEqual(80);
  });
});

describe('the mobile shell can actually be scrolled', () => {
  const css = readFileSync(resolve(process.cwd(), 'src/app.css'), 'utf8');

  it('every dvh height is behind @supports, with a vh rule to fall back to', () => {
    // `.app.mobile` clips its own overflow. If `height: 100dvh` is dropped by
    // a browser that does not know the unit, the shell sizes to its content,
    // the clip hides everything past the fold, and the transcript is not a
    // scroll container at all — the exact report this guard was written for.
    // Desktop degrades into a page scrollbar instead, which is why this only
    // ever showed up on a phone.
    //
    // The form is load-bearing. Writing the pair in ONE block —
    // `height: 100vh; height: 100dvh;` — reads as the same intent and ships
    // as neither: esbuild's CSS minifier drops the first as dead and emits
    // only `100dvh`. That version passes any test written against the source
    // and fixes nothing in dist/, so this asserts the shape that survives the
    // build, not the intent.
    const lines = css.split('\n').map((l) => l.trim());
    const bad: string[] = [];
    lines.forEach((line, i) => {
      if (!/^height:\s*100dvh/.test(line)) return;
      const above = lines.slice(Math.max(0, i - 4), i).join(' ');
      if (!/@supports\s*\(height:\s*100dvh\)/.test(above)) {
        bad.push(`line ${i + 1}: ${line} — not inside @supports (height: 100dvh)`);
      }
    });
    expect(bad, 'a dvh height the minifier will leave unguarded').toEqual([]);

    // And the base rules it falls back to still exist.
    expect(css).toMatch(/\.app \{[^}]*height:\s*100vh/);
    expect(css).toMatch(/\.app\.mobile \{[^}]*height:\s*100vh/);
  });

  it('the chat column cannot outgrow its track', () => {
    // A grid item's min-height is `auto` — "at least as tall as my content" —
    // so without this the chat grows to fit the whole transcript.
    const chat = css.slice(css.indexOf('\n.chat {'));
    expect(chat.slice(0, chat.indexOf('}'))).toContain('min-height: 0');
  });

  it('the transcript keeps a touch drag to itself', () => {
    const t = css.slice(css.indexOf('\n.transcript {'));
    const block = t.slice(0, t.indexOf('}'));
    expect(block).toContain('overflow-y: auto');
    expect(block).toContain('min-height: 0');
    expect(block).toContain('overscroll-behavior: contain');
  });
});
