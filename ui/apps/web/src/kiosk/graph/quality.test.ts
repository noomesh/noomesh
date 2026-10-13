// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 PersonifAI LLC

import { readFileSync } from 'node:fs';
import { resolve } from 'node:path';
import { describe, it, expect } from 'vitest';
import { createGovernor, mayPushIn, smooth } from './quality';

// Frame WORK time in ms (sim + paint), not the vsync interval: a page
// pinned at 100% CPU still gets a 16ms rAF cadence, it just paints late.
const run = (g: ReturnType<typeof createGovernor>, ms: number, frames: number, from = 0, step = 16) => {
  let now = from;
  let q = g.quality;
  for (let i = 0; i < frames; i++) {
    now += step;
    q = g.observe(ms, now);
  }
  return { q, now };
};

describe('graph quality governor', () => {
  it('starts full', () => {
    expect(createGovernor().quality).toBe('full');
  });

  it('one slow frame is not a slow machine', () => {
    const g = createGovernor();
    run(g, 8, 60);
    expect(g.observe(90, 60 * 16 + 16)).toBe('full');
  });

  it('sustained slow frames drop to lean, and only after the hold', () => {
    const g = createGovernor({ leanAboveMs: 28, holdMs: 2000 });
    // Quadro FX 1700 on host5: ~45ms of work per frame, forever.
    const early = run(g, 45, 60); // ~1s
    expect(early.q).toBe('full');
    const late = run(g, 45, 90, early.now); // past 2s
    expect(late.q).toBe('lean');
  });

  it('recovery needs a longer sustained run than the drop did', () => {
    const g = createGovernor({ leanAboveMs: 28, fullBelowMs: 14, holdMs: 2000, recoverMs: 10000 });
    const { now } = run(g, 45, 200);
    expect(g.quality).toBe('lean');
    const brief = run(g, 6, 200, now); // ~3s of fast frames: not enough
    expect(brief.q).toBe('lean');
    const long = run(g, 6, 500, brief.now); // ~8s more: enough
    expect(long.q).toBe('full');
  });

  it('lean that is still too slow drops again to flat, and climbs back one step at a time', () => {
    const g = createGovernor({ leanAboveMs: 28, flatAboveMs: 45, fullBelowMs: 14, holdMs: 2000, recoverMs: 10000 });
    // host5 after #234: lean engaged, frames still ~60ms of work.
    const a = run(g, 60, 200);
    expect(a.q).toBe('lean');
    const b = run(g, 60, 200, a.now);
    expect(b.q).toBe('flat');
    // Flat made it cheap: ~20ms. Not fast enough for full, but below the
    // flat line for long enough → back to lean, and no further.
    const c = run(g, 20, 800, b.now);
    expect(c.q).toBe('lean');
    const d = run(g, 20, 800, c.now);
    expect(d.q).toBe('lean');
  });

  // host5, measured: 14ms of work drawing lean, and full expensive enough
  // to have demoted in the first place. The promotion rule reads lean's
  // number — the CHEAP tier's currency — and guesses that full will fit.
  // On this box it does not, so the naive rule cycles: ten quiet seconds,
  // climb, two ugly seconds, fall, repeat, forever.
  //
  // Counting TRANSITIONS, not sampling the tier: a cycling system read at
  // one moment gives whichever answer that moment happens to hold, and the
  // first version of this test passed against the bug for exactly that
  // reason. What the viewer suffers is the picture changing, so that is
  // what gets counted.
  const cycles = (
    g: ReturnType<typeof createGovernor>,
    cost: { lean: number; full: number },
    seconds: number,
  ) => {
    let now = 0;
    let last = g.quality;
    let changes = 0;
    for (let i = 0; i < Math.round((seconds * 1000) / 16); i++) {
      now += 16;
      const q = g.observe(g.quality === 'full' ? cost.full : cost.lean, now);
      if (q !== last) {
        changes++;
        last = q;
      }
    }
    return changes;
  };

  it('a climb that does not hold makes the next one much harder', () => {
    // 90 seconds on a box where full costs 60ms and lean 13ms. Settling in
    // costs one change; each failed climb costs two. With no penalty the
    // climb repeats every ~12s — about fourteen changes of appearance.
    const changes = cycles(createGovernor(), { lean: 13, full: 60 }, 90);
    expect(changes).toBeGreaterThanOrEqual(1); // it must still degrade
    expect(changes).toBeLessThanOrEqual(5); // settle + at most two attempts
  });

  it('a climb that holds resets the penalty', () => {
    const g = createGovernor();
    // A box busy at first and then genuinely free: full costs 60ms during
    // the first climb, 8ms afterwards.
    let full = 60;
    let now = 0;
    const step = (frames: number) => {
      for (let i = 0; i < frames; i++) {
        now += 16;
        g.observe(g.quality === 'full' ? full : 13, now);
      }
    };
    step(1200);
    expect(g.quality).toBe('lean');
    full = 8; // the other process went away
    // Long enough to serve the backed-off wait, climb, AND then hold past
    // the 30s probation — the holding is the part under test.
    step(4500);
    expect(g.quality).toBe('full');
    full = 60; // a genuinely bad patch, long after the climb proved good
    step(300);
    expect(g.quality).toBe('lean');
    // Held past probation before this, so the slate was wiped: the next
    // climb waits the BASE ten seconds, not the penalty.
    full = 8;
    step(800);
    expect(g.quality).toBe('full');
  });

  // The push-in is the single most expensive moment on this screen: zoom
  // 2.4 makes every gradient cover ~2.4x the pixels and fades the tags in,
  // and it is HELD for fourteen seconds. The operator watched it happen:
  // "floating really well, and then new data comes in, it tries the
  // complex version and then reverts, making it choppy". A tier is a
  // statement about what the machine can carry — so the celebration has
  // to obey it, rather than being the one thing that ignores it.
  describe('the push-in obeys the tier', () => {
    const free = { cameraFree: true, reducedMotion: false, sinceLastPushS: 99, gapS: 35 };

    it('is allowed only at full', () => {
      expect(mayPushIn({ ...free, quality: 'full' })).toBe(true);
      expect(mayPushIn({ ...free, quality: 'lean' })).toBe(false);
      expect(mayPushIn({ ...free, quality: 'flat' })).toBe(false);
    });

    // The unit tests above prove the RULE. They say nothing about whether
    // the frame loop asks it — revert the call site and they all still
    // pass. Source-read carefully (comments stripped, and the subject
    // asserted to exist first, so a restructure fails loudly here rather
    // than passing vacuously). See an earlier change.
    it('the frame loop asks the rule rather than deciding for itself', () => {
      // resolve() from the package root, not import.meta.url: under the
      // jsdom environment that is an http: URL and readFileSync throws
      // TypeError — which looks like a failure and is not one. Getting
      // this wrong cost me a false "watched it fail" here.
      const src = readFileSync(resolve(process.cwd(), 'src/kiosk/GraphKiosk.tsx'), 'utf8')
        .replace(/\/\*[\s\S]*?\*\//g, '')
        .split('\n')
        .filter((l) => !l.trim().startsWith('//'))
        .join('\n');
      expect(src, 'the push-in is gone from GraphKiosk: this guard is stale').toContain(
        'focusUntil = t + FOCUS_HOLD_S',
      );
      expect(src).toContain('mayPushIn({');
      expect(src, 'the frame loop decides the push-in itself again').not.toMatch(
        /if \(!reduced && focusId == null/,
      );
    });

    it('still respects reduced motion, the gap, and a busy camera at full', () => {
      expect(mayPushIn({ ...free, quality: 'full', reducedMotion: true })).toBe(false);
      expect(mayPushIn({ ...free, quality: 'full', cameraFree: false })).toBe(false);
      expect(mayPushIn({ ...free, quality: 'full', sinceLastPushS: 34 })).toBe(false);
    });
  });

  it('smoothing seeds on the first sample rather than averaging against nothing', () => {
    expect(smooth(0, 40)).toBe(40);
    expect(smooth(10, 20)).toBeCloseTo(11, 6);
    expect(smooth(10, 20, 0.5)).toBeCloseTo(15, 6);
  });

  it('a forced quality never moves', () => {
    const g = createGovernor({ forced: 'lean' });
    expect(run(g, 4, 2000).q).toBe('lean');
    const h = createGovernor({ forced: 'full' });
    expect(run(h, 120, 2000).q).toBe('full');
  });
});
