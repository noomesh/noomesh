// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 PersonifAI LLC

// The quality governor: the page notices it is on a slow machine and
// degrades — visibly, and on its own.
//
// Why this exists: the first display was a shelf PC with a Quadro FX 1700,
// a 2007 card no browser can composite on. Chromium fell back to software
// rendering, one renderer process sat at 100% CPU, and the graph — a sim
// that is never still, drawn at 2× pixels through a blur pass, plus
// particles — crawled. Nothing in the page knew. It kept asking for the
// full picture from a machine that could not draw it.
//
// The rule is the one the health view already follows for data: degrade
// visibly, never silently. So this measures the WORK a frame took (sim +
// paint), not the interval between frames — a pinned CPU still gets a 16ms
// requestAnimationFrame cadence, it just paints late — and after a
// sustained run of slow frames it drops to `lean`: 1× pixels, no blur
// layer, fewer particles, a 30fps cap, and a readout line that says so.
//
// Hysteresis, deliberately asymmetric: dropping takes two seconds of slow
// frames (a burst on ingest must not flip it), recovering takes ten seconds
// of fast ones (flapping between the two looks worse than either).
// `?quality=lean|full` pins it, for a display whose operator has decided.

// full → lean → flat. Lean keeps the look and drops the expensive
// passes; flat keeps only the picture — solid hubs, single-stroke links,
// no particles, no tags — for a machine lean still cannot carry. The
// goal is flowing motion, not snapping from state to state: the second tier
// exists because a cheaper frame is the only way to get more of them.
export type Quality = 'full' | 'lean' | 'flat';

export interface GovernorOptions {
  /** Smoothed frame work above this, sustained, drops full → lean. */
  leanAboveMs: number;
  /** Smoothed frame work above this while ALREADY lean, sustained, drops lean → flat. */
  flatAboveMs: number;
  /** Smoothed frame work below this, sustained, returns to full. */
  fullBelowMs: number;
  /** How long the slow run must last before dropping. */
  holdMs: number;
  /** How long the fast run must last before recovering. */
  recoverMs: number;
  /** Pinned by the URL; the governor then never moves. */
  forced?: Quality;
}

export interface Governor {
  readonly quality: Quality;
  /** Smoothed frame work, ms — what the decision is made on. */
  readonly avgMs: number;
  /** Feed one frame's work time; returns the quality to draw the NEXT frame at. */
  observe(frameMs: number, nowMs: number): Quality;
}

const DEFAULTS: GovernorOptions = { leanAboveMs: 28, flatAboveMs: 45, fullBelowMs: 14, holdMs: 2000, recoverMs: 10_000 };

/** Cheapest tier first, so a step's direction is a comparison. */
const RANK: Record<Quality, number> = { flat: 0, lean: 1, full: 2 };

/**
 * How long a climb must survive to count as justified.
 *
 * A climb is a GUESS, and the only evidence for it is measured in the
 * cheaper tier's currency: 13ms drawing lean says nothing certain about
 * what full will cost, and on host5 full is four times dearer because
 * 2× pixels through a blur is four times the work. A climb that is undone
 * within this window was a bad guess.
 */
const PROBATION_MS = 30_000;

/**
 * The ceiling on the penalty. A fixed machine's verdict does not change,
 * so after two refusals it should stop asking — but not forever, because
 * the thing that made it slow may have been another process.
 */
const MAX_PROMOTE_MS = 10 * 60_000;

/**
 * One EMA step over ~10 samples: a single outlier moves the average a
 * tenth of the way, and the first sample seeds it rather than being
 * averaged against a zero that never happened.
 */
export function smooth(prev: number, sample: number, k = 0.1): number {
  return prev === 0 ? sample : prev + (sample - prev) * k;
}

export function createGovernor(opts: Partial<GovernorOptions> = {}): Governor {
  const o = { ...DEFAULTS, ...opts };
  let quality: Quality = o.forced ?? 'full';
  let avg = 0;
  // The step the current run is heading for, and when that run began.
  // Null while the average sits inside the band for the current tier.
  let toward: Quality | null = null;
  let since = 0;
  // The quiet run a climb currently needs, and when the last climb happened.
  // Measured at 14ms drawing lean, host5 sat exactly on the promotion line:
  // ten quiet seconds, climb, two ugly seconds, fall, repeat — fourteen
  // changes of appearance in ninety seconds, which is worse than either
  // steady state. Each climb that does not hold makes the next one dearer.
  let promoteAfter = o.recoverMs;
  let climbedAt: number | null = null;

  // One step at a time, in either direction. Climbing back goes flat →
  // lean → full, each leg needing its own sustained run: the machine
  // that just proved it cannot carry lean gets lean back only after it
  // has carried flat easily for a while, and full only after that.
  const next = (): Quality | null => {
    if (quality === 'full') return avg > o.leanAboveMs ? 'lean' : null;
    if (quality === 'lean') return avg > o.flatAboveMs ? 'flat' : avg < o.fullBelowMs ? 'full' : null;
    return avg < o.leanAboveMs ? 'lean' : null;
  };
  return {
    get quality() {
      return quality;
    },
    get avgMs() {
      return avg;
    },
    observe(frameMs, nowMs) {
      if (o.forced) return quality;
      // EMA over ~10 frames: one slow frame moves it a tenth of the way.
      avg = smooth(avg, frameMs);

      // A climb that survived probation was a good guess, so the slate is
      // wiped: whatever made the machine slow has gone, and a bad patch
      // later deserves to be treated as a first offence rather than
      // inheriting a penalty earned by different conditions.
      if (climbedAt !== null && nowMs - climbedAt >= PROBATION_MS) {
        promoteAfter = o.recoverMs;
        climbedAt = null;
      }
      const want = next();
      if (want !== toward) {
        toward = want;
        since = nowMs;
      }
      if (want === null) return quality;
      const dropping = RANK[want] < RANK[quality];
      if (nowMs - since < (dropping ? o.holdMs : promoteAfter)) return quality;

      if (dropping && climbedAt !== null && nowMs - climbedAt < PROBATION_MS) {
        // That climb did not hold. Ask for a much longer quiet run before
        // trying again, so the display stops cycling between two looks.
        promoteAfter = Math.min(promoteAfter * 4, MAX_PROMOTE_MS);
      }
      climbedAt = dropping ? null : nowMs;
      quality = want;
      toward = null;
      return quality;
    },
  };
}

/**
 * May the camera push in on an entity that just grew?
 *
 * The push-in is the display's signature move and its most expensive
 * moment by a distance: zoom 2.4 makes every gradient — hubs, dendrite
 * dots, particles — cover about 2.4x the pixels, brings the metadata tags
 * in on top, and HOLDS all of that for fourteen seconds.
 *
 * It was also the one thing on the page that never asked what tier it was
 * in. So on a machine already drawing lean, the arrival of data — the one
 * moment the screen has something to say — was the moment it went choppy.
 * The operator watched it happen and named the rule this function now
 * enforces: if the page has adapted to a cheap way of drawing, new data
 * has to adhere to that too.
 *
 * Below full the camera stays wide. The arrival is still visible, in the
 * things that cost nothing extra: the hub's activity and the warm strand
 * along its links, both already driven by how recently it grew.
 */
export function mayPushIn(o: {
  quality: Quality;
  /** `prefers-reduced-motion`. */
  reducedMotion: boolean;
  /** No push-in currently running. */
  cameraFree: boolean;
  /** Seconds since the last push-in ended. */
  sinceLastPushS: number;
  /** The minimum gap between push-ins. */
  gapS: number;
}): boolean {
  if (o.quality !== 'full') return false;
  return !o.reducedMotion && o.cameraFree && o.sinceLastPushS > o.gapS;
}
