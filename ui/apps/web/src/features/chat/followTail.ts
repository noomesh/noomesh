// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 PersonifAI LLC

/**
 * Is the reader still following the end of the transcript?
 *
 * Extracted from ChatPane so the rule can be tested: jsdom has no layout, so
 * a rendered transcript reports every dimension as zero and any assertion
 * about scrolling passes for the wrong reason.
 */

/**
 * How close to the end still counts as "at the bottom", in CSS pixels.
 *
 * Not zero. A fractional scroll offset, a sub-pixel line height or the
 * browser's own rounding leaves a gap of a pixel or two at the true end, and
 * reading that as "scrolled away" would stop the transcript following its own
 * generation — the bug this file exists to prevent, one pixel wide.
 *
 * Not large either: past roughly one line of text it starts yanking a reader
 * who genuinely scrolled up.
 */
export const TAIL_SLACK = 48;

export interface ScrollMetrics {
  scrollHeight: number;
  scrollTop: number;
  clientHeight: number;
}

/** True when the viewport is at, or within [`TAIL_SLACK`] of, the end. */
export function atTail({ scrollHeight, scrollTop, clientHeight }: ScrollMetrics): boolean {
  return scrollHeight - scrollTop - clientHeight <= TAIL_SLACK;
}
