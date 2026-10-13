// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 PersonifAI LLC

// The liveness band, shared by every kiosk view. One always-visible strip:
// time since the last DATA, counting up. Climbing into red = the data path
// is dead; frozen = the page itself is dead (an earlier change.2).
//
// The number is the age of what is on screen, never the age of the
// connection. It used to be both — a keepalive reset it — so the band read
// "live · 3s since last data" over a picture hours old. When the two
// disagree the band says which it means, because "live" is a claim about
// the pipe and the number beside it is a claim about the facts.

import { liveness, fmtDuration, type KioskState } from './store';

/** Which of several views is showing. Rendered as dots — a hint that there are others, not a control. */
export interface Pager {
  count: number;
  index: number;
}

export function LivenessBand({ state, now, title = 'NOOMESH', pager }: { state: KioskState; now: number; title?: string; pager?: Pager }) {
  const l = liveness(state, now);
  // Nothing has ever arrived at all — not even a keepalive.
  const waiting = l.contactAgeMs == null;
  const word = state.stream === 'auth'
    ? `credential rejected (${state.authStatus ?? '?'})`
    : l.stale
      ? 'NO DATA'
      : waiting
        ? state.stream === 'reconnecting'
          ? 'waiting for gateway'
          : 'connecting'
        : state.stream === 'live'
          // Connected, and saying so — but not claiming the picture is
          // current when it is not. "live" alone over stale facts is the
          // confident wrong answer this band exists to prevent.
          ? (l.dataStale ? 'live · no new data' : 'live')
          : 'reconnecting';
  const cls = [
    'band',
    l.stale || state.stream === 'auth' ? 'stale' : '',
    waiting ? 'waiting' : '',
    !l.stale && l.dataStale ? 'quiet' : '',
  ].join(' ');
  return (
    <div className={cls} role="status" aria-live="polite">
      <span className="brand">{title}</span>
      <span>
        <span className="word">{word}</span>
        {l.dataAgeMs != null ? (
          <>
            {' · '}
            <span className="age">{fmtDuration(l.dataAgeMs)}</span> since last data
          </>
        ) : l.contactAgeMs != null ? (
          // Attached to a gateway that has sent us nothing but keepalives.
          // The old band counted those and showed a reassuring few seconds.
          <>
            {' · '}
            <span className="age">no data yet</span>
            {' · connected '}
            <span className="age">{fmtDuration(l.contactAgeMs)}</span> ago
          </>
        ) : null}
      </span>
      <span className="clock">
        {new Date(now).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' })}
        {pager && pager.count > 1 && (
          <span className="pager" aria-hidden="true">
            {Array.from({ length: pager.count }, (_, i) => (
              <i key={i} className={i === pager.index ? 'on' : ''} />
            ))}
          </span>
        )}
      </span>
    </div>
  );
}
