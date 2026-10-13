// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 PersonifAI LLC

import { cn } from '@/lib/utils';
import type { ChatStatus } from '@/features/chat/useCoordinator';

/**
 * The collapsed chat: a slim strip that keeps the coordinator reachable — and
 * its connection state visible — while the panel has the width.
 *
 * The chat itself stays mounted behind this (see App), so expanding restores
 * the same socket and the same transcript rather than reconnecting.
 */
export function ChatRail({ status, onExpand }: { status: ChatStatus; onExpand: () => void }) {
  return (
    <div className="chat-rail">
      <button type="button" onClick={onExpand} aria-label="Expand chat" title="Expand chat">
        {/* Same panel glyph as the chat bar's minimise control, so expanding
            reads as the inverse of what collapsed it. */}
        <svg viewBox="0 0 20 20" aria-hidden="true">
          <rect x="2.5" y="4" width="15" height="12" rx="1.5" />
          <rect x="2.5" y="4" width="5.5" height="12" fill="currentColor" stroke="none" opacity="0.4" />
          <path d="M8 4v12" />
        </svg>
      </button>
      <span className={cn('rail-dot', status !== 'live' && 'off')} title={status} />
      <span className="rail-label" aria-hidden="true">Coordinator</span>
    </div>
  );
}
