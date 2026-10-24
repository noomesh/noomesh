// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 PersonifAI LLC

import type { ReactNode } from 'react';
import type { NavSection } from './nav';

/**
 * Nav entries and icons for tabs only the `full` edition ships.
 *
 * These live here rather than in `nav.tsx` so a `core` build does not carry
 * their *labels* either — vite.config.ts aliases this module to
 * `nav.extended.empty` (see editions.ts). Filtering at runtime would have hidden
 * the tabs while still shipping "Graph", "Brain Map", "Explorer" as strings in
 * the bundle, which is a roadmap leak even though it is not a code leak.
 *
 * `group` matches the group name in nav.tsx; entries are merged into that
 * section, or appended as a new one if it does not exist in core.
 */
export const EXTENDED_NAV: NavSection[] = [
  {
    group: 'Operate',
    items: [
      { id: 'jobs', label: 'Jobs', status: 'live' },
      { id: 'proposals', label: 'Proposals', status: 'live' },
      { id: 'channels', label: 'Channels', status: 'live' },
      // Operator-only: every agent-to-agent thread, not just your own.
      { id: 'traffic', label: 'Agent traffic', status: 'live' },
    ],
  },
  {
    group: 'Knowledge',
    items: [
      { id: 'explorer', label: 'Explorer', status: 'live' },
      { id: 'files', label: 'Files', status: 'live' },
    ],
  },
  {
    group: 'Pro',
    items: [{ id: 'brain', label: 'Brain Map', status: 'live' }],
  },
];

export const EXTENDED_ICONS: Record<string, ReactNode> = {
  jobs: (
    <>
      <rect x="4" y="4" width="12" height="13" rx="1" />
      <rect x="7.5" y="2.5" width="5" height="3" rx="1" />
      <path d="M7 9h6M7 12h6M7 15h4" />
    </>
  ),
  proposals: <path d="M10 3a4 4 0 0 0-4 4v3l-1.5 2h11L14 10V7a4 4 0 0 0-4-4zM8 16a2 2 0 0 0 4 0" />,
  channels: (
    <>
      <circle cx="10" cy="11" r="2" />
      <path d="M6 7a5 5 0 0 0 0 8M14 7a5 5 0 0 1 0 8M10 13v4" />
    </>
  ),
  explorer: (
    <>
      <circle cx="10" cy="10" r="7" />
      <path d="M13 7l-2 4-4 2 2-4z" />
    </>
  ),
  traffic: <path d="M3 7h11M11 4l3 3-3 3M17 13H6M9 10l-3 3 3 3" />,
  files: <path d="M3 6h5l2 2h7v8H3z" />,
  brain: (
    <>
      <circle cx="10" cy="5" r="1.8" />
      <circle cx="5" cy="14" r="1.8" />
      <circle cx="15" cy="14" r="1.8" />
      <path d="M9 6.4l-3 6M11 6.4l3 6M6.5 14h7" />
    </>
  ),
};
