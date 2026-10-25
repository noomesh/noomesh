// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 PersonifAI LLC

import type { ReactNode } from 'react';
// Aliased path, not relative: vite.config.ts swaps this for an empty stub in
// `core` builds, so extended labels and icons never reach the bundle.
import { EXTENDED_NAV, EXTENDED_ICONS } from '@/shell/nav.extended';
import { inEdition } from './editions';

export type TabStatus = 'live' | 'soon';

export interface NavItem {
  id: string;
  label: string;
  status: TabStatus;
}
export interface NavSection {
  group?: string;
  items: NavItem[];
}

/** Tabs every edition ships. Group order here is the order in the sidebar. */
const CORE_NAV: NavSection[] = [
  {
    items: [
      { id: 'chat', label: 'Chat', status: 'live' },
    ],
  },
  {
    group: 'Operate',
    items: [
      { id: 'cluster', label: 'Cluster', status: 'live' },
      { id: 'backends', label: 'Backends', status: 'live' },
      { id: 'model-prefs', label: 'Models', status: 'live' },
      { id: 'tasks', label: 'Tasks', status: 'live' },
      // Add-on web UIs, each opened in a new tab on its own origin.
      { id: 'addons', label: 'Add-ons', status: 'live' },
    ],
  },
  {
    group: 'Knowledge',
    items: [
      { id: 'memory', label: 'Memory', status: 'live' },
      { id: 'rag', label: 'Documents', status: 'live' },
      { id: 'connections', label: 'Connections', status: 'live' },
      { id: 'graph', label: 'Graph', status: 'live' },
    ],
  },
  {
    group: 'Diagnostics',
    items: [
      { id: 'observability', label: 'Observe', status: 'live' },
      { id: 'usage', label: 'Usage', status: 'live' },
      { id: 'security', label: 'Security', status: 'live' },
      // "Is the agent doing things I did not ask for, and is that loop even
      // alive?" — the same question Security answers for individual tool calls.
      { id: 'autonomy', label: 'Autonomy', status: 'live' },
      // Which learned prompt skills may be injected: a person decides.
      { id: 'skills', label: 'Skills', status: 'live' },
      { id: 'admin', label: 'Admin', status: 'live' },
    ],
  },
  {
    group: 'Reference',
    items: [
      { id: 'docs', label: 'Docs', status: 'live' },
      { id: 'workflow', label: 'Architecture', status: 'live' },
    ],
  },
];

/**
 * Core sections with the extended items folded into matching groups, then any
 * extended-only group (e.g. "Pro") appended. In a core build EXTENDED_NAV is
 * empty, so this collapses to CORE_NAV.
 */
function mergeNav(core: NavSection[], extended: NavSection[]): NavSection[] {
  const merged = core.map((s) => {
    const extra = extended.find((e) => e.group === s.group);
    return extra ? { ...s, items: [...s.items, ...extra.items] } : s;
  });
  const coreGroups = new Set(core.map((s) => s.group));
  return [...merged, ...extended.filter((e) => !coreGroups.has(e.group))];
}

/**
 * What this build shows. The `inEdition` filter is belt-and-braces — with the
 * nav split it is already true, but it keeps a mis-assigned id from producing
 * a tab whose panel does not exist.
 */
export const NAV: NavSection[] = mergeNav(CORE_NAV, EXTENDED_NAV)
  .map((s) => ({ ...s, items: s.items.filter((i) => inEdition(i.id)) }))
  .filter((s) => s.items.length > 0);

/** Every tab in the build — used to label the mobile bar and sheets. */
export const ALL_TABS: Record<string, NavItem> = Object.fromEntries(
  NAV.flatMap((s) => s.items).map((i) => [i.id, i]),
);

// Minimal single-color stroke icons (viewBox 0 0 20 20), one per tab.
const CORE_ICONS: Record<string, ReactNode> = {
  chat: <path d="M3 4h14v10H8l-4 3v-3H3z" />,
  cluster: (
    <>
      <rect x="3" y="4" width="14" height="3.5" />
      <rect x="3" y="12.5" width="14" height="3.5" />
    </>
  ),
  backends: <path d="M11 3l-6 8h4l-1 6 6-8h-4z" />,
  'model-prefs': <path d="M4 6h12M4 10h12M4 14h12M8 4v4M13 8v4M7 12v4" />,
  memory: (
    <>
      <ellipse cx="10" cy="5.5" rx="6" ry="2.5" />
      <path d="M4 5.5v9c0 1.4 2.7 2.5 6 2.5s6-1.1 6-2.5v-9" />
    </>
  ),
  connections: <path d="M8 6H6a4 4 0 0 0 0 8h2m4-8h2a4 4 0 0 1 0 8h-2M6 10h8" />,
  observability: <path d="M3 12h3l2-6 3 11 2-7 1 2h3" />,
  usage: (
    <>
      <rect x="3.5" y="10" width="3.5" height="6.5" />
      <rect x="8.5" y="6" width="3.5" height="10.5" />
      <rect x="13.5" y="3" width="3.5" height="13.5" />
    </>
  ),
  security: (
    <>
      <rect x="5" y="9" width="10" height="8" rx="1" />
      <path d="M7 9V7a3 3 0 0 1 6 0v2" />
    </>
  ),
  docs: <path d="M4 4h5a2 2 0 0 1 2 2v10a2 2 0 0 0-2-2H4zM16 4h-5a2 2 0 0 0-2 2v10a2 2 0 0 1 2-2h5z" />,
  tasks: (
    <>
      <circle cx="10" cy="10" r="6.5" />
      <path d="M10 6v4l3 2" />
    </>
  ),
  rag: (
    <>
      <path d="M6 3h6l4 4v10H6z" />
      <path d="M12 3v4h4M8 11h6M8 14h5" />
    </>
  ),
  graph: (
    <>
      <circle cx="5" cy="6" r="1.8" />
      <circle cx="15" cy="6" r="1.8" />
      <circle cx="10" cy="14" r="1.8" />
      <path d="M6.6 7l6.8 5M13.4 7l-6.8 5M6.5 6h7" />
    </>
  ),
  autonomy: (
    <>
      <circle cx="10" cy="10" r="6" />
      <path d="M10 4v12M6 7c2.5 1.2 5.5 1.2 8 0M6 13c2.5-1.2 5.5-1.2 8 0" />
    </>
  ),
  skills: (
    <>
      <path d="M5 3h8l3 3v11H5z" />
      <path d="M8 10l1.6 1.6L13 8" />
    </>
  ),
  admin: (
    <>
      <circle cx="10" cy="10" r="2.6" />
      <path d="M10 3v2M10 15v2M3 10h2M15 10h2M5 5l1.5 1.5M13.5 13.5L15 15M15 5l-1.5 1.5M5 15l1.5-1.5" />
    </>
  ),
  addons: (
    <>
      <rect x="3" y="3" width="6" height="6" rx="1" />
      <rect x="11" y="3" width="6" height="6" rx="1" />
      <rect x="3" y="11" width="6" height="6" rx="1" />
      <path d="M14 11v6M11 14h6" />
    </>
  ),
  workflow: (
    <>
      <rect x="3" y="4" width="6" height="4" rx="1" />
      <rect x="11" y="12" width="6" height="4" rx="1" />
      <path d="M6 8v3a1 1 0 0 0 1 1h4" />
    </>
  ),
};

export const ICONS: Record<string, ReactNode> = { ...CORE_ICONS, ...EXTENDED_ICONS };
