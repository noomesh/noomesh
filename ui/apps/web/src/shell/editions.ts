// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 PersonifAI LLC

/**
 * Editions — which tabs a given build of the console ships.
 *
 * `full` is everything (what we run ourselves). `core` is the surface an
 * open-source self-hoster gets.
 *
 * This is deliberately just a list. Moving a tab between editions is a
 * one-line change, so the assignment is cheap to argue about.
 *
 * The seam, not the split: the plan is to give the shell
 * clean extension points now and split repos later, when the first EE feature
 * exists. Splitting later should be a file move, not a refactor.
 */

export type Edition = 'core' | 'full';

/** Build-time. Defaults to `full` so `npm run dev` is unchanged. */
export const EDITION: Edition =
  (import.meta.env.VITE_EDITION as Edition | undefined) === 'core' ? 'core' : 'full';

/**
 * Tabs the core edition ships.
 *
 * **The test changed on 2026-08-27.** It used to be "nothing that fronts a
 * subsystem the open build does not have" — which was doing the work of a
 * commercial boundary, back when Trellion's build pipeline was going to stay
 * closed. Trellion now opens in full, so that test excludes nothing and the
 * Graph and Documents tabs came back.
 *
 * The test now: *is this a real answer to a question a self-hoster will
 * actually ask, and is this the only place that answers it?* Note what that
 * does NOT ask — how big the panel is. Line count measures effort, not value:
 * Autonomy is 150 lines and is the only view of what the agent does unprompted,
 * while a larger tab can still be a worse copy of one we already ship.
 */
export const CORE_TABS: readonly string[] = [
  'chat', // the reason anyone installs it
  'cluster', // "my machines, as one system" — the core claim
  'backends', // start/stop models across nodes — the differentiator vs plain Ollama
  'model-prefs', // which model answers each purpose; embedding spaces (operator-gated)
  'tasks', // scheduled work; basic self-hosting need
  'addons', // add-on web UIs, each on its own origin; empty until one is enabled
  'memory', // conversations persist — the other thing cloud does not do privately
  'rag', // document ingest — the reason to have a graph at all
  'connections', // private Google account and data-source drafts
  'graph', // the knowledge graph itself
  'observability', // GPU metrics
  'usage', // token accounting; nobody else self-hosted shows it
  'security', // approval gates on agent actions — a genuine differentiator
  'skills', // promote or reject learned prompt skills before they are injected
  'autonomy', // what it does when nobody asked; same safety class as approvals
  'admin', // users and behavioural flags (operator-gated in the sidebar)
  'docs', // in-app runbooks
  'workflow', // architecture diagram — orients a first-time installer
];

/**
 * Everything else, with the reason it is not in core. Kept as data rather than
 * a comment so it is answerable when someone asks "why is X missing?".
 *
 * `closed` — fronts a subsystem the open build does not include.
 * `operator` — real and core-served, but cluster-governance rather than
 * first-run material.
 * `thin` — not finished enough to lead with.
 */
export const EXTENDED_TABS: Record<string, { reason: 'closed' | 'operator' | 'thin'; note: string }> =
  {
    brain: {
      reason: 'closed',
      note: 'Evolve add-on status. Requires the evolve add-on to be enabled.',
    },
    explorer: {
      reason: 'thin',
      note: 'Trellion recall memory. Open now, but niche enough that it is noise on a first run.',
    },
    jobs: {
      reason: 'operator',
      note: 'real (the CLI and MCP tools submit here) but a single-node install mostly sees an empty queue',
    },
    proposals: { reason: 'operator', note: 'cluster governance' },
    channels: { reason: 'operator', note: 'Telegram/Chat bridges' },
    traffic: { reason: 'operator', note: 'all agent-to-agent threads (operator-only)' },
    files: { reason: 'operator', note: 'user directory config' },
  };

/** Does this edition ship this tab? */
export const inEdition = (id: string, edition: Edition = EDITION): boolean =>
  edition === 'full' || CORE_TABS.includes(id);
