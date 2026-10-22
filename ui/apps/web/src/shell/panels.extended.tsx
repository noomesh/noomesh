// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 PersonifAI LLC

import type { ComponentType } from 'react';
import { JobsPanel } from '@/features/jobs/JobsPanel';
import { ProposalsPanel } from '@/features/proposals/ProposalsPanel';
import { ChannelsPanel } from '@/features/channels/ChannelsPanel';
import { FilesPanel } from '@/features/files/FilesPanel';
import { ExplorerPanel } from '@/features/explorer/ExplorerPanel';
import { AgentTrafficPanel } from '@/features/agent-traffic/AgentTrafficPanel';
import { BrainMapPanel } from '@/features/brain-map/BrainMapPanel';

/**
 * Panels only the `full` edition ships.
 *
 * In a `core` build this module is aliased away to `panels.extended.empty`
 * (see vite.config.ts), so none of these imports reach the bundle — the seam
 * is real, not cosmetic. Splitting this into a private EE repo later is a
 * file move: delete this module and the feature directories it names.
 */
export const EXTENDED_PANELS: Record<string, ComponentType> = {
  jobs: JobsPanel,
  traffic: AgentTrafficPanel,
  proposals: ProposalsPanel,
  channels: ChannelsPanel,
  files: FilesPanel,
  explorer: ExplorerPanel,
  brain: BrainMapPanel,
};
