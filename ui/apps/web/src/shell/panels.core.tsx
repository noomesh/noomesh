// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 PersonifAI LLC

import type { ComponentType } from 'react';
import { ClusterPanel } from '@/features/cluster/ClusterPanel';
import { BackendsPanel } from '@/features/backends/BackendsPanel';
import { TasksPanel } from '@/features/tasks/TasksPanel';
import { MemoryPanel } from '@/features/memory/MemoryPanel';
import { RagPanel } from '@/features/rag/RagPanel';
import { GraphPanel } from '@/features/graph/GraphPanel';
import { ObservabilityPanel } from '@/features/observability/ObservabilityPanel';
import { UsagePanel } from '@/features/usage/UsagePanel';
import { SecurityPanel } from '@/features/security/SecurityPanel';
import { AutonomyPanel } from '@/features/autonomy/AutonomyPanel';
import { AdminPanel } from '@/features/admin/AdminPanel';
import { ModelPrefsPanel } from '@/features/model-prefs/ModelPrefsPanel';
import { DocsPanel } from '@/features/docs/DocsPanel';
import { WorkflowPanel } from '@/features/workflow/WorkflowPanel';

/** Panels every edition ships. `chat` has no panel — it is the left column. */
export const CORE_PANELS: Record<string, ComponentType> = {
  cluster: ClusterPanel,
  backends: BackendsPanel,
  tasks: TasksPanel,
  memory: MemoryPanel,
  rag: RagPanel,
  graph: GraphPanel,
  observability: ObservabilityPanel,
  usage: UsagePanel,
  security: SecurityPanel,
  autonomy: AutonomyPanel,
  admin: AdminPanel,
  'model-prefs': ModelPrefsPanel,
  docs: DocsPanel,
  workflow: WorkflowPanel,
};
