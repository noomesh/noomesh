// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 PersonifAI LLC

import type { NodeInfo } from '@/features/_diagram/DiagramView';
import type { ConsolePieces } from './useConsolePieces';
import type { AddonState } from '@/features/observability/useObservability';

/**
 * Slots: the licensed lanes of the console diagrams.
 *
 * Core ships every node of both diagrams, so the picture is complete. What a
 * licensed node DOES internally is not core's to describe: each such node is a
 * slot, and the add-on that owns it fills the slot at runtime with a `piece`.
 * With no piece the node shows its name, a state badge and one neutral
 * sentence. Id scheme: `<addonId>:<lane>`, addonId as in `/health`'s `addons`.
 */
export interface Slot {
  slotId: string;
  addonId: string;
  title: string;
}

export const SLOTS: Slot[] = [
  { slotId: 'evolve:ga', addonId: 'evolve', title: 'Parameter tuning' },
  { slotId: 'evolve:ga-cycle', addonId: 'evolve', title: 'Parameter tuning cycle' },
  { slotId: 'evolve:ga-score', addonId: 'evolve', title: 'Score candidates' },
  { slotId: 'evolve:ga-evolve', addonId: 'evolve', title: 'Evolve candidates' },
  { slotId: 'evolve:ga-apply', addonId: 'evolve', title: 'Apply configuration' },
  { slotId: 'evolve:hofstadter', addonId: 'evolve', title: 'Self-review loop' },
  { slotId: 'evolve:hofstadter-cycle', addonId: 'evolve', title: 'Self-review cycle' },
  { slotId: 'evolve:observe', addonId: 'evolve', title: 'Observe' },
  { slotId: 'evolve:verify', addonId: 'evolve', title: 'Verify' },
  { slotId: 'evolve:reflect', addonId: 'evolve', title: 'Reflect' },
  { slotId: 'evolve:adapt', addonId: 'evolve', title: 'Adapt' },
  { slotId: 'evolve:composite-score', addonId: 'evolve', title: 'Composite score' },
  { slotId: 'evolve:composite-metric', addonId: 'evolve', title: 'Composite score metric' },
  { slotId: 'trellion_intel:graph-nav', addonId: 'trellion_intel', title: 'Graph navigation' },
  { slotId: 'trellion_intel:temporal', addonId: 'trellion_intel', title: 'Temporal recall' },
];

/**
 * The wire shape of an add-on's piece. `useConsolePieces()` flattens the pieces
 * it has fetched into `{ [slotId]: slot }`; today it returns `{}`.
 */
export interface AddonPiece {
  version: 1;
  addon: string;
  slots: { [slotId: string]: { title: string; description: string; steps?: string[] } };
}

/** Where a slot sits in a diagram: the node's layer label and hue. */
export interface SlotNode {
  slotId: string;
  l: string;
  c: string;
}

const ADDON_NAMES: Record<string, string> = { evolve: 'Evolve', trellion_intel: 'Trellion Intel' };
const addonName = (id: string) => ADDON_NAMES[id] ?? id;

/**
 * Build the modal content for each slot node.
 * `states` is the add-on state map the console already reads from `/health`;
 * an add-on absent from it is "not installed" (absent is not failed, and
 * either way the node is not live). No piece for the slot: placeholder.
 */
export function slotNodeInfo(
  nodes: Record<string, SlotNode>,
  states: Record<string, AddonState>,
  pieces: ConsolePieces = {},
): Record<string, NodeInfo> {
  const out: Record<string, NodeInfo> = {};
  for (const [nodeId, n] of Object.entries(nodes)) {
    const slot = SLOTS.find((s) => s.slotId === n.slotId);
    if (!slot) continue;
    const filled = pieces[slot.slotId];
    out[nodeId] = {
      t: filled?.title ?? slot.title,
      l: n.l,
      c: n.c,
      d: filled?.description ?? `Provided by the ${addonName(slot.addonId)} add-on.`,
      steps: filled?.steps?.length ? filled.steps : undefined,
      badge: states[slot.addonId] === 'enabled' ? 'installed' : 'not installed · Intelligent tier',
    };
  }
  return out;
}

/** Add-on id → state, from the `/health` map the observability hook already polls. */
export function addonStateMap(addons: { id: string; state: AddonState }[] | undefined): Record<string, AddonState> {
  return Object.fromEntries((addons ?? []).map((a) => [a.id, a.state]));
}
