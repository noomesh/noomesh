// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 PersonifAI LLC

import { useQuery, useMetisClient } from '@metis/core';
import { SLOTS, type AddonPiece } from './slots';

/** `{ [slotId]: { title, description, steps? } }`, the shape `slotNodeInfo` reads. */
export type ConsolePieces = AddonPiece['slots'];
type ConsolePiece = ConsolePieces[string];

/**
 * The add-ons that own slots in the console diagrams, derived from the slot
 * registry. Only these are asked: an add-on with no slots (`trellion`) would
 * answer 404 for nothing, and a new slot owner is picked up by adding its slots.
 */
const SLOT_OWNERS = [...new Set(SLOTS.map((s) => s.addonId))];

/** Stable identity while nothing has loaded, so consumers do not re-render. */
const NONE: ConsolePieces = {};

/** Keep only well-formed slots under `<addon>:`; the gateway validates too, but this is the last gate before render. */
function slotsOf(addon: string, body: unknown): ConsolePieces {
  const slots = (body as { slots?: unknown } | null | undefined)?.slots;
  if (!slots || typeof slots !== 'object') return {};
  const out: ConsolePieces = {};
  for (const [key, raw] of Object.entries(slots as Record<string, unknown>)) {
    const s = raw as Partial<ConsolePiece> | null;
    if (!key.startsWith(`${addon}:`) || !s) continue;
    if (typeof s.title !== 'string' || typeof s.description !== 'string') continue;
    if (s.steps !== undefined && !(Array.isArray(s.steps) && s.steps.every((x) => typeof x === 'string'))) continue;
    out[key] = s.steps === undefined
      ? { title: s.title, description: s.description }
      : { title: s.title, description: s.description, steps: s.steps };
  }
  return out;
}

/**
 * Each installed add-on's piece of the console diagrams, merged into
 * `{ [slotId]: slot }`. `steps` is optional.
 *
 * Asks `/health` which add-ons are `enabled`, then fetches
 * `/api/addons/<id>/console-piece` for those that own slots. Any failure
 * (disabled, 502, network, a malformed piece) leaves that add-on's keys absent,
 * which means the slot shows its placeholder. Never throws and never toasts:
 * the queryFn catches everything, so the query itself cannot error.
 */
export function useConsolePieces(): ConsolePieces {
  const client = useMetisClient();
  const q = useQuery<ConsolePieces>({
    queryKey: ['console-pieces'],
    refetchInterval: 60_000,
    queryFn: async () => {
      try {
        const health = await client.GET('/health');
        const states = (health.data?.addons ?? {}) as Record<string, unknown>;
        const owners = SLOT_OWNERS.filter((id) => states[id] === 'enabled');
        const merged: ConsolePieces = {};
        await Promise.all(
          owners.map(async (id) => {
            try {
              const r = await client.GET('/api/addons/{addon_id}/console-piece', {
                params: { path: { addon_id: id } },
              });
              Object.assign(merged, slotsOf(id, r.data));
            } catch {
              /* this add-on's slots stay absent */
            }
          }),
        );
        return merged;
      } catch {
        return NONE;
      }
    },
  });
  return q.data ?? NONE;
}
