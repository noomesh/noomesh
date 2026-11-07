// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 PersonifAI LLC

/** One entry of the node agent's `lanes` heartbeat report (proposal i403):
 *  a backend, its placed model, and a state. Carried verbatim on the node
 *  record; not in the typed contract yet, so it is read defensively. */
export interface Lane {
  backend: string;
  model: string;
  role: string;
  state: string;
  reason: string;
}

/** `undefined`: the agent predates lanes (routed by running_backends).
 *  `[]`: the agent says nothing is placed. A lane with no backend or no
 *  model is dropped, as the gateway's class table drops it. */
export function readLanes(raw: unknown): Lane[] | undefined {
  const v = (raw as { lanes?: unknown } | null)?.lanes;
  if (!Array.isArray(v)) return undefined;
  const text = (o: unknown, k: string) => {
    const s = (o as Record<string, unknown> | null)?.[k];
    return typeof s === 'string' ? s.trim() : '';
  };
  const out: Lane[] = [];
  for (const l of v) {
    const backend = text(l, 'backend');
    const placed = text(l, 'model');
    // An absolute path is named by its file, as the gateway names it.
    const model = placed.startsWith('/') ? (placed.split('/').pop() ?? '') : placed;
    if (!backend || !model) continue;
    out.push({ backend, model, role: text(l, 'role'), state: text(l, 'state'), reason: text(l, 'reason') });
  }
  return out;
}

const isChat = (l: Lane) => l.role === '' || l.role === 'chat';
/** The states the class table routes (serving, on demand, then unconfirmed). */
const ROUTED = new Set(['serving', 'on_demand', 'unknown', 'unplaced']);

/** One line per chat lane the gateway does not route right now, e.g.
 *  `vllm org/new-model: loading (reconciling: runtime runs org/old-model)`.
 *  Serving and routed lanes say nothing: the backend chips already show
 *  them. Empty when there is nothing to say. */
export function laneLines(lanes?: Lane[]): string[] {
  if (!lanes) return [];
  return lanes
    .filter((l) => isChat(l) && !ROUTED.has(l.state))
    .map((l) => `${l.backend} ${l.model}: ${l.state || 'no state'}${l.reason ? ` (${l.reason})` : ''}`);
}
