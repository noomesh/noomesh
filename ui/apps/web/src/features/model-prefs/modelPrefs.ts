// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 PersonifAI LLC

// Pure row-building for the Model preferences panel. No React, no fetch: the
// wire shapes are normalised here once so the panel renders decisions, not JSON.

export interface ModelClass {
  name: string;
  declared: boolean;
  dynamic: boolean;
}

export interface ModelAlias {
  alias: string;
  class: string;
  builtin: boolean;
  purpose: boolean;
}

export interface PoolNode {
  node: string;
  backend: string;
  model: string;
  desiredState: string;
  advertising: boolean;
}

export interface EmbeddingSpace {
  space: string;
  model: string;
  dims: number | null;
  isDefault: boolean;
  pool: PoolNode[];
  live: number;
}

/** The class a purpose falls to when nothing is preferred: any live chat node. */
export const NO_PREFERENCE_CLASS = 'chat-default';

export interface PurposeRow {
  purpose: string;
  /** The preferred class or model name, or null when there is no preference. */
  target: string | null;
  /** Display text for the "prefers" column. */
  text: string;
  /** True when a class of that name exists right now. Always true when there is no preference. */
  served: boolean;
  /** Short state word for the badge. */
  state: 'any live node' | 'served' | 'not served yet';
}

export function purposeRows(aliases: ModelAlias[], classes: ModelClass[]): PurposeRow[] {
  const classNames = new Set(classes.map((c) => c.name));
  return aliases
    .filter((a) => a.purpose)
    .map((a): PurposeRow => {
      if (a.class === NO_PREFERENCE_CLASS) {
        return {
          purpose: a.alias,
          target: null,
          text: 'no preference — any live chat node',
          served: true,
          state: 'any live node',
        };
      }
      const served = classNames.has(a.class);
      return {
        purpose: a.alias,
        target: a.class,
        text: a.class,
        served,
        state: served ? 'served' : 'not served yet',
      };
    });
}

/** The one-line note under the purposes section about chat-default. */
export function chatDefaultLine(classes: ModelClass[]): string {
  const c = classes.find((x) => x.name === NO_PREFERENCE_CLASS);
  if (c && c.declared && !c.dynamic) {
    return 'chat-default is declared: it routes to the nodes named in its declaration.';
  }
  return 'chat-default is dynamic: it means every live chat node.';
}

export type NodeState = 'serving' | 'placed, not advertising' | 'stopped';

/** serving = desired running AND advertising. */
export function nodeState(n: PoolNode): NodeState {
  if (n.desiredState === 'running') return n.advertising ? 'serving' : 'placed, not advertising';
  return 'stopped';
}

export interface SpaceRow {
  space: string;
  model: string;
  dimsText: string;
  isDefault: boolean;
  live: number;
  pool: { node: string; backend: string; model: string; state: NodeState }[];
  /** Warning text, or null when the space has something serving it. */
  warning: string | null;
  deletable: boolean;
}

export function spaceRows(spaces: EmbeddingSpace[]): SpaceRow[] {
  return spaces.map((s) => ({
    space: s.space,
    model: s.model,
    dimsText: s.dims == null ? 'dims unknown' : String(s.dims),
    isDefault: s.isDefault,
    live: s.live,
    pool: s.pool.map((n) => ({ node: n.node, backend: n.backend, model: n.model, state: nodeState(n) })),
    warning:
      s.live > 0
        ? null
        : s.isDefault
          ? `Nothing is serving ${s.model} — every embed for the default space "${s.space}" fails until a node does.`
          : `Nothing is serving ${s.model} — embeds for "${s.space}" fail until a node does.`,
    deletable: !s.isDefault,
  }));
}

export function unmatchedWarning(n: PoolNode): string {
  return `${n.node} (${n.backend}) serves ${n.model || 'an unnamed model'}, which no space uses — it serves nobody.`;
}

/** Validate the "declare a space" form. Returns an error string or the clean body. */
export function parseSpaceForm(
  name: string,
  model: string,
  dims: string,
): { error: string } | { space: string; body: { model: string; dims?: number } } {
  const space = name.trim();
  const m = model.trim();
  if (!space) return { error: 'Give the space a name.' };
  if (!/^[A-Za-z0-9][A-Za-z0-9._-]*$/.test(space)) {
    return { error: 'Space names use letters, digits, dot, dash and underscore.' };
  }
  if (!m) return { error: 'Name the embedding model this space is bound to.' };
  const d = dims.trim();
  if (!d) return { space, body: { model: m } };
  const n = Number(d);
  if (!Number.isInteger(n) || n <= 0) return { error: 'Dimensions must be a positive whole number.' };
  return { space, body: { model: m, dims: n } };
}

/** Pull the server's own message out of an error body of unknown shape. */
export function errorMessage(err: unknown, fallback: string): string {
  if (typeof err === 'string' && err) return err;
  if (err && typeof err === 'object') {
    const o = err as Record<string, unknown>;
    for (const k of ['error', 'message', 'detail']) {
      const v = o[k];
      if (typeof v === 'string' && v) return v;
      if (v && typeof v === 'object') {
        const inner = (v as Record<string, unknown>).message;
        if (typeof inner === 'string' && inner) return inner;
      }
    }
  }
  return fallback;
}
