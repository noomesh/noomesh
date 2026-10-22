// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 PersonifAI LLC

import { useQuery, useMetisClient, useAuth } from '@metis/core';

/** A reported number, or null when the field is absent or not a number. */
export function num(v: unknown): number | null {
  return typeof v === 'number' && Number.isFinite(v) ? v : null;
}
/** Scale a reported number; null stays null. */
export function scale(v: number | null, k: number): number | null {
  return v === null ? null : v * k;
}

export interface HealthDep {
  name: string;
  /** 'unknown' = the gateway reported nothing about this dependency. */
  status: 'ok' | 'down' | 'unknown';
}
// A telemetry number the gateway did not send is `null`, never 0: a GPU
// whose temperature is unreported must not draw as a cold one (i191 D-UI).
export interface Gpu {
  name: string;
  temp: number | null;
  util: number | null;
  vramUsed: number | null;
  vramTotal: number | null;
  power: number | null;
}
export interface Container {
  name: string;
  node: string;
  status: string;
  cpu: number;
  memUsed: number;
  memLimit: number;
  memPct: number;
}
/**
 * Add-on state. Deliberately **not** a boolean.
 *
 * `disabled` and `unhealthy` are opposite kinds of fact and must not render
 * alike: the first is a choice the operator made, the second is a fault. A
 * boolean collapses them, which is how the first cut of this panel would have
 * painted a broken add-on as "switched off" — the precise confusion
 * `addons.rs` exists to prevent.
 *
 * `unhealthy` (flag on, container missing or down) is specced in the gateway's
 * an earlier change and **not emitted yet**. It is handled here so that when it
 * lands, the console is already correct rather than needing a retrofit.
 *
 * `unknown` catches any state we do not recognise — neither green nor red,
 * because guessing in either direction is worse than admitting we don't know.
 */
export type AddonState = 'enabled' | 'disabled' | 'unhealthy' | 'unknown';

/**
 * An opt-in subsystem, from `/health`'s `addons` map.
 *
 * Deliberately NOT folded into `deps`. The gateway's comment on the field is
 * explicit: *"an operator who opted out must see 'disabled', never
 * degraded-red… broken vs turned-off stay distinguishable (watchdog owns
 * broken)."* Painting a disabled add-on red would report a deliberate
 * configuration choice as a fault — which is why these render as their own
 * row rather than alongside Postgres and NATS.
 */
export interface Addon {
  /** Raw key from the gateway (`trellion`, `evolve`, `trellion_intel`, …). */
  id: string;
  label: string;
  state: AddonState;
}

export interface ObsData {
  status: string;
  deps: HealthDep[];
  addons: Addon[];
  gpus: Gpu[];
  containers: Container[];
  /** false = the account is below the operator role; container stats (GET /api/logs/docker-stats) are operator-only, like every log route. */
  containersAvailable: boolean;
}

/**
 * Add-on names we have a nicer label for. Anything not listed still renders —
 * the gateway builds this map from its `addons::ADDONS` table, so a new add-on
 * appears with no schema change, and a console that only knew a fixed list
 * would silently omit it.
 */
const ADDON_LABELS: Record<string, string> = {
  trellion: 'Trellion (knowledge)',
  trellion_intel: 'Trellion Intel (adaptive retrieval)',
  evolve: 'Evolve (self-tuning)',
};

const prettifyAddon = (id: string) =>
  ADDON_LABELS[id] ?? id.replace(/[_-]+/g, ' ').replace(/\b\w/g, (c) => c.toUpperCase());

/** Narrow the gateway's string to a state we render, without guessing. */
function addonState(raw: unknown): AddonState {
  return raw === 'enabled' || raw === 'disabled' || raw === 'unhealthy' ? raw : 'unknown';
}

/** Observability: gateway/service health + GPU telemetry + container stats (15s). */
export function useObservability() {
  const client = useMetisClient();
  const { isOperator } = useAuth();
  return useQuery<ObsData>({
    queryKey: ['observability', isOperator],
    refetchInterval: 15_000,
    queryFn: async () => {
      // Container stats ride a log route, and every /api/logs/* answers an
      // Operator or Admin only. Below that role the call is not made: one
      // 403 would otherwise fail the whole panel, health and GPUs included.
      const [h, g, c] = await Promise.all([
        client.GET('/health'),
        client.GET('/api/cluster/gpu-metrics'),
        isOperator ? client.GET('/api/logs/docker-stats') : Promise.resolve({ data: undefined }),
      ]);
      const deps = h.data?.dependencies ?? {};
      // Absent (undefined) → 'unknown', not 'ok': the gateway said nothing about
      // this dependency, so don't paint it green.
      const depStatus = (d?: { healthy?: boolean }): HealthDep['status'] =>
        d?.healthy === true ? 'ok' : d?.healthy === false ? 'down' : 'unknown';
      const status = String(h.data?.status ?? 'unknown');
      const gateway: HealthDep['status'] =
        status === 'healthy' || status === 'ok' ? 'ok' : status === 'unknown' ? 'unknown' : 'down';
      return {
        status,
        deps: [
          { name: 'Gateway', status: gateway },
          { name: 'Postgres', status: depStatus(deps.postgresql) },
          { name: 'NATS', status: depStatus(deps.nats) },
          { name: 'Redis', status: depStatus(deps.redis) },
        ],
        // Rendered from whatever keys arrive, in the gateway's own order —
        // not a fixed list. `addons::ADDONS` is a table there, so hardcoding
        // the names here would quietly drop the next add-on that lands.
        addons: Object.entries(h.data?.addons ?? {}).map(([id, state]) => ({
          id,
          label: prettifyAddon(id),
          state: addonState(state),
        })),
        gpus: (g.data?.gpus ?? []).map((x) => ({
          name: x.name || `GPU ${x.index ?? 0}`,
          temp: num(x.temperature),
          util: num(x.utilization),
          vramUsed: scale(num(x.memory_used), 1 / 1024),
          vramTotal: scale(num(x.memory_total), 1 / 1024),
          power: num(x.power),
        })),
        containersAvailable: isOperator,
        containers: (c.data?.containers ?? []).map((x) => ({
          name: x.name ?? '?',
          node: x.node_hostname || x.node_id || '?',
          status: x.status ?? '',
          cpu: x.cpu_percent ?? 0,
          memUsed: x.mem_usage_mb ?? 0,
          memLimit: x.mem_limit_mb ?? 0,
          memPct: x.mem_percent ?? 0,
        })),
      };
    },
  });
}
