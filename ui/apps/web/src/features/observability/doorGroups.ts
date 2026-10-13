// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 PersonifAI LLC

import type { Container } from './useObservability';

/**
 * A backend that cannot terminate TLS itself runs behind an stunnel sidecar —
 * its mTLS "door". Docker reports the door as a container of its own, so a
 * flat list showed `noo-stunnel-ollama` beside `noo-ollama` and read as two
 * ollamas per node. This folds each door into its backend's row.
 *
 * The naming rule is the source's, not a table: compose names the door
 * `${NOO_CONTAINER_PREFIX:-noo}-stunnel-<x>` beside `${NOO_CONTAINER_PREFIX:-noo}-<x>`
 * (docker-compose.cluster.yml), and the node agent uses the same names
 * (node-agent-go/internal/docker/client.go StunnelContainerPrefix,
 * SidecarContainerFor). So `<p>-stunnel-<x>` is the door for `<p>-<x>` on the
 * same node — which also covers `noo-stunnel-tei-gpu` → `noo-tei-gpu` and
 * `noo-stunnel-ollama-embed` → `noo-ollama-embed` with no special case.
 */
const DOOR_RE = /^(.+)-stunnel-(.+)$/;

/**
 * Services that are served ONLY through a sidecar door — used for one thing:
 * warning when a running backend has no door at all. Mirrors the `Sidecar`
 * column of backendDoors (node-agent-go/internal/docker/client.go) plus the
 * compose-only variants (tei-gpu, ollama-embed). vLLM terminates TLS itself
 * and airllm is plain by named exception, so neither is here. The grouping
 * above does not read this list.
 */
const DOORED_SERVICES = ['llamacpp', 'ollama', 'ollama-embed', 'tei', 'tei-gpu', 'reranker'];

/** `noo-stunnel-ollama` → `noo-ollama`; null for a name that is not a door. */
export function doorBackendName(name: string): string | null {
  const m = DOOR_RE.exec(name);
  return m ? `${m[1]}-${m[2]}` : null;
}

function expectsDoor(name: string): boolean {
  return DOORED_SERVICES.some((svc) => {
    if (!name.endsWith(`-${svc}`)) return false;
    const prefix = name.slice(0, -(svc.length + 1));
    return prefix.length > 0 && !prefix.endsWith('-stunnel');
  });
}

export type DoorState = 'running' | 'down' | 'missing';

export interface ContainerRow extends Container {
  /** The backend's mTLS door, folded into this row; null = none seen. */
  door: Container | null;
  /** Door state for the badge; null when this backend has no door and needs none. */
  doorState: DoorState | null;
  /** Set when the door is missing or not running while the backend runs. */
  doorWarning: string | null;
  /** This row is a door whose backend is not in the list — a leftover. */
  orphanDoor: boolean;
}

const running = (c: Container) => c.status === 'running';

/**
 * One row per backend, its door attached. A door with no matching backend on
 * its node is NOT hidden: it stays as its own row, flagged, so a leftover
 * sidecar is visible. Row order follows the first appearance of either half.
 */
export function groupBackendDoors(containers: Container[]): ContainerRow[] {
  const key = (node: string, name: string) => `${node}\u0000${name}`;
  const present = new Set(containers.map((c) => key(c.node, c.name)));
  const doors = new Map<string, Container>();
  for (const c of containers) {
    const backend = doorBackendName(c.name);
    if (backend && present.has(key(c.node, backend))) doors.set(key(c.node, backend), c);
  }

  const rows: ContainerRow[] = [];
  for (const c of containers) {
    const backend = doorBackendName(c.name);
    if (backend) {
      if (present.has(key(c.node, backend))) continue; // folded into its backend's row
      rows.push({
        ...c,
        door: null,
        doorState: null,
        doorWarning: `mTLS door with no ${backend} on ${c.node} — leftover sidecar`,
        orphanDoor: true,
      });
      continue;
    }
    const door = doors.get(key(c.node, c.name)) ?? null;
    const doorState: DoorState | null = door
      ? running(door)
        ? 'running'
        : 'down'
      : expectsDoor(c.name)
        ? 'missing'
        : null;
    let doorWarning: string | null = null;
    if (running(c) && doorState === 'missing') {
      doorWarning = `${c.name} is running with no mTLS door — callers cannot reach it`;
    } else if (running(c) && doorState === 'down') {
      doorWarning = `${c.name} is running but its mTLS door ${door!.name} is ${door!.status || 'not running'}`;
    }
    rows.push({ ...c, door, doorState, doorWarning, orphanDoor: false });
  }
  return rows;
}
