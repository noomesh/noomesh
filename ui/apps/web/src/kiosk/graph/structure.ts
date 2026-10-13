// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 PersonifAI LLC

// What "the structure changed" means for the graph view: a different set of
// entities or a different set of links — never a different order, and never
// a different count. The simulation is rebuilt only when this key changes;
// everything else (degrees, activity) flows into the running sim.
//
// This exists because the first cut keyed on the nodes in display order, and
// display order is by size, so every ingest re-ordered the key and rebuilt
// the simulation from scratch — the whole cloud re-seeded on each
// `graph.delta`, which in the bulk-ingest rehearsal was every two seconds.
// Display order is by DEGREE now rather than member count, and degree moves
// on every ingest too, so the guard still earns its place.

export function structureKey(nodeIds: readonly string[], links: readonly { src: string; dst: string }[]): string {
  const ids = [...new Set(nodeIds)].sort();
  const edges = [...new Set(links.map((l) => (l.src < l.dst ? `${l.src}>${l.dst}` : `${l.dst}>${l.src}`)))].sort();
  return `${ids.join(',')}|${edges.join(',')}`;
}
