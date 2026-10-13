// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 PersonifAI LLC

// Generates GET/api/kiosk/graph.json — what the display actually fetches.
//
// The ENTITY level, as the gateway's kiosk projection sends it by DEFAULT:
// ids (uuids), types and degrees, and edges with nothing but endpoints. No
// `name`, no `rel_type` — the real gateway does not put them on the wire
// unless the page asked with `?labels=1`, and a mock that sends them anyway
// would let a names-leak ship while every local run looked fine.
//
// `entity_count` is the WHOLE graph; the nodes are the 160 hubs a wall can
// legibly hold. The two differing is the point — the display renders both.
//
// Deterministic. Run: node mock/fixtures/gen-kiosk-graph.mjs
import fs from 'node:fs';
import path from 'node:path';
import url from 'node:url';

const HERE = path.dirname(url.fileURLToPath(import.meta.url));
let s = 20260914;
const rand = () => {
  s = (s + 0x6d2b79f5) >>> 0;
  let t = Math.imul(s ^ (s >>> 15), 1 | s);
  t = (t + Math.imul(t ^ (t >>> 7), 61 | t)) ^ t;
  return ((t ^ (t >>> 14)) >>> 0) / 4294967296;
};
const hex = (n) => Array.from({ length: n }, () => '0123456789abcdef'[Math.floor(rand() * 16)]).join('');
const uuid = () => `${hex(8)}-${hex(4)}-${hex(4)}-${hex(4)}-${hex(12)}`;

// The open tier's real proportions: mostly concepts, some documents and
// people. A type is a bucket, not a name, so it IS sent without the opt-in.
const TYPES = [
  ...Array(60).fill('concept'),
  ...Array(25).fill('document'),
  ...Array(10).fill('person'),
  ...Array(5).fill('organization'),
];

const N = 160; // KIOSK_GRAPH_LIMIT in routes/kiosk.rs
const nodes = Array.from({ length: N }, () => ({
  id: uuid(),
  type: TYPES[Math.floor(rand() * TYPES.length)],
  degree: 0,
}));

// A few hubs carry most of the connections — which is what `top_entities_by
// _degree` selects for, and what makes the cloud read as a structure rather
// than a mesh.
const key = (a, b) => (a < b ? `${a}|${b}` : `${b}|${a}`);
const seen = new Set();
const edges = [];
for (const n of nodes) {
  const want = 2 + Math.floor(rand() * 4);
  let tries = 0;
  let made = 0;
  while (made < want && tries++ < 40) {
    const pick = rand() < 0.5 ? nodes[Math.floor(rand() * 20)] : nodes[Math.floor(rand() * N)];
    if (!pick || pick.id === n.id || seen.has(key(n.id, pick.id))) continue;
    seen.add(key(n.id, pick.id));
    edges.push({ src: n.id, dst: pick.id });
    n.degree++;
    pick.degree++;
    made++;
  }
}
nodes.sort((a, b) => b.degree - a.degree);

const out = {
  nodes,
  edges,
  stats: {
    node_count: nodes.length,
    edge_count: edges.length,
    max_degree: nodes[0].degree,
    min_degree: nodes[nodes.length - 1].degree,
  },
  // The live box on the day this view changed: 4,538 entities, of which
  // clustering had reached 761.
  entity_count: 4538,
};
const target = path.join(HERE, 'GET/api/kiosk/graph.json');
fs.mkdirSync(path.dirname(target), { recursive: true });
fs.writeFileSync(target, JSON.stringify(out, null, 2) + '\n');
const leaked = JSON.stringify(out).match(/"(name|rel_type)"/);
if (leaked) throw new Error(`the mock is sending ${leaked[1]}, which the gateway withholds`);
console.log(`${nodes.length} entities, ${edges.length} links → ${path.relative(process.cwd(), target)}`);
