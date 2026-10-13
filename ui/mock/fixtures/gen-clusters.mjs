// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 PersonifAI LLC

// Generates GET/api/v1/graph/clusters/overview.json — a knowledge graph the
// size of a developer's own system after a few months: dozens of clusters,
// a few thousand entities, a couple of hundred inter-cluster links.
// Deterministic. Run: node mock/fixtures/gen-clusters.mjs
import fs from 'node:fs';
import path from 'node:path';
import url from 'node:url';

const HERE = path.dirname(url.fileURLToPath(import.meta.url));
let s = 20260904;
const rand = () => {
  s = (s + 0x6d2b79f5) >>> 0;
  let t = Math.imul(s ^ (s >>> 15), 1 | s);
  t = (t + Math.imul(t ^ (t >>> 7), 61 | t)) ^ t;
  return ((t ^ (t >>> 14)) >>> 0) / 4294967296;
};

const NAMES = [
  'mesh operations', 'people', 'pai-assistant', 'pai-mesh-ui', 'trellion', 'hardware', 'security & pki', 'launch',
  'design', 'models', 'conversations', 'misc', 'gateway', 'node agents', 'scheduler', 'embeddings', 'vllm', 'ollama',
  'docker', 'kubernetes', 'tailscale', 'certificates', 'backups', 'monitoring', 'prometheus', 'grafana', 'postgres',
  'nats', 'redis', 'migrations', 'cli', 'onboarding', 'docs', 'runbooks', 'proposals', 'followups', 'releases',
  'ghcr', 'licensing', 'entitlements', 'evolve', 'heartbeat', 'autonomy', 'approvals', 'recall', 'recall memory',
  'rag ingest', 'graph build',
];
const N = NAMES.length; // 48
const nodes = NAMES.map((name, i) => {
  const big = i < 12; // the first dozen are the old fixture's, kept large
  const members = big ? 24 + Math.floor(rand() * 100) : 4 + Math.floor(rand() * 40);
  return { id: `c${String(i + 1).padStart(2, '0')}`, name, type: 'cluster', level: 1, degree: 0, member_count: members };
});
// Links: each cluster to 2–4 others, preferring big ones; no duplicates.
const key = (a, b) => (a < b ? `${a}|${b}` : `${b}|${a}`);
const seen = new Set();
const edges = [];
for (const n of nodes) {
  const want = 2 + Math.floor(rand() * 3);
  let tries = 0;
  let made = 0;
  while (made < want && tries++ < 40) {
    const pick = rand() < 0.55 ? nodes[Math.floor(rand() * 12)] : nodes[Math.floor(rand() * N)];
    if (!pick || pick.id === n.id || seen.has(key(n.id, pick.id))) continue;
    seen.add(key(n.id, pick.id));
    edges.push({
      src: n.id,
      dst: pick.id,
      rel_type: 'INTER_CLUSTER',
      confidence: Math.round((0.5 + rand() * 0.5) * 100) / 100,
      weight: 1 + Math.floor(rand() * Math.min(n.member_count, pick.member_count) * 0.3),
    });
    n.degree++;
    pick.degree++;
    made++;
  }
}
const out = { nodes, edges, stats: { node_count: nodes.length, edge_count: edges.length, level: 1 } };
const target = path.join(HERE, 'GET/api/v1/graph/clusters/overview.json');
fs.writeFileSync(target, JSON.stringify(out, null, 2) + '\n');
const entities = nodes.reduce((a, n) => a + n.member_count, 0);
console.log(`${nodes.length} clusters, ${entities} entities, ${edges.length} links → ${path.relative(process.cwd(), target)}`);
