// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 PersonifAI LLC

// Mock gateway — lets the UI run with no backend at all.
//
//   npm run mock          # listens on :9800 (PORT env to override)
//   npm run dev:mock      # vite dev server proxying to this mock
//
// REST: every request is matched against contracts/openapi.json.
//   - Response body resolution order:
//       1. mock/fixtures/<METHOD>/<path>.json   (literal path, then the spec's
//          templated path with {param} segments as directory names)
//       2. the spec's response example / synthesized stub from its schema
//       3. {}
//   - A path NOT in the contract returns 404 {"detail":"not in contract"} and
//     logs loudly — that's the point: UI calls outside the contract fail fast.
//
// WS: /ws/coordinator streams a scripted chat turn per contracts/ws/ws-protocol.md
//     (metadata → thinking → content chunks → done). /ws/collab answers ping
//     with pong and sends keepalives.

import http from 'node:http';
import fs from 'node:fs';
import path from 'node:path';
import url from 'node:url';
import { WebSocketServer } from 'ws';

const ROOT = path.dirname(url.fileURLToPath(import.meta.url));
const PORT = Number(process.env.PORT || 9800);
const spec = JSON.parse(fs.readFileSync(path.join(ROOT, '../contracts/openapi.json'), 'utf8'));
const specPaths = Object.keys(spec.paths || {});

// ── Contract matching ────────────────────────────────────────────────────────
function matchSpecPath(reqPath) {
  if (spec.paths[reqPath]) return reqPath;
  const segs = reqPath.split('/');
  return specPaths.find(sp => {
    const ss = sp.split('/');
    if (ss.length !== segs.length) return false;
    return ss.every((s, i) => s === segs[i] || (s.startsWith('{') && s.endsWith('}')));
  }) || null;
}

// ── Stub synthesis from an OpenAPI schema ────────────────────────────────────
function synth(schema, depth = 0) {
  if (!schema || depth > 6) return null;
  if (schema.example !== undefined) return schema.example;
  if (schema.$ref) {
    const parts = schema.$ref.replace(/^#\//, '').split('/');
    let node = spec;
    for (const p of parts) node = node?.[p];
    return synth(node, depth + 1);
  }
  switch (schema.type) {
    case 'object': {
      const o = {};
      for (const [k, v] of Object.entries(schema.properties || {})) o[k] = synth(v, depth + 1);
      return o;
    }
    case 'array': return schema.items ? [synth(schema.items, depth + 1)].filter(v => v !== null) : [];
    case 'string': return schema.enum ? schema.enum[0] : '';
    case 'integer': case 'number': return 0;
    case 'boolean': return false;
    default: return schema.properties ? synth({ ...schema, type: 'object' }, depth) : {};
  }
}

// Fixtures may be query-specific: `<path>__<key>=<value>.json` wins over the
// plain `<path>.json`. Without this a tab whose only job is switching a query
// param (Usage's node/model/backend/source toggle) looks broken offline — the
// request changes, the response never does.
function fixtureFor(method, reqPath, specPath, query) {
  const dir = path.join(ROOT, 'fixtures', method.toUpperCase());
  const bases = [reqPath, specPath].filter(Boolean).map(p => p.replace(/^\//, ''));
  const suffixes = Object.entries(query || {})
    .map(([k, v]) => `__${k}=${Array.isArray(v) ? v[0] : v}`);

  for (const b of bases) {
    for (const suffix of [...suffixes, '']) {
      const f = path.join(dir, b + suffix + '.json');
      if (fs.existsSync(f)) return JSON.parse(fs.readFileSync(f, 'utf8'));
    }
  }
  return undefined;
}

// ── Hardcoded auth endpoints (session flow must work end-to-end) ────────────
const MOCK_TOKEN = 'mock-token';
const authRoutes = {
  'POST /auth/token': () => ({ access_token: MOCK_TOKEN, token_type: 'bearer' }),
  'POST /api/auth/refresh': () => ({ access_token: MOCK_TOKEN, token_type: 'bearer' }),
  'POST /auth/refresh': () => ({ access_token: MOCK_TOKEN, token_type: 'bearer' }),
  'POST /api/auth/logout': () => ({ ok: true }),
  'GET /auth/me': () => ({ username: 'dev', scopes: ['admin', 'write', 'read'] }),
  // NOTE: `/health` deliberately has NO handler here. It used to return
  // `{status:'ok', engine:'mock'}`, which shadowed the far richer
  // fixtures/GET/health.json and made Observe untestable offline — the
  // dependency pills all read "unknown" and `addons` did not exist at all.
  // Handlers win over fixtures, so a stub here silently disables a fixture.
  // Same shape of trap as the invented `approval_outcome` frame: a mock that
  // agrees with nothing real teaches the client the wrong thing.
};

const server = http.createServer((req, res) => {
  const parsed = url.parse(req.url, true);
  const reqPath = parsed.pathname.replace(/\/$/, '') || '/';
  const reqQuery = parsed.query || {};
  const cors = {
    'Access-Control-Allow-Origin': req.headers.origin || '*',
    'Access-Control-Allow-Methods': 'GET,POST,PUT,PATCH,DELETE,OPTIONS',
    'Access-Control-Allow-Headers': 'Authorization,Content-Type',
    'Access-Control-Allow-Credentials': 'true',
  };
  if (req.method === 'OPTIONS') { res.writeHead(204, cors); return res.end(); }

  const send = (code, body) => {
    res.writeHead(code, { 'Content-Type': 'application/json', ...cors });
    res.end(JSON.stringify(body));
  };

  const hard = authRoutes[`${req.method} ${reqPath}`];
  if (hard) { console.log(`  ${req.method} ${reqPath} -> auth mock`); return send(200, hard()); }

  // The kiosk's state stream. NOT in the contract — it is a proposed path
  // (contracts/proposed/api-events-stream.json), so it is matched here, ahead
  // of the contract check, on purpose: the 404-on-uncontracted rule must keep
  // meaning what it means, and this is the one deliberate exception, named.
  if (req.method === 'GET' && reqPath === '/api/events/stream') return sseStream(req, res, cors);

  const specPath = matchSpecPath(reqPath);
  if (!specPath) {
    console.warn(`✗ ${req.method} ${reqPath} -> 404 NOT IN CONTRACT (add to contracts/openapi.json)`);
    return send(404, { detail: 'not in contract', path: reqPath });
  }

  const op = spec.paths[specPath][req.method.toLowerCase()];
  const fixture = fixtureFor(req.method, reqPath, specPath, reqQuery);
  if (fixture !== undefined) {
    console.log(`  ${req.method} ${reqPath} -> fixture`);
    return send(200, fixture);
  }
  const respSchema = op?.responses?.['200']?.content?.['application/json'];
  const body = respSchema?.example ?? synth(respSchema?.schema) ?? {};
  console.log(`  ${req.method} ${reqPath} -> ${op ? 'stub' : 'stub (method not in contract)'}`);
  send(200, body);
});

// ── SSE: /api/events/stream ─────────────────────────────────────────────────
// The proposed shape the kiosk is built against
// (contracts/proposed/api-events-stream.json). The gateway's version is
// pai-assistant an earlier change mechanism 3; when it lands, this mock follows it,
// not the reverse, and the fragment moves into openapi.json.
//
// What it exercises, deliberately: a keepalive on a fixed interval (silence
// must mean *dead*, so the client can tell "nothing changed" from "stream
// died"); ids on every event so Last-Event-ID resume is observable; and a
// scripted story so every kiosk region gets a transition to show — a node
// goes dark and comes back, a job fails, a heartbeat task fails then recovers,
// a GPU sits pinned. MOCK_SSE_KEEPALIVE_MS shortens the keepalive to test the
// liveness band without waiting.
const KEEPALIVE_MS = Number(process.env.MOCK_SSE_KEEPALIVE_MS || 5000);
let sseId = 0;

function sseStream(req, res, cors) {
  const since = req.headers['last-event-id'];
  console.log(`  GET /api/events/stream -> sse${since ? ` (resume after ${since})` : ''}`);
  res.writeHead(200, {
    'Content-Type': 'text/event-stream',
    'Cache-Control': 'no-cache, no-transform',
    Connection: 'keep-alive',
    ...cors,
  });
  const emit = (event, data) => {
    if (res.destroyed) return;
    res.write(`id: ${++sseId}\nevent: ${event}\ndata: ${JSON.stringify({ ts: new Date().toISOString(), ...data })}\n\n`);
  };
  res.write('retry: 3000\n\n');
  emit('hello', { keepalive_ms: KEEPALIVE_MS });

  const timers = [];
  const every = (ms, fn) => timers.push(setInterval(fn, ms));
  const after = (ms, fn) => timers.push(setTimeout(fn, ms));

  every(KEEPALIVE_MS, () => { if (!res.destroyed) res.write(': keepalive\n\n'); });

  // GPU samples: prime-01 idles and wanders; atlas-02 stays pinned so the
  // "pinned for N minutes" duration is visible on day one.
  let u1 = 38;
  every(3000, () => {
    u1 = Math.max(5, Math.min(70, u1 + Math.round((Math.random() - 0.5) * 16)));
    emit('gpu.sample', { node_id: 'prime-01', hostname: 'prime-01', index: '0', name: 'RTX 4090',
      utilization: u1, memory_used: 14520, memory_total: 24564, temperature: 52 + Math.round(u1 / 10) });
    emit('gpu.sample', { node_id: 'atlas-02', hostname: 'atlas-02', index: '0', name: 'RTX 3090',
      utilization: 91 + Math.round(Math.random() * 6), memory_used: 23340, memory_total: 24564, temperature: 72 });
  });

  // MOCK_INGEST_BURST=1: rehearse the "upload a ton of data" video. Every
  // couple of seconds an ingest lands, so the capture rig, the push-in
  // cadence and the counters can be judged before the real pipeline
  // exists. Off by default; the story below is the normal loop.
  //
  // No `clusters` array. The display's graph view is entity-level now, so
  // those were cluster ids arriving at a screen holding entity ids: they
  // could only miss. The two counts are the part that is true on every
  // tier and moves on every ingest, which is the whole reason the view
  // changed — see contracts/proposed/api-events-stream.json.
  if (process.env.MOCK_INGEST_BURST) {
    every(2200, () => {
      const added = 1 + Math.floor(Math.random() * 9);
      emit('graph.delta', { entities_added: added, edges_added: Math.floor(added * 1.4) });
    });
    return req.on('close', () => { timers.forEach(clearTimeout); timers.forEach(clearInterval); });
  }

  // The story. Loops so a display left running keeps having something to say.
  const story = () => {
    after(20_000, () => emit('node.state', { node_id: 'atlas-02', hostname: 'atlas-02', status: 'offline', previous: 'busy' }));
    after(50_000, () => emit('node.state', { node_id: 'atlas-02', hostname: 'atlas-02', status: 'online', previous: 'offline' }));
    after(55_000, () => emit('node.state', { node_id: 'atlas-02', hostname: 'atlas-02', status: 'busy', previous: 'online' }));
    after(65_000, () => emit('job.state', { job_id: 'j-9e1f00aa41', type: 'inference', status: 'failed', node_id: 'prime-01', error: 'CUDA out of memory' }));
    after(80_000, () => emit('heartbeat.task', { task: 'rag_reindex', ok: false, error: 'embedder timeout after 120s' }));
    after(95_000, () => emit('scheduler.state', { running: true, paused: false, queue_depth: 4, active_jobs: 1 }));
    after(110_000, () => emit('heartbeat.task', { task: 'rag_reindex', ok: true }));
    after(115_000, () => emit('scheduler.state', { running: true, paused: false, queue_depth: 1, active_jobs: 1 }));
    // Ingests, for the graph view: how much landed, never which entities.
    // Naming entities on the stream would put the knowledge base's contents
    // on a hallway wall by a second route, after the fetch path was closed.
    after(12_000, () => emit('graph.delta', { entities_added: 7, edges_added: 11 }));
    after(45_000, () => emit('graph.delta', { entities_added: 3, edges_added: 4 }));
    after(70_000, () => emit('graph.delta', { entities_added: 5, edges_added: 6 }));
    after(90_000, () => emit('graph.delta', { entities_added: 12, edges_added: 20 }));
    after(105_000, () => emit('graph.delta', { entities_added: 2, edges_added: 1 }));
    after(120_000, story);
  };
  story();

  req.on('close', () => { timers.forEach(clearTimeout); timers.forEach(clearInterval); console.log('  SSE /api/events/stream closed'); });
}

// ── WebSockets ──────────────────────────────────────────────────────────────
const wssCoord = new WebSocketServer({ noServer: true });
const wssCollab = new WebSocketServer({ noServer: true });

server.on('upgrade', (req, socket, head) => {
  const p = url.parse(req.url).pathname;
  if (p === '/ws/coordinator') wssCoord.handleUpgrade(req, socket, head, ws => wssCoord.emit('connection', ws, req));
  else if (p === '/ws/collab') wssCollab.handleUpgrade(req, socket, head, ws => wssCollab.emit('connection', ws, req));
  else socket.destroy();
});

const sleep = ms => new Promise(r => setTimeout(r, ms));

wssCoord.on('connection', ws => {
  console.log('  WS /ws/coordinator connected');
  ws.on('message', async raw => {
    let msg = {};
    try { msg = JSON.parse(raw); } catch { return; }
    if (!msg.prompt) return;
    const j = o => ws.send(JSON.stringify(o));
    const convId = msg.conversation_id || 'mock-conv-' + Math.random().toString(36).slice(2, 10);
    j({ type: 'metadata', conversation_id: convId, model: 'mock/model-1', backend: 'mock', api_format: 'openai', engine: 'mock' });
    if (msg.enable_thinking) {
      for (const t of ['Considering the question… ', 'consulting the contract… ', 'done.']) {
        j({ type: 'thinking', text: t }); await sleep(120);
      }
    }
    // An exec-approval, so the inline approval card is exercisable offline.
    // Prompts mentioning a risky verb raise one; everything else does not, so
    // the common path stays quick.
    //
    // This block used to send `approval_outcome: 'Approved — running…'`, which
    // the gateway NEVER sends — an approved call emits no outcome frame at all
    // (gateway-rust tools.rs; ws-protocol.md §2B). The invented frame is what
    // let the console's inverted reading of it survive: the mock agreed with
    // the bug. Both real paths are modelled here now.
    if (/\b(delete|remove|deploy|restart|drop)\b/i.test(msg.prompt)) {
      const requestId = 'apr_' + Math.random().toString(36).slice(2, 10);
      const tool = 'pai_execute_command';
      // The gate lives inside the call, so tool_call — carrying the arguments
      // the card displays — always precedes the request.
      j({ type: 'tool_call', name: tool, arguments: { command: `rm -rf /var/cache/${msg.prompt.slice(0, 12)}` } });
      j({
        type: 'approval_request',
        request_id: requestId,
        tool,
        window_secs: 120,
        text: `\u{1F510} Approval needed: ${tool} (id ${requestId})`,
      });
      await sleep(2500);
      // "deny" in the prompt takes the refusal path; anything else is allowed
      // and closes the card via tool_result, exactly as the gateway does.
      if (/\bdeny\b/i.test(msg.prompt)) {
        j({ type: 'approval_outcome', text: `\u{1F6AB} ${tool} was NOT executed — denied by mock-operator.` });
        j({ type: 'tool_result', name: tool, success: false, output: '',
            error: 'Security: approval denied by mock-operator', elapsed_ms: 2500 });
      } else {
        j({ type: 'tool_result', name: tool, success: true,
            output: 'removed 3 files', error: null, elapsed_ms: 2540 });
      }
    }

    // One tool round-trip, so the UI's tool_call → tool_result path is
    // exercisable offline (the frames are contracted in ws-protocol.md §2B).
    j({ type: 'tool_call', name: 'pai_cluster_status', arguments: { verbose: false } });
    await sleep(400);
    j({ type: 'tool_result', name: 'pai_cluster_status', success: true,
        output: '{"nodes":3,"online":1,"busy":1}', error: null, elapsed_ms: 412 });
    const reply = `(mock) You said: "${msg.prompt}". This response is streamed by mock/server.mjs per contracts/ws/ws-protocol.md.`;
    for (const word of reply.split(/(?<= )/)) {
      j({ type: 'content', text: word }); await sleep(30);
    }
    j({ type: 'done', iterations: 1, tool_calls: 1, elapsed_seconds: 1.2, tokens_in: 42, tokens_out: 24, engine: 'mock' });
  });
});

wssCollab.on('connection', ws => {
  console.log('  WS /ws/collab connected');
  const keep = setInterval(() => ws.readyState === ws.OPEN && ws.send(JSON.stringify({ type: 'keepalive' })), 30000);
  ws.on('message', raw => {
    try { if (JSON.parse(raw).type === 'ping') ws.send(JSON.stringify({ type: 'pong' })); } catch {}
  });
  ws.on('close', () => clearInterval(keep));

  // Scripted demo collaboration so the Collab tab has something to render
  // (real events are relayed from the collab engine via NATS).
  const j = o => ws.readyState === ws.OPEN && ws.send(JSON.stringify(o));
  (async () => {
    await sleep(500);
    j({ type: 'collab_start', collab_id: 'demo-collab', roles: ['planner', 'coder', 'reviewer'],
        backends: [{ role: 'coder', backend_type: 'vllm', node_id: 'prime-01' }] });
    const script = [
      ['planner', 'Plan: 1) parse the cluster telemetry, 2) rank nodes by load, 3) recommend a target. '],
      ['coder', 'def hottest(nodes):\n    return max(nodes, key=lambda n: n.load)\n'],
      ['planner', 'Reviewer — check the empty-cluster edge case. '],
      ['reviewer', 'max() throws on an empty list; add a guard and return None. Otherwise the ranking is correct. '],
      ['coder', '    if not nodes:\n        return None\n'],
    ];
    for (const [role, content] of script) {
      j({ type: 'iteration_start', role, iteration: 1 });
      for (const w of content.split(/(?<= )/)) { j({ type: 'tokens', role, content: w }); await sleep(24); }
      await sleep(160);
    }
    j({ type: 'done', role: 'coder', iteration: 1 });
    j({ type: 'collab_done',
        outcomes: { planner: 'complete', coder: 'complete', reviewer: 'complete' },
        results: {} });
  })();
});

server.listen(PORT, () => {
  console.log(`Mock gateway on http://localhost:${PORT}  (${specPaths.length} contracted paths)`);
  console.log('Fixtures dir: mock/fixtures/<METHOD>/<path>.json');
});
