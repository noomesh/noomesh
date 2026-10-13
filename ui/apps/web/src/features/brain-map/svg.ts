// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 PersonifAI LLC

import type { NodeInfo, LegendItem } from '@/features/_diagram/DiagramView';
import type { SlotNode } from '@/features/addons/slots';

// Base architecture diagram (ported verbatim from the legacy brain.html) with
// the "Identity & Evolution" add-on overlay integrated inline. Colors stay in the legacy
// palette here — reskin() remaps them to Slate at render. Marker ids are
// brain-* prefixed to avoid colliding with the Workflow diagram.
export const BRAIN_SVG = `
<svg viewBox="-25 0 1250 500" xmlns="http://www.w3.org/2000/svg" id="brain-svg">
  <defs>
    <filter id="brain-glow"><feGaussianBlur stdDeviation="3" result="b"/><feMerge><feMergeNode in="b"/><feMergeNode in="SourceGraphic"/></feMerge></filter>
    <filter id="brain-pglow"><feGaussianBlur stdDeviation="4" result="b"/><feMerge><feMergeNode in="b"/><feMergeNode in="SourceGraphic"/></feMerge></filter>
    <marker id="brain-ah-orange" viewBox="0 0 10 10" refX="9" refY="5" markerWidth="6" markerHeight="6" orient="auto-start-reverse"><path d="M0 0L10 5L0 10z" fill="#f97316"/></marker>
    <marker id="brain-ah-blue" viewBox="0 0 10 10" refX="9" refY="5" markerWidth="6" markerHeight="6" orient="auto-start-reverse"><path d="M0 0L10 5L0 10z" fill="#38bdf8"/></marker>
    <marker id="brain-ah-amber" viewBox="0 0 10 10" refX="9" refY="5" markerWidth="6" markerHeight="6" orient="auto-start-reverse"><path d="M0 0L10 5L0 10z" fill="#f59e0b"/></marker>
    <marker id="brain-ah-lime" viewBox="0 0 10 10" refX="9" refY="5" markerWidth="6" markerHeight="6" orient="auto-start-reverse"><path d="M0 0L10 5L0 10z" fill="#84cc16"/></marker>
  </defs>

  <text x="600" y="16" text-anchor="middle" fill="rgba(56,189,248,0.5)" font-size="10" font-weight="700" letter-spacing="2">INTERFACE</text>
  <g class="brain-node" data-id="dashboard"><rect x="343" y="28" width="110" height="28" rx="14" fill="rgba(56,189,248,0.1)" stroke="rgba(56,189,248,0.4)" stroke-width="1"/><text x="398" y="46" text-anchor="middle" fill="#38bdf8" font-size="11">Dashboard</text></g>
  <g class="brain-node" data-id="api-gateway"><rect x="478" y="28" width="110" height="28" rx="14" fill="rgba(56,189,248,0.1)" stroke="rgba(56,189,248,0.4)" stroke-width="1"/><text x="533" y="46" text-anchor="middle" fill="#38bdf8" font-size="11">API Gateway</text></g>
  <g class="brain-node" data-id="channels"><rect x="613" y="28" width="110" height="28" rx="14" fill="rgba(56,189,248,0.1)" stroke="rgba(56,189,248,0.4)" stroke-width="1"/><text x="668" y="46" text-anchor="middle" fill="#38bdf8" font-size="11">Channels</text></g>
  <g class="brain-node" data-id="mcp-hub"><rect x="748" y="28" width="110" height="28" rx="14" fill="rgba(56,189,248,0.1)" stroke="rgba(56,189,248,0.4)" stroke-width="1"/><text x="803" y="46" text-anchor="middle" fill="#38bdf8" font-size="11">MCP Hub</text></g>

  <rect x="100" y="68" width="1000" height="320" rx="16" fill="rgba(16,185,129,0.04)" stroke="rgba(16,185,129,0.25)" stroke-width="1.5"/>
  <text x="115" y="84" fill="rgba(16,185,129,0.5)" font-size="10" font-weight="700" letter-spacing="2">SYSTEM 1 · AUTOMATIC</text>
  <g class="brain-node" data-id="backend-mgr"><rect x="340" y="96" width="130" height="28" rx="14" fill="rgba(16,185,129,0.1)" stroke="rgba(16,185,129,0.4)" stroke-width="1"/><text x="405" y="114" text-anchor="middle" fill="#10b981" font-size="11">BackendManager</text></g>
  <circle class="brain-status-dot" id="brain-sd-backend" cx="474" cy="100" r="4" fill="#4b5563"/>
  <g class="brain-node" data-id="security"><rect x="490" y="96" width="110" height="28" rx="14" fill="rgba(16,185,129,0.1)" stroke="rgba(16,185,129,0.4)" stroke-width="1"/><text x="545" y="114" text-anchor="middle" fill="#10b981" font-size="11">Security</text></g>
  <circle class="brain-status-dot" id="brain-sd-security" cx="604" cy="100" r="4" fill="#4b5563"/>
  <g class="brain-node" data-id="cache"><rect x="620" y="96" width="90" height="28" rx="14" fill="rgba(16,185,129,0.1)" stroke="rgba(16,185,129,0.4)" stroke-width="1"/><text x="665" y="114" text-anchor="middle" fill="#10b981" font-size="11">Cache</text></g>
  <g class="brain-node" data-id="recall-memory"><rect x="730" y="96" width="115" height="28" rx="14" fill="rgba(16,185,129,0.1)" stroke="rgba(16,185,129,0.4)" stroke-width="1"/><text x="787" y="114" text-anchor="middle" fill="#10b981" font-size="11">Recall Memory</text></g>

  <rect x="170" y="130" width="860" height="248" rx="14" fill="rgba(6,182,212,0.04)" stroke="rgba(6,182,212,0.25)" stroke-width="1.5"/>
  <text x="185" y="146" fill="rgba(6,182,212,0.5)" font-size="10" font-weight="700" letter-spacing="2">LONG-TERM MEMORY</text>
  <text x="452" y="155" text-anchor="middle" fill="rgba(6,182,212,0.35)" font-size="8" font-weight="600" letter-spacing="1">EPISODIC</text>
  <text x="673" y="155" text-anchor="middle" fill="rgba(6,182,212,0.35)" font-size="8" font-weight="600" letter-spacing="1">SEMANTIC</text>
  <line x1="515" y1="140" x2="515" y2="184" stroke="rgba(6,182,212,0.15)" stroke-width="1" stroke-dasharray="3,3"/>
  <g class="brain-node" data-id="conversations"><rect x="395" y="158" width="115" height="28" rx="14" fill="rgba(6,182,212,0.1)" stroke="rgba(6,182,212,0.4)" stroke-width="1"/><text x="452" y="176" text-anchor="middle" fill="#06b6d4" font-size="11">Conversations</text></g>
  <g class="brain-node" data-id="pageindex"><rect x="540" y="158" width="115" height="28" rx="14" fill="rgba(6,182,212,0.1)" stroke="rgba(6,182,212,0.4)" stroke-width="1"/><text x="597" y="176" text-anchor="middle" fill="#06b6d4" font-size="11">PageIndex KB</text></g>
  <g class="brain-node" data-id="knowledge-graph"><rect x="685" y="158" width="130" height="28" rx="14" fill="rgba(6,182,212,0.1)" stroke="rgba(6,182,212,0.4)" stroke-width="1"/><text x="750" y="176" text-anchor="middle" fill="#06b6d4" font-size="11">Knowledge Graph</text></g>

  <rect x="220" y="192" width="760" height="175" rx="12" fill="rgba(236,72,153,0.04)" stroke="rgba(236,72,153,0.25)" stroke-width="1.5"/>
  <text x="235" y="208" fill="rgba(236,72,153,0.5)" font-size="10" font-weight="700" letter-spacing="2">SYSTEM 2 · DELIBERATE</text>
  <g class="brain-node" data-id="coordinator"><rect x="238" y="220" width="125" height="28" rx="14" fill="rgba(236,72,153,0.1)" stroke="rgba(236,72,153,0.4)" stroke-width="1"/><text x="300" y="238" text-anchor="middle" fill="#ec4899" font-size="11">Coordinator</text></g>
  <g class="brain-node" data-id="tools"><rect x="375" y="220" width="95" height="28" rx="14" fill="rgba(236,72,153,0.1)" stroke="rgba(236,72,153,0.4)" stroke-width="1"/><text x="422" y="238" text-anchor="middle" fill="#ec4899" font-size="11">Tools</text></g>
  <g class="brain-node" data-id="claude-code"><rect x="482" y="220" width="110" height="28" rx="14" fill="rgba(236,72,153,0.1)" stroke="rgba(236,72,153,0.4)" stroke-width="1"/><text x="537" y="238" text-anchor="middle" fill="#ec4899" font-size="11">Claude Code</text></g>
  <g class="brain-node" data-id="multi-agent"><rect x="604" y="220" width="110" height="28" rx="14" fill="rgba(236,72,153,0.1)" stroke="rgba(236,72,153,0.4)" stroke-width="1"/><text x="659" y="238" text-anchor="middle" fill="#ec4899" font-size="11">Multi-Agent</text></g>
  <g class="brain-node" data-id="autonomy"><rect x="726" y="220" width="110" height="28" rx="14" fill="rgba(236,72,153,0.1)" stroke="rgba(236,72,153,0.4)" stroke-width="1"/><text x="781" y="238" text-anchor="middle" fill="#ec4899" font-size="11">Autonomy</text></g>
  <circle class="brain-status-dot" id="brain-sd-autonomy" cx="840" cy="224" r="4" fill="#4b5563"/>
  <g class="brain-node" data-id="scheduler"><rect x="848" y="220" width="105" height="28" rx="14" fill="rgba(236,72,153,0.1)" stroke="rgba(236,72,153,0.4)" stroke-width="1"/><text x="900" y="238" text-anchor="middle" fill="#ec4899" font-size="11">Scheduler</text></g>

  <rect x="340" y="255" width="520" height="105" rx="10" fill="rgba(239,68,68,0.07)" stroke="rgba(239,68,68,0.35)" stroke-width="1.5"/>
  <text x="600" y="271" text-anchor="middle" fill="rgba(239,68,68,0.6)" font-size="10" font-weight="700" letter-spacing="2">IDENTITY &amp; EVOLUTION</text>
  <g class="brain-node" data-id="static-identity"><rect x="460" y="283" width="130" height="28" rx="14" fill="rgba(239,68,68,0.12)" stroke="rgba(239,68,68,0.45)" stroke-width="1"/><text x="525" y="301" text-anchor="middle" fill="#ef4444" font-size="11">Static Identity</text></g>
  <g class="brain-node" data-id="self-config"><rect x="610" y="283" width="130" height="28" rx="14" fill="rgba(239,68,68,0.12)" stroke="rgba(239,68,68,0.45)" stroke-width="1"/><text x="675" y="301" text-anchor="middle" fill="#ef4444" font-size="11">Self-Identity</text></g>
  <g class="brain-node" data-id="hofstadter-loop"><rect x="405" y="320" width="130" height="28" rx="14" fill="rgba(245,158,11,0.12)" stroke="rgba(245,158,11,0.45)" stroke-width="1"/><text x="470" y="338" text-anchor="middle" fill="#f59e0b" font-size="11">Evolution Loop</text></g>
  <circle class="brain-status-dot" id="brain-sd-hofstadter" cx="529" cy="324" r="4" fill="#4b5563"/>
  <g class="brain-node" data-id="genetic-algorithm"><rect x="600" y="320" width="140" height="28" rx="14" fill="rgba(132,204,22,0.12)" stroke="rgba(132,204,22,0.45)" stroke-width="1"/><text x="670" y="338" text-anchor="middle" fill="#84cc16" font-size="11">Parameter Tuning</text></g>
  <circle class="brain-status-dot" id="brain-sd-ga" cx="734" cy="324" r="4" fill="#4b5563"/>

  <rect x="100" y="408" width="1000" height="55" rx="10" fill="rgba(249,115,22,0.06)" stroke="rgba(249,115,22,0.25)" stroke-width="1"/>
  <text x="600" y="422" text-anchor="middle" fill="rgba(249,115,22,0.5)" font-size="10" font-weight="700" letter-spacing="2">INFRASTRUCTURE</text>
  <g class="brain-node" data-id="gpu-nodes"><rect x="285" y="432" width="110" height="28" rx="14" fill="rgba(249,115,22,0.1)" stroke="rgba(249,115,22,0.4)" stroke-width="1"/><text x="340" y="450" text-anchor="middle" fill="#f97316" font-size="11">GPU Nodes</text></g>
  <g class="brain-node" data-id="backends"><rect x="415" y="432" width="110" height="28" rx="14" fill="rgba(249,115,22,0.1)" stroke="rgba(249,115,22,0.4)" stroke-width="1"/><text x="470" y="450" text-anchor="middle" fill="#f97316" font-size="11">Backends</text></g>
  <g class="brain-node" data-id="postgresql"><rect x="545" y="432" width="110" height="28" rx="14" fill="rgba(249,115,22,0.1)" stroke="rgba(249,115,22,0.4)" stroke-width="1"/><text x="600" y="450" text-anchor="middle" fill="#f97316" font-size="11">PostgreSQL</text></g>
  <g class="brain-node" data-id="redis-nats"><rect x="675" y="432" width="110" height="28" rx="14" fill="rgba(249,115,22,0.1)" stroke="rgba(249,115,22,0.4)" stroke-width="1"/><text x="730" y="450" text-anchor="middle" fill="#f97316" font-size="11">Redis + NATS</text></g>
  <g class="brain-node" data-id="tei"><rect x="805" y="432" width="110" height="28" rx="14" fill="rgba(249,115,22,0.1)" stroke="rgba(249,115,22,0.4)" stroke-width="1"/><text x="860" y="450" text-anchor="middle" fill="#f97316" font-size="11">TEI</text></g>

  <g class="brain-loop" data-id="loop-heartbeat">
    <path d="M 1100,435 C 1185,435 1185,78 1100,78" fill="none" stroke="#f97316" stroke-width="2.5" stroke-opacity="0.6" stroke-dasharray="6,4" marker-end="url(#brain-ah-orange)"/>
    <circle cx="1100" cy="435" r="5" fill="#f97316" stroke="#f97316" stroke-width="1.5" opacity="0.9"/>
    <circle cx="1100" cy="78" r="5" fill="#10b981" stroke="#f97316" stroke-width="1.5" opacity="0.9"/>
    <text x="1175" y="260" fill="#f97316" font-size="9" font-weight="600" letter-spacing="1" transform="rotate(-90,1175,260)" text-anchor="middle">HEARTBEAT 30s</text>
    <circle r="3" fill="#f97316" opacity="0.9" filter="url(#brain-pglow)"><animateMotion dur="3s" repeatCount="indefinite" path="M 1100,435 C 1185,435 1185,78 1100,78"/></circle>
  </g>
  <g class="brain-loop" data-id="loop-feedback">
    <path d="M 100,56 C 15,56 15,345 100,345" fill="none" stroke="#38bdf8" stroke-width="2.5" stroke-opacity="0.6" stroke-dasharray="6,4" marker-end="url(#brain-ah-blue)"/>
    <circle cx="100" cy="56" r="5" fill="#38bdf8" stroke="#38bdf8" stroke-width="1.5" opacity="0.9"/>
    <circle cx="100" cy="345" r="5" fill="#ef4444" stroke="#38bdf8" stroke-width="1.5" opacity="0.9"/>
    <text x="-12" y="200" fill="#38bdf8" font-size="9" font-weight="600" letter-spacing="1" transform="rotate(-90,-12,200)" text-anchor="middle">USER FEEDBACK</text>
    <circle r="3" fill="#38bdf8" opacity="0.9" filter="url(#brain-pglow)"><animateMotion dur="5s" repeatCount="indefinite" path="M 100,56 C 15,56 15,345 100,345"/></circle>
  </g>
  <g class="brain-loop" data-id="loop-hofstadter">
    <path d="M 1100,325 C 1150,325 1150,360 1100,360" fill="none" stroke="#f59e0b" stroke-width="2.5" stroke-opacity="0.7" marker-end="url(#brain-ah-amber)"/>
    <path d="M 1100,347 C 1130,347 1130,338 1100,338" fill="none" stroke="#f59e0b" stroke-width="2.5" stroke-opacity="0.7" marker-end="url(#brain-ah-amber)"/>
    <text x="1140" y="345" fill="#f59e0b" font-size="9" font-weight="600" letter-spacing="1" transform="rotate(-90,1140,345)" text-anchor="middle">ADAPTATION</text>
    <circle r="3.5" fill="#f59e0b" opacity="0.9" filter="url(#brain-pglow)"><animateMotion dur="9s" repeatCount="indefinite" path="M 1100,325 C 1150,325 1150,360 1100,360"/></circle>
  </g>
  <g class="brain-loop" data-id="loop-ga">
    <path d="M 100,235 C 62,235 62,310 100,310" fill="none" stroke="#84cc16" stroke-width="2.5" stroke-opacity="0.7" marker-end="url(#brain-ah-lime)"/>
    <path d="M 100,325 C 45,325 45,222 100,222" fill="none" stroke="#84cc16" stroke-width="2.5" stroke-opacity="0.7" marker-end="url(#brain-ah-lime)"/>
    <text x="40" y="275" fill="#84cc16" font-size="9" font-weight="600" letter-spacing="1" transform="rotate(-90,40,275)" text-anchor="middle">TUNING</text>
    <circle r="3.5" fill="#84cc16" opacity="0.9" filter="url(#brain-pglow)"><animateMotion dur="7s" repeatCount="indefinite" path="M 100,235 C 62,235 62,310 100,310"/></circle>
  </g>
  <g class="brain-node" data-id="composite-score">
    <circle cx="1150" cy="32" r="22" fill="rgba(245,158,11,0.1)" stroke="rgba(245,158,11,0.5)" stroke-width="2"/>
    <text x="1150" y="27" text-anchor="middle" fill="#f59e0b" font-size="7" font-weight="700" letter-spacing="0.5">COMPOSITE</text>
    <text x="1150" y="41" text-anchor="middle" fill="#f59e0b" font-size="11" font-weight="600" id="brain-score-val">—</text>
  </g>
</svg>`;

export const BRAIN_LEGEND: LegendItem[] = [
  { label: 'Interface', color: '#5f8fd0' },
  { label: 'System 1', color: '#5aa66e' },
  { label: 'Long-term Memory', color: '#3f9fb0' },
  { label: 'System 2', color: '#9a7bc8' },
  { label: 'Identity & Evolution', color: '#e0a24a' },
  { label: 'Infrastructure', color: '#9a8f80' },
];

export const BRAIN_INFO: Record<string, NodeInfo> = {
  dashboard: { t: 'Dashboard', l: 'Interface', c: '#38bdf8', d: 'Single-page web UI with real-time WebSocket updates.', f: 'gateway/index.html', k: 'API Gateway, CoordinatorAgent' },
  'api-gateway': { t: 'API Gateway', l: 'Interface', c: '#38bdf8', d: 'FastAPI on port 8080. Central HTTP and WebSocket entry point.', f: 'gateway/app.py', k: 'CoordinatorAgent, All subsystems' },
  channels: { t: 'Channels', l: 'Interface', c: '#38bdf8', d: 'Bidirectional messaging bridges: Google Chat, Telegram, WhatsApp.', f: 'channels/', k: 'CoordinatorAgent, HeartbeatScheduler' },
  'mcp-hub': { t: 'MCP Hub', l: 'Interface', c: '#38bdf8', d: 'MCP doors on the gateway (/mcp/operator, /mcp/user) exposing the tool registry.', f: 'mcp_local.rs, mcp_external.rs', k: 'Claude Code, CoordinatorAgent' },
  'backend-mgr': { t: 'BackendManager', l: 'System 1 · Automatic', c: '#10b981', d: 'On-demand inference backend lifecycle. Auto-start on best node, circuit breakers, idle auto-stop.', f: 'cluster/backend_manager.py', k: 'Inference Backends, GPU Nodes' },
  security: { t: 'Security', l: 'System 1 · Automatic', c: '#10b981', d: 'Input sanitisation, rate limiting, risk-based tool execution gating.', f: 'gateway/security.py', k: 'API Gateway, Tool Execution' },
  cache: { t: 'Redis Cache', l: 'System 1 · Automatic', c: '#10b981', d: 'LLM response caching, session state, hot data. <5ms lookup.', f: 'Redis service', k: 'CoordinatorAgent' },
  'recall-memory': { t: 'Recall Memory', l: 'System 1 · Automatic', c: '#10b981', d: 'Episodic memory of past conversations and graph walks, archived and searched by similarity.', f: 'trellion/live/recall/', k: 'CoordinatorAgent' },
  conversations: { t: 'Conversation Memory', l: 'Long-term · Episodic', c: '#06b6d4', d: 'Chat history in PostgreSQL with pgvector 384-dim embeddings.', f: 'memory/conversation_store.py', k: 'CoordinatorAgent, Embedding Worker' },
  pageindex: { t: 'PageIndex KB', l: 'Long-term · Semantic', c: '#06b6d4', d: 'Document knowledge base. PDFs, Markdown, HTML to chunks to embeddings.', f: 'memory/rag_integration.py', k: 'Knowledge Graph, Embedding Worker' },
  'knowledge-graph': { t: 'Knowledge Graph', l: 'Long-term · Semantic', c: '#06b6d4', d: 'Entities + typed relationship edges extracted from documents.', f: 'memory/graph_extraction.py', k: 'PageIndex KB, CoordinatorAgent' },
  coordinator: { t: 'CoordinatorAgent', l: 'System 2 · Deliberate', c: '#ec4899', d: 'Core executive function. Local LLM agentic loop: resolve backend, call LLM, execute tools, iterate.', f: 'gateway/coordinator.py', k: 'All tools, Memory, Self-Identity' },
  tools: { t: 'Tool Execution', l: 'System 2 · Deliberate', c: '#ec4899', d: '25+ MCP tools: inference, cluster ops, RAG, graph search, web search.', f: 'tools/, mcp/tools.py', k: 'CoordinatorAgent, MCP Hub' },
  'claude-code': { t: 'Claude Code', l: 'System 2 · Deliberate', c: '#ec4899', d: 'Delegated coding tool invoked via pai_coding_task.', f: 'gateway/coding_tool.py', k: 'CoordinatorAgent, MCP Hub' },
  'multi-agent': { t: 'Multi-Agent', l: 'System 2 · Deliberate', c: '#ec4899', d: 'Role-based orchestrator: researcher, coder, reviewer agents.', f: 'agents/', k: 'CoordinatorAgent, Tool Execution' },
  autonomy: { t: 'AutonomyEngine', l: 'System 2 · Deliberate', c: '#ec4899', d: 'Executive control over memory health. 9 locations on 1-2 min cycles.', f: 'cluster/autonomy.py', k: 'BackendManager, Node Heartbeat' },
  scheduler: { t: 'HeartbeatScheduler', l: 'System 2 · Deliberate', c: '#ec4899', d: 'Cron-based scheduled tasks with results sent to channels.', f: 'gateway/heartbeat.py', k: 'Channels, CoordinatorAgent' },
  'static-identity': { t: 'Static Identity', l: 'Identity', c: '#ef4444', d: 'Immutable core persona in prompts/coordinator.md.', f: 'prompts/coordinator.md', k: 'CoordinatorAgent' },
  'self-config': { t: 'Self-Identity Config', l: 'Identity & Evolution', c: '#ef4444', d: 'Mutable personality layer: tone, verbosity, operating principles, preferences.\n\nThis is the memory that evolves — the evolve add-on writes here.', f: 'config.py (SelfConfig)', k: 'Hofstadter Loop, Genetic Algorithm, CoordinatorAgent' },
  'gpu-nodes': { t: 'GPU Nodes', l: 'Infrastructure', c: '#f97316', d: 'Physical compute. Tier 1 (vLLM), Tier 2 (llama.cpp), Tier 3 (CPU).', f: 'cluster/node.py', k: 'Node Heartbeat, BackendManager' },
  backends: { t: 'Inference Backends', l: 'Infrastructure', c: '#f97316', d: 'Docker-managed LLM serving: vLLM, Ollama, llama.cpp.', f: 'Docker containers', k: 'GPU Nodes, BackendManager' },
  postgresql: { t: 'PostgreSQL', l: 'Infrastructure', c: '#f97316', d: 'Primary shared memory store with pgvector extensions.', f: 'db/models.py', k: 'All memory systems' },
  'redis-nats': { t: 'Redis + NATS', l: 'Infrastructure', c: '#f97316', d: 'Redis: distributed cache. NATS JetStream: message bus.', f: 'Docker services', k: 'Cache, Job queue' },
  tei: { t: 'TEI', l: 'Infrastructure', c: '#f97316', d: 'HuggingFace Text Embeddings Inference on GPU nodes.', f: 'Docker service', k: 'PageIndex KB, Conversation Memory' },
  // Loops
  'loop-heartbeat': { t: 'Node Heartbeat', l: 'Infrastructure → System 1', c: '#f97316', d: 'The pulse of the cluster. Every 30s nodes report load, VRAM, running backends, GPU temp.' },
  'loop-feedback': { t: 'User Feedback', l: 'Interface → Identity', c: '#38bdf8', d: 'Human judgment shapes identity over time. Thumbs up/down and corrections become training signal.' },
};

// Licensed lanes: rendered through the slot registry (features/addons/slots.ts),
// never described here.
export const BRAIN_SLOT_NODES: Record<string, SlotNode> = {
  'hofstadter-loop': { slotId: 'evolve:hofstadter', l: 'Identity & Evolution', c: '#f59e0b' },
  'genetic-algorithm': { slotId: 'evolve:ga', l: 'Identity & Evolution', c: '#84cc16' },
  'composite-score': { slotId: 'evolve:composite-score', l: 'Cross-layer Metric', c: '#f59e0b' },
  'loop-hofstadter': { slotId: 'evolve:hofstadter-cycle', l: 'Identity ↔ System 2', c: '#f59e0b' },
  'loop-ga': { slotId: 'evolve:ga-cycle', l: 'Identity ↔ System 2', c: '#84cc16' },
};
