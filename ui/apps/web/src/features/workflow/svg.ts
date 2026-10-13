// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 PersonifAI LLC

import type { NodeInfo, LegendItem } from '@/features/_diagram/DiagramView';
import type { SlotNode } from '@/features/addons/slots';

// Base swim-lane data-flow diagram (ported verbatim from the legacy workflow.html)
// with the pro "Lane 4 — Evolution" overlay integrated. Legacy palette kept here;
// reskin() remaps to Slate at render. viewBox extended to fit Lane 4.
export const WORKFLOW_SVG = `
<svg id="workflow-svg" viewBox="0 0 1400 720" xmlns="http://www.w3.org/2000/svg">
  <defs>
    <filter id="wf-glow"><feGaussianBlur stdDeviation="3" result="b"/><feMerge><feMergeNode in="b"/><feMergeNode in="SourceGraphic"/></feMerge></filter>
    <filter id="wf-pglow"><feGaussianBlur stdDeviation="4" result="b"/><feMerge><feMergeNode in="b"/><feMergeNode in="SourceGraphic"/></feMerge></filter>
    <marker id="wf-ah-blue" viewBox="0 0 10 10" refX="9" refY="5" markerWidth="6" markerHeight="6" orient="auto-start-reverse"><path d="M0 0L10 5L0 10z" fill="#38bdf8"/></marker>
    <marker id="wf-ah-cyan" viewBox="0 0 10 10" refX="9" refY="5" markerWidth="6" markerHeight="6" orient="auto-start-reverse"><path d="M0 0L10 5L0 10z" fill="#06b6d4"/></marker>
    <marker id="wf-ah-green" viewBox="0 0 10 10" refX="9" refY="5" markerWidth="6" markerHeight="6" orient="auto-start-reverse"><path d="M0 0L10 5L0 10z" fill="#10b981"/></marker>
    <marker id="wf-ah-muted" viewBox="0 0 10 10" refX="9" refY="5" markerWidth="6" markerHeight="6" orient="auto-start-reverse"><path d="M0 0L10 5L0 10z" fill="#94a3b8"/></marker>
    <marker id="wf-ah-amber" viewBox="0 0 10 10" refX="9" refY="5" markerWidth="6" markerHeight="6" orient="auto-start-reverse"><path d="M0 0L10 5L0 10z" fill="#f59e0b"/></marker>
    <marker id="wf-ah-red" viewBox="0 0 10 10" refX="9" refY="5" markerWidth="6" markerHeight="6" orient="auto-start-reverse"><path d="M0 0L10 5L0 10z" fill="#ef4444"/></marker>
  </defs>

  <rect x="10" y="10" width="1380" height="155" rx="10" fill="rgba(56,189,248,0.04)" stroke="rgba(56,189,248,0.25)" stroke-width="1.5"/>
  <text x="24" y="30" fill="rgba(56,189,248,0.6)" font-size="11" font-weight="700" letter-spacing="2">REQUEST PROCESSING</text>
  <text x="24" y="42" font-size="8" fill="rgba(56,189,248,0.35)">POST /api/inference &bull; WS /ws/coordinator</text>

  <g class="wf-node" data-id="user"><rect x="60" y="60" width="100" height="32" rx="16" fill="rgba(56,189,248,0.1)" stroke="rgba(56,189,248,0.4)" stroke-width="1"/><text x="110" y="80" text-anchor="middle" fill="#38bdf8" font-size="11">User</text></g>
  <g class="wf-node" data-id="api-gw"><rect x="210" y="60" width="120" height="32" rx="16" fill="rgba(56,189,248,0.1)" stroke="rgba(56,189,248,0.4)" stroke-width="1"/><text x="270" y="80" text-anchor="middle" fill="#38bdf8" font-size="11">API Gateway</text></g>
  <g class="wf-node" data-id="inject-ctx"><rect x="385" y="60" width="130" height="32" rx="16" fill="rgba(56,189,248,0.1)" stroke="rgba(56,189,248,0.4)" stroke-width="1"/><text x="450" y="80" text-anchor="middle" fill="#38bdf8" font-size="11">_inject_context()</text></g>
  <g class="wf-node" data-id="agentic-loop"><rect x="575" y="55" width="140" height="42" rx="16" fill="rgba(56,189,248,0.12)" stroke="rgba(56,189,248,0.5)" stroke-width="1.5"/><text x="645" y="73" text-anchor="middle" fill="#38bdf8" font-size="11" font-weight="600">_agentic_loop()</text><text x="645" y="86" text-anchor="middle" fill="rgba(56,189,248,0.5)" font-size="8">max 15 iterations</text></g>
  <g class="wf-node" data-id="call-llm"><rect x="775" y="60" width="120" height="32" rx="16" fill="rgba(56,189,248,0.1)" stroke="rgba(56,189,248,0.4)" stroke-width="1"/><text x="835" y="80" text-anchor="middle" fill="#38bdf8" font-size="11">_call_llm()</text></g>
  <g class="wf-node" data-id="exec-tools"><rect x="950" y="60" width="155" height="32" rx="16" fill="rgba(56,189,248,0.1)" stroke="rgba(56,189,248,0.4)" stroke-width="1"/><text x="1027" y="80" text-anchor="middle" fill="#38bdf8" font-size="11">_execute_tools()</text></g>
  <g class="wf-node" data-id="record-ex"><rect x="1160" y="60" width="145" height="32" rx="16" fill="rgba(56,189,248,0.1)" stroke="rgba(56,189,248,0.4)" stroke-width="1"/><text x="1232" y="80" text-anchor="middle" fill="#38bdf8" font-size="11">_record_exchange()</text></g>

  <line x1="160" y1="76" x2="208" y2="76" stroke="#38bdf8" stroke-width="1.5" stroke-opacity="0.6" marker-end="url(#wf-ah-blue)"/>
  <line x1="330" y1="76" x2="383" y2="76" stroke="#38bdf8" stroke-width="1.5" stroke-opacity="0.6" marker-end="url(#wf-ah-blue)"/>
  <line x1="515" y1="76" x2="573" y2="76" stroke="#38bdf8" stroke-width="1.5" stroke-opacity="0.6" marker-end="url(#wf-ah-blue)"/>
  <line x1="715" y1="76" x2="773" y2="76" stroke="#38bdf8" stroke-width="1.5" stroke-opacity="0.6" marker-end="url(#wf-ah-blue)"/>
  <line x1="895" y1="76" x2="948" y2="76" stroke="#38bdf8" stroke-width="1.5" stroke-opacity="0.6" marker-end="url(#wf-ah-blue)"/>
  <line x1="1105" y1="76" x2="1158" y2="76" stroke="#38bdf8" stroke-width="1.5" stroke-opacity="0.6" marker-end="url(#wf-ah-blue)"/>

  <path d="M 1027,92 L 1027,120 Q 1027,130 1017,130 L 655,130 Q 645,130 645,120 L 645,97" fill="none" stroke="#38bdf8" stroke-width="1.5" stroke-opacity="0.5" marker-end="url(#wf-ah-blue)"/>
  <text x="830" y="142" text-anchor="middle" fill="rgba(56,189,248,0.6)" font-size="8" font-weight="600">tool results</text>
  <text x="830" y="152" fill="var(--muted-foreground)" font-size="8" font-style="italic">iterate until done</text>
  <text x="835" y="56" text-anchor="middle" fill="var(--muted-foreground)" font-size="8" font-style="italic">~1-5s per call</text>
  <text x="1232" y="56" text-anchor="middle" fill="var(--muted-foreground)" font-size="8" font-style="italic">persist to DB</text>
  <circle r="3" fill="#38bdf8" opacity="0.9" filter="url(#wf-pglow)"><animateMotion dur="8s" repeatCount="indefinite" path="M 110,76 L 270,76 L 450,76 L 645,76 L 835,76 L 1027,76 L 1232,76"/></circle>

  <rect x="10" y="180" width="1380" height="155" rx="10" fill="rgba(6,182,212,0.04)" stroke="rgba(6,182,212,0.25)" stroke-width="1.5"/>
  <text x="24" y="200" fill="rgba(6,182,212,0.6)" font-size="11" font-weight="700" letter-spacing="2">MEMORY PIPELINE</text>
  <text x="24" y="212" font-size="8" fill="rgba(6,182,212,0.35)">PageIndex KB &bull; Conversation Memory &bull; Knowledge Graph</text>

  <text x="80" y="240" font-size="8" fill="rgba(6,182,212,0.4)" font-weight="600">VECTOR PATH</text>
  <g class="wf-node" data-id="ingest"><rect x="60" y="248" width="110" height="32" rx="16" fill="rgba(6,182,212,0.1)" stroke="rgba(6,182,212,0.4)" stroke-width="1"/><text x="115" y="268" text-anchor="middle" fill="#06b6d4" font-size="11">ingest_file()</text></g>
  <g class="wf-node" data-id="chunker"><rect x="225" y="248" width="100" height="32" rx="16" fill="rgba(6,182,212,0.1)" stroke="rgba(6,182,212,0.4)" stroke-width="1"/><text x="275" y="268" text-anchor="middle" fill="#06b6d4" font-size="11">Chunker</text></g>
  <g class="wf-node" data-id="tei-embed"><rect x="380" y="248" width="110" height="32" rx="16" fill="rgba(6,182,212,0.1)" stroke="rgba(6,182,212,0.4)" stroke-width="1"/><text x="435" y="268" text-anchor="middle" fill="#06b6d4" font-size="11">TEI Embed</text></g>
  <g class="wf-node" data-id="pgvector"><rect x="545" y="248" width="110" height="32" rx="16" fill="rgba(6,182,212,0.1)" stroke="rgba(6,182,212,0.4)" stroke-width="1"/><text x="600" y="268" text-anchor="middle" fill="#06b6d4" font-size="11">pgvector</text></g>

  <line x1="170" y1="264" x2="223" y2="264" stroke="#06b6d4" stroke-width="1.5" stroke-opacity="0.6" marker-end="url(#wf-ah-cyan)"/>
  <line x1="325" y1="264" x2="378" y2="264" stroke="#06b6d4" stroke-width="1.5" stroke-opacity="0.6" marker-end="url(#wf-ah-cyan)"/>
  <line x1="490" y1="264" x2="543" y2="264" stroke="#06b6d4" stroke-width="1.5" stroke-opacity="0.6" marker-end="url(#wf-ah-cyan)"/>

  <text x="80" y="296" font-size="8" fill="rgba(6,182,212,0.4)" font-weight="600">GRAPH PATH</text>
  <g class="wf-node" data-id="entity-extract"><rect x="225" y="302" width="140" height="32" rx="16" fill="rgba(6,182,212,0.1)" stroke="rgba(6,182,212,0.4)" stroke-width="1"/><text x="295" y="322" text-anchor="middle" fill="#06b6d4" font-size="11">EntityExtractor</text></g>
  <g class="wf-node" data-id="graph-build"><rect x="420" y="302" width="130" height="32" rx="16" fill="rgba(6,182,212,0.1)" stroke="rgba(6,182,212,0.4)" stroke-width="1"/><text x="485" y="322" text-anchor="middle" fill="#06b6d4" font-size="11">GraphBuilder</text></g>
  <g class="wf-node" data-id="knowledge-graph"><rect x="605" y="302" width="140" height="32" rx="16" fill="rgba(6,182,212,0.1)" stroke="rgba(6,182,212,0.4)" stroke-width="1"/><text x="675" y="322" text-anchor="middle" fill="#06b6d4" font-size="11">Knowledge Graph</text></g>

  <path d="M 170,264 L 190,264 Q 200,264 200,274 L 200,318 Q 200,322 210,322 L 223,322" fill="none" stroke="#06b6d4" stroke-width="1.5" stroke-opacity="0.5" marker-end="url(#wf-ah-cyan)"/>
  <line x1="365" y1="318" x2="418" y2="318" stroke="#06b6d4" stroke-width="1.5" stroke-opacity="0.6" marker-end="url(#wf-ah-cyan)"/>
  <line x1="550" y1="318" x2="603" y2="318" stroke="#06b6d4" stroke-width="1.5" stroke-opacity="0.6" marker-end="url(#wf-ah-cyan)"/>

  <g class="wf-node" data-id="conv-store"><rect x="830" y="248" width="155" height="32" rx="16" fill="rgba(6,182,212,0.1)" stroke="rgba(6,182,212,0.4)" stroke-width="1"/><text x="907" y="268" text-anchor="middle" fill="#06b6d4" font-size="11">ConversationStore</text></g>
  <g class="wf-node" data-id="embed-worker"><rect x="1040" y="248" width="150" height="32" rx="16" fill="rgba(6,182,212,0.1)" stroke="rgba(6,182,212,0.4)" stroke-width="1"/><text x="1115" y="268" text-anchor="middle" fill="#06b6d4" font-size="11">EmbeddingWorker</text></g>
  <g class="wf-node" data-id="intelli-router"><rect x="1240" y="248" width="140" height="32" rx="16" fill="rgba(6,182,212,0.1)" stroke="rgba(6,182,212,0.4)" stroke-width="1"/><text x="1310" y="268" text-anchor="middle" fill="#06b6d4" font-size="11">IntelligentRouter</text></g>

  <line x1="985" y1="264" x2="1038" y2="264" stroke="#06b6d4" stroke-width="1.5" stroke-opacity="0.6" marker-end="url(#wf-ah-cyan)"/>
  <path d="M 1240,264 L 670,264 Q 660,264 660,274 L 660,297" fill="none" stroke="#06b6d4" stroke-width="1" stroke-opacity="0.35" stroke-dasharray="4,3"/>
  <circle r="3" fill="#06b6d4" opacity="0.9" filter="url(#wf-pglow)"><animateMotion dur="7s" repeatCount="indefinite" path="M 115,264 L 275,264 L 435,264 L 600,264"/></circle>

  <rect x="10" y="350" width="1380" height="170" rx="10" fill="rgba(16,185,129,0.04)" stroke="rgba(16,185,129,0.25)" stroke-width="1.5"/>
  <text x="24" y="370" fill="rgba(16,185,129,0.6)" font-size="11" font-weight="700" letter-spacing="2">SELF-REGULATION</text>
  <text x="24" y="382" font-size="8" fill="rgba(16,185,129,0.35)">Node Heartbeat &bull; AutonomyEngine &bull; HeartbeatScheduler</text>

  <text x="80" y="400" font-size="8" fill="rgba(16,185,129,0.4)" font-weight="600">HEARTBEAT</text>
  <g class="wf-node" data-id="node-agent"><rect x="60" y="406" width="115" height="32" rx="16" fill="rgba(16,185,129,0.1)" stroke="rgba(16,185,129,0.4)" stroke-width="1"/><text x="117" y="426" text-anchor="middle" fill="#10b981" font-size="11">Node Agent</text></g>
  <g class="wf-node" data-id="node-registry"><rect x="245" y="406" width="130" height="32" rx="16" fill="rgba(16,185,129,0.1)" stroke="rgba(16,185,129,0.4)" stroke-width="1"/><text x="310" y="426" text-anchor="middle" fill="#10b981" font-size="11">NodeRegistry</text></g>
  <g class="wf-node" data-id="node-status"><rect x="445" y="406" width="140" height="32" rx="16" fill="rgba(16,185,129,0.1)" stroke="rgba(16,185,129,0.4)" stroke-width="1"/><text x="515" y="426" text-anchor="middle" fill="#10b981" font-size="11">Status Update</text></g>
  <g class="wf-node" data-id="backend-mgr2"><rect x="655" y="406" width="140" height="32" rx="16" fill="rgba(16,185,129,0.1)" stroke="rgba(16,185,129,0.4)" stroke-width="1"/><text x="725" y="426" text-anchor="middle" fill="#10b981" font-size="11">BackendManager</text></g>

  <line x1="175" y1="422" x2="243" y2="422" stroke="#10b981" stroke-width="1.5" stroke-opacity="0.6" marker-end="url(#wf-ah-green)"/>
  <line x1="375" y1="422" x2="443" y2="422" stroke="#10b981" stroke-width="1.5" stroke-opacity="0.6" marker-end="url(#wf-ah-green)"/>
  <line x1="585" y1="422" x2="653" y2="422" stroke="#10b981" stroke-width="1.5" stroke-opacity="0.6" marker-end="url(#wf-ah-green)"/>

  <text x="80" y="454" font-size="8" fill="rgba(16,185,129,0.4)" font-weight="600">AUTONOMY</text>
  <g class="wf-node" data-id="autonomy-eng"><rect x="60" y="460" width="140" height="32" rx="16" fill="rgba(16,185,129,0.1)" stroke="rgba(16,185,129,0.4)" stroke-width="1"/><text x="130" y="480" text-anchor="middle" fill="#10b981" font-size="11">AutonomyEngine</text></g>
  <g class="wf-node" data-id="conditions"><rect x="265" y="460" width="130" height="32" rx="16" fill="rgba(16,185,129,0.1)" stroke="rgba(16,185,129,0.4)" stroke-width="1"/><text x="330" y="480" text-anchor="middle" fill="#10b981" font-size="11">Check Conditions</text></g>
  <g class="wf-node" data-id="actions"><rect x="465" y="460" width="130" height="32" rx="16" fill="rgba(16,185,129,0.1)" stroke="rgba(16,185,129,0.4)" stroke-width="1"/><text x="530" y="480" text-anchor="middle" fill="#10b981" font-size="11">Fire Actions</text></g>

  <line x1="200" y1="476" x2="263" y2="476" stroke="#10b981" stroke-width="1.5" stroke-opacity="0.6" marker-end="url(#wf-ah-green)"/>
  <line x1="395" y1="476" x2="463" y2="476" stroke="#10b981" stroke-width="1.5" stroke-opacity="0.6" marker-end="url(#wf-ah-green)"/>

  <text x="80" y="506" font-size="8" fill="rgba(16,185,129,0.4)" font-weight="600">SCHEDULER</text>
  <g class="wf-node" data-id="hb-sched"><rect x="60" y="510" width="155" height="32" rx="16" fill="rgba(16,185,129,0.1)" stroke="rgba(16,185,129,0.4)" stroke-width="1"/><text x="137" y="530" text-anchor="middle" fill="#10b981" font-size="11">HeartbeatScheduler</text></g>
  <g class="wf-node" data-id="exec-action"><rect x="270" y="510" width="140" height="32" rx="16" fill="rgba(16,185,129,0.1)" stroke="rgba(16,185,129,0.4)" stroke-width="1"/><text x="340" y="530" text-anchor="middle" fill="#10b981" font-size="11">Execute Action</text></g>
  <g class="wf-node" data-id="notify"><rect x="465" y="510" width="130" height="32" rx="16" fill="rgba(16,185,129,0.1)" stroke="rgba(16,185,129,0.4)" stroke-width="1"/><text x="530" y="530" text-anchor="middle" fill="#10b981" font-size="11">Notify Channel</text></g>

  <line x1="215" y1="526" x2="268" y2="526" stroke="#10b981" stroke-width="1.5" stroke-opacity="0.6" marker-end="url(#wf-ah-green)"/>
  <line x1="410" y1="526" x2="463" y2="526" stroke="#10b981" stroke-width="1.5" stroke-opacity="0.6" marker-end="url(#wf-ah-green)"/>
  <circle r="3" fill="#10b981" opacity="0.9" filter="url(#wf-pglow)"><animateMotion dur="4s" repeatCount="indefinite" path="M 117,422 L 310,422 L 515,422 L 725,422"/></circle>

  <path d="M 620,248 L 620,174 Q 620,170 610,170 L 465,170 Q 460,170 460,166 L 460,94" fill="none" stroke="#06b6d4" stroke-width="1.3" stroke-opacity="0.55" stroke-dasharray="5,3" marker-end="url(#wf-ah-cyan)"/>
  <text x="555" y="168" fill="#06b6d4" font-size="8" font-weight="600">RAG retrieval (docs + graph)</text>
  <path d="M 907,248 L 907,176 Q 907,172 897,172 L 448,172 Q 443,172 443,168 L 443,94" fill="none" stroke="#06b6d4" stroke-width="1.3" stroke-opacity="0.45" stroke-dasharray="5,3" marker-end="url(#wf-ah-cyan)"/>
  <text x="680" y="176" fill="#06b6d4" font-size="8" font-weight="600">conversation memory (384-dim)</text>
  <path d="M 1232,92 L 1232,140 Q 1232,150 1222,150 L 917,150 Q 907,150 907,160 L 907,246" fill="none" stroke="#94a3b8" stroke-width="1.2" stroke-opacity="0.5" stroke-dasharray="5,3" marker-end="url(#wf-ah-muted)"/>
  <text x="1065" y="148" fill="#94a3b8" font-size="8" font-weight="600">persist memory (write)</text>
  <path d="M 725,406 L 725,365 Q 725,355 735,355 L 825,355 Q 835,355 835,345 L 835,94" fill="none" stroke="#10b981" stroke-width="1.2" stroke-opacity="0.5" stroke-dasharray="5,3" marker-end="url(#wf-ah-green)"/>
  <text x="790" y="345" fill="#10b981" font-size="8" font-weight="600">backend URL for inference</text>
  <path d="M 530,460 L 530,355 Q 530,345 520,345 L 200,345 Q 190,345 190,335 L 190,282" fill="none" stroke="#10b981" stroke-width="1.2" stroke-opacity="0.45" stroke-dasharray="5,3" marker-end="url(#wf-ah-green)"/>
  <text x="365" y="342" fill="#10b981" font-size="8" font-weight="600">submit jobs (embed + graph + ingest)</text>

  <rect x="10" y="535" width="1380" height="170" rx="10" fill="rgba(239,68,68,0.04)" stroke="rgba(239,68,68,0.25)" stroke-width="1.5"/>
  <text x="24" y="555" class="wf-lane-label" fill="rgba(239,68,68,0.6)">EVOLUTION</text>
  <text x="24" y="567" font-size="8" fill="rgba(239,68,68,0.35)">Self-Evolution &bull; Self-Identity</text>
  <text x="80" y="585" font-size="8" fill="rgba(245,158,11,0.4)" font-weight="600">SELF-TUNING</text>
  <g class="wf-node" data-id="composite"><rect x="60" y="590" width="140" height="32" rx="16" fill="rgba(245,158,11,0.12)" stroke="rgba(245,158,11,0.45)" stroke-width="1"/><text x="130" y="610" text-anchor="middle" fill="#f59e0b" font-size="11">composite_score</text></g>
  <g class="wf-node" data-id="observe"><rect x="250" y="590" width="100" height="32" rx="16" fill="rgba(245,158,11,0.1)" stroke="rgba(245,158,11,0.4)" stroke-width="1"/><text x="300" y="610" text-anchor="middle" fill="#f59e0b" font-size="11">OBSERVE</text></g>
  <g class="wf-node" data-id="verify"><rect x="395" y="590" width="90" height="32" rx="16" fill="rgba(245,158,11,0.1)" stroke="rgba(245,158,11,0.4)" stroke-width="1"/><text x="440" y="610" text-anchor="middle" fill="#f59e0b" font-size="11">VERIFY</text></g>
  <g class="wf-node" data-id="reflect"><rect x="530" y="590" width="95" height="32" rx="16" fill="rgba(245,158,11,0.1)" stroke="rgba(245,158,11,0.4)" stroke-width="1"/><text x="577" y="610" text-anchor="middle" fill="#f59e0b" font-size="11">REFLECT</text></g>
  <g class="wf-node" data-id="adapt"><rect x="670" y="590" width="90" height="32" rx="16" fill="rgba(245,158,11,0.1)" stroke="rgba(245,158,11,0.4)" stroke-width="1"/><text x="715" y="610" text-anchor="middle" fill="#f59e0b" font-size="11">ADAPT</text></g>
  <line x1="200" y1="606" x2="248" y2="606" stroke="#f59e0b" stroke-width="1.5" stroke-opacity="0.6" marker-end="url(#wf-ah-amber)"/>
  <line x1="350" y1="606" x2="393" y2="606" stroke="#f59e0b" stroke-width="1.5" stroke-opacity="0.6" marker-end="url(#wf-ah-amber)"/>
  <line x1="485" y1="606" x2="528" y2="606" stroke="#f59e0b" stroke-width="1.5" stroke-opacity="0.6" marker-end="url(#wf-ah-amber)"/>
  <line x1="625" y1="606" x2="668" y2="606" stroke="#f59e0b" stroke-width="1.5" stroke-opacity="0.6" marker-end="url(#wf-ah-amber)"/>
  <text x="300" y="586" text-anchor="middle" class="wf-timing">metrics</text>
  <text x="440" y="586" text-anchor="middle" class="wf-timing">check</text>
  <text x="577" y="586" text-anchor="middle" class="wf-timing">review</text>
  <text x="715" y="586" text-anchor="middle" class="wf-timing">adjust</text>
  <text x="830" y="585" font-size="8" fill="rgba(132,204,22,0.4)" font-weight="600">PROMPT EVOLUTION</text>
  <g class="wf-node" data-id="ga-trial"><rect x="830" y="590" width="140" height="32" rx="16" fill="rgba(132,204,22,0.12)" stroke="rgba(132,204,22,0.45)" stroke-width="1"/><text x="900" y="610" text-anchor="middle" fill="#84cc16" font-size="11">record_trial()</text></g>
  <g class="wf-node" data-id="ga-evolve"><rect x="1020" y="590" width="120" height="32" rx="16" fill="rgba(132,204,22,0.12)" stroke="rgba(132,204,22,0.45)" stroke-width="1"/><text x="1080" y="610" text-anchor="middle" fill="#84cc16" font-size="11">evolve</text></g>
  <g class="wf-node" data-id="ga-apply"><rect x="1190" y="590" width="140" height="32" rx="16" fill="rgba(132,204,22,0.12)" stroke="rgba(132,204,22,0.45)" stroke-width="1"/><text x="1260" y="610" text-anchor="middle" fill="#84cc16" font-size="11">apply</text></g>
  <line x1="760" y1="606" x2="828" y2="606" stroke="#84cc16" stroke-width="1.5" stroke-opacity="0.5" marker-end="url(#wf-ah-muted)"/>
  <line x1="970" y1="606" x2="1018" y2="606" stroke="#84cc16" stroke-width="1.5" stroke-opacity="0.6" marker-end="url(#wf-ah-muted)"/>
  <line x1="1140" y1="606" x2="1188" y2="606" stroke="#84cc16" stroke-width="1.5" stroke-opacity="0.6" marker-end="url(#wf-ah-muted)"/>
  <text x="900" y="586" text-anchor="middle" class="wf-timing">score candidates</text>
  <text x="1080" y="586" text-anchor="middle" class="wf-timing">select best</text>
  <text x="1260" y="586" text-anchor="middle" class="wf-timing">update config</text>
  <text x="993" y="630" text-anchor="middle" class="wf-timing">candidate configurations</text>
  <path d="M 715,622 L 715,666 Q 715,676 705,676 L 140,676 Q 130,676 130,666 L 130,622" fill="none" stroke="#f59e0b" stroke-width="1.5" stroke-opacity="0.4" stroke-dasharray="6,3" marker-end="url(#wf-ah-amber)"/>
  <text x="420" y="690" text-anchor="middle" class="wf-arrow-label" fill="rgba(245,158,11,0.6)">periodic cycle</text>
  <text x="420" y="700" class="wf-timing">slow cycle, spans many hours</text>
  <circle r="3" fill="#f59e0b" opacity="0.9" filter="url(#wf-pglow)"><animateMotion dur="10s" repeatCount="indefinite" path="M 130,606 L 300,606 L 440,606 L 577,606 L 715,606 L 900,606 L 1080,606 L 1260,606"/></circle>
  <path d="M 58,76 Q 45,76 45,86 L 45,530 Q 45,540 55,540 L 120,540 Q 130,540 130,550 L 130,588" fill="none" stroke="rgba(245,158,11,0.5)" stroke-width="1.2" stroke-dasharray="5,3" marker-end="url(#wf-ah-amber)"/>
  <text x="38" y="340" class="wf-arrow-label" fill="#f59e0b" transform="rotate(-90,38,340)" text-anchor="middle">metrics feed → composite_score</text>
  <path d="M 1330,590 L 1330,545 Q 1330,535 1340,535 L 1365,535 Q 1375,535 1375,525 L 1375,86 Q 1375,76 1365,76 L 717,76" fill="none" stroke="rgba(239,68,68,0.5)" stroke-width="1.2" stroke-dasharray="5,3" marker-end="url(#wf-ah-red)"/>
  <text x="1368" y="310" class="wf-arrow-label" fill="#ef4444" transform="rotate(90,1368,310)" text-anchor="middle">SelfConfig → _agentic_loop()</text>
</svg>`;

export const WORKFLOW_LEGEND: LegendItem[] = [
  { label: 'Request Processing', color: '#5f8fd0' },
  { label: 'Memory Pipeline', color: '#3f9fb0' },
  { label: 'Self-Regulation', color: '#5aa66e' },
  { label: 'Evolution · Loop', color: '#d9a441' },
  { label: 'Evolution · Tuning', color: '#8a9a4e' },
];

export const WORKFLOW_INFO: Record<string, NodeInfo> = {
  user: { t: 'User Input', l: 'Lane 1 · Request Processing', c: '#38bdf8', d: 'Requests arrive from: Dashboard, REST API, WebSocket, Google Chat, Telegram, WhatsApp.', f: 'gateway-rust/src/routes/, src/channels/' },
  'api-gw': { t: 'API Gateway', l: 'Lane 1 · Request Processing', c: '#38bdf8', d: 'Rust (axum) on port 8080. Routes requests to CoordinatorAgent, validates auth, applies rate limiting.', f: 'gateway-rust/src/routes/' },
  'inject-ctx': { t: '_inject_context()', l: 'Lane 1 · Request Processing', c: '#38bdf8', d: 'Enriches user message with memory and RAG context from four sources: conversation history, PageIndex docs, knowledge graph, and recall memory.', f: 'gateway-rust/src/coordinator/' },
  'agentic-loop': { t: '_agentic_loop()', l: 'Lane 1 · Request Processing', c: '#38bdf8', d: 'Core reasoning loop. Calls LLM, checks for tool calls, executes them, feeds results back. Up to 15 iterations.', f: 'gateway-rust/src/coordinator/' },
  'call-llm': { t: '_call_llm()', l: 'Lane 1 · Request Processing', c: '#38bdf8', d: 'Sends messages to resolved backend. Local models use OpenAI-compatible /v1/chat/completions.', f: 'gateway-rust/src/coordinator/' },
  'exec-tools': { t: '_execute_tools()', l: 'Lane 1 · Request Processing', c: '#38bdf8', d: 'Dispatches tool calls. PAI tools go through MCP tools handler. External tools go through MCP hub.', f: 'gateway-rust/src/coordinator/, src/tools.rs' },
  'record-ex': { t: '_record_exchange()', l: 'Lane 1 · Request Processing', c: '#38bdf8', d: 'Persists completed exchange to conversation memory with metadata.', f: 'gateway-rust/src/coordinator/' },
  ingest: { t: 'ingest_file()', l: 'Lane 2 · Memory Pipeline', c: '#06b6d4', d: 'Entry point for document ingestion. Detects file type, extracts content, feeds into vector and graph paths.', f: 'trellion live/rag_integration.py' },
  chunker: { t: 'Chunker', l: 'Lane 2 · Memory Pipeline', c: '#06b6d4', d: 'Splits text into overlapping chunks of ~512 tokens with sentence-boundary-aware splitting.', f: 'trellion live/embedding_worker.py' },
  'tei-embed': { t: 'TEI Embed', l: 'Lane 2 · Memory Pipeline', c: '#06b6d4', d: 'Embedding backend on GPU nodes. Trellion reaches it through the gateway embed endpoint, not TEI directly.', f: 'trellion live/embedding_worker.py' },
  pgvector: { t: 'pgvector Store', l: 'Lane 2 · Memory Pipeline', c: '#06b6d4', d: 'PostgreSQL with pgvector. Stores document (768-dim) and conversation (384-dim) embeddings.', f: 'trellion live/pgvector_store.py' },
  'entity-extract': { t: 'EntityExtractor', l: 'Lane 2 · Memory Pipeline', c: '#06b6d4', d: 'LLM-based entity extraction from document chunks.', f: 'trellion live/graph_builder.py' },
  'graph-build': { t: 'GraphBuilder', l: 'Lane 2 · Memory Pipeline', c: '#06b6d4', d: 'Constructs typed relationship edges between entities.', f: 'trellion live/graph_builder.py' },
  'knowledge-graph': { t: 'Knowledge Graph', l: 'Lane 2 · Memory Pipeline', c: '#06b6d4', d: 'Neo4j-style graph in PostgreSQL. Entities as nodes, typed relationships as edges.', f: 'trellion live/graph_builder.py' },
  'conv-store': { t: 'ConversationStore', l: 'Lane 2 · Memory Pipeline', c: '#06b6d4', d: 'PostgreSQL-backed chat history with 384-dim semantic search.', f: 'trellion live/conversation_store.py' },
  'embed-worker': { t: 'EmbeddingWorker', l: 'Lane 2 · Memory Pipeline', c: '#06b6d4', d: 'Async background worker that batches unembedded items and sends to TEI.', f: 'trellion live/embedding_worker.py' },
  'intelli-router': { t: 'IntelligentRouter', l: 'Lane 2 · Memory Pipeline', c: '#06b6d4', d: 'Query-time routing for memory retrieval. Chooses best search strategy.', f: 'trellion live/intelligent_router.py' },
  'node-agent': { t: 'Node Agent', l: 'Lane 3 · Self-Regulation', c: '#10b981', d: 'Runs on each GPU worker node. Reports metrics every 30s.', f: 'node-agent-go/' },
  'node-registry': { t: 'NodeRegistry', l: 'Lane 3 · Self-Regulation', c: '#10b981', d: 'In-memory registry of all known nodes with status and capabilities.', f: 'gateway-rust/src/routes/cluster.rs' },
  'node-status': { t: 'Status Update', l: 'Lane 3 · Self-Regulation', c: '#10b981', d: 'Status transitions: ONLINE, BUSY, OFFLINE, QUARANTINED.', f: 'gateway-rust/src/routes/cluster.rs' },
  'backend-mgr2': { t: 'BackendManager', l: 'Lane 3 · Self-Regulation', c: '#10b981', d: 'Manages inference backend lifecycle. Auto-start, idle scaledown, optimal node selection.', f: 'gateway-rust/src/routes/cluster.rs' },
  'autonomy-eng': { t: 'AutonomyEngine', l: 'Lane 3 · Self-Regulation', c: '#10b981', d: 'Patrols 9 locations on 1-2 min cycles. Condition-based self-healing.', f: 'gateway-rust/src/autonomy_loop.rs' },
  conditions: { t: 'Check Conditions', l: 'Lane 3 · Self-Regulation', c: '#10b981', d: 'Each location defines a condition function returning True/False.', f: 'gateway-rust/src/autonomy_evaluators.rs' },
  actions: { t: 'Fire Actions', l: 'Lane 3 · Self-Regulation', c: '#10b981', d: '9 action types: start/stop/scale backends, quarantine nodes, submit jobs, ingest, alert, log.', f: 'gateway-rust/src/autonomy_loop.rs' },
  'hb-sched': { t: 'HeartbeatScheduler', l: 'Lane 3 · Self-Regulation', c: '#10b981', d: 'Cron-based scheduled tasks with results sent to messaging channels.', f: 'gateway-rust/src/heartbeat_loop.rs' },
  'exec-action': { t: 'Execute Action', l: 'Lane 3 · Self-Regulation', c: '#10b981', d: 'Dispatches scheduled task to appropriate subsystem.', f: 'gateway-rust/src/heartbeat_loop.rs' },
  notify: { t: 'Notify Channel', l: 'Lane 3 · Self-Regulation', c: '#10b981', d: 'Sends task results to Google Chat, Telegram, or WhatsApp.', f: 'gateway-rust/src/heartbeat_loop.rs, src/channels/' },
};

// Licensed lanes: rendered through the slot registry (features/addons/slots.ts),
// never described here.
export const WORKFLOW_SLOT_NODES: Record<string, SlotNode> = {
  'composite': { slotId: 'evolve:composite-metric', l: 'Lane 4 · Evolution', c: '#f59e0b' },
  'observe': { slotId: 'evolve:observe', l: 'Lane 4 · Evolution Loop', c: '#f59e0b' },
  'verify': { slotId: 'evolve:verify', l: 'Lane 4 · Evolution Loop', c: '#f59e0b' },
  'reflect': { slotId: 'evolve:reflect', l: 'Lane 4 · Evolution Loop', c: '#f59e0b' },
  'adapt': { slotId: 'evolve:adapt', l: 'Lane 4 · Evolution Loop', c: '#f59e0b' },
  'ga-trial': { slotId: 'evolve:ga-score', l: 'Lane 4 · Parameter Tuning', c: '#84cc16' },
  'ga-evolve': { slotId: 'evolve:ga-evolve', l: 'Lane 4 · Parameter Tuning', c: '#84cc16' },
  'ga-apply': { slotId: 'evolve:ga-apply', l: 'Lane 4 · Parameter Tuning', c: '#84cc16' },
};
