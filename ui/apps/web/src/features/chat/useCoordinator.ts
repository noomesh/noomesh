// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 PersonifAI LLC

import { useEffect, useRef, useState } from 'react';
import { createSocket, type ManagedSocket } from '@metis/api';
import { tokenStore, refreshToken } from '@/lib/client';

/** Per-turn accounting from the `done` frame (ws-protocol.md §2B). */
export interface TurnStats {
  elapsedSeconds?: number;
  tokensIn?: number;
  tokensOut?: number;
  tokensPerSec?: number;
  iterations?: number;
  toolCalls?: number;
  cached?: boolean;
}

/**
 * An exec-approval raised by a tool call in this turn. `approval_request`
 * opens it; a decision (ours or anyone's) or the window elapsing closes it.
 */
export interface ApprovalRun {
  id: string;
  tool: string;
  /**
   * What the call was invoked with, lifted from the preceding `tool_call`
   * frame. Approving `pai_execute_command` without seeing the command is not
   * a decision — it is a rubber stamp.
   */
  args?: string;
  /** Decision window in seconds, from the frame. */
  windowSecs: number;
  /** Epoch ms the window closes — computed on arrival so the card can count down. */
  deadline: number;
  status: 'pending' | 'approved' | 'denied' | 'expired';
  /** The gateway's own wording, from `approval_outcome`. */
  outcome?: string;
}

/** One tool invocation within a turn: `tool_call` opens it, `tool_result` closes it. */
export interface ToolRun {
  name: string;
  /** Single-line summary of the call's `arguments`, for the approval card. */
  args?: string;
  status: 'running' | 'ok' | 'fail';
  /** Server-reported duration from `tool_result`. */
  elapsedMs?: number;
  /** Truncated output, or the error message when it failed. */
  detail?: string;
}

export interface ChatTurn {
  role: 'you' | 'metis';
  text: string;
  /** Reasoning tokens only — tool calls live in `tools`, not in here. */
  thinking?: string;
  /** How long reasoning ran, measured client-side from first thinking token. */
  thinkMs?: number;
  tools?: ToolRun[];
  approvals?: ApprovalRun[];
  streaming?: boolean;
  error?: boolean;
  stats?: TurnStats;
  /**
   * The node harness running this turn, from `harness_dispatched`. Absent
   * when the gateway answers itself. A vendor CLI turn can take minutes; the
   * console names who is answering so the wait is not silent (i233).
   */
  answering?: { node: string; kind?: string };
}

export type ChatStatus = 'connecting' | 'live' | 'closed' | 'auth';

/** What answered the last turn, from the `metadata` frame. */
export interface Serving {
  model?: string;
  backend?: string;
}

// The subset of coordinator server→client frames we render (see
// contracts/ws/ws-protocol.md §2B).
interface CoordFrame {
  type: string;
  text?: string;
  conversation_id?: string;
  name?: string;
  tool?: string;
  model?: string;
  backend?: string;
  // `harness_dispatched` — the node running the turn and its harness kind.
  node?: string;
  kind?: string;
  // `tool_call` — the call's parameters, as an object or a JSON string.
  arguments?: unknown;
  // `approval_request` / `approval_outcome`.
  request_id?: string;
  window_secs?: number;
  // `tool_result`.
  success?: boolean;
  output?: string;
  error?: string | null;
  elapsed_ms?: number;
  // `done` accounting.
  iterations?: number;
  tool_calls?: number;
  elapsed_seconds?: number;
  tokens_in?: number;
  tokens_out?: number;
  cached?: boolean;
}

/**
 * Read the `done` frame's accounting.
 *
 * The field names are the gateway's (`agent_loop.rs`), not OpenAI's — the old
 * stats footer was blank because it read `output_tokens`/`prompt_tokens`, which
 * this frame never carries. See ws-protocol.md §4.
 */
function readStats(f: CoordFrame): TurnStats | undefined {
  const stats: TurnStats = {
    elapsedSeconds: f.elapsed_seconds,
    tokensIn: f.tokens_in,
    tokensOut: f.tokens_out,
    iterations: f.iterations,
    toolCalls: f.tool_calls,
    cached: f.cached,
  };
  if (f.tokens_out && f.elapsed_seconds) {
    stats.tokensPerSec = Math.round(f.tokens_out / f.elapsed_seconds);
  }
  // Cache hits and the error path carry almost nothing — don't render an
  // empty footer for them.
  const meaningful =
    stats.elapsedSeconds || stats.tokensOut || stats.tokensIn || stats.toolCalls || stats.cached;
  return meaningful ? stats : undefined;
}

/** Keys whose values are never worth showing and sometimes harmful to show. */
const SECRET_KEY = /(token|secret|password|passwd|api[-_]?key|authorization|credential)/i;

const ARGS_MAX = 240;

/**
 * One readable line describing what a tool was called with.
 *
 * The gateway sends `arguments` on `tool_call` unredacted, so this is also the
 * masking point for the in-conversation surface. It is deliberately shallow:
 * the operator needs to read the command they are approving, and a card that
 * redacts the interesting part is no better than one showing nothing. The
 * out-of-band Security queue is a different problem — that one has no
 * `tool_call` frame to draw on and needs the gateway to redact server-side
 *.
 */
export function summariseArgs(raw: unknown): string | undefined {
  if (raw === undefined || raw === null) return undefined;
  let v: unknown = raw;
  // Some backends hand tool arguments back as a JSON string, not an object.
  if (typeof v === 'string') {
    const s = v.trim();
    if (!s) return undefined;
    if (!s.startsWith('{')) return clip(flatten(s));
    try {
      v = JSON.parse(s);
    } catch {
      return clip(flatten(s));
    }
  }
  if (typeof v !== 'object') return clip(flatten(String(v)));

  const parts: string[] = [];
  for (const [k, val] of Object.entries(v as Record<string, unknown>)) {
    if (val === undefined || val === null || val === '') continue;
    if (SECRET_KEY.test(k)) {
      parts.push(`${k}=•••`);
      continue;
    }
    const text = typeof val === 'string' ? val : JSON.stringify(val);
    parts.push(`${k}=${flatten(text)}`);
  }
  // Two spaces between pairs: `key=value` pairs run together illegibly with
  // one, and a comma reads as part of the value for shell commands.
  return parts.length ? clip(parts.join('  ')) : undefined;
}

/** Collapse newlines and runs of whitespace so one value stays on one line. */
function flatten(s: string): string {
  return s.replace(/\s+/g, ' ').trim();
}

function clip(s: string): string {
  return s.length > ARGS_MAX ? `${s.slice(0, ARGS_MAX - 1)}…` : s;
}

const GREETING: ChatTurn = {
  role: 'metis',
  text: 'Connected to the mesh. Ask me about the cluster, or anything else.',
};

/** Live coordinator chat over /ws/coordinator via @metis/api's reconnecting socket. */
export function useCoordinator() {
  const [messages, setMessages] = useState<ChatTurn[]>([GREETING]);
  const [status, setStatus] = useState<ChatStatus>('connecting');
  // `busy` gates the composer while a turn streams; the ref is the synchronous
  // guard so a burst of send() calls can't append a second in-flight turn (which
  // would misroute the first turn's content/done frames into the wrong bubble).
  const [busy, setBusy] = useState(false);
  const busyRef = useRef(false);
  const mark = (v: boolean) => {
    busyRef.current = v;
    setBusy(v);
  };
  const sockRef = useRef<ManagedSocket | null>(null);
  const convId = useRef<string | null>(null);
  const [serving, setServing] = useState<Serving | null>(null);
  // Wall-clock start of the current turn's reasoning phase; null once closed.
  const thinkStart = useRef<number | null>(null);

  /**
   * Close the reasoning phase and return how long it ran, or undefined if it
   * was already closed.
   *
   * Must be called OUTSIDE a state updater: this mutates, and StrictMode
   * double-invokes updaters — the second pass would see a cleared ref and drop
   * the measurement.
   */
  const takeThinkMs = (): number | undefined => {
    if (thinkStart.current === null) return undefined;
    const ms = Date.now() - thinkStart.current;
    thinkStart.current = null;
    return ms;
  };

  // Patch the last (streaming assistant) message in place as tokens arrive.
  const patchLast = (fn: (t: ChatTurn) => Partial<ChatTurn>) =>
    setMessages((ms) => {
      if (!ms.length) return ms;
      const copy = ms.slice();
      const last = copy[copy.length - 1]!;
      copy[copy.length - 1] = { ...last, ...fn(last) };
      return copy;
    });

  useEffect(() => {
    const sock = createSocket('/ws/coordinator', {
      baseUrl: '',
      getToken: () => (tokenStore.get() as string | null) ?? '',
      refreshToken,
      reconnectMs: 1000,
      onOpen: () => setStatus('live'),
      onClose: () => {
        setStatus('closed');
        // A turn interrupted by a drop would otherwise stream forever.
        if (busyRef.current) {
          patchLast(() => ({ streaming: false }));
          mark(false);
        }
      },
      onAuthFail: () => setStatus('auth'),
      onMessage: (data) => {
        const f = data as CoordFrame;
        switch (f.type) {
          case 'metadata':
            if (f.conversation_id) convId.current = f.conversation_id;
            if (f.model || f.backend) setServing({ model: f.model, backend: f.backend });
            break;
          case 'harness_dispatched':
            if (f.node) patchLast(() => ({ answering: { node: f.node!, kind: f.kind || undefined } }));
            break;
          case 'thinking':
            if (thinkStart.current === null) thinkStart.current = Date.now();
            patchLast((l) => ({ thinking: (l.thinking ?? '') + (f.text ?? '') }));
            break;
          case 'content': {
            // First content token ends the reasoning phase — that's what the
            // "Thought for Ns" label reports.
            const ms = takeThinkMs();
            patchLast((l) => ({
              text: l.text + (f.text ?? ''),
              ...(ms === undefined ? {} : { thinkMs: ms }),
            }));
            break;
          }
          case 'content_clear':
            patchLast(() => ({ text: '' }));
            break;
          // `arguments` rides along on this frame. Keeping it is what lets an
          // approval card say *what* it is gating — see `approval_request`.
          case 'tool_call':
            patchLast((l) => ({
              tools: [
                ...(l.tools ?? []),
                { name: f.name ?? 'tool', status: 'running', args: summariseArgs(f.arguments) },
              ],
            }));
            break;
          // An agent asking permission. Dropping this frame — which is what
          // the client did before — means the operator is never asked, the
          // turn silently stalls, and the request expires unseen.
          case 'approval_request': {
            const id = f.request_id ?? '';
            if (!id) break;
            const windowSecs = Number(f.window_secs) || 300;
            const tool = f.tool ?? f.name ?? 'tool';
            patchLast((l) => {
              if ((l.approvals ?? []).some((a) => a.id === id)) return {};
              // The gateway emits `tool_call` (with arguments) immediately
              // before running the tool, and the approval gate lives inside
              // that run — so the still-open run of this tool is the call being
              // gated, and its arguments are what the operator is deciding on.
              const open = (l.tools ?? []).filter((t) => t.name === tool && t.status === 'running');
              return {
                approvals: [
                  ...(l.approvals ?? []),
                  {
                    id,
                    tool,
                    args: open[open.length - 1]?.args,
                    windowSecs,
                    deadline: Date.now() + windowSecs * 1000,
                    status: 'pending' as const,
                  },
                ],
              };
            });
            break;
          }

          // The gateway's verdict — but ONLY for the negative case. Verified
          // against gateway-rust: `notify_exec_outcome` is called from exactly
          // two sites (tools.rs), both in the rejection branch — ApprovalDenied
          // and ApprovalTimeout. An *approved* call emits no outcome frame at
          // all; it just runs. So this frame always means "it did NOT run", and
          // marking it `approved` (which we did) inverted the one signal the
          // gateway added specifically so a human never has to trust the model's
          // own account of whether a blocked action happened.
          //
          // No `request_id` on this frame — but the tool call blocks awaiting
          // the decision, so only one approval is ever outstanding per turn.
          case 'approval_outcome':
            patchLast((l) => ({
              approvals: (l.approvals ?? []).map((a) =>
                a.status === 'pending' ? { ...a, status: 'denied' as const, outcome: f.text } : a,
              ),
            }));
            break;

          // Closes the matching open run. Without this the frame is dropped and
          // a tool appears to run forever (ws-protocol.md §2B).
          case 'tool_result':
            patchLast((l) => {
              const tools = [...(l.tools ?? [])];
              // Last matching run wins — the same tool can be called twice.
              for (let i = tools.length - 1; i >= 0; i--) {
                const t = tools[i]!;
                if (t.name === f.name && t.status === 'running') {
                  tools[i] = {
                    ...t,
                    status: f.success ? 'ok' : 'fail',
                    elapsedMs: f.elapsed_ms,
                    detail: f.success ? f.output : (f.error ?? f.output ?? 'failed'),
                  };
                  break;
                }
              }
              // An APPROVED call produces no outcome frame — the gateway just
              // runs it — so this is the only signal that closes the card in the
              // yes case. Without it the card sat pending until its countdown
              // elapsed and then claimed "expired — it did not run" about an
              // action that had, in fact, just run.
              //
              // The card records the DECISION, not whether the tool then
              // worked: the gate is what the operator answered. Only a
              // `Security:`-prefixed error means the call was blocked (that is
              // the gateway's own wording for a rejected call); any other
              // failure means it was allowed to run and failed on its own.
              const blocked = !f.success && (f.error ?? '').startsWith('Security:');
              const approvals = (l.approvals ?? []).map((a) =>
                a.status === 'pending' && a.tool === f.name
                  ? { ...a, status: (blocked ? 'denied' : 'approved') as ApprovalRun['status'] }
                  : a,
              );
              return { tools, approvals };
            });
            break;
          case 'done': {
            // A turn can end without ever emitting content (tool-only, or an
            // error path), so close the reasoning phase here too.
            const ms = takeThinkMs();
            patchLast(() => ({
              streaming: false,
              stats: readStats(f),
              ...(ms === undefined ? {} : { thinkMs: ms }),
            }));
            mark(false);
            break;
          }
          case 'error':
            // Only a turn in flight owns the last bubble. An error with no turn
            // running (an older gateway's "Token expired" before its 4401 close)
            // was appended to a long-finished reply, once per token lifetime.
            if (!busyRef.current) break;
            patchLast((l) => ({
              text: (l.text ? `${l.text}\n` : '') + `⚠ ${f.text ?? 'error'}`,
              streaming: false,
              error: true,
            }));
            mark(false);
            break;
          default:
            break; // keepalive / unknown
        }
      },
    });
    sockRef.current = sock;
    return () => sock.close();
  }, []);

  /** `model` is the user's override from the picker; null/'' means let the gateway choose. */
  const send = (prompt: string, model?: string | null) => {
    const p = prompt.trim();
    if (!p || busyRef.current) return;
    const sock = sockRef.current;
    if (!sock || sock.readyState !== WebSocket.OPEN) {
      // Not connected — surface it instead of appending a bubble that would
      // stream forever behind a dropped frame.
      setMessages((ms) => [
        ...ms,
        { role: 'you', text: p },
        { role: 'metis', text: '⚠ Not connected to the mesh — reconnecting. Try again in a moment.', error: true },
      ]);
      return;
    }
    const ok = sock.send({
      prompt: p,
      conversation_id: convId.current,
      enable_thinking: true,
      model: model || null,
    });
    if (!ok) return;
    thinkStart.current = null;
    mark(true);
    setMessages((ms) => [...ms, { role: 'you', text: p }, { role: 'metis', text: '', streaming: true }]);
  };

  // Only allow a send when connected and no turn is mid-stream.
  const canSend = status === 'live' && !busy;

  return { messages, status, send, canSend, busy, serving };
}
