// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 PersonifAI LLC

// @vitest-environment jsdom
import { describe, it, expect, beforeEach, afterEach, vi } from 'vitest';
import { renderHook, act } from '@testing-library/react';

// Hoisted so the vi.mock factory can reference the fake socket without a TDZ error.
const H = vi.hoisted(() => {
  const sock: {
    socket: null;
    readyState: number;
    send: ReturnType<typeof vi.fn>;
    reconnectNow: () => void;
    close: () => void;
  } = {
    socket: null,
    readyState: 0, // CONNECTING
    send: vi.fn(function (this: void) {
      return false;
    }),
    reconnectNow: () => {},
    close: () => {},
  };
  sock.send = vi.fn(() => sock.readyState === 1); // true only when OPEN
  return { sock, opts: { current: {} as Record<string, (arg?: unknown) => void> } };
});

vi.mock('@metis/api', () => ({
  createSocket: (_path: string, opts: Record<string, (arg?: unknown) => void>) => {
    H.opts.current = opts;
    return H.sock;
  },
}));
vi.mock('@/lib/client', () => ({
  tokenStore: { get: () => 'tok' },
  refreshToken: async () => 'tok',
}));

import { useCoordinator, TURN_IDLE_MS, type ChatTurn } from './useCoordinator';

const last = (arr: ChatTurn[]) => arr[arr.length - 1]!;
const fire = (name: string, arg?: unknown) => act(() => H.opts.current[name]?.(arg));

beforeEach(() => {
  H.sock.readyState = 0;
  H.sock.send.mockClear();
  H.opts.current = {};
});

afterEach(() => {
  vi.useRealTimers();
  vi.restoreAllMocks();
});

describe('useCoordinator', () => {
  it('send() while the socket is not OPEN surfaces an error, no streaming bubble, no send (finding #1)', () => {
    const { result } = renderHook(() => useCoordinator());
    act(() => result.current.send('hi'));

    const msgs = result.current.messages;
    expect(msgs[msgs.length - 2]).toMatchObject({ role: 'you', text: 'hi' });
    expect(last(msgs)).toMatchObject({ role: 'metis', error: true });
    expect(last(msgs).streaming).toBeFalsy();
    expect(H.sock.send).not.toHaveBeenCalled();
  });

  it('send() when OPEN appends a streaming turn, sends, and disables the composer', () => {
    const { result } = renderHook(() => useCoordinator());
    fire('onOpen', {}); // status → live
    H.sock.readyState = 1; // OPEN
    act(() => result.current.send('hello'));

    expect(H.sock.send).toHaveBeenCalledTimes(1);
    expect(last(result.current.messages)).toMatchObject({ role: 'metis', text: '', streaming: true });
    expect(result.current.canSend).toBe(false);
  });

  it('ignores a second send while a turn is still streaming (finding #4)', () => {
    const { result } = renderHook(() => useCoordinator());
    fire('onOpen', {});
    H.sock.readyState = 1;
    act(() => result.current.send('first'));
    const count = result.current.messages.length;

    act(() => result.current.send('second')); // busy → ignored
    expect(result.current.messages.length).toBe(count);
    expect(H.sock.send).toHaveBeenCalledTimes(1);
  });

  it('streams content into the last turn and clears busy on done', () => {
    const { result } = renderHook(() => useCoordinator());
    fire('onOpen', {});
    H.sock.readyState = 1;
    act(() => result.current.send('q'));

    fire('onMessage', { type: 'content', text: 'Hi ' });
    fire('onMessage', { type: 'content', text: 'there' });
    expect(last(result.current.messages).text).toBe('Hi there');

    fire('onMessage', { type: 'done' });
    expect(last(result.current.messages).streaming).toBeFalsy();
    expect(result.current.canSend).toBe(true);
  });

  it('reads the done frame accounting onto the finished turn', () => {
    const { result } = renderHook(() => useCoordinator());
    fire('onOpen', {});
    H.sock.readyState = 1;
    act(() => result.current.send('q'));

    fire('onMessage', {
      type: 'done',
      iterations: 2,
      tool_calls: 1,
      elapsed_seconds: 4.0,
      tokens_in: 812,
      tokens_out: 240,
      engine: 'rust',
    });

    // Gateway field names, not OpenAI's — reading output_tokens/prompt_tokens
    // is what left the old stats footer blank (ws-protocol.md §4).
    expect(last(result.current.messages).stats).toMatchObject({
      elapsedSeconds: 4.0,
      tokensIn: 812,
      tokensOut: 240,
      iterations: 2,
      toolCalls: 1,
      tokensPerSec: 60,
    });
  });

  it('leaves stats undefined when done carries no accounting (error path)', () => {
    const { result } = renderHook(() => useCoordinator());
    fire('onOpen', {});
    H.sock.readyState = 1;
    act(() => result.current.send('q'));

    fire('onMessage', { type: 'done', iterations: 0, error: 'boom' });
    expect(last(result.current.messages).stats).toBeUndefined();
  });

  it('sends the picked model, and null when left on auto', () => {
    const { result } = renderHook(() => useCoordinator());
    fire('onOpen', {});
    H.sock.readyState = 1;

    act(() => result.current.send('q', 'org/qwen-32b'));
    expect(H.sock.send).toHaveBeenLastCalledWith(
      expect.objectContaining({ model: 'org/qwen-32b' }),
    );

    fire('onMessage', { type: 'done' });
    act(() => result.current.send('q2', ''));
    expect(H.sock.send).toHaveBeenLastCalledWith(expect.objectContaining({ model: null }));
  });

  it('separates tool runs from reasoning, and closes them on tool_result', () => {
    const { result } = renderHook(() => useCoordinator());
    fire('onOpen', {});
    H.sock.readyState = 1;
    act(() => result.current.send('q'));

    fire('onMessage', { type: 'thinking', text: 'pondering' });
    fire('onMessage', { type: 'tool_call', name: 'pai_cluster_status' });
    expect(last(result.current.messages).tools).toEqual([
      { name: 'pai_cluster_status', status: 'running' },
    ]);
    // Tool calls must not leak into the reasoning text.
    expect(last(result.current.messages).thinking).toBe('pondering');

    fire('onMessage', {
      type: 'tool_result',
      name: 'pai_cluster_status',
      success: true,
      output: '{"nodes":3}',
      elapsed_ms: 412,
    });
    expect(last(result.current.messages).tools).toEqual([
      { name: 'pai_cluster_status', status: 'ok', elapsedMs: 412, detail: '{"nodes":3}' },
    ]);
  });

  it('names the node and harness kind answering a dispatched turn', () => {
    const { result } = renderHook(() => useCoordinator());
    fire('onOpen', {});
    H.sock.readyState = 1;
    act(() => result.current.send('q'));
    expect(last(result.current.messages).answering).toBeUndefined();

    fire('onMessage', { type: 'harness_dispatched', node: 'mcmini', kind: 'copilot' });
    expect(last(result.current.messages).answering).toEqual({ node: 'mcmini', kind: 'copilot' });

    // A harness older than 0.6.13 names no kind: the node alone.
    fire('onMessage', { type: 'done' });
    act(() => result.current.send('q2'));
    fire('onMessage', { type: 'harness_dispatched', node: 'awolf' });
    expect(last(result.current.messages).answering).toEqual({ node: 'awolf', kind: undefined });
  });

  it('collects a vendor harness working text apart from the answer', () => {
    const { result } = renderHook(() => useCoordinator());
    fire('onOpen', {});
    H.sock.readyState = 1;
    act(() => result.current.send('q'));

    fire('onMessage', { type: 'working', text: 'Let me check ' });
    fire('onMessage', { type: 'working', text: 'the nodes.' });
    fire('onMessage', { type: 'content', text: 'Three nodes.' });
    const m = last(result.current.messages);
    expect(m.working).toBe('Let me check the nodes.');
    expect(m.text).toBe('Three nodes.');
  });

  it('a failed tool_result carries the error as its detail', () => {
    const { result } = renderHook(() => useCoordinator());
    fire('onOpen', {});
    H.sock.readyState = 1;
    act(() => result.current.send('q'));

    fire('onMessage', { type: 'tool_call', name: 'boom' });
    fire('onMessage', { type: 'tool_result', name: 'boom', success: false, error: 'exploded' });
    expect(last(result.current.messages).tools?.[0]).toMatchObject({
      status: 'fail',
      detail: 'exploded',
    });
  });

  it('measures the reasoning phase and closes it on first content', () => {
    const { result } = renderHook(() => useCoordinator());
    fire('onOpen', {});
    H.sock.readyState = 1;
    act(() => result.current.send('q'));

    fire('onMessage', { type: 'thinking', text: 'hm' });
    expect(last(result.current.messages).thinkMs).toBeUndefined();

    fire('onMessage', { type: 'content', text: 'answer' });
    // Measured, not inferred — StrictMode double-invokes updaters, so the
    // stamping must survive being rendered twice.
    expect(typeof last(result.current.messages).thinkMs).toBe('number');

    const first = last(result.current.messages).thinkMs;
    fire('onMessage', { type: 'content', text: ' more' });
    expect(last(result.current.messages).thinkMs).toBe(first);
  });

  it('raises an approval card when the agent asks permission', () => {
    const { result } = renderHook(() => useCoordinator());
    fire('onOpen', {});
    H.sock.readyState = 1;
    act(() => result.current.send('delete the cache'));

    fire('onMessage', {
      type: 'approval_request',
      request_id: 'apr_1',
      tool: 'pai_execute_command',
      window_secs: 120,
    });

    const a = last(result.current.messages).approvals?.[0];
    expect(a).toMatchObject({ id: 'apr_1', tool: 'pai_execute_command', windowSecs: 120, status: 'pending' });
    // Dropping this frame is what made the console silently not ask.
    expect(a!.deadline).toBeGreaterThan(Date.now());
  });

  it('ignores a repeated approval_request for the same id', () => {
    const { result } = renderHook(() => useCoordinator());
    fire('onOpen', {});
    H.sock.readyState = 1;
    act(() => result.current.send('q'));

    const frame = { type: 'approval_request', request_id: 'apr_1', tool: 't', window_secs: 60 };
    fire('onMessage', frame);
    fire('onMessage', frame); // a reconnect can replay it
    expect(last(result.current.messages).approvals).toHaveLength(1);
  });

  it('ignores an approval_request with no request_id — there is nothing to answer', () => {
    const { result } = renderHook(() => useCoordinator());
    fire('onOpen', {});
    H.sock.readyState = 1;
    act(() => result.current.send('q'));

    fire('onMessage', { type: 'approval_request', tool: 'x' });
    expect(last(result.current.messages).approvals ?? []).toHaveLength(0);
  });

  // gateway-rust calls notify_exec_outcome from exactly two sites (tools.rs),
  // both in the rejection branch. There is no such thing as an approval_outcome
  // meaning "yes" — an approved call simply runs. This test previously asserted
  // the opposite, using an "Approved — running…" text the gateway never sends.
  it('treats approval_outcome as a refusal — the frame only ever means it did NOT run', () => {
    const { result } = renderHook(() => useCoordinator());
    fire('onOpen', {});
    H.sock.readyState = 1;
    act(() => result.current.send('q'));

    fire('onMessage', { type: 'approval_request', request_id: 'apr_1', tool: 't', window_secs: 60 });
    // Verbatim shape of the denial notice.
    fire('onMessage', { type: 'approval_outcome', text: '🚫 t was NOT executed — denied by alice.' });

    expect(last(result.current.messages).approvals?.[0]).toMatchObject({
      status: 'denied',
      outcome: '🚫 t was NOT executed — denied by alice.',
    });
  });

  it('treats an expiry notice as a refusal too', () => {
    const { result } = renderHook(() => useCoordinator());
    fire('onOpen', {});
    H.sock.readyState = 1;
    act(() => result.current.send('q'));

    fire('onMessage', { type: 'approval_request', request_id: 'apr_1', tool: 't', window_secs: 60 });
    fire('onMessage', {
      type: 'approval_outcome',
      text: '⏳ t was NOT executed — the approval request expired after 60s with no decision.',
    });

    expect(last(result.current.messages).approvals?.[0]?.status).toBe('denied');
  });

  // The yes case has no frame of its own, so tool_result is the only thing that
  // can close the card. Without this the card counted down and then claimed
  // "expired — it did not run" about an action that had just run.
  it('closes the card as approved when the gated tool actually runs', () => {
    const { result } = renderHook(() => useCoordinator());
    fire('onOpen', {});
    H.sock.readyState = 1;
    act(() => result.current.send('q'));

    fire('onMessage', { type: 'tool_call', name: 'pai_execute_command', arguments: { command: 'ls' } });
    fire('onMessage', { type: 'approval_request', request_id: 'apr_1', tool: 'pai_execute_command', window_secs: 60 });
    fire('onMessage', { type: 'tool_result', name: 'pai_execute_command', success: true, output: 'a\nb' });

    expect(last(result.current.messages).approvals?.[0]?.status).toBe('approved');
  });

  it('records the decision, not the tool — a permitted call that then fails is still approved', () => {
    const { result } = renderHook(() => useCoordinator());
    fire('onOpen', {});
    H.sock.readyState = 1;
    act(() => result.current.send('q'));

    fire('onMessage', { type: 'tool_call', name: 'pai_execute_command', arguments: { command: 'nope' } });
    fire('onMessage', { type: 'approval_request', request_id: 'apr_1', tool: 'pai_execute_command', window_secs: 60 });
    fire('onMessage', {
      type: 'tool_result',
      name: 'pai_execute_command',
      success: false,
      error: 'command not found',
    });

    expect(last(result.current.messages).approvals?.[0]?.status).toBe('approved');
  });

  it('reads a blocked call off the gateway’s Security: prefix', () => {
    const { result } = renderHook(() => useCoordinator());
    fire('onOpen', {});
    H.sock.readyState = 1;
    act(() => result.current.send('q'));

    fire('onMessage', { type: 'tool_call', name: 'pai_execute_command', arguments: { command: 'rm -rf /' } });
    fire('onMessage', { type: 'approval_request', request_id: 'apr_1', tool: 'pai_execute_command', window_secs: 60 });
    fire('onMessage', {
      type: 'tool_result',
      name: 'pai_execute_command',
      success: false,
      error: 'Security: approval denied by alice',
    });

    expect(last(result.current.messages).approvals?.[0]?.status).toBe('denied');
  });

  // Approving `pai_execute_command` without seeing the command is a rubber
  // stamp. The arguments are already on the tool_call frame that precedes it.
  it('shows the operator what they are approving', () => {
    const { result } = renderHook(() => useCoordinator());
    fire('onOpen', {});
    H.sock.readyState = 1;
    act(() => result.current.send('q'));

    fire('onMessage', {
      type: 'tool_call',
      name: 'pai_execute_command',
      arguments: { command: 'rm -rf /var/cache/pai', timeout: 30 },
    });
    fire('onMessage', { type: 'approval_request', request_id: 'apr_1', tool: 'pai_execute_command', window_secs: 60 });

    expect(last(result.current.messages).approvals?.[0]?.args).toBe(
      'command=rm -rf /var/cache/pai  timeout=30',
    );
  });

  it('defaults the approval window to 300s when the frame omits it', () => {
    const { result } = renderHook(() => useCoordinator());
    fire('onOpen', {});
    H.sock.readyState = 1;
    act(() => result.current.send('q'));

    fire('onMessage', { type: 'approval_request', request_id: 'apr_1', tool: 't' });
    expect(last(result.current.messages).approvals?.[0]?.windowSecs).toBe(300);
  });

  it('tracks what answered the turn from the metadata frame', () => {
    const { result } = renderHook(() => useCoordinator());
    fire('onOpen', {});
    expect(result.current.serving).toBeNull();

    fire('onMessage', { type: 'metadata', conversation_id: 'c1', model: 'org/m', backend: 'vllm' });
    expect(result.current.serving).toEqual({ model: 'org/m', backend: 'vllm' });
  });

  it('a socket close mid-stream clears the streaming flag', () => {
    const { result } = renderHook(() => useCoordinator());
    fire('onOpen', {});
    H.sock.readyState = 1;
    act(() => result.current.send('q'));
    expect(last(result.current.messages).streaming).toBe(true);

    fire('onClose', { code: 1006 });
    expect(last(result.current.messages).streaming).toBeFalsy();
    expect(result.current.status).toBe('closed');
  });

  it('an error with no turn in flight does not touch the finished reply', () => {
    const { result } = renderHook(() => useCoordinator());
    fire('onOpen', {});
    H.sock.readyState = 1;
    act(() => result.current.send('q'));
    fire('onMessage', { type: 'content', text: 'answer' });
    fire('onMessage', { type: 'done' });

    // An older gateway sent this before every 4401 close, one per token lifetime.
    fire('onMessage', { type: 'error', text: 'Token expired' });
    fire('onMessage', { type: 'error', text: 'Token expired' });
    expect(last(result.current.messages)).toMatchObject({ text: 'answer' });
    expect(last(result.current.messages).error).toBeFalsy();
  });

  it('an error during a turn still lands in that turn', () => {
    const { result } = renderHook(() => useCoordinator());
    fire('onOpen', {});
    H.sock.readyState = 1;
    act(() => result.current.send('q'));
    fire('onMessage', { type: 'error', text: 'backend down' });
    expect(last(result.current.messages)).toMatchObject({ text: '⚠ backend down', error: true });
    expect(result.current.canSend).toBe(true);
  });

  // ── a turn whose done never arrives (0.6.15: Send stayed disabled while live) ──

  const inFlight = () => {
    const hook = renderHook(() => useCoordinator());
    fire('onOpen', {});
    H.sock.readyState = 1;
    act(() => hook.result.current.send('q'));
    return hook;
  };

  it('gives up on a turn after TURN_IDLE_MS with no frame: composer unlocks, socket replaced', () => {
    vi.useFakeTimers();
    const reconnect = vi.spyOn(H.sock, 'reconnectNow');
    const { result } = inFlight();
    fire('onMessage', { type: 'content', text: 'partial' });

    act(() => vi.advanceTimersByTime(TURN_IDLE_MS - 1));
    expect(result.current.canSend).toBe(false);
    // A keepalive is the turn still alive: the clock starts again.
    fire('onMessage', { type: 'keepalive' });
    act(() => vi.advanceTimersByTime(TURN_IDLE_MS - 1));
    expect(result.current.canSend).toBe(false);
    expect(reconnect).not.toHaveBeenCalled();

    act(() => vi.advanceTimersByTime(1));
    expect(result.current.canSend).toBe(true);
    expect(result.current.status).toBe('live');
    const l = last(result.current.messages);
    expect(l).toMatchObject({ streaming: false, error: true });
    expect(l.text).toContain('partial');
    expect(l.text).toContain('cut off');
    expect(reconnect).toHaveBeenCalledTimes(1);
  });

  it('a finished turn leaves no idle clock behind', () => {
    vi.useFakeTimers();
    const reconnect = vi.spyOn(H.sock, 'reconnectNow');
    const { result } = inFlight();
    fire('onMessage', { type: 'content', text: 'done answer' });
    fire('onMessage', { type: 'done' });
    act(() => vi.advanceTimersByTime(TURN_IDLE_MS * 2));
    expect(last(result.current.messages)).toMatchObject({ text: 'done answer' });
    expect(last(result.current.messages).error).toBeFalsy();
    expect(reconnect).not.toHaveBeenCalled();
  });

  it('stop() ends the in-flight turn at once and replaces the socket; idle, it does nothing', () => {
    const reconnect = vi.spyOn(H.sock, 'reconnectNow');
    const { result } = inFlight();
    act(() => result.current.stop());
    expect(result.current.canSend).toBe(true);
    expect(last(result.current.messages)).toMatchObject({ streaming: false, error: true });
    expect(last(result.current.messages).text).toContain('Stopped');
    expect(reconnect).toHaveBeenCalledTimes(1);

    const before = result.current.messages.length;
    act(() => result.current.stop());
    expect(result.current.messages.length).toBe(before);
    expect(reconnect).toHaveBeenCalledTimes(1);
  });

  // ── what a turn is doing before its first token (operator, 2026-11-01) ──

  it('tracks the phase frames, then thinking, and clears on the first answer token', () => {
    vi.useFakeTimers();
    vi.setSystemTime(1_000_000);
    const { result } = inFlight();
    fire('onMessage', { type: 'phase', phase: 'routed', node: 'mcmini', slots_busy: 2, slots_total: 2, queued_ahead: 1 });
    expect(last(result.current.messages).phase).toMatchObject({ kind: 'routed', node: 'mcmini', since: 1_000_000 });

    vi.setSystemTime(1_004_000);
    fire('onMessage', { type: 'phase', phase: 'prompt', input_tokens: 1834 });
    expect(last(result.current.messages).phase).toMatchObject({ kind: 'prompt', node: 'mcmini', since: 1_004_000 });

    vi.setSystemTime(1_005_000);
    fire('onMessage', { type: 'thinking', text: 'hmm' });
    expect(last(result.current.messages).phase).toMatchObject({ kind: 'thinking', since: 1_005_000 });
    vi.setSystemTime(1_009_000);
    fire('onMessage', { type: 'thinking', text: ' more' });
    expect(last(result.current.messages).phase).toMatchObject({ kind: 'thinking', since: 1_005_000 });

    fire('onMessage', { type: 'content', text: 'Answer' });
    expect(last(result.current.messages).phase).toBeUndefined();
    // A late phase frame once tokens flow does not bring the line back.
    fire('onMessage', { type: 'phase', phase: 'routed', node: 'host8' });
    expect(last(result.current.messages).phase).toBeUndefined();
  });

  it('an older gateway with no phase frames still gets a routed line from harness_dispatched', () => {
    const { result } = inFlight();
    fire('onMessage', { type: 'harness_dispatched', node: 'mcmini', kind: 'claude-code' });
    expect(last(result.current.messages).phase).toMatchObject({ kind: 'routed', node: 'mcmini' });
  });

  it('a tool call, done, or error clears the phase', () => {
    for (const end of [{ type: 'tool_call', name: 'noo_cluster_status' }, { type: 'done' }, { type: 'error', text: 'x' }]) {
      const { result } = inFlight();
      fire('onMessage', { type: 'phase', phase: 'routed', node: 'awolf' });
      fire('onMessage', end);
      expect(last(result.current.messages).phase).toBeUndefined();
    }
  });
});
