// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 PersonifAI LLC

import { useQuery } from '@metis/core';
import { apiGet } from '@/lib/client';

export interface Thread {
  id: string;
  messages: number;
  started: string;
  last: string;
  /** Every name that sent or received in the thread, sorted, de-duplicated. */
  participants: string[];
}

export interface TrafficMessage {
  id: string;
  from: string;
  to: string;
  kind: string;
  body: unknown;
  ts: string;
  enc: string;
  sigVerified: boolean;
  fromNode: string | null;
  fromHarness: string | null;
}

export interface LiveSession {
  connection: string;
  label: string;
  consumer: string | null;
  displayName: string | null;
  lastSeen: string | null;
}

type Raw = Record<string, unknown>;
const str = (v: unknown, d = ''): string => (typeof v === 'string' ? v : d);
const strs = (v: unknown): string[] => (Array.isArray(v) ? v.filter((x): x is string => typeof x === 'string') : []);

export function parseThreads(data: unknown): Thread[] {
  const rows = ((data as Raw | null)?.threads ?? []) as Raw[];
  return rows.map((t) => ({
    id: str(t.thread_id),
    messages: typeof t.messages === 'number' ? t.messages : 0,
    started: str(t.started),
    last: str(t.last),
    participants: [...new Set([...strs(t.senders), ...strs(t.recipients)])].sort(),
  }));
}

/** The API returns newest first; the thread view reads oldest first. */
export function parseMessages(data: unknown): TrafficMessage[] {
  const rows = ((data as Raw | null)?.messages ?? []) as Raw[];
  return rows
    .map((m) => {
      const fid = (m.from_id ?? {}) as Raw;
      return {
        id: str(m.id),
        from: str(m.from),
        to: str(m.to),
        kind: str(m.kind),
        body: m.body,
        ts: str(m.ts),
        enc: str(m.enc, 'none'),
        sigVerified: m.sig_verified === true,
        fromNode: typeof fid.node === 'string' ? fid.node : null,
        fromHarness: typeof fid.harness === 'string' ? fid.harness : null,
      };
    })
    .sort((a, b) => Date.parse(a.ts) - Date.parse(b.ts));
}

export function parsePresence(data: unknown): LiveSession[] {
  const rows = ((data as Raw | null)?.sessions ?? []) as Raw[];
  return rows.map((s) => ({
    connection: str(s.connection),
    label: str(s.label),
    consumer: typeof s.consumer === 'string' ? s.consumer : null,
    displayName: typeof s.display_name === 'string' ? s.display_name : null,
    lastSeen: typeof s.last_seen === 'string' ? s.last_seen : null,
  }));
}

/** Text filter (thread id or participant substring) plus an exact-participant filter. */
export function filterThreads(threads: Thread[], text: string, participant: string): Thread[] {
  const q = text.trim().toLowerCase();
  return threads.filter(
    (t) =>
      (!participant || t.participants.includes(participant)) &&
      (!q || t.id.toLowerCase().includes(q) || t.participants.some((p) => p.toLowerCase().includes(q))),
  );
}

/** `body.text` when present; otherwise pretty JSON. `long` bodies render collapsed. */
export function renderBody(body: unknown): { text: string; isText: boolean; long: boolean } {
  const t = (body as Raw | null)?.text;
  if (typeof t === 'string') return { text: t, isText: true, long: t.length > 600 };
  const text = typeof body === 'string' ? body : JSON.stringify(body ?? null, null, 2);
  return { text, isText: false, long: text.length > 300 };
}

async function must<T>(path: string, what: string): Promise<T> {
  const d = await apiGet<T>(path);
  if (d === null) throw new Error(`${what} unavailable`);
  return d;
}

/** Every thread on the system (operator widened view), newest activity first. */
export function useThreads(refetchMs: number | false) {
  return useQuery<Thread[]>({
    queryKey: ['agent-traffic', 'threads'],
    refetchInterval: refetchMs,
    queryFn: async () => parseThreads(await must('/api/agents/threads?all=true&limit=200', 'Threads API')),
  });
}

/** One thread's messages, oldest first. */
export function useThreadMessages(thread: string | null, refetchMs: number | false) {
  return useQuery<TrafficMessage[]>({
    queryKey: ['agent-traffic', 'messages', thread],
    enabled: !!thread,
    refetchInterval: refetchMs,
    queryFn: async () =>
      parseMessages(
        await must(
          `/api/agents/messages?all=true&limit=200&thread=${encodeURIComponent(thread ?? '')}`,
          'Messages API',
        ),
      ),
  });
}

/** Live MCP sessions. */
export function usePresence(refetchMs: number | false) {
  return useQuery<LiveSession[]>({
    queryKey: ['agent-traffic', 'presence'],
    refetchInterval: refetchMs,
    queryFn: async () => parsePresence(await must('/api/agents/presence?all=true', 'Presence API')),
  });
}
