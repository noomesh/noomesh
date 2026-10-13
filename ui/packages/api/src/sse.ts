// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 PersonifAI LLC

// @metis/api — server-sent-events reader.
//
// The kiosk's transport,
// built on fetch + ReadableStream rather than the native EventSource, for two
// reasons that matter to an unattended display:
//   1. EventSource cannot set request headers, so the bearer would have to go
//      in the URL — into access logs, backups and `ps aux`. fetch can.
//   2. EventSource hides a 401 behind an opaque `error` event, indistinguishable
//      from a network blip. A dead credential and a dead network need different
//      responses (re-mint vs. wait), so the HTTP status has to surface.
// Decoupled from the DOM like ws.ts: token getter and baseUrl are injected, so
// it runs on web and React Native alike.

export interface StreamEvent {
  /** `id:` of this event, if the server sent one. */
  id: string | null;
  /** `event:` — 'message' when absent, per the SSE spec. */
  event: string;
  /** `data:` lines joined with '\n', as the spec says. Not parsed here. */
  data: string;
}

export interface EventStreamOptions {
  /** Absolute gateway origin, or '' for same-origin relative paths. */
  baseUrl?: string;
  /**
   * Optional since 2026-09-06. The kiosk has no credential of its own — its
   * local proxy attaches the header — so "no token" is a valid configuration
   * here, not a missing one. The console still passes it.
   */
  getToken?(): string | null | Promise<string | null>;
  onEvent?: (ev: StreamEvent) => void;
  /** A `:` comment line — the gateway's keepalive. Fires for every one. */
  onKeepalive?: () => void;
  onOpen?: () => void;
  /**
   * The stream ended or failed for a non-credential reason: a network error
   * (`status` null), a non-2xx other than 401/403, or a clean server close.
   * A reconnect is scheduled after this fires.
   */
  onError?: (status: number | null) => void;
  /** 401/403 — the credential is dead. No reconnect; re-minting is the host's job. */
  onAuthFail?: (status: number) => void;
  /** Base backoff in ms; 0 disables auto-reconnect. A `retry:` field overrides it. */
  reconnectMs?: number;
  maxBackoffMs?: number;
  /**
   * Abort and reconnect when no bytes — events or keepalive comments — have
   * arrived for this long. 0 disables. This is what acts on the keepalive
   * gap: a proxy between the client and the gateway (the kiosk sits behind
   * `tailscale serve`; the dev server's proxy behaves the same) can hold the
   * client connection open after the upstream dies, so `read()` never
   * resolves and the stream looks alive forever. Set it from the server's
   * announced keepalive interval; see `setStallMs`.
   */
  stallMs?: number;
  /** Fired when the stall timeout trips, just before the reconnect. */
  onStall?: () => void;
  fetchImpl?: typeof fetch;
}

export interface EventStream {
  /** Sent back as `Last-Event-ID` on reconnect so the server can fill the gap. */
  readonly lastEventId: string | null;
  readonly connected: boolean;
  /** Change the stall timeout — e.g. once the server has announced its keepalive interval. Re-arms immediately. */
  setStallMs(ms: number): void;
  reconnectNow(): void;
  close(): void;
}

interface Pending {
  id: string | null;
  event: string;
  data: string[];
}

const fresh = (): Pending => ({ id: null, event: 'message', data: [] });

export function createEventStream(path: string, opts: EventStreamOptions): EventStream {
  const {
    baseUrl = '',
    onEvent = () => {},
    onKeepalive = () => {},
    onOpen = () => {},
    onError = () => {},
    onAuthFail = () => {},
    onStall = () => {},
    maxBackoffMs = 30_000,
    fetchImpl = fetch,
  } = opts;
  let reconnectMs = opts.reconnectMs ?? 3000;
  let stallMs = opts.stallMs ?? 0;

  let lastEventId: string | null = null;
  let connected = false;
  let closedByUser = false;
  let attempts = 0;
  let timer: ReturnType<typeof setTimeout> | null = null;
  let stallTimer: ReturnType<typeof setTimeout> | null = null;
  let controller: AbortController | null = null;
  // Bumped on every connect. A read loop whose generation is stale belongs to
  // a connection that reconnectNow()/close() already superseded, and must not
  // schedule its own reconnect — the same duplicate-socket race ws.ts guards.
  let generation = 0;

  function schedule() {
    if (closedByUser || reconnectMs <= 0) return;
    const delay = Math.min(reconnectMs * Math.pow(2, attempts++), maxBackoffMs);
    timer = setTimeout(connect, delay);
  }

  function disarmStall() {
    if (stallTimer) clearTimeout(stallTimer);
    stallTimer = null;
  }

  /** (Re)start the stall clock for the connection owned by `ac`. Any byte resets it. */
  function armStall(ac: AbortController) {
    disarmStall();
    if (stallMs <= 0) return;
    stallTimer = setTimeout(() => {
      stallTimer = null;
      onStall();
      // Aborting rejects the pending read(); the loop below then takes the
      // ordinary "stream ended" path — onError(null) and a reconnect.
      ac.abort();
    }, stallMs);
  }

  /** One SSE line. Returns the (possibly dispatched-and-reset) pending event. */
  function handleLine(line: string, ev: Pending): Pending {
    if (line === '') {
      // Dispatch on blank line — but only if data was actually set; an event
      // with no data lines is dropped, per spec.
      if (ev.data.length) onEvent({ id: ev.id, event: ev.event, data: ev.data.join('\n') });
      return fresh();
    }
    if (line.startsWith(':')) {
      onKeepalive();
      return ev;
    }
    const colon = line.indexOf(':');
    const field = colon < 0 ? line : line.slice(0, colon);
    let value = colon < 0 ? '' : line.slice(colon + 1);
    if (value.startsWith(' ')) value = value.slice(1);
    switch (field) {
      case 'event':
        ev.event = value;
        break;
      case 'data':
        ev.data.push(value);
        break;
      case 'id':
        // Spec: an id containing NUL is ignored. Set immediately, not on
        // dispatch — the spec's "last event ID buffer" updates on the line.
        if (!value.includes('\0')) {
          ev.id = value;
          lastEventId = value;
        }
        break;
      case 'retry': {
        const n = Number.parseInt(value, 10);
        if (Number.isFinite(n) && n >= 0) reconnectMs = n;
        break;
      }
      default:
        // Unknown fields are ignored, per spec.
        break;
    }
    return ev;
  }

  async function connect() {
    timer = null;
    const gen = ++generation;
    controller?.abort();
    const ac = new AbortController();
    controller = ac;

    const headers: Record<string, string> = { Accept: 'text/event-stream' };
    const token = opts.getToken ? await opts.getToken() : null;
    if (token) headers.Authorization = `Bearer ${token}`;
    if (lastEventId != null) headers['Last-Event-ID'] = lastEventId;

    let resp: Response;
    try {
      resp = await fetchImpl(`${baseUrl}${path}`, {
        method: 'GET',
        headers,
        signal: ac.signal,
        credentials: 'same-origin',
        cache: 'no-store',
      });
    } catch {
      if (gen !== generation || closedByUser) return;
      onError(null);
      schedule();
      return;
    }
    if (gen !== generation || closedByUser) return;

    if (resp.status === 401 || resp.status === 403) {
      onAuthFail(resp.status);
      return;
    }
    if (!resp.ok || !resp.body) {
      onError(resp.status);
      schedule();
      return;
    }

    connected = true;
    attempts = 0;
    onOpen();
    armStall(ac);

    const reader = resp.body.getReader();
    const decoder = new TextDecoder();
    let buf = '';
    let ev = fresh();
    try {
      for (;;) {
        const { value, done } = await reader.read();
        if (done) break;
        armStall(ac);
        buf += decoder.decode(value, { stream: true });
        let nl: number;
        while ((nl = buf.indexOf('\n')) >= 0) {
          let line = buf.slice(0, nl);
          buf = buf.slice(nl + 1);
          if (line.endsWith('\r')) line = line.slice(0, -1);
          ev = handleLine(line, ev);
        }
      }
    } catch {
      // Aborted by reconnectNow()/close()/the stall clock, or the network
      // dropped mid-read. All fall through; the generation check decides.
    }
    disarmStall();
    connected = false;
    if (gen !== generation || closedByUser) return;
    // A stream that ends without an abort is a server close or a dropped
    // connection. Either way the display is now blind until we're back.
    onError(null);
    schedule();
  }

  void connect();

  return {
    get lastEventId() {
      return lastEventId;
    },
    get connected() {
      return connected;
    },
    setStallMs(ms) {
      stallMs = ms;
      if (connected && controller) armStall(controller);
      else disarmStall();
    },
    reconnectNow() {
      closedByUser = false;
      if (timer) {
        clearTimeout(timer);
        timer = null;
      }
      attempts = 0;
      void connect();
    },
    close() {
      closedByUser = true;
      if (timer) clearTimeout(timer);
      timer = null;
      disarmStall();
      generation++;
      controller?.abort();
      connected = false;
    },
  };
}
