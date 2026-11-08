// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 PersonifAI LLC

// @metis/api — reconnecting WebSocket factory.
//
// Ported from legacy core/ws.js, decoupled from the DOM: the token getter and
// (optional) baseUrl are injected so it runs on web and React Native alike.
// Browsers can't set an Authorization header on the WS upgrade, and a JWT in
// the URL lands in proxy logs and browser history (i515c). So each connect
// first mints a single-use, 30-second ticket (POST /api/ws-ticket with the
// bearer) and opens `?ticket=`; the gateway refuses `?token=` on these
// sockets. A 401 at the ticket counts as an auth close. Close codes 1008 / 4401 = the
// credential is not good here: a bad token at the handshake, the token's
// `exp` passing while the socket was open, or a logout. With `refreshToken`
// set, the factory refreshes ONCE and reconnects with the new token; if that
// fails (or a second 4401 follows without the socket ever opening) it stops
// and fires onAuthFail — never a reconnect loop on a dead session.

export interface SocketAuth {
  /** Absolute gateway origin. Required off-web (no `location`); on web, '' derives from location. */
  baseUrl?: string;
  getToken(): string | null;
  /** Injected for tests; defaults to the global fetch. */
  fetchImpl?: typeof fetch;
}

/** Where a ticket for one of the console's sockets is minted. */
export const WS_TICKET_PATH = '/api/ws-ticket';

/** Why a ticket could not be had: the credential, or the way there. */
export class TicketError extends Error {
  constructor(message: string, readonly auth: boolean) {
    super(message);
  }
}

function httpBase(auth: SocketAuth): string {
  if (auth.baseUrl) return new URL(auth.baseUrl).origin;
  if (typeof location === 'undefined') {
    throw new Error('wsUrl: baseUrl is required when there is no global location (React Native).');
  }
  return location.origin;
}

/** Mint a single-use ticket for `path` with the current access token. */
export async function mintTicket(path: string, auth: SocketAuth): Promise<string> {
  const token = auth.getToken();
  if (!token) throw new TicketError('no access token to mint a socket ticket with', true);
  const f = auth.fetchImpl ?? fetch;
  const r = await f(`${httpBase(auth)}${WS_TICKET_PATH}`, {
    method: 'POST',
    headers: { Authorization: `Bearer ${token}`, 'Content-Type': 'application/json' },
    body: JSON.stringify({ socket: path }),
    cache: 'no-store',
  });
  if (r.status === 401 || r.status === 403) throw new TicketError(`socket ticket refused: ${r.status}`, true);
  if (!r.ok) throw new TicketError(`socket ticket: ${r.status} ${r.statusText}`, false);
  const body = (await r.json()) as { ticket?: string };
  if (!body.ticket) throw new TicketError('socket ticket: the answer carried no ticket', false);
  return body.ticket;
}

export interface SocketOptions extends SocketAuth {
  onMessage?: (data: unknown, ev: MessageEvent) => void;
  onOpen?: (ev: Event) => void;
  onClose?: (ev: CloseEvent) => void;
  onAuthFail?: (ev: CloseEvent) => void;
  /**
   * Silent token refresh (see `createTokenRefresher`). Called once per
   * auth close; a resolved token reconnects, null ends the socket.
   */
  refreshToken?: () => Promise<string | null>;
  /** Base backoff in ms; 0 disables auto-reconnect. */
  reconnectMs?: number;
  maxBackoffMs?: number;
}

/** The socket URL for a minted ticket. Never a token: only `?ticket=`. */
export function wsUrl(path: string, ticket: string, auth: SocketAuth): string {
  const t = encodeURIComponent(ticket);
  if (auth.baseUrl) {
    const u = new URL(auth.baseUrl);
    const proto = u.protocol === 'https:' ? 'wss:' : 'ws:';
    return `${proto}//${u.host}${path}?ticket=${t}`;
  }
  if (typeof location === 'undefined') {
    throw new Error('wsUrl: baseUrl is required when there is no global location (React Native).');
  }
  const proto = location.protocol === 'https:' ? 'wss:' : 'ws:';
  return `${proto}//${location.host}${path}?ticket=${t}`;
}

export interface ManagedSocket {
  readonly socket: WebSocket | null;
  readonly readyState: number;
  send(msg: unknown): boolean;
  reconnectNow(): void;
  close(): void;
}

export function createSocket(path: string, opts: SocketOptions): ManagedSocket {
  const {
    onMessage = () => {},
    onOpen = () => {},
    onClose = () => {},
    onAuthFail = () => {},
    refreshToken,
    reconnectMs = 3000,
    maxBackoffMs = 30000,
  } = opts;

  let ws: WebSocket | null = null;
  let closedByUser = false;
  let attempts = 0;
  let timer: ReturnType<typeof setTimeout> | null = null;
  // One refresh per auth close; cleared when a socket actually opens.
  let refreshedSinceOpen = false;

  function scheduleReconnect() {
    if (closedByUser || reconnectMs <= 0) return;
    const delay = Math.min(reconnectMs * Math.pow(2, attempts++), maxBackoffMs);
    timer = setTimeout(() => void connect(), delay);
  }

  /** A credential that is not good here: refresh once, then give up. */
  function authFailed(ev: CloseEvent) {
    if (refreshToken && !refreshedSinceOpen) {
      refreshedSinceOpen = true;
      void refreshToken().then((fresh) => {
        if (closedByUser) return;
        if (fresh) void connect();
        else onAuthFail(ev);
      });
      return;
    }
    onAuthFail(ev);
  }

  async function connect() {
    let ticket: string;
    try {
      ticket = await mintTicket(path, opts);
    } catch (e) {
      if (closedByUser) return;
      if (e instanceof TicketError && e.auth) {
        // No CloseEvent constructor off-web (React Native): the shape is enough.
        authFailed({ code: 4401, reason: e.message, wasClean: false } as CloseEvent);
      } else {
        console.warn('socket ticket unavailable:', e);
        scheduleReconnect();
      }
      return;
    }
    if (closedByUser) return;
    ws = new WebSocket(wsUrl(path, ticket, opts));
    ws.onopen = (ev) => {
      attempts = 0;
      refreshedSinceOpen = false;
      onOpen(ev);
    };
    ws.onmessage = (ev) => {
      let data: unknown = ev.data;
      try {
        data = JSON.parse(ev.data);
      } catch {
        /* raw string */
      }
      onMessage(data, ev);
    };
    ws.onclose = (ev) => {
      onClose(ev);
      if (closedByUser) return;
      if (ev.code === 1008 || ev.code === 4401) {
        authFailed(ev);
        return;
      }
      scheduleReconnect();
    };
  }
  void connect();

  return {
    get socket() {
      return ws;
    },
    get readyState() {
      return ws ? ws.readyState : WebSocket.CLOSED;
    },
    send(msg) {
      if (!ws || ws.readyState !== WebSocket.OPEN) return false;
      ws.send(typeof msg === 'string' ? msg : JSON.stringify(msg));
      return true;
    },
    reconnectNow() {
      closedByUser = false;
      if (timer) {
        clearTimeout(timer);
        timer = null;
      }
      attempts = 0;
      // Detach the outgoing socket's handlers before closing it: otherwise its
      // onclose fires with closedByUser=false and schedules its own reconnect,
      // racing the connect() below into duplicate concurrent sockets.
      const old = ws;
      if (old) {
        old.onopen = old.onmessage = old.onclose = null;
        try {
          old.close();
        } catch {
          /* ignore */
        }
      }
      void connect();
    },
    close() {
      closedByUser = true;
      if (timer) clearTimeout(timer);
      try {
        ws?.close();
      } catch {
        /* ignore */
      }
    },
  };
}
