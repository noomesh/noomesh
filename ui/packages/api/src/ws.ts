// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 PersonifAI LLC

// @metis/api — reconnecting WebSocket factory.
//
// Ported from legacy core/ws.js, decoupled from the DOM: the token getter and
// (optional) baseUrl are injected so it runs on web and React Native alike.
// Browsers can't set an Authorization header on the WS upgrade, so the gateway
// takes the JWT as ?token= on /ws/* routes. Close codes 1008 / 4401 = the
// credential is not good here: a bad token at the handshake, the token's
// `exp` passing while the socket was open, or a logout. With `refreshToken`
// set, the factory refreshes ONCE and reconnects with the new token; if that
// fails (or a second 4401 follows without the socket ever opening) it stops
// and fires onAuthFail — never a reconnect loop on a dead session.

export interface SocketAuth {
  /** Absolute gateway origin. Required off-web (no `location`); on web, '' derives from location. */
  baseUrl?: string;
  getToken(): string | null;
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

export function wsUrl(path: string, auth: SocketAuth): string {
  const token = encodeURIComponent(auth.getToken() ?? '');
  if (auth.baseUrl) {
    const u = new URL(auth.baseUrl);
    const proto = u.protocol === 'https:' ? 'wss:' : 'ws:';
    return `${proto}//${u.host}${path}?token=${token}`;
  }
  if (typeof location === 'undefined') {
    throw new Error('wsUrl: baseUrl is required when there is no global location (React Native).');
  }
  const proto = location.protocol === 'https:' ? 'wss:' : 'ws:';
  return `${proto}//${location.host}${path}?token=${token}`;
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

  function connect() {
    ws = new WebSocket(wsUrl(path, opts));
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
        if (refreshToken && !refreshedSinceOpen) {
          refreshedSinceOpen = true;
          void refreshToken().then((fresh) => {
            if (closedByUser) return;
            if (fresh) connect();
            else onAuthFail(ev);
          });
          return;
        }
        onAuthFail(ev);
        return;
      }
      if (reconnectMs > 0) {
        const delay = Math.min(reconnectMs * Math.pow(2, attempts++), maxBackoffMs);
        timer = setTimeout(connect, delay);
      }
    };
  }
  connect();

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
      connect();
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
