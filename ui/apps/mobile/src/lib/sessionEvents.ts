// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 PersonifAI LLC

// Tiny pub/sub so the REST client can tell the auth layer that a 401-refresh
// failed. The web app uses a window event for this; React Native has no window,
// so we use a plain listener set instead.
type Listener = () => void;
const listeners = new Set<Listener>();

export const sessionEvents = {
  onExpire(listener: Listener): () => void {
    listeners.add(listener);
    return () => listeners.delete(listener);
  },
  emitExpire(): void {
    listeners.forEach((l) => l());
  },
};
