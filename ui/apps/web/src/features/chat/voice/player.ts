// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 PersonifAI LLC

// One read-aloud at a time, app-wide. Starting a message stops whatever else
// was playing; the speaker buttons subscribe to know which one is live.

type Listener = () => void;

let playingId: string | null = null;
let current: AbortController | null = null;
const listeners = new Set<Listener>();

const notify = () => listeners.forEach((l) => l());

export function subscribe(l: Listener): () => void {
  listeners.add(l);
  return () => listeners.delete(l);
}

export const getPlaying = (): string | null => playingId;

export function stopPlayback(): void {
  current?.abort();
  current = null;
  if (playingId !== null) {
    playingId = null;
    notify();
  }
}

const isAbort = (e: unknown) => e instanceof DOMException && e.name === 'AbortError';

/** Play one blob on `audio`, resolving when it ends. */
function playBlob(audio: HTMLAudioElement, blob: Blob, signal: AbortSignal): Promise<void> {
  return new Promise((resolve, reject) => {
    const url = URL.createObjectURL(blob);
    let settled = false;
    const done = (err?: unknown) => {
      if (settled) return;
      settled = true;
      audio.onended = null;
      audio.onerror = null;
      signal.removeEventListener('abort', onAbort);
      URL.revokeObjectURL(url);
      if (err) reject(err);
      else resolve();
    };
    const onAbort = () => {
      audio.pause();
      done(new DOMException('stopped', 'AbortError'));
    };
    if (signal.aborted) return onAbort();
    signal.addEventListener('abort', onAbort, { once: true });
    audio.onended = () => done();
    audio.onerror = () => done(new Error('The browser could not play the returned audio.'));
    audio.src = url;
    try {
      const p = audio.play();
      if (p && typeof p.catch === 'function') p.catch((e: unknown) => done(e));
    } catch (e) {
      done(e);
    }
  });
}

/**
 * Read `chunks` aloud under `id`. `fetchChunk` turns one chunk into audio; the
 * next chunk is fetched while the current one plays. Resolves when playback
 * ends or is stopped; rejects with a user-facing Error on failure.
 *
 * The <audio> element is created synchronously, inside the click that called
 * this, so browsers that tie playback to a user gesture accept it.
 */
export async function playChunks(
  id: string,
  chunks: string[],
  fetchChunk: (text: string, signal: AbortSignal) => Promise<Blob>,
): Promise<void> {
  stopPlayback();
  const ctrl = new AbortController();
  current = ctrl;
  playingId = id;
  notify();
  const audio = new Audio();
  try {
    let next: Promise<Blob> | null = chunks.length ? fetchChunk(chunks[0], ctrl.signal) : null;
    for (let i = 0; i < chunks.length && next; i++) {
      const blob = await next;
      if (ctrl.signal.aborted) break;
      next = i + 1 < chunks.length ? fetchChunk(chunks[i + 1], ctrl.signal) : null;
      // An unawaited prefetch that fails after a stop must not surface as an
      // unhandled rejection; it is awaited (and reported) on the next turn.
      next?.catch(() => undefined);
      await playBlob(audio, blob, ctrl.signal);
    }
  } catch (e) {
    if (isAbort(e) || ctrl.signal.aborted) return;
    if (e instanceof DOMException && e.name === 'NotAllowedError') {
      throw new Error('The browser blocked playback. Click the speaker again to retry.');
    }
    throw e instanceof Error ? e : new Error(String(e));
  } finally {
    if (current === ctrl) {
      current = null;
      playingId = null;
      notify();
    }
  }
}
