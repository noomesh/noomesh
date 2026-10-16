// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 PersonifAI LLC

import { useCallback, useEffect, useRef, useState } from 'react';
import { useMetisClient } from '@metis/core';
import { cn } from '@/lib/utils';
import { transcribe } from './voiceApi';
import type { ControlState } from './useVoice';

/** Longest recording, in seconds — keeps the upload well under the gateway's body limit. */
export const MAX_RECORD_SECONDS = 120;

/** Keyboard shortcut that toggles recording (matched on `code`, so layouts agree). */
export const RECORD_SHORTCUT = { altKey: true, code: 'KeyM', label: 'Alt+M' } as const;

// Containers every STT provider in the tree accepts, in preference order.
// Chrome/Firefox/Edge record webm/opus; Safari records mp4/aac.
const MIME_PREFERENCE = ['audio/webm;codecs=opus', 'audio/webm', 'audio/ogg;codecs=opus', 'audio/mp4'];

function pickMime(): string | undefined {
  if (typeof MediaRecorder === 'undefined' || typeof MediaRecorder.isTypeSupported !== 'function') return undefined;
  return MIME_PREFERENCE.find((m) => MediaRecorder.isTypeSupported(m));
}

function micError(e: unknown): string {
  const name = e instanceof DOMException || e instanceof Error ? e.name : '';
  if (name === 'NotAllowedError' || name === 'SecurityError' || name === 'PermissionDeniedError') {
    return 'Microphone access was denied. Allow it in your browser’s site settings, then try again.';
  }
  if (name === 'NotFoundError' || name === 'OverconstrainedError') return 'No microphone was found.';
  if (name === 'NotReadableError') return 'The microphone is in use by another application.';
  return `Could not start the microphone${e instanceof Error && e.message ? `: ${e.message}` : '.'}`;
}

const mmss = (s: number) => `${Math.floor(s / 60)}:${String(s % 60).padStart(2, '0')}`;

type Phase = 'idle' | 'requesting' | 'recording' | 'transcribing';

export interface MicControlProps {
  state: Exclude<ControlState, 'hidden'>;
  reason?: string;
  /** Called with the recognised text. Never sends; the composer decides. */
  onTranscript: (text: string) => void;
  /** Inline error for the composer to show; null clears it. */
  onError: (message: string | null) => void;
}

/**
 * Record → transcribe → hand the text to the composer. Click (or Alt+M) to
 * start, again to stop; Esc or the ✕ cancels without transcribing.
 */
export function MicControl({ state, reason, onTranscript, onError }: MicControlProps) {
  const client = useMetisClient();
  const [phase, setPhase] = useState<Phase>('idle');
  const [elapsed, setElapsed] = useState(0);
  const rec = useRef<MediaRecorder | null>(null);
  const stream = useRef<MediaStream | null>(null);
  const cancelled = useRef(false);
  const upload = useRef<AbortController | null>(null);
  const timer = useRef<ReturnType<typeof setInterval> | null>(null);
  const mounted = useRef(true);

  const releaseMic = () => {
    if (timer.current) clearInterval(timer.current);
    timer.current = null;
    stream.current?.getTracks().forEach((t) => t.stop());
    stream.current = null;
  };

  useEffect(() => {
    mounted.current = true;
    return () => {
      mounted.current = false;
      cancelled.current = true;
      upload.current?.abort();
      try {
        if (rec.current && rec.current.state !== 'inactive') rec.current.stop();
      } catch {
        /* already stopped */
      }
      releaseMic();
    };
  }, []);

  const stop = useCallback(() => {
    const r = rec.current;
    if (r && r.state !== 'inactive') r.stop();
  }, []);

  const cancel = useCallback(() => {
    cancelled.current = true;
    upload.current?.abort();
    const r = rec.current;
    if (r && r.state !== 'inactive') r.stop();
    else {
      releaseMic();
      setPhase('idle');
    }
  }, []);

  const start = useCallback(async () => {
    onError(null);
    if (typeof window !== 'undefined' && window.isSecureContext === false) {
      onError('Voice input needs a secure (https) connection to the console.');
      return;
    }
    if (!navigator.mediaDevices?.getUserMedia || typeof MediaRecorder === 'undefined') {
      onError('This browser cannot record audio.');
      return;
    }
    setPhase('requesting');
    let s: MediaStream;
    try {
      s = await navigator.mediaDevices.getUserMedia({ audio: true });
    } catch (e) {
      setPhase('idle');
      onError(micError(e));
      return;
    }
    if (!mounted.current) {
      s.getTracks().forEach((t) => t.stop());
      return;
    }
    stream.current = s;
    const mime = pickMime();
    let r: MediaRecorder;
    try {
      r = mime ? new MediaRecorder(s, { mimeType: mime }) : new MediaRecorder(s);
    } catch (e) {
      releaseMic();
      setPhase('idle');
      onError(micError(e));
      return;
    }
    const parts: Blob[] = [];
    cancelled.current = false;
    r.ondataavailable = (ev: BlobEvent) => {
      if (ev.data && ev.data.size) parts.push(ev.data);
    };
    r.onstop = async () => {
      releaseMic();
      rec.current = null;
      if (cancelled.current || !mounted.current) {
        if (mounted.current) setPhase('idle');
        return;
      }
      const blob = new Blob(parts, { type: r.mimeType || mime || 'audio/webm' });
      if (!blob.size) {
        setPhase('idle');
        onError('Nothing was recorded.');
        return;
      }
      setPhase('transcribing');
      const ctrl = new AbortController();
      upload.current = ctrl;
      try {
        const text = await transcribe(client, blob, ctrl.signal);
        if (ctrl.signal.aborted || !mounted.current) return;
        if (text) onTranscript(text);
        else onError('No speech was recognised.');
      } catch (e) {
        if (!ctrl.signal.aborted && mounted.current) onError((e as Error).message);
      } finally {
        if (upload.current === ctrl) upload.current = null;
        if (mounted.current) setPhase('idle');
      }
    };
    rec.current = r;
    r.start();
    setElapsed(0);
    setPhase('recording');
    const t0 = Date.now();
    timer.current = setInterval(() => {
      const secs = Math.floor((Date.now() - t0) / 1000);
      setElapsed(secs);
      if (secs >= MAX_RECORD_SECONDS) stop();
    }, 250);
  }, [client, onError, onTranscript, stop]);

  const toggle = useCallback(() => {
    if (state !== 'ready') return;
    if (phase === 'idle') void start();
    else if (phase === 'recording') stop();
  }, [phase, start, state, stop]);

  // Alt+M toggles from anywhere in the console; Esc cancels a recording.
  useEffect(() => {
    const onKey = (e: KeyboardEvent) => {
      if (e.altKey === RECORD_SHORTCUT.altKey && !e.ctrlKey && !e.metaKey && e.code === RECORD_SHORTCUT.code) {
        e.preventDefault();
        toggle();
      } else if (e.key === 'Escape' && (phase === 'recording' || phase === 'transcribing')) {
        e.preventDefault();
        cancel();
      }
    };
    window.addEventListener('keydown', onKey);
    return () => window.removeEventListener('keydown', onKey);
  }, [toggle, cancel, phase]);

  const recording = phase === 'recording';
  const label = recording
    ? 'Stop recording and transcribe'
    : phase === 'transcribing'
      ? 'Transcribing…'
      : 'Record a voice message';

  return (
    <>
      {(recording || phase === 'transcribing') && (
        <span className="rec-strip" role="status" aria-live="polite">
          {recording ? (
            <>
              <span className="rec-dot" aria-hidden="true" />
              <span className="rec-time" aria-label={`Recording, ${elapsed} seconds`}>
                {mmss(elapsed)}
              </span>
            </>
          ) : (
            <span className="rec-time">Transcribing…</span>
          )}
          <button type="button" className="rec-cancel" onClick={cancel} aria-label="Cancel recording" title="Cancel (Esc)">
            <svg viewBox="0 0 20 20" aria-hidden="true">
              <path d="M6 6l8 8M14 6l-8 8" />
            </svg>
          </button>
        </span>
      )}
      <button
        type="button"
        className={cn('mic-btn', recording && 'on', phase !== 'idle' && !recording && 'busy')}
        onClick={toggle}
        disabled={state === 'down' || phase === 'requesting' || phase === 'transcribing'}
        aria-pressed={recording}
        aria-label={label}
        aria-keyshortcuts={RECORD_SHORTCUT.label}
        title={state === 'down' ? reason : `${label} (${RECORD_SHORTCUT.label})`}
      >
        {recording ? (
          <svg viewBox="0 0 20 20" aria-hidden="true">
            <rect x="5.5" y="5.5" width="9" height="9" rx="1.5" fill="currentColor" stroke="none" />
          </svg>
        ) : (
          <svg viewBox="0 0 20 20" aria-hidden="true">
            <rect x="7.5" y="2.5" width="5" height="9" rx="2.5" />
            <path d="M4.5 9.5a5.5 5.5 0 0 0 11 0M10 15v2.5" />
          </svg>
        )}
      </button>
    </>
  );
}
