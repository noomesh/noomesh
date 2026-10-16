// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 PersonifAI LLC

import { useEffect, useState, useSyncExternalStore } from 'react';
import { useMetisClient } from '@metis/core';
import { cn } from '@/lib/utils';
import { chunkText, speakable, synthesize } from './voiceApi';
import { getPlaying, playChunks, stopPlayback, subscribe } from './player';
import { useVoicePref, type ControlState } from './useVoice';

export interface SpeakButtonProps {
  /** Stable id for this message; one playback runs at a time across the app. */
  id: string;
  text: string;
  state: Exclude<ControlState, 'hidden'>;
  reason?: string;
}

/** Read an assistant reply aloud; click again to stop. */
export function SpeakButton({ id, text, state, reason }: SpeakButtonProps) {
  const client = useMetisClient();
  const [voice] = useVoicePref();
  const playing = useSyncExternalStore(subscribe, getPlaying) === id;
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);

  // Leaving the transcript (or the message going away) stops its audio.
  useEffect(
    () => () => {
      if (getPlaying() === id) stopPlayback();
    },
    [id],
  );

  const toggle = () => {
    if (playing) {
      stopPlayback();
      return;
    }
    setError(null);
    const chunks = chunkText(speakable(text));
    if (!chunks.length) {
      setError('Nothing to read aloud.');
      return;
    }
    let first = true;
    setLoading(true);
    playChunks(id, chunks, async (t, signal) => {
      try {
        return await synthesize(client, t, voice, signal);
      } finally {
        if (first) {
          first = false;
          setLoading(false);
        }
      }
    })
      .catch((e: Error) => setError(e.message))
      .finally(() => setLoading(false));
  };

  const label = playing ? 'Stop reading aloud' : 'Read aloud';
  return (
    <span className="speak">
      <button
        type="button"
        className={cn('speak-btn', playing && 'on', loading && 'busy')}
        onClick={toggle}
        disabled={state === 'down'}
        aria-pressed={playing}
        aria-label={label}
        title={state === 'down' ? reason : label}
      >
        {playing ? (
          <svg viewBox="0 0 20 20" aria-hidden="true">
            <rect x="5.5" y="5.5" width="9" height="9" rx="1" fill="currentColor" stroke="none" />
          </svg>
        ) : (
          <svg viewBox="0 0 20 20" aria-hidden="true">
            <path d="M3.5 8v4h3l4 3.5v-11L6.5 8z" />
            <path d="M13.5 7.5a3.5 3.5 0 0 1 0 5M15.5 5.5a6.5 6.5 0 0 1 0 9" />
          </svg>
        )}
      </button>
      {error && (
        <span className="speak-err" role="alert">
          {error}
        </span>
      )}
    </span>
  );
}
