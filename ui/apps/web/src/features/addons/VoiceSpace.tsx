// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 PersonifAI LLC

import { useState } from 'react';
import { useAuth } from '@metis/core';
import { LoginOverlay } from '@/components/LoginOverlay';
import { useOpenAddonUi } from './useAddonUis';

/** Never embed a console-origin document or a foreign host from a handoff. */
export function voiceFrameUrl(value: string, here: Location): URL {
  const url = new URL(value);
  if (url.protocol !== 'https:' || url.hostname !== here.hostname || url.origin === here.origin
      || url.username || url.password || url.pathname !== '/__noo/session' || url.hash
      || !url.searchParams.get('code') || [...url.searchParams.keys()].some((key) => key !== 'code')) {
    throw new Error('Voice Space returned an invalid address. Reopen it from the console.');
  }
  return url;
}

/** The address bar stays on /voice-space; no console bearer crosses the frame. */
export function VoiceSpace() {
  const { ready, isLoggedIn, user } = useAuth();
  return <>
    <LoginOverlay />
    {!ready && <p role="status">Connecting…</p>}
    {ready && isLoggedIn && user && <AuthenticatedVoiceSpace key={user.username} />}
  </>;
}

function AuthenticatedVoiceSpace() {
  const open = useOpenAddonUi();
  const [frame, setFrame] = useState<{ url: string; origin: string } | null>(null);
  const [error, setError] = useState('');
  // Account changes/logouts unmount the iframe immediately. A fresh page or
  // reload requires a fresh handoff; one-use codes are never persisted.
  async function start() {
    setError('');
    setFrame(null);
    try {
      const url = voiceFrameUrl(await open.mutateAsync('pai-voice'), window.location);
      setFrame({ url: url.href, origin: url.origin });
    } catch (e) {
      setError((e as Error).message || 'Voice Space could not open.');
    }
  }
  return <>
    <main style={{ height: '100dvh', display: 'flex', flexDirection: 'column' }}>
      <nav aria-label="Voice Space" style={{ display: 'flex', gap: 16, alignItems: 'center', padding: 12 }}>
        <a href="/">Noomesh</a>
        <strong>Voice Space</strong>
        <button type="button" onClick={() => void start()} disabled={open.isPending}>
          {open.isPending ? 'Opening…' : frame ? 'Reconnect' : 'Open voice'}
        </button>
      </nav>
      {error && <p role="alert">{error}</p>}
      {frame && <iframe title="Voice workspace" src={frame.url}
        allow={`microphone ${frame.origin}; autoplay ${frame.origin}`}
        sandbox="allow-scripts allow-same-origin allow-forms allow-downloads"
        referrerPolicy="no-referrer" style={{ width: '100%', flex: 1, border: 0 }} />}
    </main>
  </>;
}
