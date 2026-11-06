// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 PersonifAI LLC

import { useEffect, useState } from 'react';
import { useAuth } from '@metis/core';
import { LoginOverlay } from '@/components/LoginOverlay';
import { useOpenAddonUi, useAddonUis } from './useAddonUis';

/** Never embed a console-origin document or a foreign host from a handoff. */
export function addonFrameUrl(value: string, here: Location): URL {
  const url = new URL(value);
  if (url.protocol !== 'https:' || url.hostname !== here.hostname || url.origin === here.origin
      || url.username || url.password || url.pathname !== '/__noo/session' || url.hash
      || url.searchParams.getAll('code').length !== 1 || !url.searchParams.get('code') || [...url.searchParams.keys()].some((key) => key !== 'code')) {
    throw new Error('Workspace returned an invalid address. Reopen it from the console.');
  }
  return url;
}

/** A signed console entry; no console bearer crosses the frame. */
export function AddonSpace() {
  const { ready, isLoggedIn, user } = useAuth();
  const addon = document.querySelector<HTMLMetaElement>('meta[name="noo-addon-space"]')?.content;
  return <>
    <LoginOverlay />
    {!ready && <p role="status">Connecting…</p>}
    {ready && isLoggedIn && user && (addon
      ? <AuthenticatedAddonSpace key={user.username} addon={addon} />
      : <p role="status">No add-on workspace is configured.</p>)}
  </>;
}

function AuthenticatedAddonSpace({ addon }: { addon: string }) {
  const open = useOpenAddonUi();
  const list = useAddonUis();
  const ui = list.data?.find((entry) => entry.addon === addon);
  const canOpen = !!ui?.canOpen && ui.consolePath === window.location.pathname;
  const title = ui?.title ?? 'Workspace';
  const [frame, setFrame] = useState<{ url: string; origin: string } | null>(null);
  const [error, setError] = useState('');
  useEffect(() => {
    if (!canOpen) setFrame(null);
  }, [canOpen]);
  useEffect(() => {
    const blocked = (event: SecurityPolicyViolationEvent) => {
      if (event.effectiveDirective === 'frame-src' || event.effectiveDirective === 'child-src') {
        setError('The console Content Security Policy blocks this workspace. Ask the operator to allow its isolated origin in frame-src.');
        setFrame(null);
      }
    };
    document.addEventListener('securitypolicyviolation', blocked);
    return () => document.removeEventListener('securitypolicyviolation', blocked);
  }, []);
  // Account changes/logouts unmount the iframe immediately. A fresh page or
  // reload requires a fresh handoff; one-use codes are never persisted.
  async function start() {
    if (!canOpen) return;
    setError('');
    setFrame(null);
    try {
      const url = addonFrameUrl(await open.mutateAsync(addon), window.location);
      setFrame({ url: url.href, origin: url.origin });
    } catch (e) {
      setError((e as Error).message || 'Workspace could not open.');
    }
  }
  return <>
    <main style={{ height: '100dvh', display: 'flex', flexDirection: 'column' }}>
      <nav aria-label={title} style={{ display: 'flex', gap: 16, alignItems: 'center', padding: 12 }}>
        <a href="/">Noomesh</a>
        <strong>{title}</strong>
        <button type="button" onClick={() => void start()} disabled={!canOpen || open.isPending}>
          {open.isPending ? 'Opening…' : frame ? 'Reconnect' : 'Open'}
        </button>
      </nav>
      {!ui && <p role="status">{list.isLoading ? 'Loading workspace…' : 'This workspace is unavailable to your account.'}</p>}
      {ui && !canOpen && <p role="status">Your account cannot open this workspace.</p>}
      {error && <p role="alert">{error}</p>}
      {frame && canOpen && <iframe title={title} src={frame.url}
        allow={(ui?.framePermissions ?? []).map((permission) => `${permission} ${frame.origin}`).join('; ')}
        sandbox="allow-scripts allow-same-origin allow-forms allow-downloads"
        referrerPolicy="no-referrer" style={{ width: '100%', flex: 1, border: 0 }} />}
    </main>
  </>;
}
