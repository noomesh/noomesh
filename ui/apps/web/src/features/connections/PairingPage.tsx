// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 PersonifAI LLC
import { useEffect, useRef, useState } from 'react';
import { useAuth, useMetisClient } from '@metis/core';
import type { components } from '@metis/api';
import { LoginOverlay } from '@/components/LoginOverlay';
import { rememberPairing, takePairingReturn } from './pairingReturn';
import './connections.css';

export function PairingPage() {
  const { user, isLoggedIn } = useAuth();
  const client = useMetisClient();
  const [code, setCode] = useState('');
  const [preview, setPreview] = useState<components['schemas']['ConnectionPairingPreview'] | null>(null);
  const [busy, setBusy] = useState(false);
  const [done, setDone] = useState(false);
  const [error, setError] = useState('');
  const completionStarted = useRef(false);

  useEffect(() => { setPreview(null); }, [user?.username]);

  useEffect(() => {
    if (!user || completionStarted.current) return;
    let returned: ReturnType<typeof takePairingReturn>;
    try { returned = takePairingReturn(user.username); }
    catch (e) { setError((e as Error).message); return; }
    if (!returned) return;
    completionStarted.current = true;
    setBusy(true);
    const { pending, result } = returned;
    void (async () => {
      try {
        if (result.error) throw new Error('Access was declined. Start a new pairing from your terminal when ready.');
        const response = await client.POST('/api/connections/oauth/complete', {
          body: { session_id: pending.session_id, completion_token: pending.completion_token, state: pending.state, code: result.code! },
        });
        if (response.error || !response.data) throw new Error('Unable to finish connecting. Start a new pairing from your terminal.');
        setDone(true);
      } catch (e) { setError((e as Error).message); }
      finally {
        setBusy(false);
        void client.POST('/api/connections/oauth/cancel', { body: { session_id: pending.session_id } }).catch(() => {});
      }
    })();
  }, [client, user]);

  async function lookup(event: React.FormEvent) {
    event.preventDefault(); setError(''); setBusy(true);
    try {
      const response = await client.POST('/api/connections/pairing/lookup', { body: { code } });
      if (response.error || !response.data) throw new Error('Code not found, expired, or already used. Check the code and sign in to the same Noomesh account as the terminal.');
      setPreview(response.data);
    } catch (e) { setError((e as Error).message); }
    finally { setBusy(false); }
  }
  async function approve() {
    if (!user) return;
    setBusy(true); setError('');
    let session: components['schemas']['ConnectionOAuthSession'] | undefined;
    try {
      const response = await client.POST('/api/connections/pairing/approve', { body: { code } });
      if (response.error || !response.data) throw new Error('This request expired or was cancelled. Start a new pairing from the terminal.');
      session = response.data;
      // Full-page navigation works on phones without pop-ups or another app.
      window.location.assign(rememberPairing(session, user.username));
    } catch (e) {
      setError((e as Error).message); setBusy(false); setPreview(null);
      if (session) void client.POST('/api/connections/oauth/cancel', { body: { session_id: session.session_id } }).catch(() => {});
    }
  }
  async function decline() {
    if (!preview) return;
    setBusy(true); setError('');
    try {
      const response = await client.DELETE('/api/connections/pairing/{id}', { params: { path: { id: preview.id } } });
      if (response.error) throw new Error('Unable to cancel. Try again.');
      setPreview(null); setCode(''); setError('Pairing cancelled. Your terminal has been notified.');
    } catch (e) { setError((e as Error).message); }
    finally { setBusy(false); }
  }
  return <>
    <LoginOverlay />
    <main className="pairing-page">
      <h1>Connect an account</h1>
      {done ? <p role="status">Account connected. You can close this page and return to your terminal.</p> : <>
        <p>Signed in to Noomesh as <strong>{user?.username || '…'}</strong>. Use the same Noomesh account as your terminal.</p>
        {error && <p role="alert">{error}</p>}
        {busy ? <p role="status">{completionStarted.current ? 'Finishing your connection…' : 'Please wait…'}</p> : preview ? <>
          <h2>Approve this request?</h2>
          <p>Device: <strong>{preview.device_name}</strong></p>
          <p>Integration: <strong>{preview.provider === 'google' ? 'Google' : preview.provider}</strong></p>
          <p>Requested access: {preview.services.map(s => s === 'google_drive' ? 'Google Drive (read only)' : s === 'gmail' ? 'Gmail (read only)' : s).join(', ')}.</p>
          <p>Continue only if you started this request. You will choose an account and approve access with the provider.</p>
          <div className="pairing-actions"><button type="button" onClick={approve}>Continue to {preview.provider === 'google' ? 'Google' : preview.provider}</button><button type="button" onClick={decline}>Cancel request</button></div>
        </> : <form onSubmit={lookup}>
          <label htmlFor="pairing-code">Pairing code from your terminal</label>
          <input id="pairing-code" value={code} onChange={e => setCode(e.target.value)} placeholder="ABCDE-FGHJK" autoComplete="off" autoCapitalize="characters" spellCheck={false} maxLength={32} required disabled={!isLoggedIn} />
          <button type="submit" disabled={!isLoggedIn}>Review request</button>
          <p>Codes expire after 10 minutes. Your Google browser login stays on this device; Noomesh stores the connection on your controller.</p>
        </form>}
      </>}
    </main>
  </>;
}
