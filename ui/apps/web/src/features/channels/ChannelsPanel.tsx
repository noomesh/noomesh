// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 PersonifAI LLC

import { useState } from 'react';
import { toast } from 'sonner';
import { StatusBadge } from '@/components/StatusBadge';
import { Button } from '@/components/ui/button';
import { Input } from '@/components/ui/input';
import { useConfirm } from '@/components/ConfirmDialog';
import { dash, DASH } from '@/lib/num';
import {
  useChannels,
  useDeleteRecipient,
  useAddRecipient,
  useTestChannel,
  prettyChannel,
  type Recipient,
} from './useChannels';

const FALLBACK_CHANNELS = ['google_chat', 'telegram', 'whatsapp'];

export function ChannelsPanel() {
  const ch = useChannels();
  const del = useDeleteRecipient();
  const add = useAddRecipient();
  const test = useTestChannel();
  const confirm = useConfirm();
  const deletingId = del.isPending ? del.variables : undefined;

  const [arChannel, setArChannel] = useState('');
  const [arId, setArId] = useState('');
  const [arName, setArName] = useState('');
  const [arNotes, setArNotes] = useState('');
  const [arDefault, setArDefault] = useState(false);
  const [tChannel, setTChannel] = useState('');
  const [tRecipient, setTRecipient] = useState('');

  const channelOpts = ch.data?.adapters.length
    ? ch.data.adapters.map((a) => a.name)
    : FALLBACK_CHANNELS;

  function onAdd(e: React.FormEvent) {
    e.preventDefault();
    if (!arChannel || !arId.trim()) return;
    add.mutate(
      {
        channel: arChannel,
        recipientId: arId.trim(),
        displayName: arName.trim() || undefined,
        notes: arNotes.trim() || undefined,
        isDefault: arDefault,
      },
      {
        onSuccess: () => {
          toast.success('Recipient added', { description: arName.trim() || arId.trim() });
          setArId('');
          setArName('');
          setArNotes('');
          setArDefault(false);
        },
        onError: (err) => toast.error('Add failed', { description: (err as Error).message }),
      },
    );
  }

  function onTest(e: React.FormEvent) {
    e.preventDefault();
    if (!tChannel || !tRecipient.trim()) return;
    test.mutate(
      { channel: tChannel, recipient: tRecipient.trim() },
      {
        onSuccess: () => toast.success('Test message sent', { description: `${prettyChannel(tChannel)} → ${tRecipient.trim()}` }),
        onError: (err) => toast.error('Test failed', { description: (err as Error).message }),
      },
    );
  }

  async function onDelete(r: Recipient) {
    const ok = await confirm({
      title: `Delete "${r.displayName}"?`,
      description: `Removes the saved ${prettyChannel(r.channel)} recipient.`,
      confirmText: 'Delete',
      destructive: true,
    });
    if (!ok) return;
    del.mutate(r.id, {
      onSuccess: () => toast.success('Recipient deleted', { description: r.displayName }),
      onError: (e) => toast.error('Delete failed', { description: (e as Error).message }),
    });
  }

  return (
    <section className="panel">
      <div className="panel-head">
        <h2>Channels</h2>
        <span className="meta">
          {ch.data ? `${ch.data.summary.adapters} adapters · ${dash(ch.data.summary.activeConvos)} active · queue ${ch.data.summary.queueMode}` : '—'}
        </span>
      </div>

      {ch.isLoading && <div className="state">Loading channels…</div>}
      {ch.isError && <div className="state err">{(ch.error as Error)?.message}</div>}

      {ch.data && (
        <>
          {ch.data.adapters.length ? (
            <div className="adapter-grid">
              {ch.data.adapters.map((a) => (
                <div className="adapter" key={a.name}>
                  <div className="adapter-head">
                    <span className="adapter-name">{prettyChannel(a.name)}</span>
                    <StatusBadge tone="good">active</StatusBadge>
                  </div>
                  {a.received === null && a.sent === null && a.errors === null ? (
                    // Not measured: say so in the gateway's words, not as a bare dash.
                    <div className="adapter-stats" title={a.statsDetail ?? undefined}>
                      <span>{a.statsDetail ?? `traffic counters ${DASH}`}</span>
                    </div>
                  ) : (
                    <div className="adapter-stats">
                      <span>
                        recv <b>{dash(a.received)}</b>
                      </span>
                      <span>
                        sent <b>{dash(a.sent)}</b>
                      </span>
                      <span className={a.errors !== null && a.errors > 0 ? 'err' : undefined}>
                        errors <b>{dash(a.errors)}</b>
                      </span>
                    </div>
                  )}
                </div>
              ))}
            </div>
          ) : (
            <div className="state">No channel adapters registered.</div>
          )}

          <h3 className="subhead">Test a channel</h3>
          <form className="op-form" onSubmit={onTest}>
            <select className="op-select" value={tChannel} onChange={(e) => setTChannel(e.target.value)} aria-label="Test channel">
              <option value="">channel…</option>
              {channelOpts.map((c) => (
                <option key={c} value={c}>
                  {prettyChannel(c)}
                </option>
              ))}
            </select>
            <Input placeholder="recipient id" value={tRecipient} onChange={(e) => setTRecipient(e.target.value)} aria-label="Test recipient" />
            <Button size="sm" variant="outline" type="submit" disabled={test.isPending || !tChannel || !tRecipient.trim()}>
              {test.isPending ? 'Sending…' : 'Send test'}
            </Button>
          </form>

          <h3 className="subhead">Saved recipients</h3>
          <form className="op-form" onSubmit={onAdd}>
            <select className="op-select" value={arChannel} onChange={(e) => setArChannel(e.target.value)} aria-label="Recipient channel">
              <option value="">channel…</option>
              {channelOpts.map((c) => (
                <option key={c} value={c}>
                  {prettyChannel(c)}
                </option>
              ))}
            </select>
            <Input placeholder="recipient id" value={arId} onChange={(e) => setArId(e.target.value)} aria-label="Recipient id" />
            <Input placeholder="display name" value={arName} onChange={(e) => setArName(e.target.value)} aria-label="Display name" />
            <Input placeholder="notes (optional)" value={arNotes} onChange={(e) => setArNotes(e.target.value)} aria-label="Notes" />
            <label className="op-check">
              <input type="checkbox" checked={arDefault} onChange={(e) => setArDefault(e.target.checked)} /> default
            </label>
            <Button size="sm" type="submit" disabled={add.isPending || !arChannel || !arId.trim()}>
              {add.isPending ? 'Adding…' : 'Add recipient'}
            </Button>
          </form>
          {ch.data.recipients.length ? (
            ch.data.recipients.map((r) => (
              <div className="recipient-row" key={r.id}>
                <div className="recipient-main">
                  <div className="recipient-line1">
                    <span className="recipient-name">{r.displayName}</span>
                    <span className="recipient-ch">{prettyChannel(r.channel)}</span>
                    {r.isDefault && <StatusBadge tone="neutral">default</StatusBadge>}
                  </div>
                  <div className="recipient-meta">
                    {r.recipientId}
                    {r.notes ? ` · ${r.notes}` : ''}
                  </div>
                </div>
                <Button size="sm" variant="outline" disabled={deletingId === r.id} onClick={() => onDelete(r)}>
                  {deletingId === r.id ? '…' : 'Delete'}
                </Button>
              </div>
            ))
          ) : (
            <div className="state">No saved recipients.</div>
          )}
        </>
      )}
    </section>
  );
}
