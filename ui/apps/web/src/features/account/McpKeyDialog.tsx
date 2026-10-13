// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 PersonifAI LLC

import { useState } from 'react';
import * as AlertDialog from '@radix-ui/react-alert-dialog';
import { toast } from 'sonner';
import { useAuth } from '@metis/core';
import { Button } from '@/components/ui/button';
import { Input } from '@/components/ui/input';
import { useMcpKeyStatus, useIssueMcpKey, useRevokeMcpKey } from './useMcpKey';

/**
 * Self-service MCP key management for the logged-in account.
 *
 * The key is a bearer form of the caller's own account — the gateway derives
 * the consumer and the bound user from the JWT, and pins the scope set — so
 * this is exposed to every tier, not just operators.
 *
 * The raw key is returned exactly once and only its hash is stored. That
 * shapes the whole component:
 *
 *  - the key lives in local state, never in the query cache, so a background
 *    refetch cannot replace it while the user is mid-copy;
 *  - while it is on screen the dialog refuses Esc and outside-click, because
 *    a stray click would destroy the only copy in existence;
 *  - re-issuing is presented as ROTATION, since it silently invalidates the
 *    previous key and any client still configured with it.
 */
export function McpKeyDialog({ open, onOpenChange }: { open: boolean; onOpenChange: (o: boolean) => void }) {
  const { user } = useAuth();
  const status = useMcpKeyStatus();
  const issue = useIssueMcpKey();
  const revoke = useRevokeMcpKey();
  const [note, setNote] = useState('');
  const [issued, setIssued] = useState<string | null>(null);

  const close = () => {
    setIssued(null); // the key is gone from the app the moment this closes
    setNote('');
    onOpenChange(false);
  };

  const doIssue = async () => {
    try {
      const r = await issue.mutateAsync({ note: note.trim() || undefined });
      setIssued(r.key);
      if (r.replacedActive > 0) toast.info('Your previous key was revoked.');
    } catch (e) {
      toast.error((e as Error).message);
    }
  };

  const doRevoke = async () => {
    try {
      const n = await revoke.mutateAsync();
      toast.success(n > 0 ? 'MCP key revoked.' : 'You had no active key.');
    } catch (e) {
      toast.error((e as Error).message);
    }
  };

  const copy = async () => {
    if (!issued) return;
    try {
      await navigator.clipboard.writeText(issued);
      toast.success('Key copied.');
    } catch {
      toast.error('Copy failed — select the key and copy it manually.');
    }
  };

  const snippet = issued
    ? JSON.stringify(
        {
          mcpServers: {
            metis: {
              type: 'http',
              url: `${window.location.origin}/mcp`,
              headers: { Authorization: `Bearer ${issued}` },
            },
          },
        },
        null,
        2,
      )
    : '';

  return (
    <AlertDialog.Root open={open} onOpenChange={(o) => !o && !issued && close()}>
      <AlertDialog.Portal>
        <AlertDialog.Overlay className="confirm-overlay" />
        <AlertDialog.Content
          className="confirm-content mcp-key-dialog"
          // AlertDialog already blocks outside-click (that is what separates it
          // from Dialog), so Esc is the only accidental dismissal left. Block
          // it too while the one-time key is on screen: a reflexive Esc would
          // destroy the only copy that exists.
          onEscapeKeyDown={(e) => {
            if (issued) e.preventDefault();
          }}
        >
          <AlertDialog.Title className="confirm-title">MCP key</AlertDialog.Title>

          {issued ? (
            <>
              <AlertDialog.Description className="confirm-desc">
                Copy this now — it is shown <b>once</b>. Noomesh stores only a hash, so it cannot be
                shown again; losing it means issuing a new one.
              </AlertDialog.Description>
              <pre className="mcp-key-value">{issued}</pre>
              <p className="mcp-key-hint">Add to your client&rsquo;s MCP config:</p>
              <pre className="mcp-key-snippet">{snippet}</pre>
              <div className="confirm-actions">
                <Button size="sm" variant="outline" onClick={copy}>
                  Copy key
                </Button>
                <Button size="sm" onClick={close}>
                  Done
                </Button>
              </div>
            </>
          ) : (
            <>
              <AlertDialog.Description className="confirm-desc">
                Connects an MCP client (Claude Code, and others) to Noomesh as{' '}
                <b>{user?.username ?? 'you'}</b>. The key carries your account: tool calls run with
                your scopes and knowledge-base access, and nothing more.
              </AlertDialog.Description>

              {status.isLoading ? (
                <p className="mcp-key-hint">Checking…</p>
              ) : status.data?.active ? (
                <div className="mcp-key-status">
                  <div>
                    <b>Active key</b>
                    {status.data.note ? ` · ${status.data.note}` : ''}
                  </div>
                  <div className="dim">
                    Issued {fmt(status.data.createdAt)} · last used{' '}
                    {status.data.lastUsedAt ? fmt(status.data.lastUsedAt) : 'never'}
                  </div>
                </div>
              ) : (
                <p className="mcp-key-hint">You have no active key.</p>
              )}

              <Input
                placeholder="Label (optional) — e.g. work laptop"
                value={note}
                onChange={(e) => setNote(e.target.value)}
              />

              <div className="confirm-actions">
                <Button size="sm" variant="outline" onClick={close}>
                  Close
                </Button>
                {status.data?.active && (
                  <Button size="sm" variant="destructive" onClick={doRevoke} disabled={revoke.isPending}>
                    Revoke
                  </Button>
                )}
                <Button size="sm" onClick={doIssue} disabled={issue.isPending}>
                  {issue.isPending ? 'Issuing…' : status.data?.active ? 'Replace key' : 'Issue key'}
                </Button>
              </div>
              {status.data?.active && (
                <p className="mcp-key-warn">
                  Replacing revokes the current key immediately — any client still using it stops
                  working.
                </p>
              )}
            </>
          )}
        </AlertDialog.Content>
      </AlertDialog.Portal>
    </AlertDialog.Root>
  );
}

function fmt(iso: string): string {
  const d = new Date(iso);
  return isNaN(d.getTime()) ? '—' : d.toLocaleDateString();
}
