// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 PersonifAI LLC

import { useState } from 'react';
import { toast } from 'sonner';
import { Button } from '@/components/ui/button';
import { Input } from '@/components/ui/input';
import { StatusBadge } from '@/components/StatusBadge';
import { useConfirm } from '@/components/ConfirmDialog';
import {
  useConnections,
  useConnectionActions,
  type Account,
  type Source,
  type SourcePolicy,
} from './useConnections';
import './connections.css';

export function policyDescription(policy: SourcePolicy): string {
  if (policy.kind === 'gmail') {
    const selection =
      policy.exposure === 'mailbox'
        ? 'Mailbox'
        : policy.label_ids?.length
          ? `${policy.label_ids.length} selected labels`
          : 'Choose labels after sign-in';
    return `${selection} · past ${policy.lookback_days ?? 30} days`;
  }
  if (policy.exposure === 'all_accessible') return 'All accessible Drive files';
  if (policy.exposure === 'selected_drive') return 'One selected drive';
  return policy.folder_ids?.length
    ? `${policy.folder_ids.length} selected folders`
    : 'Choose folders after sign-in';
}

export function ConnectionsPanel() {
  const query = useConnections();
  const { addAccount, addSource, removeAccount, removeSource } =
    useConnectionActions();
  const confirm = useConfirm();
  const [showAccountForm, setShowAccountForm] = useState(false);
  const [accountLabel, setAccountLabel] = useState('');
  const [email, setEmail] = useState('');
  const [sourceAccount, setSourceAccount] = useState<string | null>(null);
  const [sourceName, setSourceName] = useState('');
  const [kind, setKind] = useState<'google_drive' | 'gmail'>('google_drive');
  const [exposure, setExposure] = useState('selected');
  const [lookback, setLookback] = useState(30);
  const busy =
    addAccount.isPending ||
    addSource.isPending ||
    removeAccount.isPending ||
    removeSource.isPending;
  const report = (error: Error) => toast.error(error.message);

  function saveAccount(e: React.FormEvent) {
    e.preventDefault();
    addAccount.mutate(
      { label: accountLabel.trim(), email_hint: email.trim() || null },
      {
        onSuccess: () => {
          setAccountLabel('');
          setEmail('');
          setShowAccountForm(false);
          toast.success('Account draft saved');
        },
        onError: report,
      },
    );
  }

  function saveSource(e: React.FormEvent) {
    e.preventDefault();
    if (!sourceAccount) return;
    const policy: SourcePolicy =
      kind === 'gmail'
        ? {
            kind: 'gmail',
            exposure: exposure === 'all' ? 'mailbox' : 'selected_labels',
            label_ids: [],
            lookback_days: lookback,
          }
        : {
            kind: 'google_drive',
            exposure:
              exposure === 'all'
                ? 'all_accessible'
                : exposure === 'drive'
                  ? 'selected_drive'
                  : 'selected_folders',
            folder_ids: [],
          };
    addSource.mutate(
      {
        account_id: sourceAccount,
        name:
          sourceName.trim() || (kind === 'gmail' ? 'Gmail' : 'Google Drive'),
        policy,
      },
      {
        onSuccess: () => {
          setSourceAccount(null);
          toast.success('Source draft saved');
        },
        onError: report,
      },
    );
  }

  async function deleteAccount(account: Account) {
    if (
      await confirm({
        title: `Remove ${account.label}?`,
        description: 'Removes this account draft and all of its source drafts.',
        confirmText: 'Remove draft',
        destructive: true,
      })
    ) {
      removeAccount.mutate(account.id, {
        onError: report,
        onSuccess: () => {
          if (sourceAccount === account.id) setSourceAccount(null);
        },
      });
    }
  }

  async function deleteSource(source: Source) {
    if (
      await confirm({
        title: `Remove ${source.name}?`,
        confirmText: 'Remove draft',
        destructive: true,
      })
    ) {
      removeSource.mutate(source.id, { onError: report });
    }
  }

  return (
    <section className="panel connections-panel">
      <div className="panel-head">
        <h2>Connections</h2>
        <Button
          size="sm"
          disabled={!query.data || busy}
          onClick={() => setShowAccountForm(true)}
        >
          Add Google account
        </Button>
      </div>
      <p className="connections-intro">
        Keep work and personal accounts together here. Each account can have
        several Drive and Gmail sources. Your drafts are private to you.
      </p>
      {query.isLoading && (
        <div className="state">Loading your connections…</div>
      )}
      {query.isError && (
        <div className="state" role="alert">
          Unable to load your connections.{' '}
          <Button size="sm" variant="outline" onClick={() => query.refetch()}>
            Try again
          </Button>
        </div>
      )}
      {query.data && (
        <>
          <div className="connections-notice" role="status">
            <strong>Prepare your connections</strong>
            <p>
              {query.data.providers.find((p) => p.id === 'google')
                ?.authorization_detail ??
                'Google sign-in is not available yet. Your saved drafts do not access Google data.'}
            </p>
          </div>
          {showAccountForm && (
            <form className="connections-form" onSubmit={saveAccount}>
              <h3>Add an account draft</h3>
              <label>
                Account name
                <Input
                  value={accountLabel}
                  onChange={(e) => setAccountLabel(e.target.value)}
                  placeholder="Work or Personal"
                  maxLength={100}
                  required
                />
              </label>
              <label>
                Google email (optional)
                <Input
                  type="email"
                  value={email}
                  onChange={(e) => setEmail(e.target.value)}
                  placeholder="you@example.com"
                  maxLength={254}
                />
              </label>
              <p className="connections-detail">
                This is a reminder of which account to sign into. Google will
                confirm the account when sign-in becomes available.
              </p>
              <div className="connections-actions">
                <Button size="sm" disabled={busy || !accountLabel.trim()}>
                  Save account draft
                </Button>
                <Button
                  type="button"
                  size="sm"
                  variant="outline"
                  disabled={busy}
                  onClick={() => setShowAccountForm(false)}
                >
                  Cancel
                </Button>
              </div>
            </form>
          )}
          {query.data.accounts.length === 0 && !showAccountForm && (
            <div className="state">
              Add your first Google account draft to prepare Drive or Gmail
              sources.
            </div>
          )}
          <div className="connections-accounts">
            {query.data.accounts.map((account) => (
              <article
                key={account.id}
                className="connection-account"
                aria-label={account.label}
              >
                <div className="connection-account-head">
                  <div>
                    <h3>{account.label}</h3>
                    {account.email_hint && (
                      <p className="connections-detail">
                        {account.email_hint} · unverified
                      </p>
                    )}
                  </div>
                  <StatusBadge tone="warn">Needs sign-in</StatusBadge>
                </div>
                <div className="connections-actions">
                  <Button
                    size="sm"
                    variant="outline"
                    disabled
                    title="Google sign-in is not available yet"
                  >
                    Sign in with Google
                  </Button>
                  <Button
                    size="sm"
                    variant="outline"
                    disabled={busy}
                    onClick={() => {
                      setSourceAccount(account.id);
                      setSourceName('');
                      setKind('google_drive');
                      setExposure('selected');
                      setLookback(30);
                    }}
                  >
                    Add source
                  </Button>
                  <Button
                    size="sm"
                    variant="ghost"
                    disabled={busy}
                    onClick={() => deleteAccount(account)}
                  >
                    Remove account draft
                  </Button>
                </div>
                <ul className="connection-sources">
                  {query.data.sources
                    .filter((source) => source.account_id === account.id)
                    .map((source) => (
                      <li key={source.id}>
                        <div>
                          <strong>{source.name}</strong>
                          <p className="connections-detail">
                            {source.policy.kind === 'gmail'
                              ? 'Gmail'
                              : 'Google Drive'}{' '}
                            · {policyDescription(source.policy)}
                          </p>
                          <p className="connections-detail">
                            Draft · Private · Read only
                          </p>
                        </div>
                        <Button
                          size="sm"
                          variant="ghost"
                          disabled={busy}
                          aria-label={`Remove ${source.name} draft`}
                          onClick={() => deleteSource(source)}
                        >
                          Remove
                        </Button>
                      </li>
                    ))}
                </ul>
                {sourceAccount === account.id && (
                  <form className="connections-form" onSubmit={saveSource}>
                    <h4>Add a source to {account.label}</h4>
                    <label>
                      Service
                      <select
                        className="op-select"
                        value={kind}
                        onChange={(e) => {
                          setKind(e.target.value as typeof kind);
                          setExposure('selected');
                        }}
                      >
                        <option value="google_drive">Google Drive</option>
                        <option value="gmail">Gmail</option>
                      </select>
                    </label>
                    <label>
                      Source name (optional)
                      <Input
                        value={sourceName}
                        maxLength={100}
                        onChange={(e) => setSourceName(e.target.value)}
                        placeholder={
                          kind === 'gmail' ? 'Work mail' : 'Project documents'
                        }
                      />
                    </label>
                    <label>
                      Content to use
                      <select
                        className="op-select"
                        value={exposure}
                        onChange={(e) => setExposure(e.target.value)}
                      >
                        <option value="selected">
                          {kind === 'gmail'
                            ? 'Selected labels'
                            : 'Selected folders'}
                        </option>
                        {kind === 'google_drive' && (
                          <option value="drive">One selected drive</option>
                        )}
                        <option value="all">
                          {kind === 'gmail'
                            ? 'Mailbox'
                            : 'All accessible Drive files'}
                        </option>
                      </select>
                    </label>
                    {kind === 'gmail' && (
                      <label>
                        Mail history
                        <select
                          className="op-select"
                          value={lookback}
                          onChange={(e) => setLookback(Number(e.target.value))}
                        >
                          <option value={7}>Past 7 days</option>
                          <option value={30}>Past 30 days</option>
                          <option value={90}>Past 90 days</option>
                          <option value={365}>Past year</option>
                        </select>
                      </label>
                    )}
                    <p className="connections-detail">
                      {exposure !== 'all'
                        ? 'Choose the folders, drive or labels after signing in. '
                        : ''}
                      These settings describe what Noomesh will use. Google may
                      request broader account permissions during sign-in.
                    </p>
                    <div className="connections-actions">
                      <Button size="sm" disabled={busy}>
                        Save source draft
                      </Button>
                      <Button
                        type="button"
                        size="sm"
                        variant="outline"
                        disabled={busy}
                        onClick={() => setSourceAccount(null)}
                      >
                        Cancel
                      </Button>
                    </div>
                  </form>
                )}
              </article>
            ))}
          </div>
        </>
      )}
    </section>
  );
}
