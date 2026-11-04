// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 PersonifAI LLC

import { useEffect, useState } from 'react';
import { toast } from 'sonner';
import { relTime } from '@/lib/format';
import { StatusBadge } from '@/components/StatusBadge';
import { Button } from '@/components/ui/button';
import { Input } from '@/components/ui/input';
import { useConfirm } from '@/components/ConfirmDialog';
import {
  useAccessAddons,
  useAddonAccess,
  usePersonAccess,
  useSetAddonAccess,
  type AccessFeature,
  type AccessSetting,
  type AccessView,
  type SetValue,
} from './useAddonAccess';

/** `role:user`, `team:ops`, `user:alice`, `key:svc`: the gateway parses it; this only says what is expected. */
const SUBJECT_HINT = 'role:user · team:<name> · user:<account> · key:<consumer>';

/** The settings for one feature, most specific first, as `decide` reads them. */
export function settingsFor(view: AccessView, feature: string): AccessSetting[] {
  const order = (s: string) => (s.startsWith('key:') || s.startsWith('user:') ? 0 : s.startsWith('team:') ? 1 : 2);
  return view.settings.filter((s) => s.feature === feature).sort((a, b) => order(a.subject) - order(b.subject) || a.subject.localeCompare(b.subject));
}

/**
 * Add-on access: per add-on, the features it declares, every on/off setting
 * with who set it and why, a form to change one, and "who decided" for one
 * person. Operator or above reads; the gateway lets only an admin write, and
 * only a super admin change a setting that covers admins.
 */
export function AddonAccessPanel() {
  const addons = useAccessAddons();
  const [addon, setAddon] = useState<string | null>(null);
  useEffect(() => {
    if (!addon && addons.data?.length) setAddon(addons.data[0]);
  }, [addon, addons.data]);
  const view = useAddonAccess(addon);

  return (
    <section className="panel">
      <div className="panel-head">
        <h2>Add-on access</h2>
        <span className="meta">{view.isFetching ? 'refreshing…' : 'who may use each feature'}</span>
      </div>
      {addons.isLoading && <div className="state">Loading add-ons…</div>}
      {addons.isError && <div className="state err">{(addons.error as Error)?.message}</div>}
      {addons.data && !addons.data.length && <div className="state">No add-on is enabled.</div>}
      {addons.data && addons.data.length > 0 && (
        <div className="addon-access-pick" role="tablist" aria-label="Add-on">
          {addons.data.map((a) => (
            <Button key={a} size="sm" variant={a === addon ? 'default' : 'outline'} role="tab" aria-selected={a === addon} onClick={() => setAddon(a)}>
              {a}
            </Button>
          ))}
        </div>
      )}
      {view.isLoading && addon && <div className="state">Loading {addon}…</div>}
      {view.isError && <div className="state err">{(view.error as Error)?.message}</div>}
      {view.data && <AccessBody view={view.data} />}
    </section>
  );
}

function AccessBody({ view }: { view: AccessView }) {
  if (view.legacy) {
    return (
      <div className="state">
        {view.addon} declares no features yet. Its routes keep their own role gates until it ships a manifest with features.
      </div>
    );
  }
  return (
    <>
      <div className="meta">
        Super admins: {view.superAdmins.length ? view.superAdmins.join(', ') : 'none named (every admin acts as one)'}
      </div>
      {view.features.map((f) => (
        <FeatureBlock key={f.name} view={view} feature={f} />
      ))}
      {view.staleFeatures.length > 0 && (
        <div className="state">
          Kept settings for features {view.addon} no longer declares (they open nothing): {[...new Set(view.staleFeatures)].join(', ')}
        </div>
      )}
      <SetAccessForm view={view} />
      <WhoDecided view={view} />
    </>
  );
}

function FeatureBlock({ view, feature: f }: { view: AccessView; feature: AccessFeature }) {
  const set = useSetAddonAccess();
  const confirm = useConfirm();
  const rows = settingsFor(view, f.name);

  async function onClear(s: AccessSetting) {
    const ok = await confirm({
      title: `Clear ${s.subject} on ${f.title}?`,
      description: `${s.subject} goes back to inheriting from the next broader setting.`,
      confirmText: 'Clear',
    });
    if (!ok) return;
    set.mutate(
      { addon: view.addon, feature: f.name, subject: s.subject, value: 'inherit' },
      {
        onSuccess: () => toast.success('Setting cleared', { description: `${f.name} · ${s.subject}` }),
        onError: (e) => toast.error('Not changed', { description: e.message }),
      },
    );
  }

  return (
    <div className="addon-access-feature">
      <h3 className="subhead">
        {f.title} <span className="meta">{view.addon}:{f.name}</span>
      </h3>
      {f.description && <div className="meta">{f.description}</div>}
      <div className="addon-access-tags">
        <StatusBadge tone="neutral">suggested: {f.suggested || 'none'}</StatusBadge>
        {f.ui && <StatusBadge tone="neutral">web UI</StatusBadge>}
        {f.delegate && <StatusBadge tone="neutral">acts through tasks</StatusBadge>}
        {f.hasUnscopedWrite && <StatusBadge tone="warn">writes not owner-scoped</StatusBadge>}
        {f.routes.length > 0 && <span className="meta">routes: {f.routes.join(', ')}</span>}
      </div>
      {rows.length ? (
        <div className="cache-list">
          {rows.map((s) => (
            <div className="cache-row" key={s.subject}>
              <span className="cache-name">
                <StatusBadge tone={s.allowed ? 'good' : 'bad'}>{s.allowed ? 'on' : 'off'}</StatusBadge> {s.subject}
              </span>
              <span className="cache-meta">
                {s.setBy || '?'}
                {s.setAt ? ` · ${relTime(s.setAt)} ago` : ''}
                {s.source && s.source !== 'operator' ? ` · ${s.source}` : ''}
                {s.reason ? ` · “${s.reason}”` : ''}
              </span>
              <Button
                size="sm"
                variant="outline"
                disabled={set.isPending}
                onClick={() => onClear(s)}
                title="Remove this setting; the subject inherits again"
              >
                Clear
              </Button>
            </div>
          ))}
        </div>
      ) : (
        <div className="state">No settings: nobody below a super admin may use it until one is turned on.</div>
      )}
    </div>
  );
}

function SetAccessForm({ view }: { view: AccessView }) {
  const set = useSetAddonAccess();
  const [feature, setFeature] = useState(view.features[0]?.name ?? '');
  const [subject, setSubject] = useState('');
  const [value, setValue] = useState<SetValue>('on');
  const [reason, setReason] = useState('');
  useEffect(() => {
    if (!view.features.some((f) => f.name === feature)) setFeature(view.features[0]?.name ?? '');
  }, [view, feature]);

  function onSubmit(e: React.FormEvent) {
    e.preventDefault();
    if (!feature || !subject.trim()) return;
    set.mutate(
      { addon: view.addon, feature, subject: subject.trim(), value, reason },
      {
        onSuccess: (r) => {
          toast.success(`${feature} · ${subject.trim()}: ${r.from} → ${r.to}`);
          setReason('');
        },
        onError: (err) => toast.error('Not changed', { description: err.message }),
      },
    );
  }

  return (
    <form className="addon-access-form" onSubmit={onSubmit}>
      <h3 className="subhead">Set access</h3>
      <label>
        Feature
        <select value={feature} onChange={(e) => setFeature(e.target.value)}>
          {view.features.map((f) => (
            <option key={f.name} value={f.name}>
              {f.title} ({f.name})
            </option>
          ))}
        </select>
      </label>
      <label>
        Subject
        <Input value={subject} onChange={(e) => setSubject(e.target.value)} placeholder={SUBJECT_HINT} aria-label="Subject" />
      </label>
      <label>
        Value
        <select value={value} onChange={(e) => setValue(e.target.value as SetValue)}>
          <option value="on">on</option>
          <option value="off">off</option>
          <option value="inherit">inherit (clear)</option>
        </select>
      </label>
      <label>
        Reason
        <Input
          value={reason}
          onChange={(e) => setReason(e.target.value)}
          placeholder={value === 'off' ? 'required when turning a feature off' : 'optional'}
          aria-label="Reason"
        />
      </label>
      <Button type="submit" size="sm" disabled={set.isPending || !feature || !subject.trim()}>
        {set.isPending ? 'Saving…' : 'Save'}
      </Button>
    </form>
  );
}

function WhoDecided({ view }: { view: AccessView }) {
  const [draft, setDraft] = useState('');
  const [account, setAccount] = useState('');
  const person = usePersonAccess(view.addon, account);
  return (
    <div className="addon-access-who">
      <h3 className="subhead">Who decided</h3>
      <form
        className="addon-access-form"
        onSubmit={(e) => {
          e.preventDefault();
          setAccount(draft.trim());
        }}
      >
        <Input value={draft} onChange={(e) => setDraft(e.target.value)} placeholder="account name" aria-label="Account" />
        <Button type="submit" size="sm" variant="outline" disabled={!draft.trim()}>
          Check
        </Button>
      </form>
      {person.isLoading && account && <div className="state">Checking {account}…</div>}
      {person.isError && <div className="state err">{(person.error as Error)?.message}</div>}
      {person.data && (
        <>
          <div className="meta">
            {person.data.account} · {person.data.role ?? 'no role'}
            {person.data.teams.length ? ` · teams ${person.data.teams.join(', ')}` : ''}
            {person.data.superAdmin ? ' · super admin' : ''}
          </div>
          <div className="cache-list">
            {person.data.features.map((f) => (
              <div className="cache-row" key={f.feature}>
                <span className="cache-name">
                  <StatusBadge tone={f.allowed ? 'good' : 'bad'}>{f.allowed ? 'allowed' : 'refused'}</StatusBadge> {f.title}
                </span>
                <span className="cache-meta">decided by {f.decidedBy || '?'}</span>
              </div>
            ))}
          </div>
        </>
      )}
    </div>
  );
}
