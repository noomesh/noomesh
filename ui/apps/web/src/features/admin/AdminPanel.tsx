// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 PersonifAI LLC

import { toast } from 'sonner';
import { useAuth } from '@metis/core';
import { relTime } from '@/lib/format';
import { StatusBadge } from '@/components/StatusBadge';
import { Button } from '@/components/ui/button';
import { useAdmin, useSetFlag, type Flag } from './useAdmin';

export function AdminPanel() {
  const admin = useAdmin();
  const setFlag = useSetFlag();
  const { user } = useAuth();
  const pendingKey = setFlag.isPending ? setFlag.variables?.key : undefined;

  function onToggle(f: Flag) {
    setFlag.mutate(
      { key: f.key, value: !f.value },
      {
        onSuccess: () => toast.success(`${f.label} → ${!f.value ? 'ON' : 'OFF'}`),
        onError: (e) => toast.error('Set flag failed', { description: (e as Error).message }),
      },
    );
  }

  // Group flags by category
  const byCategory: Record<string, Flag[]> = {};
  for (const f of admin.data?.flags ?? []) (byCategory[f.category] ??= []).push(f);

  return (
    <section className="panel">
      <div className="panel-head">
        <h2>Admin</h2>
        <span className="meta">operator</span>
      </div>

      {admin.isLoading && <div className="state">Loading admin…</div>}
      {admin.isError && <div className="state err">{(admin.error as Error)?.message}</div>}

      {admin.data && (
        <>
          <h3 className="subhead">Users &amp; scopes</h3>
          {admin.data.users.map((u) => (
            <div className="user-row" key={u.username}>
              <div className="user-l">
                <span className="user-name">
                  {u.username}
                  {u.username === user?.username && <span className="user-you">you</span>}
                </span>
                <span className="user-scopes">
                  {u.scopes.map((s) => (
                    <span className="scope-chip" key={s}>
                      {s}
                    </span>
                  ))}
                </span>
              </div>
              <div className="user-r">
                <StatusBadge tone={u.disabled ? 'bad' : u.locked ? 'warn' : 'good'}>
                  {u.disabled ? 'disabled' : u.locked ? 'locked' : 'active'}
                </StatusBadge>
                <span className="user-login">{u.lastLogin ? `${relTime(u.lastLogin)} ago` : 'never'}</span>
              </div>
            </div>
          ))}

          <h3 className="subhead">Behavioral flags</h3>
          {Object.keys(byCategory)
            .sort()
            .map((cat) => (
              <div className="flag-group" key={cat}>
                <div className="flag-cat">{cat}</div>
                {byCategory[cat].map((f) => (
                  <div className="flag-row" key={f.key}>
                    <Button
                      size="sm"
                      variant={f.value ? 'default' : 'outline'}
                      disabled={pendingKey === f.key}
                      onClick={() => onToggle(f)}
                    >
                      {f.value ? 'ON' : 'OFF'}
                    </Button>
                    <div className="flag-main">
                      <span className="flag-label">{f.label}</span>
                      <span className="flag-help">{f.help}</span>
                    </div>
                    <span className="flag-source">[{f.source}]</span>
                  </div>
                ))}
              </div>
            ))}
        </>
      )}
    </section>
  );
}
