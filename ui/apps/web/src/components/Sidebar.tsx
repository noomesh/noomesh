// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 PersonifAI LLC

import { useState } from 'react';
import { useAuth } from '@metis/core';
import { cn } from '@/lib/utils';
import { NAV, ICONS, type NavItem } from '@/shell/nav';
import { UserMenu } from '@/components/UserMenu';
import { useClusterNodes } from '@/features/cluster/useClusterNodes';

export function Sidebar({ active, onSelect }: { active: string; onSelect: (id: string) => void }) {
  const { isOperator } = useAuth();
  // Shared query key with the Cluster tab — no extra polling.
  const cluster = useClusterNodes();
  // Only read after the isLoading/isError branches below; 0 here is the "nothing yet" layout default.
  const online = cluster.data?.stats.online ?? 0;

  // Groups start open. They used to start collapsed, which meant a fresh
  // install showed two tabs and four unlabelled headers — the whole console
  // looked empty to someone seeing it for the first time. At core-edition size
  // (14 tabs) the list is longer than it was but still short enough that
  // hiding it saves little. Collapsing is still there for anyone who wants it.
  const [open, setOpen] = useState<Record<string, boolean>>(() =>
    Object.fromEntries(NAV.filter((s) => s.group).map((s) => [s.group!, true])),
  );
  const toggle = (g: string) => setOpen((o) => ({ ...o, [g]: !o[g] }));

  // Operator-only tabs are hidden for non-operators (the backend enforces
  // scopes too). Note `admin` is a CORE tab since 2026-08-27, so this gate now
  // runs in the open-source build as well — a non-operator on an OSS install
  // sees 13 tabs, not 14.
  const OPERATOR_TABS = ['admin', 'model-prefs', 'skills', 'traffic'];
  const visible = (item: NavItem) => !OPERATOR_TABS.includes(item.id) || isOperator;

  const renderBtn = (item: NavItem) => (
    <button
      key={item.id}
      className={cn(active === item.id && 'active', item.status === 'soon' && 'soon-item')}
      onClick={() => onSelect(item.id)}
    >
      <svg viewBox="0 0 20 20">{ICONS[item.id]}</svg>
      <span className="label">{item.label}</span>
      {item.status === 'soon' && <span className="soon">soon</span>}
    </button>
  );

  return (
    <aside className="side">
      <div className="side-brand">
        <div className="name">Noomesh</div>
        {/* Was hardcoded "mesh online", which claimed a healthy mesh on a fresh
            install with nothing enrolled. Report what is actually there. */}
        <div className={cn('stat', !online && 'idle')}>
          {cluster.isLoading
            ? 'connecting…'
            : cluster.isError
              ? 'gateway unreachable'
              : online
                ? `${online} node${online === 1 ? '' : 's'} online`
                : 'no nodes yet'}
        </div>
      </div>
      <nav className="nav">
        {NAV.map((section, i) => {
          const items = section.items.filter(visible);
          if (!items.length) return null;
          return section.group ? (
            <div key={section.group} className={cn('nav-group', !open[section.group] && 'collapsed')}>
              <button className="nav-group-header" onClick={() => toggle(section.group!)}>
                <span>{section.group}</span>
                <span className="chev">▾</span>
              </button>
              <div className="nav-group-items">{items.map(renderBtn)}</div>
            </div>
          ) : (
            <div key={`primary-${i}`} className="nav-primary">
              {items.map(renderBtn)}
            </div>
          );
        })}
      </nav>
      <div className="side-foot">
        <UserMenu />
      </div>
    </aside>
  );
}
