// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 PersonifAI LLC

import { useState } from 'react';
import { toast } from 'sonner';
import { StatusBadge } from '@/components/StatusBadge';
import { Button } from '@/components/ui/button';
import { Input } from '@/components/ui/input';
import {
  useClearPreference,
  useDeclareSpace,
  useDeleteSpace,
  useModelPrefs,
  useSetPreference,
} from './useModelPrefs';
import {
  chatDefaultLine,
  parseSpaceForm,
  purposeRows,
  spaceRows,
  unmatchedWarning,
  type PurposeRow,
} from './modelPrefs';

function PurposeLine({ row, classNames }: { row: PurposeRow; classNames: string[] }) {
  const [draft, setDraft] = useState('');
  const [note, setNote] = useState<string | null>(null);
  const set = useSetPreference();
  const clear = useClearPreference();
  const listId = `mp-classes-${row.purpose}`;

  function onSet(e: React.FormEvent) {
    e.preventDefault();
    const target = draft.trim();
    if (!target) return;
    set.mutate(
      { alias: row.purpose, target },
      {
        onSuccess: (n) => {
          setNote(n);
          setDraft('');
          toast.success(`${row.purpose} now prefers ${target}`);
        },
        onError: (err) => toast.error('Set preference failed', { description: (err as Error).message }),
      },
    );
  }
  function onClear() {
    clear.mutate(row.purpose, {
      onSuccess: () => {
        setNote(null);
        toast.success(`${row.purpose} → any live chat node`);
      },
      onError: (err) => toast.error('Clear preference failed', { description: (err as Error).message }),
    });
  }

  return (
    <div className="cache-row" style={{ flexWrap: 'wrap', gap: 8 }}>
      <span className="cache-name">{row.purpose}</span>
      <span className="cache-meta">{row.text}</span>
      <StatusBadge tone={row.state === 'not served yet' ? 'warn' : 'good'}>{row.state}</StatusBadge>
      <form className="op-form" onSubmit={onSet} style={{ flex: '1 1 260px' }}>
        <Input
          list={listId}
          placeholder="class or model name"
          value={draft}
          onChange={(e) => setDraft(e.target.value)}
          aria-label={`Preferred class or model for ${row.purpose}`}
        />
        <datalist id={listId}>
          {classNames.map((c) => (
            <option key={c} value={c} />
          ))}
        </datalist>
        <Button size="sm" type="submit" disabled={set.isPending || !draft.trim()}>
          {set.isPending ? 'Saving…' : 'Set preference'}
        </Button>
        <Button
          size="sm"
          type="button"
          variant="outline"
          disabled={clear.isPending || row.target === null}
          onClick={onClear}
        >
          Clear
        </Button>
      </form>
      {note && <div className="state warn" style={{ flexBasis: '100%' }}>{note}</div>}
    </div>
  );
}

export function ModelPrefsPanel() {
  const q = useModelPrefs();
  const declare = useDeclareSpace();
  const del = useDeleteSpace();
  const [name, setName] = useState('');
  const [model, setModel] = useState('');
  const [dims, setDims] = useState('');

  function onDeclare(e: React.FormEvent) {
    e.preventDefault();
    const parsed = parseSpaceForm(name, model, dims);
    if ('error' in parsed) {
      toast.error(parsed.error);
      return;
    }
    declare.mutate(parsed, {
      onSuccess: () => {
        toast.success(`Declared space ${parsed.space}`);
        setName('');
        setModel('');
        setDims('');
      },
      onError: (err) => toast.error('Declare space failed', { description: (err as Error).message }),
    });
  }
  function onDelete(space: string) {
    if (!window.confirm(`Remove embedding space "${space}"? Nothing will embed into it afterwards.`)) return;
    del.mutate(space, {
      onSuccess: () => toast.success(`Removed space ${space}`),
      onError: (err) => toast.error('Delete space failed', { description: (err as Error).message }),
    });
  }

  const d = q.data;
  const purposes = d ? purposeRows(d.aliases, d.classes) : [];
  const spaces = d ? spaceRows(d.spaces) : [];

  return (
    <section className="panel">
      <div className="panel-head">
        <h2>Model preferences</h2>
        <span className="meta">operator{q.isFetching && ' · refreshing…'}</span>
      </div>

      {q.isLoading && <div className="state">Loading model preferences…</div>}
      {q.isError && <div className="state err">{(q.error as Error)?.message}</div>}

      {d && (
        <>
          <h3 className="subhead">Chat purposes</h3>
          <p className="flag-help">
            A preference is tried first; the mesh answers behind it, so a preference that is not served yet
            never breaks chat.
          </p>
          {purposes.map((p) => (
            <PurposeLine key={p.purpose} row={p} classNames={d.classes.map((c) => c.name)} />
          ))}
          {purposes.length === 0 && <div className="state">No purposes reported</div>}
          <p className="flag-help">{chatDefaultLine(d.classes)}</p>

          <h3 className="subhead">Embedding spaces</h3>
          <p className="flag-help">
            A space is one purpose bound to one embedding model. Embeds never fall back across models, because
            vectors from different models cannot be compared.
          </p>
          {spaces.map((s) => (
            <div className="cache-row" key={s.space} style={{ flexWrap: 'wrap', gap: 8 }}>
              <span className="cache-name">
                {s.space}
                {s.isDefault && <span className="user-you">default</span>}
              </span>
              <span className="cache-meta">
                {s.model} · {s.dimsText} · {s.live} live
              </span>
              <StatusBadge tone={s.live > 0 ? 'good' : 'bad'}>{s.live > 0 ? 'serving' : 'not serving'}</StatusBadge>
              {s.deletable && (
                <Button size="sm" variant="outline" disabled={del.isPending} onClick={() => onDelete(s.space)}>
                  Delete
                </Button>
              )}
              <div style={{ flexBasis: '100%' }}>
                {s.pool.length === 0 && <span className="flag-help">no nodes placed on this model</span>}
                {s.pool.map((n, i) => (
                  <div className="flag-help" key={`${n.node}-${n.backend}-${i}`}>
                    {n.node} · {n.backend} · {n.state}
                  </div>
                ))}
              </div>
              {s.warning && <div className="state err" style={{ flexBasis: '100%' }}>{s.warning}</div>}
            </div>
          ))}
          {spaces.length === 0 && <div className="state">No embedding spaces</div>}
          {d.unmatched.map((n, i) => (
            <div className="state warn" key={`${n.node}-${i}`}>
              {unmatchedWarning(n)}
            </div>
          ))}

          <h3 className="subhead">Declare a space</h3>
          <form className="op-form" onSubmit={onDeclare}>
            <Input placeholder="space name" value={name} onChange={(e) => setName(e.target.value)} aria-label="Space name" />
            <Input placeholder="embedding model" value={model} onChange={(e) => setModel(e.target.value)} aria-label="Embedding model" />
            <Input placeholder="dims (optional)" value={dims} onChange={(e) => setDims(e.target.value)} aria-label="Dimensions" />
            <Button size="sm" type="submit" disabled={declare.isPending}>
              {declare.isPending ? 'Declaring…' : 'Declare space'}
            </Button>
          </form>
          <p className="flag-help">
            A space&apos;s model cannot be changed later — that is a re-embed of everything in it. To use a
            different model, declare a new space.
          </p>
        </>
      )}
    </section>
  );
}
