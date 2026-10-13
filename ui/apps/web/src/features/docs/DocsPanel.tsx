// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 PersonifAI LLC

import { useState } from 'react';
import { renderMarkdown } from '@/lib/markdown';
import { useRunbooks, useRunbook, useFullSpec } from './useRunbooks';

/**
 * Opens the full spec in a new tab, having fetched it WITH the bearer.
 *
 * A blob URL rather than an href: the document is authenticated, and the
 * browser will not attach our token to a plain navigation. Revoked on the
 * next click so a long-lived panel does not accumulate them.
 */
function SpecLink() {
  const { load, pending, error } = useFullSpec();
  return (
    <button className="docs-link" type="button" onClick={load} disabled={pending}>
      {pending ? 'Opening…' : error ? `OpenAPI spec — ${error}` : 'OpenAPI spec (JSON) ↗'}
    </button>
  );
}

/**
 * Operational runbooks, rendered in-app.
 *
 * This panel used to be twelve `<a target="_blank">` links: ten to
 * `/docs/runbooks/<slug>` and two to `/docs` and `/static/openapi.json`. Eleven
 * of the twelve were dead — `gateway-rust` serves neither `/docs` nor
 * `/docs/runbooks/*`, and the runbook API it *does* serve is authenticated, so
 * a plain link could not have worked anyway. The gateway's route comment says
 * exactly this, having already fixed the same bug in the legacy console
 * (task #14). The React port reintroduced it.
 *
 * The list is no longer hard-coded either: ten slugs were baked in here, while
 * the gateway serves whatever runbooks that install has.
 */
export function DocsPanel() {
  const [open, setOpen] = useState<string | null>(null);
  const list = useRunbooks();
  const book = useRunbook(open);

  const selected = list.data?.find((r) => r.name === open);

  return (
    <section className="panel">
      <div className="panel-head">
        <h2>Docs</h2>
        <span className="meta">
          {list.data ? `${list.data.length} runbooks · API reference` : 'runbooks · API reference'}
        </span>
      </div>

      <h3 className="subhead">Operational runbooks</h3>

      {list.isPending && <p className="muted">Loading runbooks…</p>}

      {list.isError && (
        <p className="muted">
          Could not load the runbooks. They are served by the gateway, so this usually means the
          gateway is unreachable rather than that the docs are missing.
        </p>
      )}

      {list.data?.length === 0 && (
        <p className="muted">This gateway has no runbooks installed.</p>
      )}

      {!!list.data?.length && (
        <div className="runbook-grid">
          {list.data.map((r) => (
            <button
              key={r.name}
              type="button"
              className={`runbook-card${open === r.name ? ' active' : ''}`}
              onClick={() => setOpen(open === r.name ? null : r.name)}
              aria-expanded={open === r.name}
            >
              <strong>{r.title}</strong>
              <span>{r.name}</span>
            </button>
          ))}
        </div>
      )}

      {open && (
        <div className="runbook-view">
          <div className="runbook-head">
            <h3>{selected?.title ?? open}</h3>
            <button type="button" className="runbook-close" onClick={() => setOpen(null)}>
              Close
            </button>
          </div>
          {book.isPending && <p className="muted">Loading…</p>}
          {book.isError && <p className="muted">{(book.error as Error).message}</p>}
          {book.data !== undefined && (
            // Safe by construction: renderMarkdown escapes the whole source
            // before adding any markup, so nothing in a runbook can reach the
            // DOM as markup. See lib/markdown.ts.
            <div className="runbook-body" dangerouslySetInnerHTML={{ __html: renderMarkdown(book.data) }} />
          )}
        </div>
      )}

      <h3 className="subhead">API reference</h3>
      <div className="docs-links">
        {/* Fetched, not linked — the same rule the runbooks above follow, and
            for the same reason `useRunbooks` gives: a target=_blank href can
            never carry the bearer. The full spec stopped being a public file
            on 2026-09-19 (it was the whole route map, readable with no
            credential), so this link would now 401 exactly as the eleven dead
            links before it did. */}
        <SpecLink />
        <a className="docs-link" href="/static/openapi.public.json" target="_blank" rel="noreferrer">
          Public endpoints only (JSON) ↗
        </a>
      </div>
    </section>
  );
}
