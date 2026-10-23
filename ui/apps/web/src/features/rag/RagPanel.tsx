// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 PersonifAI LLC

import { useState } from 'react';
import { toast } from 'sonner';
import { useQuery, useMutation, useQueryClient, useMetisClient } from '@metis/core';
import { awaitOperation, isOperationHandle, OperationError } from '@metis/api';
import { relTime } from '@/lib/format';
import { num, dash, ratioOrNull } from '@/lib/num';
import { StatTiles } from '@/components/StatTiles';
import { StatusBadge, type Tone } from '@/components/StatusBadge';
import { Input } from '@/components/ui/input';
import { Button } from '@/components/ui/button';

interface Doc {
  id: string;
  title: string;
  source: string;
  createdAt: string;
}
interface RagData {
  // null = the gateway did not send it (renders a dash, never 0).
  docs: number | null;
  pages: number | null;
  chunks: number | null;
  embeddedPages: number | null;
  embedderState: string;
  documents: Doc[];
}

function useRag() {
  const client = useMetisClient();
  return useQuery<RagData>({
    queryKey: ['rag'],
    refetchInterval: 30_000,
    queryFn: async () => {
      const [s, d] = await Promise.all([
        client.GET('/api/v1/rag/status'),
        client.GET('/api/v1/docs'),
      ]);
      return {
        docs: num(s.data?.doc_count),
        pages: num(s.data?.page_count),
        chunks: num(s.data?.chunk_count),
        embeddedPages: num(s.data?.embedded_pages),
        // The live gateway reports `started` (bool), not the previously-assumed
        // `embedder_state.state`, so the badge always read 'unknown'.
        embedderState: s.data?.started ? 'running' : 'stopped',
        documents: (d.data ?? []).map((x) => ({
          id: x.doc_id ?? '',
          title: x.title || x.doc_id || '(untitled)',
          source: x.source_uri ?? '',
          createdAt: x.created_at ?? '',
        })),
      };
    },
  });
}

/**
 * Who a new document is for. Every document has an audience; the default is
 * the uploader. "Only me" sends NO `roles`, so the gateway applies its own
 * default (`user:<you>`) rather than the UI guessing the account name — a
 * connection subject (`you/label`) would produce a tier nobody can read.
 * Team audiences (`team:<name>`) are available from the CLI
 * (`noo rag ingest --audience team:<name>`); the console does not list a
 * person's teams, so it does not offer them.
 */
type Audience = 'me' | 'company';
const AUDIENCE_ROLES: Record<Audience, string[] | undefined> = {
  me: undefined,
  company: ['company'],
};

/** Ingest a text document into the knowledge base (POST /api/v1/docs/ingest). */
function useIngestDoc() {
  const client = useMetisClient();
  const qc = useQueryClient();
  return useMutation({
    mutationFn: async (vars: { text: string; title?: string; sourceUri?: string; roles?: string[] }) => {
      const { data, error } = await client.POST('/api/v1/docs/ingest', {
        body: {
          text: vars.text,
          ...(vars.title ? { title: vars.title } : {}),
          ...(vars.sourceUri ? { source_uri: vars.sourceUri } : {}),
          ...(vars.roles ? { roles: vars.roles } : {}),
        },
      });
      if (error) throw new Error('Ingest failed');
      // The route is operation-backed: 200 with the worker's reply if the ingest finished within its
      // wait, 202 with a handle if it did not. Follow the handle so "ingested" means finished.
      let reply: unknown = data;
      if (isOperationHandle(data)) {
        try {
          reply = await awaitOperation(client, data, { timeoutMs: 120_000 });
        } catch (e) {
          if (e instanceof OperationError) throw new Error(e.message || 'Ingest failed');
          return 'Still indexing in the background — it will appear in the document list';
        }
      }
      return (reply as { message?: string })?.message ?? 'Document queued for indexing';
    },
    onSuccess: () => qc.invalidateQueries({ queryKey: ['rag'] }),
  });
}

const stateTone = (s: string): Tone => (s === 'running' ? 'good' : s === 'error' ? 'bad' : 'neutral');

export function RagPanel() {
  const rag = useRag();
  const ingest = useIngestDoc();
  const ratio = rag.data ? ratioOrNull(rag.data.embeddedPages, rag.data.pages) : null;
  const coverage = ratio === null ? null : Math.round(ratio * 100);

  const [title, setTitle] = useState('');
  const [source, setSource] = useState('');
  const [text, setText] = useState('');
  const [audience, setAudience] = useState<Audience>('me');

  function onIngest(e: React.FormEvent) {
    e.preventDefault();
    const body = text.trim();
    if (!body) return;
    ingest.mutate(
      {
        text: body,
        title: title.trim() || undefined,
        sourceUri: source.trim() || undefined,
        roles: AUDIENCE_ROLES[audience],
      },
      {
        onSuccess: (message) => {
          toast.success('Document ingested', { description: message });
          setTitle('');
          setSource('');
          setText('');
        },
        onError: (err) => toast.error('Ingest failed', { description: (err as Error).message }),
      },
    );
  }

  return (
    <section className="panel">
      <div className="panel-head">
        <h2>Documents</h2>
        <div className="panel-head-right">
          {rag.data && <StatusBadge tone={stateTone(rag.data.embedderState)}>{rag.data.embedderState}</StatusBadge>}
          <span className="meta">{rag.isFetching ? 'refreshing…' : 'RAG index'}</span>
        </div>
      </div>

      {rag.isLoading && <div className="state">Loading index…</div>}
      {rag.isError && <div className="state err">{(rag.error as Error)?.message}</div>}

      {rag.data && (
        <>
          <StatTiles
            tiles={[
              { label: 'Documents', value: dash(rag.data.docs) },
              { label: 'Pages', value: dash(rag.data.pages) },
              { label: 'Chunks', value: dash(rag.data.chunks) },
              { label: 'Embedded', value: dash(coverage, (n) => `${n}%`), hot: coverage !== null && coverage < 100 },
            ]}
          />

          <h3 className="subhead">Add document</h3>
          <form className="ingest-form" onSubmit={onIngest}>
            <div className="op-form">
              <Input placeholder="title (optional)" value={title} onChange={(e) => setTitle(e.target.value)} aria-label="Document title" />
              <Input placeholder="source uri (optional)" value={source} onChange={(e) => setSource(e.target.value)} aria-label="Source URI" />
            </div>
            <textarea
              className="op-textarea"
              placeholder="paste document text to index…"
              value={text}
              onChange={(e) => setText(e.target.value)}
              rows={4}
              aria-label="Document text"
            />
            <select
              className="op-select"
              value={audience}
              onChange={(e) => setAudience(e.target.value as Audience)}
              aria-label="Who can read this document"
            >
              <option value="me">Only me</option>
              <option value="company">Company</option>
            </select>
            <div>
              <Button size="sm" type="submit" disabled={ingest.isPending || !text.trim()}>
                {ingest.isPending ? 'Ingesting…' : 'Ingest document'}
              </Button>
            </div>
          </form>

          <h3 className="subhead">Recent documents</h3>
          {rag.data.documents.length ? (
            rag.data.documents.map((doc) => (
              <div className="doc-row" key={doc.id}>
                <div className="doc-main">
                  <div className="doc-title">{doc.title}</div>
                  {doc.source && <div className="doc-source">{doc.source}</div>}
                </div>
                <span className="doc-time">{doc.createdAt ? `${relTime(doc.createdAt)} ago` : '—'}</span>
              </div>
            ))
          ) : (
            <div className="state">No documents indexed.</div>
          )}
        </>
      )}
    </section>
  );
}
