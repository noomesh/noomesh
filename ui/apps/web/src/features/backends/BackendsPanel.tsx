// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 PersonifAI LLC

import { useState } from 'react';
import { toast } from 'sonner';
import { cn } from '@/lib/utils';
import { Button } from '@/components/ui/button';
import { useClusterNodes } from '@/features/cluster/useClusterNodes';
import { meterLevel } from '@/lib/meter';
import { Input } from '@/components/ui/input';
import { useConfirm } from '@/components/ConfirmDialog';
import {
  useBackends,
  useCachedModels,
  useStartBackend,
  useCacheModel,
  useStopBackend,
  type Backend,
} from './useBackends';

const BACKEND_TYPES = ['ollama', 'vllm', 'llamacpp', 'embedding'];

export function BackendsPanel() {
  const backends = useBackends();
  const cached = useCachedModels();
  const stop = useStopBackend();
  const start = useStartBackend();
  const cacheModel = useCacheModel();
  const confirm = useConfirm();

  const [beType, setBeType] = useState('ollama');
  const [beNode, setBeNode] = useState('');
  const [beModel, setBeModel] = useState('');
  const [cmModel, setCmModel] = useState('');
  const [cmNode, setCmNode] = useState('');

  function onStart(e: React.FormEvent) {
    e.preventDefault();
    start.mutate(
      { backend: beType, nodeId: beNode.trim() || undefined, model: beModel.trim() || undefined },
      {
        onSuccess: () => {
          toast.success('Backend starting', {
            description: `${beType}${beNode ? ` on ${beNode}` : ' (auto node)'}`,
          });
          setBeNode('');
          setBeModel('');
        },
        onError: (err) => toast.error('Start failed', { description: (err as Error).message }),
      },
    );
  }

  function onCache(e: React.FormEvent) {
    e.preventDefault();
    const model = cmModel.trim();
    if (!model) return;
    cacheModel.mutate(
      { model, nodeId: cmNode.trim() || undefined },
      {
        onSuccess: () => {
          toast.success('Caching model', { description: model });
          setCmModel('');
          setCmNode('');
        },
        onError: (err) => toast.error('Cache failed', { description: (err as Error).message }),
      },
    );
  }

  async function onStop(b: Backend) {
    const ok = await confirm({
      title: `Stop ${b.backend} on ${b.nodeId}?`,
      description: `This unloads ${b.model} and frees the node's VRAM.`,
      confirmText: 'Stop backend',
      destructive: true,
    });
    if (!ok) return;
    stop.mutate(
      { backend: b.backend, nodeId: b.nodeId },
      {
        onSuccess: () => toast.success('Backend stopped', { description: `${b.backend} on ${b.nodeId}` }),
        onError: (e) => toast.error('Stop failed', { description: (e as Error).message }),
      },
    );
  }

  const stopping = stop.isPending ? stop.variables : undefined;

  // Same node list the Cluster tab shows; offline nodes can't run anything, so
  // offering them would only produce a failure the user has to interpret.
  const cluster = useClusterNodes();
  const onlineNodes = (cluster.data?.nodes ?? []).filter((n) => n.status !== 'offline');

  return (
    <section className="panel">
      <div className="panel-head">
        <h2>Backends</h2>
        <span className="meta">
          {backends.data ? `${backends.data.length} running` : '—'}
          {backends.isFetching && ' · refreshing…'}
        </span>
      </div>

      <form className="op-form" onSubmit={onStart}>
        <select className="op-select" value={beType} onChange={(e) => setBeType(e.target.value)} aria-label="Backend type">
          {BACKEND_TYPES.map((t) => (
            <option key={t} value={t}>
              {t}
            </option>
          ))}
        </select>
        <select
          className="op-select"
          value={beNode}
          onChange={(e) => setBeNode(e.target.value)}
          aria-label="Node"
          title="Which machine runs it. Auto picks the node that can actually fit the model."
        >
          <option value="">{onlineNodes.length ? 'node — auto' : 'no nodes online'}</option>
          {onlineNodes.map((n) => (
            <option key={n.id} value={n.id}>
              {n.hostname}
              {n.gpu ? ` · ${n.gpu}` : ''}
            </option>
          ))}
        </select>
        <Input placeholder="model (optional)" value={beModel} onChange={(e) => setBeModel(e.target.value)} aria-label="Model" />
        <Button
          size="sm"
          type="submit"
          disabled={start.isPending}
          title="Start a model server on the cluster. First start pulls the weights, which can take minutes."
        >
          {start.isPending ? 'Starting…' : 'Start backend'}
        </Button>
      </form>

      {backends.isLoading && <div className="state">Loading backends…</div>}
      {backends.isError && <div className="state err">{(backends.error as Error)?.message}</div>}
      {backends.data &&
        (backends.data.length ? (
          backends.data.map((b, i) => {
            const busy = stopping?.backend === b.backend && stopping?.nodeId === b.nodeId;
            return (
              <div className="backend" key={`${b.nodeId}-${b.backend}-${i}`}>
                <div className="backend-main">
                  <div>
                    <span className="backend-name">{b.backend}</span>
                    <span className="backend-node">on {b.nodeId}</span>
                  </div>
                  <div className="backend-model">{b.model}</div>
                </div>
                <div className="backend-right">
                  {b.load != null && (
                    <div className="meter">
                      {b.load.toFixed(2)}
                      <span className="track">
                        <span
                          className={cn('fill', meterLevel(b.load * 100, 'high-bad'))}
                          style={{ width: `${Math.round(b.load * 100)}%` }}
                        />
                      </span>
                    </div>
                  )}
                  <Button
                    size="sm"
                    variant="outline"
                    disabled={busy}
                    onClick={() => onStop(b)}
                    title={`Stop ${b.backend} on ${b.nodeId}. In-flight requests to it will fail.`}
                  >
                    {busy ? 'Stopping…' : 'Stop'}
                  </Button>
                </div>
              </div>
            );
          })
        ) : (
          <div className="onboard">
            <p className="onboard-lead">No backends running.</p>
            <p>
              A backend is the process that actually serves a model. Start one above —
              pick a type and leave the node on auto, and the gateway puts it wherever it
              fits. The first start downloads the weights, so give it a few minutes.
            </p>
          </div>
        ))}

      <h3 className="subhead">Cached models</h3>
      <form className="op-form" onSubmit={onCache}>
        <Input
          placeholder="model to cache…"
          value={cmModel}
          onChange={(e) => setCmModel(e.target.value)}
          aria-label="Model to cache"
          title="A model identifier, e.g. Qwen/Qwen2.5-32B-Instruct"
        />
        <select
          className="op-select"
          value={cmNode}
          onChange={(e) => setCmNode(e.target.value)}
          aria-label="Cache node"
          title="Pull the weights onto one node. Leave on all to cache everywhere."
        >
          <option value="">{onlineNodes.length ? 'node — all' : 'no nodes online'}</option>
          {onlineNodes.map((n) => (
            <option key={n.id} value={n.id}>
              {n.hostname}
            </option>
          ))}
        </select>
        <Button
          size="sm"
          variant="outline"
          type="submit"
          disabled={cacheModel.isPending || !cmModel.trim()}
          title="Download the weights now so the first request doesn't wait for them."
        >
          {cacheModel.isPending ? 'Caching…' : 'Cache'}
        </Button>
      </form>
      {cached.isLoading && <div className="state">Loading cache…</div>}
      {cached.isError && <div className="state err">{(cached.error as Error)?.message}</div>}
      {cached.data &&
        (cached.data.length ? (
          <div className="cache-list">
            {cached.data.map((m, i) => (
              <div className="cache-row" key={`${m.name}-${i}`}>
                <span className="cache-name">{m.name}</span>
                <span className="cache-meta">
                  {m.backend} · {m.size} · {m.nodes.join(', ') || '—'}
                </span>
              </div>
            ))}
          </div>
        ) : (
          <div className="state">No cached models</div>
        ))}
    </section>
  );
}
