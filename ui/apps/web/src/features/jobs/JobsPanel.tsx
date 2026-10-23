// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 PersonifAI LLC

import { useState } from 'react';
import { toast } from 'sonner';
import { relTime } from '@/lib/format';
import { dash } from '@/lib/num';
import { StatTiles } from '@/components/StatTiles';
import { StatusBadge } from '@/components/StatusBadge';
import { Button } from '@/components/ui/button';
import { useClusterNodes } from '@/features/cluster/useClusterNodes';
import { Input } from '@/components/ui/input';
import { useConfirm } from '@/components/ConfirmDialog';
import {
  useSchedulerStatus,
  useJobs,
  useCancelJob,
  useSchedulerPause,
  useDrainNode,
  useSubmitJob,
} from './useJobs';
import { jobStatusMeta, type Job } from './types';

const FILTERS: [string, string][] = [
  ['', 'All'],
  ['running', 'Running'],
  ['queued', 'Queued'],
  ['completed', 'Completed'],
  ['failed', 'Failed'],
];

export function JobsPanel() {
  const sched = useSchedulerStatus();
  const jobs = useJobs();
  const cancel = useCancelJob();
  const pause = useSchedulerPause();
  const drain = useDrainNode();
  const submit = useSubmitJob();
  const confirm = useConfirm();
  const [filter, setFilter] = useState('');
  const [drainNode, setDrainNode] = useState('');
  const [jobType, setJobType] = useState('');
  const [jobPriority, setJobPriority] = useState('5');
  const [jobNode, setJobNode] = useState('');
  const [jobPayload, setJobPayload] = useState('');

  const rows = (jobs.data ?? []).filter((j) => !filter || j.status === filter);
  const cancellingId = cancel.isPending ? cancel.variables : undefined;
  const paused = sched.data?.paused ?? false;

  async function onCancel(j: Job) {
    const ok = await confirm({
      title: `Cancel job ${j.id.slice(0, 10)}?`,
      description: `Stops the ${j.type} job${j.nodeId ? ` on ${j.nodeId}` : ''}.`,
      confirmText: 'Cancel job',
      destructive: true,
    });
    if (!ok) return;
    cancel.mutate(j.id, {
      onSuccess: () => toast.success('Job cancelled', { description: j.id.slice(0, 10) }),
      onError: (e) => toast.error('Cancel failed', { description: (e as Error).message }),
    });
  }

  function onTogglePause() {
    pause.mutate(paused, {
      onSuccess: () => toast.success(paused ? 'Scheduler resumed' : 'Scheduler paused'),
      onError: (e) => toast.error('Action failed', { description: (e as Error).message }),
    });
  }

  function onDrain(e: React.FormEvent) {
    e.preventDefault();
    const n = drainNode.trim();
    if (!n) return;
    drain.mutate(
      { nodeId: n, drain: true },
      {
        onSuccess: () => {
          toast.success('Node drained', { description: n });
          setDrainNode('');
        },
        onError: (err) => toast.error('Drain failed', { description: (err as Error).message }),
      },
    );
  }

  function onUndrain(n: string) {
    drain.mutate(
      { nodeId: n, drain: false },
      {
        onSuccess: () => toast.success('Node restored', { description: n }),
        onError: (err) => toast.error('Undrain failed', { description: (err as Error).message }),
      },
    );
  }

  function onSubmitJob(e: React.FormEvent) {
    e.preventDefault();
    let payload: Record<string, unknown> = {};
    if (jobPayload.trim()) {
      try {
        payload = JSON.parse(jobPayload);
      } catch {
        toast.error('Invalid payload', { description: 'Payload must be valid JSON.' });
        return;
      }
    }
    submit.mutate(
      {
        type: jobType.trim() || 'inference',
        payload,
        priority: Number(jobPriority) || 5,
        forceNode: jobNode.trim() || undefined,
      },
      {
        onSuccess: (jobId) => {
          toast.success('Job submitted', { description: jobId ? jobId.slice(0, 12) : jobType.trim() || 'inference' });
          setJobPayload('');
        },
        onError: (err) => toast.error('Submit failed', { description: (err as Error).message }),
      },
    );
  }

  // Draining is a node-level action; a typo silently does nothing, so offer
  // the real list rather than a free-text box.
  const cluster = useClusterNodes();
  const drainable = (cluster.data?.nodes ?? []).filter(
    (n) => n.status !== 'offline' && !(sched.data?.drainedNodes ?? []).includes(n.id),
  );

  return (
    <section className="panel">
      <div className="panel-head">
        <h2>Jobs</h2>
        <div className="panel-head-right">
          {(jobs.isFetching || sched.isFetching) && <span className="meta">refreshing…</span>}
          <Button
            size="sm"
            variant={paused ? 'default' : 'outline'}
            disabled={pause.isPending || !sched.data}
            onClick={onTogglePause}
            title={
              paused
                ? 'Start dispatching queued jobs again.'
                : 'Stop dispatching new jobs. Running jobs finish; the queue just holds.'
            }
          >
            {paused ? 'Resume scheduler' : 'Pause scheduler'}
          </Button>
        </div>
      </div>

      {sched.isError && <div className="state err">{(sched.error as Error)?.message}</div>}
      {sched.data && (
        <StatTiles
          tiles={[
            { label: 'Scheduler', value: paused ? 'Paused' : 'Running', hot: paused },
            { label: 'Queued', value: dash(sched.data.queued) },
            { label: 'Running', value: dash(sched.data.running) },
            { label: 'Clients', value: dash(sched.data.clients) },
          ]}
        />
      )}

      {sched.data && sched.data.drainedNodes.length > 0 && (
        <div className="drained-row">
          <span className="drained-label">Drained</span>
          {sched.data.drainedNodes.map((n) => (
            <button
              key={n}
              className="drained-chip"
              onClick={() => onUndrain(n)}
              disabled={drain.isPending}
              title={`Undrain ${n} — let the scheduler use it again`}
            >
              {n} ✕
            </button>
          ))}
        </div>
      )}

      <form className="op-form" onSubmit={onDrain}>
        <select
          className="op-select"
          value={drainNode}
          onChange={(e) => setDrainNode(e.target.value)}
          aria-label="Node to drain"
          title="Take a node out of scheduling for maintenance. Running jobs finish first."
        >
          <option value="">{drainable.length ? 'node to drain…' : 'no nodes available'}</option>
          {drainable.map((n) => (
            <option key={n.id} value={n.id}>
              {n.hostname}
            </option>
          ))}
        </select>
        <Button
          size="sm"
          variant="outline"
          type="submit"
          disabled={drain.isPending || !drainNode.trim()}
          title="Stop scheduling new work onto this node. Reversible from the Drained row above."
        >
          {drain.isPending ? 'Draining…' : 'Drain node'}
        </Button>
      </form>

      <h3 className="subhead">Submit a job</h3>
      <form className="ingest-form" onSubmit={onSubmitJob}>
        <div className="op-form">
          <Input placeholder="type (inference)" value={jobType} onChange={(e) => setJobType(e.target.value)} aria-label="Job type" />
          <Input
            placeholder="priority"
            type="number"
            value={jobPriority}
            onChange={(e) => setJobPriority(e.target.value)}
            aria-label="Priority"
          />
          <Input placeholder="force node (optional)" value={jobNode} onChange={(e) => setJobNode(e.target.value)} aria-label="Force node" />
        </div>
        <textarea
          className="op-textarea"
          placeholder={'payload JSON (optional), e.g. {"prompt": "…"}'}
          value={jobPayload}
          onChange={(e) => setJobPayload(e.target.value)}
          rows={3}
          aria-label="Payload JSON"
        />
        <div>
          <Button
            size="sm"
            type="submit"
            disabled={submit.isPending}
            title="Queue a background job. The scheduler assigns it to a node when one is free."
          >
            {submit.isPending ? 'Submitting…' : 'Submit job'}
          </Button>
        </div>
      </form>

      <div className="jobs-head">
        <span className="queue-label">Queue</span>
        <select
          className="filter-select"
          value={filter}
          onChange={(e) => setFilter(e.target.value)}
          aria-label="Filter jobs by status"
          title="Show only jobs in this state"
        >
          {FILTERS.map(([v, l]) => (
            <option key={v || 'all'} value={v}>
              {l}
            </option>
          ))}
        </select>
      </div>

      {jobs.isLoading && <div className="state">Loading jobs…</div>}
      {jobs.isError && <div className="state err">{(jobs.error as Error)?.message}</div>}
      {jobs.data &&
        (rows.length ? (
          <div className="job-list">
            {rows.map((j) => {
              const meta = jobStatusMeta(j.status);
              const busy = cancellingId === j.id;
              const cancelable = j.status === 'queued' || j.status === 'running';
              return (
                <div className="job-row" key={j.id}>
                  <div className="job-main">
                    <div className="job-line1">
                      <StatusBadge tone={meta.tone}>{meta.label}</StatusBadge>
                      <span className="job-id">{j.id.slice(0, 10)}</span>
                      <span className="job-type">{j.type}</span>
                    </div>
                    <div className="job-line2">
                      P{j.priority ?? '—'} · {j.nodeId ?? 'unassigned'}
                      {j.createdAt ? ` · ${relTime(j.createdAt)} ago` : ''}
                    </div>
                  </div>
                  {cancelable && (
                    <Button
                      size="sm"
                      variant="outline"
                      disabled={busy}
                      onClick={() => onCancel(j)}
                      title={
                        j.status === 'running'
                          ? 'Stop this job mid-run. Partial work is not rolled back.'
                          : 'Remove this job from the queue before it starts.'
                      }
                    >
                      {busy ? '…' : 'Cancel'}
                    </Button>
                  )}
                </div>
              );
            })}
          </div>
        ) : (
          <div className="state">No matching jobs.</div>
        ))}
    </section>
  );
}
