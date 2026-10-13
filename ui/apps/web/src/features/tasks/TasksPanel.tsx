// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 PersonifAI LLC

import { useState } from 'react';
import { toast } from 'sonner';
import { relTime, relUntil } from '@/lib/format';
import { StatTiles } from '@/components/StatTiles';
import { StatusBadge } from '@/components/StatusBadge';
import { Button } from '@/components/ui/button';
import { Input } from '@/components/ui/input';
import { useConfirm } from '@/components/ConfirmDialog';
import {
  useTasks,
  useRunTask,
  useToggleTask,
  useCreateTask,
  useDeleteTask,
  type HeartbeatTask,
} from './useTasks';

export function TasksPanel() {
  const t = useTasks();
  const run = useRunTask();
  const toggle = useToggleTask();
  const create = useCreateTask();
  const del = useDeleteTask();
  const confirm = useConfirm();

  const runningId = run.isPending ? run.variables : undefined;
  const togglingId = toggle.isPending ? toggle.variables : undefined;
  const deletingId = del.isPending ? del.variables : undefined;

  const [nId, setNId] = useState('');
  const [nName, setNName] = useState('');
  const [nSchedule, setNSchedule] = useState('');
  const [nAction, setNAction] = useState('');

  function onRun(task: HeartbeatTask) {
    run.mutate(task.id, {
      onSuccess: () => toast.success('Task queued', { description: task.name }),
      onError: (e) => toast.error('Run failed', { description: (e as Error).message }),
    });
  }
  function onToggle(task: HeartbeatTask) {
    toggle.mutate(task.id, {
      onSuccess: () => toast.success(task.enabled ? 'Task paused' : 'Task enabled', { description: task.name }),
      onError: (e) => toast.error('Toggle failed', { description: (e as Error).message }),
    });
  }
  function onCreate(e: React.FormEvent) {
    e.preventDefault();
    const id = nId.trim();
    const name = nName.trim();
    const schedule = nSchedule.trim();
    const action = nAction.trim();
    if (!id || !name || !schedule || !action) return;
    create.mutate(
      { id, name, schedule, action },
      {
        onSuccess: () => {
          toast.success('Task created', { description: name });
          setNId('');
          setNName('');
          setNSchedule('');
          setNAction('');
        },
        onError: (err) => toast.error('Create failed', { description: (err as Error).message }),
      },
    );
  }
  async function onDelete(task: HeartbeatTask) {
    const ok = await confirm({
      title: `Delete "${task.name}"?`,
      description: 'Removes this scheduled task from the heartbeat scheduler.',
      confirmText: 'Delete',
      destructive: true,
    });
    if (!ok) return;
    del.mutate(task.id, {
      onSuccess: () => toast.success('Task deleted', { description: task.name }),
      onError: (err) => toast.error('Delete failed', { description: (err as Error).message }),
    });
  }

  const active = t.data?.tasks.filter((x) => x.enabled).length ?? 0;

  return (
    <section className="panel">
      <div className="panel-head">
        <h2>Tasks</h2>
        <span className="meta">{t.isFetching ? 'refreshing…' : 'heartbeat scheduler'}</span>
      </div>

      {t.isLoading && <div className="state">Loading tasks…</div>}
      {t.isError && <div className="state err">{(t.error as Error)?.message}</div>}

      {t.data && (
        <>
          <StatTiles
            tiles={[
              { label: 'Scheduler', value: t.data.running ? 'Running' : 'Stopped', hot: !t.data.running },
              { label: 'Active', value: active },
              { label: 'Total', value: t.data.tasks.length },
              { label: 'Croniter', value: t.data.croniter ? 'yes' : 'no', hot: !t.data.croniter },
            ]}
          />

          <h3 className="subhead">Scheduled tasks</h3>
          <form className="op-form" onSubmit={onCreate}>
            <Input placeholder="id" value={nId} onChange={(e) => setNId(e.target.value)} aria-label="Task id" />
            <Input placeholder="name" value={nName} onChange={(e) => setNName(e.target.value)} aria-label="Task name" />
            <Input placeholder="cron e.g. 0 9 * * *" value={nSchedule} onChange={(e) => setNSchedule(e.target.value)} aria-label="Schedule" />
            <Input placeholder="action" value={nAction} onChange={(e) => setNAction(e.target.value)} aria-label="Action" />
            <Button
              size="sm"
              type="submit"
              disabled={create.isPending || !nId.trim() || !nName.trim() || !nSchedule.trim() || !nAction.trim()}
            >
              {create.isPending ? 'Adding…' : 'Add task'}
            </Button>
          </form>
          {t.data.tasks.length ? (
            t.data.tasks.map((task) => {
              const busy = runningId === task.id || togglingId === task.id;
              return (
                <div className="task-row" key={task.id}>
                  <div className="task-main">
                    <div className="task-line1">
                      <StatusBadge tone={task.enabled ? 'good' : 'neutral'}>
                        {task.enabled ? 'enabled' : 'paused'}
                      </StatusBadge>
                      <span className="task-name">{task.name}</span>
                      <span className="task-action">{task.action}</span>
                    </div>
                    <div className="task-line2">
                      <span className="task-cron">{task.schedule}</span>
                      {' · next '}
                      {task.enabled ? relUntil(task.nextRun) : '—'}
                      {task.lastRun ? ` · last ${relTime(task.lastRun)} ago` : ''}
                    </div>
                  </div>
                  <div className="task-actions">
                    <Button size="sm" disabled={busy} onClick={() => onRun(task)}>
                      {runningId === task.id ? '…' : 'Run'}
                    </Button>
                    <Button size="sm" variant="outline" disabled={busy} onClick={() => onToggle(task)}>
                      {task.enabled ? 'Pause' : 'Enable'}
                    </Button>
                    <Button
                      size="sm"
                      variant="outline"
                      disabled={busy || deletingId === task.id}
                      onClick={() => onDelete(task)}
                    >
                      {deletingId === task.id ? '…' : 'Delete'}
                    </Button>
                  </div>
                </div>
              );
            })
          ) : (
            <div className="state">No tasks configured.</div>
          )}
        </>
      )}
    </section>
  );
}
