// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 PersonifAI LLC

import { useQuery, useMutation, useQueryClient, useMetisClient } from '@metis/core';

export interface HeartbeatTask {
  id: string;
  name: string;
  schedule: string;
  action: string;
  enabled: boolean;
  lastRun: string | null;
  nextRun: string | null;
}
export interface TasksData {
  running: boolean;
  croniter: boolean;
  tasks: HeartbeatTask[];
}

const KEY = ['heartbeat'];

/** Heartbeat scheduler status + scheduled tasks (polled 15s). */
export function useTasks() {
  const client = useMetisClient();
  return useQuery<TasksData>({
    queryKey: KEY,
    refetchInterval: 15_000,
    queryFn: async () => {
      const [s, t] = await Promise.all([
        client.GET('/api/heartbeat/status'),
        client.GET('/api/heartbeat/tasks'),
      ]);
      if (s.error || t.error) throw new Error('Heartbeat status unavailable');
      return {
        running: !!(s.data?.enabled && s.data?.running),
        croniter: s.data?.croniter_available ?? false,
        tasks: (t.data?.tasks ?? []).map((x) => ({
          id: x.id ?? '',
          name: x.name || x.id || '(unnamed)',
          schedule: x.schedule ?? '',
          action: x.action ?? '',
          enabled: x.enabled ?? false,
          lastRun: x.last_run ?? null,
          nextRun: x.next_run ?? null,
        })),
      };
    },
  });
}

/** Create a new heartbeat task (POST /api/heartbeat/tasks). */
export function useCreateTask() {
  const client = useMetisClient();
  const qc = useQueryClient();
  return useMutation({
    mutationFn: async (vars: { id: string; name: string; schedule: string; action: string }) => {
      const { error } = await client.POST('/api/heartbeat/tasks', {
        body: { id: vars.id, name: vars.name, schedule: vars.schedule, action: vars.action, enabled: true },
      });
      if (error) throw new Error('Create failed');
    },
    onSuccess: () => qc.invalidateQueries({ queryKey: KEY }),
  });
}

/** Delete a heartbeat task (DELETE /api/heartbeat/tasks/{task_id}). */
export function useDeleteTask() {
  const client = useMetisClient();
  const qc = useQueryClient();
  return useMutation({
    mutationFn: async (id: string) => {
      const { error } = await client.DELETE('/api/heartbeat/tasks/{task_id}', {
        params: { path: { task_id: id } },
      });
      if (error) throw new Error('Delete failed');
    },
    onSuccess: () => qc.invalidateQueries({ queryKey: KEY }),
  });
}

/** Run a task now. */
export function useRunTask() {
  const client = useMetisClient();
  const qc = useQueryClient();
  return useMutation({
    mutationFn: async (id: string) => {
      const { error } = await client.POST('/api/heartbeat/tasks/{task_id}/run', {
        params: { path: { task_id: id } },
      });
      if (error) throw new Error('Run failed');
    },
    onSuccess: () => qc.invalidateQueries({ queryKey: KEY }),
  });
}

/** Enable/disable (toggle) a task. */
export function useToggleTask() {
  const client = useMetisClient();
  const qc = useQueryClient();
  return useMutation({
    mutationFn: async (id: string) => {
      const { error } = await client.PUT('/api/heartbeat/tasks/{task_id}/toggle', {
        params: { path: { task_id: id } },
      });
      if (error) throw new Error('Toggle failed');
    },
    onSuccess: () => qc.invalidateQueries({ queryKey: KEY }),
  });
}
