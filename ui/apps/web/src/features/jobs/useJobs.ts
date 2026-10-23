// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 PersonifAI LLC

import { useQuery, useMutation, useQueryClient, useMetisClient } from '@metis/core';
import { num } from '@/lib/num';
import type { Job } from './types';

const JOBS_KEY = ['scheduler', 'jobs'];
const STATUS_KEY = ['scheduler', 'status'];

export interface SchedulerStatus {
  paused: boolean;
  // null = the gateway did not send it (renders a dash, never 0).
  queued: number | null;
  running: number | null;
  clients: number | null;
  drainedNodes: string[];
}

/** Scheduler status + connected clients (polled 10s). */
export function useSchedulerStatus() {
  const client = useMetisClient();
  return useQuery<SchedulerStatus>({
    queryKey: STATUS_KEY,
    refetchInterval: 10_000,
    queryFn: async () => {
      const [s, c] = await Promise.all([
        client.GET('/api/scheduler/status'),
        client.GET('/api/alerts/clients'),
      ]);
      if (s.error || !s.data) throw new Error('Scheduler API unavailable');
      return {
        paused: s.data.paused ?? false,
        queued: num(s.data.queue_depth),
        running: num(s.data.active_jobs),
        clients: num(c.data?.connected_clients),
        drainedNodes: s.data.drained_nodes ?? [],
      };
    },
  });
}

/** The job queue (GET /api/jobs, polled 10s). */
export function useJobs() {
  const client = useMetisClient();
  return useQuery<Job[]>({
    queryKey: JOBS_KEY,
    refetchInterval: 10_000,
    queryFn: async () => {
      const { data, error } = await client.GET('/api/jobs');
      if (error) throw new Error('Jobs API unavailable');
      return (data?.jobs ?? []).map(
        (j): Job => ({
          id: j.job_id ?? '',
          type: j.type ?? '?',
          status: j.status ?? 'unknown',
          priority: j.priority ?? null,
          nodeId: j.node_id ?? null,
          createdAt: j.created_at ?? '',
        }),
      );
    },
  });
}

/** Cancel a job (DELETE /api/jobs/{job_id}). */
export function useCancelJob() {
  const client = useMetisClient();
  const qc = useQueryClient();
  return useMutation({
    mutationFn: async (jobId: string) => {
      const { error } = await client.DELETE('/api/jobs/{job_id}', {
        params: { path: { job_id: jobId } },
      });
      if (error) throw new Error('Cancel failed');
    },
    onSuccess: () => qc.invalidateQueries({ queryKey: JOBS_KEY }),
  });
}

/** Submit a new job to the scheduler (POST /api/jobs/submit). Returns the job id. */
export function useSubmitJob() {
  const client = useMetisClient();
  const qc = useQueryClient();
  return useMutation({
    mutationFn: async (vars: {
      type: string;
      payload: Record<string, unknown>;
      priority: number;
      forceNode?: string;
    }) => {
      const { data, error } = await client.POST('/api/jobs/submit', {
        body: {
          type: vars.type,
          payload: vars.payload,
          priority: vars.priority,
          ...(vars.forceNode ? { force_node: vars.forceNode } : {}),
        },
      });
      if (error) throw new Error('Submit failed');
      const d = data as { job_id?: string; error?: string };
      if (d?.error) throw new Error(d.error);
      return d?.job_id ?? '';
    },
    onSuccess: () => qc.invalidateQueries({ queryKey: JOBS_KEY }),
  });
}

/** Drain or restore a node (POST /api/scheduler/{drain,undrain}/{node_id}). */
export function useDrainNode() {
  const client = useMetisClient();
  const qc = useQueryClient();
  return useMutation({
    mutationFn: async (vars: { nodeId: string; drain: boolean }) => {
      const opts = { params: { path: { node_id: vars.nodeId } } };
      const { error } = vars.drain
        ? await client.POST('/api/scheduler/drain/{node_id}', opts)
        : await client.POST('/api/scheduler/undrain/{node_id}', opts);
      if (error) throw new Error(vars.drain ? 'Drain failed' : 'Undrain failed');
    },
    onSuccess: () => qc.invalidateQueries({ queryKey: STATUS_KEY }),
  });
}

/** Pause or resume the scheduler. Pass the CURRENT paused state. */
export function useSchedulerPause() {
  const client = useMetisClient();
  const qc = useQueryClient();
  return useMutation({
    mutationFn: async (currentlyPaused: boolean) => {
      const { error } = currentlyPaused
        ? await client.POST('/api/scheduler/resume', {})
        : await client.POST('/api/scheduler/pause', {});
      if (error) throw new Error('Scheduler action failed');
    },
    onSuccess: () => qc.invalidateQueries({ queryKey: STATUS_KEY }),
  });
}
