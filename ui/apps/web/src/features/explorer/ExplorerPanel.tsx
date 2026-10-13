// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 PersonifAI LLC

import { useQuery, useMetisClient } from '@metis/core';
import { cn } from '@/lib/utils';
import { StatTiles } from '@/components/StatTiles';

interface EpisodeKind {
  kind: string;
  records: number;
}
interface RecallData {
  started: boolean;
  enabled: boolean | null;
  totalRecords: number | null;
  liveRecords: number | null;
  tombstoned: number | null;
  kinds: EpisodeKind[];
}

function useRecallMemory() {
  const client = useMetisClient();
  return useQuery<RecallData>({
    queryKey: ['recall-memory'],
    refetchInterval: 30_000,
    queryFn: async () => {
      const { data, error } = await client.GET('/api/v1/recall/status');
      if (error) throw new Error('Recall memory not available');
      return {
        started: data?.started ?? false,
        enabled: data?.enabled ?? null,
        // null = the worker could not count; show a dash, not a zero.
        totalRecords: data?.total_records ?? null,
        liveRecords: data?.lifecycle?.live_records ?? null,
        tombstoned: data?.lifecycle?.tombstoned_records ?? null,
        kinds: Object.entries((data?.episodes_by_type ?? {}) as Record<string, number>).map(
          ([kind, records]) => ({ kind, records }),
        ),
      };
    },
  });
}

const fmtCount = (n: number | null) => (n == null ? '—' : n.toLocaleString());

export function ExplorerPanel() {
  const vm = useRecallMemory();

  return (
    <section className="panel">
      <div className="panel-head">
        <h2>Explorer</h2>
        <span className="meta">recall memory</span>
      </div>

      {vm.isLoading && <div className="state">Loading recall memory…</div>}
      {vm.isError && <div className="state err">{(vm.error as Error)?.message}</div>}

      {vm.data && (
        <>
          <StatTiles
            tiles={[
              {
                label: 'Archiver',
                value: !vm.data.started ? 'Off' : vm.data.enabled === false ? 'Disabled' : 'Running',
                hot: !vm.data.started || vm.data.enabled === false,
              },
              { label: 'Episodes', value: fmtCount(vm.data.totalRecords) },
              { label: 'Live', value: fmtCount(vm.data.liveRecords) },
              { label: 'Tombstoned', value: fmtCount(vm.data.tombstoned) },
            ]}
          />

          <h3 className="subhead">Live episodes by type</h3>
          {vm.data.kinds.length ? (
            vm.data.kinds.map((k) => (
              <div className="vseg-row" key={k.kind}>
                <div className="vseg-id">
                  <span className={cn('vseg-kind', k.kind === 'traversal' ? 'trav' : 'conv')}>{k.kind}</span>
                </div>
                <span className="vseg-records">{k.records.toLocaleString()} records</span>
              </div>
            ))
          ) : (
            <div className="state">No episodes recorded.</div>
          )}
        </>
      )}
    </section>
  );
}
