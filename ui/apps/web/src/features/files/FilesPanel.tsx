// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 PersonifAI LLC

import { useQuery, useMetisClient } from '@metis/core';
import { cn } from '@/lib/utils';

interface Dir {
  host: string;
  mount: string;
  label: string;
  writable: boolean;
  protected: boolean;
}

function useUserDirs() {
  const client = useMetisClient();
  return useQuery<Dir[]>({
    queryKey: ['files', 'user-dirs'],
    queryFn: async () => {
      const { data, error } = await client.GET('/api/v1/settings/user-dirs');
      if (error) throw new Error('File locations API unavailable');
      return (data?.directories ?? []).map((d) => ({
        host: d.host ?? '',
        mount: d.mount ?? '',
        label: d.label ?? '',
        writable: d.writable ?? false,
        protected: d.protected ?? false,
      }));
    },
  });
}

export function FilesPanel() {
  const dirs = useUserDirs();

  return (
    <section className="panel">
      <div className="panel-head">
        <h2>File locations</h2>
        <span className="meta">{dirs.data ? `${dirs.data.length} configured` : '—'}</span>
      </div>

      {dirs.isLoading && <div className="state">Loading directories…</div>}
      {dirs.isError && <div className="state err">{(dirs.error as Error)?.message}</div>}

      {dirs.data &&
        (dirs.data.length ? (
          dirs.data.map((d) => (
            <div className={cn('dir-row', d.writable && 'writable')} key={d.host}>
              <span className="dir-icon">📁</span>
              <div className="dir-main">
                <div className="dir-host">
                  {d.host}
                  {d.protected && (
                    <span className="dir-shield" title="Protected — AI access requires approval">
                      🛡
                    </span>
                  )}
                </div>
                <div className="dir-mount">mount: {d.mount}</div>
              </div>
              {d.label && <span className="dir-label">{d.label}</span>}
              <span className={cn('dir-rw', d.writable ? 'rw' : 'ro')}>{d.writable ? 'RW' : 'RO'}</span>
            </div>
          ))
        ) : (
          <div className="state">No directories configured.</div>
        ))}
    </section>
  );
}
