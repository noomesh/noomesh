// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 PersonifAI LLC

import { toast } from 'sonner';
import { cn } from '@/lib/utils';
import { meterLevel } from '@/lib/meter';
import { StatTiles } from '@/components/StatTiles';
import { StatusBadge, type Tone } from '@/components/StatusBadge';
import { Button } from '@/components/ui/button';
import { useMemory, useEmbedControl } from './useMemory';

const num = (n: number) => n.toLocaleString();
const workerTone = (s: string): Tone =>
  s === 'running' ? 'good' : s === 'error' ? 'bad' : 'neutral';

export function MemoryPanel() {
  const mem = useMemory();
  const embed = useEmbedControl();
  const running = mem.data?.worker.state === 'running';

  function onToggle() {
    const action = running ? 'stop' : 'start';
    embed.mutate(action, {
      onSuccess: () => toast.success(`Embedding worker ${action === 'start' ? 'started' : 'stopped'}`),
      onError: (e) => toast.error('Action failed', { description: (e as Error).message }),
    });
  }

  const coverage = mem.data && mem.data.storage.total > 0
    ? Math.round((mem.data.storage.embedded / mem.data.storage.total) * 100)
    : 0;

  return (
    <section className="panel">
      <div className="panel-head">
        <h2>Memory</h2>
        <div className="panel-head-right">
          {mem.data && <StatusBadge tone={workerTone(mem.data.worker.state)}>{mem.data.worker.state}</StatusBadge>}
          <Button
            size="sm"
            variant={running ? 'outline' : 'default'}
            disabled={embed.isPending || !mem.data}
            onClick={onToggle}
            title={
              running
                ? 'Pause embedding. Existing embeddings are kept; new conversations just wait.'
                : 'Embed conversations so they can be searched. Runs in the background and uses a backend.'
            }
          >
            {running ? 'Stop worker' : 'Start worker'}
          </Button>
        </div>
      </div>

      {mem.isLoading && <div className="state">Loading memory stats…</div>}
      {mem.isError && <div className="state err">{(mem.error as Error)?.message}</div>}

      {mem.data && (
        <>
          <h3 className="subhead">Storage · {coverage}% embedded</h3>
          <StatTiles
            tiles={[
              { label: 'Records', value: num(mem.data.storage.total) },
              { label: 'Embedded', value: num(mem.data.storage.embedded) },
              { label: 'Unembedded', value: num(mem.data.storage.unembedded), hot: mem.data.storage.unembedded > 0 },
              { label: 'Users', value: mem.data.storage.users },
            ]}
          />

          <h3 className="subhead">Conversations</h3>
          <StatTiles
            tiles={[
              { label: 'Conversations', value: num(mem.data.conv.conversations) },
              { label: 'Messages', value: num(mem.data.conv.messages) },
              { label: 'Tool calls', value: num(mem.data.conv.toolCalls) },
              { label: 'Avg msgs', value: mem.data.conv.avgMessages.toFixed(1) },
            ]}
          />

          <h3 className="subhead">Tool usage</h3>
          {mem.data.tools.length ? (
            mem.data.tools.map((t) => {
              const rate = Math.round(t.successRate * 100);
              return (
                <div className="tool-row" key={t.name}>
                  <div className="tool-id">
                    <span className="tool-name">{t.name}</span>
                    <span className="tool-calls">{num(t.calls)} calls</span>
                  </div>
                  <div className="tool-right">
                    <span className="meter tool-meter">
                      {rate}%
                      <span className="track">
                        <span
                          className={cn('fill', meterLevel(rate, 'high-good'))}
                          style={{ width: `${Math.min(100, rate)}%` }}
                        />
                      </span>
                    </span>
                    <span className="tool-avg">{t.avgMs ? `${Math.round(t.avgMs)}ms` : '—'}</span>
                  </div>
                </div>
              );
            })
          ) : (
            <div className="state">No tool activity.</div>
          )}
        </>
      )}
    </section>
  );
}
