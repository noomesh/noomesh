// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 PersonifAI LLC

import { useState } from 'react';
import { toast } from 'sonner';
import { useQuery, useMutation, useQueryClient, useMetisClient } from '@metis/core';
import { relTime } from '@/lib/format';
import { StatusBadge, type Tone } from '@/components/StatusBadge';
import { Button } from '@/components/ui/button';
import { useConfirm } from '@/components/ConfirmDialog';

const HINTS: Record<string, string> = {
  unembedded_documents: 'Embeds new documents into the knowledge base so they become searchable via RAG.',
  missing_graph_entities: 'Extracts entities and relationships from documents to build the knowledge graph.',
  node_health: 'Monitors cluster nodes and alerts when any go offline.',
  node_auto_quarantine: 'Quarantines nodes that fail 3+ times in a row to prevent cascading errors.',
  backend_availability: 'Auto-starts an inference backend if none are running so the agent can think.',
  backend_idle_scaledown: 'Stops idle backends on remote nodes to free GPU memory. Controller is exempt.',
  backend_scaling: 'Scales up replicas when average cluster load exceeds 80%. Opt-in only.',
  job_queue_depth: 'Warns when the async job queue gets too deep (>10 pending).',
  watched_folders: 'Auto-ingests new files from monitored folders into the knowledge base.',
  test_suite_health: 'Periodically runs health checks against key endpoints.',
  cert_auto_rotate:
    'Rotates certs expiring within 30 days. Armed, that is a fleet-wide backup, rotate, reload and probe.',
  cert_expiry_check:
    'Alerts on certs expiring within 30 days. Alerts only — the rule above is the one that acts.',
  disk_watermark: 'Alerts past the disk watermark; armed, reclaims Docker space along a bounded ladder.',
};

type Outcome = 'would' | 'fired' | 'error' | 'all';

interface Decision {
  at: string;
  location: string;
  outcome: string;
  target: string | null;
  detail: string;
}

interface DecisionsResult {
  rows: Decision[];
  /** Set when the store could not be READ. Distinct from an empty `rows`,
   *  which means nothing would have happened. */
  unreadable?: string;
  detail?: string;
}

interface AutonomyLoc {
  name: string;
  enabled: boolean;
  interval: number;
  lastCheck: string | null;
  /** RFC3339, or null for unknown. From the audit table, so it survives a
   *  restart — unlike lastCheck, which lives in the loop's memory. */
  lastFired: string | null;
  /** `undefined` = this rule has NO action gate. `false` = it has one and it
   *  is off. Never collapse them: the first says it cannot act at all, the
   *  second says it could if armed, and that difference is exactly what an
   *  operator uses to decide what is safe to turn on. */
  armed?: boolean;
  dryRun?: boolean;
  conditions: number;
  actions: number;
  source: string;
}

interface AutonomyStatus {
  /** The engine is *permitted* to act. */
  enabled: boolean;
  /** The engine's loop is *actually ticking*. Not the same fact. */
  running: boolean;
  runningDetail: string | null;
  auditEntries: number | null;
  auditDetail: string | null;
  locations: AutonomyLoc[];
}

function useAutonomy() {
  const client = useMetisClient();
  return useQuery<AutonomyStatus>({
    queryKey: ['autonomy'],
    refetchInterval: 30_000,
    queryFn: async () => {
      const { data, error } = await client.GET('/api/autonomy/status');
      if (error) throw new Error('Autonomy engine not available');
      return {
        enabled: data?.enabled ?? false,
        running: data?.running ?? false,
        runningDetail: data?.running_detail ?? null,
        auditEntries: data?.audit_entries ?? null,
        auditDetail: data?.audit_detail ?? null,
        locations: (data?.locations ?? []).map((l) => ({
          name: l.name ?? '?',
          enabled: l.enabled ?? true,
          interval: l.interval ?? 0,
          lastCheck: l.last_check ?? null,
          lastFired: l.last_fired ?? null,
          // Deliberately not `?? false` — absence is not a negative.
          armed: typeof l.armed === 'boolean' ? l.armed : undefined,
          dryRun: typeof l.dry_run === 'boolean' ? l.dry_run : undefined,
          conditions: l.conditions ?? 0,
          actions: l.actions ?? 0,
          source: l.source ?? 'config',
        })),
      };
    },
  });
}

/** What autonomy WOULD have done: the decisions a disarmed rule logged
 *  instead of taking. Returns the unreadable envelope rather than throwing —
 *  an empty list means "nothing would have happened", an unreadable store
 *  means "I cannot tell you", and rendering the second as the first is the
 *  defect this endpoint was added to remove. */
function useDecisions(outcome: Outcome) {
  const client = useMetisClient();
  return useQuery<DecisionsResult>({
    queryKey: ['autonomy', 'decisions', outcome],
    refetchInterval: 30_000,
    queryFn: async () => {
      const { data, error } = await client.GET('/api/autonomy/decisions', {
        params: { query: { limit: 25, outcome } },
      });
      if (error || !data) throw new Error('Decisions are currently unavailable.');
      if (data.error) return { unreadable: data.error, detail: data.detail ?? '', rows: [] };
      return {
        rows: (data.decisions ?? []).map(
          (x): Decision => ({
            at: x.at ?? '',
            location: x.location ?? '?',
            outcome: x.outcome ?? '',
            target: x.target ?? null,
            detail: x.detail ?? '',
          }),
        ),
      };
    },
  });
}

/** Arm or disarm a rule's ACTION. The toggle route upserts
 *  `noo_autonomy_overrides`, which wins over the YAML and applies on the next
 *  tick — no restart. `config` is sent only when arming changes, so enabling
 *  a rule can never silently disarm an action the operator opted into. */
function useToggleLocation() {
  const client = useMetisClient();
  const qc = useQueryClient();
  return useMutation({
    mutationFn: async (vars: { name: string; enabled: boolean; armed: boolean }) => {
      const { error } = await client.POST('/api/autonomy/locations/{name}/toggle', {
        params: { path: { name: vars.name } },
        body: { enabled: vars.enabled, config: { enabled_action: vars.armed } },
      });
      if (error) throw new Error('Change refused — operator permission required?');
    },
    onSuccess: () => qc.invalidateQueries({ queryKey: ['autonomy'] }),
  });
}

/** Three states, not two — see AutonomyLoc.armed. */
function armedMeta(l: AutonomyLoc): { label: string; tone: Tone; title: string } {
  if (l.armed === undefined)
    return {
      label: '—',
      tone: 'neutral',
      title: 'No action gate: this rule reports or alerts, it does not change anything.',
    };
  if (!l.armed)
    return {
      label: 'Disarmed',
      tone: 'neutral',
      title: 'Has an action, switched off. It records what it would have done instead.',
    };
  if (l.dryRun)
    return {
      label: 'Dry run',
      tone: 'warn',
      title: 'Armed but still previewing: the second opt-in (dry_run: false) is not set.',
    };
  return { label: 'Armed', tone: 'bad', title: 'This rule CHANGES the fleet when it fires.' };
}

function outcomeMeta(outcome: string): { label: string; tone: Tone } {
  switch (outcome) {
    case 'fired':
      return { label: 'Did', tone: 'bad' };
    case 'would':
      return { label: 'Would have', tone: 'warn' };
    case 'error':
      return { label: 'Could not evaluate', tone: 'bad' };
    default:
      return { label: outcome || 'unknown', tone: 'neutral' };
  }
}

const OUTCOMES: [Outcome, string][] = [
  ['would', 'Would have'],
  ['fired', 'Did'],
  ['error', 'Could not evaluate'],
  ['all', 'Everything'],
];

/** Null is UNKNOWN, not never: lastCheck is empty after a restart and
 *  lastFired is empty until something fires. A dash says "I cannot tell
 *  you"; "never" would be a claim. */
const when = (iso: string | null) => (iso ? `${relTime(iso)} ago` : '—');
const fmtInterval = (s: number) => (s >= 60 ? `${Math.round(s / 60)}m` : `${s}s`);

/**
 * What the agent does when nobody asked it to.
 *
 * The headline is deliberately two facts, not one. The gateway separates
 * *enabled* (the engine is permitted to act) from *running* (its loop is
 * actually ticking) because collapsing them is the "the loop died and nobody
 * noticed" failure its `loop_health` registry exists to catch. This panel used
 * to read neither — it listed the rules and said nothing about whether the
 * engine evaluating them was alive.
 */
export function AutonomyPanel() {
  const [outcome, setOutcome] = useState<Outcome>('would');
  const auto = useAutonomy();
  const decisions = useDecisions(outcome);
  const toggle = useToggleLocation();
  const confirm = useConfirm();
  const d = auto.data;
  const active = d?.locations.filter((l) => l.enabled).length ?? 0;
  const armedCount = d?.locations.filter((l) => l.armed && !l.dryRun).length ?? 0;
  const busy = toggle.isPending ? toggle.variables?.name : undefined;

  async function onArm(l: AutonomyLoc, next: boolean) {
    const ok = await confirm({
      title: next ? `Arm ${l.name}?` : `Disarm ${l.name}?`,
      description: next
        ? 'Armed, this rule changes the fleet when its condition holds. Read what it would have done first — the decisions below are exactly that.'
        : 'It keeps watching and keeps recording what it would have done, but takes no action.',
      confirmText: next ? 'Arm' : 'Disarm',
      destructive: next,
    });
    if (!ok) return;
    toggle.mutate(
      { name: l.name, enabled: l.enabled, armed: next },
      {
        onSuccess: () =>
          toast.success(next ? 'Armed' : 'Disarmed', {
            description: `${l.name} — applies on the next tick, no restart`,
          }),
        onError: (e) => toast.error('Change failed', { description: (e as Error).message }),
      },
    );
  }

  // Permitted but not ticking is the case worth shouting about: every rule
  // below reads as armed while nothing is actually evaluating them.
  const stalled = !!d && d.enabled && !d.running;

  return (
    <section className="panel">
      <div className="panel-head">
        <h2>Autonomy</h2>
        <span className="meta">
          {d ? `${active}/${d.locations.length} rules on · ${armedCount} armed` : '—'}
          {auto.isFetching && ' · refreshing…'}
        </span>
      </div>

      {auto.isLoading && <div className="state">Loading autonomy engine…</div>}
      {auto.isError && <div className="state err">{(auto.error as Error)?.message}</div>}

      {d && (
        <>
          <div className="auto-status">
            <div className={`auto-stat ${d.enabled ? 'on' : 'off'}`}>
              <span className="auto-stat-k">Permitted to act</span>
              <span className="auto-stat-v">{d.enabled ? 'yes' : 'no'}</span>
            </div>
            <div className={`auto-stat ${d.running ? 'on' : d.enabled ? 'bad' : 'off'}`}>
              <span className="auto-stat-k">Loop alive</span>
              <span className="auto-stat-v">{d.running ? 'yes' : 'no'}</span>
            </div>
          </div>

          {stalled && (
            <div className="auto-warn">
              Autonomy is enabled but its loop is not running — the rules below are not being
              evaluated.{d.runningDetail ? ` ${d.runningDetail}` : ''}
            </div>
          )}
          {!stalled && !d.running && d.runningDetail && (
            <p className="auto-note">{d.runningDetail}</p>
          )}

          <h3 className="subhead">Rules</h3>
          {d.locations.length === 0 && <p className="auto-note">No autonomy rules configured.</p>}
          {d.locations.map((l) => (
            <div className="auto-row" key={l.name}>
              <span className={`auto-dot ${l.enabled ? 'on' : 'off'}`} />
              <div className="auto-main">
                <div className="auto-head">
                  <span className="auto-name">{l.name}</span>
                  <span className="auto-interval">every {fmtInterval(l.interval)}</span>
                  {/* What it would actually do, which is the thing a new
                      operator wants before deciding whether to leave it on. */}
                  <span className="auto-interval">
                    {l.conditions} cond · {l.actions} action{l.actions === 1 ? '' : 's'}
                  </span>
                  {l.source === 'db' && <span className="auto-interval">custom</span>}
                  <span title={armedMeta(l).title}>
                    <StatusBadge tone={armedMeta(l).tone}>{armedMeta(l).label}</StatusBadge>
                  </span>
                </div>
                {/* Null reads as a dash, not "never" — see `when`. The old
                    line inferred "active" from lastCheck, which the gateway
                    hardcoded to null until 2026-09-04, so every rule read
                    "pending" forever. */}
                <div className="auto-meta">
                  checked {when(l.lastCheck)} · fired {when(l.lastFired)}
                </div>
                {HINTS[l.name] && <div className="auto-hint">{HINTS[l.name]}</div>}
              </div>
              {l.armed !== undefined && (
                <Button
                  size="sm"
                  variant={l.armed ? 'outline' : 'default'}
                  disabled={busy === l.name}
                  onClick={() => onArm(l, !l.armed)}
                >
                  {busy === l.name ? '…' : l.armed ? 'Disarm' : 'Arm'}
                </Button>
              )}
            </div>
          ))}

          <div className="panel-head" style={{ marginTop: '1.25rem' }}>
            <h3 className="subhead">Decisions</h3>
            <select
              className="filter-select"
              value={outcome}
              onChange={(e) => setOutcome(e.target.value as Outcome)}
              aria-label="Filter autonomy decisions by outcome"
            >
              {OUTCOMES.map(([v, label]) => (
                <option key={v} value={v}>
                  {label}
                </option>
              ))}
            </select>
          </div>

          {decisions.isLoading && <div className="state">Loading decisions…</div>}
          {decisions.isError && (
            <div className="state err">{(decisions.error as Error)?.message}</div>
          )}
          {/* Unreadable and empty are DIFFERENT answers. Rendering the first
              as the second says "autonomy has never acted" when the truth is
              that nobody can tell. */}
          {decisions.data?.unreadable ? (
            <div className="state err">
              {decisions.data.unreadable}
              {decisions.data.detail ? ` — ${decisions.data.detail}` : ''}
            </div>
          ) : decisions.data && decisions.data.rows.length === 0 ? (
            <p className="auto-note">
              {outcome === 'would'
                ? 'Nothing recorded — no disarmed rule has met its condition yet.'
                : 'Nothing recorded for this outcome.'}
            </p>
          ) : (
            decisions.data?.rows.map((x, i) => (
              <div className="auto-row" key={`${x.at}-${i}`}>
                <div className="auto-main">
                  <div className="auto-head">
                    <StatusBadge tone={outcomeMeta(x.outcome).tone}>
                      {outcomeMeta(x.outcome).label}
                    </StatusBadge>
                    <span className="auto-name">{x.location}</span>
                    {x.target && <span className="auto-interval">{x.target}</span>}
                    <span className="auto-interval">{when(x.at)}</span>
                  </div>
                  {x.detail && <div className="auto-hint">{x.detail}</div>}
                </div>
              </div>
            ))
          )}

          <p className="auto-note">
            {d.auditEntries !== null
              ? `${d.auditEntries} recorded action${d.auditEntries === 1 ? '' : 's'}.`
              : (d.auditDetail ?? 'Fired actions are not tracked on this install.')}
          </p>
        </>
      )}
    </section>
  );
}
