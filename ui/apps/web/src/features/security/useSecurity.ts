// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 PersonifAI LLC

import { useQuery, useMutation, useQueryClient, useMetisClient } from '@metis/core';
import { num } from '@/lib/num';

export interface Cert {
  name: string;
  role: string;
  subject: string;
  expires: string;
  /** null = no readable expiry (renders a dash, never 0d). */
  daysLeft: number | null;
  /** 'unknown' = the cert exists but reported no readable expiry. */
  status: 'ok' | 'expiring' | 'expired' | 'missing' | 'unknown';
}
export interface PendingApproval {
  id: string;
  tool: string;
  riskLevel: string;
  createdAt: string;
}
export interface SecurityData {
  riskLevel: string;
  violations: Record<string, number>;
  stats: { pending: number | null; approved: number | null; denied: number | null; total: number | null };
  pending: PendingApproval[];
  pki: {
    configured: boolean;
    summary: { total: number; ok: number; expiring: number; expired: number };
    certs: Cert[];
  };
}

const KEY = ['security'];

/** Aggregated security posture: violations + approvals + PKI (polled 30s). */
export function useSecurity() {
  const client = useMetisClient();
  return useQuery<SecurityData>({
    queryKey: KEY,
    refetchInterval: 30_000,
    queryFn: async () => {
      const [v, s, p, k] = await Promise.all([
        client.GET('/api/security/violations', { params: { query: { period_hours: 24 } } }),
        client.GET('/api/approval/stats'),
        client.GET('/api/approval/pending'),
        client.GET('/api/security/pki/status'),
      ]);
      if (v.error || s.error) throw new Error('Security posture unavailable');
      // PKI shape (now typed by the contract): { status, pki_dir,
      // certs: { ca, gateway, nodes:[{node_id, cert}] } }. No summary/days_left/
      // per-cert status are provided — derive them from not_after.
      type PkiCert = { exists?: boolean; subject?: string; not_after?: string };
      const pk = k.data;
      const parseCert = (name: string, role: string, c?: PkiCert): Cert => {
        const exp = c?.not_after ? new Date(c.not_after) : null;
        const daysLeft =
          exp && !isNaN(exp.getTime()) ? Math.round((exp.getTime() - Date.now()) / 86_400_000) : null;
        const status: Cert['status'] = !c?.exists
          ? 'missing'
          : daysLeft === null
            ? 'unknown'
            : daysLeft < 0
            ? 'expired'
            : daysLeft <= 30
              ? 'expiring'
              : 'ok';
        return { name, role, subject: c?.subject ?? '', expires: c?.not_after ?? '', daysLeft, status };
      };
      const cs = pk?.certs ?? {};
      const certs: Cert[] = [];
      if (cs.ca) certs.push(parseCert('CA', 'ca', cs.ca));
      if (cs.gateway) certs.push(parseCert('Gateway', 'gateway', cs.gateway));
      for (const n of Array.isArray(cs.nodes) ? cs.nodes : []) {
        certs.push(parseCert(n.node_id || 'node', 'node', n.cert));
      }
      return {
        riskLevel: v.data?.risk_level ?? 'UNKNOWN',
        violations: (v.data?.violations ?? {}) as Record<string, number>,
        stats: {
          pending: num(s.data?.pending),
          approved: num(s.data?.approved),
          denied: num(s.data?.denied),
          total: num(s.data?.total),
        },
        pending: (p.data?.pending ?? []).map((r) => ({
          id: r.id ?? '',
          tool: r.tool ?? '?',
          riskLevel: r.risk_level ?? 'low',
          createdAt: r.created_at ?? '',
        })),
        pki: {
          configured: pk?.status ? pk.status !== 'not_initialized' : certs.length > 0,
          summary: {
            total: certs.length,
            ok: certs.filter((c) => c.status === 'ok').length,
            expiring: certs.filter((c) => c.status === 'expiring').length,
            expired: certs.filter((c) => c.status === 'expired' || c.status === 'missing').length,
          },
          certs,
        },
      };
    },
  });
}

/** Approve or deny a pending exec-approval request. */
export function useApprovalDecision() {
  const client = useMetisClient();
  const qc = useQueryClient();
  return useMutation({
    mutationFn: async (vars: { id: string; decision: 'approve' | 'deny' }) => {
      const opts = { params: { path: { request_id: vars.id } } };
      const res =
        vars.decision === 'approve'
          ? await client.POST('/api/approval/{request_id}/approve', opts)
          : await client.POST('/api/approval/{request_id}/deny', opts);
      if (res.error) throw new Error('Decision failed');
    },
    onSuccess: () => qc.invalidateQueries({ queryKey: KEY }),
  });
}
