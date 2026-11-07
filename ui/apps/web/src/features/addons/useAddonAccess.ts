// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 PersonifAI LLC

import { useMutation, useQuery, useQueryClient, useMetisClient } from '@metis/core';

/**
 * Add-on access (noomesh-internal f99): which people may use each feature an
 * add-on declares. The add-on declares its features; noomesh holds the
 * settings and enforces them the same way on every surface. These are the
 * routes `noo addons access …` drives; there is no second write path.
 */

/** One feature the add-on's manifest declares. */
export interface AccessFeature {
  name: string;
  title: string;
  description: string;
  /** Who the add-on recommends it for (`user|operator|admin|none`). Grants nothing. */
  suggested: string;
  /** May act for a present person through their tasks. */
  delegate: boolean;
  /** The add-on routes this feature opens. */
  routes: string[];
  /** This feature gates the add-on's web UI. */
  ui: boolean;
  /** Opens a write route the add-on did not declare owner-scoped. */
  hasUnscopedWrite: boolean;
}

/** One stored on/off setting. "Inherit" is the absence of one. */
export interface AccessSetting {
  feature: string;
  /** `role:<tier>`, `team:<name>`, `user:<account>` or `key:<consumer>`. */
  subject: string;
  allowed: boolean;
  setBy: string;
  setAt: string;
  source: string;
  reason: string | null;
}

export interface AccessView {
  addon: string;
  /** Declares no features yet: its routes keep their own `min_role`. */
  legacy: boolean;
  features: AccessFeature[];
  settings: AccessSetting[];
  /** Settings kept for features the add-on no longer declares; they open nothing. */
  staleFeatures: string[];
  superAdmins: string[];
}

/** One person's answer for one feature, and the setting that decided it. */
export interface PersonFeature {
  feature: string;
  title: string;
  allowed: boolean;
  decidedBy: string;
}

export interface PersonView {
  account: string;
  role: string | null;
  teams: string[];
  superAdmin: boolean;
  /** This add-on's features for the person; empty when it declares none. */
  features: PersonFeature[];
}

export type SetValue = 'on' | 'off' | 'inherit';

/** The gateway's own words on failure (`{"detail"}` or `{"error"}`). */
export function gatewayMessage(error: unknown): string | undefined {
  if (error && typeof error === 'object') {
    const e = error as { error?: unknown; detail?: unknown };
    if (typeof e.error === 'string' && e.error) return e.error;
    if (typeof e.detail === 'string' && e.detail) return e.detail;
  }
  return undefined;
}

const str = (v: unknown): string => (typeof v === 'string' ? v : '');
const strs = (v: unknown): string[] => (Array.isArray(v) ? v.filter((x): x is string => typeof x === 'string') : []);
const obj = (v: unknown): Record<string, unknown> => (v && typeof v === 'object' ? (v as Record<string, unknown>) : {});

/** The `GET /api/addons/{addon}/access` body, as the panel reads it. */
export function toAccessView(raw: unknown): AccessView {
  const r = obj(raw);
  const features = (Array.isArray(r.features) ? r.features : []).map((f) => {
    const x = obj(f);
    return {
      name: str(x.name),
      title: str(x.title) || str(x.name),
      description: str(x.description),
      suggested: str(x.suggested),
      delegate: x.delegate === true,
      routes: strs(x.routes),
      ui: x.ui === true,
      hasUnscopedWrite: x.has_unscoped_write === true,
    };
  });
  const settings = (Array.isArray(r.settings) ? r.settings : []).map((s) => {
    const x = obj(s);
    return {
      feature: str(x.feature),
      subject: str(x.subject),
      allowed: x.allowed === true,
      setBy: str(x.set_by),
      setAt: str(x.set_at),
      source: str(x.source),
      reason: typeof x.reason === 'string' && x.reason ? x.reason : null,
    };
  });
  return {
    addon: str(r.addon),
    legacy: r.legacy === true,
    features,
    settings,
    staleFeatures: strs(r.stale_features),
    superAdmins: strs(r.super_admins),
  };
}

/** The `GET /api/security/users/{username}/addon-access` body, narrowed to one add-on. */
export function toPersonView(raw: unknown, addon: string): PersonView {
  const r = obj(raw);
  const mine = (Array.isArray(r.addons) ? r.addons : []).map(obj).find((a) => a.addon === addon);
  return {
    account: str(r.account),
    role: typeof r.role === 'string' ? r.role : null,
    teams: strs(r.teams),
    superAdmin: r.super_admin === true,
    features: (Array.isArray(mine?.features) ? mine.features : []).map((f) => {
      const x = obj(f);
      return { feature: str(x.feature), title: str(x.title) || str(x.feature), allowed: x.allowed === true, decidedBy: str(x.decided_by) };
    }),
  };
}

/**
 * The add-ons access can be set on: `/health`'s `addons_registered` (sent to
 * a signed-in caller), the runtime registry, where every add-on has a route
 * manifest. Not the `enabled` words in `addons`: those include the compiled
 * rows (identity, trellion, trellion_intel), which have no manifest, so the
 * access route 404s each one. Without the field (a gateway older than this
 * console) nothing is guessed: the list is unavailable.
 */
export function useAccessAddons() {
  const client = useMetisClient();
  return useQuery<string[]>({
    queryKey: ['addon-access', 'addons'],
    refetchInterval: 60_000,
    queryFn: async () => {
      const { data, error } = await client.GET('/health');
      if (error || !data) throw new Error(gatewayMessage(error) ?? 'Add-on list unavailable');
      const registered = (data as { addons_registered?: unknown }).addons_registered;
      if (!Array.isArray(registered)) {
        throw new Error('This gateway does not list its registered add-ons (older than this console)');
      }
      return registered.filter((id): id is string => typeof id === 'string');
    },
  });
}

/** `GET /api/addons/{addon}/access`. Operator or above. */
export function useAddonAccess(addon: string | null) {
  const client = useMetisClient();
  return useQuery<AccessView>({
    queryKey: ['addon-access', 'view', addon],
    enabled: !!addon,
    queryFn: async () => {
      const { data, error } = await client.GET('/api/addons/{addon}/access', {
        params: { path: { addon: addon ?? '' } },
      });
      if (error || !data) throw new Error(gatewayMessage(error) ?? `Access settings for ${addon} unavailable`);
      return toAccessView(data);
    },
  });
}

/**
 * `PUT /api/addons/{addon}/access`. Admin. The gateway decides what is
 * allowed (a setting that covers an admin is a super admin's; turning one off
 * takes a reason) and its refusal is shown as it words it.
 */
export function useSetAddonAccess() {
  const client = useMetisClient();
  const qc = useQueryClient();
  return useMutation<
    { from: string; to: string },
    Error,
    { addon: string; feature: string; subject: string; value: SetValue; reason?: string }
  >({
    mutationFn: async ({ addon, feature, subject, value, reason }) => {
      const body: { feature: string; subject: string; value: SetValue; reason?: string } = { feature, subject, value };
      if (reason && reason.trim()) body.reason = reason.trim();
      const { data, error } = await client.PUT('/api/addons/{addon}/access', {
        params: { path: { addon } },
        body,
      });
      if (error || !data) throw new Error(gatewayMessage(error) ?? 'The change was not saved');
      const d = obj(data);
      return { from: str(d.from), to: str(d.to) };
    },
    onSuccess: (_r, v) => {
      qc.invalidateQueries({ queryKey: ['addon-access', 'view', v.addon] });
      qc.invalidateQueries({ queryKey: ['addon-access', 'person'] });
    },
  });
}

/** `GET /api/security/users/{username}/addon-access`: who decided, for one person. Operator or above. */
export function usePersonAccess(addon: string | null, username: string) {
  const client = useMetisClient();
  const account = username.trim();
  return useQuery<PersonView>({
    queryKey: ['addon-access', 'person', addon, account],
    enabled: !!addon && !!account,
    queryFn: async () => {
      const { data, error } = await client.GET('/api/security/users/{username}/addon-access', {
        params: { path: { username: account } },
      });
      if (error || !data) throw new Error(gatewayMessage(error) ?? `No access answer for ${account}`);
      return toPersonView(data, addon ?? '');
    },
  });
}
