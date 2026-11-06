// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 PersonifAI LLC

import { describe, it, expect, vi, beforeEach } from 'vitest';

const H = vi.hoisted(() => ({
  get: vi.fn(),
  put: vi.fn(),
  invalidate: vi.fn(),
  lastQuery: { current: null as null | Record<string, unknown> },
  lastMutation: { current: null as null | Record<string, unknown> },
}));

vi.mock('@metis/core', () => ({
  useMetisClient: () => ({ GET: H.get, PUT: H.put }),
  useQueryClient: () => ({ invalidateQueries: H.invalidate }),
  useQuery: (opts: Record<string, unknown>) => {
    H.lastQuery.current = opts;
    return { data: undefined, isLoading: true };
  },
  useMutation: (opts: Record<string, unknown>) => {
    H.lastMutation.current = opts;
    return {};
  },
}));

import {
  toAccessView,
  toPersonView,
  useAccessAddons,
  useAddonAccess,
  useSetAddonAccess,
  usePersonAccess,
} from './useAddonAccess';
import { settingsFor } from './AddonAccessPanel';

const runQuery = () => (H.lastQuery.current?.queryFn as () => Promise<unknown>)();
const runMutation = (v: unknown) => (H.lastMutation.current?.mutationFn as (v: unknown) => Promise<unknown>)(v);

// The gateway's body (routes/addon_access.rs access_get), with the fictional add-on.
const BODY = {
  addon: 'rhaddon',
  legacy: false,
  features: [
    { name: 'talk', title: 'Talk', description: 'Live voice', suggested: 'user', delegate: true, routes: ['session'], ui: true, has_unscoped_write: false },
    { name: 'admin_tools', title: '', suggested: 'admin', routes: [], has_unscoped_write: true },
  ],
  settings: [
    { addon: 'rhaddon', feature: 'talk', subject: 'role:user', allowed: true, set_by: 'root', set_at: '2026-11-04T10:00:00Z', source: 'operator', reason: null },
    { addon: 'rhaddon', feature: 'talk', subject: 'user:bob', allowed: false, set_by: 'root', set_at: '2026-11-04T10:01:00Z', source: 'operator', reason: 'left the team' },
    { addon: 'rhaddon', feature: 'talk', subject: 'team:ops', allowed: true, set_by: 'ann', set_at: '', source: 'enable', reason: '' },
  ],
  stale_features: ['old'],
  super_admins: ['root'],
};

describe('toAccessView', () => {
  it('maps the gateway body, defaulting a blank title to the name', () => {
    const v = toAccessView(BODY);
    expect(v.addon).toBe('rhaddon');
    expect(v.features[0]).toEqual({
      name: 'talk', title: 'Talk', description: 'Live voice', suggested: 'user', delegate: true, routes: ['session'], ui: true, hasUnscopedWrite: false,
    });
    expect(v.features[1]).toMatchObject({ title: 'admin_tools', delegate: false, ui: false, hasUnscopedWrite: true, description: '' });
    expect(v.settings[1]).toEqual({
      feature: 'talk', subject: 'user:bob', allowed: false, setBy: 'root', setAt: '2026-11-04T10:01:00Z', source: 'operator', reason: 'left the team',
    });
    expect(v.settings[2].reason).toBeNull();
    expect(v.staleFeatures).toEqual(['old']);
    expect(v.superAdmins).toEqual(['root']);
  });

  it('reads a malformed body as empty, never as allowed', () => {
    const v = toAccessView({ settings: [{ feature: 'talk', subject: 'role:user', allowed: 'yes' }] });
    expect(v.settings[0].allowed).toBe(false);
    expect(v.features).toEqual([]);
    expect(toAccessView(null).legacy).toBe(false);
  });

  it('orders a feature’s settings as decide reads them: credential, team, role', () => {
    expect(settingsFor(toAccessView(BODY), 'talk').map((s) => s.subject)).toEqual(['user:bob', 'team:ops', 'role:user']);
  });
});

describe('toPersonView', () => {
  it('keeps the one add-on and the setting that decided each feature', () => {
    const p = toPersonView(
      {
        account: 'bob', role: 'user', teams: ['ops'], super_admin: false,
        addons: [
          { addon: 'other', features: [{ feature: 'x', allowed: true, decided_by: 'role:user' }] },
          { addon: 'rhaddon', features: [{ feature: 'talk', title: 'Talk', allowed: false, decided_by: 'user:bob' }] },
        ],
      },
      'rhaddon',
    );
    expect(p).toEqual({
      account: 'bob', role: 'user', teams: ['ops'], superAdmin: false,
      features: [{ feature: 'talk', title: 'Talk', allowed: false, decidedBy: 'user:bob' }],
    });
  });
});

describe('the routes', () => {
  beforeEach(() => {
    H.get.mockReset();
    H.put.mockReset();
    H.invalidate.mockReset();
  });

  it('lists only enabled add-ons from /health', async () => {
    H.get.mockResolvedValue({ data: { addons: { rhaddon: 'enabled', other: 'disabled', third: 'enabled' } } });
    useAccessAddons();
    await expect(runQuery()).resolves.toEqual(['rhaddon', 'third']);
    expect(H.get).toHaveBeenCalledWith('/health');
  });

  it('reads one add-on’s access and says the gateway’s refusal', async () => {
    H.get.mockResolvedValue({ data: BODY });
    useAddonAccess('rhaddon');
    await runQuery();
    expect(H.get).toHaveBeenCalledWith('/api/addons/{addon}/access', { params: { path: { addon: 'rhaddon' } } });
    H.get.mockResolvedValue({ error: { detail: 'add-on "rhaddon" is not registered on this gateway' } });
    await expect(runQuery()).rejects.toThrow('not registered');
  });

  it('puts a change, sends a reason only when given, and refreshes the view', async () => {
    H.put.mockResolvedValue({ data: { from: 'inherit', to: 'off' } });
    useSetAddonAccess();
    await expect(runMutation({ addon: 'rhaddon', feature: 'talk', subject: 'user:bob', value: 'off', reason: '  left  ' })).resolves.toEqual({ from: 'inherit', to: 'off' });
    expect(H.put).toHaveBeenCalledWith('/api/addons/{addon}/access', {
      params: { path: { addon: 'rhaddon' } },
      body: { feature: 'talk', subject: 'user:bob', value: 'off', reason: 'left' },
    });
    await runMutation({ addon: 'rhaddon', feature: 'talk', subject: 'role:user', value: 'on', reason: '  ' });
    expect(H.put.mock.calls[1][1].body).toEqual({ feature: 'talk', subject: 'role:user', value: 'on' });
    (H.lastMutation.current?.onSuccess as (r: unknown, v: unknown) => void)({}, { addon: 'rhaddon' });
    expect(H.invalidate).toHaveBeenCalledWith({ queryKey: ['addon-access', 'view', 'rhaddon'] });
  });

  it('shows the gateway’s refusal of a change as it words it', async () => {
    H.put.mockResolvedValue({ error: { error: 'turning a feature off takes a reason' } });
    useSetAddonAccess();
    await expect(runMutation({ addon: 'rhaddon', feature: 'talk', subject: 'role:user', value: 'off' })).rejects.toThrow('takes a reason');
  });

  it('asks the person route with the trimmed account', async () => {
    H.get.mockResolvedValue({ data: { account: 'bob', addons: [] } });
    usePersonAccess('rhaddon', '  bob ');
    expect(H.lastQuery.current?.enabled).toBe(true);
    await runQuery();
    expect(H.get).toHaveBeenCalledWith('/api/security/users/{username}/addon-access', { params: { path: { username: 'bob' } } });
    usePersonAccess('rhaddon', '   ');
    expect(H.lastQuery.current?.enabled).toBe(false);
  });
});
