// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 PersonifAI LLC

// @vitest-environment jsdom
import { describe, it, expect, vi, afterEach } from 'vitest';
import { render, screen, cleanup } from '@testing-library/react';

const H = vi.hoisted(() => ({
  status: { data: undefined as unknown },
}));

vi.mock('@metis/core', () => ({
  useAuth: () => ({ ready: true, isLoggedIn: true }),
  useMetisClient: () => ({}),
  useMutation: () => ({ isPending: false, mutateAsync: vi.fn() }),
  useQuery: () => H.status,
}));

import { OpenGrafana } from './ObservabilityPanel';
import { grafanaOffLine, type MonitoringStatus } from './useGrafanaSession';

const OFF: MonitoringStatus = {
  monitoring: 'lean',
  grafana: false,
  log_search: false,
  traces: false,
  message: 'Dashboards, log search and traces are off on this install: noo stack monitoring on',
};

afterEach(cleanup);

describe('Open Grafana when dashboards are off by choice', () => {
  it('shows a muted line naming the command instead of the button', () => {
    H.status = { data: OFF };
    render(<OpenGrafana />);
    expect(screen.queryByRole('button', { name: /open grafana/i })).toBeNull();
    const line = document.querySelector('.open-grafana-off');
    expect(line?.textContent).toBe('Dashboards are off on this install: noo stack monitoring on');
  });

  it('keeps the button when Grafana is on, and when the status is unknown (older gateway, error, loading)', () => {
    const shown: (MonitoringStatus | null | undefined)[] = [{ ...OFF, monitoring: 'full', grafana: true }, null, undefined];
    for (const data of shown) {
      H.status = { data };
      render(<OpenGrafana />);
      expect(screen.getByRole('button', { name: /open grafana/i })).toBeTruthy();
      expect(document.querySelector('.open-grafana-off')).toBeNull();
      cleanup();
    }
  });

  it('hides the button only on an explicit grafana: false', () => {
    expect(grafanaOffLine(undefined)).toBeNull();
    expect(grafanaOffLine(null)).toBeNull();
    expect(grafanaOffLine({ ...OFF, grafana: true })).toBeNull();
    expect(grafanaOffLine({ ...OFF, monitoring: 'lean', grafana: false })).toContain('noo stack monitoring on');
  });
});
