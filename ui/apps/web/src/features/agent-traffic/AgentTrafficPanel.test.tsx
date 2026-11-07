// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 PersonifAI LLC

// @vitest-environment jsdom
import { describe, it, expect, vi, afterEach } from 'vitest';
import { render, screen, fireEvent, cleanup } from '@testing-library/react';
import panelSrc from './AgentTrafficPanel.tsx?raw';
import { readFileSync } from 'node:fs';
import { resolve } from 'node:path';

vi.mock('@metis/core', () => ({ useAuth: () => ({ isOperator: true }), useQuery: () => ({}) }));

import { Message } from './AgentTrafficPanel';
import type { TrafficMessage } from './useAgentTraffic';

const msg = (body: unknown, to = 'thread'): TrafficMessage => ({
  id: 'm1',
  from: 'rbwolf/operator-rbwolf',
  to,
  kind: 'message',
  body,
  ts: '2026-11-05T23:05:25Z',
  enc: 'sealed',
  sigVerified: true,
  fromNode: null,
  fromHarness: null,
});

afterEach(cleanup);

describe('AgentTrafficPanel', () => {
  it('shows a long message as a readable preview, and Show all expands it', () => {
    const text = Array.from({ length: 20 }, (_, i) => `paragraph ${i}`).join('\n');
    render(<Message m={msg({ text })} />);
    const body = document.querySelector('pre.traffic-body') as HTMLElement;
    expect(body.hidden).toBe(false);
    expect(body.textContent).toContain('paragraph 0');
    expect(body.textContent).not.toContain('paragraph 19');
    fireEvent.click(screen.getByRole('button', { name: /show all/i }));
    expect(body.textContent).toContain('paragraph 19');
  });

  it('labels a message to the thread address as going to the thread', () => {
    render(<Message m={msg({ text: 'hi' })} />);
    expect(document.querySelector('.traffic-route')?.textContent).toContain('→ the thread');
    cleanup();
    render(<Message m={msg({ text: 'hi' }, 'rbwolf/codex-lse1ln')} />);
    expect(document.querySelector('.traffic-route')?.textContent).toContain('→ rbwolf/codex-lse1ln');
  });

  it('styles the participant dropdown like the console, in the dark scheme', () => {
    expect(panelSrc).toMatch(/<select\s+className="filter-select"/);
    // Read from disk: vitest hands CSS imports back empty (css is not processed).
    const appCss = readFileSync(resolve(process.cwd(), 'src/app.css'), 'utf8');
    const start = appCss.indexOf(':root {');
    const root = appCss.slice(start, appCss.indexOf('}', start));
    expect(root).toContain('color-scheme: dark');
  });
});
