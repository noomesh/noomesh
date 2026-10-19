// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 PersonifAI LLC

import { describe, expect, it } from 'vitest';
import {
  chatDefaultLine,
  errorMessage,
  nodeState,
  parseSpaceForm,
  purposeRows,
  spaceRows,
  unmatchedWarning,
  type EmbeddingSpace,
  type PoolNode,
} from './modelPrefs';

const node = (o: Partial<PoolNode> = {}): PoolNode => ({
  node: 'n1',
  backend: 'llamacpp',
  model: 'm',
  desiredState: 'running',
  advertising: true,
  ...o,
});

describe('purposeRows', () => {
  const classes = [
    { name: 'chat-default', declared: false, dynamic: true },
    { name: 'fast', declared: true, dynamic: false },
  ];
  it('treats chat-default as no preference', () => {
    const [r] = purposeRows([{ alias: 'knowledge', class: 'chat-default', builtin: true, purpose: true }], classes);
    expect(r.target).toBeNull();
    expect(r.text).toBe('no preference — any live chat node');
    expect(r.state).toBe('any live node');
  });
  it('marks a preference served only when a class of that name exists', () => {
    const rows = purposeRows(
      [
        { alias: 'knowledge', class: 'fast', builtin: true, purpose: true },
        { alias: 'graph', class: 'gemma-x', builtin: true, purpose: true },
      ],
      classes,
    );
    expect(rows.map((r) => [r.purpose, r.served, r.state])).toEqual([
      ['knowledge', true, 'served'],
      ['graph', false, 'not served yet'],
    ]);
  });
  it('drops aliases that are not purposes', () => {
    expect(purposeRows([{ alias: 'gpt-4', class: 'fast', builtin: true, purpose: false }], classes)).toEqual([]);
  });
});

describe('chatDefaultLine', () => {
  it('says dynamic unless declared', () => {
    expect(chatDefaultLine([])).toMatch(/dynamic/);
    expect(chatDefaultLine([{ name: 'chat-default', declared: true, dynamic: false }])).toMatch(/declared/);
    expect(chatDefaultLine([{ name: 'chat-default', declared: false, dynamic: true }])).toMatch(/dynamic/);
  });
});

describe('nodeState', () => {
  it('serving needs desired running AND advertising', () => {
    expect(nodeState(node())).toBe('serving');
    expect(nodeState(node({ advertising: false }))).toBe('placed, not advertising');
    expect(nodeState(node({ desiredState: 'stopped', advertising: true }))).toBe('stopped');
  });
});

describe('spaceRows', () => {
  const space = (o: Partial<EmbeddingSpace> = {}): EmbeddingSpace => ({
    space: 'knowledge',
    model: 'harrier',
    dims: 1024,
    isDefault: true,
    pool: [node()],
    live: 1,
    ...o,
  });
  it('has no warning while something serves the space', () => {
    const [r] = spaceRows([space()]);
    expect(r.warning).toBeNull();
    expect(r.deletable).toBe(false);
    expect(r.dimsText).toBe('1024');
  });
  it('warns that every embed fails when the default has live=0', () => {
    const [r] = spaceRows([space({ live: 0, pool: [] })]);
    expect(r.warning).toMatch(/every embed for the default space/);
  });
  it('warns plainly for a non-default space and allows delete', () => {
    const [r] = spaceRows([space({ space: 'code', isDefault: false, live: 0, dims: null })]);
    expect(r.warning).toMatch(/embeds for "code" fail/);
    expect(r.deletable).toBe(true);
    expect(r.dimsText).toBe('dims unknown');
  });
});

describe('unmatchedWarning', () => {
  it('says it serves nobody', () => {
    expect(unmatchedWarning(node({ model: 'stray' }))).toMatch(/stray.*serves nobody/);
  });
});

describe('parseSpaceForm', () => {
  it('requires a name and model', () => {
    expect(parseSpaceForm('', 'm', '')).toHaveProperty('error');
    expect(parseSpaceForm('x', ' ', '')).toHaveProperty('error');
    expect(parseSpaceForm('bad name', 'm', '')).toHaveProperty('error');
  });
  it('omits dims when blank and validates it otherwise', () => {
    expect(parseSpaceForm(' code ', ' m ', '')).toEqual({ space: 'code', body: { model: 'm' } });
    expect(parseSpaceForm('code', 'm', '768')).toEqual({ space: 'code', body: { model: 'm', dims: 768 } });
    expect(parseSpaceForm('code', 'm', '7.5')).toHaveProperty('error');
    expect(parseSpaceForm('code', 'm', '-3')).toHaveProperty('error');
  });
});

describe('errorMessage', () => {
  it('prefers the server message', () => {
    expect(errorMessage({ error: 'would hide a class' }, 'x')).toBe('would hide a class');
    expect(errorMessage({ detail: 'nope' }, 'x')).toBe('nope');
    expect(errorMessage({ error: { message: 'deep' } }, 'x')).toBe('deep');
    expect(errorMessage('plain', 'x')).toBe('plain');
    expect(errorMessage(undefined, 'fallback')).toBe('fallback');
  });
});
