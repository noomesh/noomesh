// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 PersonifAI LLC

import { describe, it, expect } from 'vitest';
import { laneLines, readLanes } from './lanes';

const lane = (backend: string, model: string, state: string, reason = '', role = 'chat') => ({
  backend,
  model,
  role,
  state,
  reason,
});

describe('readLanes', () => {
  it('no key is an older agent; a list is read, an empty list kept', () => {
    expect(readLanes({ id: 'a' })).toBeUndefined();
    expect(readLanes({ lanes: 'garbage' })).toBeUndefined();
    expect(readLanes({ lanes: [] })).toEqual([]);
    expect(readLanes(null)).toBeUndefined();
  });

  it('drops a lane with no backend or model and names a path by its file', () => {
    const got = readLanes({
      lanes: [lane('vllm', '', 'serving'), { model: 'x' }, 7, lane('llamacpp', '/models/small.gguf', 'missing', 'not on disk')],
    });
    expect(got).toEqual([lane('llamacpp', 'small.gguf', 'missing', 'not on disk')]);
  });
});

describe('laneLines', () => {
  it('names each chat lane the gateway does not route, with the agent reason', () => {
    const lines = laneLines(
      readLanes({
        lanes: [
          lane('ollama', 'gemma4:12b', 'serving'),
          lane('ollama', 'qwen3:4b', 'on_demand', 'not loaded'),
          lane('vllm', 'org/new-model', 'loading', 'reconciling: runtime runs org/old-model'),
          lane('llamacpp', 'small.gguf', 'missing', 'not on disk', ''),
          lane('vllm', 'org/other', 'down', 'not running'),
          lane('vllm', 'org/next', 'frobbing'),
          lane('native', 'mistral', 'unplaced'),
          lane('ollama', 'q', 'unknown', 'no presence yet'),
          lane('ollama', 'harrier', 'missing', 'not on disk', 'embed'),
        ],
      }),
    );
    expect(lines).toEqual([
      'vllm org/new-model: loading (reconciling: runtime runs org/old-model)',
      'llamacpp small.gguf: missing (not on disk)',
      'vllm org/other: down (not running)',
      'vllm org/next: frobbing',
    ]);
  });

  it('says nothing for an older agent, no lanes, or every lane routed', () => {
    expect(laneLines(undefined)).toEqual([]);
    expect(laneLines([])).toEqual([]);
    expect(laneLines(readLanes({ lanes: [lane('ollama', 'gemma4:12b', 'serving')] }))).toEqual([]);
  });
});
