// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 PersonifAI LLC

import { defineConfig } from 'vitest/config';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

// Standalone test config (not the app's vite.config) so unit tests don't pull in
// the Tailwind/CSS pipeline. Mirrors the aliases the app code uses.
const dir = path.dirname(fileURLToPath(import.meta.url));

export default defineConfig({
  resolve: {
    alias: {
      '@': path.resolve(dir, 'src'),
      '@metis/api': path.resolve(dir, '../../packages/api/src/index.ts'),
      '@metis/core': path.resolve(dir, '../../packages/core/src/index.ts'),
    },
  },
  test: {
    environment: 'jsdom',
    include: ['src/**/*.test.{ts,tsx}'],
  },
});
