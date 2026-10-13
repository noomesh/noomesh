// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 PersonifAI LLC

// Vite dev server + build for the noomesh web console.
//
// Mirrors the legacy vite.config.js proxy so the browser stays same-origin with
// the gateway (or the mock): /api, /auth, /ws, etc. are forwarded to
// PAI_API_TARGET. Resolution order: .env / .env.local (gitignored) → process env
// → the mock on :9800. This keeps a private gateway URL out of git — set it in
// apps/web/.env.local (see .env.example). The two @metis/* workspace packages
// are aliased straight to their TS source so Vite/esbuild transpiles them.

import { defineConfig, loadEnv } from 'vite';
import react from '@vitejs/plugin-react';
import tailwind from '@tailwindcss/vite';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const dir = path.dirname(fileURLToPath(import.meta.url));
const proxyPaths = ['/api', '/auth', '/health', '/metrics', '/v1'];

export default defineConfig(({ mode }) => {
  // '' prefix = load unprefixed vars (PAI_API_TARGET) too, not just VITE_*.
  const env = loadEnv(mode, dir, '');
  const target = env.PAI_API_TARGET || process.env.PAI_API_TARGET || 'http://localhost:9800';
  const wsTarget = target.replace(/^http/, 'ws');

  // Editions (src/shell/editions.ts). In a `core` build the extended panel
  // registry is aliased to an empty stub, so those panels — and everything
  // they import — are absent from the bundle rather than merely hidden. That
  // is what makes the seam real: the OSS artifact cannot contain a Graph panel
  // it has no service for.
  // Driven by `--mode core` rather than an env var, so it works the same on
  // Windows and POSIX and needs no .env file (.env.* is gitignored here).
  const edition = mode === 'core' || env.VITE_EDITION === 'core' ? 'core' : 'full';

  return {
    plugins: [react(), tailwind()],
    // Two entries, one build. kiosk.html → src/kiosk is the unattended display
    // its own bundle,
    // importing nothing from src/features or src/shell — asserted by
    // src/kiosk/isolation.test.ts, not left to convention. The gateway must
    // serve /kiosk from dist/kiosk.html explicitly; it has no SPA fallback.
    build: {
      rollupOptions: {
        input: {
          main: path.resolve(dir, 'index.html'),
          kiosk: path.resolve(dir, 'kiosk.html'),
        },
      },
    },
    // editions.ts reads import.meta.env.VITE_EDITION; inject it so the mode
    // flag alone is enough.
    define: {
      'import.meta.env.VITE_EDITION': JSON.stringify(edition),
      // The stack tag this console was built from, as a plain string that
      // survives minification — see src/kiosk/build.ts. `dev` locally: a
      // build must never claim a tag it was not cut from.
      __NOO_CONSOLE_BUILD__: JSON.stringify(
        env.NOO_CONSOLE_BUILD || process.env.NOO_CONSOLE_BUILD || 'dev',
      ),
    },
    resolve: {
      alias: {
        ...(edition === 'core'
          ? {
              '@/shell/panels.extended': path.resolve(dir, 'src/shell/panels.extended.empty.tsx'),
              '@/shell/nav.extended': path.resolve(dir, 'src/shell/nav.extended.empty.tsx'),
            }
          : {}),
        '@': path.resolve(dir, 'src'),
        '@metis/tokens/tokens.css': path.resolve(dir, '../../packages/tokens/src/tokens.css'),
        '@metis/tokens': path.resolve(dir, '../../packages/tokens/src/slate.ts'),
        '@metis/api': path.resolve(dir, '../../packages/api/src/index.ts'),
        '@metis/core': path.resolve(dir, '../../packages/core/src/index.ts'),
      },
    },
    server: {
      port: 5174,
      proxy: {
        ...Object.fromEntries(proxyPaths.map((p) => [p, { target, changeOrigin: true, secure: false }])),
        '/ws': { target: wsTarget, ws: true, changeOrigin: true, secure: false },
      },
    },
  };
});
