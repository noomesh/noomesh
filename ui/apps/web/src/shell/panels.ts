// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 PersonifAI LLC

import type { ComponentType } from 'react';
import { CORE_PANELS } from './panels.core';
// Aliased path, not relative: vite.config.ts swaps this module for the empty
// stub in `core` builds, and the alias only matches the '@/shell/...' form.
import { EXTENDED_PANELS } from '@/shell/panels.extended';
import { EDITION, inEdition } from './editions';

/**
 * The panels this build ships.
 *
 * In `core` builds `panels.extended` resolves to the empty stub, so the spread
 * contributes nothing and the extended code never enters the bundle. The
 * `inEdition` filter is belt-and-braces: it keeps the registry honest even if
 * the alias is misconfigured, so a mismatch shows up as a missing tab rather
 * than a tab that 404s against a service the build cannot reach.
 */
export const PANELS: Record<string, ComponentType> = Object.fromEntries(
  Object.entries({ ...CORE_PANELS, ...EXTENDED_PANELS }).filter(([id]) => inEdition(id)),
);

export { EDITION };
