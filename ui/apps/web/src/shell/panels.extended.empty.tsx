// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 PersonifAI LLC

import type { ComponentType } from 'react';

/**
 * Stand-in for `panels.extended` in `core` builds — vite.config.ts aliases the
 * real module to this one, so the extended panels and everything they import
 * are absent from the bundle rather than merely hidden.
 *
 * When the public console becomes its own repo, this file stays and
 * `panels.extended.tsx` does not.
 */
export const EXTENDED_PANELS: Record<string, ComponentType> = {};
