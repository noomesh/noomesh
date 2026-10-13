// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 PersonifAI LLC

import type { ReactNode } from 'react';
import type { NavSection } from './nav';

/**
 * Stand-in for `nav.extended` in `core` builds. Keeps extended tab labels and
 * icons out of the bundle entirely, not merely unrendered.
 *
 * When the public console becomes its own repo, this file stays and
 * `nav.extended.tsx` does not.
 */
export const EXTENDED_NAV: NavSection[] = [];
export const EXTENDED_ICONS: Record<string, ReactNode> = {};
