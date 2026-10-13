// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 PersonifAI LLC

// @metis/tokens — the Slate palette (Instrument design language).
//
// Single source of truth for color. Web consumes tokens.css (CSS variables);
// mobile (NativeWind / RN) consumes these JS objects. Rules: `primary` = system /
// interaction; `warn` = "needs attention" (never the brand); neutrals are cool,
// biased toward the brand so the grey reads chosen, not default.

export interface SlateTheme {
  bg: string;
  sidebar: string;
  surface: string;
  surface2: string;
  surface3: string;
  ink: string;
  ink2: string;
  dim: string;
  primary: string;
  primaryForeground: string;
  primarySoft: string;
  good: string;
  warn: string;
  bad: string;
}

export const slateDark: SlateTheme = {
  bg: '#0C0E12',
  sidebar: '#090B0E',
  surface: '#14171D',
  surface2: '#1B1F28',
  surface3: '#232937',
  ink: '#E6EAF1',
  ink2: '#AAB4C4',
  dim: '#8993A6',
  primary: '#5F8FD0',
  primaryForeground: '#08111C',
  primarySoft: 'rgba(95,143,208,0.14)',
  good: '#46C08A',
  warn: '#E0A24A',
  bad: '#E5675A',
};

export const slateLight: SlateTheme = {
  bg: '#EAEEF3',
  sidebar: '#E7EBF2',
  surface: '#F8FAFC',
  surface2: '#EEF1F6',
  surface3: '#E4E9F0',
  ink: '#182230',
  ink2: '#46566B',
  dim: '#6B7789',
  primary: '#3F6FB0',
  primaryForeground: '#FFFFFF',
  primarySoft: 'rgba(63,111,176,0.12)',
  good: '#2F8F66',
  warn: '#B5771F',
  bad: '#C04A44',
};

export const slate = { dark: slateDark, light: slateLight } as const;
