// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 PersonifAI LLC

import { useEffect, useState } from 'react';

/**
 * Subscribe to a CSS media query.
 *
 * Web-only by design, and therefore in `apps/web`, not `@metis/core` — that
 * package is consumed under React Native, where `matchMedia` doesn't exist.
 */
export function useMediaQuery(query: string): boolean {
  const [matches, setMatches] = useState(() =>
    typeof window === 'undefined' ? false : window.matchMedia(query).matches,
  );

  useEffect(() => {
    if (typeof window === 'undefined') return;
    const mql = window.matchMedia(query);
    // Re-read on subscribe: the query may have changed between render and effect.
    setMatches(mql.matches);
    const onChange = (e: MediaQueryListEvent) => setMatches(e.matches);
    mql.addEventListener('change', onChange);
    return () => mql.removeEventListener('change', onChange);
  }, [query]);

  return matches;
}

/**
 * The one breakpoint the shell changes shape at: below it the console is a
 * chat with a drawer and sheets, above it a three-column desktop layout.
 * Kept in sync with `--bp-mobile` usage in app.css.
 */
export const MOBILE_QUERY = '(max-width: 860px)';

export const useIsMobile = () => useMediaQuery(MOBILE_QUERY);
