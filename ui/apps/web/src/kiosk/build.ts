// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 PersonifAI LLC

/**
 * Which build of the console this is.
 *
 * A wall display should be able to answer "what are you running?" without
 * anyone trusting a tag name. It could not: when a release session tried
 * to confirm from the wire that the served bundle carried two kiosk fixes,
 * every candidate marker had been renamed by the minifier — a module-local
 * const and an exported function both vanish into single letters. The tag
 * was right and the check was impossible, which is a bad place to be,
 * because the next time the tag is wrong it will look exactly the same.
 *
 * A string literal survives minification. So the console carries the build
 * it came from, and anyone can read it off the public bundle:
 *
 *     curl -s https://<controller>/assets/kiosk-*.js | grep -o 'ui-[0-9a-f]*'
 *
 * Since 2026-11-11 that is a CONTENT identity, `ui-<git tree hash of ui/>`
 * (publish-web.yml), not the release tag: an rc and its final carry the same
 * one, so a final re-tags the rc's gateway instead of rebuilding it, and a
 * display still running an old console still reports its old id.
 *
 * `dev` when built outside the release workflow — it must never claim a
 * tag it was not cut from, because a false build stamp is worse than none.
 */
declare const __NOO_CONSOLE_BUILD__: string;

export const CONSOLE_BUILD: string =
  typeof __NOO_CONSOLE_BUILD__ === 'string' ? __NOO_CONSOLE_BUILD__ : 'dev';
