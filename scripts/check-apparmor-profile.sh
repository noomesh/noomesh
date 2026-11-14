#!/usr/bin/env bash
# SPDX-License-Identifier: AGPL-3.0-only
# Copyright 2026 PersonifAI LLC
# Parse-check docker/apparmor-noo-sandbox inside throwaway containers, so a
# host without AppArmor (WSL2) can still prove the profile loads where it is
# meant to:
#   * the bundled file with the AppArmor 4.x parser Ubuntu 24.04 ships;
#   * the file as onboard renders it for an AppArmor 3.x parser (Ubuntu
#     22.04: the one `userns,` line becomes a comment, see
#     noo-cli/src/onboard/sandbox_apparmor.rs `render`) with 22.04's parser.
# Needs docker and network for the apt install; nothing is loaded into any
# kernel (-Q).
#
#   bash scripts/check-apparmor-profile.sh            # exit 0 = both parse
#   NOO_APPARMOR_CHECK_ONLY=24.04 bash scripts/check-apparmor-profile.sh
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
PROFILE="$ROOT/docker/apparmor-noo-sandbox"
[ -f "$PROFILE" ] || { echo "missing: $PROFILE" >&2; exit 2; }
ONLY="${NOO_APPARMOR_CHECK_ONLY:-}"

parse() { # IMAGE FILE WANT_MAJOR
    docker run --rm -v "$2:/p/noo-sandbox:ro" -e WANT="$3" "$1" sh -c '
      apt-get update -qq >/dev/null 2>&1
      DEBIAN_FRONTEND=noninteractive apt-get install -y -qq apparmor >/dev/null 2>&1
      v="$(apparmor_parser --version | head -1)"
      case "$v" in *" $WANT."*) ;; *) echo "expected an AppArmor $WANT.x parser, got: $v" >&2; exit 3 ;; esac
      apparmor_parser -Q -K --skip-cache /p/noo-sandbox && echo "ok: noo-sandbox parses with $v"
    '
}

if [ -z "$ONLY" ] || [ "$ONLY" = 24.04 ]; then
    parse "${NOO_APPARMOR_CHECK_IMAGE:-ubuntu:24.04}" "$PROFILE" 4
fi
if [ -z "$ONLY" ] || [ "$ONLY" = 22.04 ]; then
    tmp="$(mktemp)"; trap 'rm -f "$tmp"' EXIT
    # The same transform as render(): the line that is exactly `userns,`
    # (indented) becomes a comment; every other line is kept.
    sed -E 's/^([[:space:]]*)userns,[[:space:]]*$/\1# userns, omitted: this host'"'"'s AppArmor parser predates the rule (4.0); its policy does not mediate user namespaces/' "$PROFILE" > "$tmp"
    chmod 0644 "$tmp"
    parse ubuntu:22.04 "$tmp" 3
fi
