# shellcheck shell=bash
# SPDX-License-Identifier: AGPL-3.0-only
# Copyright 2026 PersonifAI LLC

# The install cells' dispatch-input rules, sourced by run.sh and upgrade.sh
# BEFORE either script uses the value. CLI_TAG and PREV_TAG come from
# install-matrix.yml's free-text dispatch inputs (`cli_tag`, `prev_tag`), and
# run.sh splices CLI_TAG into the README install line it runs with `sh -c`:
# an unchecked `$(...)`, backtick or `;` there runs on the runner.
#
#   cli_tag   exactly `latest` or noo-cli-vX.Y.Z with an optional -rc.N
#   prev_tag  empty, or exactly noo-cli-vX.Y.Z (a final)
#
# Whole-string matches (bash's `=~` anchors `$` at the end of the string, so a
# trailing newline is refused), ASCII digits only (LC_ALL=C: no locale range
# lets a non-ASCII digit through). The same rules are held, by running every
# copy on one corpus, in install-matrix.yml's `Validate dispatch inputs` steps
# and in upgrade_judge.py (tests/test_dispatch_inputs_never_reach_a_shell_raw.py).

CLI_TAG_RE='^(latest|noo-cli-v[0-9]+\.[0-9]+\.[0-9]+(-rc\.[0-9]+)?)$'
PREV_TAG_RE='^(noo-cli-v[0-9]+\.[0-9]+\.[0-9]+)?$'

# require_tag NAME VALUE REGEX RULE: refuse (exit status 1, the rule named on
# stderr) unless VALUE matches REGEX whole. The value is printed %q-quoted, so
# a newline in it cannot start a workflow command.
require_tag() {
    local LC_ALL=C
    if [[ $2 =~ $3 ]]; then
        return 0
    fi
    printf '::error::%s %q refused: must be %s\n' "$1" "$2" "$4" >&2
    return 1
}

require_cli_tag() {
    require_tag CLI_TAG "$1" "$CLI_TAG_RE" "exactly latest or noo-cli-vX.Y.Z with an optional -rc.N"
}

require_prev_tag() {
    require_tag PREV_TAG "$1" "$PREV_TAG_RE" "empty or exactly noo-cli-vX.Y.Z (a final)"
}
