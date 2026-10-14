# noo CLI output style guide

This document dictates what `noo` output looks like. It is the source of
truth: the `ui` module implements it, a test enforces it, and any change
to the look of the CLI starts by editing this file.

Scope: the Rust `noo` binary only.

The guide sits on top of the **Agent contract** (`--json`,
exit codes). Nothing here relaxes that contract.

Revision 2.1 (2026-09-03, same day) added §5 "Rhythm": phases, blank
lines before closing lines, indented sub-steps, one-line waiting, framed
subprocess output — and brought the bash launchers under the same rules.

Revision 2 (2026-09-03) replaced the first draft after a day of use. The
changes: terminal first (everything a human sees is on stdout, scripts
opt into less with `--quiet`/`--json`), visible case, brand colours with
truecolour, symbol fallbacks, boxed header and ruled sections, full
guidance instead of one hint, and the `noomesh` wordmark.

---

## 1. Principles

1. **Terminal first.** The default output is for a person at a terminal
   and a shell redirect captures all of it. Scripts and agents opt into
   less: `--json` for one machine-readable value, `--quiet` for only the
   captured value. Nothing a human would want is dropped to reach a
   script's needs.
2. **Style only when a human is looking.** Colour, glyphs and the wordmark
   appear only on an interactive terminal (§3). Piped, logged, `--json`
   and `--quiet` output is plain text.
3. **Colour is never the only signal.** Every coloured state also carries
   a glyph or a word.
4. **Branded, on the terminal's terms.** The palette is the Noomesh Slate
   palette from the console's design tokens, emitted as truecolour where the terminal
   supports it and mapped onto the 16 basic colours elsewhere (§4).
5. **Visible structure.** A boxed title, ruled sections, underlined table
   headers, glyph-led rows. Structure is drawn with light box characters
   and rules, never around content: a table or a runbook is never boxed,
   so it copy-pastes into chat and tickets as text.
6. **Full guidance.** When the CLI knows what to do next, it says all of
   it: every relevant command, in order, with a line of why. It never
   trims to one hint or refers the reader to a document it could quote.
7. **Consistent vocabulary.** The same state prints the same way in every
   command (§4).
8. **No emoji.** Glyphs come from the fixed set in §4.

---

## 2. Streams and modes

| Mode | stdout | stderr |
|---|---|---|
| default (human) | everything: wordmark, header, sections, results, steps, confirmations, guidance, hints | errors only (`✗ …` plus guidance) |
| `--quiet` | the captured value only (an id, a secret, a path, a result body). Nothing else | errors only |
| `--json` | exactly one JSON value | one JSON error object on failure, else nothing |

Rules:

- **Errors are always stderr**, in every mode, so `2>/dev/null` and exit
  codes keep working. An error is a `✗` line followed by its guidance.
- **Progress rewriting** (spinners, in-place percent lines) is stderr and
  only on a TTY; it never appears in a redirect or a log.
- **The captured value** is whatever a script would want from the
  command: job id, task id, minted secret, written path, the model's
  answer. In default mode it is printed on its own line so it is still
  easy to grab; in `--quiet` it is the only line. Secrets, tokens, keys and
  PEM are never styled in any mode.
- `--quiet` and `--json` are mutually exclusive; `--json` wins.

---

## 3. When styling is on

Resolved once per process. First match wins.

| Signal | Result |
|---|---|
| `--json` or `--quiet` | plain |
| `--color=never` | plain |
| `--color=always` | styled |
| `NO_COLOR` set | plain |
| `CLICOLOR_FORCE` set and not `0` | styled |
| `TERM=dumb` | plain |
| stdout is not a TTY | plain |
| otherwise | styled |

Within styled mode, **colour depth** is chosen separately:
`COLORTERM=truecolor` or `24bit` → brand truecolour; anything else → the
16-colour mapping. `--color=always` alone does not imply truecolour.

Plain mode switches glyphs to their ASCII fallbacks (§4) and box drawing
to ASCII (§5), so logs and non-UTF-8 consoles stay readable and aligned.

The **wordmark** (§5) appears only in styled mode on an interactive
entry point: bare `noo`, `noo --help`, and the start of `noo chat`. It
never appears for a subcommand, in plain mode, or in `--quiet`/`--json`.

---

## 4. Vocabulary

### Glyphs

| Meaning | Styled | Plain | Colour |
|---|---|---|---|
| success / healthy | `✓` | `+` | good |
| failure / error | `✗` | `x` | bad |
| warning / degraded | `!` | `!` | warn |
| in progress / step | `→` | `>` | brand |
| neutral bullet | `•` | `-` | default |
| section marker | `◆` | `#` | brand |
| hint / next command | `▸` | `>` | brand |

Plain fallbacks are single characters so column alignment is identical in
both modes.

### Colours

Semantic tokens map onto the Slate palette (the console's tokens package,
dark-theme values, which read correctly on both dark and
light terminals in practice):

| Token | Truecolour | 16-colour | Use for |
|---|---|---|---|
| `brand` | `#5f8fd0` | blue | header title, section markers, step and hint glyphs, command names, the wordmark |
| `good` | `#46c08a` | green | healthy state, success glyph, `Running`, `Verified` |
| `warn` | `#e0a24a` | yellow | degraded state, warning glyph, `Stale`, `Pending`, dry-run |
| `bad` | `#e5675a` | red | failed state, error glyph, `Down`, `Unreachable` |
| `emph` | bold | bold | the one value the eye should land on, key-value labels |
| `muted` | `#8993a6` | dim | secondary detail, ids, timestamps, explanations, rules and box lines |

`cmd` (command names in prose and hints) is `brand`. Magenta is unused
and reserved. No background colours, no blink, no underline.

Colour goes on the glyph, the state word and the command name, not on
whole lines.

### State words

Title case. Use these and no synonyms. `ui::state()` colours them; the table
below is the same list, and `scripts/check-state-words.py` fails if the two
drift.

| Word | Tone | Means |
|---|---|---|
| `Running` | good | service up and healthy |
| `Healthy` | good | passed its own check |
| `Ok` | good | the generic affirmative |
| `Done` | good | operation succeeded |
| `Verified` | good | confirmed by positive evidence, not inferred |
| `Connected` | good | a link is established |
| `Online` | good | present in the live view |
| `Up to date` | good | nothing to do |
| `No change` | good | nothing to do |
| `Fired` | good | a scheduled action ran |
| `Ready` | good | can accept work |
| `Active` | good | a unit is running |
| `Enabled` | good | switched on |
| `Applied` | good | a change landed |
| `In-sync` / `In sync` | good | two sides agree |
| `Degraded` | warn | up, but not fully |
| `Stale` | warn | known, last seen long ago |
| `Pending` | warn | known, never seen |
| `Skipped` | warn | deliberately not done |
| `Dry-run` | warn | shown, not performed |
| `Warning` | warn | the generic caution |
| `Not reported` | warn | the source said nothing |
| `Queued` | warn | accepted, not yet run |
| `Paused` | warn | stopped on purpose, resumable |
| `Expiring soon` | warn | valid now, not for long |
| `Unknown` | warn | we could not tell |
| `Would <verb>` | warn | dry-run outcome |
| `Stopped` | bad | not running |
| `Unreachable` | bad | cannot be reached |
| `Down` | bad | not serving |
| `Failed` | bad | it did not happen |
| `Error` | bad | the generic negative |
| `Offline` | bad | absent from the live view |
| `Damaged` | bad | present but broken |
| `Expired` | bad | past its validity |
| `Cancelled` | bad | stopped before completing |
| `Dead` | bad | gave up permanently |
| `Exited` | bad | a process ended |
| `Disabled` | bad | switched off |
| `Revoked` | bad | withdrawn |

### Outcomes: four words, used the same way everywhere

Anything that delivers, applies, or acts reports one of exactly four. The
distinction that matters most is the second one, and it is the one most
often collapsed into the third.

| Outcome | Means | Exit / status |
|---|---|---|
| **Verified** / **Applied** | positively confirmed: the far side said so, or we read it back | success |
| **Degraded** | the fast path did not work; the slow one still applies, so the thing WILL happen | success, with the reason |
| **Failed** | it did not happen, and nothing else will make it happen | failure |
| **Unknown** | we could not tell — the check itself did not run | never rendered as either of the above |

**Degraded is not Failed.** `cluster nodes … fetch-now` returns 200 with
`status: "not_poked"` when a node refuses the poke, because the node's 60s
timer collects the same bundle regardless. Reporting "failed" for something
that lands forty seconds later is the false negative that teaches an
operator to ignore the real one.

**Staged is not delivered.** A command that hands work to an asynchronous
rail says `Queued`, never `Done`. `noo cluster sync-model-files` closes with
"N job(s) queued", because the pulls happen on the nodes afterwards and this
process cannot see them finish.

### Absence is never a negative

A missing value means *we do not know*, and it must never be rendered as the
negative state. This rule has caught real bugs:

- an empty audit list read as "the autonomy loop has never acted", when the
  table it read did not exist;
- `running.unwrap_or(false)` printed `Stopped` for a node that had simply
  not reported;
- a node-agent too old to send `peer_identity_enforced` is reported
  **unknown**, not safe.

In practice: no `unwrap_or(false)`, no `unwrap_or_default()` on a field
whose absence is meaningful, and a store that cannot be read says so instead
of returning an empty list.

### Case

- **Header title**: Title Case (`Cluster`, `Docker Host Plane`).
- **Section label**: Title Case (`◆ Nodes`, `◆ Recovery, In Order`).
- **Table columns**: UPPERCASE (`NODE  STATUS  BUS  LOAD`).
- **Key-value labels**: Title Case (`Gateway`, `Stack Tag`). A key that is
  data rather than a label (a class alias, a node id) prints as declared:
  `ui::kv_verbatim`.
- **State words**: Title Case (table above).
- **Confirmations and steps**: sentence case, no trailing period
  (`✓ Join key minted`, `→ Pulling image`).
- **Muted explanations**: sentence case, may be full sentences.

The `ui` module applies header, section, column, label, state and
message case itself, so callers pass natural text and the guide stays
enforceable in one place.

---

## 5. Layout

### Wordmark

Interactive entry points only (§3). Block letters in brand colour,
followed by a muted tagline with the version, then a blank line.

```
 ███╗   ██╗ ██████╗  ██████╗ ███╗   ███╗███████╗███████╗██╗  ██╗
 ████╗  ██║██╔═══██╗██╔═══██╗████╗ ████║██╔════╝██╔════╝██║  ██║
 ██╔██╗ ██║██║   ██║██║   ██║██╔████╔██║█████╗  ███████╗███████║
 ██║╚██╗██║██║   ██║██║   ██║██║╚██╔╝██║██╔══╝  ╚════██║██╔══██║
 ██║ ╚████║╚██████╔╝╚██████╔╝██║ ╚═╝ ██║███████╗███████║██║  ██║
 ╚═╝  ╚═══╝ ╚═════╝  ╚═════╝ ╚═╝     ╚═╝╚══════╝╚══════╝╚═╝  ╚═╝
 local-first AI agent mesh · noo 0.3.80
```

### Header

The first block of a query command. A light box the width of the
terminal (capped at 100 columns), title in `brand` bold on the left, the
most important scalar in `muted` on the right. Plain mode draws the box
with `+`, `-` and `|`.

```
┌──────────────────────────────────────────────────────────────┐
│ Cluster                          controller node-a · 4 nodes │
└──────────────────────────────────────────────────────────────┘
```

Mutating commands do not print a header. Their first line is the first
`→` step.

### Section

A `◆` marker and the label in bold, then a muted rule to the same width as
the header, then the rows. One blank line before each section. Sections
do not nest; a sub-grouping is a muted label indented two spaces.

```

◆ Nodes
──────────────────────────────────────────────────────────────
  ✓ node-a    controller   Running     llamacpp gemma-4-26b
  ✓ node-b     worker       Running     vllm gemma-4-12b
  ! node-c    worker       Stale       last seen 3h ago
```

Empty sections are omitted. If the whole result is empty, one muted line:
`No nodes` / `No jobs`.

### Key-value rows

Label in bold Title Case, padded to the longest label, two spaces, value.

```
  Gateway     https://node-a:8080
  Stack Tag   v0.1.83
  Paired CLI  0.3.80
```

### Tables

Two-space indent. Column names UPPERCASE in `muted`, underlined by a muted
rule spanning the table's width. Two-space gutters. Text left-aligned,
numbers right-aligned. A glyph column, when present, is first and has no
name. The last column truncates to the terminal width with `…`; rows
never wrap. Missing values print as `—` (plain `-`).

```
     ID        STATE     NODE     AGE     MODEL
  ───────────────────────────────────────────────────
  ✓  a1b2c3    Running   node-b    12m     gemma-4-12b
  •  d4e5f6    Queued    —        3s      gemma-4-12b
```

### Steps (mutating commands)

Each step is a `→` line when it starts. The final line of a mutation is a
`✓` summary or a `✗` failure. The captured value, if any, follows on its
own line.

```
→ Staging bundle for node-b
✓ Staged bundle for node-b (applies on next fetch tick)
→ Restarting node-agent on node-b
✗ Restart failed: ssh: connection refused
```

### Rhythm

Spacing is part of the vocabulary. Tight is fine inside a unit of work;
between units the reader needs air.

- **Phases get a section.** A mutation with more than one phase prints
  `◆ Phase` (via `ui::phase`, a section) before each: `upgrade --all`
  reads as CLI · Stack · Gateway · CLI Assets · Nodes.
- **One blank line before every closing line.** A `✓` that closes a
  phase, any `✗`, and the guidance block are preceded by a blank line.
  Steps inside a phase stay tight. `ui::close_done`/`ui::close_failed`
  do this; `ui::guide` already prints its rule.
- **Sub-steps indent.** Work under a parent step is indented two spaces
  (`ui::sub`), and per-item work (a node, a key, a service) sits under a
  muted item label (`ui::item`), so the item and its steps read as one
  unit.
- **Details hang under their line.** At most three muted notes under a
  `✓`; more becomes a key-value block.
- **Waiting is one line.** A poll shows one live line on a TTY with the
  elapsed time (`ui::Poll`), and off a TTY prints one line per minute,
  never every few seconds.
- **Subprocess output is ours to frame.** A child's stdout is captured
  and summarised (`✓ 12 images pulled in 29s`), or shown under a muted
  `output` label indented two spaces. Never interleaved bare. Docker
  compose's own progress renderer is the one exception: it is
  interactive, self-erasing and familiar, so it is left as is.
- **Launchers follow the guide.** The bash launchers under `scripts/`
  (`noomesh-start/stop/restart/rebuild/clean`) source `scripts/lib-ui.sh`,
  which mirrors the glyphs, colours and mode rules (`NO_COLOR`, TTY). No
  emoji, no `compose ps` dump (that is `noo stack status`), tips as a
  guidance block.
- **A launcher's closing line is earned.** `✓ Services restarted` prints
  only after every compose call exited 0; a failure closes with `✗` and
  exits non-zero. A name an operator can read off `noo stack status` is a
  valid argument (`evolve` for `noo-evolve`), and an unknown name is a
  refusal that lists the valid ones.

### Guidance

After a result, failure or warning, everything the reader should know
next, in order. Each command is a `▸` line with the command in `brand`;
explanations are muted lines indented beneath. There is no limit on the
number of `▸` lines. A muted rule separates guidance from the result when
both are present.

```
──────────────────────────────────────────────────────────────
▸ noo cluster reconnect node-b
    re-establishes the node-agent session; safe to repeat
▸ noo cluster logs node-b
    if reconnect fails, the agent log names the cause
```

### Runbooks

Long-form recovery guidance (for example `doctor`) prints in full on
stdout: a section per phase, `•` bullets for steps, commands on their own
indented lines in `brand`, traps and explanations as muted lines above
the command they concern. Nothing is elided or deferred to a document; a
document may be cited *in addition*, as the last muted line.

### Errors

Stderr, all modes. `✗ What failed` in the operator's terms, then the
guidance block. Exit code per the Agent contract.

---

## 6. Wording

- Sentence case for messages, no trailing period on single lines.
- Present tense for what is happening (`→ Pulling image`), past tense for
  what happened (`✓ Pulled image`).
- Object then state: `Gateway unreachable`.
- The `✗` line says what failed; the `▸` lines say what to do.
- Counts live in the header or a key-value row, not in prose.
- Never print internal names the operator cannot act on (work-package
  ids, followup numbers, struct names).

### Provenance

A resolved value that has more than one possible source says which source
answered. `Gateway  https://localhost:8080` is a correct answer on the
controller and a symptom on a laptop, and the URL alone cannot tell those
apart, so the row reads:

```
  Gateway  https://localhost:8080  the default: this box is the controller, so the gateway is local
  Gateway  https://ctl.example:8080  from /etc/noo/controller-url, written at enrollment
```

The provenance is muted and names something the operator can go read or
unset — an environment variable, a file path, a flag. Applies to any value
the CLI resolves through a precedence chain: gateway URL, credential, CA,
config file.

### Difference is not discrepancy

Do not render two values that merely differ as a conflict unless something
proves they conflict. `auth status` warned `issued by <tailnet name>, not
the current target` because it compared URL strings — but the controller
answers to `localhost` from its own box and to its tailnet name from
everywhere else, so the warning fired on the machine the operator was
standing on. Where a probe can settle it, let the probe settle it: a
gateway that accepts the credential and names its subject is the issuer,
whatever it is called here. Warn only when the evidence is absent.

---

## 7. `--json` and `--quiet`

- `--json`: stdout carries exactly one JSON value, no styling; stderr
  carries nothing on success and one `{"error","code","hint"}` object on
  failure.
- `--quiet`: stdout carries only the captured value(s), one per line, no
  styling; stderr carries errors only. Commands with no captured value
  print nothing. Exit codes unchanged.

---

## 8. The `ui` module

`noo-cli/src/ui.rs` is the only place in the crate that emits an escape
sequence or a box-drawing character. Every layout function returns a
`String`; the printers write to stdout (narration) or stderr (errors).

```rust
// mode
ui::styled() -> bool                 ui::truecolor() -> bool
ui::quiet() -> bool                  ui::set_mode(Mode)  ui::set_quiet(bool)

// tokens (§4)
ui::brand  ui::good  ui::warn  ui::bad  ui::emph  ui::muted  ui::cmd
ui::glyph(Glyph::{Ok,Err,Warn,Step,Bullet,Section,Hint}) -> String
ui::glyph_cell(Glyph)                ui::dash() -> &str
ui::state(&str) -> String            // Title-cased and coloured

// layout (§5)
ui::wordmark() -> String
ui::header(title, right: Option<&str>) -> String     // boxed
ui::section(label) -> String                          // ◆ Label + rule
ui::rule() -> String
ui::kv(&[(&str, String)]) -> String
ui::kv_verbatim(&[(&str, String)]) -> String   // keys that are data, printed as given
ui::table(&[Col], &[Vec<String>]) -> String
ui::status_line(Glyph, msg) -> String
ui::hint(cmd) -> String              ui::note(text) -> String   // ▸ / muted explanation

// rhythm (§5)
ui::phase(label) -> String           // ◆ Phase + rule, for multi-phase mutations
ui::item(label) -> String            // muted per-item label ("  node-1")
ui::sub(line) -> String              // indent a rendered line two spaces
ui::close_done(msg)  ui::close_warned(msg)  ui::close_failed(msg, hint)   // blank line first
ui::Poll::start(msg) -> Poll         // one live line with elapsed; .tick() / .done() / .failed()
ui::capture(label, text)             // frame a child's output under a muted label

// printers — stdout narration, suppressed by --quiet
ui::step(msg)  ui::done(msg)  ui::warned(msg)
ui::guide(&[(&str /*cmd*/, &str /*why*/)])
ui::value(text)                      // the captured value: printed in every mode

// printers — stderr, never suppressed
ui::failed(msg, hint: Option<&str>)
```

`output::fail` calls `ui::failed`; the exit-code contract does not move.

---

## 9. Enforcement

- Unit tests in `ui.rs` snapshot each layout function in plain mode and
  check the styled escape shapes for both colour depths.
- A test greps the crate for `\x1b[`, box-drawing characters and the
  retired markers outside `ui.rs` and fails on any hit. There is no
  allow-list.
- Review checks for any PR touching output: `noo <cmd> --json | jq .`
  parses; `noo <cmd> --quiet` prints only the value; `noo <cmd> | cat`
  contains no escape codes and the same text as the terminal minus
  styling.

---

## 10. Worked example

`noo stack status`, styled:

```
┌──────────────────────────────────────────────────────────────┐
│ Stack                           v0.1.83 · node-a · up 3d 4h  │
└──────────────────────────────────────────────────────────────┘

◆ Services
──────────────────────────────────────────────────────────────
     SERVICE       STATE      VERSION    PORTS
  ──────────────────────────────────────────────
  ✓  gateway       Running    0.1.83     :8080
  ✓  trellion      Running    0.1.83
  ✓  postgres      Running    16.4
  !  node-agent    Degraded   0.3.74     paired CLI is 0.3.80

──────────────────────────────────────────────────────────────
▸ noo cluster upgrade-agents
    brings node-agent to the CLI's paired version on every node
```

Piped (`| cat`), the same text with `+ - |` boxes, `+`/`!` glyphs and no
colour. `--quiet`: nothing (status has no captured value). `--json`: one
object.
