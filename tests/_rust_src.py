# SPDX-License-Identifier: AGPL-3.0-only
# Copyright 2026 PersonifAI LLC

"""What a Python guard that reads Rust source should read (followup 215, i460).

This is the Python copy of `noo-cli/src/test_src.rs` and
`gateway-rust/src/test_src.rs`. Every guard under tests/ that reads Rust
source goes through it instead of defining its own strip. Each of the
hand-rolled ones cut the file at the FIRST `#[cfg(test)]`, which hides
everything after a test-only item, or counted braces with no notion of a
string or a comment. All three copies run every row of
tests/fixtures/test_src_cases.json and must agree
(tests/test_rust_src_readers.py), so a lexer fix lands in all of them.

- `own_code(src)`: comments blanked to spaces (newlines kept, string
  literals kept), and every `#[cfg(test)]` item removed whole, by brace
  matching or up to its `;`. Nothing after a test-only item is lost.
- `own_code_lines(src)`: the same, but a removed item leaves its newlines,
  so a guard that reports line numbers still reports the file's own.
- `fn_body(code, marker)`: from the first `marker` through the matching
  closing brace of the first code `{` after it. Raises AssertionError
  "this guard is stale" when the marker or the body is missing.
- `strip_comments(src)`: comments only.

Positions are byte offsets internally. Delimiters are ASCII, so a UTF-8
continuation byte never looks like one.
"""

from __future__ import annotations

_CODE, _COMMENT, _LIT = 0, 1, 2
_ATTR = b"#[cfg(test)]"


def _is_ident(c: int) -> bool:
    return c < 0x80 and (chr(c).isalnum() or c == ord("_"))


def _classify(b: bytes) -> list[int]:
    n = len(b)
    out = [_CODE] * n
    i = 0

    def mark(f: int, t: int, c: int) -> None:
        for x in range(f, min(t, n)):
            out[x] = c

    def find(sub: bytes, start: int) -> int | None:
        r = b.find(sub, start)
        return None if r < 0 else r

    while i < n:
        c = b[i]
        if c == 0x2F and i + 1 < n and b[i + 1] == 0x2F:  # //
            e = find(b"\n", i)
            end = n if e is None else e
            mark(i, end, _COMMENT)
            i = end
        elif c == 0x2F and i + 1 < n and b[i + 1] == 0x2A:  # /* nested */
            j, depth = i + 2, 1
            while j < n and depth > 0:
                if b[j] == 0x2F and j + 1 < n and b[j + 1] == 0x2A:
                    depth += 1
                    j += 2
                elif b[j] == 0x2A and j + 1 < n and b[j + 1] == 0x2F:
                    depth -= 1
                    j += 2
                else:
                    j += 1
            mark(i, j, _COMMENT)
            i = j
        elif c == 0x22:  # "
            j = i + 1
            while j < n and b[j] != 0x22:
                j += 2 if b[j] == 0x5C else 1
            end = min(j + 1, n)
            mark(i, end, _LIT)
            i = end
        elif c == 0x72 and ((i == 0 or not _is_ident(b[i - 1])) or (i >= 1 and b[i - 1] == 0x62 and (i < 2 or not _is_ident(b[i - 2])))):
            # r"…", r#"…"#, br"…"
            j = i + 1
            while j < n and b[j] == 0x23:
                j += 1
            if j < n and b[j] == 0x22:
                close = b'"' + b"#" * (j - i - 1)
                e = find(close, j + 1)
                end = n if e is None else e + len(close)
                mark(i, end, _LIT)
                i = end
            else:
                i += 1
        elif c == 0x27:  # ' : a char literal, or a lifetime
            if i + 2 < n and b[i + 1] == 0x5C:
                e = find(b"'", i + 3)
                end = n if e is None else e + 1
                mark(i, end, _LIT)
                i = end
            elif i + 1 < n:
                lead = b[i + 1]
                width = 1 if lead < 0x80 else 2 if lead < 0xE0 else 3 if lead < 0xF0 else 4
                after = i + 1 + width
                if after < n and b[after] == 0x27:
                    mark(i, after + 1, _LIT)
                    i = after + 1
                else:
                    i += 1
            else:
                i += 1
        else:
            i += 1
    return out


def _matching_brace(b: bytes, cls: list[int], open_: int) -> int | None:
    depth = 0
    for i in range(open_, len(b)):
        if cls[i] != _CODE:
            continue
        if b[i] == 0x7B:
            depth += 1
        elif b[i] == 0x7D:
            depth -= 1
            if depth == 0:
                return i
    return None


def strip_comments(src: str) -> str:
    """`src` with every comment replaced by spaces (newlines kept)."""
    b = src.encode()
    cls = _classify(b)
    return bytes(0x20 if (k == _COMMENT and x != 0x0A) else x for x, k in zip(b, cls)).decode()


def _own(src: str, keep_lines: bool) -> str:
    code = strip_comments(src).encode()
    cls = _classify(code)
    out = bytearray()
    at = search = 0
    while True:
        start = code.find(_ATTR, search)
        if start < 0:
            break
        if cls[start] != _CODE:
            search = start + len(_ATTR)
            continue
        end = None
        nest = 0
        for i in range(start + len(_ATTR), len(code)):
            if cls[i] != _CODE:
                continue
            x = code[i]
            if x in (0x28, 0x5B):
                nest += 1
            elif x in (0x29, 0x5D):
                nest -= 1
            if x == 0x3B and nest == 0:
                end = i + 1
                break
            if x == 0x7B:
                m = _matching_brace(code, cls, i)
                end = None if m is None else m + 1
                break
        if end is None:
            end = len(code)
        out += code[at:start]
        if keep_lines:
            out += b"\n" * code.count(b"\n", start, end)
        at = search = end
    out += code[at:]
    return out.decode()


def own_code(src: str) -> str:
    """The code a guard should read: comments blanked, `#[cfg(test)]` items removed."""
    return _own(src, keep_lines=False)


def own_code_lines(src: str) -> str:
    """`own_code`, with each removed item's newlines kept (line numbers stay the file's)."""
    return _own(src, keep_lines=True)


def fn_body(code: str, marker: str) -> str:
    """The item `marker` introduces, through its own closing brace."""
    b = code.encode()
    cls = _classify(b)
    start = b.find(marker.encode())
    assert start >= 0, f"this guard is stale: `{marker}` is not in the code"
    open_ = next((i for i in range(start, len(b)) if cls[i] == _CODE and b[i] == 0x7B), None)
    assert open_ is not None, f"this guard is stale: `{marker}` has no body"
    close = _matching_brace(b, cls, open_)
    assert close is not None, f"this guard is stale: `{marker}` never closes"
    return b[start : close + 1].decode()
