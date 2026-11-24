#!/usr/bin/env python3
"""Of each line on stdin, only its
timestamp (the first field) and its level (a JSON `"level":"X"` or a
`level=X` field, when the line carries one). Used when the upload scan
refused a node-side log: the times and levels say when things happened
without carrying any of the line's text."""
import re
import sys

LEVEL = re.compile(r'"level"\s*:\s*"([A-Za-z]+)"|\blevel=([A-Za-z]+)')
for line in sys.stdin:
    parts = line.split(None, 1)
    if not parts:
        continue
    m = LEVEL.search(line)
    lvl = (m.group(1) or m.group(2)) if m else "-"
    print(parts[0], lvl)
