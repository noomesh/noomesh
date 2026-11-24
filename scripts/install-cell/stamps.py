#!/usr/bin/env python3
"""Of each line on stdin, only its timestamp and its level: what is kept of a
captured log the upload scan or the credential check refused. Nothing else of
the line survives: the first field is kept only when it IS a timestamp (a
line without one, such as an indented continuation of a multi-line message,
gives `-`), and the level only when it is one of the known level words."""
import re
import sys

TS = re.compile(r"^\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d(\.\d+)?(Z|[+-]\d\d:?\d\d)?$")
LEVELS = {"TRACE", "DEBUG", "INFO", "NOTICE", "WARN", "WARNING", "ERROR", "FATAL", "PANIC", "CRITICAL"}
LEVEL = re.compile(r'"level"\s*:\s*"([A-Za-z]+)"|\blevel=([A-Za-z]+)')

for line in sys.stdin:
    parts = line.split(None, 1)
    if not parts:
        continue
    ts = parts[0] if TS.match(parts[0]) else "-"
    m = LEVEL.search(line)
    lvl = (m.group(1) or m.group(2)) if m else ""
    print(ts, lvl.upper() if lvl.upper() in LEVELS else "-")
