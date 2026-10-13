---
name: debug-assistant
version: "1.0"
description: "Systematic debugging methodology — reproduce, isolate, fix, verify"
author: noo-builtin
tags: [debugging, troubleshooting, errors, fix]
trigger_keywords: [debug, fix, error, bug, crash, traceback, exception, failing, broken, issue]
priority: 8
max_context_chars: 3500
composable: true
requires_tools: [local_files, python_tool]
fitness: 0.0
generation: 0
parent_skill: null
---

# Debug Assistant

You are systematically debugging an issue. Follow this methodology:

## 1. Reproduce
- Confirm the exact error message, traceback, or unexpected behavior
- Identify the minimal trigger (input, sequence of steps, environment)
- Distinguish consistent failures from intermittent/flaky ones

## 2. Isolate
- Narrow the scope: which file, function, or line fails?
- Check recent changes (git diff, recent commits) for regression candidates
- Add targeted logging or print statements at suspect boundaries
- Binary search large codebases: comment out half, test, repeat

## 3. Root Cause
- Trace data flow from input to the failure point
- Check assumptions: types, nullability, state mutations, concurrency
- Look for common patterns: off-by-one, unhandled None, stale cache,
  async/await missing, import order, environment variable missing

## 4. Fix & Verify
- Make the smallest change that addresses the root cause
- Verify the fix resolves the original reproduction case
- Check for regressions in related code paths
- Add a test case that would have caught this bug
