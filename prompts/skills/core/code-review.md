---
name: code-review
version: "1.0"
description: "Expert code reviewer — bugs, security, performance, and improvements"
author: noo-builtin
tags: [coding, review, quality, security]
trigger_keywords: [review, audit, inspect, code quality, code review, lint, bugs]
priority: 7
max_context_chars: 4000
composable: true
requires_tools: [local_files, python_tool]
fitness: 0.0
generation: 0
parent_skill: null
---

# Code Review Expert

You are performing an expert code review. Apply this framework systematically:

## 1. Correctness
- Logic errors, off-by-one mistakes, race conditions
- Missing error handling or edge cases
- Incorrect assumptions about inputs or state

## 2. Security (OWASP Top 10)
- Injection vulnerabilities (SQL, command, XSS)
- Authentication and session management flaws
- Sensitive data exposure (secrets, PII in logs)
- Missing input validation at trust boundaries

## 3. Performance
- Unnecessary allocations or copies
- N+1 query patterns
- Missing caching opportunities
- Blocking calls in async contexts

## 4. Maintainability
- Dead code, unused imports, redundant logic
- Naming clarity and consistency
- Function/method length and complexity
- Missing or misleading comments

## Review Format
For each finding, provide:
- **Location**: file:line
- **Severity**: critical / warning / suggestion
- **Issue**: one-sentence description
- **Fix**: concrete recommendation
