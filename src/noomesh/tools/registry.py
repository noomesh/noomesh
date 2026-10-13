# SPDX-License-Identifier: AGPL-3.0-only
# Copyright 2026 PersonifAI LLC

from __future__ import annotations

import math
import re
from collections import Counter
from typing import Dict, Iterable, List, Tuple

from .base import ToolSpec

_TOKEN_RE = re.compile(r"[a-zA-Z0-9_]+")


def _tokenize(text: str) -> set[str]:
    return {token.lower() for token in _TOKEN_RE.findall(text)}

def _tokenize_list(text: str) -> List[str]:
    return [token.lower() for token in _TOKEN_RE.findall(text)]


def _jaccard(a: set[str], b: set[str]) -> float:
    if not a or not b:
        return 0.0
    return len(a & b) / len(a | b)


def _bm25_scores(query_tokens: List[str], docs: List[List[str]]) -> List[float]:
    if not docs:
        return []
    if not query_tokens:
        return [0.0 for _ in docs]

    N = len(docs)
    avgdl = sum(len(doc) for doc in docs) / N if N else 0.0
    df: Counter[str] = Counter()
    for doc in docs:
        for term in set(doc):
            df[term] += 1

    idf = {
        term: math.log((N - freq + 0.5) / (freq + 0.5) + 1.0)
        for term, freq in df.items()
    }

    k1 = 1.5
    b = 0.75
    scores: List[float] = []
    for doc in docs:
        tf = Counter(doc)
        dl = len(doc)
        score = 0.0
        for term in query_tokens:
            if term not in tf:
                continue
            denom = tf[term] + k1 * (1 - b + b * (dl / avgdl if avgdl else 0.0))
            score += idf.get(term, 0.0) * (tf[term] * (k1 + 1)) / denom
        scores.append(score)

    return scores


class ToolRegistry:
    def __init__(self) -> None:
        self._tools: Dict[str, ToolSpec] = {}

    def register(self, tool: ToolSpec) -> None:
        if tool.name in self._tools:
            raise ValueError(f"Tool already registered: {tool.name}")
        self._tools[tool.name] = tool

    def get(self, name: str) -> ToolSpec:
        if name not in self._tools:
            raise KeyError(f"Unknown tool: {name}")
        return self._tools[name]

    def list(self) -> Iterable[ToolSpec]:
        return self._tools.values()

    def to_ollama_tools(self) -> List[dict]:
        return [tool.to_ollama() for tool in self._tools.values()]

    def select_for_prompt(
        self,
        prompt: str,
        max_tools: int = 8,
        min_score: float = 0.1,
        scoring: str = "jaccard",
        always_include: Iterable[str] | None = None,
    ) -> List[ToolSpec]:
        if not prompt:
            selected: List[ToolSpec] = []
            if always_include:
                for name in always_include:
                    if name in self._tools and self._tools[name] not in selected:
                        selected.append(self._tools[name])
            return selected

        query_list = _tokenize_list(prompt)
        query_tokens = set(query_list)
        scored: List[Tuple[ToolSpec, float]] = []
        tools_list = list(self._tools.values())

        if scoring == "bm25":
            docs = [
                _tokenize_list(f"{tool.name} {tool.description}") for tool in tools_list
            ]
            scores = _bm25_scores(query_list, docs)
            scored = list(zip(tools_list, scores))
        else:
            for tool in tools_list:
                text = f"{tool.name} {tool.description}"
                score = _jaccard(query_tokens, _tokenize(text))
                scored.append((tool, score))

        scored.sort(key=lambda x: x[1], reverse=True)
        selected = [tool for tool, score in scored if score >= min_score][:max_tools]

        if always_include:
            for name in always_include:
                if name in self._tools and self._tools[name] not in selected:
                    selected.append(self._tools[name])

        return selected
