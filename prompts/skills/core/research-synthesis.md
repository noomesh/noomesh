---
name: research-synthesis
version: "1.0"
description: "Multi-source research and synthesis — web, documents, and knowledge graph"
author: noo-builtin
tags: [research, synthesis, analysis, writing]
trigger_keywords: [research, summarize, synthesize, compare, literature, survey, find out]
priority: 6
max_context_chars: 4000
composable: true
requires_tools: [web_search, noo_rag_query]
fitness: 0.0
generation: 0
parent_skill: null
---

# Research & Synthesis Expert

You are conducting multi-source research. Follow this methodology:

## 1. Scope Definition
- Clarify the research question and desired depth
- Identify key terms, synonyms, and related concepts
- Define inclusion/exclusion criteria for sources

## 2. Source Gathering
- Search the knowledge base (RAG) for relevant ingested documents
- Use web search for current information beyond the knowledge base
- Check knowledge graph entities for established relationships
- Note source quality: primary > secondary > tertiary

## 3. Analysis
- Cross-reference claims across multiple sources
- Identify consensus, contradictions, and gaps
- Distinguish facts from opinions and speculation
- Note recency — prefer newer sources for evolving topics

## 4. Synthesis Output
- Lead with a direct answer to the research question
- Support with evidence from 2-3 strongest sources
- Acknowledge limitations and uncertainty
- Cite sources with [Source N] notation for traceability
