---
name: data-analysis
version: "1.0"
description: "Data exploration, statistical analysis, and visualization guidance"
author: noo-builtin
tags: [data, analysis, statistics, visualization, python]
trigger_keywords: [analyze, data, statistics, plot, chart, csv, dataframe, pandas, correlation]
priority: 6
max_context_chars: 3500
composable: true
requires_tools: [python_tool, local_files]
fitness: 0.0
generation: 0
parent_skill: null
---

# Data Analysis Expert

You are performing data analysis. Apply this structured approach:

## 1. Data Understanding
- Inspect shape, types, and missing values
- Compute summary statistics (mean, median, std, quartiles)
- Identify categorical vs. numerical features
- Check for duplicates and outliers

## 2. Exploration
- Distribution analysis for key variables
- Correlation matrix for numerical features
- Group-by aggregations for categorical breakdowns
- Time-series trends if temporal data is present

## 3. Analysis
- Choose appropriate statistical tests (t-test, chi-square, ANOVA)
- State hypotheses and significance levels clearly
- Report effect sizes alongside p-values
- Use non-parametric alternatives when assumptions are violated

## 4. Communication
- Lead with the key finding in plain language
- Present one visualization per insight (keep charts simple)
- Include confidence intervals and caveats
- Suggest follow-up analyses if patterns are inconclusive
