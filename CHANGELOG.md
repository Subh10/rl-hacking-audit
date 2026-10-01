# Changelog
## 0.4.0
- Added: scenario scanner, deterministic oracles (canary, tool policy, exfil, forbidden token), 12 converters, 12 built-in scenarios,
  YAML/JSON scenarios, OpenAI-compatible/Anthropic/HTTP adapters, SARIF/Markdown/HTML reports, real replay, Wilson/Fisher/Holm stats,
  report comparison + CI gates, RL checkpoint comparison, GitHub Action, optional advisory LLM judge.
- Fixed: legacy RuleEvaluator flagged refusals ("I cannot provide secrets") as HIGH secret leaks; adaptive planner `branch_factor`
  compared global frontier size; mutation candidates were randomly truncated; `StaticAttack.id()` was non-deterministic.
