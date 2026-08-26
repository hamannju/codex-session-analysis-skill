# Codex Session Analysis Skill

Standalone distribution of the `codex-session-analysis` skill.

The skill builds a scoped evidence pack from local Codex history, session
metadata, rollout summaries, Git activity, and optional workspace notes. Codex
then uses that evidence to produce a concise human-readable activity report.

## Repository layout

- `skills/codex-session-analysis/` — installable Codex skill
- `tests/codex_session_analysis/` — synthetic parser, privacy, and contract tests
- `scripts/validate.sh` — skill validation, lint, smoke test, and regression suite

The repository contains no captured Codex sessions or generated activity
reports.

## Install

Ask Codex to use `$skill-installer` with:

```text
https://github.com/hamannju/codex-session-analysis-skill/tree/main/skills/codex-session-analysis
```

The installed skill is named `codex-session-analysis` and is invoked as
`$codex-session-analysis`.

## Validate

Requirements: Git and `uv`. The validation script prefers the system
`skill-creator` validator from a local Codex installation and falls back to a
repository-owned compatible validator in clean environments.

```bash
./scripts/validate.sh
```

Set `SKILL_VALIDATOR=/absolute/path/to/quick_validate.py` or
`SKILL_CREATOR_DIR=/absolute/path/to/skill-creator` to require a specific
external validator.
