# AGENTS.md - codex-session-analysis-skill

This repository distributes the standalone `codex-session-analysis` skill.

## Rules

- Use `uv` for Python execution and one-off development dependencies.
- Keep the installable skill under `skills/codex-session-analysis/` concise and
  self-contained.
- Preserve `codex-session-analysis` as the canonical skill and collector name.
- Never commit Codex history files, session JSONL, rollout archives, generated
  activity reports, secrets, credentials, or real prompt excerpts.
- Use synthetic fixtures for tests. A privacy regression must prove suppression
  without embedding a real secret or conversation.
- Treat Git commits as repository evidence, not automatic proof that Codex
  authored the work.
- Run `./scripts/validate.sh` before committing changes.
