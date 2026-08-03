---
name: codex-session-analysis
description: Analyze and summarize local Codex CLI history, sessions, rollout summaries, git activity, and workspace notes for a requested date range. Use when the user asks for a Codex Session Analysis, a session-history summary, an activity report, what Codex worked on, or asks "was haben wir gemacht" / "was lief im Zeitraum".
---

# Codex Session Analysis

## Scope Rules

Default to `--scope local` unless the user explicitly asks for a broader or narrower report.

- `local`: default. Current Codex session plus current project/repo. Use for "what happened here", "in this chat", or unspecific report requests.
- `session`: only one Codex session. Use when the user says "current chat/session" and does not want project-wide context.
- `project`: current repo/project across matching Codex sessions. Use when the user says "this project/repo/folder".
- `global`: whole machine/user. Use only when the user says "global", "whole machine", "everything under my user", or similar.

If no date range is given, use the helper defaults: today plus yesterday in `Europe/Berlin`. If the user gives a range without timezone, interpret it as `Europe/Berlin` business time and state that assumption.

## Default Workflow

1. Resolve the intended scope using the rules above.
2. Build an evidence pack with the bundled helper:

```bash
uv run --with tzdata -- python "$HOME/.codex/skills/codex-session-analysis/scripts/extract_codex_session_evidence.py" \
  --scope local \
  --start "2026-05-15" \
  --end "2026-05-18 17:40" \
  --timezone Europe/Berlin \
  --cwd "$PWD" \
  --format markdown
```

For a whole-machine/user report, pass `--scope global` explicitly:

```bash
uv run --with tzdata -- python "$HOME/.codex/skills/codex-session-analysis/scripts/extract_codex_session_evidence.py" \
  --scope global \
  --start "2026-05-15" \
  --end "2026-05-18 17:40" \
  --timezone Europe/Berlin \
  --format markdown
```

On Windows, also use `uv`; do not install `tzdata` globally:

```powershell
uv run --with tzdata -- python "$HOME\.codex\skills\codex-session-analysis\scripts\extract_codex_session_evidence.py" `
  --scope local `
  --start "2026-05-15" `
  --end "2026-05-18 17:40" `
  --timezone Europe/Berlin `
  --home $HOME `
  --cwd $PWD `
  --machine windows-laptop `
  --repo-root "$HOME\gitlab" `
  --repo-root "$HOME\github" `
  --output "$HOME\codex-session-analysis-windows.md"
```

If the Codex Desktop App stores history somewhere other than `$HOME\.codex`, pass that directory with `--codex-home`.

For programmatic JSON use, read [references/json-contract.md](references/json-contract.md) before querying fields. Check `schema_version`, the collector hash, and `diagnostics.status`; state a coverage caveat when diagnostics are partial.

3. Use the evidence pack as input, then write a human summary. Do not paste raw prompt logs unless the user explicitly asks and the content has been checked for secrets.
4. Group the final report by day and project/repository. Prefer concrete outcomes, changed repos, deploy/test/ops actions, and unresolved follow-ups over chat chronology.
5. Include the helper's non-additive activity-coverage estimate when useful. Treat it as orientation, never time tracking:
   - "span hours" means first observed event to last observed event and includes pauses;
   - "active estimate hours" caps gaps between events with `--activity-gap-minutes` (default: 30 minutes);
   - project estimates use canonical session `cwd` and recognized legacy/modern tool-call workdirs;
   - parallel sessions overlap, so project rows are not additive and must not be summed.
6. If the user asks for a file, write a Markdown report under the requested path. Use a date-based filename when no filename is given.

## Sources

Use these local sources, in this order:

- `$HOME/.codex/history.jsonl`: primary user prompt index.
- `$HOME/.codex/sessions/**/*.jsonl`: session metadata, working directories, and tool activity.
- `$HOME/.codex/memories/rollout_summaries/*.md`: compact cross-session summaries. Treat these as helpful synthesis and verify important claims with logs or git activity when possible.
- `$HOME/gitlab/*` and `$HOME/github/*`: git commit activity in the requested range.
- `$HOME/Obsidian` Markdown files: optional documentation evidence when note changes matter.

For non-global scopes, the helper filters sessions by session ID and/or project `cwd`, and limits git activity to the project root. If the current Codex runtime exposes `CODEX_THREAD_ID` or `CODEX_SESSION_ID`, the helper uses it for `local` and `session` scope.

For pure `session` scope, do not scan notes: local Markdown files have no strict session binding. Treat Git commits as repository context, not proof that Codex authored them; use the separate author and committer fields when attribution matters.

Avoid `$HOME/.codex/log/codex-tui.log` by default because it is large and noisy. Use it only for terminal/TUI debugging questions.

## Privacy And Safety

- Never include secrets, passwords, tokens, private keys, cookies, PATs, SMTP credentials, OAuth device codes, or full credential file contents.
- Do not open `$HOME/.codex/auth.json` or unrelated credential files for activity reporting.
- If a prompt says credentials were provided, summarize that as "credentials were provided/used" without values.
- The helper suppresses prompt previews completely when it detects secret context. Do not attempt to reconstruct those previews from another source for the report.
- Redact secret-looking strings in snippets and evidence.
- Reports should be useful operational summaries, not raw chat archives.

## Report Shape

Start with:

- requested range and interpreted timezone;
- scope used (`local`, `session`, `project`, or `global`);
- sources checked;
- short executive summary.

Then include:

- day-by-day/project-by-project activity;
- non-additive activity-coverage estimates by day and, for broader scopes, by project;
- important files/repos touched;
- deployments, service changes, and credentials/security work at a high level;
- remaining open items and confidence/caveats.

Keep the output concise enough to scan. If there are many activities, prioritize the work with lasting artifacts: commits, docs, services, repos, deployments, and explicit decisions.
