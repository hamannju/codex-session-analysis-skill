#!/usr/bin/env bash

set -euo pipefail

script_dir=$(
  cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd
)
repo_root=$(
  cd -- "${script_dir}/.." && pwd
)

skill_dir="${repo_root}/skills/codex-session-analysis"
codex_root="${CODEX_HOME:-${HOME}/.codex}"
validator="${SKILL_VALIDATOR:-${codex_root}/skills/.system/skill-creator/scripts/quick_validate.py}"

if [[ ! -f "${validator}" ]]; then
  echo "error: skill validator not found: ${validator}" >&2
  echo "set SKILL_VALIDATOR=/absolute/path/to/quick_validate.py" >&2
  exit 1
fi

uv run --with pyyaml python "${validator}" "${skill_dir}"
uv run --with ruff ruff check \
  "${skill_dir}/scripts/extract_codex_session_evidence.py" \
  "${repo_root}/tests/codex_session_analysis"
uv run --with tzdata python \
  "${skill_dir}/scripts/extract_codex_session_evidence.py" --help >/dev/null
uv run --with pytest --with tzdata pytest -q \
  "${repo_root}/tests/codex_session_analysis"

git -C "${repo_root}" diff --check
