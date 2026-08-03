from __future__ import annotations

import importlib.util
import json
import sys
from collections.abc import Callable
from pathlib import Path
from types import ModuleType, SimpleNamespace
from typing import Any

import pytest

REPO_ROOT = Path(__file__).resolve().parents[2]
HELPER_PATH = (
    REPO_ROOT
    / "skills"
    / "codex-session-analysis"
    / "scripts"
    / "extract_codex_session_evidence.py"
)


@pytest.fixture(scope="session")
def activity_module() -> ModuleType:
    """Import the hyphenated skill helper without making it a package."""
    module_name = "spedition_skills_codex_session_analysis"
    spec = importlib.util.spec_from_file_location(module_name, HELPER_PATH)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules[module_name] = module
    spec.loader.exec_module(module)
    return module


@pytest.fixture
def jsonl_writer() -> Callable[[Path, list[Any]], Path]:
    def write(path: Path, rows: list[Any]) -> Path:
        path.parent.mkdir(parents=True, exist_ok=True)
        content = "".join(json.dumps(row) + "\n" for row in rows)
        path.write_text(content, encoding="utf-8")
        return path

    return write


@pytest.fixture
def synthetic_layout(tmp_path: Path) -> SimpleNamespace:
    home = tmp_path / "synthetic-home"
    codex_home = home / "codex-data"
    sessions = codex_home / "sessions"
    summaries = codex_home / "memories" / "rollout_summaries"
    notes = home / "synthetic-notes"
    repo_root = tmp_path / "synthetic-repositories"

    for directory in (sessions, summaries, notes, repo_root):
        directory.mkdir(parents=True, exist_ok=True)
    (codex_home / "history.jsonl").write_text("", encoding="utf-8")

    return SimpleNamespace(
        home=home,
        codex_home=codex_home,
        sessions=sessions,
        summaries=summaries,
        notes=notes,
        repo_root=repo_root,
    )
