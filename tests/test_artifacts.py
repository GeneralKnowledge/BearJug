"""Committed JSON Schemas and examples stay in step with the models."""

from pathlib import Path

from bearjug.schema import parse_event, parse_intelligence
from bearjug.schema.export import render

ROOT = Path(__file__).resolve().parent.parent


def test_json_schemas_are_current():
    for name, text in render().items():
        committed = (ROOT / "schema" / name).read_text()
        assert committed == text, f"schema/{name} is stale: run python -m bearjug.schema.export"


def test_examples_validate():
    for line in (ROOT / "examples" / "prod-db-01-session.jsonl").read_text().splitlines():
        parse_event(line)
    for line in (ROOT / "examples" / "prod-db-01-intelligence.jsonl").read_text().splitlines():
        parse_intelligence(line)


def test_json_schemas_say_they_are_structural_only():
    for name, text in render().items():
        assert "STRUCTURAL ONLY" in text, name
