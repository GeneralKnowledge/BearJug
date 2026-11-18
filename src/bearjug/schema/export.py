"""Write the canonical schema as JSON Schema, for non-Python components.

    python -m bearjug.schema.export [output_dir]   # default: ./schema
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

from pydantic import TypeAdapter

from .events import EVENT_ADAPTER
from .evidence import RawEvidence
from .intelligence import INTELLIGENCE_ADAPTER

SCHEMAS: dict[str, TypeAdapter] = {
    "evidence.schema.json": TypeAdapter(RawEvidence),
    "event.schema.json": EVENT_ADAPTER,
    "intelligence.schema.json": INTELLIGENCE_ADAPTER,
}


def render() -> dict[str, str]:
    return {
        name: json.dumps(adapter.json_schema(), indent=2, sort_keys=True) + "\n"
        for name, adapter in SCHEMAS.items()
    }


def main(argv: list[str]) -> int:
    out = Path(argv[1]) if len(argv) > 1 else Path("schema")
    out.mkdir(parents=True, exist_ok=True)
    for name, text in render().items():
        (out / name).write_text(text)
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
